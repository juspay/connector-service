/**
 * ConnectorClient — high-level wrapper around UniFFI bindings.
 *
 * Handles the full round-trip for any payment flow:
 *   1. Build connector HTTP request via {flow}_req_transformer (FFI)
 *   2. Execute the HTTP request via our standardized HttpClient
 *   3. Parse the connector response via {flow}_res_transformer (FFI)
 *
 * Flow methods (authorize, capture, void, refund, …) are defined as Kotlin
 * extension functions in GeneratedFlows.kt — no flow names are hardcoded here.
 * To add a new flow: edit sdk/flows.yaml and run `make generate`.
 */

package payments

import com.google.protobuf.ByteString
import com.google.protobuf.MessageLite
import com.google.protobuf.Parser

class ConnectorClient(
    val config: ClientConfig,
    libPath: String? = null
) {
    private val httpClient: okhttp3.OkHttpClient

    init {
        // Instance-level connection pool (OkHttpClient)
        // Infrastructure (Proxy, Certs) fixed at client level.
        this.httpClient = HttpClient.createClient(config.http)
    }

    /**
     * Merges request-level overrides with client defaults to build the 
     * final context for the Rust transformation engine.
     */
    private fun resolveFfiOptions(requestOptions: RequestOptions?): FfiOptions {
        val builder = FfiOptions.newBuilder()
            .setEnvironment(config.environment)
            .setConnector(config.connector)
        
        // Prefer request-level auth override
        if (requestOptions != null && requestOptions.hasAuth()) {
            builder.auth = requestOptions.auth
        } else if (config.hasAuth()) {
            builder.auth = config.auth
        }
        
        return builder.build()
    }

    /**
     * Resolves the final timeout configuration for a request.
     * Identity Rule: Only timeouts can be overridden per request.
     */
    private fun resolveTimeoutConfig(requestOptions: RequestOptions?): HttpTimeoutConfig? {
        val clientTimeouts = if (config.hasHttp() && config.http.hasTimeouts()) config.http.timeouts else null
        val overrideTimeouts = if (requestOptions != null && requestOptions.hasTimeouts()) requestOptions.timeouts else null

        if (overrideTimeouts == null) {
            return clientTimeouts
        }

        // Merge timeouts: override > client default
        val builder = HttpTimeoutConfig.newBuilder()
        if (clientTimeouts != null) {
            builder.mergeFrom(clientTimeouts)
        }
        builder.mergeFrom(overrideTimeouts)
        
        return builder.build()
    }

    /**
     * Execute a full round-trip for any payment flow.
     *
     * @param flow Flow name matching the FFI transformer prefix (e.g. "authorize").
     * @param requestBytes Serialized protobuf request bytes.
     * @param responseParser Protobuf parser for the expected response type.
     * @param metadata Map with connector routing and auth info.
     * @param requestOptions Optional RequestOptions message.
     * @return Parsed protobuf response.
     */
    fun <T : MessageLite> executeFlow(
        flow: String,
        requestBytes: ByteArray,
        responseParser: Parser<T>,
        metadata: Map<String, String>,
        requestOptions: RequestOptions? = null,
    ): T {
        val reqTransformer = FlowRegistry.reqTransformers[flow]
            ?: error("Unknown flow: '$flow'. Add it to sdk/flows.yaml and run `make codegen`.")
        val resTransformer = FlowRegistry.resTransformers[flow]
            ?: error("Unknown flow: '$flow'. Add it to sdk/flows.yaml and run `make codegen`.")

        // 1. Resolve final configuration (Pattern-based merging)
        val ffiOptions = resolveFfiOptions(requestOptions)
        val optionsBytes = ffiOptions.toByteArray()
        val timeoutConfig = resolveTimeoutConfig(requestOptions)

        // 2. Build connector HTTP request via FFI (returns FfiConnectorHttpRequest protobuf bytes)
        val connectorRequestBytes = reqTransformer(requestBytes, metadata, optionsBytes)
        val connectorRequest = FfiConnectorHttpRequest.parseFrom(connectorRequestBytes)

        val httpRequest = HttpRequest(
            url = connectorRequest.url,
            method = connectorRequest.method,
            headers = connectorRequest.headersMap,
            body = if (connectorRequest.hasBody()) connectorRequest.body.toByteArray() else null
        )

        // 3. Execute HTTP request via standardized HttpClient using the connection pool
        val response = HttpClient.execute(httpRequest, timeoutConfig, this.httpClient)

        // 4. Encode HTTP response as FfiConnectorHttpResponse protobuf bytes
        val ffiResponseBytes = FfiConnectorHttpResponse.newBuilder()
            .setStatusCode(response.statusCode)
            .putAllHeaders(response.headers)
            .setBody(ByteString.copyFrom(response.body))
            .build()
            .toByteArray()

        // 5. Parse connector response via FFI
        val resultBytes = resTransformer(
            ffiResponseBytes,
            requestBytes,
            metadata,
            optionsBytes,
        )

        return responseParser.parseFrom(resultBytes)
    }
}
