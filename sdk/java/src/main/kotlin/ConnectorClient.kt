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
    libPath: String? = null,
    private val options: Options = Options.getDefaultInstance()
) {
    private val httpClient: okhttp3.OkHttpClient

    init {
        // Instance-level connection pool (OkHttpClient)
        this.httpClient = HttpClient.createClient(options.http)
    }

    /**
     * Execute a full round-trip for any payment flow.
     *
     * @param flow Flow name matching the FFI transformer prefix (e.g. "authorize").
     * @param requestBytes Serialized protobuf request bytes.
     * @param responseParser Protobuf parser for the expected response type.
     * @param metadata Map with connector routing and auth info.
     * @param optionsBytes Optional FfiOptions serialized to bytes. Pass null for default.
     * @return Parsed protobuf response.
     */
    fun <T : MessageLite> executeFlow(
        flow: String,
        requestBytes: ByteArray,
        responseParser: Parser<T>,
        metadata: Map<String, String>,
        optionsBytes: ByteArray? = null,
    ): T {
        val reqTransformer = FlowRegistry.reqTransformers[flow]
            ?: error("Unknown flow: '$flow'. Add it to sdk/flows.yaml and run `make codegen`.")
        val resTransformer = FlowRegistry.resTransformers[flow]
            ?: error("Unknown flow: '$flow'. Add it to sdk/flows.yaml and run `make codegen`.")

        val opts = optionsBytes ?: ByteArray(0)

        // 1. Build connector HTTP request via FFI (returns FfiConnectorHttpRequest protobuf bytes)
        val connectorRequestBytes = reqTransformer(requestBytes, metadata, opts)
        val connectorRequest = FfiConnectorHttpRequest.parseFrom(connectorRequestBytes)

        val httpRequest = HttpRequest(
            url = connectorRequest.url,
            method = connectorRequest.method,
            headers = connectorRequest.headersMap,
            body = if (connectorRequest.hasBody()) connectorRequest.body.toByteArray() else null
        )

        // 2. Execute HTTP request via standardized HttpClient
        val response = HttpClient.execute(httpRequest, options.http, this.httpClient)

        // 3. Encode HTTP response as FfiConnectorHttpResponse protobuf bytes
        val ffiResponseBytes = FfiConnectorHttpResponse.newBuilder()
            .setStatusCode(response.statusCode)
            .putAllHeaders(response.headers)
            .setBody(ByteString.copyFrom(response.body))
            .build()
            .toByteArray()

        // 4. Parse connector response via FFI
        val resultBytes = resTransformer(
            ffiResponseBytes,
            requestBytes,
            metadata,
            opts,
        )

        return responseParser.parseFrom(resultBytes)
    }
}
