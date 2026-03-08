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

open class ConnectorClient(
    val identity: ClientIdentity,
    val defaults: ConfigOptions = ConfigOptions.getDefaultInstance(),
    libPath: String? = null
) {
    private val httpClient: okhttp3.OkHttpClient

    init {
        // Instance-level cache: create the primary connection pool at startup
        // Infrastructure (Proxy, Certs) fixed at client level.
        val httpConfig = if (defaults.hasHttp()) defaults.http else null
        this.httpClient = HttpClient.createClient(httpConfig)
    }

    /**
     * Merges request-level options with client defaults to build the 
     * final context for the Rust transformation engine.
     */
    private fun resolveFfiOptions(overrides: ConfigOptions?): FfiOptions {
        // Resolve Environment: Request Override > Client Default > Sandbox (0)
        // Note: Java Protobuf enums don't have hasField() methods.
        val environment = when {
            overrides != null && overrides.environment != Environment.ENVIRONMENT_UNSPECIFIED -> overrides.environment
            defaults.environment != Environment.ENVIRONMENT_UNSPECIFIED -> defaults.environment
            else -> Environment.SANDBOX
        }

        return FfiOptions.newBuilder()
            .setEnvironment(environment)
            .setConnector(identity.connector)
            .setAuth(identity.auth)
            .build()
    }

    /**
     * Merges request-level HTTP overrides with client defaults.
     */
    private fun resolveHttpConfig(overrides: ConfigOptions?): HttpConfig? {
        val clientHttp = if (defaults.hasHttp()) defaults.http else null
        val overrideHttp = if (overrides != null && overrides.hasHttp()) overrides.http else null

        if (overrideHttp == null) return clientHttp
        
        // Merge: Field-level override > Client default
        val builder = HttpConfig.newBuilder()
        if (clientHttp != null) {
            builder.mergeFrom(clientHttp)
        }
        builder.mergeFrom(overrideHttp)
        
        return builder.build()
    }

    /**
     * Execute a full round-trip for any payment flow.
     *
     * @param flow Flow name matching the FFI transformer prefix (e.g. "authorize").
     * @param requestBytes Serialized protobuf request bytes.
     * @param responseParser Protobuf parser for the expected response type.
     * @param options Optional ConfigOptions message.
     * @return Parsed protobuf response.
     */
    fun <T : MessageLite> executeFlow(
        flow: String,
        requestBytes: ByteArray,
        responseParser: Parser<T>,
        options: ConfigOptions? = null,
    ): T {
        val reqTransformer = FlowRegistry.reqTransformers[flow]
            ?: error("Unknown flow: '$flow'")
        val resTransformer = FlowRegistry.resTransformers[flow]
            ?: error("Unknown flow: '$flow'")

        // 1. Resolve final configuration (Pattern-based merging)
        val ffiOptions = resolveFfiOptions(options)
        val optionsBytes = ffiOptions.toByteArray()
        val httpConfig = resolveHttpConfig(options)

        // 2. Build connector HTTP request via FFI
        val connectorRequestBytes = reqTransformer(requestBytes, optionsBytes)
        val connectorRequest = FfiConnectorHttpRequest.parseFrom(connectorRequestBytes)

        val httpRequest = HttpRequest(
            url = connectorRequest.url,
            method = connectorRequest.method,
            headers = connectorRequest.headersMap,
            body = if (connectorRequest.hasBody()) connectorRequest.body.toByteArray() else null
        )

        // 3. Execute HTTP request via standardized HttpClient using the connection pool
        val response = HttpClient.execute(httpRequest, httpConfig, this.httpClient)

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
            optionsBytes,
        )

        return responseParser.parseFrom(resultBytes)
    }

    /**
     * Execute a single-step flow directly via FFI (no HTTP round-trip).
     * Used for inbound flows like webhook processing where the connector sends data to us.
     *
     * @param flow Flow name matching the FFI transformer (e.g. "handle").
     * @param requestBytes Serialized protobuf request bytes.
     * @param responseParser Protobuf parser for the expected response type.
     * @param options Optional ConfigOptions for FFI context. Merged with client defaults.
     * @return Parsed protobuf response.
     */
    fun <T : MessageLite> executeDirect(
        flow: String,
        requestBytes: ByteArray,
        responseParser: Parser<T>,
        options: ConfigOptions? = null,
    ): T {
        val transformer = FlowRegistry.directTransformers[flow]
            ?: error("Unknown single-step flow: '$flow'. Register it via a {flow}_transformer in services/payments.rs and run `make generate`.")

        val ffiOptions = resolveFfiOptions(options)
        val optionsBytes = ffiOptions.toByteArray()

        val resultBytes = transformer(requestBytes, optionsBytes)
        return responseParser.parseFrom(resultBytes)
    }
}
