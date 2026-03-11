
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
 *
 * Error Handling:
 *   FFI transformers return raw bytes that may represent either a success proto or
 *   an error proto (RequestError for req_transformer, ResponseError for res_transformer).
 *   On error, the decoded proto (RequestError or ResponseError) is thrown directly.
 *   Callers can catch the specific error type:
 *
 *       try {
 *           val response = client.authorize(request)
 *       } catch (e: RequestError) {
 *           println("${e.errorCode}: ${e.errorMessage}")
 *       } catch (e: ResponseError) {
 *           println("${e.errorCode}: ${e.errorMessage}")
 *       }
 */

package payments

import com.google.protobuf.ByteString
import com.google.protobuf.InvalidProtocolBufferException
import com.google.protobuf.MessageLite
import com.google.protobuf.Parser

open class ConnectorClient(
    val config: ConnectorConfig,
    val defaults: RequestConfig = RequestConfig.getDefaultInstance(),
    libPath: String? = null
) {
    private val httpClient: okhttp3.OkHttpClient

    init {
        // Instance-level cache: create the primary connection pool at startup
        val httpConfig = if (defaults.hasHttp()) defaults.http else null
        this.httpClient = HttpClient.createClient(httpConfig)
    }

    /**
     * Builds FfiOptions from config. Environment comes from ConnectorConfig (immutable).
     */
    private fun resolveFfiOptions(overrides: RequestConfig?): FfiOptions {
        return FfiOptions.newBuilder()
            .setEnvironment(config.environment)
            .setConnector(config.connector)
            .setAuth(config.auth)
            .build()
    }

    /**
     * Merges request-level HTTP overrides with client defaults.
     */
    private fun resolveHttpConfig(overrides: RequestConfig?): HttpConfig? {
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
     * Parse FFI req_transformer bytes as either FfiConnectorHttpRequest or RequestError.
     * Tries the success type first; on failure parses as RequestError and throws
     * the RequestError directly.
     */
    private fun checkReqError(resultBytes: ByteArray): FfiConnectorHttpRequest {
        return try {
            FfiConnectorHttpRequest.parseFrom(resultBytes)
        } catch (e: InvalidProtocolBufferException) {
            // Try parsing as RequestError and throw directly
            throw RequestError.parseFrom(resultBytes)
        }
    }

    /**
     * Parse FFI res_transformer bytes as either success type or ResponseError.
     * Tries the success type first; on failure parses as ResponseError and throws
     * the ResponseError directly.
     */
    private fun <T : MessageLite> checkResError(
        resultBytes: ByteArray,
        successParser: Parser<T>
    ): T {
        return try {
            successParser.parseFrom(resultBytes)
        } catch (e: InvalidProtocolBufferException) {
            // Try parsing as ResponseError and throw directly
            throw ResponseError.parseFrom(resultBytes)
        }
    }


    /**
     * Execute a full round-trip for any payment flow.
     *
     * Errors from the FFI layer are thrown as RequestError or ResponseError directly.
     *
     * @param flow Flow name matching the FFI transformer prefix (e.g. "authorize").
     * @param requestBytes Serialized protobuf request bytes.
     * @param responseParser Protobuf parser for the expected response type.
     * @param options Optional RequestConfig message.
     * @return Parsed protobuf response.
     * @throws RequestError If the req_transformer returns an error proto.
     * @throws ResponseError If the res_transformer returns an error proto.
     */
    fun <T : MessageLite> executeFlow(
        flow: String,
        requestBytes: ByteArray,
        responseParser: Parser<T>,
        options: RequestConfig? = null,
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
        //    Parse result bytes as FfiConnectorHttpRequest; if that fails, parse as RequestError.
        val connectorRequestBytes = reqTransformer(requestBytes, optionsBytes)
        val connectorRequest = checkReqError(connectorRequestBytes)

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
        //    Parse result bytes as success type; if that fails, parse as ResponseError.
        val resultBytes = resTransformer(
            ffiResponseBytes,
            requestBytes,
            optionsBytes,
        )

        return checkResError(resultBytes, responseParser)
    }


    /**
     * Execute a single-step flow directly via FFI (no HTTP round-trip).
     * Used for inbound flows like webhook processing where the connector sends data to us.
     *
     * Errors are thrown as ResponseError directly.
     *
     * @param flow Flow name matching the FFI transformer (e.g. "handle").
     * @param requestBytes Serialized protobuf request bytes.
     * @param responseParser Protobuf parser for the expected response type.
     * @param options Optional RequestConfig for FFI context. Merged with client defaults.
     * @return Parsed protobuf response.
     * @throws ResponseError If the FFI transformer returns an error proto.
     */
    fun <T : MessageLite> executeDirect(
        flow: String,
        requestBytes: ByteArray,
        responseParser: Parser<T>,
        options: RequestConfig? = null,
    ): T {
        val transformer = FlowRegistry.directTransformers[flow]
            ?: error("Unknown single-step flow: '$flow'. Register it via a {flow}_transformer in services/payments.rs and run `make generate`.")

        val ffiOptions = resolveFfiOptions(options)
        val optionsBytes = ffiOptions.toByteArray()

        val resultBytes = transformer(requestBytes, optionsBytes)
        
        // Parse result bytes as success type; if that fails, parse as ResponseError.
        return checkResError(resultBytes, responseParser)
    }
}