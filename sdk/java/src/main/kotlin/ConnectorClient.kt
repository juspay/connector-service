/**
 * ConnectorClient — high-level wrapper around UniFFI FFI bindings.
 *
 * Handles the full round-trip:
 *   1. Build connector HTTP request via authorizeReqTransformer (FFI)
 *   2. Execute the HTTP request via OkHttp
 *   3. Parse the connector response via authorizeResTransformer (FFI)
 *
 * All types (Connector, ConnectorAuth, ConnectorConfig) come from proto
 * codegen — same pattern as Currency, CaptureMethod, etc.
 */

import uniffi.connector_service_ffi.authorizeReqTransformer
import uniffi.connector_service_ffi.authorizeResTransformer
import okhttp3.Headers.Companion.toHeaders
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import ucs.v2.Payment.*
import ucs.v2.PaymentMethods.*

// ── ConnectorClient ───────────────────────────────────────────────────────────

/**
 * High-level client for connector payment operations via UniFFI FFI.
 *
 * All types come from proto codegen (payment.proto, package ucs.v2).
 * Same pattern as Currency, CaptureMethod, etc.
 *
 * Example:
 * ```kotlin
 * val config = ConnectorConfig.newBuilder()
 *     .setConnector(Connector.STRIPE)
 *     .setAuth(ConnectorAuth.newBuilder()
 *         .setHeaderKey(HeaderKeyAuth.newBuilder().setApiKey("sk_test_...").build())
 *         .build()
 *     )
 *     .build()
 * val client = ConnectorClient(config)
 * ```
 */
class ConnectorClient(
    config: ConnectorConfig,
) {

    private val httpClient = OkHttpClient()

    /** Bundled connector config — proto bytes, built once, reused for every call. */
    private val configBytes: ByteArray = config.toByteArray()

    /**
     * Execute a full authorize round-trip: FFI request build -> HTTP -> FFI response parse.
     *
     * @param request A PaymentServiceAuthorizeRequest protobuf message.
     * @return PaymentServiceAuthorizeResponse protobuf message.
     */
    fun authorize(
        request: PaymentServiceAuthorizeRequest,
    ): PaymentServiceAuthorizeResponse {
        // Step 1: Serialize the protobuf request to bytes
        val requestBytes = request.toByteArray()

        // Step 2: Build the connector HTTP request via FFI
        val connectorRequestJson = authorizeReqTransformer(requestBytes, configBytes, null)
        val connectorRequest = JSONObject(connectorRequestJson)

        val url = connectorRequest.getString("url")
        val method = connectorRequest.getString("method")

        val headersObj = connectorRequest.optJSONObject("headers") ?: JSONObject()
        val headersMap = mutableMapOf<String, String>()
        for (key in headersObj.keys()) {
            headersMap[key] = headersObj.getString(key)
        }

        val body = connectorRequest.opt("body")?.toString()

        // Step 3: Execute the HTTP request via OkHttp
        val requestBody = body?.toRequestBody(
            headersMap["Content-Type"]?.toMediaTypeOrNull()
        )

        val httpRequest = Request.Builder()
            .url(url)
            .method(method, requestBody)
            .headers(headersMap.toHeaders())
            .build()

        val response = httpClient.newCall(httpRequest).execute()

        // Step 4: Parse the connector response via FFI
        val responseBody = response.body?.string() ?: ""
        val responseHeaders = mutableMapOf<String, String>()
        for (name in response.headers.names()) {
            responseHeaders[name] = response.header(name) ?: ""
        }

        val resultBytes = authorizeResTransformer(
            responseBody.toByteArray(Charsets.UTF_8),
            response.code.toUShort(),
            responseHeaders,
            requestBytes,
            configBytes,
            null,
        )

        // Step 5: Deserialize the protobuf response
        return PaymentServiceAuthorizeResponse.parseFrom(resultBytes)
    }
}
