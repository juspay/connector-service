/**
 * ConnectorClient — high-level wrapper around UniFFI FFI bindings.
 *
 * Handles the full round-trip:
 *   1. Build connector HTTP request via authorize_req (FFI)
 *   2. Execute the HTTP request via OkHttp
 *   3. Parse the connector response via authorize_res (FFI)
 *
 * Mirrors the Node.js client at sdk/node-ffi-client/src/client.js
 * and the Python client at examples/example-uniffi-py/connector_client.py.
 */

import uniffi.connector_service_ffi.authorizeReqTransformer
import uniffi.connector_service_ffi.authorizeResTransformer
import okhttp3.Headers.Companion.toHeaders
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import ucs.v2.Payment.PaymentServiceAuthorizeRequest
import ucs.v2.Payment.PaymentServiceAuthorizeResponse

class ConnectorClient {

    private val httpClient = OkHttpClient()

    /**
     * Execute a full authorize round-trip: FFI request build -> HTTP -> FFI response parse.
     *
     * @param request A PaymentServiceAuthorizeRequest protobuf message.
     * @param metadata Map with connector routing and auth info.
     * @param optionsBytes Optional FfiOptions serialized to bytes. Pass empty byte array or null for default.
     * @return PaymentServiceAuthorizeResponse protobuf message.
     */
    fun authorize(
        request: PaymentServiceAuthorizeRequest,
        metadata: Map<String, String>,
        optionsBytes: ByteArray? = null,
    ): PaymentServiceAuthorizeResponse {
        // Step 1: Serialize the protobuf request to bytes
        val requestBytes = request.toByteArray()

        // Use provided bytes or default to empty byte array
        val opts = optionsBytes ?: ByteArray(0)

        // Step 2: Build the connector HTTP request via FFI
        val connectorRequestJson = authorizeReqTransformer(requestBytes, metadata, optionsBytes)
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
            metadata,
            optionsBytes,
        )

        // Step 5: Deserialize the protobuf response
        return PaymentServiceAuthorizeResponse.parseFrom(resultBytes)
    }
}
