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
import ucs.v2.Payment.PaymentServiceAuthorizeRequest
import ucs.v2.Payment.PaymentServiceAuthorizeResponse

class ConnectorClient {

    private val httpClient = OkHttpClient()

    /**
     * Execute a full authorize round-trip: FFI request build -> HTTP -> FFI response parse.
     *
     * @param request A PaymentServiceAuthorizeRequest protobuf message.
     * @param metadata Map with connector routing and auth info.
     * @return PaymentServiceAuthorizeResponse protobuf message.
     */
    fun authorize(
        request: PaymentServiceAuthorizeRequest,
        metadata: Map<String, String>,
    ): PaymentServiceAuthorizeResponse {
        // Step 1: Serialize the protobuf request to bytes
        val requestBytes = request.toByteArray()

        // Step 2: Build the connector HTTP request via FFI
        // Now returns a native FfiConnectorHttpRequest object, no JSONObject needed!
        val connectorRequest = authorizeReqTransformer(requestBytes, metadata)

        val url = connectorRequest.url
        val method = connectorRequest.method
        val headersMap = connectorRequest.headers
        val bodyBytes = connectorRequest.body

        // Step 3: Execute the HTTP request via OkHttp
        // bodyBytes is already a ByteArray (or null), OkHttp handles this natively
        val requestBody = bodyBytes?.toRequestBody(
            headersMap["Content-Type"]?.toMediaTypeOrNull()
        )

        val httpRequest = Request.Builder()
            .url(url)
            .method(method, requestBody)
            .headers(headersMap.toHeaders())
            .build()

        val response = httpClient.newCall(httpRequest).execute()

        // Step 4: Parse the connector response via FFI
        val responseBody = response.body?.bytes() ?: byteArrayOf()
        val responseHeaders = mutableMapOf<String, String>()
        for (name in response.headers.names()) {
            responseHeaders[name] = response.header(name) ?: ""
        }

        val resultBytes = authorizeResTransformer(
            responseBody,
            response.code.toUShort(),
            responseHeaders,
            requestBytes,
            metadata,
        )

        // Step 5: Deserialize the protobuf response
        return PaymentServiceAuthorizeResponse.parseFrom(resultBytes)
    }
}
