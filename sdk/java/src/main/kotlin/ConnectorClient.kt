/**
 * ConnectorClient — high-level wrapper around UniFFI FFI bindings.
 *
 * Handles the full round-trip:
 *   1. Build connector HTTP request via authorize_req (FFI)
 *   2. Execute the HTTP request via HttpClient
 *   3. Parse the connector response via authorize_res (FFI)
 */

package payments

import uniffi.connector_service_ffi.authorizeReqTransformer
import uniffi.connector_service_ffi.authorizeResTransformer
import ucs.v2.Payment.PaymentServiceAuthorizeRequest
import ucs.v2.Payment.PaymentServiceAuthorizeResponse

class ConnectorClient(private val options: Map<String, Any> = emptyMap()) {

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
        val connectorRequest = authorizeReqTransformer(requestBytes, metadata, opts)

        // Step 3: Execute the HTTP request via our specialized HttpClient
        // This handles pooling, split timeouts, and binary safety.
        val httpReq = HttpRequest(
            url = connectorRequest.url,
            method = connectorRequest.method,
            headers = connectorRequest.headers,
            body = connectorRequest.body
        )
        
        val httpResponse = HttpClient.execute(httpReq, options)

        // Step 4: Parse the connector response via FFI
        val resultBytes = authorizeResTransformer(
            httpResponse.body,
            httpResponse.statusCode.toUShort(),
            httpResponse.headers,
            requestBytes,
            metadata,
            opts,
        )

        // Step 5: Deserialize the protobuf response
        return PaymentServiceAuthorizeResponse.parseFrom(resultBytes)
    }
}
