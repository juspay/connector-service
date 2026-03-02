/**
 * ConnectorClient — high-level wrapper around UniFFI bindings.
 *
 * Handles the full round-trip:
 *   1. Serialize protobuf request to bytes
 *   2. Build connector HTTP request via authorizeReqTransformer (UniFFI FFI)
 *   3. Execute the HTTP request via our standardized HttpClient
 *   4. Parse the connector response via authorizeResTransformer (UniFFI FFI)
 *   5. Deserialize protobuf response from bytes
 */

package payments

import uniffi.connector_service_ffi.*
import ucs.v2.Payment.*
import ucs.v2.SdkOptions.Options
import ucs.v2.SdkOptions.FfiOptions

class ConnectorClient(private val options: Options = Options.getDefaultInstance()) {

    /**
     * Execute a full authorize round-trip.
     * 
     * @param request A PaymentServiceAuthorizeRequest protobuf message.
     * @param metadata Map with connector routing and auth info. Must include:
     *                 - "connector": connector name (e.g. "Stripe")
     *                 - "connector_auth_type": JSON string of auth config
     *                 - x-* headers for masked metadata
     * @param ffiOptions Optional FfiOptions protobuf message override.
     * @return PaymentServiceAuthorizeResponse protobuf message.
     */
    fun authorize(
        request: PaymentServiceAuthorizeRequest,
        metadata: Map<String, String>,
        ffiOptions: FfiOptions? = null,
    ): PaymentServiceAuthorizeResponse {
        val requestBytes = request.toByteArray()
        
        // Resolve FFI options (prefer call-specific, fallback to client-global)
        val ffi = ffiOptions ?: (if (options.hasFfi()) options.ffi else null)
        val opts = ffi?.toByteArray() ?: ByteArray(0)

        // 1. Build Request via FFI
        val connectorRequest = authorizeReqTransformer(requestBytes, metadata, opts)

        // 2. Execute HTTP (uses Global HttpOptions)
        val httpReq = HttpRequest(
            url = connectorRequest.url,
            method = connectorRequest.method,
            headers = connectorRequest.headers,
            body = connectorRequest.body
        )
        val httpOptions = if (options.hasHttp()) options.http else ucs.v2.SdkOptions.HttpOptions.getDefaultInstance()
        val httpResponse = HttpClient.execute(httpReq, httpOptions)

        // 3. Parse Response via FFI
        val ffiRes = FfiConnectorHttpResponse(
            statusCode = httpResponse.statusCode.toUShort(),
            headers = httpResponse.headers,
            body = httpResponse.body
        )

        val resultBytes = authorizeResTransformer(
            ffiRes,
            requestBytes,
            metadata,
            opts,
        )

        // 4. Decode Result
        return PaymentServiceAuthorizeResponse.parseFrom(resultBytes)
    }
}
