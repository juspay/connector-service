/**
 * ConnectorClient — high-level wrapper around UniFFI FFI bindings.
 *
 * Handles the full round-trip:
 *   1. Build connector HTTP request via authorizeReqTransformer (UniFFI FFI)
 *   2. Execute the HTTP request via HttpClient
 *   3. Parse the connector response via authorizeResTransformer (UniFFI FFI)
 */

package payments

import uniffi.connector_service_ffi.*
import ucs.v2.Payment.*
import ucs.v2.SdkOptions.FfiOptions
import ucs.v2.SdkOptions.EnvOptions

class ConnectorClient(private val options: HttpOptions = HttpOptions()) {

    private fun getOptionsBytes(ffiOptions: FfiOptions? = null): ByteArray {
        val builder = FfiOptions.newBuilder()
        val envBuilder = EnvOptions.newBuilder()
        envBuilder.testMode = true // Default to true
        builder.env = envBuilder.build()
        
        if (ffiOptions != null) {
            builder.mergeFrom(ffiOptions)
        }
        return builder.build().toByteArray()
    }

    /**
     * Execute a full authorize round-trip.
     */
    fun authorize(
        request: PaymentServiceAuthorizeRequest,
        metadata: Map<String, String>,
        ffiOptions: FfiOptions? = null,
    ): PaymentServiceAuthorizeResponse {
        val requestBytes = request.toByteArray()
        val opts = getOptionsBytes(ffiOptions)

        // 1. Build Request via FFI
        val connectorRequest = authorizeReqTransformer(requestBytes, metadata, opts)

        // 2. Execute HTTP
        val httpReq = HttpRequest(
            url = connectorRequest.url,
            method = connectorRequest.method,
            headers = connectorRequest.headers,
            body = connectorRequest.body
        )
        val httpResponse = HttpClient.execute(httpReq, options)

        // 3. Parse Response via FFI
        // Now uses the FfiConnectorHttpResponse record!
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

    // Additional flows (capture, void, etc.) would follow the same pattern
}
