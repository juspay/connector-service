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

import okhttp3.OkHttpClient
import ucs.v2.Payments.PaymentServiceAuthorizeRequest
import ucs.v2.Payments.PaymentServiceAuthorizeResponse
import ucs.v2.SdkOptions.FfiOptions
import ucs.v2.SdkOptions.Options

class ConnectorClient(
    libPath: String? = null,
    private val options: Options = Options.getDefaultInstance()
) {
    private val uniffi = UniffiClient(libPath)
    private val httpClient: OkHttpClient

    init {
        // Instance-level connection pool (OkHttpClient)
        // Uses proto-generated HttpOptions directly
        this.httpClient = HttpClient.createClient(options.http)
    }

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
        ffiOptions: FfiOptions? = null
    ): PaymentServiceAuthorizeResponse {
        // 1. Serialize request
        val requestBytes = request.toByteArray()

        // 2. Resolve FFI options (prefer call-specific override)
        val ffi = ffiOptions ?: (if (options.hasFfi()) options.ffi else null)
        val optionsBytes = ffi?.toByteArray() ?: byteArrayOf()

        // 3. Transform to connector request via FFI (returns Protobuf bytes)
        val resultBytes = uniffi.authorizeReq(requestBytes, metadata, optionsBytes)
        val connectorReq = ucs.v2.SdkOptions.FfiConnectorHttpRequest.parseFrom(resultBytes)

        val connectorRequest = HttpRequest(
            url = connectorReq.url,
            method = connectorReq.method,
            headers = connectorReq.headersMap,
            body = if (connectorReq.hasBody()) connectorReq.body.toByteArray() else null
        )

        // 4. Execute network call (uses proto HttpOptions directly and owned client)
        val response = HttpClient.execute(connectorRequest, options.http, this.httpClient)

        // 5. Transform connector response via FFI
        val resProto = ucs.v2.SdkOptions.FfiConnectorHttpResponse.newBuilder()
            .setStatusCode(response.statusCode)
            .putAllHeaders(response.headers)
            .setBody(com.google.protobuf.ByteString.copyFrom(response.body))
            .build()
        val resBytes = resProto.toByteArray()

        val responseBytes = uniffi.authorizeRes(resBytes, requestBytes, metadata, optionsBytes)

        // 6. Deserialize and return
        return PaymentServiceAuthorizeResponse.parseFrom(responseBytes)
    }
}