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

import ucs.v2.Payments.PaymentServiceAuthorizeRequest
import ucs.v2.Payments.PaymentServiceAuthorizeResponse
import ucs.v2.SdkOptions.FfiOptions
import ucs.v2.SdkOptions.Options

class ConnectorClient(
    libPath: String? = null,
    private val options: Options = Options.getDefaultInstance()
) {
    private val uniffi = UniffiClient(libPath)

    /**
     * Internal helper to map Protobuf HttpOptions to Native HttpClient options.
     */
    private fun getNativeHttpOptions(): HttpOptions {
        if (!options.hasHttp()) return HttpOptions()
        val proto = options.http

        return HttpOptions(
            totalTimeoutMs = if (proto.hasTotalTimeoutMs()) proto.totalTimeoutMs.toLong() else null,
            connectTimeoutMs = if (proto.hasConnectTimeoutMs()) proto.connectTimeoutMs.toLong() else null,
            responseTimeoutMs = if (proto.hasResponseTimeoutMs()) proto.responseTimeoutMs.toLong() else null,
            keepAliveTimeoutMs = if (proto.hasKeepAliveTimeoutMs()) proto.keepAliveTimeoutMs.toLong() else null,
            proxy = if (proto.hasProxy()) {
                ProxyConfig(
                    httpUrl = if (proto.proxy.hasHttpUrl()) proto.proxy.httpUrl else null,
                    httpsUrl = if (proto.proxy.hasHttpsUrl()) proto.proxy.httpsUrl else null,
                    bypassUrls = proto.proxy.bypassUrlsList ?: emptyList()
                )
            } else null,
            caCert = if (proto.hasCaCert()) proto.caCert.toByteArray() else null
        )
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

        // 4. Execute network call (uses native options mapped from proto)
        val response = HttpClient.execute(connectorRequest, getNativeHttpOptions())

        // 5. Transform connector response via FFI
        // New Step: Serialize native response to Protobuf bytes (Safe)
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
