// AUTO-GENERATED — do not edit by hand.
// Source: services.proto ∩ services/payments.rs  |  Regenerate: make generate

package payments

import uniffi.connector_service_ffi.authorizeReqTransformer
import uniffi.connector_service_ffi.authorizeResTransformer
import uniffi.connector_service_ffi.captureReqTransformer
import uniffi.connector_service_ffi.captureResTransformer
import uniffi.connector_service_ffi.createAccessTokenReqTransformer
import uniffi.connector_service_ffi.createAccessTokenResTransformer
import uniffi.connector_service_ffi.getReqTransformer
import uniffi.connector_service_ffi.getResTransformer
import uniffi.connector_service_ffi.refundReqTransformer
import uniffi.connector_service_ffi.refundResTransformer
import uniffi.connector_service_ffi.voidReqTransformer
import uniffi.connector_service_ffi.voidResTransformer

object FlowRegistry {
    val reqTransformers: Map<String, (ByteArray, Map<String, String>, ByteArray) -> ByteArray> = mapOf(
        "authorize" to ::authorizeReqTransformer,
        "capture" to ::captureReqTransformer,
        "create_access_token" to ::createAccessTokenReqTransformer,
        "get" to ::getReqTransformer,
        "refund" to ::refundReqTransformer,
        "void" to ::voidReqTransformer,
    )

    val resTransformers: Map<String, (ByteArray, ByteArray, Map<String, String>, ByteArray) -> ByteArray> = mapOf(
        "authorize" to ::authorizeResTransformer,
        "capture" to ::captureResTransformer,
        "create_access_token" to ::createAccessTokenResTransformer,
        "get" to ::getResTransformer,
        "refund" to ::refundResTransformer,
        "void" to ::voidResTransformer,
    )
}

// Extension functions — typed with concrete proto request/response types.

// authorize: PaymentService.Authorize — Authorize a payment amount on a payment method. This reserves funds without capturing them, essential for verifying availability before finalizing.
fun ConnectorClient.authorize(request: PaymentServiceAuthorizeRequest, metadata: Map<String, String>, options: RequestOptions? = null): PaymentServiceAuthorizeResponse =
    executeFlow("authorize", request.toByteArray(), PaymentServiceAuthorizeResponse.parser(), metadata, options)

// capture: PaymentService.Capture — Finalize an authorized payment transaction. Transfers reserved funds from customer to merchant account, completing the payment lifecycle.
fun ConnectorClient.capture(request: PaymentServiceCaptureRequest, metadata: Map<String, String>, options: RequestOptions? = null): PaymentServiceCaptureResponse =
    executeFlow("capture", request.toByteArray(), PaymentServiceCaptureResponse.parser(), metadata, options)

// create_access_token: MerchantAuthenticationService.CreateAccessToken — Generate short-lived connector authentication token. Provides secure credentials for connector API access without storing secrets client-side.
fun ConnectorClient.create_access_token(request: MerchantAuthenticationServiceCreateAccessTokenRequest, metadata: Map<String, String>, options: RequestOptions? = null): MerchantAuthenticationServiceCreateAccessTokenResponse =
    executeFlow("create_access_token", request.toByteArray(), MerchantAuthenticationServiceCreateAccessTokenResponse.parser(), metadata, options)

// get: PaymentService.Get — Retrieve current payment status from the payment processor. Enables synchronization between your system and payment processors for accurate state tracking.
fun ConnectorClient.get(request: PaymentServiceGetRequest, metadata: Map<String, String>, options: RequestOptions? = null): PaymentServiceGetResponse =
    executeFlow("get", request.toByteArray(), PaymentServiceGetResponse.parser(), metadata, options)

// refund: PaymentService.Refund — Initiate a refund to customer's payment method. Returns funds for returns, cancellations, or service adjustments after original payment.
fun ConnectorClient.refund(request: PaymentServiceRefundRequest, metadata: Map<String, String>, options: RequestOptions? = null): RefundResponse =
    executeFlow("refund", request.toByteArray(), RefundResponse.parser(), metadata, options)

// void: PaymentService.Void — Cancel an authorized payment before capture. Releases held funds back to customer, typically used when orders are cancelled or abandoned.
fun ConnectorClient.void(request: PaymentServiceVoidRequest, metadata: Map<String, String>, options: RequestOptions? = null): PaymentServiceVoidResponse =
    executeFlow("void", request.toByteArray(), PaymentServiceVoidResponse.parser(), metadata, options)
