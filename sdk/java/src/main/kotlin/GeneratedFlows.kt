// AUTO-GENERATED — do not edit by hand.
// Source: services.proto ∩ services/payments.rs  |  Regenerate: make generate

package payments

import ucs.v2.Payment.*

import uniffi.connector_service_ffi.authenticateReqTransformer
import uniffi.connector_service_ffi.authenticateResTransformer
import uniffi.connector_service_ffi.authorizeReqTransformer
import uniffi.connector_service_ffi.authorizeResTransformer
import uniffi.connector_service_ffi.captureReqTransformer
import uniffi.connector_service_ffi.captureResTransformer
import uniffi.connector_service_ffi.chargeReqTransformer
import uniffi.connector_service_ffi.chargeResTransformer
import uniffi.connector_service_ffi.createReqTransformer
import uniffi.connector_service_ffi.createResTransformer
import uniffi.connector_service_ffi.createAccessTokenReqTransformer
import uniffi.connector_service_ffi.createAccessTokenResTransformer
import uniffi.connector_service_ffi.createOrderReqTransformer
import uniffi.connector_service_ffi.createOrderResTransformer
import uniffi.connector_service_ffi.createSessionTokenReqTransformer
import uniffi.connector_service_ffi.createSessionTokenResTransformer
import uniffi.connector_service_ffi.getReqTransformer
import uniffi.connector_service_ffi.getResTransformer
import uniffi.connector_service_ffi.postAuthenticateReqTransformer
import uniffi.connector_service_ffi.postAuthenticateResTransformer
import uniffi.connector_service_ffi.preAuthenticateReqTransformer
import uniffi.connector_service_ffi.preAuthenticateResTransformer
import uniffi.connector_service_ffi.refundReqTransformer
import uniffi.connector_service_ffi.refundResTransformer
import uniffi.connector_service_ffi.reverseReqTransformer
import uniffi.connector_service_ffi.reverseResTransformer
import uniffi.connector_service_ffi.setupRecurringReqTransformer
import uniffi.connector_service_ffi.setupRecurringResTransformer
import uniffi.connector_service_ffi.tokenizeReqTransformer
import uniffi.connector_service_ffi.tokenizeResTransformer
import uniffi.connector_service_ffi.voidReqTransformer
import uniffi.connector_service_ffi.voidResTransformer
import uniffi.connector_service_ffi.handleEventTransformer

object FlowRegistry {
    val reqTransformers: Map<String, (ByteArray, Map<String, String>, ByteArray) -> ByteArray> = mapOf(
        "authenticate" to ::authenticateReqTransformer,
        "authorize" to ::authorizeReqTransformer,
        "capture" to ::captureReqTransformer,
        "charge" to ::chargeReqTransformer,
        "create" to ::createReqTransformer,
        "create_access_token" to ::createAccessTokenReqTransformer,
        "create_order" to ::createOrderReqTransformer,
        "create_session_token" to ::createSessionTokenReqTransformer,
        "get" to ::getReqTransformer,
        "post_authenticate" to ::postAuthenticateReqTransformer,
        "pre_authenticate" to ::preAuthenticateReqTransformer,
        "refund" to ::refundReqTransformer,
        "reverse" to ::reverseReqTransformer,
        "setup_recurring" to ::setupRecurringReqTransformer,
        "tokenize" to ::tokenizeReqTransformer,
        "void" to ::voidReqTransformer,
    )

    val resTransformers: Map<String, (ByteArray, ByteArray, Map<String, String>, ByteArray) -> ByteArray> = mapOf(
        "authenticate" to ::authenticateResTransformer,
        "authorize" to ::authorizeResTransformer,
        "capture" to ::captureResTransformer,
        "charge" to ::chargeResTransformer,
        "create" to ::createResTransformer,
        "create_access_token" to ::createAccessTokenResTransformer,
        "create_order" to ::createOrderResTransformer,
        "create_session_token" to ::createSessionTokenResTransformer,
        "get" to ::getResTransformer,
        "post_authenticate" to ::postAuthenticateResTransformer,
        "pre_authenticate" to ::preAuthenticateResTransformer,
        "refund" to ::refundResTransformer,
        "reverse" to ::reverseResTransformer,
        "setup_recurring" to ::setupRecurringResTransformer,
        "tokenize" to ::tokenizeResTransformer,
        "void" to ::voidResTransformer,
    )

    // Single-step flows: direct transformer, no HTTP round-trip.
    val directTransformers: Map<String, (ByteArray, Map<String, String>, ByteArray) -> ByteArray> = mapOf(
        "handle_event" to ::handleEventTransformer,
    )

}

// Per-service client classes — typed with concrete proto request/response types.

class CustomerClient(libPath: String? = null, options: Options = Options.getDefaultInstance()) : ConnectorClient(libPath, options) {
    // create: CustomerService.Create — Create customer record in the payment processor system. Stores customer details for future payment operations without re-sending personal information.
    fun create(request: CustomerServiceCreateRequest, metadata: Map<String, String>, options: FfiOptions? = null): CustomerServiceCreateResponse =
        executeFlow("create", request.toByteArray(), CustomerServiceCreateResponse.parser(), metadata, options?.toByteArray())

}

class EventClient(libPath: String? = null, options: Options = Options.getDefaultInstance()) : ConnectorClient(libPath, options) {
    // handle_event: EventService.HandleEvent — Process webhook notifications from connectors. Translates connector events into standardized responses for asynchronous payment state updates.
    fun handle_event(request: EventServiceHandleRequest, metadata: Map<String, String>, options: FfiOptions? = null): EventServiceHandleResponse =
        executeDirect("handle_event", request.toByteArray(), EventServiceHandleResponse.parser(), metadata, options?.toByteArray())

}

class MerchantAuthenticationClient(libPath: String? = null, options: Options = Options.getDefaultInstance()) : ConnectorClient(libPath, options) {
    // create_access_token: MerchantAuthenticationService.CreateAccessToken — Generate short-lived connector authentication token. Provides secure credentials for connector API access without storing secrets client-side.
    fun create_access_token(request: MerchantAuthenticationServiceCreateAccessTokenRequest, metadata: Map<String, String>, options: FfiOptions? = null): MerchantAuthenticationServiceCreateAccessTokenResponse =
        executeFlow("create_access_token", request.toByteArray(), MerchantAuthenticationServiceCreateAccessTokenResponse.parser(), metadata, options?.toByteArray())

    // create_session_token: MerchantAuthenticationService.CreateSessionToken — Create session token for payment processing. Maintains session state across multiple payment operations for improved security and tracking.
    fun create_session_token(request: MerchantAuthenticationServiceCreateSessionTokenRequest, metadata: Map<String, String>, options: FfiOptions? = null): MerchantAuthenticationServiceCreateSessionTokenResponse =
        executeFlow("create_session_token", request.toByteArray(), MerchantAuthenticationServiceCreateSessionTokenResponse.parser(), metadata, options?.toByteArray())

}

class PaymentMethodAuthenticationClient(libPath: String? = null, options: Options = Options.getDefaultInstance()) : ConnectorClient(libPath, options) {
    // authenticate: PaymentMethodAuthenticationService.Authenticate — Execute 3DS challenge or frictionless verification. Authenticates customer via bank challenge or behind-the-scenes verification for fraud prevention.
    fun authenticate(request: PaymentMethodAuthenticationServiceAuthenticateRequest, metadata: Map<String, String>, options: FfiOptions? = null): PaymentMethodAuthenticationServiceAuthenticateResponse =
        executeFlow("authenticate", request.toByteArray(), PaymentMethodAuthenticationServiceAuthenticateResponse.parser(), metadata, options?.toByteArray())

    // post_authenticate: PaymentMethodAuthenticationService.PostAuthenticate — Validate authentication results with the issuing bank. Processes bank's authentication decision to determine if payment can proceed.
    fun post_authenticate(request: PaymentMethodAuthenticationServicePostAuthenticateRequest, metadata: Map<String, String>, options: FfiOptions? = null): PaymentMethodAuthenticationServicePostAuthenticateResponse =
        executeFlow("post_authenticate", request.toByteArray(), PaymentMethodAuthenticationServicePostAuthenticateResponse.parser(), metadata, options?.toByteArray())

    // pre_authenticate: PaymentMethodAuthenticationService.PreAuthenticate — Initiate 3DS flow before payment authorization. Collects device data and prepares authentication context for frictionless or challenge-based verification.
    fun pre_authenticate(request: PaymentMethodAuthenticationServicePreAuthenticateRequest, metadata: Map<String, String>, options: FfiOptions? = null): PaymentMethodAuthenticationServicePreAuthenticateResponse =
        executeFlow("pre_authenticate", request.toByteArray(), PaymentMethodAuthenticationServicePreAuthenticateResponse.parser(), metadata, options?.toByteArray())

}

class PaymentMethodClient(libPath: String? = null, options: Options = Options.getDefaultInstance()) : ConnectorClient(libPath, options) {
    // tokenize: PaymentMethodService.Tokenize — Tokenize payment method for secure storage. Replaces raw card details with secure token for one-click payments and recurring billing.
    fun tokenize(request: PaymentMethodServiceTokenizeRequest, metadata: Map<String, String>, options: FfiOptions? = null): PaymentMethodServiceTokenizeResponse =
        executeFlow("tokenize", request.toByteArray(), PaymentMethodServiceTokenizeResponse.parser(), metadata, options?.toByteArray())

}

class PaymentClient(libPath: String? = null, options: Options = Options.getDefaultInstance()) : ConnectorClient(libPath, options) {
    // authorize: PaymentService.Authorize — Authorize a payment amount on a payment method. This reserves funds without capturing them, essential for verifying availability before finalizing.
    fun authorize(request: PaymentServiceAuthorizeRequest, metadata: Map<String, String>, options: FfiOptions? = null): PaymentServiceAuthorizeResponse =
        executeFlow("authorize", request.toByteArray(), PaymentServiceAuthorizeResponse.parser(), metadata, options?.toByteArray())

    // capture: PaymentService.Capture — Finalize an authorized payment transaction. Transfers reserved funds from customer to merchant account, completing the payment lifecycle.
    fun capture(request: PaymentServiceCaptureRequest, metadata: Map<String, String>, options: FfiOptions? = null): PaymentServiceCaptureResponse =
        executeFlow("capture", request.toByteArray(), PaymentServiceCaptureResponse.parser(), metadata, options?.toByteArray())

    // create_order: PaymentService.CreateOrder — Initialize an order in the payment processor system. Sets up payment context before customer enters card details for improved authorization rates.
    fun create_order(request: PaymentServiceCreateOrderRequest, metadata: Map<String, String>, options: FfiOptions? = null): PaymentServiceCreateOrderResponse =
        executeFlow("create_order", request.toByteArray(), PaymentServiceCreateOrderResponse.parser(), metadata, options?.toByteArray())

    // get: PaymentService.Get — Retrieve current payment status from the payment processor. Enables synchronization between your system and payment processors for accurate state tracking.
    fun get(request: PaymentServiceGetRequest, metadata: Map<String, String>, options: FfiOptions? = null): PaymentServiceGetResponse =
        executeFlow("get", request.toByteArray(), PaymentServiceGetResponse.parser(), metadata, options?.toByteArray())

    // refund: PaymentService.Refund — Initiate a refund to customer's payment method. Returns funds for returns, cancellations, or service adjustments after original payment.
    fun refund(request: PaymentServiceRefundRequest, metadata: Map<String, String>, options: FfiOptions? = null): RefundResponse =
        executeFlow("refund", request.toByteArray(), RefundResponse.parser(), metadata, options?.toByteArray())

    // reverse: PaymentService.Reverse — Reverse a captured payment before settlement. Recovers funds after capture but before bank settlement, used for corrections or cancellations.
    fun reverse(request: PaymentServiceReverseRequest, metadata: Map<String, String>, options: FfiOptions? = null): PaymentServiceReverseResponse =
        executeFlow("reverse", request.toByteArray(), PaymentServiceReverseResponse.parser(), metadata, options?.toByteArray())

    // setup_recurring: PaymentService.SetupRecurring — Setup a recurring payment instruction for future payments/ debits. This could be for SaaS subscriptions, monthly bill payments, insurance payments and similar use cases.
    fun setup_recurring(request: PaymentServiceSetupRecurringRequest, metadata: Map<String, String>, options: FfiOptions? = null): PaymentServiceSetupRecurringResponse =
        executeFlow("setup_recurring", request.toByteArray(), PaymentServiceSetupRecurringResponse.parser(), metadata, options?.toByteArray())

    // void: PaymentService.Void — Cancel an authorized payment before capture. Releases held funds back to customer, typically used when orders are cancelled or abandoned.
    fun void(request: PaymentServiceVoidRequest, metadata: Map<String, String>, options: FfiOptions? = null): PaymentServiceVoidResponse =
        executeFlow("void", request.toByteArray(), PaymentServiceVoidResponse.parser(), metadata, options?.toByteArray())

}

class RecurringPaymentClient(libPath: String? = null, options: Options = Options.getDefaultInstance()) : ConnectorClient(libPath, options) {
    // charge: RecurringPaymentService.Charge — Charge using an existing stored recurring payment instruction. Processes repeat payments for subscriptions or recurring billing without collecting payment details.
    fun charge(request: RecurringPaymentServiceChargeRequest, metadata: Map<String, String>, options: FfiOptions? = null): RecurringPaymentServiceChargeResponse =
        executeFlow("charge", request.toByteArray(), RecurringPaymentServiceChargeResponse.parser(), metadata, options?.toByteArray())

}
