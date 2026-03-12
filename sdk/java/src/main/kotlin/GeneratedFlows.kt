// AUTO-GENERATED — do not edit by hand.
// Source: services.proto ∩ services/payments.rs  |  Regenerate: make generate

package payments

import types.Payment.*

import uniffi.connector_service_ffi.acceptReqTransformer
import uniffi.connector_service_ffi.acceptResTransformer
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
import uniffi.connector_service_ffi.defendReqTransformer
import uniffi.connector_service_ffi.defendResTransformer
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
import uniffi.connector_service_ffi.submitEvidenceReqTransformer
import uniffi.connector_service_ffi.submitEvidenceResTransformer
import uniffi.connector_service_ffi.tokenizeReqTransformer
import uniffi.connector_service_ffi.tokenizeResTransformer
import uniffi.connector_service_ffi.voidReqTransformer
import uniffi.connector_service_ffi.voidResTransformer
import uniffi.connector_service_ffi.handleEventTransformer

object FlowRegistry {
    val reqTransformers: Map<String, (ByteArray, ByteArray) -> ByteArray> = mapOf(
        "accept" to { requestBytes, optionsBytes -> acceptReqTransformer(requestBytes, emptyMap(), optionsBytes) },
        "authenticate" to { requestBytes, optionsBytes -> authenticateReqTransformer(requestBytes, emptyMap(), optionsBytes) },
        "authorize" to { requestBytes, optionsBytes -> authorizeReqTransformer(requestBytes, emptyMap(), optionsBytes) },
        "capture" to { requestBytes, optionsBytes -> captureReqTransformer(requestBytes, emptyMap(), optionsBytes) },
        "charge" to { requestBytes, optionsBytes -> chargeReqTransformer(requestBytes, emptyMap(), optionsBytes) },
        "create" to { requestBytes, optionsBytes -> createReqTransformer(requestBytes, emptyMap(), optionsBytes) },
        "create_access_token" to { requestBytes, optionsBytes -> createAccessTokenReqTransformer(requestBytes, emptyMap(), optionsBytes) },
        "create_order" to { requestBytes, optionsBytes -> createOrderReqTransformer(requestBytes, emptyMap(), optionsBytes) },
        "create_session_token" to { requestBytes, optionsBytes -> createSessionTokenReqTransformer(requestBytes, emptyMap(), optionsBytes) },
        "defend" to { requestBytes, optionsBytes -> defendReqTransformer(requestBytes, emptyMap(), optionsBytes) },
        "get" to { requestBytes, optionsBytes -> getReqTransformer(requestBytes, emptyMap(), optionsBytes) },
        "post_authenticate" to { requestBytes, optionsBytes -> postAuthenticateReqTransformer(requestBytes, emptyMap(), optionsBytes) },
        "pre_authenticate" to { requestBytes, optionsBytes -> preAuthenticateReqTransformer(requestBytes, emptyMap(), optionsBytes) },
        "refund" to { requestBytes, optionsBytes -> refundReqTransformer(requestBytes, emptyMap(), optionsBytes) },
        "reverse" to { requestBytes, optionsBytes -> reverseReqTransformer(requestBytes, emptyMap(), optionsBytes) },
        "setup_recurring" to { requestBytes, optionsBytes -> setupRecurringReqTransformer(requestBytes, emptyMap(), optionsBytes) },
        "submit_evidence" to { requestBytes, optionsBytes -> submitEvidenceReqTransformer(requestBytes, emptyMap(), optionsBytes) },
        "tokenize" to { requestBytes, optionsBytes -> tokenizeReqTransformer(requestBytes, emptyMap(), optionsBytes) },
        "void" to { requestBytes, optionsBytes -> voidReqTransformer(requestBytes, emptyMap(), optionsBytes) },
    )

    val resTransformers: Map<String, (ByteArray, ByteArray, ByteArray) -> ByteArray> = mapOf(
        "accept" to { responseBytes, requestBytes, optionsBytes -> acceptResTransformer(responseBytes, requestBytes, emptyMap(), optionsBytes) },
        "authenticate" to { responseBytes, requestBytes, optionsBytes -> authenticateResTransformer(responseBytes, requestBytes, emptyMap(), optionsBytes) },
        "authorize" to { responseBytes, requestBytes, optionsBytes -> authorizeResTransformer(responseBytes, requestBytes, emptyMap(), optionsBytes) },
        "capture" to { responseBytes, requestBytes, optionsBytes -> captureResTransformer(responseBytes, requestBytes, emptyMap(), optionsBytes) },
        "charge" to { responseBytes, requestBytes, optionsBytes -> chargeResTransformer(responseBytes, requestBytes, emptyMap(), optionsBytes) },
        "create" to { responseBytes, requestBytes, optionsBytes -> createResTransformer(responseBytes, requestBytes, emptyMap(), optionsBytes) },
        "create_access_token" to { responseBytes, requestBytes, optionsBytes -> createAccessTokenResTransformer(responseBytes, requestBytes, emptyMap(), optionsBytes) },
        "create_order" to { responseBytes, requestBytes, optionsBytes -> createOrderResTransformer(responseBytes, requestBytes, emptyMap(), optionsBytes) },
        "create_session_token" to { responseBytes, requestBytes, optionsBytes -> createSessionTokenResTransformer(responseBytes, requestBytes, emptyMap(), optionsBytes) },
        "defend" to { responseBytes, requestBytes, optionsBytes -> defendResTransformer(responseBytes, requestBytes, emptyMap(), optionsBytes) },
        "get" to { responseBytes, requestBytes, optionsBytes -> getResTransformer(responseBytes, requestBytes, emptyMap(), optionsBytes) },
        "post_authenticate" to { responseBytes, requestBytes, optionsBytes -> postAuthenticateResTransformer(responseBytes, requestBytes, emptyMap(), optionsBytes) },
        "pre_authenticate" to { responseBytes, requestBytes, optionsBytes -> preAuthenticateResTransformer(responseBytes, requestBytes, emptyMap(), optionsBytes) },
        "refund" to { responseBytes, requestBytes, optionsBytes -> refundResTransformer(responseBytes, requestBytes, emptyMap(), optionsBytes) },
        "reverse" to { responseBytes, requestBytes, optionsBytes -> reverseResTransformer(responseBytes, requestBytes, emptyMap(), optionsBytes) },
        "setup_recurring" to { responseBytes, requestBytes, optionsBytes -> setupRecurringResTransformer(responseBytes, requestBytes, emptyMap(), optionsBytes) },
        "submit_evidence" to { responseBytes, requestBytes, optionsBytes -> submitEvidenceResTransformer(responseBytes, requestBytes, emptyMap(), optionsBytes) },
        "tokenize" to { responseBytes, requestBytes, optionsBytes -> tokenizeResTransformer(responseBytes, requestBytes, emptyMap(), optionsBytes) },
        "void" to { responseBytes, requestBytes, optionsBytes -> voidResTransformer(responseBytes, requestBytes, emptyMap(), optionsBytes) },
    )

    // Single-step flows: direct transformer, no HTTP round-trip.
    val directTransformers: Map<String, (ByteArray, ByteArray) -> ByteArray> = mapOf(
        "handle_event" to { requestBytes, optionsBytes -> handleEventTransformer(requestBytes, emptyMap(), optionsBytes) },
    )

}

// Per-service client classes — typed with concrete proto request/response types.

class CustomerClient(
    config: ConnectorConfig,
    defaults: RequestConfig = RequestConfig.getDefaultInstance(),
    libPath: String? = null
) : ConnectorClient(config, defaults, libPath) {
    // create: CustomerService.Create — Create customer record in the payment processor system. Stores customer details for future payment operations without re-sending personal information.
    fun create(request: CustomerServiceCreateRequest, options: RequestConfig? = null): CustomerServiceCreateResponse =
        executeFlow("create", request.toByteArray(), CustomerServiceCreateResponse.parser(), options)

}

class DisputeClient(
    config: ConnectorConfig,
    defaults: RequestConfig = RequestConfig.getDefaultInstance(),
    libPath: String? = null
) : ConnectorClient(config, defaults, libPath) {
    // accept: DisputeService.Accept — Concede dispute and accepts chargeback loss. Acknowledges liability and stops dispute defense process when evidence is insufficient.
    fun accept(request: DisputeServiceAcceptRequest, options: RequestConfig? = null): DisputeServiceAcceptResponse =
        executeFlow("accept", request.toByteArray(), DisputeServiceAcceptResponse.parser(), options)

    // defend: DisputeService.Defend — Submit defense with reason code for dispute. Presents formal argument against customer's chargeback claim with supporting documentation.
    fun defend(request: DisputeServiceDefendRequest, options: RequestConfig? = null): DisputeServiceDefendResponse =
        executeFlow("defend", request.toByteArray(), DisputeServiceDefendResponse.parser(), options)

    // submit_evidence: DisputeService.SubmitEvidence — Upload evidence to dispute customer chargeback. Provides documentation like receipts and delivery proof to contest fraudulent transaction claims.
    fun submit_evidence(request: DisputeServiceSubmitEvidenceRequest, options: RequestConfig? = null): DisputeServiceSubmitEvidenceResponse =
        executeFlow("submit_evidence", request.toByteArray(), DisputeServiceSubmitEvidenceResponse.parser(), options)

}

class EventClient(
    config: ConnectorConfig,
    defaults: RequestConfig = RequestConfig.getDefaultInstance(),
    libPath: String? = null
) : ConnectorClient(config, defaults, libPath) {
    // handle_event: EventService.HandleEvent — Process webhook notifications from connectors. Translates connector events into standardized responses for asynchronous payment state updates.
    fun handle_event(request: EventServiceHandleRequest, options: RequestConfig? = null): EventServiceHandleResponse =
        executeDirect("handle_event", request.toByteArray(), EventServiceHandleResponse.parser(), options)

}

class MerchantAuthenticationClient(
    config: ConnectorConfig,
    defaults: RequestConfig = RequestConfig.getDefaultInstance(),
    libPath: String? = null
) : ConnectorClient(config, defaults, libPath) {
    // create_access_token: MerchantAuthenticationService.CreateAccessToken — Generate short-lived connector authentication token. Provides secure credentials for connector API access without storing secrets client-side.
    fun create_access_token(request: MerchantAuthenticationServiceCreateAccessTokenRequest, options: RequestConfig? = null): MerchantAuthenticationServiceCreateAccessTokenResponse =
        executeFlow("create_access_token", request.toByteArray(), MerchantAuthenticationServiceCreateAccessTokenResponse.parser(), options)

    // create_session_token: MerchantAuthenticationService.CreateSessionToken — Create session token for payment processing. Maintains session state across multiple payment operations for improved security and tracking.
    fun create_session_token(request: MerchantAuthenticationServiceCreateSessionTokenRequest, options: RequestConfig? = null): MerchantAuthenticationServiceCreateSessionTokenResponse =
        executeFlow("create_session_token", request.toByteArray(), MerchantAuthenticationServiceCreateSessionTokenResponse.parser(), options)

}

class PaymentMethodAuthenticationClient(
    config: ConnectorConfig,
    defaults: RequestConfig = RequestConfig.getDefaultInstance(),
    libPath: String? = null
) : ConnectorClient(config, defaults, libPath) {
    // authenticate: PaymentMethodAuthenticationService.Authenticate — Execute 3DS challenge or frictionless verification. Authenticates customer via bank challenge or behind-the-scenes verification for fraud prevention.
    fun authenticate(request: PaymentMethodAuthenticationServiceAuthenticateRequest, options: RequestConfig? = null): PaymentMethodAuthenticationServiceAuthenticateResponse =
        executeFlow("authenticate", request.toByteArray(), PaymentMethodAuthenticationServiceAuthenticateResponse.parser(), options)

    // post_authenticate: PaymentMethodAuthenticationService.PostAuthenticate — Validate authentication results with the issuing bank. Processes bank's authentication decision to determine if payment can proceed.
    fun post_authenticate(request: PaymentMethodAuthenticationServicePostAuthenticateRequest, options: RequestConfig? = null): PaymentMethodAuthenticationServicePostAuthenticateResponse =
        executeFlow("post_authenticate", request.toByteArray(), PaymentMethodAuthenticationServicePostAuthenticateResponse.parser(), options)

    // pre_authenticate: PaymentMethodAuthenticationService.PreAuthenticate — Initiate 3DS flow before payment authorization. Collects device data and prepares authentication context for frictionless or challenge-based verification.
    fun pre_authenticate(request: PaymentMethodAuthenticationServicePreAuthenticateRequest, options: RequestConfig? = null): PaymentMethodAuthenticationServicePreAuthenticateResponse =
        executeFlow("pre_authenticate", request.toByteArray(), PaymentMethodAuthenticationServicePreAuthenticateResponse.parser(), options)

}

class PaymentMethodClient(
    config: ConnectorConfig,
    defaults: RequestConfig = RequestConfig.getDefaultInstance(),
    libPath: String? = null
) : ConnectorClient(config, defaults, libPath) {
    // tokenize: PaymentMethodService.Tokenize — Tokenize payment method for secure storage. Replaces raw card details with secure token for one-click payments and recurring billing.
    fun tokenize(request: PaymentMethodServiceTokenizeRequest, options: RequestConfig? = null): PaymentMethodServiceTokenizeResponse =
        executeFlow("tokenize", request.toByteArray(), PaymentMethodServiceTokenizeResponse.parser(), options)

}

class PaymentClient(
    config: ConnectorConfig,
    defaults: RequestConfig = RequestConfig.getDefaultInstance(),
    libPath: String? = null
) : ConnectorClient(config, defaults, libPath) {
    // authorize: PaymentService.Authorize — Authorize a payment amount on a payment method. This reserves funds without capturing them, essential for verifying availability before finalizing.
    fun authorize(request: PaymentServiceAuthorizeRequest, options: RequestConfig? = null): PaymentServiceAuthorizeResponse =
        executeFlow("authorize", request.toByteArray(), PaymentServiceAuthorizeResponse.parser(), options)

    // capture: PaymentService.Capture — Finalize an authorized payment transaction. Transfers reserved funds from customer to merchant account, completing the payment lifecycle.
    fun capture(request: PaymentServiceCaptureRequest, options: RequestConfig? = null): PaymentServiceCaptureResponse =
        executeFlow("capture", request.toByteArray(), PaymentServiceCaptureResponse.parser(), options)

    // create_order: PaymentService.CreateOrder — Initialize an order in the payment processor system. Sets up payment context before customer enters card details for improved authorization rates.
    fun create_order(request: PaymentServiceCreateOrderRequest, options: RequestConfig? = null): PaymentServiceCreateOrderResponse =
        executeFlow("create_order", request.toByteArray(), PaymentServiceCreateOrderResponse.parser(), options)

    // get: PaymentService.Get — Retrieve current payment status from the payment processor. Enables synchronization between your system and payment processors for accurate state tracking.
    fun get(request: PaymentServiceGetRequest, options: RequestConfig? = null): PaymentServiceGetResponse =
        executeFlow("get", request.toByteArray(), PaymentServiceGetResponse.parser(), options)

    // refund: PaymentService.Refund — Initiate a refund to customer's payment method. Returns funds for returns, cancellations, or service adjustments after original payment.
    fun refund(request: PaymentServiceRefundRequest, options: RequestConfig? = null): RefundResponse =
        executeFlow("refund", request.toByteArray(), RefundResponse.parser(), options)

    // reverse: PaymentService.Reverse — Reverse a captured payment before settlement. Recovers funds after capture but before bank settlement, used for corrections or cancellations.
    fun reverse(request: PaymentServiceReverseRequest, options: RequestConfig? = null): PaymentServiceReverseResponse =
        executeFlow("reverse", request.toByteArray(), PaymentServiceReverseResponse.parser(), options)

    // setup_recurring: PaymentService.SetupRecurring — Setup a recurring payment instruction for future payments/ debits. This could be for SaaS subscriptions, monthly bill payments, insurance payments and similar use cases.
    fun setup_recurring(request: PaymentServiceSetupRecurringRequest, options: RequestConfig? = null): PaymentServiceSetupRecurringResponse =
        executeFlow("setup_recurring", request.toByteArray(), PaymentServiceSetupRecurringResponse.parser(), options)

    // void: PaymentService.Void — Cancel an authorized payment before capture. Releases held funds back to customer, typically used when orders are cancelled or abandoned.
    fun void(request: PaymentServiceVoidRequest, options: RequestConfig? = null): PaymentServiceVoidResponse =
        executeFlow("void", request.toByteArray(), PaymentServiceVoidResponse.parser(), options)

}

class RecurringPaymentClient(
    config: ConnectorConfig,
    defaults: RequestConfig = RequestConfig.getDefaultInstance(),
    libPath: String? = null
) : ConnectorClient(config, defaults, libPath) {
    // charge: RecurringPaymentService.Charge — Charge using an existing stored recurring payment instruction. Processes repeat payments for subscriptions or recurring billing without collecting payment details.
    fun charge(request: RecurringPaymentServiceChargeRequest, options: RequestConfig? = null): RecurringPaymentServiceChargeResponse =
        executeFlow("charge", request.toByteArray(), RecurringPaymentServiceChargeResponse.parser(), options)

}
