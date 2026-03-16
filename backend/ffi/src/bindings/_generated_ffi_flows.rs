// AUTO-GENERATED — do not edit by hand.
// Source: services.proto ∩ services/payments.rs  |  Regenerate: make generate

use grpc_api_types::payments::{
    CustomerServiceCreateRequest,
    MerchantAuthenticationServiceCreateAccessTokenRequest,
    MerchantAuthenticationServiceCreateSessionTokenRequest,
    PaymentMethodAuthenticationServiceAuthenticateRequest,
    PaymentMethodAuthenticationServicePostAuthenticateRequest,
    PaymentMethodAuthenticationServicePreAuthenticateRequest,
    PaymentMethodServiceTokenizeRequest,
    PaymentServiceAuthorizeRequest,
    PaymentServiceCaptureRequest,
    PaymentServiceCreateOrderRequest,
    PaymentServiceGetRequest,
    PaymentServiceRefundRequest,
    PaymentServiceReverseRequest,
    PaymentServiceSetupRecurringRequest,
    PaymentServiceVoidRequest,
    RecurringPaymentServiceChargeRequest,
};
use grpc_api_types::payouts::PayoutServiceCreateRequest;
use crate::handlers::payments::{
    authenticate_req_handler, authenticate_res_handler,
    authorize_req_handler, authorize_res_handler,
    capture_req_handler, capture_res_handler,
    charge_req_handler, charge_res_handler,
    create_req_handler, create_res_handler,
    create_access_token_req_handler, create_access_token_res_handler,
    create_order_req_handler, create_order_res_handler,
    create_session_token_req_handler, create_session_token_res_handler,
    get_req_handler, get_res_handler,
    post_authenticate_req_handler, post_authenticate_res_handler,
    pre_authenticate_req_handler, pre_authenticate_res_handler,
    refund_req_handler, refund_res_handler,
    reverse_req_handler, reverse_res_handler,
    setup_recurring_req_handler, setup_recurring_res_handler,
    tokenize_req_handler, tokenize_res_handler,
    void_req_handler, void_res_handler,
    create_payout_req_handler, create_payout_res_handler,
};

// authenticate: PaymentMethodAuthenticationService.Authenticate — Execute 3DS challenge or frictionless verification. Authenticates customer via bank challenge or behind-the-scenes verification for fraud prevention.
define_ffi_flow!(authenticate, PaymentMethodAuthenticationServiceAuthenticateRequest, authenticate_req_handler, authenticate_res_handler);
// authorize: PaymentService.Authorize — Authorize a payment amount on a payment method. This reserves funds without capturing them, essential for verifying availability before finalizing.
define_ffi_flow!(authorize, PaymentServiceAuthorizeRequest, authorize_req_handler, authorize_res_handler);
// capture: PaymentService.Capture — Finalize an authorized payment transaction. Transfers reserved funds from customer to merchant account, completing the payment lifecycle.
define_ffi_flow!(capture, PaymentServiceCaptureRequest, capture_req_handler, capture_res_handler);
// charge: RecurringPaymentService.Charge — Charge using an existing stored recurring payment instruction. Processes repeat payments for subscriptions or recurring billing without collecting payment details.
define_ffi_flow!(charge, RecurringPaymentServiceChargeRequest, charge_req_handler, charge_res_handler);
// create: CustomerService.Create — Create customer record in the payment processor system. Stores customer details for future payment operations without re-sending personal information.
define_ffi_flow!(create, CustomerServiceCreateRequest, create_req_handler, create_res_handler);
// create_access_token: MerchantAuthenticationService.CreateAccessToken — Generate short-lived connector authentication token. Provides secure credentials for connector API access without storing secrets client-side.
define_ffi_flow!(create_access_token, MerchantAuthenticationServiceCreateAccessTokenRequest, create_access_token_req_handler, create_access_token_res_handler);
// create_order: PaymentService.CreateOrder — Initialize an order in the payment processor system. Sets up payment context before customer enters card details for improved authorization rates.
define_ffi_flow!(create_order, PaymentServiceCreateOrderRequest, create_order_req_handler, create_order_res_handler);
// create_session_token: MerchantAuthenticationService.CreateSessionToken — Create session token for payment processing. Maintains session state across multiple payment operations for improved security and tracking.
define_ffi_flow!(create_session_token, MerchantAuthenticationServiceCreateSessionTokenRequest, create_session_token_req_handler, create_session_token_res_handler);
// get: PaymentService.Get — Retrieve current payment status from the payment processor. Enables synchronization between your system and payment processors for accurate state tracking.
define_ffi_flow!(get, PaymentServiceGetRequest, get_req_handler, get_res_handler);
// post_authenticate: PaymentMethodAuthenticationService.PostAuthenticate — Validate authentication results with the issuing bank. Processes bank's authentication decision to determine if payment can proceed.
define_ffi_flow!(post_authenticate, PaymentMethodAuthenticationServicePostAuthenticateRequest, post_authenticate_req_handler, post_authenticate_res_handler);
// pre_authenticate: PaymentMethodAuthenticationService.PreAuthenticate — Initiate 3DS flow before payment authorization. Collects device data and prepares authentication context for frictionless or challenge-based verification.
define_ffi_flow!(pre_authenticate, PaymentMethodAuthenticationServicePreAuthenticateRequest, pre_authenticate_req_handler, pre_authenticate_res_handler);
// refund: PaymentService.Refund — Initiate a refund to customer's payment method. Returns funds for returns, cancellations, or service adjustments after original payment.
define_ffi_flow!(refund, PaymentServiceRefundRequest, refund_req_handler, refund_res_handler);
// reverse: PaymentService.Reverse — Reverse a captured payment before settlement. Recovers funds after capture but before bank settlement, used for corrections or cancellations.
define_ffi_flow!(reverse, PaymentServiceReverseRequest, reverse_req_handler, reverse_res_handler);
// setup_recurring: PaymentService.SetupRecurring — Setup a recurring payment instruction for future payments/ debits. This could be for SaaS subscriptions, monthly bill payments, insurance payments and similar use cases.
define_ffi_flow!(setup_recurring, PaymentServiceSetupRecurringRequest, setup_recurring_req_handler, setup_recurring_res_handler);
// tokenize: PaymentMethodService.Tokenize — Tokenize payment method for secure storage. Replaces raw card details with secure token for one-click payments and recurring billing.
define_ffi_flow!(tokenize, PaymentMethodServiceTokenizeRequest, tokenize_req_handler, tokenize_res_handler);
// void: PaymentService.Void — Cancel an authorized payment before capture. Releases held funds back to customer, typically used when orders are cancelled or abandoned.
define_ffi_flow!(void, PaymentServiceVoidRequest, void_req_handler, void_res_handler);

// create_payout: PayoutService.Create — Create a payout.
define_ffi_flow!(create_payout, PayoutServiceCreateRequest, create_payout_req_handler, create_payout_res_handler);
