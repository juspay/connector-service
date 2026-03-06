// AUTO-GENERATED — do not edit by hand.
// Source: services.proto ∩ services/payments.rs  |  Regenerate: make generate

use grpc_api_types::payments::{
    MerchantAuthenticationServiceCreateAccessTokenRequest,
    PaymentServiceAuthorizeRequest,
    PaymentServiceCaptureRequest,
    PaymentServiceGetRequest,
    PaymentServiceRefundRequest,
    PaymentServiceVoidRequest,
};
use crate::handlers::payments::{
    authorize_req_handler, authorize_res_handler,
    capture_req_handler, capture_res_handler,
    create_access_token_req_handler, create_access_token_res_handler,
    get_req_handler, get_res_handler,
    refund_req_handler, refund_res_handler,
    void_req_handler, void_res_handler,
};

// authorize: PaymentService.Authorize — Authorize a payment amount on a payment method. This reserves funds without capturing them, essential for verifying availability before finalizing.
define_ffi_flow!(authorize, PaymentServiceAuthorizeRequest, authorize_req_handler, authorize_res_handler);
// capture: PaymentService.Capture — Finalize an authorized payment transaction. Transfers reserved funds from customer to merchant account, completing the payment lifecycle.
define_ffi_flow!(capture, PaymentServiceCaptureRequest, capture_req_handler, capture_res_handler);
// create_access_token: MerchantAuthenticationService.CreateAccessToken — Generate short-lived connector authentication token. Provides secure credentials for connector API access without storing secrets client-side.
define_ffi_flow!(create_access_token, MerchantAuthenticationServiceCreateAccessTokenRequest, create_access_token_req_handler, create_access_token_res_handler);
// get: PaymentService.Get — Retrieve current payment status from the payment processor. Enables synchronization between your system and payment processors for accurate state tracking.
define_ffi_flow!(get, PaymentServiceGetRequest, get_req_handler, get_res_handler);
// refund: PaymentService.Refund — Initiate a refund to customer's payment method. Returns funds for returns, cancellations, or service adjustments after original payment.
define_ffi_flow!(refund, PaymentServiceRefundRequest, refund_req_handler, refund_res_handler);
// void: PaymentService.Void — Cancel an authorized payment before capture. Releases held funds back to customer, typically used when orders are cancelled or abandoned.
define_ffi_flow!(void, PaymentServiceVoidRequest, void_req_handler, void_res_handler);
