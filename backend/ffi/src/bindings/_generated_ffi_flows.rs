// AUTO-GENERATED — do not edit by hand.
// Source: services.proto ∩ services/payments.rs  |  Regenerate: make generate

use grpc_api_types::payments::{
    CustomerServiceCreateRequest,
    MerchantAuthenticationServiceCreateAccessTokenRequest,
    PaymentServiceAuthorizeRequest,
    PaymentServiceCaptureRequest,
    PaymentServiceCreateOrderRequest,
    PaymentServiceGetRequest,
    PaymentServiceRefundRequest,
    PaymentServiceReverseRequest,
    PaymentServiceVoidRequest,
    RecurringPaymentServiceChargeRequest,
};
use crate::handlers::payments::{
    authorize_req_handler, authorize_res_handler,
    capture_req_handler, capture_res_handler,
    charge_req_handler, charge_res_handler,
    create_req_handler, create_res_handler,
    create_access_token_req_handler, create_access_token_res_handler,
    create_order_req_handler, create_order_res_handler,
    get_req_handler, get_res_handler,
    refund_req_handler, refund_res_handler,
    reverse_req_handler, reverse_res_handler,
    void_req_handler, void_res_handler,
};

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
// get: PaymentService.Get — Retrieve current payment status from the payment processor. Enables synchronization between your system and payment processors for accurate state tracking.
define_ffi_flow!(get, PaymentServiceGetRequest, get_req_handler, get_res_handler);
// refund: PaymentService.Refund — Initiate a refund to customer's payment method. Returns funds for returns, cancellations, or service adjustments after original payment.
define_ffi_flow!(refund, PaymentServiceRefundRequest, refund_req_handler, refund_res_handler);
// reverse: PaymentService.Reverse — Reverse a captured payment before settlement. Recovers funds after capture but before bank settlement, used for corrections or cancellations.
define_ffi_flow!(reverse, PaymentServiceReverseRequest, reverse_req_handler, reverse_res_handler);
// void: PaymentService.Void — Cancel an authorized payment before capture. Releases held funds back to customer, typically used when orders are cancelled or abandoned.
define_ffi_flow!(void, PaymentServiceVoidRequest, void_req_handler, void_res_handler);
