// AUTO-GENERATED — do not edit by hand.
// Source: services.proto ∩ services/payments.rs  |  Regenerate: make generate

use grpc_api_types::payments::{
    CustomerServiceCreateRequest,
    CustomerServiceCreateResponse,
    MerchantAuthenticationServiceCreateAccessTokenRequest,
    MerchantAuthenticationServiceCreateAccessTokenResponse,
    PaymentServiceAuthorizeRequest,
    PaymentServiceAuthorizeResponse,
    PaymentServiceCaptureRequest,
    PaymentServiceCaptureResponse,
    PaymentServiceGetRequest,
    PaymentServiceGetResponse,
    PaymentServiceRefundRequest,
    PaymentServiceReverseRequest,
    PaymentServiceReverseResponse,
    PaymentServiceVoidRequest,
    PaymentServiceVoidResponse,
    RecurringPaymentServiceChargeRequest,
    RecurringPaymentServiceChargeResponse,
    RefundResponse,
};
use crate::services::payments::{
    authorize_req_transformer, authorize_res_transformer,
    capture_req_transformer, capture_res_transformer,
    charge_req_transformer, charge_res_transformer,
    create_req_transformer, create_res_transformer,
    create_access_token_req_transformer, create_access_token_res_transformer,
    get_req_transformer, get_res_transformer,
    refund_req_transformer, refund_res_transformer,
    reverse_req_transformer, reverse_res_transformer,
    void_req_transformer, void_res_transformer,
};

// authorize: PaymentService.Authorize — Authorize a payment amount on a payment method. This reserves funds without capturing them, essential for verifying availability before finalizing.
impl_flow_handlers!(authorize, PaymentServiceAuthorizeRequest, PaymentServiceAuthorizeResponse, authorize_req_transformer, authorize_res_transformer);
// capture: PaymentService.Capture — Finalize an authorized payment transaction. Transfers reserved funds from customer to merchant account, completing the payment lifecycle.
impl_flow_handlers!(capture, PaymentServiceCaptureRequest, PaymentServiceCaptureResponse, capture_req_transformer, capture_res_transformer);
// charge: RecurringPaymentService.Charge — Charge using an existing stored recurring payment instruction. Processes repeat payments for subscriptions or recurring billing without collecting payment details.
impl_flow_handlers!(charge, RecurringPaymentServiceChargeRequest, RecurringPaymentServiceChargeResponse, charge_req_transformer, charge_res_transformer);
// create: CustomerService.Create — Create customer record in the payment processor system. Stores customer details for future payment operations without re-sending personal information.
impl_flow_handlers!(create, CustomerServiceCreateRequest, CustomerServiceCreateResponse, create_req_transformer, create_res_transformer);
// create_access_token: MerchantAuthenticationService.CreateAccessToken — Generate short-lived connector authentication token. Provides secure credentials for connector API access without storing secrets client-side.
impl_flow_handlers!(create_access_token, MerchantAuthenticationServiceCreateAccessTokenRequest, MerchantAuthenticationServiceCreateAccessTokenResponse, create_access_token_req_transformer, create_access_token_res_transformer);
// get: PaymentService.Get — Retrieve current payment status from the payment processor. Enables synchronization between your system and payment processors for accurate state tracking.
impl_flow_handlers!(get, PaymentServiceGetRequest, PaymentServiceGetResponse, get_req_transformer, get_res_transformer);
// refund: PaymentService.Refund — Initiate a refund to customer's payment method. Returns funds for returns, cancellations, or service adjustments after original payment.
impl_flow_handlers!(refund, PaymentServiceRefundRequest, RefundResponse, refund_req_transformer, refund_res_transformer);
// reverse: PaymentService.Reverse — Reverse a captured payment before settlement. Recovers funds after capture but before bank settlement, used for corrections or cancellations.
impl_flow_handlers!(reverse, PaymentServiceReverseRequest, PaymentServiceReverseResponse, reverse_req_transformer, reverse_res_transformer);
// void: PaymentService.Void — Cancel an authorized payment before capture. Releases held funds back to customer, typically used when orders are cancelled or abandoned.
impl_flow_handlers!(void, PaymentServiceVoidRequest, PaymentServiceVoidResponse, void_req_transformer, void_res_transformer);
