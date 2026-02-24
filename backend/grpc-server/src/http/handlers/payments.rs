use axum::{
    extract::{Extension, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use grpc_api_types::payments::{
    payment_service_server::PaymentService, DisputeResponse,
    PaymentMethodAuthenticationServiceAuthenticateRequest,
    PaymentMethodAuthenticationServicePostAuthenticateRequest,
    PaymentMethodAuthenticationServicePreAuthenticateRequest, PaymentServiceAuthenticateResponse,
     PaymentServiceAuthorizeRequest,
    PaymentServiceAuthorizeResponse, PaymentServiceCaptureRequest, PaymentServiceCaptureResponse,
    MerchantAuthenticationServiceCreateAccessTokenRequest, MerchantAuthenticationServiceCreateAccessTokenResponse,
    CustomerServiceCreateRequest, CustomerServiceCreateResponse,
    PaymentServiceCreateOrderRequest, PaymentServiceCreateOrderResponse,
    PaymentMethodServiceTokenizeRequest, PaymentMethodServiceTokenizeResponse,
    MerchantAuthenticationServiceCreateSessionTokenRequest, PaymentServiceCreateSessionTokenResponse,
    PaymentServiceDisputeRequest, PaymentServiceGetRequest, PaymentServiceGetResponse,
    PaymentServicePostAuthenticateResponse, PaymentServicePreAuthenticateResponse,
    PaymentServiceRefundRequest, PaymentServiceRegisterAutoDebitRequest,
    PaymentServiceRegisterAutoDebitResponse, RecurringPaymentServiceChargeResponse,
    PaymentServiceTransformRequest, PaymentServiceTransformResponse,
    PaymentServiceVerifyRedirectResponseRequest, PaymentServiceVerifyRedirectResponseResponse,
    PaymentServiceReverseRequest, PaymentServiceReverseResponse,
    PaymentServiceVoidRequest, PaymentServiceVoidResponse, RecurringPaymentServiceChargeRequest,
    RefundResponse,
};
use std::sync::Arc;

use crate::configs::Config;
use crate::http::handlers::macros::http_handler;
use crate::http::{
    error::HttpError, http_headers_to_grpc_metadata, state::AppState,
    transfer_config_to_grpc_request, utils::ValidatedJson,
};

http_handler!(
    authorize,
    PaymentServiceAuthorizeRequest,
    PaymentServiceAuthorizeResponse,
    authorize,
    payments_service
);
// http_handler!(
//     authorize_only,
//     PaymentServiceAuthorizeOnlyRequest,
//     PaymentServiceAuthorizeResponse,
//     authorize_only,
//     payments_service
// );
http_handler!(
    capture,
    PaymentServiceCaptureRequest,
    PaymentServiceCaptureResponse,
    capture,
    payments_service
);
http_handler!(
    void,
    PaymentServiceVoidRequest,
    PaymentServiceVoidResponse,
    void,
    payments_service
);
http_handler!(
    void_post_capture,
    PaymentServiceReverseRequest,
    PaymentServiceReverseResponse,
    void_post_capture,
    payments_service
);
http_handler!(
    get_payment,
    PaymentServiceGetRequest,
    PaymentServiceGetResponse,
    get,
    payments_service
);
http_handler!(
    create_order,
    PaymentServiceCreateOrderRequest,
    PaymentServiceCreateOrderResponse,
    create_order,
    payments_service
);
http_handler!(
    create_session_token,
    MerchantAuthenticationServiceCreateSessionTokenRequest,
    PaymentServiceCreateSessionTokenResponse,
    create_session_token,
    payments_service
);
http_handler!(
    create_connector_customer,
    CustomerServiceCreateRequest,
    CustomerServiceCreateResponse,
    create_connector_customer,
    payments_service
);
http_handler!(
    create_payment_method_token,
    PaymentMethodServiceTokenizeRequest,
    PaymentMethodServiceTokenizeResponse,
    create_payment_method_token,
    payments_service
);
http_handler!(
    register,
    PaymentServiceRegisterAutoDebitRequest,
    PaymentServiceRegisterAutoDebitResponse,
    register,
    payments_service
);
http_handler!(
    register_only,
    PaymentServiceRegisterAutoDebitRequest,
    PaymentServiceRegisterAutoDebitResponse,
    register_only,
    payments_service
);
http_handler!(
    repeat_everything,
    RecurringPaymentServiceChargeRequest,
    RecurringPaymentServiceChargeResponse,
    repeat_everything,
    payments_service
);
http_handler!(
    refund,
    PaymentServiceRefundRequest,
    RefundResponse,
    refund,
    payments_service
);
http_handler!(
    dispute,
    PaymentServiceDisputeRequest,
    DisputeResponse,
    dispute,
    payments_service
);
http_handler!(
    pre_authenticate,
    PaymentMethodAuthenticationServicePreAuthenticateRequest,
    PaymentServicePreAuthenticateResponse,
    pre_authenticate,
    payments_service
);
http_handler!(
    authenticate,
    PaymentMethodAuthenticationServiceAuthenticateRequest,
    PaymentServiceAuthenticateResponse,
    authenticate,
    payments_service
);
http_handler!(
    post_authenticate,
    PaymentMethodAuthenticationServicePostAuthenticateRequest,
    PaymentServicePostAuthenticateResponse,
    post_authenticate,
    payments_service
);
http_handler!(
    create_access_token,
    MerchantAuthenticationServiceCreateAccessTokenRequest,
    MerchantAuthenticationServiceCreateAccessTokenResponse,
    create_access_token,
    payments_service
);
http_handler!(
    transform,
    PaymentServiceTransformRequest,
    PaymentServiceTransformResponse,
    transform,
    payments_service
);
http_handler!(
    verify_redirect_response,
    PaymentServiceVerifyRedirectResponseRequest,
    PaymentServiceVerifyRedirectResponseResponse,
    verify_redirect_response,
    payments_service
);
