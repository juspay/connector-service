use axum::{
    extract::{Extension, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use grpc_api_types::payments::{
    payment_service_server::PaymentService, DisputeResponse, PaymentServiceAuthenticateRequest,
    PaymentServiceAuthenticateResponse, PaymentServiceAuthorizeOnlyRequest,
    PaymentServiceAuthorizeRequest, PaymentServiceAuthorizeResponse, PaymentServiceCaptureRequest,
    PaymentServiceCaptureResponse, PaymentServiceCreateAccessTokenRequest,
    PaymentServiceCreateAccessTokenResponse, PaymentServiceCreateConnectorCustomerRequest,
    PaymentServiceCreateConnectorCustomerResponse, PaymentServiceCreateOrderRequest,
    PaymentServiceCreateOrderResponse, PaymentServiceCreatePaymentMethodTokenRequest,
    PaymentServiceCreatePaymentMethodTokenResponse, PaymentServiceCreateSessionTokenRequest,
    PaymentServiceCreateSessionTokenResponse, PaymentServiceDisputeRequest,
    PaymentServiceGetRequest, PaymentServiceGetResponse, PaymentServicePostAuthenticateRequest,
    PaymentServicePostAuthenticateResponse, PaymentServicePreAuthenticateRequest,
    PaymentServicePreAuthenticateResponse, PaymentServiceRefundRequest,
    PaymentServiceRegisterRequest, PaymentServiceRegisterResponse,
    PaymentServiceRepeatEverythingRequest, PaymentServiceRepeatEverythingResponse,
    PaymentServiceTransformRequest, PaymentServiceTransformResponse,
    PaymentServiceVerifyRedirectResponseRequest, PaymentServiceVerifyRedirectResponseResponse,
    PaymentServiceVoidPostCaptureRequest, PaymentServiceVoidPostCaptureResponse,
    PaymentServiceVoidRequest, PaymentServiceVoidResponse, RefundResponse,
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
http_handler!(
    authorize_only,
    PaymentServiceAuthorizeOnlyRequest,
    PaymentServiceAuthorizeResponse,
    authorize_only,
    payments_service
);
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
    PaymentServiceVoidPostCaptureRequest,
    PaymentServiceVoidPostCaptureResponse,
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
    PaymentServiceCreateSessionTokenRequest,
    PaymentServiceCreateSessionTokenResponse,
    create_session_token,
    payments_service
);
http_handler!(
    create_connector_customer,
    PaymentServiceCreateConnectorCustomerRequest,
    PaymentServiceCreateConnectorCustomerResponse,
    create_connector_customer,
    payments_service
);
http_handler!(
    create_payment_method_token,
    PaymentServiceCreatePaymentMethodTokenRequest,
    PaymentServiceCreatePaymentMethodTokenResponse,
    create_payment_method_token,
    payments_service
);
http_handler!(
    register,
    PaymentServiceRegisterRequest,
    PaymentServiceRegisterResponse,
    register,
    payments_service
);
http_handler!(
    register_only,
    PaymentServiceRegisterRequest,
    PaymentServiceRegisterResponse,
    register_only,
    payments_service
);
http_handler!(
    repeat_everything,
    PaymentServiceRepeatEverythingRequest,
    PaymentServiceRepeatEverythingResponse,
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
    PaymentServicePreAuthenticateRequest,
    PaymentServicePreAuthenticateResponse,
    pre_authenticate,
    payments_service
);
http_handler!(
    authenticate,
    PaymentServiceAuthenticateRequest,
    PaymentServiceAuthenticateResponse,
    authenticate,
    payments_service
);
http_handler!(
    post_authenticate,
    PaymentServicePostAuthenticateRequest,
    PaymentServicePostAuthenticateResponse,
    post_authenticate,
    payments_service
);
http_handler!(
    create_access_token,
    PaymentServiceCreateAccessTokenRequest,
    PaymentServiceCreateAccessTokenResponse,
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
