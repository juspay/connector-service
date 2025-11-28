use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use grpc_api_types::payments::{
    DisputeResponse, PaymentServiceAuthenticateRequest, PaymentServiceAuthenticateResponse, PaymentServiceAuthorizeOnlyRequest, PaymentServiceAuthorizeRequest, PaymentServiceAuthorizeResponse, PaymentServiceCaptureRequest, PaymentServiceCaptureResponse, PaymentServiceCreateAccessTokenRequest, PaymentServiceCreateAccessTokenResponse, PaymentServiceCreateConnectorCustomerRequest, PaymentServiceCreateConnectorCustomerResponse, PaymentServiceCreateOrderRequest, PaymentServiceCreateOrderResponse, PaymentServiceCreatePaymentMethodTokenRequest, PaymentServiceCreatePaymentMethodTokenResponse, PaymentServiceCreateSessionTokenRequest, PaymentServiceCreateSessionTokenResponse, PaymentServiceDisputeRequest, PaymentServiceGetRequest, PaymentServiceGetResponse, PaymentServicePostAuthenticateRequest, PaymentServicePostAuthenticateResponse, PaymentServicePreAuthenticateRequest, PaymentServicePreAuthenticateResponse, PaymentServiceRefundRequest, PaymentServiceRegisterRequest, PaymentServiceRegisterResponse, PaymentServiceRepeatEverythingRequest, PaymentServiceRepeatEverythingResponse, PaymentServiceTransformRequest, PaymentServiceTransformResponse, PaymentServiceVoidPostCaptureRequest, PaymentServiceVoidPostCaptureResponse, PaymentServiceVoidRequest, PaymentServiceVoidResponse, RefundResponse, payment_service_server::PaymentService, samsung_wallet::payment_credential
};

use crate::http::{
    error::HttpError, http_headers_to_grpc_metadata, state::AppState, utils::ValidatedJson,
};

pub async fn authorize(
    State(state): State<AppState>,
    headers: HeaderMap,
    ValidatedJson(payload): ValidatedJson<PaymentServiceAuthorizeRequest>,
) -> Result<Json<PaymentServiceAuthorizeResponse>, HttpError> {
    // Create gRPC request with payload
    let mut grpc_request = tonic::Request::new(payload);

    // Convert HTTP headers to gRPC metadata and merge into request
    let grpc_metadata = http_headers_to_grpc_metadata(&headers).map_err(|status| HttpError {
        status: StatusCode::BAD_REQUEST,
        message: status.message().to_string(),
    })?;

    // Merge the converted metadata into the request
    *grpc_request.metadata_mut() = grpc_metadata;

    // Call existing gRPC service implementation
    let grpc_response = state.payments_service.authorize(grpc_request).await?;

    // Extract inner response and return as JSON
    Ok(Json(grpc_response.into_inner()))
}

pub async fn authorize_only(
    State(state): State<AppState>,
    headers: HeaderMap,
    ValidatedJson(payload): ValidatedJson<PaymentServiceAuthorizeOnlyRequest>,
) -> Result<Json<PaymentServiceAuthorizeResponse>, HttpError> {
    let mut grpc_request = tonic::Request::new(payload);
    let grpc_metadata = http_headers_to_grpc_metadata(&headers).map_err(|status| HttpError {
        status: StatusCode::BAD_REQUEST,
        message: status.message().to_string(),
    })?;
    *grpc_request.metadata_mut() = grpc_metadata;
    let grpc_response = state.payments_service.authorize_only(grpc_request).await?;
    Ok(Json(grpc_response.into_inner()))
}

pub async fn capture(
    State(state): State<AppState>,
    headers: HeaderMap,
    ValidatedJson(payload): ValidatedJson<PaymentServiceCaptureRequest>,
) -> Result<Json<PaymentServiceCaptureResponse>, HttpError> {
    let mut grpc_request = tonic::Request::new(payload);
    let grpc_metadata = http_headers_to_grpc_metadata(&headers).map_err(|status| HttpError {
        status: StatusCode::BAD_REQUEST,
        message: status.message().to_string(),
    })?;
    *grpc_request.metadata_mut() = grpc_metadata;
    let grpc_response = state.payments_service.capture(grpc_request).await?;
    Ok(Json(grpc_response.into_inner()))
}

pub async fn void(
    State(state): State<AppState>,
    headers: HeaderMap,
    ValidatedJson(payload): ValidatedJson<PaymentServiceVoidRequest>,
) -> Result<Json<PaymentServiceVoidResponse>, HttpError> {
    let mut grpc_request = tonic::Request::new(payload);
    let grpc_metadata = http_headers_to_grpc_metadata(&headers).map_err(|status| HttpError {
        status: StatusCode::BAD_REQUEST,
        message: status.message().to_string(),
    })?;
    *grpc_request.metadata_mut() = grpc_metadata;
    let grpc_response = state.payments_service.void(grpc_request).await?;
    Ok(Json(grpc_response.into_inner()))
}

pub async fn void_post_capture(
    State(state): State<AppState>,
    headers: HeaderMap,
    ValidatedJson(payload): ValidatedJson<PaymentServiceVoidPostCaptureRequest>,
) -> Result<Json<PaymentServiceVoidPostCaptureResponse>, HttpError> {
    let mut grpc_request = tonic::Request::new(payload);
    let grpc_metadata = http_headers_to_grpc_metadata(&headers).map_err(|status| HttpError {
        status: StatusCode::BAD_REQUEST,
        message: status.message().to_string(),
    })?;
    *grpc_request.metadata_mut() = grpc_metadata;
    let grpc_response = state.payments_service.void_post_capture(grpc_request).await?;
    Ok(Json(grpc_response.into_inner()))
}

pub async fn get_payment(
    State(state): State<AppState>,
    headers: HeaderMap,
    ValidatedJson(payload): ValidatedJson<PaymentServiceGetRequest>,
) -> Result<Json<PaymentServiceGetResponse>, HttpError> {
    let mut grpc_request = tonic::Request::new(payload);
    let grpc_metadata = http_headers_to_grpc_metadata(&headers).map_err(|status| HttpError {
        status: StatusCode::BAD_REQUEST,
        message: status.message().to_string(),
    })?;
    *grpc_request.metadata_mut() = grpc_metadata;
    let grpc_response = state.payments_service.get(grpc_request).await?;
    Ok(Json(grpc_response.into_inner()))
}

pub async fn create_order(
    State(state): State<AppState>,
    headers: HeaderMap,
    ValidatedJson(payload): ValidatedJson<PaymentServiceCreateOrderRequest>,
) -> Result<Json<PaymentServiceCreateOrderResponse>, HttpError> {
    let mut grpc_request = tonic::Request::new(payload);
    let grpc_metadata = http_headers_to_grpc_metadata(&headers).map_err(|status| HttpError {
        status: StatusCode::BAD_REQUEST,
        message: status.message().to_string(),
    })?;
    *grpc_request.metadata_mut() = grpc_metadata;
    let grpc_response = state.payments_service.create_order(grpc_request).await?;
    Ok(Json(grpc_response.into_inner()))
}

pub async fn create_session_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    ValidatedJson(payload): ValidatedJson<PaymentServiceCreateSessionTokenRequest>,
) -> Result<Json<PaymentServiceCreateSessionTokenResponse>, HttpError> {
    let mut grpc_request = tonic::Request::new(payload);
    let grpc_metadata = http_headers_to_grpc_metadata(&headers).map_err(|status| HttpError {
        status: StatusCode::BAD_REQUEST,
        message: status.message().to_string(),
    })?;
    *grpc_request.metadata_mut() = grpc_metadata;
    let grpc_response = state.payments_service.create_session_token(grpc_request).await?;
    Ok(Json(grpc_response.into_inner()))
}

pub async fn create_connector_customer(
    State(state): State<AppState>,
    headers: HeaderMap,
    ValidatedJson(payload): ValidatedJson<PaymentServiceCreateConnectorCustomerRequest>,
) -> Result<Json<PaymentServiceCreateConnectorCustomerResponse>, HttpError> {
    let mut grpc_request = tonic::Request::new(payload);
    let grpc_metadata = http_headers_to_grpc_metadata(&headers).map_err(|status| HttpError {
        status: StatusCode::BAD_REQUEST,
        message: status.message().to_string(),
    })?;
    *grpc_request.metadata_mut() = grpc_metadata;
    let grpc_response = state.payments_service.create_connector_customer(grpc_request).await?;
    Ok(Json(grpc_response.into_inner()))
}

pub async fn create_payment_method_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    ValidatedJson(payload): ValidatedJson<PaymentServiceCreatePaymentMethodTokenRequest>,
) -> Result<Json<PaymentServiceCreatePaymentMethodTokenResponse>, HttpError> {
    let mut grpc_request = tonic::Request::new(payload);
    let grpc_metadata = http_headers_to_grpc_metadata(&headers).map_err(|status| HttpError {
        status: StatusCode::BAD_REQUEST,
        message: status.message().to_string(),
    })?;
    *grpc_request.metadata_mut() = grpc_metadata;
    let grpc_response = state.payments_service.create_payment_method_token(grpc_request).await?;
    Ok(Json(grpc_response.into_inner()))
}

pub async fn register(
    State(state): State<AppState>,
    headers: HeaderMap,
    ValidatedJson(payload): ValidatedJson<PaymentServiceRegisterRequest>,
) -> Result<Json<PaymentServiceRegisterResponse>, HttpError> {
    let mut grpc_request = tonic::Request::new(payload);
    let grpc_metadata = http_headers_to_grpc_metadata(&headers).map_err(|status| HttpError {
        status: StatusCode::BAD_REQUEST,
        message: status.message().to_string(),
    })?;
    *grpc_request.metadata_mut() = grpc_metadata;
    let grpc_response = state.payments_service.register(grpc_request).await?;
    Ok(Json(grpc_response.into_inner()))
}

pub async fn register_only(
    State(state): State<AppState>,
    headers: HeaderMap,
    ValidatedJson(payload): ValidatedJson<PaymentServiceRegisterRequest>,
) -> Result<Json<PaymentServiceRegisterResponse>, HttpError> {
    let mut grpc_request = tonic::Request::new(payload);
    let grpc_metadata = http_headers_to_grpc_metadata(&headers).map_err(|status| HttpError {
        status: StatusCode::BAD_REQUEST,
        message: status.message().to_string(),
    })?;
    *grpc_request.metadata_mut() = grpc_metadata;
    let grpc_response = state.payments_service.register_only(grpc_request).await?;
    Ok(Json(grpc_response.into_inner()))
}

pub async fn repeat_everything(
    State(state): State<AppState>,
    headers: HeaderMap,
    ValidatedJson(payload): ValidatedJson<PaymentServiceRepeatEverythingRequest>,
) -> Result<Json<PaymentServiceRepeatEverythingResponse>, HttpError> {
    let mut grpc_request = tonic::Request::new(payload);
    let grpc_metadata = http_headers_to_grpc_metadata(&headers).map_err(|status| HttpError {
        status: StatusCode::BAD_REQUEST,
        message: status.message().to_string(),
    })?;
    *grpc_request.metadata_mut() = grpc_metadata;
    let grpc_response = state.payments_service.repeat_everything(grpc_request).await?;
    Ok(Json(grpc_response.into_inner()))
}

pub async fn refund(
    State(state): State<AppState>,
    headers: HeaderMap,
    ValidatedJson(payload): ValidatedJson<PaymentServiceRefundRequest>,
) -> Result<Json<RefundResponse>, HttpError> {
    let mut grpc_request = tonic::Request::new(payload);
    let grpc_metadata = http_headers_to_grpc_metadata(&headers).map_err(|status| HttpError {
        status: StatusCode::BAD_REQUEST,
        message: status.message().to_string(),
    })?;
    *grpc_request.metadata_mut() = grpc_metadata;
    let grpc_response = state.payments_service.refund(grpc_request).await?;
    Ok(Json(grpc_response.into_inner()))
}

pub async fn dispute(
    State(state): State<AppState>,
    headers: HeaderMap,
    ValidatedJson(payload): ValidatedJson<PaymentServiceDisputeRequest>,
) -> Result<Json<DisputeResponse>, HttpError> {
    let mut grpc_request = tonic::Request::new(payload);
    let grpc_metadata = http_headers_to_grpc_metadata(&headers).map_err(|status| HttpError {
        status: StatusCode::BAD_REQUEST,
        message: status.message().to_string(),
    })?;
    *grpc_request.metadata_mut() = grpc_metadata;
    let grpc_response = state.payments_service.dispute(grpc_request).await?;
    Ok(Json(grpc_response.into_inner()))
}

pub async fn pre_authenticate(
    State(state): State<AppState>,
    headers: HeaderMap,
    ValidatedJson(payload): ValidatedJson<PaymentServicePreAuthenticateRequest>,
) -> Result<Json<PaymentServicePreAuthenticateResponse>, HttpError> {
    let mut grpc_request = tonic::Request::new(payload);
    let grpc_metadata = http_headers_to_grpc_metadata(&headers).map_err(|status| HttpError {
        status: StatusCode::BAD_REQUEST,
        message: status.message().to_string(),
    })?;
    *grpc_request.metadata_mut() = grpc_metadata;
    let grpc_response = state.payments_service.pre_authenticate(grpc_request).await?;
    Ok(Json(grpc_response.into_inner()))
}

pub async fn authenticate(
    State(state): State<AppState>,
    headers: HeaderMap,
    ValidatedJson(payload): ValidatedJson<PaymentServiceAuthenticateRequest>,
) -> Result<Json<PaymentServiceAuthenticateResponse>, HttpError> {
    let mut grpc_request = tonic::Request::new(payload);
    let grpc_metadata = http_headers_to_grpc_metadata(&headers).map_err(|status| HttpError {
        status: StatusCode::BAD_REQUEST,
        message: status.message().to_string(),
    })?;
    *grpc_request.metadata_mut() = grpc_metadata;
    let grpc_response = state.payments_service.authenticate(grpc_request).await?;
    Ok(Json(grpc_response.into_inner()))
}

pub async fn post_authenticate(
    State(state): State<AppState>,
    headers: HeaderMap,
    ValidatedJson(payload): ValidatedJson<PaymentServicePostAuthenticateRequest>,
) -> Result<Json<PaymentServicePostAuthenticateResponse>, HttpError> {
    let mut grpc_request = tonic::Request::new(payload);
    let grpc_metadata = http_headers_to_grpc_metadata(&headers).map_err(|status| HttpError {
        status: StatusCode::BAD_REQUEST,
        message: status.message().to_string(),
    })?;
    *grpc_request.metadata_mut() = grpc_metadata;
    let grpc_response = state.payments_service.post_authenticate(grpc_request).await?;
    Ok(Json(grpc_response.into_inner()))
}

pub async fn create_access_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    ValidatedJson(payload): ValidatedJson<PaymentServiceCreateAccessTokenRequest>,
) -> Result<Json<PaymentServiceCreateAccessTokenResponse>, HttpError> {
    let mut grpc_request = tonic::Request::new(payload);
    let grpc_metadata = http_headers_to_grpc_metadata(&headers).map_err(|status| HttpError {
        status: StatusCode::BAD_REQUEST,
        message: status.message().to_string(),
    })?;
    *grpc_request.metadata_mut() = grpc_metadata;
    let grpc_response = state.payments_service.create_access_token(grpc_request).await?;
    Ok(Json(grpc_response.into_inner()))
}

pub async fn transform(
    State(state): State<AppState>,
    headers: HeaderMap,
    ValidatedJson(payload): ValidatedJson<PaymentServiceTransformRequest>,
) -> Result<Json<PaymentServiceTransformResponse>, HttpError> {
    let mut grpc_request = tonic::Request::new(payload);
    let grpc_metadata = http_headers_to_grpc_metadata(&headers).map_err(|status| HttpError {
        status: StatusCode::BAD_REQUEST,
        message: status.message().to_string(),
    })?;
    *grpc_request.metadata_mut() = grpc_metadata;
    let grpc_response = state.payments_service.transform(grpc_request).await?;
    Ok(Json(grpc_response.into_inner()))
}
