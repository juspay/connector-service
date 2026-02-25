use axum::{
    extract::{Extension, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use grpc_api_types::payments::{
    composite_payment_service_server::CompositePaymentService, CompositeAuthorizeRequest,
    CompositeAuthorizeResponse,
};
use std::sync::Arc;

use ucs_env::configs::Config;
use crate::http::handlers::macros::http_handler;
use crate::http::{
    error::HttpError, http_headers_to_grpc_metadata, state::AppState,
    transfer_config_to_grpc_request, utils::ValidatedJson,
};

http_handler!(
    authorize,
    CompositeAuthorizeRequest,
    CompositeAuthorizeResponse,
    composite_authorize,
    composite_payments_service
);
