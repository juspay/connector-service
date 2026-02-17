use axum::{
    extract::{Extension, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use grpc_api_types::payments::{
    refund_service_server::RefundService, RefundResponse, RefundServiceGetRequest,
    RefundServiceTransformRequest, RefundServiceTransformResponse,
};
use std::sync::Arc;

use crate::http::handlers::macros::http_handler;
use crate::http::{
    error::HttpError, http_headers_to_grpc_metadata, state::AppState,
    transfer_config_to_grpc_request, utils::ValidatedJson,
};
use common_crate::configs::Config;

http_handler!(
    get_refund,
    RefundServiceGetRequest,
    RefundResponse,
    get,
    refunds_service
);

http_handler!(
    transform_refund,
    RefundServiceTransformRequest,
    RefundServiceTransformResponse,
    transform,
    refunds_service
);
