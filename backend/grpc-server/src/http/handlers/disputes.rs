use axum::{
    extract::{Extension, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use grpc_api_types::payments::{
    dispute_service_server::DisputeService, DisputeServiceAcceptRequest, DisputeServiceAcceptResponse,
    DisputeServiceDefendRequest, DisputeServiceDefendResponse, DisputeResponse, DisputeServiceGetRequest,
    DisputeServiceSubmitEvidenceRequest, DisputeServiceSubmitEvidenceResponse,
    DisputeServiceTransformRequest, DisputeServiceTransformResponse,
};
use std::sync::Arc;

use crate::configs::Config;
use crate::http::handlers::macros::http_handler;
use crate::http::{
    error::HttpError, http_headers_to_grpc_metadata, state::AppState,
    transfer_config_to_grpc_request, utils::ValidatedJson,
};

http_handler!(
    submit_evidence,
    DisputeServiceSubmitEvidenceRequest,
    DisputeServiceSubmitEvidenceResponse,
    submit_evidence,
    disputes_service
);

http_handler!(
    get_dispute,
    DisputeServiceGetRequest,
    DisputeResponse,
    get,
    disputes_service
);

http_handler!(
    defend_dispute,
    DisputeServiceDefendRequest,
    DisputeServiceDefendResponse,
    defend,
    disputes_service
);

http_handler!(
    accept_dispute,
    DisputeServiceAcceptRequest,
    DisputeServiceAcceptResponse,
    accept,
    disputes_service
);

http_handler!(
    transform_dispute,
    DisputeServiceTransformRequest,
    DisputeServiceTransformResponse,
    transform,
    disputes_service
);
