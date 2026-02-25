use axum::{
    extract::{Extension, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use grpc_api_types::payments::{
    dispute_service_server::DisputeService, DisputeResponse, DisputeServiceAcceptRequest,
    DisputeServiceAcceptResponse, DisputeServiceDefendRequest, DisputeServiceDefendResponse,
    DisputeServiceGetRequest, DisputeServiceSubmitEvidenceRequest,
    DisputeServiceSubmitEvidenceResponse,
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
    dispute_service
);

http_handler!(
    get_dispute,
    DisputeServiceGetRequest,
    DisputeResponse,
    get,
    dispute_service
);

http_handler!(
    defend_dispute,
    DisputeServiceDefendRequest,
    DisputeServiceDefendResponse,
    defend,
    dispute_service
);

http_handler!(
    accept_dispute,
    DisputeServiceAcceptRequest,
    DisputeServiceAcceptResponse,
    accept,
    dispute_service
);

// http_handler!(
//     transform_dispute,
//     DisputeServiceTransformRequest,
//     DisputeServiceTransformResponse,
//     transform,
//     dispute_service
// );
