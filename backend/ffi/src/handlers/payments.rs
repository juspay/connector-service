pub const EMBEDDED_DEVELOPMENT_CONFIG: &str = include_str!("../../../../config/development.toml");
// pub mod napi_handler;

use common_crate::error::PaymentAuthorizationError;
use grpc_api_types::payments::{PaymentServiceAuthorizeRequest, PaymentServiceAuthorizeResponse};

use crate::services::payments::{authorize_req, authorize_res};

use crate::types::FFIRequestData;
use domain_types::payment_method_data::DefaultPCIHolder;

// Generate authorize_res_flow handler
pub fn authorize_req_handler(
    request: FFIRequestData<PaymentServiceAuthorizeRequest>,
) -> Result<Option<common_utils::request::Request>, PaymentAuthorizationError> {
    let metadata_payload = request.extracted_metadata;
    let metadata = &request.masked_metadata;
    let payload = request.payload;
    let config = crate::utils::load_config(EMBEDDED_DEVELOPMENT_CONFIG)?;

    authorize_req::<DefaultPCIHolder>(
        payload,
        &config,
        metadata_payload.connector,
        metadata_payload.connector_auth_type,
        metadata,
    )
}

// Generate authorize_res_flow handler
pub fn authorize_res_handler(
    request: FFIRequestData<PaymentServiceAuthorizeRequest>,
    response: domain_types::router_response_types::Response,
) -> Result<PaymentServiceAuthorizeResponse, PaymentServiceAuthorizeResponse> {
    let metadata_payload = request.extracted_metadata;
    let metadata = &request.masked_metadata;
    let payload = request.payload;
    let config = crate::utils::load_config(EMBEDDED_DEVELOPMENT_CONFIG)?;

    authorize_res::<DefaultPCIHolder>(
        payload,
        &config,
        metadata_payload.connector,
        metadata_payload.connector_auth_type,
        metadata,
        response,
    )
    .map_err(|e| e.into())
}
