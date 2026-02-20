pub const EMBEDDED_DEVELOPMENT_CONFIG: &str = include_str!("../../../../config/development.toml");
// pub mod napi_handler;
use crate::macros::payment_flow_handler;
use grpc_api_types::payments::{
    PaymentServiceAuthorizeRequest, PaymentServiceAuthorizeResponse, PaymentServiceCaptureRequest,
};

use crate::services::payments::{
    authorize_req_transformer, authorize_res_transformer, capture_req_transformer,
};

use crate::types::FfiRequestData;
use domain_types::payment_method_data::DefaultPCIHolder;

// Generate authorize_req_handler using payment_flow_handler! macro
payment_flow_handler!(
    authorize_req_handler,
    authorize_req_transformer,
    PaymentServiceAuthorizeRequest,
    DefaultPCIHolder
);

// Generate authorize_res_flow handler
pub fn authorize_res_handler(
    request: FfiRequestData<PaymentServiceAuthorizeRequest>,
    response: domain_types::router_response_types::Response,
) -> Result<PaymentServiceAuthorizeResponse, ucs_env::error::PaymentAuthorizationError> {
    let metadata_payload = request.extracted_metadata;
    let metadata_owned = request.masked_metadata.unwrap_or_default();
    let metadata = &metadata_owned;
    let payload = request.payload;
    let config = crate::utils::load_config(EMBEDDED_DEVELOPMENT_CONFIG)?;

    authorize_res_transformer::<DefaultPCIHolder>(
        payload,
        &config,
        metadata_payload.connector,
        metadata_payload.connector_auth_type,
        metadata,
        response,
    )
}

// Generate capture_req_handler using payment_flow_handler! macro
payment_flow_handler!(
    capture_req_handler,
    capture_req_transformer,
    PaymentServiceCaptureRequest,
    DefaultPCIHolder
);
