pub const EMBEDDED_DEVELOPMENT_CONFIG: &str = include_str!("../../../../config/development.toml");
// pub mod napi_handler;

use grpc_api_types::payments::{PaymentServiceAuthorizeRequest, PaymentServiceAuthorizeResponse};

use crate::services::payments::{authorize_req_transformer, authorize_res_transformer};

use crate::errors::FfiPaymentError;
use crate::types::FfiRequestData;
use domain_types::payment_method_data::DefaultPCIHolder;
// authorize_req handler
pub fn authorize_req_handler(
    request: FfiRequestData<PaymentServiceAuthorizeRequest>,
) -> Result<Option<common_utils::request::Request>, FfiPaymentError> {
    let metadata_payload = request.extracted_metadata;
    let metadata_owned = request.masked_metadata.unwrap_or_default();
    let metadata = &metadata_owned;
    let payload = request.payload;
    let config = crate::utils::load_config(EMBEDDED_DEVELOPMENT_CONFIG)?;

    authorize_req_transformer::<DefaultPCIHolder>(
        payload,
        &config,
        metadata_payload.connector,
        metadata_payload.connector_auth_type,
        metadata,
    )
}

// authorize_res handler
pub fn authorize_res_handler(
    request: FfiRequestData<PaymentServiceAuthorizeRequest>,
    response: domain_types::router_response_types::Response,
) -> Result<PaymentServiceAuthorizeResponse, FfiPaymentError> {
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
