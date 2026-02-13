// Embedded development config - read at build time via include_str!
// Path goes: flows/ -> src/ -> ffi/ -> backend/ -> project_root -> config/
const EMBEDDED_DEVELOPMENT_CONFIG: &str = include_str!("../../../../config/development.toml");

use crate::macros::{payment_flow, payment_flow_wrapper};
use common_crate::error::PaymentAuthorizationError;
use external_services;
use grpc_api_types::payments::{
    PaymentServiceAuthorizeRequest, PaymentServiceAuthorizeResponse, PaymentServiceCaptureRequest,
};

use crate::types::RequestData;
use domain_types::{
    connector_flow::{Authorize, Capture},
    connector_types::{PaymentsAuthorizeData, PaymentsCaptureData},
    payment_method_data::DefaultPCIHolder,
};
// Generate authorize function using the payment_flow_generic! macro
payment_flow!(
    authorize_req,
    Authorize,
    PaymentServiceAuthorizeRequest,
    PaymentsAuthorizeData<T>,
    "PAYMENT_AUTHORIZE_ERROR"
);

// Generate capture function using the payment_flow! macro
payment_flow!(
    capture_req,
    Capture,
    PaymentServiceCaptureRequest,
    PaymentsCaptureData,
    "PAYMENT_CAPTURE_ERROR"
);

// Generate authorize_flow wrapper using payment_flow_wrapper! macro
payment_flow_wrapper!(
    authorize_req_flow,
    authorize_req,
    PaymentServiceAuthorizeRequest,
    DefaultPCIHolder
);

// Generate capture_flow wrapper using payment_flow_wrapper! macro
payment_flow_wrapper!(
    capture_req_flow,
    capture_req,
    PaymentServiceCaptureRequest,
    DefaultPCIHolder
);

pub fn authorize_res<
    T: domain_types::payment_method_data::PaymentMethodDataTypes
        + Default
        + Eq
        + std::fmt::Debug
        + Send
        + serde::Serialize
        + serde::de::DeserializeOwned
        + Clone
        + Sync
        + domain_types::types::CardConversionHelper<T>
        + 'static,
>(
    payload: PaymentServiceAuthorizeRequest,
    config: &std::sync::Arc<common_crate::configs::Config>,
    connector: domain_types::connector_types::ConnectorEnum,
    connector_auth_details: domain_types::router_data::ConnectorAuthType,
    metadata: &common_utils::metadata::MaskedMetadata,
    response: domain_types::router_response_types::Response,
) -> Result<PaymentServiceAuthorizeResponse, PaymentAuthorizationError> {
    let connector_data: connector_integration::types::ConnectorData<T> =
        connector_integration::types::ConnectorData::get_connector_by_name(&connector);
    let connector_integration: interfaces::connector_integration_v2::BoxedConnectorIntegrationV2<
        '_,
        Authorize,
        domain_types::connector_types::PaymentFlowData,
        PaymentsAuthorizeData<T>,
        domain_types::connector_types::PaymentsResponseData,
    > = connector_data.connector.get_connector_integration_v2();
    let router_data = crate::utils::create_router_data::<
        Authorize,
        T,
        PaymentServiceAuthorizeRequest,
        PaymentsAuthorizeData<T>,
    >(
        connector_auth_details,
        payload.clone(),
        config,
        metadata,
        "PAYMENT_CAPTURE_ERROR",
    )?;
    let response = external_services::service::handle_connector_response(
        Ok(Ok(response)),
        router_data,
        &connector_integration,
        None,
        None,
        common_utils::Method::Post,
        "".to_string(),
        None,
    )
    .map_err(
        |e: error_stack::Report<domain_types::errors::ConnectorError>| {
            PaymentAuthorizationError::new(
                grpc_api_types::payments::PaymentStatus::Pending,
                Some(e.to_string()),
                None,
                Some(500),
            )
        },
    )?;

    domain_types::types::generate_payment_authorize_response(response).map_err(|e| {
        PaymentAuthorizationError::new(
            grpc_api_types::payments::PaymentStatus::Pending,
            Some(e.to_string()),
            None,
            Some(500),
        )
    })
}

pub fn authorize_res_flow(
    request: RequestData<PaymentServiceAuthorizeRequest>,
    response: domain_types::router_response_types::Response,
) -> Result<PaymentServiceAuthorizeResponse, PaymentAuthorizationError> {
    let metadata_payload = request.extracted_metadata;
    let metadata = &request.masked_metadata;
    let payload = request.payload;
    let config = crate::utils::load_development_config(EMBEDDED_DEVELOPMENT_CONFIG)?;

    authorize_res::<DefaultPCIHolder>(
        payload,
        &config,
        metadata_payload.connector,
        metadata_payload.connector_auth_type,
        metadata,
        response,
    )
}
