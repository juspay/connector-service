use crate::macros::payment_flow;
use common_crate::error::PaymentAuthorizationError;
use external_services;
use grpc_api_types::payments::{
    PaymentServiceAuthorizeRequest, PaymentServiceAuthorizeResponse, PaymentServiceCaptureRequest,
};

use domain_types::{
    connector_flow::{Authorize, Capture},
    connector_types::{PaymentsAuthorizeData, PaymentsCaptureData},
};
// Generate authorize function using the payment_flow_generic! macro
// payment_flow!(
//     authorize_req,
//     Authorize,
//     PaymentServiceAuthorizeRequest,
//     PaymentsAuthorizeData<T>,
//     "PAYMENT_AUTHORIZE_ERROR"
// );

pub fn authorize_req<
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
) -> Result<Option<common_utils::request::Request>, PaymentAuthorizationError> {
    // connector integration trait
    let connector_data: connector_integration::types::ConnectorData<T> =
        connector_integration::types::ConnectorData::get_connector_by_name(&connector);

    let connector_integration: interfaces::connector_integration_v2::BoxedConnectorIntegrationV2<
        '_,
        Authorize,
        domain_types::connector_types::PaymentFlowData,
        PaymentsAuthorizeData<T>,
        domain_types::connector_types::PaymentsResponseData,
    > = connector_data.connector.get_connector_integration_v2();

    // construct router data
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
        "PAYMENT_AUTHORIZE_ERROR",
    )?;

    // transform common request type to connector specific request type
    let connector_request = connector_integration
        .build_request_v2(&router_data.clone())
        .map_err(|err| {
            PaymentAuthorizationError::new(
                grpc_api_types::payments::PaymentStatus::Pending,
                Some(err.to_string()),
                Some("PAYMENT_AUTHORIZE_ERROR".to_string()),
                None,
            )
        })?;
    Ok(connector_request)
}

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
    // connector integration trait
    let connector_data: connector_integration::types::ConnectorData<T> =
        connector_integration::types::ConnectorData::get_connector_by_name(&connector);
    let connector_integration: interfaces::connector_integration_v2::BoxedConnectorIntegrationV2<
        '_,
        Authorize,
        domain_types::connector_types::PaymentFlowData,
        PaymentsAuthorizeData<T>,
        domain_types::connector_types::PaymentsResponseData,
    > = connector_data.connector.get_connector_integration_v2();

    // construct router data
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

    // transform connector response type to common response type
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
            tracing::error!(error = ?e, "Connector response handling failed");
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

// Generate capture function using the payment_flow! macro
payment_flow!(
    capture_req,
    Capture,
    PaymentServiceCaptureRequest,
    PaymentsCaptureData,
    "PAYMENT_CAPTURE_ERROR"
);
