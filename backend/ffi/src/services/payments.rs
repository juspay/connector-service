use common_crate::error::PaymentAuthorizationError;
use external_services;
use grpc_api_types::payments::{PaymentServiceAuthorizeRequest, PaymentServiceAuthorizeResponse};

use domain_types::{
    connector_flow::Authorize,
    connector_types::{PaymentFlowData, PaymentsAuthorizeData},
    router_data::ErrorResponse,
    router_data_v2::RouterDataV2,
    utils::ForeignTryFrom,
};

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
        PaymentFlowData,
        PaymentsAuthorizeData<T>,
        domain_types::connector_types::PaymentsResponseData,
    > = connector_data.connector.get_connector_integration_v2();

    // Create PaymentFlowData from the payload
    let payment_flow_data =
        PaymentFlowData::foreign_try_from((payload.clone(), config.connectors.clone(), metadata))
            .map_err(|err| {
            tracing::error!(error = ?err, "Failed to create PaymentFlowData");
            PaymentAuthorizationError::new(
                grpc_api_types::payments::PaymentStatus::Pending,
                Some(err.to_string()),
                Some("PAYMENT_AUTHORIZE_ERROR".to_string()),
                None,
            )
        })?;

    // Create flow-specific request data
    let payment_request_data: PaymentsAuthorizeData<T> =
        PaymentsAuthorizeData::foreign_try_from(payload.clone()).map_err(|err| {
            tracing::error!(error = ?err, "Failed to create payment request data");
            PaymentAuthorizationError::new(
                grpc_api_types::payments::PaymentStatus::Pending,
                Some(err.to_string()),
                Some("PAYMENT_AUTHORIZE_ERROR".to_string()),
                None,
            )
        })?;

    // Construct RouterDataV2 directly
    let router_data = RouterDataV2 {
        flow: std::marker::PhantomData,
        resource_common_data: payment_flow_data,
        connector_auth_type: connector_auth_details,
        request: payment_request_data,
        response: Err(ErrorResponse::default()),
    };

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
        PaymentFlowData,
        PaymentsAuthorizeData<T>,
        domain_types::connector_types::PaymentsResponseData,
    > = connector_data.connector.get_connector_integration_v2();

    let payment_flow_data =
        PaymentFlowData::foreign_try_from((payload.clone(), config.connectors.clone(), metadata))
            .map_err(|err| {
            tracing::error!("Failed to process payment flow data: {:?}", err);
            PaymentAuthorizationError::new(
                grpc_api_types::payments::PaymentStatus::Pending,
                Some("Failed to process payment flow data".to_string()),
                Some("PAYMENT_FLOW_ERROR".to_string()),
                None,
            )
        })?;

    // Create flow-specific request data
    let payment_request_data: PaymentsAuthorizeData<T> =
        PaymentsAuthorizeData::foreign_try_from(payload.clone()).map_err(|err| {
            tracing::error!(error = ?err, "Failed to create payment request data");
            PaymentAuthorizationError::new(
                grpc_api_types::payments::PaymentStatus::Pending,
                Some(err.to_string()),
                Some("PAYMENT_AUTHORIZE_ERROR".to_string()),
                None,
            )
        })?;

    // construct router data
    let router_data = RouterDataV2 {
        flow: std::marker::PhantomData,
        resource_common_data: payment_flow_data,
        connector_auth_type: connector_auth_details,
        request: payment_request_data,
        response: Err(ErrorResponse::default()),
    };

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
