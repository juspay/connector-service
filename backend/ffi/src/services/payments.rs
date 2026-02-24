use external_services;
use grpc_api_types::payments::{PaymentServiceAuthorizeRequest, PaymentServiceAuthorizeResponse};

use crate::errors::{FfiError, FfiPaymentError};

use domain_types::{
    connector_flow::Authorize,
    connector_types::{PaymentFlowData, PaymentsAuthorizeData},
    router_data::ErrorResponse,
    router_data_v2::RouterDataV2,
    utils::ForeignTryFrom,
};

pub fn authorize_req_transformer<
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
    config: &std::sync::Arc<ucs_env::configs::Config>,
    connector: domain_types::connector_types::ConnectorEnum,
    connector_auth_details: domain_types::router_data::ConnectorAuthType,
    metadata: &common_utils::metadata::MaskedMetadata,
) -> Result<Option<common_utils::request::Request>, FfiPaymentError> {
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
            .map_err(|err| FfiError::IntegrationError {
            message: err.to_string(),
        })?;

    // Create flow-specific request data
    let payment_request_data: PaymentsAuthorizeData<T> =
        PaymentsAuthorizeData::foreign_try_from(payload.clone()).map_err(|err| {
            FfiError::IntegrationError {
                message: err.to_string(),
            }
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
        .map_err(|err| FfiError::IntegrationError {
            message: err.to_string(),
        })?;
    Ok(connector_request)
}

pub fn authorize_res_transformer<
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
    config: &std::sync::Arc<ucs_env::configs::Config>,
    connector: domain_types::connector_types::ConnectorEnum,
    connector_auth_details: domain_types::router_data::ConnectorAuthType,
    metadata: &common_utils::metadata::MaskedMetadata,
    response: domain_types::router_response_types::Response,
) -> Result<PaymentServiceAuthorizeResponse, FfiPaymentError> {
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
            .map_err(|err| FfiError::IntegrationError {
            message: err.to_string(),
        })?;

    // Create flow-specific request data
    let payment_request_data: PaymentsAuthorizeData<T> =
        PaymentsAuthorizeData::foreign_try_from(payload.clone()).map_err(|err| {
            FfiError::IntegrationError {
                message: err.to_string(),
            }
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
            FfiPaymentError::new(
                grpc_api_types::payments::PaymentStatus::Pending,
                Some(e.to_string()),
                None,
                Some(500),
            )
        },
    )?;

    domain_types::types::generate_payment_authorize_response(response).map_err(|e| {
        FfiPaymentError::new(
            grpc_api_types::payments::PaymentStatus::Pending,
            Some(e.to_string()),
            None,
            Some(500),
        )
    })
}
