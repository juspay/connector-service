// Embedded development config - read at build time via include_str!
// Path goes: flows/ -> src/ -> ffi/ -> backend/ -> project_root -> config/
const EMBEDDED_DEVELOPMENT_CONFIG: &str = include_str!("../../../../config/development.toml");

use crate::utils::load_development_config;
use connector_integration::types::ConnectorData;

use common_crate::{configs::Config, error::PaymentAuthorizationError};
use grpc_api_types::payments::PaymentServiceAuthorizeRequest;

use common_utils::{metadata::MaskedMetadata, request::Request};
use std::{fmt::Debug, sync::Arc};

use domain_types::{
    connector_flow::Authorize,
    connector_types::{
        ConnectorEnum, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData,
    },
    payment_method_data::{DefaultPCIHolder, PaymentMethodDataTypes},
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    utils::ForeignTryFrom,
};
use interfaces::connector_integration_v2::BoxedConnectorIntegrationV2;

fn authorize<
    T: PaymentMethodDataTypes
        + Default
        + Eq
        + Debug
        + Send
        + serde::Serialize
        + serde::de::DeserializeOwned
        + Clone
        + Sync
        + domain_types::types::CardConversionHelper<T>
        + 'static,
>(
    payload: PaymentServiceAuthorizeRequest,
    config: &Arc<Config>,
    connector: ConnectorEnum,
    connector_auth_details: ConnectorAuthType,
    metadata: &MaskedMetadata,
) -> Result<Option<Request>, PaymentAuthorizationError> {
    let connector_data = ConnectorData::get_connector_by_name(&connector);

    // Get connector integration
    let connector_integration: BoxedConnectorIntegrationV2<
        '_,
        Authorize,
        PaymentFlowData,
        PaymentsAuthorizeData<T>,
        PaymentsResponseData,
    > = connector_data.connector.get_connector_integration_v2();
    let payment_flow_data =
        PaymentFlowData::foreign_try_from((payload.clone(), config.connectors.clone(), metadata))
            .map_err(|err| {
            println!("{:?}", err);
            PaymentAuthorizationError::new(
                grpc_api_types::payments::PaymentStatus::Pending,
                Some(err.to_string()),
                Some("PAYMENT_FLOW_ERROR".to_string()),
                None,
            )
        })?;
    let payment_authorize_data = PaymentsAuthorizeData::<T>::foreign_try_from(payload.clone())
        .map_err(|err| {
            println!("{:?}", err);
            PaymentAuthorizationError::new(
                grpc_api_types::payments::PaymentStatus::Pending,
                Some(err.to_string()),
                Some("PAYMENT_AUTHORIZE_DATA_ERROR".to_string()),
                None,
            )
        })?;
    let router_data = RouterDataV2::<
        Authorize,
        PaymentFlowData,
        PaymentsAuthorizeData<T>,
        PaymentsResponseData,
    > {
        flow: std::marker::PhantomData,
        resource_common_data: payment_flow_data.clone(),
        connector_auth_type: connector_auth_details.clone(),
        request: payment_authorize_data,
        response: Err(ErrorResponse::default()),
    };
    let connector_request = connector_integration
        .build_request_v2(&router_data.clone())
        .map_err(|err| {
            PaymentAuthorizationError::new(
                grpc_api_types::payments::PaymentStatus::Pending,
                Some(err.to_string()),
                Some("PAYMENT_AUTHORIZE_DATA_ERROR".to_string()),
                None,
            )
        })?;
    Ok(connector_request)
}

#[derive(Clone, Debug, serde::Deserialize)]
pub struct MetadataPayload {
    pub connector: ConnectorEnum,
    pub connector_auth_type: ConnectorAuthType,
}

#[derive(Debug, serde::Deserialize)]
pub struct RequestData {
    pub payload: PaymentServiceAuthorizeRequest,
    pub extracted_metadata: MetadataPayload,

    #[serde(skip_deserializing, default)]
    pub masked_metadata: MaskedMetadata, // all metadata with masking config
}

pub fn authorize_flow(request: RequestData) -> Result<Option<Request>, PaymentAuthorizationError> {
    let metadata_payload = request.extracted_metadata;
    let metadata = &request.masked_metadata;
    let payload = request.payload;

    // Load embedded development config (baked into binary at build time)
    let config = load_development_config(EMBEDDED_DEVELOPMENT_CONFIG)?;

    authorize::<DefaultPCIHolder>(
        payload,
        &config,
        metadata_payload.connector,
        metadata_payload.connector_auth_type,
        metadata,
    )
}
