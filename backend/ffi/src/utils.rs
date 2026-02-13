use common_crate::{configs::Config, error::PaymentAuthorizationError};
use common_utils::consts;
use common_utils::metadata::{HeaderMaskingConfig, MaskedMetadata};
use domain_types::{
    connector_types::{ConnectorEnum, PaymentFlowData, PaymentsResponseData},
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    types::CardConversionHelper,
    utils::ForeignTryFrom,
};
use std::collections::HashMap;
use std::sync::Arc;
use tonic::metadata::{Ascii, MetadataMap, MetadataValue};
/// Creates hardcoded MaskedMetadata with default test header values
pub fn create_hardcoded_masked_metadata() -> MaskedMetadata {
    let mut headers = HashMap::new();
    headers.insert(
        consts::X_MERCHANT_ID.to_string(),
        "test_merchant_123".to_string(),
    );
    headers.insert(consts::X_CONNECTOR_NAME.to_string(), "stripe".to_string());
    headers.insert(
        consts::X_REQUEST_ID.to_string(),
        "test-request-001".to_string(),
    );
    headers.insert(consts::X_TENANT_ID.to_string(), "public".to_string());
    headers.insert(consts::X_AUTH.to_string(), "test_auth_token".to_string());
    ffi_headers_to_masked_metadata(&headers)
}

/// Converts FFI headers (HashMap) to gRPC metadata with masking support
/// Similar to http_headers_to_grpc_metadata but for FFI input
pub fn ffi_headers_to_masked_metadata(headers: &HashMap<String, String>) -> MaskedMetadata {
    let mut metadata = MetadataMap::new();

    // Required headers - these must be present
    let required_headers = [
        consts::X_CONNECTOR_NAME,
        consts::X_MERCHANT_ID,
        consts::X_REQUEST_ID,
        consts::X_TENANT_ID,
        consts::X_AUTH,
    ];

    // Optional headers - these may or may not be present
    let optional_headers = [
        consts::X_REFERENCE_ID,
        consts::X_API_KEY,
        consts::X_API_SECRET,
        consts::X_KEY1,
        consts::X_KEY2,
        consts::X_AUTH_KEY_MAP,
        consts::X_SHADOW_MODE,
    ];

    // Process required headers - fail if missing
    for header_name in required_headers {
        let header_name: &str = header_name;
        if let Some(header_value) = headers.get(header_name) {
            if let Ok(metadata_value) = convert_to_metadata_value(header_value) {
                metadata.insert(header_name, metadata_value);
            }
        }
    }

    // Process optional headers - skip if missing
    for header_name in optional_headers {
        let header_name: &str = header_name;
        if let Some(header_value) = headers.get(header_name) {
            if let Ok(metadata_value) = convert_to_metadata_value(header_value) {
                metadata.insert(header_name, metadata_value);
            }
        }
    }

    MaskedMetadata::new(metadata, HeaderMaskingConfig::default())
}

fn convert_to_metadata_value(header_value: &str) -> Result<MetadataValue<Ascii>, String> {
    MetadataValue::try_from(header_value)
        .map_err(|e| format!("Cannot convert header value to metadata: {e}"))
}

/// Load development config from the embedded config string
/// This avoids runtime path lookup by embedding the config at build time
pub fn load_development_config(
    embedded_config: &str,
) -> Result<Arc<Config>, PaymentAuthorizationError> {
    toml::from_str(embedded_config).map(Arc::new).map_err(|e| {
        PaymentAuthorizationError::new(
            grpc_api_types::payments::PaymentStatus::Pending,
            Some(e.to_string()),
            Some("CONFIG_PARSE_ERROR".to_string()),
            None,
        )
    })
}

/// Creates RouterDataV2 for payment flows
///
/// This utility function encapsulates the common logic for creating router data:
/// 1. Creates PaymentFlowData from the request payload
/// 2. Creates flow-specific request data (e.g., PaymentsAuthorizeData, PaymentsCaptureData)
/// 3. Constructs and returns RouterDataV2
///
/// # Type Parameters
///
/// * `Flow` - The flow type (Authorize, Capture, etc.)
/// * `T` - Payment method data type (usually DefaultPCIHolder)
/// * `RequestType` - The gRPC request type (e.g., PaymentServiceAuthorizeRequest)
/// * `RequestData` - The domain request data type (e.g., PaymentsAuthorizeData<T>)
///
/// # Arguments
///
/// * `connector` - The connector enum
/// * `connector_auth_details` - Connector authentication details
/// * `payload` - The request payload
/// * `config` - Application configuration
/// * `metadata` - Masked metadata from headers
/// * `error_code` - Error code to use in error responses
///
/// # Returns
///
/// Returns `RouterDataV2` on success, or `PaymentAuthorizationError` on failure
pub fn create_router_data<
    Flow,
    T: PaymentMethodDataTypes
        + Default
        + Eq
        + std::fmt::Debug
        + Send
        + serde::Serialize
        + serde::de::DeserializeOwned
        + Clone
        + Sync
        + CardConversionHelper<T>
        + 'static,
    RequestType: Clone,
    RequestData: ForeignTryFrom<RequestType>,
>(
    connector_auth_details: ConnectorAuthType,
    payload: RequestType,
    config: &Arc<Config>,
    metadata: &MaskedMetadata,
    error_code: &str,
) -> Result<
    RouterDataV2<Flow, PaymentFlowData, RequestData, PaymentsResponseData>,
    PaymentAuthorizationError,
>
where
    PaymentFlowData: for<'a> ForeignTryFrom<(
        RequestType,
        domain_types::types::Connectors,
        &'a MaskedMetadata,
    )>,
{
    // Create PaymentFlowData from the payload
    let payment_flow_data =
        PaymentFlowData::foreign_try_from((payload.clone(), config.connectors.clone(), metadata))
            .map_err(|err| {
            println!("{:?}", err);
            PaymentAuthorizationError::new(
                grpc_api_types::payments::PaymentStatus::Pending,
                Some(err.to_string()),
                Some(error_code.to_string()),
                None,
            )
        })?;

    // Create flow-specific request data
    let payment_request_data = RequestData::foreign_try_from(payload.clone()).map_err(|err| {
        println!("{:?}", err);
        PaymentAuthorizationError::new(
            grpc_api_types::payments::PaymentStatus::Pending,
            Some(err.to_string()),
            Some(error_code.to_string()),
            None,
        )
    })?;

    // Construct and return RouterDataV2
    Ok(RouterDataV2 {
        flow: std::marker::PhantomData,
        resource_common_data: payment_flow_data,
        connector_auth_type: connector_auth_details,
        request: payment_request_data,
        response: Err(ErrorResponse::default()),
    })
}
