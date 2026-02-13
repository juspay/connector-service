// FFI Handler Macro
// Generates FFI handlers for payment flows similar to http_handler!
// Supports napi bindings for Node.js FFI

/// Macro to generate FFI handlers for payment operations.
///
/// This macro generates a napi-compatible function that:
/// 1. Validates input payloads are not empty
/// 2. Parses the request payload from JSON
/// 3. Parses headers into MaskedMetadata
/// 4. Parses extracted_metadata
/// 5. Calls the flow function
/// 6. Extracts the connector request and returns it as JSON
///
/// # Example
///
/// ```rust
/// napi_handler!(
///     authorize,
///     PaymentServiceAuthorizeRequest,
///     JsRequest,
///     authorize_flow
/// );
/// ```
///
/// This generates:
/// ```rust
/// #[napi]
/// pub fn authorize(payload: String, headers: String, extracted_metadata: String) -> napi::Result<String> {
///     // ... implementation
/// }
/// ```
#[macro_export]
macro_rules! napi_handler {
    ($fn_name:ident, $req_type:ty, $resp_type:ty, $flow_fn:ident) => {
        paste::paste! {
                        #[cfg(feature = "napi")]
                        #[::napi_derive::napi]
                        pub fn [<$fn_name>] (
                            payload: napi::JsString,
                            extracted_metadata: napi::JsString,
                        ) -> napi::Result<String> {

                            use crate::types::{MetadataPayload, RequestData};
                            use crate::utils::create_hardcoded_masked_metadata;

                            // Convert inputs to Rust strings
                            let payload_str = payload.into_utf8()?.as_str()?.to_string();
                            let extracted_metadata_str =
                                extracted_metadata.into_utf8()?.as_str()?.to_string();

                            if payload_str.trim().is_empty() {
                                return Err(napi::Error::from_reason("Payload cannot be empty"));
                            }

                            if extracted_metadata_str.trim().is_empty() {
                                return Err(napi::Error::from_reason(
                                    "Extracted metadata cannot be empty",
                                ));
                            }

                            // Parse payload
                            let payload_data: $req_type = serde_json::from_str(&payload_str)
                                .map_err(|e| napi::Error::from_reason(format!(
                                    "Invalid payload JSON: {e}"
                                )))?;

                            let masked_metadata = create_hardcoded_masked_metadata();

                            // Parse metadata
                            let extracted_metadata_data: MetadataPayload =
                                serde_json::from_str(&extracted_metadata_str)
                                    .map_err(|e| napi::Error::from_reason(format!(
                                        "Invalid metadata JSON: {e}"
                                    )))?;

                            let request_data = RequestData {
                                payload: payload_data,
                                extracted_metadata: extracted_metadata_data,
                                masked_metadata,
                            };

                            // Call flow
                            let result = $flow_fn(request_data)
                                .map_err(|e| napi::Error::from_reason(format!("{:?}", e)))?;

                            let request = result.ok_or_else(|| {
                                napi::Error::from_reason("No connector request generated")
                            })?;

                            // Extract raw connector request
           let extracted_request =
        external_services::service::extract_raw_connector_request(&request);

         Ok(extracted_request)
                        }
                    }
    };
}

/// Macro to generate payment flow functions (for non-generic flows like capture)
///
/// # Example
///
/// ```rust
/// payment_flow!(
///     capture,
///     Capture,
///     PaymentServiceCaptureRequest,
///     PaymentsCaptureData,
///     "PAYMENT_CAPTURE"
/// );
/// ```
///
/// This generates the `capture` function with:
/// - All trait bounds (PaymentMethodDataTypes, Default, Eq, Debug, Send, etc.)
/// - Connector data retrieval
/// - Connector integration v2 call
/// - Flow data conversion
/// - Request data conversion
/// - Router data construction
/// - build_request_v2 call
#[macro_export]
macro_rules! payment_flow {
    (
        $fn_name:ident,
        $flow_type:ty,
        $req_type:ty,
        $req_data_type:ty,
        $error_code:expr
    ) => {
        paste::paste! {
            fn $fn_name<
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
                payload: $req_type,
                config: &std::sync::Arc<common_crate::configs::Config>,
                connector: domain_types::connector_types::ConnectorEnum,
                connector_auth_details: domain_types::router_data::ConnectorAuthType,
                metadata: &common_utils::metadata::MaskedMetadata,
            ) -> Result<Option<common_utils::request::Request>, common_crate::error::PaymentAuthorizationError> {
                let connector_data: connector_integration::types::ConnectorData<T> =
                    connector_integration::types::ConnectorData::get_connector_by_name(&connector);

                let connector_integration: interfaces::connector_integration_v2::BoxedConnectorIntegrationV2<
                    '_,
                    $flow_type,
                    domain_types::connector_types::PaymentFlowData,
                    $req_data_type,
                    domain_types::connector_types::PaymentsResponseData,
                > = connector_data.connector.get_connector_integration_v2();

                let router_data = $crate::utils::create_router_data::<
                    $flow_type,
                    T,
                    $req_type,
                    $req_data_type,
                >(
                    connector_auth_details,
                    payload.clone(),
                    config,
                    metadata,
                    $error_code,
                )?;

                let connector_request = connector_integration
                    .build_request_v2(&router_data.clone())
                    .map_err(|err| {
                        common_crate::error::PaymentAuthorizationError::new(
                            grpc_api_types::payments::PaymentStatus::Pending,
                            Some(err.to_string()),
                            Some($error_code.to_string()),
                            None,
                        )
                    })?;

                Ok(connector_request)
            }
        }
    };
}

/// Macro to generate public payment flow wrapper functions.
///
/// This macro generates a wrapper function that:
/// 1. Extracts metadata from the request
/// 2. Loads the embedded development config
/// 3. Calls the inner flow function
///
/// # Example
///
/// ```rust
/// payment_flow_wrapper!(
///     authorize_flow,
///     authorize,
///     PaymentServiceAuthorizeRequest,
///     DefaultPCIHolder
/// );
/// ```
///
/// This generates the `authorize_flow` function that wraps the `authorize` function.
#[macro_export]
macro_rules! payment_flow_wrapper {
    (
        $fn_name:ident,
        $inner_fn_name:ident,
        $req_type:ty,
        $generic_type:ty
    ) => {
        paste::paste! {
            pub fn $fn_name(
                request: $crate::flows::payments::RequestData<$req_type>,
            ) -> Result<Option<common_utils::request::Request>, common_crate::error::PaymentAuthorizationError> {
                let metadata_payload = request.extracted_metadata;
                let metadata = &request.masked_metadata;
                let payload = request.payload;

                // Load embedded development config (baked into binary at build time)
                let config = $crate::utils::load_development_config($crate::flows::payments::EMBEDDED_DEVELOPMENT_CONFIG)?;

                $inner_fn_name::<$generic_type>(
                    payload,
                    &config,
                    metadata_payload.connector,
                    metadata_payload.connector_auth_type,
                    metadata,
                )
            }
        }
    };
}

pub(crate) use napi_handler;
pub(crate) use payment_flow;
pub(crate) use payment_flow_wrapper;
