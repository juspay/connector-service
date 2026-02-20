// FFI Handler Macro
// Generates FFI handlers for payment flows similar to http_handler!
// Supports napi bindings for Node.js FFI

/// Macro to generate payment flow functions (for non-generic flows like capture)
///
/// # Example
///
/// ```ignore
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
            pub fn $fn_name<
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
                config: &std::sync::Arc<ucs_env::configs::Config>,
                connector: domain_types::connector_types::ConnectorEnum,
                connector_auth_details: domain_types::router_data::ConnectorAuthType,
                metadata: &common_utils::metadata::MaskedMetadata,
            ) -> Result<Option<common_utils::request::Request>, ucs_env::error::PaymentAuthorizationError> {
                let connector_data: connector_integration::types::ConnectorData<T> =
                    connector_integration::types::ConnectorData::get_connector_by_name(&connector);

                let connector_integration: interfaces::connector_integration_v2::BoxedConnectorIntegrationV2<
                    '_,
                    $flow_type,
                    domain_types::connector_types::PaymentFlowData,
                    $req_data_type,
                    domain_types::connector_types::PaymentsResponseData,
                > = connector_data.connector.get_connector_integration_v2();

                // Create PaymentFlowData from the payload
                let payment_flow_data =
                    domain_types::connector_types::PaymentFlowData::foreign_try_from(
                        (payload.clone(), config.connectors.clone(), metadata),
                    )
                    .map_err(|err| {
                        tracing::error!(error = ?err, "Failed to create PaymentFlowData");
                        ucs_env::error::PaymentAuthorizationError::new(
                            grpc_api_types::payments::PaymentStatus::Failure,
                            Some(err.to_string()),
                            Some($error_code.to_string()),
                            None,
                        )
                    })?;

                // Create flow-specific request data
                let payment_request_data = <$req_data_type as domain_types::utils::ForeignTryFrom<$req_type>>::foreign_try_from(payload.clone())
                    .map_err(|err| {
                        tracing::error!(error = ?err, "Failed to create payment request data");
                        ucs_env::error::PaymentAuthorizationError::new(
                            grpc_api_types::payments::PaymentStatus::Failure,
                            Some(err.to_string()),
                            Some($error_code.to_string()),
                            None,
                        )
                    })?;

                // Construct RouterDataV2 directly
                let router_data = domain_types::router_data_v2::RouterDataV2 {
                    flow: std::marker::PhantomData,
                    resource_common_data: payment_flow_data,
                    connector_auth_type: connector_auth_details,
                    request: payment_request_data,
                    response: Err(domain_types::router_data::ErrorResponse::default()),
                };

                let connector_request = connector_integration
                    .build_request_v2(&router_data.clone())
                    .map_err(|err| {
                        tracing::error!(error = ?err, "Connector response handling failed");
                        ucs_env::error::PaymentAuthorizationError::new(
                            grpc_api_types::payments::PaymentStatus::Failure,
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
/// ```ignore
/// payment_flow_handler!(
///     authorize_req_handler,
///     authorize_req_transformer,
///     PaymentServiceAuthorizeRequest,
///     DefaultPCIHolder
/// );
/// ```
///
/// This generates the `authorize_req_handler` function that wraps the `authorize_req_transformer` function.
#[macro_export]
macro_rules! payment_flow_handler {
    (
        $fn_name:ident,
        $inner_fn_name:ident,
        $req_type:ty,
        $generic_type:ty
    ) => {
        paste::paste! {
            pub fn $fn_name(
                request: $crate::types::FfiRequestData<$req_type>,
            ) -> Result<Option<common_utils::request::Request>, ucs_env::error::PaymentAuthorizationError> {
                let metadata_payload = request.extracted_metadata;
                let metadata_owned = request.masked_metadata.unwrap_or_default();
                let metadata = &metadata_owned;
                let payload = request.payload;

                // Load embedded development config (baked into binary at build time)
                let config = $crate::utils::load_config($crate::handlers::payments::EMBEDDED_DEVELOPMENT_CONFIG)?;

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

pub(crate) use payment_flow;
pub(crate) use payment_flow_handler;
