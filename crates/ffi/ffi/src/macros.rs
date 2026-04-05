//! Macros for generating request and response transformer functions
//!
//! These macros eliminate duplicate code between authorize, capture, and other flow transformers.

/// Macro to generate request transformer functions
///
/// # Example
/// ```ignore
/// req_transformer! {
///     fn_name: authorize_req_transformer,
///     request_type: PaymentServiceAuthorizeRequest,
///     flow_marker: Authorize,
///     request_data_type: PaymentsAuthorizeData<T>,
/// }
/// ```
macro_rules! req_transformer {
    (
        fn_name: $fn_name:ident,
        request_type: $request_type:ty,
        flow_marker: $flow_marker:ty,
        resource_common_data_type: $resource_common_data_type:ty,
        request_data_type: $request_data_type:ty,
        response_data_type: $response_data_type:ty $(,)?
    ) => {
        pub fn $fn_name<
            T: domain_types::payment_method_data::PaymentMethodDataTypes
                + Default
                + Eq
                + std::fmt::Debug
                + Send
                + Sync
                + Clone
                + serde::Serialize
                + serde::de::DeserializeOwned
                + 'static,
        >(
            payload: $request_type,
            config: &std::sync::Arc<ucs_env::configs::Config>,
            connector: domain_types::connector_types::ConnectorEnum,
            connector_config: domain_types::router_data::ConnectorSpecificConfig,
            metadata: &common_utils::metadata::MaskedMetadata,
        ) -> Result<Option<common_utils::request::Request>, grpc_api_types::payments::IntegrationError> {

            let connector_data: connector_integration::types::ConnectorData<T> =
                connector_integration::types::ConnectorData::get_connector_by_name(&connector);

            let connector_integration: interfaces::connector_integration_v2::BoxedConnectorIntegrationV2<
                '_,
                $flow_marker,
                $resource_common_data_type,
                $request_data_type,
                $response_data_type,
            > = connector_data.connector.get_connector_integration_v2();

            let connectors = ucs_interface_common::config::connectors_with_connector_config_overrides(
                &connector_config,
                config,
            )
            .map_err(|e: error_stack::Report<domain_types::errors::ApplicationErrorResponse>| {
                ucs_env::error::ErrorSwitch::switch(e.current_context())
            })?;

            let flow_data: $resource_common_data_type =
                domain_types::utils::ForeignTryFrom::foreign_try_from((
                    payload.clone(),
                    connectors,
                    metadata,
                ))
                .map_err(|e: error_stack::Report<domain_types::errors::ApplicationErrorResponse>| {
                    ucs_env::error::ErrorSwitch::switch(e.current_context())
                })?;

            let payment_request_data: $request_data_type =
                domain_types::utils::ForeignTryFrom::foreign_try_from(payload.clone())
                .map_err(|e: error_stack::Report<domain_types::errors::ApplicationErrorResponse>| {
                    ucs_env::error::ErrorSwitch::switch(e.current_context())
                })?;

            let router_data = domain_types::router_data_v2::RouterDataV2 {
                flow: std::marker::PhantomData,
                resource_common_data: flow_data,
                connector_config,
                request: payment_request_data,
                response: Err(domain_types::router_data::ErrorResponse::default()),
            };

            let connector_request = connector_integration
                .build_request_v2(&router_data)
                .map_err(|e: error_stack::Report<domain_types::errors::ConnectorError>| {
                    let app_error: domain_types::errors::ApplicationErrorResponse = ucs_env::error::ErrorSwitch::switch(e.current_context());
                    ucs_env::error::ErrorSwitch::switch(&app_error)
                })?;

            Ok(connector_request)
        }
    };
}

/// Macro to generate request transformer functions with payment method data processing
///
/// This variant handles flows that need `PaymentMethodData` (like authorize, setup_recurring).
/// It processes the payment method from the payload, converts it to `PaymentMethodData`,
/// and passes it as a tuple `(request_for_ftf, payment_method_data)` to `ForeignTryFrom`.
///
/// The `request_for_ftf` expression controls how the payload is transformed before being
/// passed to `ForeignTryFrom`. Use `payload.clone()` when the proto type is accepted directly,
/// or `Into::<SomeIntermediateType>::into(payload.clone())` when an intermediate type is needed
/// (e.g. `AuthorizationRequest` for the authorize flow).
macro_rules! req_transformer_with_payment_method_data {
    (
        fn_name: $fn_name:ident,
        request_type: $request_type:ty,
        flow_marker: $flow_marker:ty,
        resource_common_data_type: $resource_common_data_type:ty,
        request_data_type: $request_data_type:ty,
        response_data_type: $response_data_type:ty,
        request_for_ftf: $request_for_ftf:expr $(,)?
    ) => {
        pub fn $fn_name<
            T: domain_types::payment_method_data::PaymentMethodDataTypes
                + Default
                + Eq
                + std::fmt::Debug
                + Send
                + Sync
                + Clone
                + serde::Serialize
                + serde::de::DeserializeOwned
                + 'static,
        >(
            payload: $request_type,
            config: &std::sync::Arc<ucs_env::configs::Config>,
            connector: domain_types::connector_types::ConnectorEnum,
            connector_config: domain_types::router_data::ConnectorSpecificConfig,
            metadata: &common_utils::metadata::MaskedMetadata,
        ) -> Result<Option<common_utils::request::Request>, grpc_api_types::payments::IntegrationError> {

            let connector_data: connector_integration::types::ConnectorData<domain_types::payment_method_data::DefaultPCIHolder> =
                connector_integration::types::ConnectorData::get_connector_by_name(&connector);

            let connector_integration: interfaces::connector_integration_v2::BoxedConnectorIntegrationV2<
                '_,
                $flow_marker,
                $resource_common_data_type,
                $request_data_type,
                $response_data_type,
            > = connector_data.connector.get_connector_integration_v2();

            let connectors = ucs_interface_common::config::connectors_with_connector_config_overrides(
                &connector_config,
                config,
            )
            .map_err(|e: error_stack::Report<domain_types::errors::ApplicationErrorResponse>| {
                ucs_env::error::ErrorSwitch::switch(e.current_context())
            })?;

            let flow_data: $resource_common_data_type =
                domain_types::utils::ForeignTryFrom::foreign_try_from((
                    payload.clone(),
                    connectors,
                    metadata,
                ))
                .map_err(|e: error_stack::Report<domain_types::errors::ApplicationErrorResponse>| {
                    ucs_env::error::ErrorSwitch::switch(e.current_context())
                })?;

            // Process payment method data
            let payment_method_data_action = domain_types::types::PaymentMethodDataAction::get_payment_method_data_action(
                payload.payment_method.clone()
                    .ok_or_else(|| grpc_api_types::payments::IntegrationError {
                        error_message: "missing payment_method in the payload".to_string(),
                        error_code: "MISSING_PAYMENT_METHOD".to_string(),
                        suggested_action: None,
                        doc_url: None,
                    })?
            )
            .map_err(|_err| {
                grpc_api_types::payments::IntegrationError {
                    error_message: "Invalid payment method data".to_string(),
                    error_code: "INVALID_PAYMENT_METHOD_DATA".to_string(),
                    suggested_action: None,
                    doc_url: None,
                }
            })?;

            let payment_method_data = match payment_method_data_action {
                domain_types::types::PaymentMethodDataAction::Card(card_details) => {
                    let card = <domain_types::payment_method_data::Card<domain_types::payment_method_data::DefaultPCIHolder> as domain_types::utils::ForeignTryFrom<grpc_api_types::payments::CardDetails>>::foreign_try_from(card_details)
                        .map_err(|_err| {
                            grpc_api_types::payments::IntegrationError {
                                error_message: "Invalid card details".to_string(),
                                error_code: "INVALID_CARD_DETAILS".to_string(),
                                suggested_action: None,
                                doc_url: None,
                            }
                        })?;
                    Ok(domain_types::payment_method_data::PaymentMethodData::Card(card))
                }
                domain_types::types::PaymentMethodDataAction::Default => {
                    let pm_data = domain_types::payment_method_data::PaymentMethodData::convert_to_domain_model_for_non_card_payment_methods(
                        payload.payment_method.clone()
                            .ok_or_else(|| grpc_api_types::payments::IntegrationError {
                                error_message: "missing payment_method in the payload".to_string(),
                                error_code: "MISSING_PAYMENT_METHOD".to_string(),
                                suggested_action: None,
                                doc_url: None,
                            })?
                    )
                    .map_err(|_err| {
                        grpc_api_types::payments::IntegrationError {
                            error_message: "Invalid payment method data".to_string(),
                            error_code: "INVALID_PAYMENT_METHOD_DATA".to_string(),
                            suggested_action: None,
                            doc_url: None,
                        }
                    })?;
                    Ok(pm_data)
                }
                domain_types::types::PaymentMethodDataAction::CardProxy(_) => {
                    Err(grpc_api_types::payments::IntegrationError {
                        error_message: "CardProxy not supported in this flow".to_string(),
                        error_code: "UNSUPPORTED_PAYMENT_METHOD".to_string(),
                        suggested_action: None,
                        doc_url: None,
                    })
                }
            }?;

            let request_for_foreign_try_from = $request_for_ftf(&payload);

            let payment_request_data: $request_data_type =
                domain_types::utils::ForeignTryFrom::foreign_try_from((request_for_foreign_try_from, payment_method_data))
                .map_err(|e: error_stack::Report<domain_types::errors::ApplicationErrorResponse>| {
                    ucs_env::error::ErrorSwitch::switch(e.current_context())
                })?;

            let router_data = domain_types::router_data_v2::RouterDataV2 {
                flow: std::marker::PhantomData,
                resource_common_data: flow_data,
                connector_config,
                request: payment_request_data,
                response: Err(domain_types::router_data::ErrorResponse::default()),
            };

            let connector_request = connector_integration
                .build_request_v2(&router_data)
                .map_err(|e: error_stack::Report<domain_types::errors::ConnectorError>| {
                    let app_error: domain_types::errors::ApplicationErrorResponse = ucs_env::error::ErrorSwitch::switch(e.current_context());
                    ucs_env::error::ErrorSwitch::switch(&app_error)
                })?;

            Ok(connector_request)
        }
    };
}

/// Macro to generate request transformer functions with Option<PaymentMethodData>
///
/// This variant handles flows that need `Option<PaymentMethodData>` (like pre_authenticate, authenticate, post_authenticate).
/// It passes `None` as the payment method data in a tuple `(payload, None)` to `ForeignTryFrom`.
macro_rules! req_transformer_with_optional_payment_method_data {
    (
        fn_name: $fn_name:ident,
        request_type: $request_type:ty,
        flow_marker: $flow_marker:ty,
        resource_common_data_type: $resource_common_data_type:ty,
        request_data_type: $request_data_type:ty,
        response_data_type: $response_data_type:ty $(,)?
    ) => {
        pub fn $fn_name<
            T: domain_types::payment_method_data::PaymentMethodDataTypes
                + Default
                + Eq
                + std::fmt::Debug
                + Send
                + Sync
                + Clone
                + serde::Serialize
                + serde::de::DeserializeOwned
                + 'static,
        >(
            payload: $request_type,
            config: &std::sync::Arc<ucs_env::configs::Config>,
            connector: domain_types::connector_types::ConnectorEnum,
            connector_config: domain_types::router_data::ConnectorSpecificConfig,
            metadata: &common_utils::metadata::MaskedMetadata,
        ) -> Result<Option<common_utils::request::Request>, grpc_api_types::payments::IntegrationError> {

            let connector_data: connector_integration::types::ConnectorData<domain_types::payment_method_data::DefaultPCIHolder> =
                connector_integration::types::ConnectorData::get_connector_by_name(&connector);

            let connector_integration: interfaces::connector_integration_v2::BoxedConnectorIntegrationV2<
                '_,
                $flow_marker,
                $resource_common_data_type,
                $request_data_type,
                $response_data_type,
            > = connector_data.connector.get_connector_integration_v2();

            let connectors = ucs_interface_common::config::connectors_with_connector_config_overrides(
                &connector_config,
                config,
            )
            .map_err(|e: error_stack::Report<domain_types::errors::ApplicationErrorResponse>| {
                ucs_env::error::ErrorSwitch::switch(e.current_context())
            })?;

            let flow_data: $resource_common_data_type =
                domain_types::utils::ForeignTryFrom::foreign_try_from((
                    payload.clone(),
                    connectors,
                    metadata,
                ))
                .map_err(|e: error_stack::Report<domain_types::errors::ApplicationErrorResponse>| {
                    ucs_env::error::ErrorSwitch::switch(e.current_context())
                })?;

            let payment_request_data: $request_data_type =
                domain_types::utils::ForeignTryFrom::foreign_try_from((payload.clone(), None::<domain_types::payment_method_data::PaymentMethodData<domain_types::payment_method_data::DefaultPCIHolder>>))
                .map_err(|e: error_stack::Report<domain_types::errors::ApplicationErrorResponse>| {
                    ucs_env::error::ErrorSwitch::switch(e.current_context())
                })?;

            let router_data = domain_types::router_data_v2::RouterDataV2 {
                flow: std::marker::PhantomData,
                resource_common_data: flow_data,
                connector_config,
                request: payment_request_data,
                response: Err(domain_types::router_data::ErrorResponse::default()),
            };

            let connector_request = connector_integration
                .build_request_v2(&router_data)
                .map_err(|e: error_stack::Report<domain_types::errors::ConnectorError>| {
                    let app_error: domain_types::errors::ApplicationErrorResponse = ucs_env::error::ErrorSwitch::switch(e.current_context());
                    ucs_env::error::ErrorSwitch::switch(&app_error)
                })?;

            Ok(connector_request)
        }
    };
}

/// Macro to generate request transformer functions for token flows
///
/// Token flows first convert the token request type to the base request type
/// (e.g. `PaymentServiceTokenAuthorizeRequest` → `PaymentServiceAuthorizeRequest`)
/// using a converter function, then process via the payment method data pipeline.
macro_rules! req_transformer_token_to_base {
    (
        fn_name: $fn_name:ident,
        request_type: $request_type:ty,
        base_request_type: $base_request_type:ty,
        converter_fn: $converter_fn:path,
        flow_marker: $flow_marker:ty,
        resource_common_data_type: $resource_common_data_type:ty,
        request_data_type: $request_data_type:ty,
        response_data_type: $response_data_type:ty,
        request_for_ftf: $request_for_ftf:expr $(,)?
    ) => {
        pub fn $fn_name<
            T: domain_types::payment_method_data::PaymentMethodDataTypes
                + Default
                + Eq
                + std::fmt::Debug
                + Send
                + Sync
                + Clone
                + serde::Serialize
                + serde::de::DeserializeOwned
                + 'static,
        >(
            payload: $request_type,
            config: &std::sync::Arc<ucs_env::configs::Config>,
            connector: domain_types::connector_types::ConnectorEnum,
            connector_config: domain_types::router_data::ConnectorSpecificConfig,
            metadata: &common_utils::metadata::MaskedMetadata,
        ) -> Result<Option<common_utils::request::Request>, grpc_api_types::payments::IntegrationError> {

            // Convert token request to base request
            let base_payload: $base_request_type = $converter_fn(payload.clone());

            let connector_data: connector_integration::types::ConnectorData<domain_types::payment_method_data::DefaultPCIHolder> =
                connector_integration::types::ConnectorData::get_connector_by_name(&connector);

            let connector_integration: interfaces::connector_integration_v2::BoxedConnectorIntegrationV2<
                '_,
                $flow_marker,
                $resource_common_data_type,
                $request_data_type,
                $response_data_type,
            > = connector_data.connector.get_connector_integration_v2();

            let connectors = ucs_interface_common::config::connectors_with_connector_config_overrides(
                &connector_config,
                config,
            )
            .map_err(|e: error_stack::Report<domain_types::errors::ApplicationErrorResponse>| {
                ucs_env::error::ErrorSwitch::switch(e.current_context())
            })?;

            // Use original token payload for flow data (has its own ForeignTryFrom)
            let flow_data: $resource_common_data_type =
                domain_types::utils::ForeignTryFrom::foreign_try_from((
                    payload.clone(),
                    connectors,
                    metadata,
                ))
                .map_err(|e: error_stack::Report<domain_types::errors::ApplicationErrorResponse>| {
                    ucs_env::error::ErrorSwitch::switch(e.current_context())
                })?;

            // Process payment method data from the base payload (which has a synthetic payment_method)
            let payment_method_data_action = domain_types::types::PaymentMethodDataAction::get_payment_method_data_action(
                base_payload.payment_method.clone()
                    .ok_or_else(|| grpc_api_types::payments::IntegrationError {
                        error_message: "missing payment_method in the payload".to_string(),
                        error_code: "MISSING_PAYMENT_METHOD".to_string(),
                        suggested_action: None,
                        doc_url: None,
                    })?
            )
            .map_err(|_err| {
                grpc_api_types::payments::IntegrationError {
                    error_message: "Invalid payment method data".to_string(),
                    error_code: "INVALID_PAYMENT_METHOD_DATA".to_string(),
                    suggested_action: None,
                    doc_url: None,
                }
            })?;

            let payment_method_data = match payment_method_data_action {
                domain_types::types::PaymentMethodDataAction::Card(card_details) => {
                    let card = <domain_types::payment_method_data::Card<domain_types::payment_method_data::DefaultPCIHolder> as domain_types::utils::ForeignTryFrom<grpc_api_types::payments::CardDetails>>::foreign_try_from(card_details)
                        .map_err(|_err| {
                            grpc_api_types::payments::IntegrationError {
                                error_message: "Invalid card details".to_string(),
                                error_code: "INVALID_CARD_DETAILS".to_string(),
                                suggested_action: None,
                                doc_url: None,
                            }
                        })?;
                    Ok(domain_types::payment_method_data::PaymentMethodData::Card(card))
                }
                domain_types::types::PaymentMethodDataAction::Default => {
                    let pm_data = domain_types::payment_method_data::PaymentMethodData::convert_to_domain_model_for_non_card_payment_methods(
                        base_payload.payment_method.clone()
                            .ok_or_else(|| grpc_api_types::payments::IntegrationError {
                                error_message: "missing payment_method in the payload".to_string(),
                                error_code: "MISSING_PAYMENT_METHOD".to_string(),
                                suggested_action: None,
                                doc_url: None,
                            })?
                    )
                    .map_err(|_err| {
                        grpc_api_types::payments::IntegrationError {
                            error_message: "Invalid payment method data".to_string(),
                            error_code: "INVALID_PAYMENT_METHOD_DATA".to_string(),
                            suggested_action: None,
                            doc_url: None,
                        }
                    })?;
                    Ok(pm_data)
                }
                domain_types::types::PaymentMethodDataAction::CardProxy(_) => {
                    Err(grpc_api_types::payments::IntegrationError {
                        error_message: "CardProxy not supported in this flow".to_string(),
                        error_code: "UNSUPPORTED_PAYMENT_METHOD".to_string(),
                        suggested_action: None,
                        doc_url: None,
                    })
                }
            }?;

            let request_for_foreign_try_from = $request_for_ftf(&base_payload);

            let payment_request_data: $request_data_type =
                domain_types::utils::ForeignTryFrom::foreign_try_from((request_for_foreign_try_from, payment_method_data))
                .map_err(|e: error_stack::Report<domain_types::errors::ApplicationErrorResponse>| {
                    ucs_env::error::ErrorSwitch::switch(e.current_context())
                })?;

            let router_data = domain_types::router_data_v2::RouterDataV2 {
                flow: std::marker::PhantomData,
                resource_common_data: flow_data,
                connector_config,
                request: payment_request_data,
                response: Err(domain_types::router_data::ErrorResponse::default()),
            };

            let connector_request = connector_integration
                .build_request_v2(&router_data)
                .map_err(|e: error_stack::Report<domain_types::errors::ConnectorError>| {
                    let app_error: domain_types::errors::ApplicationErrorResponse = ucs_env::error::ErrorSwitch::switch(e.current_context());
                    ucs_env::error::ErrorSwitch::switch(&app_error)
                })?;

            Ok(connector_request)
        }
    };
}

/// Macro to generate response transformer functions for token flows
///
/// Similar to `req_transformer_token_to_base`, but for response processing.
macro_rules! res_transformer_token_to_base {
    (
        fn_name: $fn_name:ident,
        request_type: $request_type:ty,
        base_request_type: $base_request_type:ty,
        converter_fn: $converter_fn:path,
        response_type: $response_type:ty,
        flow_marker: $flow_marker:ty,
        resource_common_data_type: $resource_common_data_type:ty,
        request_data_type: $request_data_type:ty,
        response_data_type: $response_data_type:ty,
        generate_response_fn: $generate_response_fn:ident,
        request_for_ftf: $request_for_ftf:expr $(,)?
    ) => {
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
                + 'static,
        >(
            payload: $request_type,
            config: &std::sync::Arc<ucs_env::configs::Config>,
            connector: domain_types::connector_types::ConnectorEnum,
            connector_config: domain_types::router_data::ConnectorSpecificConfig,
            metadata: &common_utils::metadata::MaskedMetadata,
            response: domain_types::router_response_types::Response,
        ) -> Result<$response_type, grpc_api_types::payments::ConnectorResponseTransformationError> {

            // Convert token request to base request
            let base_payload: $base_request_type = $converter_fn(payload.clone());

            let connector_data: connector_integration::types::ConnectorData<domain_types::payment_method_data::DefaultPCIHolder> =
                connector_integration::types::ConnectorData::get_connector_by_name(&connector);

            let connector_integration: interfaces::connector_integration_v2::BoxedConnectorIntegrationV2<
                '_,
                $flow_marker,
                $resource_common_data_type,
                $request_data_type,
                $response_data_type,
            > = connector_data.connector.get_connector_integration_v2();

            let connectors = ucs_interface_common::config::connectors_with_connector_config_overrides(
                &connector_config,
                config,
            )
            .map_err(|e: error_stack::Report<domain_types::errors::ApplicationErrorResponse>| {
                ucs_env::error::ErrorSwitch::switch(e.current_context())
            })?;

            let flow_data: $resource_common_data_type =
                domain_types::utils::ForeignTryFrom::foreign_try_from((
                    payload.clone(),
                    connectors,
                    metadata,
                ))
                .map_err(|e: error_stack::Report<domain_types::errors::ApplicationErrorResponse>| {
                    ucs_env::error::ErrorSwitch::switch(e.current_context())
                })?;

            // Process payment method data from the base payload
            let payment_method_data_action = domain_types::types::PaymentMethodDataAction::get_payment_method_data_action(
                base_payload.payment_method.clone()
                    .ok_or_else(|| {
                        let app_error = domain_types::errors::ApplicationErrorResponse::BadRequest(domain_types::errors::ApiError {
                            sub_code: "MISSING_PAYMENT_METHOD".to_string(),
                            error_identifier: 400,
                            error_message: "missing payment_method in the payload".to_string(),
                            error_object: None,
                        });
                        let ie: grpc_api_types::payments::ConnectorResponseTransformationError = ucs_env::error::ErrorSwitch::switch(&app_error);
                        ie
                    })?
            )
            .map_err(|e: error_stack::Report<domain_types::errors::ApplicationErrorResponse>| {
                ucs_env::error::ErrorSwitch::switch(e.current_context())
            })?;

            let payment_method_data = match payment_method_data_action {
                domain_types::types::PaymentMethodDataAction::Card(card_details) => {
                    let card = <domain_types::payment_method_data::Card<domain_types::payment_method_data::DefaultPCIHolder> as domain_types::utils::ForeignTryFrom<grpc_api_types::payments::CardDetails>>::foreign_try_from(card_details)
                        .map_err(|e: error_stack::Report<domain_types::errors::ApplicationErrorResponse>| {
                            ucs_env::error::ErrorSwitch::switch(e.current_context())
                        })?;
                    Ok(domain_types::payment_method_data::PaymentMethodData::Card(card))
                }
                domain_types::types::PaymentMethodDataAction::Default => {
                    let pm_data = domain_types::payment_method_data::PaymentMethodData::convert_to_domain_model_for_non_card_payment_methods(
                        base_payload.payment_method.clone()
                            .ok_or_else(|| {
                                let app_error = domain_types::errors::ApplicationErrorResponse::BadRequest(domain_types::errors::ApiError {
                                    sub_code: "MISSING_PAYMENT_METHOD".to_string(),
                                    error_identifier: 400,
                                    error_message: "missing payment_method in the payload".to_string(),
                                    error_object: None,
                                });
                                let ie: grpc_api_types::payments::ConnectorResponseTransformationError = ucs_env::error::ErrorSwitch::switch(&app_error);
                                ie
                            })?
                    )
                    .map_err(|e: error_stack::Report<domain_types::errors::ApplicationErrorResponse>| {
                        ucs_env::error::ErrorSwitch::switch(e.current_context())
                    })?;
                    Ok(pm_data)
                }
                domain_types::types::PaymentMethodDataAction::CardProxy(_) => {
                    let app_error = domain_types::errors::ApplicationErrorResponse::BadRequest(domain_types::errors::ApiError {
                        sub_code: "UNSUPPORTED_PAYMENT_METHOD".to_string(),
                        error_identifier: 400,
                        error_message: "CardProxy not supported in this flow".to_string(),
                        error_object: None,
                    });
                    Err(ucs_env::error::ErrorSwitch::switch(&app_error))
                }
            }?;

            let request_for_foreign_try_from = $request_for_ftf(&base_payload);

            let payment_request_data: $request_data_type =
                domain_types::utils::ForeignTryFrom::foreign_try_from((request_for_foreign_try_from, payment_method_data))
                .map_err(|e: error_stack::Report<domain_types::errors::ApplicationErrorResponse>| {
                    ucs_env::error::ErrorSwitch::switch(e.current_context())
                })?;

            let router_data = domain_types::router_data_v2::RouterDataV2 {
                flow: std::marker::PhantomData,
                resource_common_data: flow_data,
                connector_config,
                request: payment_request_data,
                response: Err(domain_types::router_data::ErrorResponse::default()),
            };

            let classified_response = match response.status_code {
                200..=399 => Ok(response),
                _ => Err(response),
            };
            let response = external_services::service::handle_connector_response(
                Ok(classified_response),
                router_data,
                &connector_integration,
                None,
                None,
                common_utils::Method::Post,
                "".to_string(),
                None,
            )
            .map_err(|e: error_stack::Report<domain_types::errors::ConnectorError>| {
                let app_error: domain_types::errors::ApplicationErrorResponse = ucs_env::error::ErrorSwitch::switch(e.current_context());
                ucs_env::error::ErrorSwitch::switch(&app_error)
            })?;

            domain_types::types::$generate_response_fn(response)
                .map_err(|e: error_stack::Report<domain_types::errors::ApplicationErrorResponse>| {
                    ucs_env::error::ErrorSwitch::switch(e.current_context())
                })
        }
    };
}

/// Macro to generate response transformer functions
///
/// # Example
/// res_transformer! {
///     fn_name: authorize_res_transformer,
///     request_type: PaymentServiceAuthorizeRequest,
///     response_type: PaymentServiceAuthorizeResponse,
///     flow_marker: Authorize,
///     request_data_type: PaymentsAuthorizeData<T>,
///     generate_response_fn: generate_payment_authorize_response,
/// }
/// ```
macro_rules! res_transformer {
    (
        fn_name: $fn_name:ident,
        request_type: $request_type:ty,
        response_type: $response_type:ty,
        flow_marker: $flow_marker:ty,
        resource_common_data_type: $resource_common_data_type:ty,
        request_data_type: $request_data_type:ty,
        response_data_type: $response_data_type:ty,
        generate_response_fn: $generate_response_fn:ident,
    ) => {
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
                + 'static,
        >(
            payload: $request_type,
            config: &std::sync::Arc<ucs_env::configs::Config>,
            connector: domain_types::connector_types::ConnectorEnum,
            connector_config: domain_types::router_data::ConnectorSpecificConfig,
            metadata: &common_utils::metadata::MaskedMetadata,
            response: domain_types::router_response_types::Response,
        ) -> Result<$response_type, grpc_api_types::payments::ConnectorResponseTransformationError> {
            let connector_data: connector_integration::types::ConnectorData<T> =
                connector_integration::types::ConnectorData::get_connector_by_name(&connector);

            let connector_integration: interfaces::connector_integration_v2::BoxedConnectorIntegrationV2<
                '_,
                $flow_marker,
                $resource_common_data_type,
                $request_data_type,
                $response_data_type,
            > = connector_data.connector.get_connector_integration_v2();

            let connectors = ucs_interface_common::config::connectors_with_connector_config_overrides(
                &connector_config,
                config,
            )
            .map_err(|e: error_stack::Report<domain_types::errors::ApplicationErrorResponse>| {
                ucs_env::error::ErrorSwitch::switch(e.current_context())
            })?;

            let flow_data: $resource_common_data_type =
                domain_types::utils::ForeignTryFrom::foreign_try_from((
                    payload.clone(),
                    connectors,
                    metadata,
                ))
                .map_err(|e: error_stack::Report<domain_types::errors::ApplicationErrorResponse>| {
                    ucs_env::error::ErrorSwitch::switch(e.current_context())
                })?;

            let payment_request_data: $request_data_type =
                domain_types::utils::ForeignTryFrom::foreign_try_from(payload.clone())
                .map_err(|e: error_stack::Report<domain_types::errors::ApplicationErrorResponse>| {
                    ucs_env::error::ErrorSwitch::switch(e.current_context())
                })?;

            let router_data = domain_types::router_data_v2::RouterDataV2 {
                flow: std::marker::PhantomData,
                resource_common_data: flow_data,
                connector_config,
                request: payment_request_data,
                response: Err(domain_types::router_data::ErrorResponse::default()),
            };

            // transform connector response type to common response type
            // Classify response based on status code: 2xx/3xx = success, 4xx/5xx = error
            let classified_response = match response.status_code {
                200..=399 => Ok(response),
                _ => Err(response),
            };
            let response = external_services::service::handle_connector_response(
                Ok(classified_response),
                router_data,
                &connector_integration,
                None,
                None,
                common_utils::Method::Post,
                "".to_string(),
                None,
            )
            .map_err(|e: error_stack::Report<domain_types::errors::ConnectorError>| {
                let app_error: domain_types::errors::ApplicationErrorResponse = ucs_env::error::ErrorSwitch::switch(e.current_context());
                ucs_env::error::ErrorSwitch::switch(&app_error)
            })?;

            domain_types::types::$generate_response_fn(response)
                .map_err(|e: error_stack::Report<domain_types::errors::ApplicationErrorResponse>| {
                    ucs_env::error::ErrorSwitch::switch(e.current_context())
                })
        }
    };
}

/// Macro to generate response transformer functions with payment method data processing
macro_rules! res_transformer_with_payment_method_data {
    (
        fn_name: $fn_name:ident,
        request_type: $request_type:ty,
        response_type: $response_type:ty,
        flow_marker: $flow_marker:ty,
        resource_common_data_type: $resource_common_data_type:ty,
        request_data_type: $request_data_type:ty,
        response_data_type: $response_data_type:ty,
        generate_response_fn: $generate_response_fn:ident,
        request_for_ftf: $request_for_ftf:expr $(,)?
    ) => {
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
                + 'static,
        >(
            payload: $request_type,
            config: &std::sync::Arc<ucs_env::configs::Config>,
            connector: domain_types::connector_types::ConnectorEnum,
            connector_config: domain_types::router_data::ConnectorSpecificConfig,
            metadata: &common_utils::metadata::MaskedMetadata,
            response: domain_types::router_response_types::Response,
        ) -> Result<$response_type, grpc_api_types::payments::ConnectorResponseTransformationError> {
            let connector_data: connector_integration::types::ConnectorData<domain_types::payment_method_data::DefaultPCIHolder> =
                connector_integration::types::ConnectorData::get_connector_by_name(&connector);

            let connector_integration: interfaces::connector_integration_v2::BoxedConnectorIntegrationV2<
                '_,
                $flow_marker,
                $resource_common_data_type,
                $request_data_type,
                $response_data_type,
            > = connector_data.connector.get_connector_integration_v2();

            let connectors = ucs_interface_common::config::connectors_with_connector_config_overrides(
                &connector_config,
                config,
            )
            .map_err(|e: error_stack::Report<domain_types::errors::ApplicationErrorResponse>| {
                ucs_env::error::ErrorSwitch::switch(e.current_context())
            })?;

            let flow_data: $resource_common_data_type =
                domain_types::utils::ForeignTryFrom::foreign_try_from((
                    payload.clone(),
                    connectors,
                    metadata,
                ))
                .map_err(|e: error_stack::Report<domain_types::errors::ApplicationErrorResponse>| {
                    ucs_env::error::ErrorSwitch::switch(e.current_context())
                })?;

            // Process payment method data
            let payment_method_data_action = domain_types::types::PaymentMethodDataAction::get_payment_method_data_action(
                payload.payment_method.clone()
                    .ok_or_else(|| {
                        let app_error = domain_types::errors::ApplicationErrorResponse::BadRequest(domain_types::errors::ApiError {
                            sub_code: "MISSING_PAYMENT_METHOD".to_string(),
                            error_identifier: 400,
                            error_message: "missing payment_method in the payload".to_string(),
                            error_object: None,
                        });
                        let ie: grpc_api_types::payments::ConnectorResponseTransformationError = ucs_env::error::ErrorSwitch::switch(&app_error);
                        ie
                    })?
            )
            .map_err(|e: error_stack::Report<domain_types::errors::ApplicationErrorResponse>| {
                ucs_env::error::ErrorSwitch::switch(e.current_context())
            })?;

            let payment_method_data = match payment_method_data_action {
                domain_types::types::PaymentMethodDataAction::Card(card_details) => {
                    let card = <domain_types::payment_method_data::Card<domain_types::payment_method_data::DefaultPCIHolder> as domain_types::utils::ForeignTryFrom<grpc_api_types::payments::CardDetails>>::foreign_try_from(card_details)
                        .map_err(|e: error_stack::Report<domain_types::errors::ApplicationErrorResponse>| {
                            ucs_env::error::ErrorSwitch::switch(e.current_context())
                        })?;
                    Ok(domain_types::payment_method_data::PaymentMethodData::Card(card))
                }
                domain_types::types::PaymentMethodDataAction::Default => {
                    let pm_data = domain_types::payment_method_data::PaymentMethodData::convert_to_domain_model_for_non_card_payment_methods(
                        payload.payment_method.clone()
                            .ok_or_else(|| {
                                let app_error = domain_types::errors::ApplicationErrorResponse::BadRequest(domain_types::errors::ApiError {
                                    sub_code: "MISSING_PAYMENT_METHOD".to_string(),
                                    error_identifier: 400,
                                    error_message: "missing payment_method in the payload".to_string(),
                                    error_object: None,
                                });
                                let ie: grpc_api_types::payments::ConnectorResponseTransformationError = ucs_env::error::ErrorSwitch::switch(&app_error);
                                ie
                            })?
                    )
                    .map_err(|e: error_stack::Report<domain_types::errors::ApplicationErrorResponse>| {
                        ucs_env::error::ErrorSwitch::switch(e.current_context())
                    })?;
                    Ok(pm_data)
                }
                domain_types::types::PaymentMethodDataAction::CardProxy(_) => {
                    let app_error = domain_types::errors::ApplicationErrorResponse::BadRequest(domain_types::errors::ApiError {
                        sub_code: "UNSUPPORTED_PAYMENT_METHOD".to_string(),
                        error_identifier: 400,
                        error_message: "CardProxy not supported in this flow".to_string(),
                        error_object: None,
                    });
                    Err(ucs_env::error::ErrorSwitch::switch(&app_error))
                }
            }?;

            let request_for_foreign_try_from = $request_for_ftf(&payload);

            let payment_request_data: $request_data_type =
                domain_types::utils::ForeignTryFrom::foreign_try_from((request_for_foreign_try_from, payment_method_data))
                .map_err(|e: error_stack::Report<domain_types::errors::ApplicationErrorResponse>| {
                    ucs_env::error::ErrorSwitch::switch(e.current_context())
                })?;

            let router_data = domain_types::router_data_v2::RouterDataV2 {
                flow: std::marker::PhantomData,
                resource_common_data: flow_data,
                connector_config,
                request: payment_request_data,
                response: Err(domain_types::router_data::ErrorResponse::default()),
            };

            let classified_response = match response.status_code {
                200..=399 => Ok(response),
                _ => Err(response),
            };
            let response = external_services::service::handle_connector_response(
                Ok(classified_response),
                router_data,
                &connector_integration,
                None,
                None,
                common_utils::Method::Post,
                "".to_string(),
                None,
            )
            .map_err(|e: error_stack::Report<domain_types::errors::ConnectorError>| {
                let app_error: domain_types::errors::ApplicationErrorResponse = ucs_env::error::ErrorSwitch::switch(e.current_context());
                ucs_env::error::ErrorSwitch::switch(&app_error)
            })?;

            domain_types::types::$generate_response_fn(response)
                .map_err(|e: error_stack::Report<domain_types::errors::ApplicationErrorResponse>| {
                    ucs_env::error::ErrorSwitch::switch(e.current_context())
                })
        }
    };
}

/// Macro to generate response transformer functions with Option<PaymentMethodData>
macro_rules! res_transformer_with_optional_payment_method_data {
    (
        fn_name: $fn_name:ident,
        request_type: $request_type:ty,
        response_type: $response_type:ty,
        flow_marker: $flow_marker:ty,
        resource_common_data_type: $resource_common_data_type:ty,
        request_data_type: $request_data_type:ty,
        response_data_type: $response_data_type:ty,
        generate_response_fn: $generate_response_fn:ident,
    ) => {
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
                + 'static,
        >(
            payload: $request_type,
            config: &std::sync::Arc<ucs_env::configs::Config>,
            connector: domain_types::connector_types::ConnectorEnum,
            connector_config: domain_types::router_data::ConnectorSpecificConfig,
            metadata: &common_utils::metadata::MaskedMetadata,
            response: domain_types::router_response_types::Response,
        ) -> Result<$response_type, grpc_api_types::payments::ConnectorResponseTransformationError> {
            let connector_data: connector_integration::types::ConnectorData<domain_types::payment_method_data::DefaultPCIHolder> =
                connector_integration::types::ConnectorData::get_connector_by_name(&connector);

            let connector_integration: interfaces::connector_integration_v2::BoxedConnectorIntegrationV2<
                '_,
                $flow_marker,
                $resource_common_data_type,
                $request_data_type,
                $response_data_type,
            > = connector_data.connector.get_connector_integration_v2();

            let connectors = ucs_interface_common::config::connectors_with_connector_config_overrides(
                &connector_config,
                config,
            )
            .map_err(|e: error_stack::Report<domain_types::errors::ApplicationErrorResponse>| {
                ucs_env::error::ErrorSwitch::switch(e.current_context())
            })?;

            let flow_data: $resource_common_data_type =
                domain_types::utils::ForeignTryFrom::foreign_try_from((
                    payload.clone(),
                    connectors,
                    metadata,
                ))
                .map_err(|e: error_stack::Report<domain_types::errors::ApplicationErrorResponse>| {
                    ucs_env::error::ErrorSwitch::switch(e.current_context())
                })?;

            let payment_request_data: $request_data_type =
                domain_types::utils::ForeignTryFrom::foreign_try_from((payload.clone(), None::<domain_types::payment_method_data::PaymentMethodData<domain_types::payment_method_data::DefaultPCIHolder>>))
                .map_err(|e: error_stack::Report<domain_types::errors::ApplicationErrorResponse>| {
                    ucs_env::error::ErrorSwitch::switch(e.current_context())
                })?;

            let router_data = domain_types::router_data_v2::RouterDataV2 {
                flow: std::marker::PhantomData,
                resource_common_data: flow_data,
                connector_config,
                request: payment_request_data,
                response: Err(domain_types::router_data::ErrorResponse::default()),
            };

            let classified_response = match response.status_code {
                200..=399 => Ok(response),
                _ => Err(response),
            };
            let response = external_services::service::handle_connector_response(
                Ok(classified_response),
                router_data,
                &connector_integration,
                None,
                None,
                common_utils::Method::Post,
                "".to_string(),
                None,
            )
            .map_err(|e: error_stack::Report<domain_types::errors::ConnectorError>| {
                let app_error: domain_types::errors::ApplicationErrorResponse = ucs_env::error::ErrorSwitch::switch(e.current_context());
                ucs_env::error::ErrorSwitch::switch(&app_error)
            })?;

            domain_types::types::$generate_response_fn(response)
                .map_err(|e: error_stack::Report<domain_types::errors::ApplicationErrorResponse>| {
                    ucs_env::error::ErrorSwitch::switch(e.current_context())
                })
        }
    };
}

/// Macro to generate payout request transformer functions
///
/// # Example
/// payout_req_transformer!(
///     fn_name: payout_create_payout_req_transformer,
///     request_type: PayoutServiceCreateRequest,
///     flow_marker: PayoutCreate,
///     resource_common_data_type: PayoutFlowData,
///     request_data_type: PayoutCreateRequest,
///     response_data_type: PayoutCreateResponse,
/// );
/// ```
macro_rules! payout_req_transformer {
    (
        fn_name: $fn_name:ident,
        request_type: $request_type:ty,
        flow_marker: $flow_marker:ty,
        resource_common_data_type: $resource_common_data_type:ty,
        request_data_type: $request_data_type:ty,
        response_data_type: $response_data_type:ty $(,)?
    ) => {
        pub fn $fn_name<
            T: domain_types::payment_method_data::PaymentMethodDataTypes
                + Default
                + Eq
                + std::fmt::Debug
                + Send
                + Sync
                + Clone
                + serde::Serialize
                + serde::de::DeserializeOwned
                + 'static,
        >(
            payload: $request_type,
            config: &std::sync::Arc<ucs_env::configs::Config>,
            connector: domain_types::connector_types::ConnectorEnum,
            connector_config: domain_types::router_data::ConnectorSpecificConfig,
            metadata: &common_utils::metadata::MaskedMetadata,
        ) -> Result<Option<common_utils::request::Request>, grpc_api_types::payments::IntegrationError> {

            let connector_data: connector_integration::types::ConnectorData<T> =
                connector_integration::types::ConnectorData::get_connector_by_name(&connector);

            let connector_integration: interfaces::connector_integration_v2::BoxedConnectorIntegrationV2<
                '_,
                $flow_marker,
                $resource_common_data_type,
                $request_data_type,
                $response_data_type,
            > = connector_data.connector.get_connector_integration_v2();

            let connectors = ucs_interface_common::config::connectors_with_connector_config_overrides(
                &connector_config,
                config,
            )
            .map_err(|e: error_stack::Report<domain_types::errors::ApplicationErrorResponse>| {
                ucs_env::error::ErrorSwitch::switch(e.current_context())
            })?;

            let flow_data: $resource_common_data_type =
                domain_types::utils::ForeignTryFrom::foreign_try_from((
                    payload.clone(),
                    connectors,
                    metadata,
                ))
                .map_err(|e: error_stack::Report<domain_types::errors::ApplicationErrorResponse>| {
                    ucs_env::error::ErrorSwitch::switch(e.current_context())
                })?;

            let payment_request_data: $request_data_type =
                domain_types::utils::ForeignTryFrom::foreign_try_from(payload.clone())
                .map_err(|e: error_stack::Report<domain_types::errors::ApplicationErrorResponse>| {
                    ucs_env::error::ErrorSwitch::switch(e.current_context())
                })?;

            let router_data = domain_types::router_data_v2::RouterDataV2 {
                flow: std::marker::PhantomData,
                resource_common_data: flow_data,
                connector_config,
                request: payment_request_data,
                response: Err(domain_types::router_data::ErrorResponse::default()),
            };

            let connector_request = connector_integration
                .build_request_v2(&router_data)
                .map_err(|e: error_stack::Report<domain_types::errors::ConnectorError>| {
                    let app_error: domain_types::errors::ApplicationErrorResponse = ucs_env::error::ErrorSwitch::switch(e.current_context());
                    ucs_env::error::ErrorSwitch::switch(&app_error)
                })?;

            Ok(connector_request)
        }
    };
}

/// Macro to generate payout response transformer functions
///
/// # Example
/// payout_res_transformer!(
///     fn_name: payout_create_payout_res_transformer,
///     request_type: PayoutServiceCreateRequest,
///     response_type: PayoutServiceCreateResponse,
///     flow_marker: PayoutCreate,
///     resource_common_data_type: PayoutFlowData,
///     request_data_type: PayoutCreateRequest,
///     response_data_type: PayoutCreateResponse,
///     generate_response_fn: generate_payout_create_response,
/// );
/// ```
macro_rules! payout_res_transformer {
    (
        fn_name: $fn_name:ident,
        request_type: $request_type:ty,
        response_type: $response_type:ty,
        flow_marker: $flow_marker:ty,
        resource_common_data_type: $resource_common_data_type:ty,
        request_data_type: $request_data_type:ty,
        response_data_type: $response_data_type:ty,
        generate_response_fn: $generate_response_fn:ident,
    ) => {
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
                + 'static,
        >(
            payload: $request_type,
            config: &std::sync::Arc<ucs_env::configs::Config>,
            connector: domain_types::connector_types::ConnectorEnum,
            connector_config: domain_types::router_data::ConnectorSpecificConfig,
            metadata: &common_utils::metadata::MaskedMetadata,
            response: domain_types::router_response_types::Response,
        ) -> Result<$response_type, grpc_api_types::payments::ConnectorResponseTransformationError> {
            let connector_data: connector_integration::types::ConnectorData<T> =
                connector_integration::types::ConnectorData::get_connector_by_name(&connector);

            let connector_integration: interfaces::connector_integration_v2::BoxedConnectorIntegrationV2<
                '_,
                $flow_marker,
                $resource_common_data_type,
                $request_data_type,
                $response_data_type,
            > = connector_data.connector.get_connector_integration_v2();

            let connectors = ucs_interface_common::config::connectors_with_connector_config_overrides(
                &connector_config,
                config,
            )
            .map_err(|e: error_stack::Report<domain_types::errors::ApplicationErrorResponse>| {
                ucs_env::error::ErrorSwitch::switch(e.current_context())
            })?;

            let flow_data: $resource_common_data_type =
                domain_types::utils::ForeignTryFrom::foreign_try_from((
                    payload.clone(),
                    connectors,
                    metadata,
                ))
                .map_err(|e: error_stack::Report<domain_types::errors::ApplicationErrorResponse>| {
                    ucs_env::error::ErrorSwitch::switch(e.current_context())
                })?;

            let payment_request_data: $request_data_type =
                domain_types::utils::ForeignTryFrom::foreign_try_from(payload.clone())
                .map_err(|e: error_stack::Report<domain_types::errors::ApplicationErrorResponse>| {
                    ucs_env::error::ErrorSwitch::switch(e.current_context())
                })?;

            let router_data = domain_types::router_data_v2::RouterDataV2 {
                flow: std::marker::PhantomData,
                resource_common_data: flow_data,
                connector_config,
                request: payment_request_data,
                response: Err(domain_types::router_data::ErrorResponse::default()),
            };

            // transform connector response type to common response type
            // Classify response based on status code: 2xx/3xx = success, 4xx/5xx = error
            let classified_response = match response.status_code {
                200..=399 => Ok(response),
                _ => Err(response),
            };
            let response = external_services::service::handle_connector_response(
                Ok(classified_response),
                router_data,
                &connector_integration,
                None,
                None,
                common_utils::Method::Post,
                "".to_string(),
                None,
            )
            .map_err(|e: error_stack::Report<domain_types::errors::ConnectorError>| {
                let app_error: domain_types::errors::ApplicationErrorResponse = ucs_env::error::ErrorSwitch::switch(e.current_context());
                ucs_env::error::ErrorSwitch::switch(&app_error)
            })?;

            domain_types::payouts::types::$generate_response_fn(response)
                .map_err(|e: error_stack::Report<domain_types::errors::ApplicationErrorResponse>| {
                    ucs_env::error::ErrorSwitch::switch(e.current_context())
                })
        }
    };
}

pub(crate) use payout_req_transformer;
pub(crate) use payout_res_transformer;
pub(crate) use req_transformer;
pub(crate) use req_transformer_token_to_base;
pub(crate) use req_transformer_with_optional_payment_method_data;
pub(crate) use req_transformer_with_payment_method_data;
pub(crate) use res_transformer;
pub(crate) use res_transformer_token_to_base;
pub(crate) use res_transformer_with_optional_payment_method_data;
pub(crate) use res_transformer_with_payment_method_data;
