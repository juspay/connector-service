use std::{fmt::Debug, sync::Arc};

use common_enums;
use common_utils::{
    errors::CustomResult,
    events::{EventConfig, FlowName},
    lineage,
    pii::SecretSerdeValue,
};
use connector_integration::types::ConnectorData;
use domain_types::{
    connector_flow::{
        Authorize, Capture, CreateOrder, CreateSessionToken, PSync, PaymentMethodToken, Refund,
        RepeatPayment, SetupMandate, Void,
    },
    connector_types::{
        PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData,
        PaymentMethodTokenResponse, PaymentMethodTokenizationData, PaymentVoidData,
        PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData, PaymentsSyncData,
        RefundFlowData, RefundsData, RefundsResponseData, RepeatPaymentData,
        SessionTokenRequestData, SessionTokenResponseData, SetupMandateRequestData,
    },
    errors::{ApiError, ApplicationErrorResponse},
    payment_method_data::{DefaultPCIHolder, PaymentMethodDataTypes, VaultTokenHolder},
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    types::{
        generate_payment_capture_response, generate_payment_sync_response,
        generate_payment_void_response, generate_refund_response, generate_repeat_payment_response,
        generate_setup_mandate_response,
    },
    utils::ForeignTryFrom,
};
use error_stack::ResultExt;
use external_services::service::EventProcessingParams;
use grpc_api_types::payments::{
    payment_method, payment_service_server::PaymentService, DisputeResponse,
    PaymentServiceAuthorizeRequest, PaymentServiceAuthorizeResponse, PaymentServiceCaptureRequest,
    PaymentServiceCaptureResponse, PaymentServiceDisputeRequest, PaymentServiceGetRequest,
    PaymentServiceGetResponse, PaymentServiceRefundRequest, PaymentServiceRegisterRequest,
    PaymentServiceRegisterResponse, PaymentServiceRepeatEverythingRequest,
    PaymentServiceRepeatEverythingResponse, PaymentServiceTransformRequest,
    PaymentServiceTransformResponse, PaymentServiceVoidRequest, PaymentServiceVoidResponse,
    RefundResponse,
};
use hyperswitch_masking::{ErasedMaskSerialize, ExposeInterface};
use injector::{TokenData, VaultConnectors};
use interfaces::connector_integration_v2::BoxedConnectorIntegrationV2;
use tracing::info;

use crate::{
    configs::Config,
    error::{IntoGrpcStatus, PaymentAuthorizationError, ReportSwitchExt, ResultExtGrpc},
    implement_connector_operation,
    utils::{self, auth_from_metadata, grpc_logging_wrapper},
};

#[derive(Debug, Clone)]
struct EventParams<'a> {
    _connector_name: &'a str,
    _service_name: &'a str,
    request_id: &'a str,
    lineage_ids: &'a lineage::LineageIds<'a>,
    reference_id: &'a Option<String>,
}

/// Helper function for converting CardDetails to TokenData with structured types
#[derive(Debug, serde::Serialize)]
struct CardTokenData {
    card_number: String,
    cvv: String,
    exp_month: String,
    exp_year: String,
}

trait ToTokenData {
    fn to_token_data(&self) -> TokenData;
    fn to_token_data_with_vault(&self, vault_connector: VaultConnectors) -> TokenData;
}

impl ToTokenData for grpc_api_types::payments::CardDetails {
    fn to_token_data(&self) -> TokenData {
        self.to_token_data_with_vault(VaultConnectors::VGS)
    }

    fn to_token_data_with_vault(&self, vault_connector: VaultConnectors) -> TokenData {
        let card_data = CardTokenData {
            card_number: self
                .card_number
                .as_ref()
                .map(|cn| cn.to_string())
                .unwrap_or_default(),
            cvv: self
                .card_cvc
                .as_ref()
                .map(|cvc| cvc.clone().expose().to_string())
                .unwrap_or_default(),
            exp_month: self
                .card_exp_month
                .as_ref()
                .map(|em| em.clone().expose().to_string())
                .unwrap_or_default(),
            exp_year: self
                .card_exp_year
                .as_ref()
                .map(|ey| ey.clone().expose().to_string())
                .unwrap_or_default(),
        };

        let card_json = serde_json::to_value(card_data).unwrap_or(serde_json::Value::Null);

        TokenData {
            specific_token_data: SecretSerdeValue::new(card_json),
            vault_connector,
        }
    }
}
// Helper trait for payment operations
trait PaymentOperationsInternal {
    async fn internal_payment_sync(
        &self,
        request: tonic::Request<PaymentServiceGetRequest>,
    ) -> Result<tonic::Response<PaymentServiceGetResponse>, tonic::Status>;

    async fn internal_void_payment(
        &self,
        request: tonic::Request<PaymentServiceVoidRequest>,
    ) -> Result<tonic::Response<PaymentServiceVoidResponse>, tonic::Status>;

    async fn internal_refund(
        &self,
        request: tonic::Request<PaymentServiceRefundRequest>,
    ) -> Result<tonic::Response<RefundResponse>, tonic::Status>;

    async fn internal_payment_capture(
        &self,
        request: tonic::Request<PaymentServiceCaptureRequest>,
    ) -> Result<tonic::Response<PaymentServiceCaptureResponse>, tonic::Status>;
}

#[derive(Clone)]
pub struct Payments {
    pub config: Arc<Config>,
}

impl Payments {
    #[allow(clippy::too_many_arguments)]
    async fn process_authorization_internal<
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
        &self,
        payload: PaymentServiceAuthorizeRequest,
        connector: domain_types::connector_types::ConnectorEnum,
        connector_auth_details: ConnectorAuthType,
        metadata: &tonic::metadata::MetadataMap,
        metadata_payload: &utils::MetadataPayload,
        service_name: &str,
        request_id: &str,
        token_data: Option<TokenData>,
    ) -> Result<PaymentServiceAuthorizeResponse, PaymentAuthorizationError> {
        //get connector data
        let connector_data = ConnectorData::get_connector_by_name(&connector);

        // Get connector integration
        let connector_integration: BoxedConnectorIntegrationV2<
            '_,
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData<T>,
            PaymentsResponseData,
        > = connector_data.connector.get_connector_integration_v2();

        // Create common request data
        let payment_flow_data = PaymentFlowData::foreign_try_from((
            payload.clone(),
            self.config.connectors.clone(),
            metadata,
        ))
        .map_err(|err| {
            tracing::error!("Failed to process payment flow data: {:?}", err);
            PaymentAuthorizationError::new(
                grpc_api_types::payments::PaymentStatus::Pending,
                Some("Failed to process payment flow data".to_string()),
                Some("PAYMENT_FLOW_ERROR".to_string()),
                None,
            )
        })?;

        let lineage_ids = &metadata_payload.lineage_ids;
        let reference_id = &metadata_payload.reference_id;
        let should_do_order_create = connector_data.connector.should_do_order_create();

        let payment_flow_data = if should_do_order_create {
            let event_params = EventParams {
                _connector_name: &connector.to_string(),
                _service_name: service_name,
                request_id,
                lineage_ids,
                reference_id,
            };

            let order_id = self
                .handle_order_creation(
                    connector_data.clone(),
                    &payment_flow_data,
                    connector_auth_details.clone(),
                    &payload,
                    &connector.to_string(),
                    service_name,
                    event_params,
                )
                .await?;

            tracing::info!("Order created successfully with order_id: {}", order_id);
            payment_flow_data.set_order_reference_id(Some(order_id))
        } else {
            payment_flow_data
        };

        let should_do_session_token = connector_data.connector.should_do_session_token();

        let payment_flow_data = if should_do_session_token {
            let event_params = EventParams {
                _connector_name: &connector.to_string(),
                _service_name: service_name,
                request_id,
                lineage_ids,
                reference_id,
            };

            let payment_session_data = self
                .handle_session_token(
                    connector_data.clone(),
                    &payment_flow_data,
                    connector_auth_details.clone(),
                    &payload,
                    &connector.to_string(),
                    service_name,
                    event_params,
                )
                .await?;
            tracing::info!(
                "Session Token created successfully with session_id: {}",
                payment_session_data.session_token
            );
            payment_flow_data.set_session_token_id(Some(payment_session_data.session_token))
        } else {
            payment_flow_data
        };

        let should_do_payment_method_token =
            connector_data.connector.should_do_payment_method_token();

        let payment_flow_data = if should_do_payment_method_token {
            let event_params = EventParams {
                _connector_name: &connector.to_string(),
                _service_name: service_name,
                request_id,
                lineage_ids,
                reference_id,
            };
            let payment_method_token_data = self
                .handle_payment_session_token(
                    connector_data.clone(),
                    &payment_flow_data,
                    connector_auth_details.clone(),
                    event_params,
                    &payload,
                    &connector.to_string(),
                    service_name,
                )
                .await?;
            tracing::info!("Payment Method Token created successfully");
            payment_flow_data.set_payment_method_token(Some(payment_method_token_data.token))
        } else {
            payment_flow_data
        };

        // This duplicate session token check has been removed - the session token handling is already done above

        // Create connector request data
        let payment_authorize_data = PaymentsAuthorizeData::foreign_try_from(payload.clone())
            .map_err(|err| {
                tracing::error!("Failed to process payment authorize data: {:?}", err);
                PaymentAuthorizationError::new(
                    grpc_api_types::payments::PaymentStatus::Pending,
                    Some("Failed to process payment authorize data".to_string()),
                    Some("PAYMENT_AUTHORIZE_DATA_ERROR".to_string()),
                    None,
                )
            })?
            // Set session token from payment flow data if available
            .set_session_token(payment_flow_data.session_token.clone());

        // Construct router data
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

        // Execute connector processing
        let event_params = EventProcessingParams {
            connector_name: &connector.to_string(),
            service_name,
            flow_name: FlowName::Authorize,
            event_config: &self.config.events,
            raw_request_data: Some(SecretSerdeValue::new(
                payload.masked_serialize().unwrap_or_default(),
            )),
            request_id,
            lineage_ids,
            reference_id,
        };

        // Execute connector processing
        let response = external_services::service::execute_connector_processing_step(
            &self.config.proxy,
            connector_integration,
            router_data,
            None,
            event_params,
            token_data,
        )
        .await;

        // Generate response - pass both success and error cases
        let authorize_response = match response {
            Ok(success_response) => domain_types::types::generate_payment_authorize_response(
                success_response,
            )
            .map_err(|err| {
                tracing::error!("Failed to generate authorize response: {:?}", err);
                PaymentAuthorizationError::new(
                    grpc_api_types::payments::PaymentStatus::Pending,
                    Some("Failed to generate authorize response".to_string()),
                    Some("RESPONSE_GENERATION_ERROR".to_string()),
                    None,
                )
            })?,
            Err(error_report) => {
                // Convert error to RouterDataV2 with error response
                let error_router_data = RouterDataV2 {
                    flow: std::marker::PhantomData,
                    resource_common_data: payment_flow_data,
                    connector_auth_type: connector_auth_details,
                    request: PaymentsAuthorizeData::foreign_try_from(payload.clone()).map_err(
                        |err| {
                            tracing::error!(
                                "Failed to process payment authorize data in error path: {:?}",
                                err
                            );
                            PaymentAuthorizationError::new(
                                grpc_api_types::payments::PaymentStatus::Pending,
                                Some(
                                    "Failed to process payment authorize data in error path"
                                        .to_string(),
                                ),
                                Some("PAYMENT_AUTHORIZE_DATA_ERROR".to_string()),
                                None,
                            )
                        },
                    )?,
                    response: Err(ErrorResponse {
                        status_code: 400,
                        code: "CONNECTOR_ERROR".to_string(),
                        message: format!("{error_report}"),
                        reason: None,
                        attempt_status: Some(common_enums::AttemptStatus::Failure),
                        connector_transaction_id: None,
                        network_decline_code: None,
                        network_advice_code: None,
                        network_error_message: None,
                    }),
                };
                domain_types::types::generate_payment_authorize_response::<T>(error_router_data)
                    .map_err(|err| {
                        tracing::error!(
                            "Failed to generate authorize response for connector error: {:?}",
                            err
                        );
                        PaymentAuthorizationError::new(
                            grpc_api_types::payments::PaymentStatus::Pending,
                            Some(format!("Connector error: {error_report}")),
                            Some("CONNECTOR_ERROR".to_string()),
                            None,
                        )
                    })?
            }
        };

        Ok(authorize_response)
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_order_creation<
        T: PaymentMethodDataTypes
            + Default
            + Eq
            + Debug
            + Send
            + serde::Serialize
            + serde::de::DeserializeOwned
            + Clone
            + Sync
            + domain_types::types::CardConversionHelper<T>,
    >(
        &self,
        connector_data: ConnectorData<T>,
        payment_flow_data: &PaymentFlowData,
        connector_auth_details: ConnectorAuthType,
        payload: &PaymentServiceAuthorizeRequest,
        connector_name: &str,
        service_name: &str,
        event_params: EventParams<'_>,
    ) -> Result<String, PaymentAuthorizationError> {
        // Get connector integration
        let connector_integration: BoxedConnectorIntegrationV2<
            '_,
            CreateOrder,
            PaymentFlowData,
            PaymentCreateOrderData,
            PaymentCreateOrderResponse,
        > = connector_data.connector.get_connector_integration_v2();

        let currency =
            common_enums::Currency::foreign_try_from(payload.currency()).map_err(|e| {
                PaymentAuthorizationError::new(
                    grpc_api_types::payments::PaymentStatus::Pending,
                    Some(format!("Currency conversion failed: {e}")),
                    Some("CURRENCY_ERROR".to_string()),
                    None,
                )
            })?;

        let order_create_data = PaymentCreateOrderData {
            amount: common_utils::types::MinorUnit::new(payload.minor_amount),
            currency,
            integrity_object: None,
            metadata: if payload.metadata.is_empty() {
                None
            } else {
                Some(serde_json::to_value(payload.metadata.clone()).unwrap_or_default())
            },
            webhook_url: payload.webhook_url.clone(),
        };

        let order_router_data = RouterDataV2::<
            CreateOrder,
            PaymentFlowData,
            PaymentCreateOrderData,
            PaymentCreateOrderResponse,
        > {
            flow: std::marker::PhantomData,
            resource_common_data: payment_flow_data.clone(),
            connector_auth_type: connector_auth_details,
            request: order_create_data,
            response: Err(ErrorResponse::default()),
        };

        // Create event processing parameters
        let external_event_config = EventConfig::default();
        let external_event_params = EventProcessingParams {
            connector_name,
            service_name,
            flow_name: FlowName::CreateOrder,
            event_config: &external_event_config,
            raw_request_data: Some(SecretSerdeValue::new(
                serde_json::to_value(payload).unwrap_or_default(),
            )),
            request_id: event_params.request_id,
            lineage_ids: event_params.lineage_ids,
            reference_id: event_params.reference_id,
        };

        // Execute connector processing
        let response = external_services::service::execute_connector_processing_step(
            &self.config.proxy,
            connector_integration,
            order_router_data,
            None,
            external_event_params,
            None,
        )
        .await
        .map_err(
            |e: error_stack::Report<domain_types::errors::ConnectorError>| {
                PaymentAuthorizationError::new(
                    grpc_api_types::payments::PaymentStatus::Pending,
                    Some(format!("Order creation failed: {e}")),
                    Some("ORDER_CREATION_ERROR".to_string()),
                    None,
                )
            },
        )?;

        match response.response {
            Ok(PaymentCreateOrderResponse { order_id, .. }) => Ok(order_id),
            Err(e) => Err(PaymentAuthorizationError::new(
                grpc_api_types::payments::PaymentStatus::Pending,
                Some(e.message.clone()),
                Some(e.code.clone()),
                Some(e.status_code.into()),
            )),
        }
    }
    #[allow(clippy::too_many_arguments)]
    async fn handle_order_creation_for_setup_mandate<
        T: PaymentMethodDataTypes
            + Default
            + Eq
            + Debug
            + Send
            + serde::Serialize
            + serde::de::DeserializeOwned
            + Clone
            + Sync
            + domain_types::types::CardConversionHelper<T>,
    >(
        &self,
        connector_data: ConnectorData<T>,
        payment_flow_data: &PaymentFlowData,
        connector_auth_details: ConnectorAuthType,
        event_params: EventParams<'_>,
        payload: &PaymentServiceRegisterRequest,
        connector_name: &str,
        service_name: &str,
    ) -> Result<String, tonic::Status> {
        // Get connector integration
        let connector_integration: BoxedConnectorIntegrationV2<
            '_,
            CreateOrder,
            PaymentFlowData,
            PaymentCreateOrderData,
            PaymentCreateOrderResponse,
        > = connector_data.connector.get_connector_integration_v2();

        let currency = common_enums::Currency::foreign_try_from(payload.currency())
            .map_err(|e| e.into_grpc_status())?;

        let order_create_data = PaymentCreateOrderData {
            amount: common_utils::types::MinorUnit::new(0),
            currency,
            integrity_object: None,
            metadata: if payload.metadata.is_empty() {
                None
            } else {
                Some(serde_json::to_value(payload.metadata.clone()).unwrap_or_default())
            },
            webhook_url: payload.webhook_url.clone(),
        };

        let order_router_data = RouterDataV2::<
            CreateOrder,
            PaymentFlowData,
            PaymentCreateOrderData,
            PaymentCreateOrderResponse,
        > {
            flow: std::marker::PhantomData,
            resource_common_data: payment_flow_data.clone(),
            connector_auth_type: connector_auth_details,
            request: order_create_data,
            response: Err(ErrorResponse::default()),
        };

        // Execute connector processing
        let external_event_config = EventConfig::default();
        let external_event_params = EventProcessingParams {
            connector_name,
            service_name,
            flow_name: FlowName::CreateOrder,
            event_config: &external_event_config,
            raw_request_data: Some(SecretSerdeValue::new(
                serde_json::to_value(payload).unwrap_or_default(),
            )),
            request_id: event_params.request_id,
            lineage_ids: event_params.lineage_ids,
            reference_id: event_params.reference_id,
        };

        // Execute connector processing
        let response = external_services::service::execute_connector_processing_step(
            &self.config.proxy,
            connector_integration,
            order_router_data,
            None,
            external_event_params,
            None,
        )
        .await
        .switch()
        .map_err(|e| e.into_grpc_status())?;

        match response.response {
            Ok(PaymentCreateOrderResponse { order_id, .. }) => Ok(order_id),
            Err(ErrorResponse { message, .. }) => Err(tonic::Status::internal(format!(
                "Order creation error: {message}"
            ))),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_session_token<
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
        P: serde::Serialize + Clone,
    >(
        &self,
        connector_data: ConnectorData<T>,
        payment_flow_data: &PaymentFlowData,
        connector_auth_details: ConnectorAuthType,
        payload: &P,
        connector_name: &str,
        service_name: &str,
        event_params: EventParams<'_>,
    ) -> Result<SessionTokenResponseData, PaymentAuthorizationError>
    where
        SessionTokenRequestData: ForeignTryFrom<P, Error = ApplicationErrorResponse>,
    {
        // Get connector integration
        let connector_integration: BoxedConnectorIntegrationV2<
            '_,
            CreateSessionToken,
            PaymentFlowData,
            SessionTokenRequestData,
            SessionTokenResponseData,
        > = connector_data.connector.get_connector_integration_v2();

        // Create session token request data using try_from_foreign
        let session_token_request_data = SessionTokenRequestData::foreign_try_from(payload.clone())
            .map_err(|e| {
                PaymentAuthorizationError::new(
                    grpc_api_types::payments::PaymentStatus::Pending,
                    Some(format!("Session Token creation failed: {e}")),
                    Some("SESSION_TOKEN_CREATION_ERROR".to_string()),
                    Some(400), // Bad Request - client data issue
                )
            })?;

        let session_token_router_data = RouterDataV2::<
            CreateSessionToken,
            PaymentFlowData,
            SessionTokenRequestData,
            SessionTokenResponseData,
        > {
            flow: std::marker::PhantomData,
            resource_common_data: payment_flow_data.clone(),
            connector_auth_type: connector_auth_details,
            request: session_token_request_data,
            response: Err(ErrorResponse::default()),
        };

        // Create event processing parameters
        let external_event_config = EventConfig::default();
        let external_event_params = EventProcessingParams {
            connector_name,
            service_name,
            flow_name: FlowName::CreateSessionToken,
            event_config: &external_event_config,
            raw_request_data: Some(SecretSerdeValue::new(
                serde_json::to_value(payload).unwrap_or_default(),
            )),
            request_id: event_params.request_id,
            lineage_ids: event_params.lineage_ids,
            reference_id: event_params.reference_id,
        };

        // Execute connector processing
        let response = external_services::service::execute_connector_processing_step(
            &self.config.proxy,
            connector_integration,
            session_token_router_data,
            None,
            external_event_params,
            None,
        )
        .await
        .switch()
        .map_err(|e: error_stack::Report<ApplicationErrorResponse>| {
            PaymentAuthorizationError::new(
                grpc_api_types::payments::PaymentStatus::Pending,
                Some(format!("Session Token creation failed: {e}")),
                Some("SESSION_TOKEN_CREATION_ERROR".to_string()),
                Some(500), // Internal Server Error - connector processing failed
            )
        })?;

        match response.response {
            Ok(session_token_data) => {
                tracing::info!(
                    "Session token created successfully: {}",
                    session_token_data.session_token
                );
                Ok(session_token_data)
            }
            Err(ErrorResponse {
                message,
                status_code,
                ..
            }) => Err(PaymentAuthorizationError::new(
                grpc_api_types::payments::PaymentStatus::Pending,
                Some(format!("Session Token creation failed: {message}")),
                Some("SESSION_TOKEN_CREATION_ERROR".to_string()),
                Some(status_code.into()), // Use actual status code from ErrorResponse
            )),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_payment_session_token<
        T: PaymentMethodDataTypes
            + Default
            + Eq
            + Debug
            + Send
            + serde::Serialize
            + serde::de::DeserializeOwned
            + Clone
            + Sync
            + domain_types::types::CardConversionHelper<T>,
    >(
        &self,
        connector_data: ConnectorData<T>,
        payment_flow_data: &PaymentFlowData,
        connector_auth_details: ConnectorAuthType,
        event_params: EventParams<'_>,
        payload: &PaymentServiceAuthorizeRequest,
        connector_name: &str,
        service_name: &str,
    ) -> Result<PaymentMethodTokenResponse, PaymentAuthorizationError> {
        // Get connector integration
        let connector_integration: BoxedConnectorIntegrationV2<
            '_,
            PaymentMethodToken,
            PaymentFlowData,
            PaymentMethodTokenizationData<T>,
            PaymentMethodTokenResponse,
        > = connector_data.connector.get_connector_integration_v2();

        let currency =
            common_enums::Currency::foreign_try_from(payload.currency()).map_err(|e| {
                PaymentAuthorizationError::new(
                    grpc_api_types::payments::PaymentStatus::Pending,
                    Some(format!("Currency conversion failed: {e}")),
                    Some("CURRENCY_ERROR".to_string()),
                    None,
                )
            })?;
        let payment_method_tokenization_data = PaymentMethodTokenizationData {
            amount: common_utils::types::MinorUnit::new(payload.amount),
            currency,
            integrity_object: None,
            browser_info: None,
            customer_acceptance: None,
            mandate_id: None,
            setup_future_usage: None,
            setup_mandate_details: None,
            payment_method_data:
                domain_types::payment_method_data::PaymentMethodData::foreign_try_from(
                    payload.payment_method.clone().ok_or_else(|| {
                        PaymentAuthorizationError::new(
                            grpc_api_types::payments::PaymentStatus::Pending,
                            Some("Payment method is required".to_string()),
                            Some("PAYMENT_METHOD_MISSING".to_string()),
                            None,
                        )
                    })?,
                )
                .map_err(|e| {
                    PaymentAuthorizationError::new(
                        grpc_api_types::payments::PaymentStatus::Pending,
                        Some(format!("Payment method data conversion failed: {e}")),
                        Some("PAYMENT_METHOD_DATA_ERROR".to_string()),
                        None,
                    )
                })?,
        };

        let payment_method_token_router_data = RouterDataV2::<
            PaymentMethodToken,
            PaymentFlowData,
            PaymentMethodTokenizationData<T>,
            PaymentMethodTokenResponse,
        > {
            flow: std::marker::PhantomData,
            resource_common_data: payment_flow_data.clone(),
            connector_auth_type: connector_auth_details,
            request: payment_method_tokenization_data,
            response: Err(ErrorResponse::default()),
        };

        // Execute connector processing
        let external_event_params = EventProcessingParams {
            connector_name,
            service_name,
            flow_name: FlowName::PaymentMethodToken,
            event_config: &self.config.events,
            raw_request_data: Some(SecretSerdeValue::new(
                serde_json::to_value(payload).unwrap_or_default(),
            )),
            request_id: event_params.request_id,
            lineage_ids: event_params.lineage_ids,
            reference_id: event_params.reference_id,
        };
        let response = external_services::service::execute_connector_processing_step(
            &self.config.proxy,
            connector_integration,
            payment_method_token_router_data,
            None,
            external_event_params,
            None,
        )
        .await
        .switch()
        .map_err(|e: error_stack::Report<ApplicationErrorResponse>| {
            PaymentAuthorizationError::new(
                grpc_api_types::payments::PaymentStatus::Pending,
                Some(format!("Payment Method Token creation failed: {e}")),
                Some("PAYMENT_METHOD_TOKEN_CREATION_ERROR".to_string()),
                Some(500),
            )
        })?;

        match response.response {
            Ok(payment_method_token_data) => {
                tracing::info!("Payment method token created successfully");
                Ok(payment_method_token_data)
            }
            Err(ErrorResponse {
                message,
                status_code,
                ..
            }) => Err(PaymentAuthorizationError::new(
                grpc_api_types::payments::PaymentStatus::Pending,
                Some(format!("Payment Method Token creation failed: {message}")),
                Some("PAYMENT_METHOD_TOKEN_CREATION_ERROR".to_string()),
                Some(status_code.into()),
            )),
        }
    }
}

impl PaymentOperationsInternal for Payments {
    implement_connector_operation!(
        fn_name: internal_payment_sync,
        log_prefix: "PAYMENT_SYNC",
        request_type: PaymentServiceGetRequest,
        response_type: PaymentServiceGetResponse,
        flow_marker: PSync,
        resource_common_data_type: PaymentFlowData,
        request_data_type: PaymentsSyncData,
        response_data_type: PaymentsResponseData,
        request_data_constructor: PaymentsSyncData::foreign_try_from,
        common_flow_data_constructor: PaymentFlowData::foreign_try_from,
        generate_response_fn: generate_payment_sync_response,
        all_keys_required: None
    );

    implement_connector_operation!(
        fn_name: internal_void_payment,
        log_prefix: "PAYMENT_VOID",
        request_type: PaymentServiceVoidRequest,
        response_type: PaymentServiceVoidResponse,
        flow_marker: Void,
        resource_common_data_type: PaymentFlowData,
        request_data_type: PaymentVoidData,
        response_data_type: PaymentsResponseData,
        request_data_constructor: PaymentVoidData::foreign_try_from,
        common_flow_data_constructor: PaymentFlowData::foreign_try_from,
        generate_response_fn: generate_payment_void_response,
        all_keys_required: None
    );

    implement_connector_operation!(
        fn_name: internal_refund,
        log_prefix: "REFUND",
        request_type: PaymentServiceRefundRequest,
        response_type: RefundResponse,
        flow_marker: Refund,
        resource_common_data_type: RefundFlowData,
        request_data_type: RefundsData,
        response_data_type: RefundsResponseData,
        request_data_constructor: RefundsData::foreign_try_from,
        common_flow_data_constructor: RefundFlowData::foreign_try_from,
        generate_response_fn: generate_refund_response,
        all_keys_required: None
    );

    implement_connector_operation!(
        fn_name: internal_payment_capture,
        log_prefix: "PAYMENT_CAPTURE",
        request_type: PaymentServiceCaptureRequest,
        response_type: PaymentServiceCaptureResponse,
        flow_marker: Capture,
        resource_common_data_type: PaymentFlowData,
        request_data_type: PaymentsCaptureData,
        response_data_type: PaymentsResponseData,
        request_data_constructor: PaymentsCaptureData::foreign_try_from,
        common_flow_data_constructor: PaymentFlowData::foreign_try_from,
        generate_response_fn: generate_payment_capture_response,
        all_keys_required: None
    );
}

#[tonic::async_trait]
impl PaymentService for Payments {
    #[tracing::instrument(
        name = "payment_authorize",
        fields(
            name = common_utils::consts::NAME,
            service_name = tracing::field::Empty,
            service_method = FlowName::Authorize.as_str(),
            request_body = tracing::field::Empty,
            response_body = tracing::field::Empty,
            error_message = tracing::field::Empty,
            merchant_id = tracing::field::Empty,
            gateway = tracing::field::Empty,
            request_id = tracing::field::Empty,
            status_code = tracing::field::Empty,
            message_ = "Golden Log Line (incoming)",
            response_time = tracing::field::Empty,
            tenant_id = tracing::field::Empty,
            flow = FlowName::Authorize.as_str(),
            flow_specific_fields.status = tracing::field::Empty,
        )
        skip(self, request)
    )]
    async fn authorize(
        &self,
        request: tonic::Request<PaymentServiceAuthorizeRequest>,
    ) -> Result<tonic::Response<PaymentServiceAuthorizeResponse>, tonic::Status> {
        info!("PAYMENT_AUTHORIZE_FLOW: initiated");
        let service_name = request
            .extensions()
            .get::<String>()
            .cloned()
            .unwrap_or_else(|| "unknown_service".to_string());
        grpc_logging_wrapper(request, &service_name, self.config.clone(), |request, metadata_payload| {
            let service_name = service_name.clone();
            Box::pin(async move {
                let utils::MetadataPayload {connector, ref request_id, ..} = metadata_payload;
                let metadata = request.metadata().clone();
                let connector_auth_details =
                    auth_from_metadata(&metadata).map_err(|e| e.into_grpc_status())?;
                let payload = request.into_inner();

                let authorize_response = match payload.payment_method.as_ref() {
                    Some(pm) => {
                        match pm.payment_method.as_ref() {
                            Some(payment_method::PaymentMethod::Card(card_details)) => {
                                match &card_details.card_type {
                                    Some(grpc_api_types::payments::card_payment_method_type::CardType::CreditProxy(proxy_card_details)) | Some(grpc_api_types::payments::card_payment_method_type::CardType::DebitProxy(proxy_card_details)) => {
                                        let token_data = proxy_card_details.to_token_data();
                                        match Box::pin(self.process_authorization_internal::<VaultTokenHolder>(
                                            payload,
                                            connector,
                                            connector_auth_details,
                                            &metadata,
                                            &metadata_payload,
                                            &service_name,
                                            request_id,
                                            Some(token_data),
                                        ))
                                        .await
                                        {
                                            Ok(response) => {
                                                tracing::info!("INJECTOR: Authorization completed successfully with injector");
                                                response
                                            },
                                            Err(error_response) => {
                                                tracing::error!("INJECTOR: Authorization failed with injector - error: {:?}", error_response);
                                                PaymentServiceAuthorizeResponse::from(error_response)
                                            },
                                        }
                                    }
                                    _ => {
                                        tracing::info!("REGULAR: Processing regular payment (no injector)");
                                        match Box::pin(self.process_authorization_internal::<DefaultPCIHolder>(
                                            payload,
                                            connector,
                                            connector_auth_details,
                                            &metadata,
                                            &metadata_payload,
                                            &service_name,
                                            request_id,
                                            None,
                                        ))
                                        .await
                                        {
                                            Ok(response) => {
                                                tracing::info!("REGULAR: Authorization completed successfully without injector");
                                                response
                                            },
                                            Err(error_response) => {
                                                tracing::error!("REGULAR: Authorization failed without injector - error: {:?}", error_response);
                                                PaymentServiceAuthorizeResponse::from(error_response)
                                            },
                                        }
                                    }
                                }
                            }
                            _ => {
                                match Box::pin(self.process_authorization_internal::<DefaultPCIHolder>(
                                    payload,
                                    connector,
                                    connector_auth_details,
                                    &metadata,
                                    &metadata_payload,
                                    &service_name,
                                    request_id,
                                    None,
                                ))
                                .await
                                {
                                    Ok(response) => response,
                                    Err(error_response) => PaymentServiceAuthorizeResponse::from(error_response),
                                }
                            }
                        }
                    }
                    _ => {
                        match Box::pin(self.process_authorization_internal::<DefaultPCIHolder>(
                            payload,
                            connector,
                            connector_auth_details,
                            &metadata,
                            &metadata_payload,
                            &service_name,
                            request_id,
                            None,
                        ))
                        .await
                        {
                            Ok(response) => response,
                            Err(error_response) => PaymentServiceAuthorizeResponse::from(error_response),
                        }
                    }
                };

                Ok(tonic::Response::new(authorize_response))
            })
        })
        .await
    }

    #[tracing::instrument(
        name = "payment_sync",
        fields(
            name = common_utils::consts::NAME,
            service_name = common_utils::consts::PAYMENT_SERVICE_NAME,
            service_method = FlowName::Psync.as_str(),
            request_body = tracing::field::Empty,
            response_body = tracing::field::Empty,
            error_message = tracing::field::Empty,
            merchant_id = tracing::field::Empty,
            gateway = tracing::field::Empty,
            request_id = tracing::field::Empty,
            status_code = tracing::field::Empty,
            message = "Golden Log Line (incoming)",
            response_time = tracing::field::Empty,
            tenant_id = tracing::field::Empty,
            flow = FlowName::Psync.as_str(),
            flow_specific_fields.status = tracing::field::Empty,
        )
        skip(self, request)
    )]
    async fn get(
        &self,
        request: tonic::Request<PaymentServiceGetRequest>,
    ) -> Result<tonic::Response<PaymentServiceGetResponse>, tonic::Status> {
        self.internal_payment_sync(request).await
    }

    #[tracing::instrument(
        name = "payment_void",
        fields(
            name = common_utils::consts::NAME,
            service_name = common_utils::consts::PAYMENT_SERVICE_NAME,
            service_method = FlowName::Void.as_str(),
            request_body = tracing::field::Empty,
            response_body = tracing::field::Empty,
            error_message = tracing::field::Empty,
            merchant_id = tracing::field::Empty,
            gateway = tracing::field::Empty,
            request_id = tracing::field::Empty,
            status_code = tracing::field::Empty,
            message_ = "Golden Log Line (incoming)",
            response_time = tracing::field::Empty,
            tenant_id = tracing::field::Empty,
            flow = FlowName::Void.as_str(),
            flow_specific_fields.status = tracing::field::Empty,
        )
        skip(self, request)
    )]
    async fn void(
        &self,
        request: tonic::Request<PaymentServiceVoidRequest>,
    ) -> Result<tonic::Response<PaymentServiceVoidResponse>, tonic::Status> {
        self.internal_void_payment(request).await
    }

    #[tracing::instrument(
        name = "incoming_webhook",
        fields(
            name = common_utils::consts::NAME,
            service_name = common_utils::consts::PAYMENT_SERVICE_NAME,
            service_method = FlowName::IncomingWebhook.as_str(),
            request_body = tracing::field::Empty,
            response_body = tracing::field::Empty,
            error_message = tracing::field::Empty,
            merchant_id = tracing::field::Empty,
            gateway = tracing::field::Empty,
            request_id = tracing::field::Empty,
            status_code = tracing::field::Empty,
            message_ = "Golden Log Line (incoming)",
            response_time = tracing::field::Empty,
            tenant_id = tracing::field::Empty,
            flow = FlowName::IncomingWebhook.as_str(),
            flow_specific_fields.status = tracing::field::Empty,
        )
        skip(self, request)
    )]
    async fn transform(
        &self,
        request: tonic::Request<PaymentServiceTransformRequest>,
    ) -> Result<tonic::Response<PaymentServiceTransformResponse>, tonic::Status> {
        let service_name = request
            .extensions()
            .get::<String>()
            .cloned()
            .unwrap_or_else(|| "unknown_service".to_string());
        grpc_logging_wrapper(
            request,
            &service_name,
            self.config.clone(),
            |request, metadata_payload| {
                async move {
                    let connector = metadata_payload.connector;
                    let connector_auth_details = metadata_payload.connector_auth_type;
                    let payload = request.into_inner();
                    let request_details = payload
                        .request_details
                        .map(domain_types::connector_types::RequestDetails::foreign_try_from)
                        .ok_or_else(|| {
                            tonic::Status::invalid_argument("missing request_details in the payload")
                        })?
                        .map_err(|e| e.into_grpc_status())?;
                    let webhook_secrets = payload
                        .webhook_secrets
                        .map(|details| {
                            domain_types::connector_types::ConnectorWebhookSecrets::foreign_try_from(
                                details,
                            )
                            .map_err(|e| e.into_grpc_status())
                        })
                        .transpose()?;
                    //get connector data
                    let connector_data: ConnectorData<DefaultPCIHolder> =
                        ConnectorData::get_connector_by_name(&connector);

                    let source_verified = match connector_data
                    .connector
                    .verify_webhook_source(
                        request_details.clone(),
                        webhook_secrets.clone(),
                        Some(connector_auth_details.clone()),
                    ) {
                    Ok(result) => result,
                    Err(err) => {
                        tracing::warn!(
                            target: "webhook",
                            "{:?}",
                            err
                        );
                        false
                    }
                };

                    let event_type = connector_data
                        .connector
                        .get_event_type(
                            request_details.clone(),
                            webhook_secrets.clone(),
                            Some(connector_auth_details.clone()),
                        )
                        .switch()
                        .into_grpc_status()?;
                    // Get content for the webhook based on the event type using categorization
                    let content = if event_type.is_payment_event() {
                        get_payments_webhook_content(
                            connector_data,
                            request_details,
                            webhook_secrets,
                            Some(connector_auth_details),
                        )
                        .await
                        .into_grpc_status()?
                    } else if event_type.is_refund_event() {
                        get_refunds_webhook_content(
                            connector_data,
                            request_details,
                            webhook_secrets,
                            Some(connector_auth_details),
                        )
                        .await
                        .into_grpc_status()?
                    } else if event_type.is_dispute_event() {
                        get_disputes_webhook_content(
                            connector_data,
                            request_details,
                            webhook_secrets,
                            Some(connector_auth_details),
                        )
                        .await
                        .into_grpc_status()?
                    } else {
                        // For all other event types, default to payment webhook content for now
                        // This includes mandate, payout, recovery, and misc events
                        get_payments_webhook_content(
                            connector_data,
                            request_details,
                            webhook_secrets,
                            Some(connector_auth_details),
                        )
                        .await
                        .into_grpc_status()?
                    };
                    let api_event_type =
                        grpc_api_types::payments::WebhookEventType::foreign_try_from(event_type)
                            .map_err(|e| e.into_grpc_status())?;
                    let response = PaymentServiceTransformResponse {
                        event_type: api_event_type.into(),
                        content: Some(content),
                        source_verified,
                        response_ref_id: None,
                    };
                    Ok(tonic::Response::new(response))
                }
            },
        )
        .await
    }

    #[tracing::instrument(
        name = "refund",
        fields(
            name = common_utils::consts::NAME,
            service_name = common_utils::consts::PAYMENT_SERVICE_NAME,
            service_method = FlowName::Refund.as_str(),
            request_body = tracing::field::Empty,
            response_body = tracing::field::Empty,
            error_message = tracing::field::Empty,
            merchant_id = tracing::field::Empty,
            gateway = tracing::field::Empty,
            request_id = tracing::field::Empty,
            status_code = tracing::field::Empty,
            message_ = "Golden Log Line (incoming)",
            response_time = tracing::field::Empty,
            tenant_id = tracing::field::Empty,
            flow = FlowName::Refund.as_str(),
            flow_specific_fields.status = tracing::field::Empty,
        )
        skip(self, request)
    )]
    async fn refund(
        &self,
        request: tonic::Request<PaymentServiceRefundRequest>,
    ) -> Result<tonic::Response<RefundResponse>, tonic::Status> {
        self.internal_refund(request).await
    }

    #[tracing::instrument(
        name = "defend_dispute",
        fields(
            name = common_utils::consts::NAME,
            service_name = common_utils::consts::PAYMENT_SERVICE_NAME,
            service_method = FlowName::DefendDispute.as_str(),
            request_body = tracing::field::Empty,
            response_body = tracing::field::Empty,
            error_message = tracing::field::Empty,
            merchant_id = tracing::field::Empty,
            gateway = tracing::field::Empty,
            request_id = tracing::field::Empty,
            status_code = tracing::field::Empty,
            message_ = "Golden Log Line (incoming)",
            response_time = tracing::field::Empty,
            tenant_id = tracing::field::Empty,
            flow = FlowName::DefendDispute.as_str(),
            flow_specific_fields.status = tracing::field::Empty,
        )
        skip(self, request)
    )]
    async fn dispute(
        &self,
        request: tonic::Request<PaymentServiceDisputeRequest>,
    ) -> Result<tonic::Response<DisputeResponse>, tonic::Status> {
        let service_name = request
            .extensions()
            .get::<String>()
            .cloned()
            .unwrap_or_else(|| "unknown_service".to_string());
        grpc_logging_wrapper(
            request,
            &service_name,
            self.config.clone(),
            |_request, _metadata_payload| async {
                let response = DisputeResponse {
                    ..Default::default()
                };
                Ok(tonic::Response::new(response))
            },
        )
        .await
    }

    #[tracing::instrument(
        name = "payment_capture",
        fields(
            name = common_utils::consts::NAME,
            service_name = common_utils::consts::PAYMENT_SERVICE_NAME,
            service_method = FlowName::Capture.as_str(),
            request_body = tracing::field::Empty,
            response_body = tracing::field::Empty,
            error_message = tracing::field::Empty,
            merchant_id = tracing::field::Empty,
            gateway = tracing::field::Empty,
            request_id = tracing::field::Empty,
            status_code = tracing::field::Empty,
            message_ = "Golden Log Line (incoming)",
            response_time = tracing::field::Empty,
            tenant_id = tracing::field::Empty,
            flow = FlowName::Capture.as_str(),
            flow_specific_fields.status = tracing::field::Empty,
        )
        skip(self, request)
    )]
    async fn capture(
        &self,
        request: tonic::Request<PaymentServiceCaptureRequest>,
    ) -> Result<tonic::Response<PaymentServiceCaptureResponse>, tonic::Status> {
        self.internal_payment_capture(request).await
    }

    #[tracing::instrument(
        name = "setup_mandate",
        fields(
            name = common_utils::consts::NAME,
            service_name = common_utils::consts::PAYMENT_SERVICE_NAME,
            service_method = FlowName::SetupMandate.as_str(),
            request_body = tracing::field::Empty,
            response_body = tracing::field::Empty,
            error_message = tracing::field::Empty,
            merchant_id = tracing::field::Empty,
            gateway = tracing::field::Empty,
            request_id = tracing::field::Empty,
            status_code = tracing::field::Empty,
            message_ = "Golden Log Line (incoming)",
            response_time = tracing::field::Empty,
            tenant_id = tracing::field::Empty,
            flow = FlowName::SetupMandate.as_str(),
            flow_specific_fields.status = tracing::field::Empty,
        )
        skip(self, request)
    )]
    async fn register(
        &self,
        request: tonic::Request<PaymentServiceRegisterRequest>,
    ) -> Result<tonic::Response<PaymentServiceRegisterResponse>, tonic::Status> {
        info!("SETUP_MANDATE_FLOW: initiated");
        let service_name = request
            .extensions()
            .get::<String>()
            .cloned()
            .unwrap_or_else(|| "unknown_service".to_string());
        grpc_logging_wrapper(
            request,
            &service_name,
            self.config.clone(),
            |request, metadata_payload| {
                let service_name = service_name.clone();
                Box::pin(async move {
                    let (connector, request_id) =
                        (metadata_payload.connector, metadata_payload.request_id);
                    let connector_auth_details = metadata_payload.connector_auth_type;
                    let metadata = request.metadata().clone();
                    let payload = request.into_inner();

                    //get connector data
                    let connector_data = ConnectorData::get_connector_by_name(&connector);

                    // Get connector integration
                    let connector_integration: BoxedConnectorIntegrationV2<
                        '_,
                        SetupMandate,
                        PaymentFlowData,
                        SetupMandateRequestData<DefaultPCIHolder>,
                        PaymentsResponseData,
                    > = connector_data.connector.get_connector_integration_v2();

                    // Create common request data
                    let payment_flow_data = PaymentFlowData::foreign_try_from((
                        payload.clone(),
                        self.config.connectors.clone(),
                        self.config.common.environment.clone(),
                        &metadata,
                    ))
                    .map_err(|e| e.into_grpc_status())?;

                    let should_do_order_create = connector_data.connector.should_do_order_create();

                    let order_id = if should_do_order_create {
                        let event_params = EventParams {
                            _connector_name: &connector.to_string(),
                            _service_name: &service_name,
                            request_id: &request_id,
                            lineage_ids: &metadata_payload.lineage_ids,
                            reference_id: &metadata_payload.reference_id,
                        };

                        Some(
                            self.handle_order_creation_for_setup_mandate(
                                connector_data.clone(),
                                &payment_flow_data,
                                connector_auth_details.clone(),
                                event_params,
                                &payload,
                                &connector.to_string(),
                                &service_name,
                            )
                            .await?,
                        )
                    } else {
                        None
                    };
                    let payment_flow_data = payment_flow_data.set_order_reference_id(order_id);

                    let setup_mandate_request_data =
                        SetupMandateRequestData::foreign_try_from(payload.clone())
                            .map_err(|e| e.into_grpc_status())?;

                    // Create router data
                    let router_data: RouterDataV2<
                        SetupMandate,
                        PaymentFlowData,
                        SetupMandateRequestData<DefaultPCIHolder>,
                        PaymentsResponseData,
                    > = RouterDataV2 {
                        flow: std::marker::PhantomData,
                        resource_common_data: payment_flow_data,
                        connector_auth_type: connector_auth_details,
                        request: setup_mandate_request_data,
                        response: Err(ErrorResponse::default()),
                    };
                    // Create event processing parameters
                    let event_config = EventConfig::default();
                    let event_params = EventProcessingParams {
                        connector_name: &connector.to_string(),
                        service_name: &service_name,
                        flow_name: FlowName::SetupMandate,
                        event_config: &event_config,
                        raw_request_data: Some(SecretSerdeValue::new(
                            serde_json::to_value(payload).unwrap_or_default(),
                        )),
                        request_id: &request_id,
                        lineage_ids: &metadata_payload.lineage_ids,
                        reference_id: &metadata_payload.reference_id,
                    };

                    let response = external_services::service::execute_connector_processing_step(
                        &self.config.proxy,
                        connector_integration,
                        router_data,
                        None,
                        event_params,
                        None, // token_data - None for non-proxy payments
                    )
                    .await
                    .switch()
                    .map_err(|e| e.into_grpc_status())?;

                    // Generate response
                    let setup_mandate_response = generate_setup_mandate_response(response)
                        .map_err(|e| e.into_grpc_status())?;

                    Ok(tonic::Response::new(setup_mandate_response))
                })
            },
        )
        .await
    }

    #[tracing::instrument(
        name = "repeat_payment",
        fields(
            name = common_utils::consts::NAME,
            service_name = common_utils::consts::PAYMENT_SERVICE_NAME,
            service_method = FlowName::RepeatPayment.as_str(),
            request_body = tracing::field::Empty,
            response_body = tracing::field::Empty,
            error_message = tracing::field::Empty,
            merchant_id = tracing::field::Empty,
            gateway = tracing::field::Empty,
            request_id = tracing::field::Empty,
            status_code = tracing::field::Empty,
            message_ = "Golden Log Line (incoming)",
            response_time = tracing::field::Empty,
            tenant_id = tracing::field::Empty,
        ),
        skip(self, request)
    )]
    async fn repeat_everything(
        &self,
        request: tonic::Request<PaymentServiceRepeatEverythingRequest>,
    ) -> Result<tonic::Response<PaymentServiceRepeatEverythingResponse>, tonic::Status> {
        info!("REPEAT_PAYMENT_FLOW: initiated");
        let service_name = request
            .extensions()
            .get::<String>()
            .cloned()
            .unwrap_or_else(|| "unknown_service".to_string());
        grpc_logging_wrapper(
            request,
            &service_name,
            self.config.clone(),
            |request, metadata_payload| {
                let service_name = service_name.clone();
                Box::pin(async move {
                    let (connector, request_id) =
                        (metadata_payload.connector, metadata_payload.request_id);
                    let connector_auth_details = metadata_payload.connector_auth_type;
                    let metadata = request.metadata().clone();
                    let payload = request.into_inner();

                    //get connector data
                    let connector_data: ConnectorData<DefaultPCIHolder> =
                        ConnectorData::get_connector_by_name(&connector);

                    // Get connector integration
                    let connector_integration: BoxedConnectorIntegrationV2<
                        '_,
                        RepeatPayment,
                        PaymentFlowData,
                        RepeatPaymentData,
                        PaymentsResponseData,
                    > = connector_data.connector.get_connector_integration_v2();

                    // Create payment flow data
                    let payment_flow_data = PaymentFlowData::foreign_try_from((
                        payload.clone(),
                        self.config.connectors.clone(),
                        &metadata,
                    ))
                    .map_err(|e| e.into_grpc_status())?;

                    // Create repeat payment data
                    let repeat_payment_data = RepeatPaymentData::foreign_try_from(payload.clone())
                        .map_err(|e| e.into_grpc_status())?;

                    // Create router data
                    let router_data: RouterDataV2<
                        RepeatPayment,
                        PaymentFlowData,
                        RepeatPaymentData,
                        PaymentsResponseData,
                    > = RouterDataV2 {
                        flow: std::marker::PhantomData,
                        resource_common_data: payment_flow_data,
                        connector_auth_type: connector_auth_details,
                        request: repeat_payment_data,
                        response: Err(ErrorResponse::default()),
                    };
                    let event_params = EventProcessingParams {
                        connector_name: &connector.to_string(),
                        service_name: &service_name,
                        flow_name: FlowName::RepeatPayment,
                        event_config: &self.config.events,
                        raw_request_data: Some(SecretSerdeValue::new(
                            payload.masked_serialize().unwrap_or_default(),
                        )),
                        request_id: &request_id,
                        lineage_ids: &metadata_payload.lineage_ids,
                        reference_id: &metadata_payload.reference_id,
                    };

                    let response = external_services::service::execute_connector_processing_step(
                        &self.config.proxy,
                        connector_integration,
                        router_data,
                        None,
                        event_params,
                        None, // token_data - None for non-proxy payments
                    )
                    .await
                    .switch()
                    .map_err(|e| e.into_grpc_status())?;

                    // Generate response
                    let repeat_payment_response = generate_repeat_payment_response(response)
                        .map_err(|e| e.into_grpc_status())?;

                    Ok(tonic::Response::new(repeat_payment_response))
                })
            },
        )
        .await
    }
}

async fn get_payments_webhook_content(
    connector_data: ConnectorData<DefaultPCIHolder>,
    request_details: domain_types::connector_types::RequestDetails,
    webhook_secrets: Option<domain_types::connector_types::ConnectorWebhookSecrets>,
    connector_auth_details: Option<ConnectorAuthType>,
) -> CustomResult<grpc_api_types::payments::WebhookResponseContent, ApplicationErrorResponse> {
    let webhook_details = connector_data
        .connector
        .process_payment_webhook(request_details, webhook_secrets, connector_auth_details)
        .switch()?;

    // Generate response
    let response = PaymentServiceGetResponse::foreign_try_from(webhook_details).change_context(
        ApplicationErrorResponse::InternalServerError(ApiError {
            sub_code: "RESPONSE_CONSTRUCTION_ERROR".to_string(),
            error_identifier: 500,
            error_message: "Error while constructing response".to_string(),
            error_object: None,
        }),
    )?;

    Ok(grpc_api_types::payments::WebhookResponseContent {
        content: Some(
            grpc_api_types::payments::webhook_response_content::Content::PaymentsResponse(response),
        ),
    })
}

async fn get_refunds_webhook_content<
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
    connector_data: ConnectorData<T>,
    request_details: domain_types::connector_types::RequestDetails,
    webhook_secrets: Option<domain_types::connector_types::ConnectorWebhookSecrets>,
    connector_auth_details: Option<ConnectorAuthType>,
) -> CustomResult<grpc_api_types::payments::WebhookResponseContent, ApplicationErrorResponse> {
    let webhook_details = connector_data
        .connector
        .process_refund_webhook(request_details, webhook_secrets, connector_auth_details)
        .switch()?;

    // Generate response - RefundService should handle this, for now return basic response
    let response = RefundResponse::foreign_try_from(webhook_details).change_context(
        ApplicationErrorResponse::InternalServerError(ApiError {
            sub_code: "RESPONSE_CONSTRUCTION_ERROR".to_string(),
            error_identifier: 500,
            error_message: "Error while constructing response".to_string(),
            error_object: None,
        }),
    )?;

    Ok(grpc_api_types::payments::WebhookResponseContent {
        content: Some(
            grpc_api_types::payments::webhook_response_content::Content::RefundsResponse(response),
        ),
    })
}

async fn get_disputes_webhook_content<
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
    connector_data: ConnectorData<T>,
    request_details: domain_types::connector_types::RequestDetails,
    webhook_secrets: Option<domain_types::connector_types::ConnectorWebhookSecrets>,
    connector_auth_details: Option<ConnectorAuthType>,
) -> CustomResult<grpc_api_types::payments::WebhookResponseContent, ApplicationErrorResponse> {
    let webhook_details = connector_data
        .connector
        .process_dispute_webhook(request_details, webhook_secrets, connector_auth_details)
        .switch()?;

    // Generate response - DisputeService should handle this, for now return basic response
    let response = DisputeResponse::foreign_try_from(webhook_details).change_context(
        ApplicationErrorResponse::InternalServerError(ApiError {
            sub_code: "RESPONSE_CONSTRUCTION_ERROR".to_string(),
            error_identifier: 500,
            error_message: "Error while constructing response".to_string(),
            error_object: None,
        }),
    )?;

    Ok(grpc_api_types::payments::WebhookResponseContent {
        content: Some(
            grpc_api_types::payments::webhook_response_content::Content::DisputesResponse(response),
        ),
    })
}
