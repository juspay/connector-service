use std::{fmt::Debug, sync::Arc};

use common_enums;
use common_utils::{consts, errors::CustomResult, events, pii};
use connector_integration::types::ConnectorData;
use domain_types::{
    connector_flow::{
<<<<<<< HEAD
        AccessToken, Authorize, Capture, CreateOrder, CreateSessionToken, FlowName, PSync, Refund,
        RepeatPayment, SetupMandate, Void,
=======
        self, Authorize, Capture, CreateOrder, CreateSessionToken, PSync, Refund, RepeatPayment,
        SetupMandate, Void,
>>>>>>> origin/main
    },
    connector_types::{
        AccessTokenResponseData, PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData, PaymentVoidData,
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
use external_services::service::{execute_connector_processing_step, EventProcessingParams};
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
use hyperswitch_masking::ErasedMaskSerialize;
use interfaces::connector_integration_v2::BoxedConnectorIntegrationV2;
use tracing::info;

use crate::{
    configs::Config,
    error::{IntoGrpcStatus, PaymentAuthorizationError, ReportSwitchExt, ResultExtGrpc},
    implement_connector_operation,
    utils::{auth_from_metadata, connector_from_metadata, grpc_logging_wrapper},
};

#[derive(Debug, Clone)]
struct EventParams<'a> {
    connector_name: &'a str,
    service_name: &'a str,
    request_id: &'a str,
}

// Error handling utilities for webhook processing
trait WebhookErrorExt<T> {
    #[allow(clippy::result_large_err)]
    fn to_grpc_status(self) -> Result<T, tonic::Status>;
}

impl<T, E> WebhookErrorExt<T> for Result<T, E>
where
    E: IntoGrpcStatus,
{
    fn to_grpc_status(self) -> Result<T, tonic::Status> {
        self.map_err(|e| e.into_grpc_status())
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
        service_name: &str,
        request_id: &str,
    ) -> Result<PaymentServiceAuthorizeResponse, PaymentAuthorizationError> {
        //get connector data
        let connector_data: ConnectorData<T> = ConnectorData::get_connector_by_name(&connector);
        let _connector_data_for_oauth = connector_data.clone();

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

        let should_do_order_create = connector_data.connector.should_do_order_create();

        let payment_flow_data = if should_do_order_create {
            let event_params = EventParams {
                connector_name: &connector.to_string(),
                service_name,
                request_id,
            };

            let order_id = self
                .handle_order_creation(
                    connector_data.clone(),
                    &payment_flow_data,
                    connector_auth_details.clone(),
                    event_params,
                    &payload,
                )
                .await?;

            tracing::info!("Order created successfully with order_id: {}", order_id);
            payment_flow_data.set_order_reference_id(Some(order_id))
        } else {
            payment_flow_data
        };

        let should_do_session_token = connector_data.connector.should_do_session_token();
        let should_do_access_token = connector_data.connector.should_do_access_token();

<<<<<<< HEAD
        let mut payment_flow_data = payment_flow_data;

        if should_do_session_token {
=======
        let payment_flow_data = if should_do_session_token {
            let event_params = EventParams {
                connector_name: &connector.to_string(),
                service_name,
                request_id,
            };

>>>>>>> origin/main
            let payment_session_data = self
                .handle_session_token(
                    connector_data.clone(),
                    &payment_flow_data,
                    connector_auth_details.clone(),
                    event_params,
                    &payload,
                )
                .await?;
            tracing::info!(
                "Session Token created successfully with session_id: {}",
                payment_session_data.session_token
            );
            payment_flow_data = payment_flow_data.set_session_token_id(Some(payment_session_data.session_token));
        }

        let grpc_access_token = if should_do_access_token {
            // Check if access token is already provided in the request
            match &payload.access_token {
                Some(existing_access_token) => {
                    // Use existing access token from request
                    tracing::info!("Using existing access token from request");
                    payment_flow_data.access_token = Some(existing_access_token.token.clone());
                    Some(existing_access_token.clone())
                }
                None => {
                    // Generate new access token only when none is provided
                    let access_token_data = self
                        .handle_access_token(
                            connector_data.clone(),
                            &payment_flow_data,
                            connector_auth_details.clone(),
                            &connector.to_string(),
                            service_name,
                        )
                        .await?;
                    tracing::info!("Access Token created successfully");
                    payment_flow_data.access_token = Some(access_token_data.access_token.clone());
                    Some(grpc_api_types::payments::AccessToken {
                        token: access_token_data.access_token,
                        expires_in_seconds: access_token_data.expires_in.unwrap_or(3600),
                        token_type: access_token_data.token_type,
                    })
                }
            }
        } else {
            None
        };

        // This duplicate session token check has been removed - the session token handling is already done above

        // Handle access token generation for OAuth connectors
        // Note: Access token management is now handled through the PaymentAccessToken trait

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
            flow_name: events::FlowName::Authorize,
            event_config: &self.config.events,
            raw_request_data: Some(pii::SecretSerdeValue::new(
                payload.masked_serialize().unwrap_or_default(),
            )),
            request_id,
        };

        let response = execute_connector_processing_step(
            &self.config.proxy,
            connector_integration,
            router_data,
            None,
            event_params,
        )
        .await;

        // Access token is handled above

        // Generate response - pass both success and error cases
        let authorize_response = match response {
            Ok(success_response) => domain_types::types::generate_payment_authorize_response(
                success_response,
                grpc_access_token.clone(),
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
<<<<<<< HEAD
                domain_types::types::generate_payment_authorize_response::<T>(
                    error_router_data,
                    grpc_access_token,
                )
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
                        None,
                    )
                })?
=======
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
>>>>>>> origin/main
            }
        };

        Ok(authorize_response)
    }

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
        event_params: EventParams<'_>,
        payload: &PaymentServiceAuthorizeRequest,
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

        // Execute connector processing
        let external_event_params = EventProcessingParams {
            connector_name: event_params.connector_name,
            service_name: event_params.service_name,
            flow_name: events::FlowName::CreateOrder,
            event_config: &self.config.events,
            raw_request_data: Some(pii::SecretSerdeValue::new(
                payload.masked_serialize().unwrap_or_default(),
            )),
            request_id: event_params.request_id,
        };

        let response = execute_connector_processing_step(
            &self.config.proxy,
            connector_integration,
            order_router_data,
            None,
            external_event_params,
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
    async fn process_payment_sync_internal(
        &self,
        payload: PaymentServiceGetRequest,
        connector: domain_types::connector_types::ConnectorEnum,
        connector_auth_details: ConnectorAuthType,
        service_name: &str,
    ) -> Result<PaymentServiceGetResponse, tonic::Status> {
        //get connector data
        let connector_data: ConnectorData<DefaultPCIHolder> =
            ConnectorData::get_connector_by_name(&connector);
        let _connector_data_for_oauth = connector_data.clone();

        // Get connector integration
        let connector_integration: BoxedConnectorIntegrationV2<
            '_,
            PSync,
            PaymentFlowData,
            PaymentsSyncData,
            PaymentsResponseData,
        > = connector_data.connector.get_connector_integration_v2();

        // Create common request data
        let payment_flow_data =
            PaymentFlowData::foreign_try_from((payload.clone(), self.config.connectors.clone()))
                .map_err(|e| {
                    tracing::error!("Failed to process payment flow data: {:?}", e);
                    e.into_grpc_status()
                })?;

        // Handle access token generation for OAuth connectors
        // Note: Access token management is now handled through the PaymentAccessToken trait

        // Create connector request data
        let payment_sync_data =
            PaymentsSyncData::foreign_try_from(payload.clone())
                .map_err(|e| {
                    tracing::error!("Failed to process payment sync data: {:?}", e);
                    e.into_grpc_status()
                })?;

        // Construct router data
        let router_data =
            RouterDataV2::<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData> {
                flow: std::marker::PhantomData,
                resource_common_data: payment_flow_data.clone(),
                connector_auth_type: connector_auth_details.clone(),
                request: payment_sync_data,
                response: Err(ErrorResponse::default()),
            };

        // Execute connector processing
        let response = external_services::service::execute_connector_processing_step(
            &self.config.proxy,
            connector_integration,
            router_data,
            None,
            &connector.to_string(),
            service_name,
        )
        .await
        .switch()
        .map_err(|e| {
            tracing::error!("Failed to execute connector processing: {:?}", e);
            e.into_grpc_status()
        })?;

        // Generate response - pass both success and error cases
        let sync_response = match response.response {
            Ok(success_response_data) => {
                // Update the payment flow data with the correct status from connector response
                let mut updated_payment_flow_data = payment_flow_data;
                updated_payment_flow_data.status = response.resource_common_data.status;

                // Create successful router data
                let success_router_data = RouterDataV2 {
                    flow: std::marker::PhantomData,
                    resource_common_data: updated_payment_flow_data,
                    connector_auth_type: connector_auth_details,
                    request: PaymentsSyncData::foreign_try_from(payload.clone())
                        .map_err(|e| e.into_grpc_status())?,
                    response: Ok(success_response_data),
                };
                generate_payment_sync_response(success_router_data)
                    .map_err(|e| {
                        tracing::error!("Failed to generate sync response: {:?}", e);
                        e.into_grpc_status()
                    })?
            }
            Err(error_response) => {
                // Update the payment flow data with the correct status from connector response
                let mut updated_payment_flow_data = payment_flow_data;
                updated_payment_flow_data.status = response.resource_common_data.status;

                // Create error router data
                let error_router_data = RouterDataV2 {
                    flow: std::marker::PhantomData,
                    resource_common_data: updated_payment_flow_data,
                    connector_auth_type: connector_auth_details,
                    request: PaymentsSyncData::foreign_try_from(payload.clone())
                        .map_err(|e| e.into_grpc_status())?,
                    response: Err(error_response),
                };
                generate_payment_sync_response(error_router_data)
                    .map_err(|e| {
                        tracing::error!("Failed to generate sync response for connector error: {:?}", e);
                        e.into_grpc_status()
                    })?
            }
        };

        Ok(sync_response)
    }

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
        let external_event_params = EventProcessingParams {
            connector_name: event_params.connector_name,
            service_name: event_params.service_name,
            flow_name: events::FlowName::CreateOrder,
            event_config: &self.config.events,
            raw_request_data: Some(pii::SecretSerdeValue::new(
                payload.masked_serialize().unwrap_or_default(),
            )),
            request_id: event_params.request_id,
        };

        let response = execute_connector_processing_step(
            &self.config.proxy,
            connector_integration,
            order_router_data,
            None,
            external_event_params,
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
        P,
    >(
        &self,
        connector_data: ConnectorData<T>,
        payment_flow_data: &PaymentFlowData,
        connector_auth_details: ConnectorAuthType,
        event_params: EventParams<'_>,
        payload: &P,
    ) -> Result<SessionTokenResponseData, PaymentAuthorizationError>
    where
        P: Clone + ErasedMaskSerialize,
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

        // Execute connector processing
        let external_event_params = EventProcessingParams {
            connector_name: event_params.connector_name,
            service_name: event_params.service_name,
            flow_name: events::FlowName::CreateSessionToken,
            event_config: &self.config.events,
            raw_request_data: Some(pii::SecretSerdeValue::new(
                payload.masked_serialize().unwrap_or_default(),
            )),
            request_id: event_params.request_id,
        };

        let response = execute_connector_processing_step(
            &self.config.proxy,
            connector_integration,
            session_token_router_data,
            None,
            external_event_params,
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

    async fn handle_access_token<
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
        connector_data: ConnectorData<T>,
        payment_flow_data: &PaymentFlowData,
        connector_auth_details: ConnectorAuthType,
        connector_name: &str,
        service_name: &str,
    ) -> Result<AccessTokenResponseData, PaymentAuthorizationError> {
        // Get connector integration
        let connector_integration: BoxedConnectorIntegrationV2<
            '_,
            AccessToken,
            PaymentFlowData,
            (),
            AccessTokenResponseData,
        > = connector_data.connector.get_connector_integration_v2();

        let access_token_router_data = RouterDataV2::<
            AccessToken,
            PaymentFlowData,
            (),
            AccessTokenResponseData,
        > {
            flow: std::marker::PhantomData,
            resource_common_data: payment_flow_data.clone(),
            connector_auth_type: connector_auth_details,
            request: (),
            response: Err(ErrorResponse::default()),
        };

        // Execute connector processing
        let response = external_services::service::execute_connector_processing_step(
            &self.config.proxy,
            connector_integration,
            access_token_router_data,
            None,
            connector_name,
            service_name,
        )
        .await
        .switch()
        .map_err(|e: error_stack::Report<ApplicationErrorResponse>| {
            PaymentAuthorizationError::new(
                grpc_api_types::payments::PaymentStatus::Pending,
                Some(format!("Access Token creation failed: {e}")),
                Some("ACCESS_TOKEN_CREATION_ERROR".to_string()),
                None,
                Some(500), // Internal Server Error - connector processing failed
            )
        })?;

        match response.response {
            Ok(access_token_data) => {
                tracing::info!("Access token created successfully");
                Ok(access_token_data)
            }
            Err(ErrorResponse {
                message,
                status_code,
                ..
            }) => Err(PaymentAuthorizationError::new(
                grpc_api_types::payments::PaymentStatus::Pending,
                Some(format!("Access Token creation failed: {message}")),
                Some("ACCESS_TOKEN_CREATION_ERROR".to_string()),
                None,
                Some(status_code.into()), // Use actual status code from ErrorResponse
            )),
        }
    }
}

impl PaymentOperationsInternal for Payments {
    async fn internal_payment_sync(
        &self,
        request: tonic::Request<PaymentServiceGetRequest>,
    ) -> Result<tonic::Response<PaymentServiceGetResponse>, tonic::Status> {
        tracing::info!("PAYMENT_SYNC_FLOW: initiated");
        let service_name = request
            .extensions()
            .get::<String>()
            .cloned()
            .unwrap_or_else(|| "unknown_service".to_string());
        grpc_logging_wrapper(request, &service_name, |request| {
            Box::pin(async {
                let connector = connector_from_metadata(request.metadata())
                    .map_err(|e| e.into_grpc_status())?;
                let connector_auth_details =
                    auth_from_metadata(request.metadata()).map_err(|e| e.into_grpc_status())?;
                let payload = request.into_inner();

                let sync_response = self
                    .process_payment_sync_internal(
                        payload,
                        connector,
                        connector_auth_details,
                        &service_name,
                    )
                    .await?;

                Ok(tonic::Response::new(sync_response))
            })
        })
        .await
    }

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
            name = consts::NAME,
            service_name = tracing::field::Empty,
            service_method = connector_flow::FlowName::Authorize.to_string(),
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
            flow = connector_flow::FlowName::Authorize.to_string(),
            flow_specific_fields.status = tracing::field::Empty,
        )
        skip(self, request)
    )]
    async fn authorize(
        &self,
        request: tonic::Request<PaymentServiceAuthorizeRequest>,
    ) -> Result<tonic::Response<PaymentServiceAuthorizeResponse>, tonic::Status> {
        info!("PAYMENT_AUTHORIZE_FLOW: initiated");

        let service_name: String = request
            .extensions()
            .get::<String>()
            .cloned()
            .unwrap_or_else(|| "unknown_service".to_string());
        grpc_logging_wrapper(request, &service_name, |request| {
            Box::pin(async {
                let (connector, _merchant_id, _tenant_id, request_id) =
                    crate::utils::connector_merchant_id_tenant_id_request_id_from_metadata(
                        request.metadata(),
                    )
                    .map_err(|e| e.into_grpc_status())?;
                let connector_auth_details =
                    auth_from_metadata(request.metadata()).map_err(|e| e.into_grpc_status())?;
                let metadata = request.metadata().clone();
                let payload = request.into_inner();

                let authorize_response = match payload.payment_method.as_ref() {
                    Some(pm) => {
                        match pm.payment_method.as_ref() {
                            Some(payment_method::PaymentMethod::Card(card_details)) => {
                                match card_details.card_type {
                                    Some(grpc_api_types::payments::card_payment_method_type::CardType::CreditProxy(_)) | Some(grpc_api_types::payments::card_payment_method_type::CardType::DebitProxy(_)) => {
                                        match Box::pin(self.process_authorization_internal::<VaultTokenHolder>(
                                            payload,
                                            connector,
                                            connector_auth_details,
                                            &metadata,
                    &service_name,
                                            &request_id,
                                        ))
                                        .await
                                        {
                                            Ok(response) => response,
                                            Err(error_response) => PaymentServiceAuthorizeResponse::from(error_response),
                                        }
                                    }
                                    _ => {
                                        match Box::pin(self.process_authorization_internal::<DefaultPCIHolder>(
                                            payload,
                                            connector,
                                            connector_auth_details,
                                            &metadata,
                                            &service_name,
                                            &request_id,
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
                                    &service_name,
                                    &request_id,
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
                            &service_name,
                            &request_id,
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
            name = consts::NAME,
            service_name = consts::PAYMENT_SERVICE_NAME,
            service_method = connector_flow::FlowName::Psync.to_string(),
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
            flow = connector_flow::FlowName::Psync.to_string(),
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
            name = consts::NAME,
            service_name = consts::PAYMENT_SERVICE_NAME,
            service_method = connector_flow::FlowName::Void.to_string(),
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
            flow = connector_flow::FlowName::Void.to_string(),
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
            name = consts::NAME,
            service_name = consts::PAYMENT_SERVICE_NAME,
            service_method = connector_flow::FlowName::IncomingWebhook.to_string(),
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
            flow = connector_flow::FlowName::IncomingWebhook.to_string(),
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
        grpc_logging_wrapper(request, &service_name, |request| async {
            let connector =
                connector_from_metadata(request.metadata()).map_err(|e| e.into_grpc_status())?;
            let connector_auth_details =
                auth_from_metadata(request.metadata()).map_err(|e| e.into_grpc_status())?;
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

            let source_verified = connector_data
                .connector
                .verify_webhook_source(
                    request_details.clone(),
                    webhook_secrets.clone(),
                    // TODO: do we need to force authentication? we can make it optional
                    Some(connector_auth_details.clone()),
                )
                .switch()
                .to_grpc_status()?;

            let event_type = connector_data
                .connector
                .get_event_type(
                    request_details.clone(),
                    webhook_secrets.clone(),
                    Some(connector_auth_details.clone()),
                )
                .switch()
                .to_grpc_status()?;

            // Get content for the webhook based on the event type using categorization
            let content = if event_type.is_payment_event() {
                get_payments_webhook_content(
                    connector_data,
                    &request_details,
                    webhook_secrets.as_ref(),
                    Some(&connector_auth_details),
                )
                .await
                .to_grpc_status()?
            } else if event_type.is_refund_event() {
                get_refunds_webhook_content(
                    connector_data,
                    &request_details,
                    webhook_secrets.as_ref(),
                    Some(&connector_auth_details),
                )
                .await
                .to_grpc_status()?
            } else if event_type.is_dispute_event() {
                get_disputes_webhook_content(
                    connector_data,
                    &request_details,
                    webhook_secrets.as_ref(),
                    Some(&connector_auth_details),
                )
                .await
                .to_grpc_status()?
            } else {
                // For all other event types, default to payment webhook content for now
                // This includes mandate, payout, recovery, and misc events
                get_payments_webhook_content(
                    connector_data,
                    &request_details,
                    webhook_secrets.as_ref(),
                    Some(&connector_auth_details),
                )
                .await
                .to_grpc_status()?
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
        })
        .await
    }

    #[tracing::instrument(
        name = "refund",
        fields(
            name = consts::NAME,
            service_name = consts::PAYMENT_SERVICE_NAME,
            service_method = connector_flow::FlowName::Refund.to_string(),
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
            flow = connector_flow::FlowName::Refund.to_string(),
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
            name = consts::NAME,
            service_name = consts::PAYMENT_SERVICE_NAME,
            service_method = connector_flow::FlowName::DefendDispute.to_string(),
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
            flow = connector_flow::FlowName::DefendDispute.to_string(),
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
        grpc_logging_wrapper(request, &service_name, |_request| async {
            let response = DisputeResponse {
                ..Default::default()
            };
            Ok(tonic::Response::new(response))
        })
        .await
    }

    #[tracing::instrument(
        name = "payment_capture",
        fields(
            name = consts::NAME,
            service_name = consts::PAYMENT_SERVICE_NAME,
            service_method = connector_flow::FlowName::Capture.to_string(),
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
            flow = connector_flow::FlowName::Capture.to_string(),
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
            name = consts::NAME,
            service_name = consts::PAYMENT_SERVICE_NAME,
            service_method = connector_flow::FlowName::SetupMandate.to_string(),
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
            flow = connector_flow::FlowName::SetupMandate.to_string(),
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
        grpc_logging_wrapper(request, &service_name, |request| {
            Box::pin(async {
                let (connector, _merchant_id, _tenant_id, request_id) =
                    crate::utils::connector_merchant_id_tenant_id_request_id_from_metadata(
                        request.metadata(),
                    )
                    .map_err(|e| e.into_grpc_status())?;
                let connector_auth_details =
                    auth_from_metadata(request.metadata()).map_err(|e| e.into_grpc_status())?;
                let metadata = request.metadata().clone();
                let payload = request.into_inner();

                //get connector data
                let connector_data: ConnectorData<DefaultPCIHolder> =
                    ConnectorData::get_connector_by_name(&connector);

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
                        connector_name: &connector.to_string(),
                        service_name: &service_name,
                        request_id: &request_id,
                    };

                    Some(
                        self.handle_order_creation_for_setup_mandate(
                            connector_data.clone(),
                            &payment_flow_data,
                            connector_auth_details.clone(),
                            event_params,
                            &payload,
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

                let event_params = EventProcessingParams {
                    connector_name: &connector.to_string(),
                    service_name: &service_name,
                    flow_name: events::FlowName::SetupMandate,
                    event_config: &self.config.events,
                    raw_request_data: Some(pii::SecretSerdeValue::new(
                        payload.masked_serialize().unwrap_or_default(),
                    )),
                    request_id: &request_id,
                };

                let response = execute_connector_processing_step(
                    &self.config.proxy,
                    connector_integration,
                    router_data,
                    None,
                    event_params,
                )
                .await
                .switch()
                .map_err(|e| e.into_grpc_status())?;

                // Generate response
                let setup_mandate_response =
                    generate_setup_mandate_response(response).map_err(|e| e.into_grpc_status())?;

                Ok(tonic::Response::new(setup_mandate_response))
            })
        })
        .await
    }

    #[tracing::instrument(
        name = "repeat_payment",
        fields(
            name = consts::NAME,
            service_name = consts::PAYMENT_SERVICE_NAME,
            service_method = connector_flow::FlowName::RepeatPayment.to_string(),
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
        grpc_logging_wrapper(request, &service_name, |request| {
            Box::pin(async {
                let (connector, _merchant_id, _tenant_id, request_id) =
                    crate::utils::connector_merchant_id_tenant_id_request_id_from_metadata(
                        request.metadata(),
                    )
                    .map_err(|e| e.into_grpc_status())?;
                let connector_auth_details =
                    auth_from_metadata(request.metadata()).map_err(|e| e.into_grpc_status())?;
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
                    flow_name: events::FlowName::RepeatPayment,
                    event_config: &self.config.events,
                    raw_request_data: Some(pii::SecretSerdeValue::new(
                        payload.masked_serialize().unwrap_or_default(),
                    )),
                    request_id: &request_id,
                };

                let response = execute_connector_processing_step(
                    &self.config.proxy,
                    connector_integration,
                    router_data,
                    None,
                    event_params,
                )
                .await
                .switch()
                .map_err(|e| e.into_grpc_status())?;

                // Generate response
                let repeat_payment_response =
                    generate_repeat_payment_response(response).map_err(|e| e.into_grpc_status())?;

                Ok(tonic::Response::new(repeat_payment_response))
            })
        })
        .await
    }
}

<<<<<<< HEAD
async fn get_payments_webhook_content<
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
=======
async fn get_payments_webhook_content(
    connector_data: ConnectorData<DefaultPCIHolder>,
    request_details: &domain_types::connector_types::RequestDetails,
    webhook_secrets: Option<&domain_types::connector_types::ConnectorWebhookSecrets>,
    connector_auth_details: Option<&ConnectorAuthType>,
>>>>>>> origin/main
) -> CustomResult<grpc_api_types::payments::WebhookResponseContent, ApplicationErrorResponse> {
    let webhook_details = connector_data
        .connector
        .process_payment_webhook(
            request_details.clone(),
            webhook_secrets.cloned(),
            connector_auth_details.cloned(),
        )
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
    request_details: &domain_types::connector_types::RequestDetails,
    webhook_secrets: Option<&domain_types::connector_types::ConnectorWebhookSecrets>,
    connector_auth_details: Option<&ConnectorAuthType>,
) -> CustomResult<grpc_api_types::payments::WebhookResponseContent, ApplicationErrorResponse> {
    let webhook_details = connector_data
        .connector
        .process_refund_webhook(
            request_details.clone(),
            webhook_secrets.cloned(),
            connector_auth_details.cloned(),
        )
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
    request_details: &domain_types::connector_types::RequestDetails,
    webhook_secrets: Option<&domain_types::connector_types::ConnectorWebhookSecrets>,
    connector_auth_details: Option<&ConnectorAuthType>,
) -> CustomResult<grpc_api_types::payments::WebhookResponseContent, ApplicationErrorResponse> {
    let webhook_details = connector_data
        .connector
        .process_dispute_webhook(
            request_details.clone(),
            webhook_secrets.cloned(),
            connector_auth_details.cloned(),
        )
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
