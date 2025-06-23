use crate::implement_connector_operation;
use crate::{
    configs::Config,
    error::{IntoGrpcStatus, ReportSwitchExt, ResultExtGrpc},
    utils::{auth_from_metadata, connector_from_metadata},
};
use connector_integration::types::ConnectorData;
use domain_types::{
    connector_flow::{
        Authorize, Capture, CreateOrder, FlowName, PSync, Refund, SetupMandate, Void,
    },
    connector_types::{
        PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData, PaymentVoidData,
        PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData, PaymentsSyncData,
        RefundFlowData, RefundsData, RefundsResponseData, SetupMandateRequestData,
    },
    errors::{ApiError, ApplicationErrorResponse},
};
use domain_types::{
    types::{
        generate_payment_capture_response, generate_payment_sync_response,
        generate_payment_void_response, generate_refund_response, generate_setup_mandate_response,
    },
    utils::ForeignTryFrom,
};
use error_stack::ResultExt;
use external_services::shared_metrics as metrics;
use grpc_api_types::payments::{
    payment_service_server::PaymentService, DisputeResponse, PaymentServiceAuthorizeRequest,
    PaymentServiceAuthorizeResponse, PaymentServiceCaptureRequest, PaymentServiceCaptureResponse,
    PaymentServiceDisputeRequest, PaymentServiceGetRequest, PaymentServiceGetResponse,
    PaymentServiceRefundRequest, PaymentServiceRegisterRequest, PaymentServiceRegisterResponse,
    PaymentServiceTransformRequest, PaymentServiceTransformResponse, PaymentServiceVoidRequest,
    PaymentServiceVoidResponse, RefundResponse,
};
use hyperswitch_common_utils::errors::CustomResult;
use hyperswitch_domain_models::{
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
};
use hyperswitch_interfaces::connector_integration_v2::BoxedConnectorIntegrationV2;
use tracing::info;

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

pub struct Payments {
    pub config: Config,
}

impl Payments {
    async fn handle_order_creation(
        &self,
        connector_data: ConnectorData,
        payment_flow_data: &mut PaymentFlowData,
        connector_auth_details: ConnectorAuthType,
        payload: &PaymentServiceAuthorizeRequest,
        connector_name: &str,
    ) -> Result<(), tonic::Status> {
        // Get connector integration
        let connector_integration: BoxedConnectorIntegrationV2<
            '_,
            CreateOrder,
            PaymentFlowData,
            PaymentCreateOrderData,
            PaymentCreateOrderResponse,
        > = connector_data.connector.get_connector_integration_v2();

        let currency = hyperswitch_common_enums::Currency::foreign_try_from(payload.currency())
            .map_err(|e| e.into_grpc_status())?;

        let order_create_data = PaymentCreateOrderData {
            amount: hyperswitch_common_utils::types::MinorUnit::new(payload.minor_amount),
            currency,
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
        let response = external_services::service::execute_connector_processing_step(
            &self.config.proxy,
            connector_integration,
            order_router_data,
            None,
            connector_name,
        )
        .await
        .switch()
        .map_err(|e| e.into_grpc_status())?;

        match response.response {
            Ok(PaymentCreateOrderResponse { order_id, .. }) => {
                payment_flow_data.reference_id = Some(order_id);
                Ok(())
            }
            Err(ErrorResponse { message, .. }) => Err(tonic::Status::internal(format!(
                "Order creation error: {}",
                message
            ))),
        }
    }
    async fn handle_order_creation_for_setup_mandate(
        &self,
        connector_data: ConnectorData,
        payment_flow_data: &mut PaymentFlowData,
        connector_auth_details: ConnectorAuthType,
        payload: &PaymentServiceRegisterRequest,
        connector_name: &str,
    ) -> Result<(), tonic::Status> {
        // Get connector integration
        let connector_integration: BoxedConnectorIntegrationV2<
            '_,
            CreateOrder,
            PaymentFlowData,
            PaymentCreateOrderData,
            PaymentCreateOrderResponse,
        > = connector_data.connector.get_connector_integration_v2();

        let currency = hyperswitch_common_enums::Currency::foreign_try_from(payload.currency())
            .map_err(|e| e.into_grpc_status())?;

        let order_create_data = PaymentCreateOrderData {
            amount: hyperswitch_common_utils::types::MinorUnit::new(0),
            currency,
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
        let response = external_services::service::execute_connector_processing_step(
            &self.config.proxy,
            connector_integration,
            order_router_data,
            None,
            connector_name,
        )
        .await
        .switch()
        .map_err(|e| e.into_grpc_status())?;

        match response.response {
            Ok(PaymentCreateOrderResponse { order_id, .. }) => {
                payment_flow_data.reference_id = Some(order_id);
                Ok(())
            }
            Err(ErrorResponse { message, .. }) => Err(tonic::Status::internal(format!(
                "Order creation error: {}",
                message
            ))),
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
    async fn authorize(
        &self,
        request: tonic::Request<PaymentServiceAuthorizeRequest>,
    ) -> Result<tonic::Response<PaymentServiceAuthorizeResponse>, tonic::Status> {
        info!("PAYMENT_AUTHORIZE_FLOW: initiated");
        let connector =
            connector_from_metadata(request.metadata()).map_err(|e| e.into_grpc_status())?;
        metrics::with_metrics_and_connector(
            &FlowName::Authorize.to_string(),
            &connector.to_string(),
            || {
                Box::pin(async {
                    let connector_auth_details =
                        auth_from_metadata(request.metadata()).map_err(|e| e.into_grpc_status())?;
                    let payload = request.into_inner();

                    //get connector data
                    let connector_data = ConnectorData::get_connector_by_name(&connector);

                    // Get connector integration
                    let connector_integration: BoxedConnectorIntegrationV2<
                        '_,
                        Authorize,
                        PaymentFlowData,
                        PaymentsAuthorizeData,
                        PaymentsResponseData,
                    > = connector_data.connector.get_connector_integration_v2();

                    // Create common request data
                    let mut payment_flow_data = PaymentFlowData::foreign_try_from((
                        payload.clone(),
                        self.config.connectors.clone(),
                    ))
                    .map_err(|e| e.into_grpc_status())?;

                    let should_do_order_create = connector_data.connector.should_do_order_create();

                    if should_do_order_create {
                        self.handle_order_creation(
                            connector_data.clone(),
                            &mut payment_flow_data,
                            connector_auth_details.clone(),
                            &payload,
                            &connector.to_string(),
                        )
                        .await?;
                    }

                    // Create connector request data
                    let payment_authorize_data =
                        PaymentsAuthorizeData::foreign_try_from(payload.clone())
                            .map_err(|e| e.into_grpc_status())?;
                    // Construct router data
                    let router_data = RouterDataV2::<
                        Authorize,
                        PaymentFlowData,
                        PaymentsAuthorizeData,
                        PaymentsResponseData,
                    > {
                        flow: std::marker::PhantomData,
                        resource_common_data: payment_flow_data,
                        connector_auth_type: connector_auth_details,
                        request: payment_authorize_data,
                        response: Err(ErrorResponse::default()),
                    };

                    // Execute connector processing
                    let response = external_services::service::execute_connector_processing_step(
                        &self.config.proxy,
                        connector_integration,
                        router_data,
                        None,
                        &connector.to_string(),
                    )
                    .await
                    .switch()
                    .map_err(|e| e.into_grpc_status())?;

                    // Generate response
                    let authorize_response =
                        domain_types::types::generate_payment_authorize_response(response)
                            .map_err(|e| e.into_grpc_status())?;

                    Ok(tonic::Response::new(authorize_response))
                })
            },
        )
        .await
    }

    async fn get(
        &self,
        request: tonic::Request<PaymentServiceGetRequest>,
    ) -> Result<tonic::Response<PaymentServiceGetResponse>, tonic::Status> {
        self.internal_payment_sync(request).await
    }

    async fn void(
        &self,
        request: tonic::Request<PaymentServiceVoidRequest>,
    ) -> Result<tonic::Response<PaymentServiceVoidResponse>, tonic::Status> {
        self.internal_void_payment(request).await
    }

    async fn transform(
        &self,
        request: tonic::Request<PaymentServiceTransformRequest>,
    ) -> Result<tonic::Response<PaymentServiceTransformResponse>, tonic::Status> {
        let connector =
            connector_from_metadata(request.metadata()).map_err(|e| e.into_grpc_status())?;
        metrics::with_metrics_and_connector(
            &FlowName::IncomingWebhook.to_string(),
            &connector.to_string(),
            || {
                Box::pin(async {
                    let connector_auth_details =
                        auth_from_metadata(request.metadata()).map_err(|e| e.into_grpc_status())?;
                    let payload = request.into_inner();

                    let request_details = payload
                        .request_details
                        .map(domain_types::connector_types::RequestDetails::foreign_try_from)
                        .ok_or_else(|| {
                            tonic::Status::invalid_argument(
                                "missing request_details in the payload",
                            )
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

                    let connector_data = ConnectorData::get_connector_by_name(&connector);

                    let source_verified = connector_data
                        .connector
                        .verify_webhook_source(
                            request_details.clone(),
                            webhook_secrets.clone(),
                            Some(connector_auth_details.clone()),
                        )
                        .switch()
                        .map_err(|e| e.into_grpc_status())?;

                    let event_type = connector_data
                        .connector
                        .get_event_type(
                            request_details.clone(),
                            webhook_secrets.clone(),
                            Some(connector_auth_details.clone()),
                        )
                        .switch()
                        .map_err(|e| e.into_grpc_status())?;

                    let content = match event_type {
                        domain_types::connector_types::EventType::Payment => {
                            get_payments_webhook_content(
                                connector_data,
                                request_details,
                                webhook_secrets,
                                Some(connector_auth_details),
                            )
                            .await
                            .map_err(|e| e.into_grpc_status())?
                        }
                        domain_types::connector_types::EventType::Refund => {
                            get_refunds_webhook_content(
                                connector_data,
                                request_details,
                                webhook_secrets,
                                Some(connector_auth_details),
                            )
                            .await
                            .map_err(|e| e.into_grpc_status())?
                        }
                        domain_types::connector_types::EventType::Dispute => {
                            get_disputes_webhook_content(
                                connector_data,
                                request_details,
                                webhook_secrets,
                                Some(connector_auth_details),
                            )
                            .await
                            .map_err(|e| e.into_grpc_status())?
                        }
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
            },
        )
        .await
    }

    async fn refund(
        &self,
        request: tonic::Request<PaymentServiceRefundRequest>,
    ) -> Result<tonic::Response<RefundResponse>, tonic::Status> {
        self.internal_refund(request).await
    }

    async fn dispute(
        &self,
        _request: tonic::Request<PaymentServiceDisputeRequest>,
    ) -> Result<tonic::Response<DisputeResponse>, tonic::Status> {
        // For now, just return a basic dispute response
        // This will need proper implementation based on domain logic
        let response = DisputeResponse {
            ..Default::default()
        };
        Ok(tonic::Response::new(response))
    }

    async fn capture(
        &self,
        request: tonic::Request<PaymentServiceCaptureRequest>,
    ) -> Result<tonic::Response<PaymentServiceCaptureResponse>, tonic::Status> {
        self.internal_payment_capture(request).await
    }

    async fn register(
        &self,
        request: tonic::Request<PaymentServiceRegisterRequest>,
    ) -> Result<tonic::Response<PaymentServiceRegisterResponse>, tonic::Status> {
        info!("SETUP_MANDATE_FLOW: initiated");
        let connector =
            connector_from_metadata(request.metadata()).map_err(|e| e.into_grpc_status())?;
        metrics::with_metrics_and_connector(
            &FlowName::SetupMandate.to_string(),
            &connector.to_string(),
            || {
                Box::pin(async {
                    let connector_auth_details =
                        auth_from_metadata(request.metadata()).map_err(|e| e.into_grpc_status())?;
                    let payload = request.into_inner();

                    let connector_data = ConnectorData::get_connector_by_name(&connector);

                    let connector_integration: BoxedConnectorIntegrationV2<
                        '_,
                        SetupMandate,
                        PaymentFlowData,
                        SetupMandateRequestData,
                        PaymentsResponseData,
                    > = connector_data.connector.get_connector_integration_v2();

                    let mut payment_flow_data = PaymentFlowData::foreign_try_from((
                        payload.clone(),
                        self.config.connectors.clone(),
                    ))
                    .map_err(|e| e.into_grpc_status())?;

                    let should_do_order_create = connector_data.connector.should_do_order_create();

                    if should_do_order_create {
                        self.handle_order_creation_for_setup_mandate(
                            connector_data.clone(),
                            &mut payment_flow_data,
                            connector_auth_details.clone(),
                            &payload,
                            &connector.to_string(),
                        )
                        .await?;
                    }

                    let setup_mandate_request_data =
                        SetupMandateRequestData::foreign_try_from(payload.clone())
                            .map_err(|e| e.into_grpc_status())?;

                    let router_data: RouterDataV2<
                        SetupMandate,
                        PaymentFlowData,
                        SetupMandateRequestData,
                        PaymentsResponseData,
                    > = RouterDataV2 {
                        flow: std::marker::PhantomData,
                        resource_common_data: payment_flow_data,
                        connector_auth_type: connector_auth_details,
                        request: setup_mandate_request_data,
                        response: Err(ErrorResponse::default()),
                    };

                    let response = external_services::service::execute_connector_processing_step(
                        &self.config.proxy,
                        connector_integration,
                        router_data,
                        None,
                        &connector.to_string(),
                    )
                    .await
                    .switch()
                    .map_err(|e| e.into_grpc_status())?;

                    let setup_mandate_response = generate_setup_mandate_response(response)
                        .map_err(|e| e.into_grpc_status())?;

                    Ok(tonic::Response::new(setup_mandate_response))
                })
            },
        )
        .await
    }
}

async fn get_payments_webhook_content(
    connector_data: ConnectorData,
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

async fn get_refunds_webhook_content(
    connector_data: ConnectorData,
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

async fn get_disputes_webhook_content(
    connector_data: ConnectorData,
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
