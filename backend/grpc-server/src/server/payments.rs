use crate::{
    configs::Config,
    error::{IntoGrpcStatus, ReportSwitchExt},
    utils::{auth_from_metadata, connector_from_metadata},
};
use connector_integration::types::ConnectorData;
use domain_types::{
    connector_flow::{
        Accept, Authorize, Capture, CreateOrder, DefendDispute, PSync, RSync, Refund, SetupMandate,
        SubmitEvidence, Void,
    },
    connector_types::{
        AcceptDisputeData, DisputeDefendData, DisputeFlowData, DisputeResponseData,
        PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData, PaymentVoidData,
        PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData, PaymentsSyncData,
        RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData, SetupMandateRequestData,
        SubmitEvidenceData,
    },
    errors::{ApiError, ApplicationErrorResponse},
    types::{generate_accept_dispute_response, generate_submit_evidence_response},
};
use domain_types::{
    types::{
        generate_payment_capture_response, generate_payment_sync_response,
        generate_payment_void_response, generate_refund_response, generate_refund_sync_response,
        generate_setup_mandate_response,
    },
    utils::ForeignTryFrom,
};
use error_stack::ResultExt;
use external_services;
use grpc_api_types::payments::{
    payment_service_server::PaymentService, AcceptDisputeRequest, AcceptDisputeResponse,
    DisputeDefendRequest, DisputeDefendResponse, IncomingWebhookRequest, IncomingWebhookResponse,
    PaymentsAuthorizeRequest, PaymentsAuthorizeResponse, PaymentsCaptureRequest,
    PaymentsCaptureResponse, PaymentsSyncRequest, PaymentsSyncResponse, PaymentsVoidRequest,
    PaymentsVoidResponse, RefundsRequest, RefundsResponse, RefundsSyncRequest, RefundsSyncResponse,
    SetupMandateRequest, SetupMandateResponse, SubmitEvidenceRequest, SubmitEvidenceResponse,
};
use hyperswitch_common_utils::errors::CustomResult;
use hyperswitch_domain_models::{
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
};
use hyperswitch_interfaces::connector_integration_v2::BoxedConnectorIntegrationV2;
use tracing::info;

pub struct Payments {
    pub config: Config,
}

impl Payments {
    async fn handle_order_creation(
        &self,
        connector_data: ConnectorData,
        payment_flow_data: &mut PaymentFlowData,
        connector_auth_details: ConnectorAuthType,
        payload: &PaymentsAuthorizeRequest,
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
        payload: &SetupMandateRequest,
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

#[tonic::async_trait]
impl PaymentService for Payments {
    async fn payment_authorize(
        &self,
        request: tonic::Request<PaymentsAuthorizeRequest>,
    ) -> Result<tonic::Response<PaymentsAuthorizeResponse>, tonic::Status> {
        info!("PAYMENT_AUTHORIZE_FLOW: initiated");

        let connector =
            connector_from_metadata(request.metadata()).map_err(|e| e.into_grpc_status())?;
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
        let mut payment_flow_data =
            PaymentFlowData::foreign_try_from((payload.clone(), self.config.connectors.clone()))
                .map_err(|e| e.into_grpc_status())?;

        let should_do_order_create = connector_data.connector.should_do_order_create();

        if should_do_order_create {
            self.handle_order_creation(
                connector_data.clone(),
                &mut payment_flow_data,
                connector_auth_details.clone(),
                &payload,
            )
            .await?;
        }

        // Create connector request data
        let payment_authorize_data = PaymentsAuthorizeData::foreign_try_from(payload.clone())
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
        )
        .await
        .switch()
        .map_err(|e| e.into_grpc_status())?;

        // Generate response
        let authorize_response = domain_types::types::generate_payment_authorize_response(response)
            .map_err(|e| e.into_grpc_status())?;

        Ok(tonic::Response::new(authorize_response))
    }

    async fn payment_sync(
        &self,
        request: tonic::Request<PaymentsSyncRequest>,
    ) -> Result<tonic::Response<PaymentsSyncResponse>, tonic::Status> {
        info!("PAYMENT_SYNC_FLOW: initiated");

        let connector =
            connector_from_metadata(request.metadata()).map_err(|e| e.into_grpc_status())?;
        let connector_auth_details =
            auth_from_metadata(request.metadata()).map_err(|e| e.into_grpc_status())?;
        let payload = request.into_inner();

        // Get connector data
        let connector_data = ConnectorData::get_connector_by_name(&connector);

        // Get connector integration
        let connector_integration: BoxedConnectorIntegrationV2<
            '_,
            PSync,
            PaymentFlowData,
            PaymentsSyncData,
            PaymentsResponseData,
        > = connector_data.connector.get_connector_integration_v2();

        // Create connector request data
        let payment_sync_data = PaymentsSyncData::foreign_try_from(payload.clone())
            .map_err(|e| e.into_grpc_status())?;

        // Create common request data
        let payment_flow_data =
            PaymentFlowData::foreign_try_from((payload.clone(), self.config.connectors.clone()))
                .map_err(|e| e.into_grpc_status())?;

        // Create router data
        let router_data = RouterDataV2 {
            flow: std::marker::PhantomData,
            resource_common_data: payment_flow_data,
            connector_auth_type: connector_auth_details,
            request: payment_sync_data,
            response: Err(ErrorResponse::default()),
        };

        // Execute connector processing
        let response = external_services::service::execute_connector_processing_step(
            &self.config.proxy,
            connector_integration,
            router_data,
        )
        .await
        .switch()
        .map_err(|e| e.into_grpc_status())?;

        // Generate response
        let sync_response =
            generate_payment_sync_response(response).map_err(|e| e.into_grpc_status())?;

        Ok(tonic::Response::new(sync_response))
    }

    async fn refund_sync(
        &self,
        request: tonic::Request<RefundsSyncRequest>,
    ) -> Result<tonic::Response<RefundsSyncResponse>, tonic::Status> {
        info!("REFUND_SYNC_FLOW: initiated");

        let connector =
            connector_from_metadata(request.metadata()).map_err(|e| e.into_grpc_status())?;
        let connector_auth_details =
            auth_from_metadata(request.metadata()).map_err(|e| e.into_grpc_status())?;
        let payload = request.into_inner();

        // Get connector data
        let connector_data = ConnectorData::get_connector_by_name(&connector);

        // Get connector integration
        let connector_integration: BoxedConnectorIntegrationV2<
            '_,
            RSync,
            RefundFlowData,
            RefundSyncData,
            RefundsResponseData,
        > = connector_data.connector.get_connector_integration_v2();

        let refund_sync_data =
            RefundSyncData::foreign_try_from(payload.clone()).map_err(|e| e.into_grpc_status())?;

        // Create common request data
        let payment_flow_data =
            RefundFlowData::foreign_try_from((payload.clone(), self.config.connectors.clone()))
                .map_err(|e| e.into_grpc_status())?;

        // Create router data
        let router_data: RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData> =
            RouterDataV2 {
                flow: std::marker::PhantomData,
                resource_common_data: payment_flow_data,
                connector_auth_type: connector_auth_details,
                request: refund_sync_data,
                response: Err(ErrorResponse::default()),
            };

        let response = external_services::service::execute_connector_processing_step(
            &self.config.proxy,
            connector_integration,
            router_data,
        )
        .await
        .switch()
        .map_err(|e| e.into_grpc_status())?;

        // Generate response
        let sync_response =
            generate_refund_sync_response(response).map_err(|e| e.into_grpc_status())?;

        Ok(tonic::Response::new(sync_response))
    }

    async fn void_payment(
        &self,
        request: tonic::Request<PaymentsVoidRequest>,
    ) -> Result<tonic::Response<PaymentsVoidResponse>, tonic::Status> {
        info!("PAYMENT_CANCEL_FLOW: initiated");
        let connector =
            connector_from_metadata(request.metadata()).map_err(|e| e.into_grpc_status())?;
        let connector_auth_details =
            auth_from_metadata(request.metadata()).map_err(|e| e.into_grpc_status())?;
        let payload = request.into_inner();

        // Get connector data
        let connector_data = ConnectorData::get_connector_by_name(&connector);

        // Get connector integration
        let connector_integration: BoxedConnectorIntegrationV2<
            '_,
            Void,
            PaymentFlowData,
            PaymentVoidData,
            PaymentsResponseData,
        > = connector_data.connector.get_connector_integration_v2();

        let payment_flow_data =
            PaymentFlowData::foreign_try_from((payload.clone(), self.config.connectors.clone()))
                .map_err(|e| e.into_grpc_status())?;

        let payment_void_data =
            PaymentVoidData::foreign_try_from(payload.clone()).map_err(|e| e.into_grpc_status())?;

        let router_data =
            RouterDataV2::<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData> {
                flow: std::marker::PhantomData,
                resource_common_data: payment_flow_data,
                connector_auth_type: connector_auth_details,
                request: payment_void_data,
                response: Err(ErrorResponse::default()),
            };

        // Execute connector processing
        let response = external_services::service::execute_connector_processing_step(
            &self.config.proxy,
            connector_integration,
            router_data,
        )
        .await
        .switch()
        .map_err(|e| e.into_grpc_status())?;

        let void_response =
            generate_payment_void_response(response).map_err(|e| e.into_grpc_status())?;

        Ok(tonic::Response::new(void_response))
    }

    async fn incoming_webhook(
        &self,
        request: tonic::Request<IncomingWebhookRequest>,
    ) -> Result<tonic::Response<IncomingWebhookResponse>, tonic::Status> {
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
                domain_types::connector_types::ConnectorWebhookSecrets::foreign_try_from(details)
                    .map_err(|e| e.into_grpc_status())
            })
            .transpose()?;

        //get connector data
        let connector_data = ConnectorData::get_connector_by_name(&connector);

        let source_verified = connector_data
            .connector
            .verify_webhook_source(
                request_details.clone(),
                webhook_secrets.clone(),
                // TODO: do we need to force authentication? we can make it optional
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

        // Get content for the webhook based on the event type
        let content = match event_type {
            domain_types::connector_types::EventType::Payment => get_payments_webhook_content(
                connector_data,
                request_details,
                webhook_secrets,
                Some(connector_auth_details),
            )
            .await
            .map_err(|e| e.into_grpc_status())?,
            domain_types::connector_types::EventType::Refund => get_refunds_webhook_content(
                connector_data,
                request_details,
                webhook_secrets,
                Some(connector_auth_details),
            )
            .await
            .map_err(|e| e.into_grpc_status())?,
        };

        let api_event_type = grpc_api_types::payments::EventType::foreign_try_from(event_type)
            .map_err(|e| e.into_grpc_status())?;

        let response = IncomingWebhookResponse {
            event_type: api_event_type.into(),
            content: Some(content),
            source_verified,
        };

        Ok(tonic::Response::new(response))
    }

    async fn refund(
        &self,
        request: tonic::Request<RefundsRequest>,
    ) -> Result<tonic::Response<RefundsResponse>, tonic::Status> {
        info!("REFUND_FLOW: initiated");

        let connector =
            connector_from_metadata(request.metadata()).map_err(|e| e.into_grpc_status())?;
        let connector_auth_details =
            auth_from_metadata(request.metadata()).map_err(|e| e.into_grpc_status())?;
        let payload = request.into_inner();

        // Get connector data
        let connector_data = ConnectorData::get_connector_by_name(&connector);

        // Get connector integration
        let connector_integration: BoxedConnectorIntegrationV2<
            '_,
            Refund,
            RefundFlowData,
            RefundsData,
            RefundsResponseData,
        > = connector_data.connector.get_connector_integration_v2();

        let refund_data =
            RefundsData::foreign_try_from(payload.clone()).map_err(|e| e.into_grpc_status())?;

        // Create common request data
        let refund_flow_data =
            RefundFlowData::foreign_try_from((payload.clone(), self.config.connectors.clone()))
                .map_err(|e| e.into_grpc_status())?;

        // Create router data
        let router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData> =
            RouterDataV2 {
                flow: std::marker::PhantomData,
                resource_common_data: refund_flow_data,
                connector_auth_type: connector_auth_details,
                request: refund_data,
                response: Err(ErrorResponse::default()),
            };

        let response = external_services::service::execute_connector_processing_step(
            &self.config.proxy,
            connector_integration,
            router_data,
        )
        .await
        .switch()
        .map_err(|e| e.into_grpc_status())?;

        // Generate response
        let refund_response =
            generate_refund_response(response).map_err(|e| e.into_grpc_status())?;

        Ok(tonic::Response::new(refund_response))
    }

    async fn defend_dispute(
        &self,
        request: tonic::Request<DisputeDefendRequest>,
    ) -> Result<tonic::Response<DisputeDefendResponse>, tonic::Status> {
        info!("DISPUTE_DEFEND_FLOW: initiated");

        let connector =
            connector_from_metadata(request.metadata()).map_err(|e| e.into_grpc_status())?;

        // Extract auth credentials
        let connector_auth_details =
            auth_from_metadata(request.metadata()).map_err(|e| e.into_grpc_status())?;
        let payload = request.into_inner();

        //get connector data
        let connector_data = ConnectorData::get_connector_by_name(&connector);

        // Get connector integration
        let connector_integration: BoxedConnectorIntegrationV2<
            '_,
            DefendDispute,
            DisputeFlowData,
            DisputeDefendData,
            DisputeResponseData,
        > = connector_data.connector.get_connector_integration_v2();

        // Create common request data
        let defend_dispute_flow_data =
            DisputeFlowData::foreign_try_from((payload.clone(), self.config.connectors.clone()))
                .map_err(|e| {
                    tonic::Status::invalid_argument(format!("Invalid request data: {}", e))
                });

        // Create connector request data
        let defend_dispute_data = DisputeDefendData::foreign_try_from(payload.clone())
            .map_err(|e| tonic::Status::invalid_argument(format!("Invalid request data: {}", e)))?;

        // Construct router data
        let router_data = RouterDataV2::<
            DefendDispute,
            DisputeFlowData,
            DisputeDefendData,
            DisputeResponseData,
        > {
            flow: std::marker::PhantomData,
            resource_common_data: defend_dispute_flow_data?,
            connector_auth_type: connector_auth_details,
            request: defend_dispute_data,
            response: Err(ErrorResponse::default()),
        };

        // Execute connector processing
        let response = external_services::service::execute_connector_processing_step(
            &self.config.proxy,
            connector_integration,
            router_data,
        )
        .await
        .map_err(|e| tonic::Status::internal(format!("Connector processing error: {}", e)))?;

        // Generate response
        let defend_dispute_response =
            match domain_types::types::generate_defend_dispute_response(response) {
                Ok(resp) => resp,
                Err(e) => {
                    return Err(tonic::Status::internal(format!(
                        "Response generation error: {}",
                        e
                    )))
                }
            };

        Ok(tonic::Response::new(defend_dispute_response))
    }

    async fn payment_capture(
        &self,
        request: tonic::Request<PaymentsCaptureRequest>,
    ) -> Result<tonic::Response<PaymentsCaptureResponse>, tonic::Status> {
        info!("PAYMENT_CAPTURE_FLOW: initiated");

        let connector =
            connector_from_metadata(request.metadata()).map_err(|e| e.into_grpc_status())?;
        let connector_auth_details =
            auth_from_metadata(request.metadata()).map_err(|e| e.into_grpc_status())?;
        let payload = request.into_inner();

        //get connector data
        let connector_data = ConnectorData::get_connector_by_name(&connector);

        // Get connector integration
        let connector_integration: BoxedConnectorIntegrationV2<
            '_,
            Capture,
            PaymentFlowData,
            PaymentsCaptureData,
            PaymentsResponseData,
        > = connector_data.connector.get_connector_integration_v2();

        // Create connector request data
        let payment_capture_data = PaymentsCaptureData::foreign_try_from(payload.clone())
            .map_err(|e| e.into_grpc_status())?;

        // Create common request data
        let payment_flow_data =
            PaymentFlowData::foreign_try_from((payload.clone(), self.config.connectors.clone()))
                .map_err(|e| e.into_grpc_status())?;

        // Create router data
        let router_data = RouterDataV2 {
            flow: std::marker::PhantomData,
            resource_common_data: payment_flow_data,
            connector_auth_type: connector_auth_details,
            request: payment_capture_data,
            response: Err(ErrorResponse::default()),
        };

        let response = external_services::service::execute_connector_processing_step(
            &self.config.proxy,
            connector_integration,
            router_data,
        )
        .await
        .switch()
        .map_err(|e| e.into_grpc_status())?;

        let capture_response =
            generate_payment_capture_response(response).map_err(|e| e.into_grpc_status())?;

        Ok(tonic::Response::new(capture_response))
    }

    async fn setup_mandate(
        &self,
        request: tonic::Request<SetupMandateRequest>,
    ) -> Result<tonic::Response<SetupMandateResponse>, tonic::Status> {
        info!("SETUP_MANDATE_FLOW: initiated");

        let connector =
            connector_from_metadata(request.metadata()).map_err(|e| e.into_grpc_status())?;
        let connector_auth_details =
            auth_from_metadata(request.metadata()).map_err(|e| e.into_grpc_status())?;
        let payload = request.into_inner();

        //get connector data
        let connector_data = ConnectorData::get_connector_by_name(&connector);

        // Get connector integration
        let connector_integration: BoxedConnectorIntegrationV2<
            '_,
            SetupMandate,
            PaymentFlowData,
            SetupMandateRequestData,
            PaymentsResponseData,
        > = connector_data.connector.get_connector_integration_v2();

        // Create common request data
        let mut payment_flow_data =
            PaymentFlowData::foreign_try_from((payload.clone(), self.config.connectors.clone()))
                .map_err(|e| e.into_grpc_status())?;

        let should_do_order_create = connector_data.connector.should_do_order_create();

        if should_do_order_create {
            self.handle_order_creation_for_setup_mandate(
                connector_data.clone(),
                &mut payment_flow_data,
                connector_auth_details.clone(),
                &payload,
            )
            .await?;
        }

        let setup_mandate_request_data = SetupMandateRequestData::foreign_try_from(payload.clone())
            .map_err(|e| e.into_grpc_status())?;

        // Create router data
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
        )
        .await
        .switch()
        .map_err(|e| e.into_grpc_status())?;

        // Generate response
        let setup_mandate_response =
            generate_setup_mandate_response(response).map_err(|e| e.into_grpc_status())?;

        Ok(tonic::Response::new(setup_mandate_response))
    }

    async fn accept_dispute(
        &self,
        request: tonic::Request<AcceptDisputeRequest>,
    ) -> Result<tonic::Response<AcceptDisputeResponse>, tonic::Status> {
        info!("DISPUTE_FLOW: initiated");
        let metadata = request.metadata().clone();
        let payload = request.into_inner();
        let connector = connector_from_metadata(&metadata).map_err(|e| e.into_grpc_status())?;

        let connector_data = ConnectorData::get_connector_by_name(&connector);

        let connector_integration: BoxedConnectorIntegrationV2<
            '_,
            Accept,
            DisputeFlowData,
            AcceptDisputeData,
            DisputeResponseData,
        > = connector_data.connector.get_connector_integration_v2();

        let dispute_data = AcceptDisputeData::foreign_try_from(payload.clone())
            .map_err(|e| e.into_grpc_status())?;

        let dispute_flow_data =
            DisputeFlowData::foreign_try_from((payload.clone(), self.config.connectors.clone()))
                .map_err(|e| e.into_grpc_status())?;

        let connector_auth_details =
            auth_from_metadata(&metadata).map_err(|e| e.into_grpc_status())?;

        let router_data: RouterDataV2<
            Accept,
            DisputeFlowData,
            AcceptDisputeData,
            DisputeResponseData,
        > = RouterDataV2 {
            flow: std::marker::PhantomData,
            resource_common_data: dispute_flow_data,
            connector_auth_type: connector_auth_details,
            request: dispute_data,
            response: Err(ErrorResponse::default()),
        };

        let response = external_services::service::execute_connector_processing_step(
            &self.config.proxy,
            connector_integration,
            router_data,
        )
        .await
        .switch()
        .map_err(|e| e.into_grpc_status())?;

        let dispute_response =
            generate_accept_dispute_response(response).map_err(|e| e.into_grpc_status())?;

        Ok(tonic::Response::new(dispute_response))
    }

    async fn submit_evidence(
        &self,
        request: tonic::Request<SubmitEvidenceRequest>,
    ) -> Result<tonic::Response<SubmitEvidenceResponse>, tonic::Status> {
        info!("DISPUTE_FLOW: initiated");
        let metadata = request.metadata().clone();
        let payload = request.into_inner();
        let connector = connector_from_metadata(&metadata).map_err(|e| e.into_grpc_status())?;
        let connector_data = ConnectorData::get_connector_by_name(&connector);

        let connector_integration: BoxedConnectorIntegrationV2<
            '_,
            SubmitEvidence,
            DisputeFlowData,
            SubmitEvidenceData,
            DisputeResponseData,
        > = connector_data.connector.get_connector_integration_v2();

        let dispute_data = SubmitEvidenceData::foreign_try_from(payload.clone())
            .map_err(|e| e.into_grpc_status())?;

        let dispute_flow_data =
            DisputeFlowData::foreign_try_from((payload.clone(), self.config.connectors.clone()))
                .map_err(|e| e.into_grpc_status())?;

        let connector_auth_details =
            auth_from_metadata(&metadata).map_err(|e| e.into_grpc_status())?;

        let router_data: RouterDataV2<
            SubmitEvidence,
            DisputeFlowData,
            SubmitEvidenceData,
            DisputeResponseData,
        > = RouterDataV2 {
            flow: std::marker::PhantomData,
            resource_common_data: dispute_flow_data,
            connector_auth_type: connector_auth_details,
            request: dispute_data,
            response: Err(ErrorResponse::default()),
        };

        let response = external_services::service::execute_connector_processing_step(
            &self.config.proxy,
            connector_integration,
            router_data,
        )
        .await
        .switch()
        .map_err(|e| e.into_grpc_status())?;

        let dispute_response =
            generate_submit_evidence_response(response).map_err(|e| e.into_grpc_status())?;

        Ok(tonic::Response::new(dispute_response))
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
    let response = PaymentsSyncResponse::foreign_try_from(webhook_details).change_context(
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

    // Generate response
    let response = RefundsSyncResponse::foreign_try_from(webhook_details).change_context(
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
