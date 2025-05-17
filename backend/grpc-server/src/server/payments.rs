use crate::{
    configs::Config,
    utils::{auth_from_metadata, connector_from_metadata},
};
use connector_integration::types::ConnectorData;
use domain_types::types::generate_payment_void_response;
use domain_types::{
    connector_flow::{
        Accept, Authorize, Capture, CreateOrder, PSync, RSync, Refund, SetupMandate,
        SubmitEvidence, Void,
    },
    connector_types::{
        AcceptDisputeData, DisputeFlowData, DisputeResponseData, PaymentCreateOrderData,
        PaymentCreateOrderResponse, PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData,
        PaymentsCaptureData, PaymentsResponseData, PaymentsSyncData, RefundFlowData,
        RefundSyncData, RefundsData, RefundsResponseData, SetupMandateRequestData,
        SubmitEvidenceData,
    },
    types::{generate_accept_dispute_response, generate_submit_evidence_response},
};
use domain_types::{
    types::{
        generate_payment_capture_response, generate_payment_sync_response,
        generate_refund_response, generate_refund_sync_response, generate_setup_mandate_response,
    },
    utils::ForeignTryFrom,
};
use external_services;
use grpc_api_types::payments::{
    payment_service_server::PaymentService, AcceptDisputeRequest, AcceptDisputeResponse,
    IncomingWebhookRequest, IncomingWebhookResponse, PaymentsAuthorizeRequest,
    PaymentsAuthorizeResponse, PaymentsCaptureRequest, PaymentsCaptureResponse,
    PaymentsSyncRequest, PaymentsSyncResponse, PaymentsVoidRequest, PaymentsVoidResponse,
    RefundsRequest, RefundsResponse, RefundsSyncRequest, RefundsSyncResponse, SetupMandateRequest,
    SetupMandateResponse, SubmitEvidenceRequest, SubmitEvidenceResponse,
};
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
        request: tonic::Request<PaymentsSyncRequest>,
    ) -> Result<tonic::Response<PaymentsSyncResponse>, tonic::Status>;

    async fn internal_refund_sync(
        &self,
        request: tonic::Request<RefundsSyncRequest>,
    ) -> Result<tonic::Response<RefundsSyncResponse>, tonic::Status>;

    async fn internal_void_payment(
        &self,
        request: tonic::Request<PaymentsVoidRequest>,
    ) -> Result<tonic::Response<PaymentsVoidResponse>, tonic::Status>;

    async fn internal_refund(
        &self,
        request: tonic::Request<RefundsRequest>,
    ) -> Result<tonic::Response<RefundsResponse>, tonic::Status>;

    async fn internal_payment_capture(
        &self,
        request: tonic::Request<PaymentsCaptureRequest>,
    ) -> Result<tonic::Response<PaymentsCaptureResponse>, tonic::Status>;
}

macro_rules! implement_payment_operation {
    (
        fn_name: $fn_name:ident,
        log_prefix: $log_prefix:literal,
        request_type: $request_type:ty,
        response_type: $response_type:ty,
        flow_marker: $flow_marker:ty,
        resource_common_data_type: $resource_common_data_type:ty,
        request_data_type: $request_data_type:ty,
        response_data_type: $response_data_type:ty,
        request_data_constructor: $request_data_constructor:path,
        common_flow_data_constructor: $common_flow_data_constructor:path,
        generate_response_fn: $generate_response_fn:path
    ) => {
        async fn $fn_name(
            &self,
            request: tonic::Request<$request_type>,
        ) -> Result<tonic::Response<$response_type>, tonic::Status> {
            info!(concat!($log_prefix, "_FLOW: initiated"));

            let connector = crate::utils::connector_from_metadata(request.metadata())?;
            let connector_auth_details = crate::utils::auth_from_metadata(request.metadata())?;
            let payload = request.into_inner();

            // Get connector data
            let connector_data = connector_integration::types::ConnectorData::get_connector_by_name(&connector);

            // Get connector integration
            let connector_integration: hyperswitch_interfaces::connector_integration_v2::BoxedConnectorIntegrationV2<
                '_,
                $flow_marker,
                $resource_common_data_type,
                $request_data_type,
                $response_data_type,
            > = connector_data.connector.get_connector_integration_v2();

            // Create connector request data
            let specific_request_data = $request_data_constructor(payload.clone())
                .map_err(|e| tonic::Status::invalid_argument(format!("Invalid request data: {}", e)))?;

            // Create common request data
            let common_flow_data = $common_flow_data_constructor((payload.clone(), self.config.connectors.clone()))
                .map_err(|e| tonic::Status::invalid_argument(format!("Invalid flow data: {}", e)))?;

            // Create router data
            let router_data = hyperswitch_domain_models::router_data_v2::RouterDataV2::<
                $flow_marker,
                $resource_common_data_type,
                $request_data_type,
                $response_data_type,
            > {
                flow: std::marker::PhantomData,
                resource_common_data: common_flow_data,
                connector_auth_type: connector_auth_details,
                request: specific_request_data,
                response: Err(hyperswitch_domain_models::router_data::ErrorResponse::default()),
            };

            // Execute connector processing
            let response_result = external_services::service::execute_connector_processing_step(
                &self.config.proxy,
                connector_integration,
                router_data,
            )
            .await
            .map_err(|e| tonic::Status::internal(format!("Connector processing error: {}", e)))?;

            // Generate response
            let final_response = $generate_response_fn(response_result)
                .map_err(|e| tonic::Status::internal(format!("Response generation error: {}", e)))?;

            Ok(tonic::Response::new(final_response))
        }
    };
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

        let currency =
            match hyperswitch_common_enums::Currency::foreign_try_from(payload.currency()) {
                Ok(currency) => currency,
                Err(e) => {
                    return Err(tonic::Status::invalid_argument(format!(
                        "Invalid currency: {}",
                        e
                    )))
                }
            };

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
        let response = match external_services::service::execute_connector_processing_step(
            &self.config.proxy,
            connector_integration,
            order_router_data,
        )
        .await
        {
            Ok(resp) => resp,
            Err(e) => {
                return Err(tonic::Status::internal(format!(
                    "Connector processing error: {}",
                    e
                )))
            }
        };

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
            .map_err(|e| tonic::Status::invalid_argument(format!("Invalid currency: {}", e)))?;

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
        .map_err(|e| tonic::Status::internal(format!("Connector processing error: {}", e)))?;

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
    implement_payment_operation!(
        fn_name: internal_payment_sync,
        log_prefix: "PAYMENT_SYNC",
        request_type: PaymentsSyncRequest,
        response_type: PaymentsSyncResponse,
        flow_marker: PSync,
        resource_common_data_type: PaymentFlowData,
        request_data_type: PaymentsSyncData,
        response_data_type: PaymentsResponseData,
        request_data_constructor: PaymentsSyncData::foreign_try_from,
        common_flow_data_constructor: PaymentFlowData::foreign_try_from,
        generate_response_fn: generate_payment_sync_response
    );

    implement_payment_operation!(
        fn_name: internal_refund_sync,
        log_prefix: "REFUND_SYNC",
        request_type: RefundsSyncRequest,
        response_type: RefundsSyncResponse,
        flow_marker: RSync,
        resource_common_data_type: RefundFlowData,
        request_data_type: RefundSyncData,
        response_data_type: RefundsResponseData,
        request_data_constructor: RefundSyncData::foreign_try_from,
        common_flow_data_constructor: RefundFlowData::foreign_try_from,
        generate_response_fn: generate_refund_sync_response
    );

    implement_payment_operation!(
        fn_name: internal_void_payment,
        log_prefix: "PAYMENT_VOID",
        request_type: PaymentsVoidRequest,
        response_type: PaymentsVoidResponse,
        flow_marker: Void,
        resource_common_data_type: PaymentFlowData,
        request_data_type: PaymentVoidData,
        response_data_type: PaymentsResponseData,
        request_data_constructor: PaymentVoidData::foreign_try_from,
        common_flow_data_constructor: PaymentFlowData::foreign_try_from,
        generate_response_fn: generate_payment_void_response
    );

    implement_payment_operation!(
        fn_name: internal_refund,
        log_prefix: "REFUND",
        request_type: RefundsRequest,
        response_type: RefundsResponse,
        flow_marker: Refund,
        resource_common_data_type: RefundFlowData,
        request_data_type: RefundsData,
        response_data_type: RefundsResponseData,
        request_data_constructor: RefundsData::foreign_try_from,
        common_flow_data_constructor: RefundFlowData::foreign_try_from,
        generate_response_fn: generate_refund_response
    );

    implement_payment_operation!(
        fn_name: internal_payment_capture,
        log_prefix: "PAYMENT_CAPTURE",
        request_type: PaymentsCaptureRequest,
        response_type: PaymentsCaptureResponse,
        flow_marker: Capture,
        resource_common_data_type: PaymentFlowData,
        request_data_type: PaymentsCaptureData,
        response_data_type: PaymentsResponseData,
        request_data_constructor: PaymentsCaptureData::foreign_try_from,
        common_flow_data_constructor: PaymentFlowData::foreign_try_from,
        generate_response_fn: generate_payment_capture_response
    );
}

#[tonic::async_trait]
impl PaymentService for Payments {
    async fn payment_authorize(
        &self,
        request: tonic::Request<PaymentsAuthorizeRequest>,
    ) -> Result<tonic::Response<PaymentsAuthorizeResponse>, tonic::Status> {
        info!("PAYMENT_AUTHORIZE_FLOW: initiated");

        let connector = connector_from_metadata(request.metadata())?;
        let connector_auth_details = auth_from_metadata(request.metadata())?;
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
        let mut payment_flow_data = match PaymentFlowData::foreign_try_from((
            payload.clone(),
            self.config.connectors.clone(),
        )) {
            Ok(data) => data,
            Err(e) => {
                return Err(tonic::Status::invalid_argument(format!(
                    "Invalid request data: {}",
                    e
                )))
            }
        };

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
        let payment_authorize_data = match PaymentsAuthorizeData::foreign_try_from(payload.clone())
        {
            Ok(data) => data,
            Err(e) => {
                return Err(tonic::Status::invalid_argument(format!(
                    "Invalid request data: {}",
                    e
                )))
            }
        };

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
        let response = match external_services::service::execute_connector_processing_step(
            &self.config.proxy,
            connector_integration,
            router_data,
        )
        .await
        {
            Ok(resp) => resp,
            Err(e) => {
                return Err(tonic::Status::internal(format!(
                    "Connector processing error: {}",
                    e
                )))
            }
        };

        // Generate response
        let authorize_response =
            match domain_types::types::generate_payment_authorize_response(response) {
                Ok(resp) => resp,
                Err(e) => {
                    return Err(tonic::Status::internal(format!(
                        "Response generation error: {}",
                        e
                    )))
                }
            };

        Ok(tonic::Response::new(authorize_response))
    }

    async fn payment_sync(
        &self,
        request: tonic::Request<PaymentsSyncRequest>,
    ) -> Result<tonic::Response<PaymentsSyncResponse>, tonic::Status> {
        self.internal_payment_sync(request).await
    }

    async fn refund_sync(
        &self,
        request: tonic::Request<RefundsSyncRequest>,
    ) -> Result<tonic::Response<RefundsSyncResponse>, tonic::Status> {
        self.internal_refund_sync(request).await
    }

    async fn void_payment(
        &self,
        request: tonic::Request<PaymentsVoidRequest>,
    ) -> Result<tonic::Response<PaymentsVoidResponse>, tonic::Status> {
        self.internal_void_payment(request).await
    }

    async fn incoming_webhook(
        &self,
        request: tonic::Request<IncomingWebhookRequest>,
    ) -> Result<tonic::Response<IncomingWebhookResponse>, tonic::Status> {
        let connector = connector_from_metadata(request.metadata())?;
        let connector_auth_details = auth_from_metadata(request.metadata())?;
        let payload = request.into_inner();

        let request_details = payload
            .request_details
            .map(domain_types::connector_types::RequestDetails::foreign_try_from)
            .ok_or_else(|| {
                tonic::Status::invalid_argument("missing request_details in the payload")
            })?
            .map_err(|e| {
                tonic::Status::invalid_argument(format!(
                    "Invalid request_details in the payload: {}",
                    e
                ))
            })?;

        let webhook_secrets = payload
            .webhook_secrets
            .map(|details| {
                domain_types::connector_types::ConnectorWebhookSecrets::foreign_try_from(details)
                    .map_err(|e| {
                        tonic::Status::invalid_argument(format!(
                            "Invalid webhook_secrets in the payload: {}",
                            e
                        ))
                    })
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
            .map_err(|e| {
                tonic::Status::internal(format!(
                    "Connector processing error in verify_webhook_source: {}",
                    e
                ))
            })?;

        let event_type = connector_data
            .connector
            .get_event_type(
                request_details.clone(),
                webhook_secrets.clone(),
                Some(connector_auth_details.clone()),
            )
            .map_err(|e| {
                tonic::Status::internal(format!(
                    "Connector processing error in get_event_type: {}",
                    e
                ))
            })?;

        // Get content for the webhook based on the event type
        let content = match event_type {
            domain_types::connector_types::EventType::Payment => {
                get_payments_webhook_content(
                    connector_data,
                    request_details,
                    webhook_secrets,
                    Some(connector_auth_details),
                )
                .await?
            }
            domain_types::connector_types::EventType::Refund => {
                get_refunds_webhook_content(
                    connector_data,
                    request_details,
                    webhook_secrets,
                    Some(connector_auth_details),
                )
                .await?
            }
        };

        let api_event_type = grpc_api_types::payments::EventType::foreign_try_from(event_type)
            .map_err(|e| {
                tonic::Status::internal(format!("Invalid event_type in the payload: {}", e))
            })?;

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
        self.internal_refund(request).await
    }

    async fn payment_capture(
        &self,
        request: tonic::Request<PaymentsCaptureRequest>,
    ) -> Result<tonic::Response<PaymentsCaptureResponse>, tonic::Status> {
        self.internal_payment_capture(request).await
    }

    async fn setup_mandate(
        &self,
        request: tonic::Request<SetupMandateRequest>,
    ) -> Result<tonic::Response<SetupMandateResponse>, tonic::Status> {
        info!("SETUP_MANDATE_FLOW: initiated");

        let connector = connector_from_metadata(request.metadata())?;
        let connector_auth_details = auth_from_metadata(request.metadata())?;
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
                .map_err(|e| {
                    tonic::Status::invalid_argument(format!("Invalid request data: {}", e))
                })?;

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
            .map_err(|e| tonic::Status::invalid_argument(format!("Invalid request data: {}", e)))?;

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
        .map_err(|e| tonic::Status::internal(format!("Connector processing error: {}", e)))?;

        // Generate response
        let setup_mandate_response = generate_setup_mandate_response(response)
            .map_err(|e| tonic::Status::internal(format!("Response generation error: {}", e)))?;

        Ok(tonic::Response::new(setup_mandate_response))
    }

    async fn accept_dispute(
        &self,
        request: tonic::Request<AcceptDisputeRequest>,
    ) -> Result<tonic::Response<AcceptDisputeResponse>, tonic::Status> {
        info!("DISPUTE_FLOW: initiated");
        let metadata = request.metadata().clone();
        let payload = request.into_inner();
        let connector = connector_from_metadata(&metadata)?;

        let connector_data = ConnectorData::get_connector_by_name(&connector);

        let connector_integration: BoxedConnectorIntegrationV2<
            '_,
            Accept,
            DisputeFlowData,
            AcceptDisputeData,
            DisputeResponseData,
        > = connector_data.connector.get_connector_integration_v2();

        let dispute_data = AcceptDisputeData::foreign_try_from(payload.clone())
            .map_err(|e| tonic::Status::invalid_argument(format!("Invalid request data: {}", e)))?;

        let dispute_flow_data =
            DisputeFlowData::foreign_try_from((payload.clone(), self.config.connectors.clone()))
                .map_err(|e| {
                    tonic::Status::invalid_argument(format!("Invalid flow data: {}", e))
                })?;

        let connector_auth_details = auth_from_metadata(&metadata)?;

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
        .map_err(|e| tonic::Status::internal(format!("Connector processing error: {}", e)))?;

        let dispute_response = generate_accept_dispute_response(response)
            .map_err(|e| tonic::Status::internal(format!("Response generation error: {}", e)))?;

        Ok(tonic::Response::new(dispute_response))
    }

    async fn submit_evidence(
        &self,
        request: tonic::Request<SubmitEvidenceRequest>,
    ) -> Result<tonic::Response<SubmitEvidenceResponse>, tonic::Status> {
        info!("DISPUTE_FLOW: initiated");
        let metadata = request.metadata().clone();
        let payload = request.into_inner();
        let connector = connector_from_metadata(&metadata)?;
        let connector_data = ConnectorData::get_connector_by_name(&connector);

        let connector_integration: BoxedConnectorIntegrationV2<
            '_,
            SubmitEvidence,
            DisputeFlowData,
            SubmitEvidenceData,
            DisputeResponseData,
        > = connector_data.connector.get_connector_integration_v2();

        let dispute_data = SubmitEvidenceData::foreign_try_from(payload.clone())
            .map_err(|e| tonic::Status::invalid_argument(format!("Invalid request data: {}", e)))?;

        let dispute_flow_data =
            DisputeFlowData::foreign_try_from((payload.clone(), self.config.connectors.clone()))
                .map_err(|e| {
                    tonic::Status::invalid_argument(format!("Invalid flow data: {}", e))
                })?;

        let connector_auth_details = auth_from_metadata(&metadata)?;

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
        .map_err(|e| tonic::Status::internal(format!("Connector processing error: {}", e)))?;

        let dispute_response = generate_submit_evidence_response(response)
            .map_err(|e| tonic::Status::internal(format!("Response generation error: {}", e)))?;

        Ok(tonic::Response::new(dispute_response))
    }
}

async fn get_payments_webhook_content(
    connector_data: ConnectorData,
    request_details: domain_types::connector_types::RequestDetails,
    webhook_secrets: Option<domain_types::connector_types::ConnectorWebhookSecrets>,
    connector_auth_details: Option<ConnectorAuthType>,
) -> Result<grpc_api_types::payments::WebhookResponseContent, tonic::Status> {
    let webhook_details = match connector_data.connector.process_payment_webhook(
        request_details,
        webhook_secrets,
        connector_auth_details,
    ) {
        Ok(resp) => resp,
        Err(e) => {
            return Err(tonic::Status::internal(format!(
                "Connector processing error in process_payment_webhook: {}",
                e
            )))
        }
    };
    // Generate response
    let response = match PaymentsSyncResponse::foreign_try_from(webhook_details) {
        Ok(resp) => resp,
        Err(e) => {
            return Err(tonic::Status::internal(format!(
                "Error while constructing response: {}",
                e
            )))
        }
    };
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
) -> Result<grpc_api_types::payments::WebhookResponseContent, tonic::Status> {
    let webhook_details = connector_data
        .connector
        .process_refund_webhook(request_details, webhook_secrets, connector_auth_details)
        .map_err(|e| {
            tonic::Status::internal(format!(
                "Connector processing error in process_refund_webhook: {}",
                e
            ))
        })?;

    // Generate response
    let response = RefundsSyncResponse::foreign_try_from(webhook_details).map_err(|e| {
        tonic::Status::internal(format!("Error while constructing response: {}", e))
    })?;

    Ok(grpc_api_types::payments::WebhookResponseContent {
        content: Some(
            grpc_api_types::payments::webhook_response_content::Content::RefundsResponse(response),
        ),
    })
}
