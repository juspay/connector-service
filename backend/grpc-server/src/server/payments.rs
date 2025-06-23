use crate::implement_connector_operation;
use crate::{
    configs::Config,
    error::{IntoGrpcStatus, ReportSwitchExt, ResultExtGrpc},
    utils::{
        attempt_status_to_str, auth_from_metadata, connector_from_metadata,
        connector_merchant_id_tenant_id_request_id_from_metadata, mask_sensitive_fields,
    },
};
use connector_integration::types::ConnectorData;
use domain_types::{
    connector_flow::{
        Accept, Authorize, Capture, CreateOrder, DefendDispute, FlowName, PSync, RSync, Refund,
        SetupMandate, SubmitEvidence, Void,
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
        generate_defend_dispute_response, generate_payment_capture_response,
        generate_payment_sync_response, generate_payment_void_response, generate_refund_response,
        generate_refund_sync_response, generate_setup_mandate_response,
    },
    utils::ForeignTryFrom,
};
use error_stack::ResultExt;
use external_services;
use grpc_api_types::payments::{
    payment_service_server::PaymentService, AcceptDisputeRequest, AcceptDisputeResponse,
    DisputeDefendRequest, DisputeDefendResponse, DisputesSyncResponse, IncomingWebhookRequest,
    IncomingWebhookResponse, PaymentsAuthorizeRequest, PaymentsAuthorizeResponse,
    PaymentsCaptureRequest, PaymentsCaptureResponse, PaymentsSyncRequest, PaymentsSyncResponse,
    PaymentsVoidRequest, PaymentsVoidResponse, RefundsRequest, RefundsResponse, RefundsSyncRequest,
    RefundsSyncResponse, SetupMandateRequest, SetupMandateResponse, SubmitEvidenceRequest,
    SubmitEvidenceResponse,
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
    async fn internal_defend_dispute(
        &self,
        request: tonic::Request<DisputeDefendRequest>,
    ) -> Result<tonic::Response<DisputeDefendResponse>, tonic::Status>;

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
            None,
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
            None,
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
        fn_name: internal_defend_dispute,
        log_prefix: "DEFEND_DISPUTE",
        request_type: DisputeDefendRequest,
        response_type: DisputeDefendResponse,
        flow_marker: DefendDispute,
        resource_common_data_type: DisputeFlowData,
        request_data_type: DisputeDefendData,
        response_data_type: DisputeResponseData,
        request_data_constructor: DisputeDefendData::foreign_try_from,
        common_flow_data_constructor: DisputeFlowData::foreign_try_from,
        generate_response_fn: generate_defend_dispute_response
    );

    implement_connector_operation!(
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

    implement_connector_operation!(
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

    implement_connector_operation!(
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

    implement_connector_operation!(
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

    implement_connector_operation!(
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
    #[tracing::instrument(
        name = "payment_authorize",
        fields(
            name = crate::consts::NAME,
            service_name = crate::consts::PAYMENT_SERVICE,
            service_method = FlowName::Authorize.to_string(),
            request_body = tracing::field::Empty,
            response_body = tracing::field::Empty,
            error_message = tracing::field::Empty,
            merchant_id = tracing::field::Empty,
            gateway = tracing::field::Empty,
            request_id = tracing::field::Empty,
            time_stamp = tracing::field::Empty,
            status_code = tracing::field::Empty,
            message_ = "Golden Log Line (incoming)",
            response_time = tracing::field::Empty,
            tenant_id = tracing::field::Empty,
            flow = FlowName::Authorize.to_string(),
            flow_specific_fields.status = tracing::field::Empty,
        )
        skip(self, request)
    )]
    async fn payment_authorize(
        &self,
        request: tonic::Request<PaymentsAuthorizeRequest>,
    ) -> Result<tonic::Response<PaymentsAuthorizeResponse>, tonic::Status> {
        info!("PAYMENT_AUTHORIZE_FLOW: initiated");
        let current_span = tracing::Span::current();
        let (gateway, merchant_id, tenant_id, request_id) =
            connector_merchant_id_tenant_id_request_id_from_metadata(request.metadata())
                .map_err(|e| e.into_grpc_status())?;
        let req_body = request.get_ref();
        let req_body_json =
            serde_json::to_string(req_body).unwrap_or_else(|_| "<serialization error>".to_string());
        let masked_request_body = mask_sensitive_fields(req_body_json);
        current_span.record("request_body", masked_request_body);
        current_span.record("time_stamp", chrono::Utc::now().to_rfc3339());
        current_span.record("gateway", gateway.to_string());
        current_span.record("merchant_id", merchant_id);
        current_span.record("tenant_id", tenant_id);
        current_span.record("request_id", request_id);

        let start_time = tokio::time::Instant::now();
        let result: Result<tonic::Response<PaymentsAuthorizeResponse>, tonic::Status> = async {
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
                payload.all_keys_required,
            )
            .await
            .switch()
            .map_err(|e| e.into_grpc_status())?;

            // Generate response
            let authorize_response =
                domain_types::types::generate_payment_authorize_response(response)
                    .map_err(|e| e.into_grpc_status())?;

            Ok(tonic::Response::new(authorize_response))
        }
        .await;
        let duration = start_time.elapsed().as_millis();
        current_span.record("response_time", duration);

        match &result {
            Ok(response) => {
                current_span.record("response_body", tracing::field::debug(response.get_ref()));

                let status = response.get_ref().status.to_string();
                let status_str = attempt_status_to_str(status);
                current_span.record("flow_specific_fields.status", status_str);
            }
            Err(status) => {
                current_span.record("error_message", status.message());
                current_span.record("status_code", status.code().to_string());
            }
        }
        result
    }

    #[tracing::instrument(
        name = "payment_sync",
        fields(
            name = crate::consts::NAME,
            service_name = crate::consts::PAYMENT_SERVICE,
            service_method = FlowName::Psync.to_string(),
            request_body = tracing::field::Empty,
            response_body = tracing::field::Empty,
            error_message = tracing::field::Empty,
            merchant_id = tracing::field::Empty,
            gateway = tracing::field::Empty,
            request_id = tracing::field::Empty,
            time_stamp = tracing::field::Empty,
            status_code = tracing::field::Empty,
            message = "Golden Log Line (incoming)",
            response_time = tracing::field::Empty,
            tenant_id = tracing::field::Empty,
            flow = FlowName::Psync.to_string(),
            flow_specific_fields.status = tracing::field::Empty,
        )
        skip(self, request)
    )]
    async fn payment_sync(
        &self,
        request: tonic::Request<PaymentsSyncRequest>,
    ) -> Result<tonic::Response<PaymentsSyncResponse>, tonic::Status> {
        let current_span = tracing::Span::current();
        let (gateway, merchant_id, tenant_id, request_id) =
            connector_merchant_id_tenant_id_request_id_from_metadata(request.metadata())
                .map_err(|e| e.into_grpc_status())?;
        let req_body = request.get_ref();
        let req_body_json =
            serde_json::to_string(req_body).unwrap_or_else(|_| "<serialization error>".to_string());
        current_span.record("request_body", req_body_json);
        current_span.record("time_stamp", chrono::Utc::now().to_rfc3339());
        current_span.record("gateway", gateway.to_string());
        current_span.record("merchant_id", merchant_id);
        current_span.record("tenant_id", tenant_id);
        current_span.record("request_id", request_id);

        let start_time = tokio::time::Instant::now();

        let result = self.internal_payment_sync(request).await;
        let duration = start_time.elapsed().as_millis();
        current_span.record("response_time", duration);

        match &result {
            Ok(response) => {
                current_span.record("response_body", tracing::field::debug(response.get_ref()));
                let status = response.get_ref().status.to_string();
                let status_str = attempt_status_to_str(status);
                current_span.record("flow_specific_fields.status", status_str);
            }
            Err(status) => {
                current_span.record("error_message", status.message());
                current_span.record("status_code", status.code().to_string());
            }
        }
        result
    }

    #[tracing::instrument(
        name = "refund_sync",
        fields(
            name = crate::consts::NAME,
            service_name = crate::consts::PAYMENT_SERVICE,
            service_method = FlowName::Rsync.to_string(),
            request_body = tracing::field::Empty,
            response_body = tracing::field::Empty,
            error_message = tracing::field::Empty,
            merchant_id = tracing::field::Empty,
            gateway = tracing::field::Empty,
            request_id = tracing::field::Empty,
            time_stamp = tracing::field::Empty,
            status_code = tracing::field::Empty,
            message_ = "Golden Log Line (incoming)",
            response_time = tracing::field::Empty,
            tenant_id = tracing::field::Empty,
            flow = FlowName::Rsync.to_string(),
            flow_specific_fields.status = tracing::field::Empty,
        )
        skip(self, request)
    )]
    async fn refund_sync(
        &self,
        request: tonic::Request<RefundsSyncRequest>,
    ) -> Result<tonic::Response<RefundsSyncResponse>, tonic::Status> {
        let current_span = tracing::Span::current();
        let (gateway, merchant_id, tenant_id, request_id) =
            connector_merchant_id_tenant_id_request_id_from_metadata(request.metadata())
                .map_err(|e| e.into_grpc_status())?;
        let req_body = request.get_ref();
        let req_body_json =
            serde_json::to_string(req_body).unwrap_or_else(|_| "<serialization error>".to_string());
        current_span.record("request_body", req_body_json);
        current_span.record("time_stamp", chrono::Utc::now().to_rfc3339());
        current_span.record("gateway", gateway.to_string());
        current_span.record("merchant_id", merchant_id);
        current_span.record("tenant_id", tenant_id);
        current_span.record("request_id", request_id);

        let start_time = tokio::time::Instant::now();

        let result = self.internal_refund_sync(request).await;
        let duration = start_time.elapsed().as_millis();
        current_span.record("response_time", duration);

        match &result {
            Ok(response) => {
                current_span.record("response_body", tracing::field::debug(response.get_ref()));
                let status = response.get_ref().status.to_string();
                let status_str = attempt_status_to_str(status);
                current_span.record("flow_specific_fields.status", status_str);
            }
            Err(status) => {
                current_span.record("error_message", status.message());
                current_span.record("status_code", status.code().to_string());
            }
        }
        result
    }

    #[tracing::instrument(
        name = "payment_void",
        fields(
            name = crate::consts::NAME,
            service_name = crate::consts::PAYMENT_SERVICE,
            service_method = FlowName::Void.to_string(),
            request_body = tracing::field::Empty,
            response_body = tracing::field::Empty,
            error_message = tracing::field::Empty,
            merchant_id = tracing::field::Empty,
            gateway = tracing::field::Empty,
            request_id = tracing::field::Empty,
            time_stamp = tracing::field::Empty,
            status_code = tracing::field::Empty,
            message_ = "Golden Log Line (incoming)",
            response_time = tracing::field::Empty,
            tenant_id = tracing::field::Empty,
            flow = FlowName::Void.to_string(),
            flow_specific_fields.status = tracing::field::Empty,
        )
        skip(self, request)
    )]
    async fn void_payment(
        &self,
        request: tonic::Request<PaymentsVoidRequest>,
    ) -> Result<tonic::Response<PaymentsVoidResponse>, tonic::Status> {
        let current_span = tracing::Span::current();
        let (gateway, merchant_id, tenant_id, request_id) =
            connector_merchant_id_tenant_id_request_id_from_metadata(request.metadata())
                .map_err(|e| e.into_grpc_status())?;
        let req_body = request.get_ref();
        let req_body_json =
            serde_json::to_string(req_body).unwrap_or_else(|_| "<serialization error>".to_string());
        current_span.record("request_body", req_body_json);
        current_span.record("time_stamp", chrono::Utc::now().to_rfc3339());
        current_span.record("gateway", gateway.to_string());
        current_span.record("merchant_id", merchant_id);
        current_span.record("tenant_id", tenant_id);
        current_span.record("request_id", request_id);

        let start_time = tokio::time::Instant::now();

        let result = self.internal_void_payment(request).await;
        let duration = start_time.elapsed().as_millis();
        current_span.record("response_time", duration);

        match &result {
            Ok(response) => {
                current_span.record("response_body", tracing::field::debug(response.get_ref()));

                let status = response.get_ref().status.to_string();
                let status_str = attempt_status_to_str(status);
                current_span.record("flow_specific_fields.status", status_str);
            }
            Err(status) => {
                current_span.record("error_message", status.message());
                current_span.record("status_code", status.code().to_string());
            }
        }
        result
    }

    #[tracing::instrument(
        name = "incoming_webhook",
        fields(
            name = crate::consts::NAME,
            service_name = crate::consts::PAYMENT_SERVICE,
            service_method = FlowName::IncomingWebhook.to_string(),
            request_body = tracing::field::Empty,
            response_body = tracing::field::Empty,
            error_message = tracing::field::Empty,
            merchant_id = tracing::field::Empty,
            gateway = tracing::field::Empty,
            request_id = tracing::field::Empty,
            time_stamp = tracing::field::Empty,
            status_code = tracing::field::Empty,
            message_ = "Golden Log Line (incoming)",
            response_time = tracing::field::Empty,
            tenant_id = tracing::field::Empty,
            flow = FlowName::IncomingWebhook.to_string(),
            flow_specific_fields.status = tracing::field::Empty,
        )
        skip(self, request)
    )]
    async fn incoming_webhook(
        &self,
        request: tonic::Request<IncomingWebhookRequest>,
    ) -> Result<tonic::Response<IncomingWebhookResponse>, tonic::Status> {
        let current_span = tracing::Span::current();
        let (gateway, merchant_id, tenant_id, request_id) =
            connector_merchant_id_tenant_id_request_id_from_metadata(request.metadata())
                .map_err(|e| e.into_grpc_status())?;
        let req_body = request.get_ref();
        let req_body_json =
            serde_json::to_string(req_body).unwrap_or_else(|_| "<serialization error>".to_string());
        current_span.record("request_body", req_body_json);
        current_span.record("time_stamp", chrono::Utc::now().to_rfc3339());
        current_span.record("gateway", gateway.to_string());
        current_span.record("merchant_id", merchant_id);
        current_span.record("tenant_id", tenant_id);
        current_span.record("request_id", request_id);

        let start_time = tokio::time::Instant::now();
        let result: Result<tonic::Response<IncomingWebhookResponse>, tonic::Status> = async {
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
                domain_types::connector_types::EventType::Dispute => get_disputes_webhook_content(
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
        .await;
        let duration = start_time.elapsed().as_millis();
        current_span.record("response_time", duration);

        match &result {
            Ok(response) => {
                current_span.record("response_body", tracing::field::debug(response.get_ref()));
            }
            Err(status) => {
                current_span.record("error_message", status.message());
                current_span.record("status_code", status.code().to_string());
            }
        }
        result
    }

    #[tracing::instrument(
        name = "refund",
        fields(
            name = crate::consts::NAME,
            service_name = crate::consts::PAYMENT_SERVICE,
            service_method = FlowName::Refund.to_string(),
            request_body = tracing::field::Empty,
            response_body = tracing::field::Empty,
            error_message = tracing::field::Empty,
            merchant_id = tracing::field::Empty,
            gateway = tracing::field::Empty,
            request_id = tracing::field::Empty,
            time_stamp = tracing::field::Empty,
            status_code = tracing::field::Empty,
            message_ = "Golden Log Line (incoming)",
            response_time = tracing::field::Empty,
            tenant_id = tracing::field::Empty,
            flow = FlowName::Refund.to_string(),
            flow_specific_fields.status = tracing::field::Empty,
        )
        skip(self, request)
    )]
    async fn refund(
        &self,
        request: tonic::Request<RefundsRequest>,
    ) -> Result<tonic::Response<RefundsResponse>, tonic::Status> {
        let current_span = tracing::Span::current();
        let (gateway, merchant_id, tenant_id, request_id) =
            connector_merchant_id_tenant_id_request_id_from_metadata(request.metadata())
                .map_err(|e| e.into_grpc_status())?;
        let req_body = request.get_ref();
        let req_body_json =
            serde_json::to_string(req_body).unwrap_or_else(|_| "<serialization error>".to_string());
        current_span.record("request_body", req_body_json);
        current_span.record("time_stamp", chrono::Utc::now().to_rfc3339());
        current_span.record("gateway", gateway.to_string());
        current_span.record("merchant_id", merchant_id);
        current_span.record("tenant_id", tenant_id);
        current_span.record("request_id", request_id);

        let start_time = tokio::time::Instant::now();

        let result = self.internal_refund(request).await;
        let duration = start_time.elapsed().as_millis();
        current_span.record("response_time", duration);

        match &result {
            Ok(response) => {
                current_span.record("response_body", tracing::field::debug(response.get_ref()));
            }
            Err(status) => {
                current_span.record("error_message", status.message());
                current_span.record("status_code", status.code().to_string());
            }
        }
        result
    }

    #[tracing::instrument(
        name = "defend_dispute",
        fields(
            name = crate::consts::NAME,
            service_name = crate::consts::PAYMENT_SERVICE,
            service_method = FlowName::DefendDispute.to_string(),
            request_body = tracing::field::Empty,
            response_body = tracing::field::Empty,
            error_message = tracing::field::Empty,
            merchant_id = tracing::field::Empty,
            gateway = tracing::field::Empty,
            request_id = tracing::field::Empty,
            time_stamp = tracing::field::Empty,
            status_code = tracing::field::Empty,
            message_ = "Golden Log Line (incoming)",
            response_time = tracing::field::Empty,
            tenant_id = tracing::field::Empty,
            flow = FlowName::DefendDispute.to_string(),
            flow_specific_fields.status = tracing::field::Empty,
        )
        skip(self, request)
    )]
    async fn defend_dispute(
        &self,
        request: tonic::Request<DisputeDefendRequest>,
    ) -> Result<tonic::Response<DisputeDefendResponse>, tonic::Status> {
        let current_span = tracing::Span::current();
        let (gateway, merchant_id, tenant_id, request_id) =
            connector_merchant_id_tenant_id_request_id_from_metadata(request.metadata())
                .map_err(|e| e.into_grpc_status())?;
        let req_body = request.get_ref();
        let req_body_json =
            serde_json::to_string(req_body).unwrap_or_else(|_| "<serialization error>".to_string());
        current_span.record("request_body", req_body_json);
        current_span.record("time_stamp", chrono::Utc::now().to_rfc3339());
        current_span.record("gateway", gateway.to_string());
        current_span.record("merchant_id", merchant_id);
        current_span.record("tenant_id", tenant_id);
        current_span.record("request_id", request_id);

        let start_time = tokio::time::Instant::now();

        let result = self.internal_defend_dispute(request).await;
        let duration = start_time.elapsed().as_millis();
        current_span.record("response_time", duration);

        match &result {
            Ok(response) => {
                current_span.record("response_body", tracing::field::debug(response.get_ref()));
            }
            Err(status) => {
                current_span.record("error_message", status.message());
                current_span.record("status_code", status.code().to_string());
            }
        }
        result
    }

    #[tracing::instrument(
        name = "payment_capture",
        fields(
            name = crate::consts::NAME,
            service_name = crate::consts::PAYMENT_SERVICE,
            service_method = FlowName::Capture.to_string(),
            request_body = tracing::field::Empty,
            response_body = tracing::field::Empty,
            error_message = tracing::field::Empty,
            merchant_id = tracing::field::Empty,
            gateway = tracing::field::Empty,
            request_id = tracing::field::Empty,
            time_stamp = tracing::field::Empty,
            status_code = tracing::field::Empty,
            message_ = "Golden Log Line (incoming)",
            response_time = tracing::field::Empty,
            tenant_id = tracing::field::Empty,
            flow = FlowName::Capture.to_string(),
            flow_specific_fields.status = tracing::field::Empty,
        )
        skip(self, request)
    )]
    async fn payment_capture(
        &self,
        request: tonic::Request<PaymentsCaptureRequest>,
    ) -> Result<tonic::Response<PaymentsCaptureResponse>, tonic::Status> {
        let current_span = tracing::Span::current();
        let (gateway, merchant_id, tenant_id, request_id) =
            connector_merchant_id_tenant_id_request_id_from_metadata(request.metadata())
                .map_err(|e| e.into_grpc_status())?;
        let req_body = request.get_ref();
        let req_body_json =
            serde_json::to_string(req_body).unwrap_or_else(|_| "<serialization error>".to_string());
        current_span.record("request_body", req_body_json);
        current_span.record("time_stamp", chrono::Utc::now().to_rfc3339());
        current_span.record("gateway", gateway.to_string());
        current_span.record("merchant_id", merchant_id);
        current_span.record("tenant_id", tenant_id);
        current_span.record("request_id", request_id);

        let start_time = tokio::time::Instant::now();

        let result = self.internal_payment_capture(request).await;
        let duration = start_time.elapsed().as_millis();
        current_span.record("response_time", duration);

        match &result {
            Ok(response) => {
                current_span.record("response_body", tracing::field::debug(response.get_ref()));

                let status = response.get_ref().status.to_string();
                let status_str = attempt_status_to_str(status);
                current_span.record("flow_specific_fields.status", status_str);
            }
            Err(status) => {
                current_span.record("error_message", status.message());
                current_span.record("status_code", status.code().to_string());
            }
        }
        result
    }

    #[tracing::instrument(
        name = "setup_mandate",
        fields(
            name = crate::consts::NAME,
            service_name = crate::consts::PAYMENT_SERVICE,
            service_method = FlowName::SetupMandate.to_string(),
            request_body = tracing::field::Empty,
            response_body = tracing::field::Empty,
            error_message = tracing::field::Empty,
            merchant_id = tracing::field::Empty,
            gateway = tracing::field::Empty,
            request_id = tracing::field::Empty,
            time_stamp = tracing::field::Empty,
            status_code = tracing::field::Empty,
            message_ = "Golden Log Line (incoming)",
            response_time = tracing::field::Empty,
            tenant_id = tracing::field::Empty,
            flow = FlowName::SetupMandate.to_string(),
            flow_specific_fields.status = tracing::field::Empty,
        )
        skip(self, request)
    )]
    async fn setup_mandate(
        &self,
        request: tonic::Request<SetupMandateRequest>,
    ) -> Result<tonic::Response<SetupMandateResponse>, tonic::Status> {
        info!("SETUP_MANDATE_FLOW: initiated");
        let current_span = tracing::Span::current();
        let (gateway, merchant_id, tenant_id, request_id) =
            connector_merchant_id_tenant_id_request_id_from_metadata(request.metadata())
                .map_err(|e| e.into_grpc_status())?;
        let req_body = request.get_ref();
        let req_body_json =
            serde_json::to_string(req_body).unwrap_or_else(|_| "<serialization error>".to_string());
        current_span.record("request_body", req_body_json);
        current_span.record("time_stamp", chrono::Utc::now().to_rfc3339());
        current_span.record("gateway", gateway.to_string());
        current_span.record("merchant_id", merchant_id);
        current_span.record("tenant_id", tenant_id);
        current_span.record("request_id", request_id);

        let start_time = tokio::time::Instant::now();

        let result: Result<tonic::Response<SetupMandateResponse>, tonic::Status> = async {
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
                )
                .await?;
            }

            let setup_mandate_request_data =
                SetupMandateRequestData::foreign_try_from(payload.clone())
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
                None,
            )
            .await
            .switch()
            .map_err(|e| e.into_grpc_status())?;

            // Generate response
            let setup_mandate_response =
                generate_setup_mandate_response(response).map_err(|e| e.into_grpc_status())?;

            Ok(tonic::Response::new(setup_mandate_response))
        }
        .await;
        let duration = start_time.elapsed().as_millis();
        current_span.record("response_time", duration);

        match &result {
            Ok(response) => {
                current_span.record("response_body", tracing::field::debug(response.get_ref()));

                let status = response.get_ref().status.to_string();
                let status_str = attempt_status_to_str(status);
                current_span.record("flow_specific_fields.status", status_str);
            }
            Err(status) => {
                current_span.record("error_message", status.message());
                current_span.record("status_code", status.code().to_string());
            }
        }
        result
    }

    #[tracing::instrument(
        name = "accept_dispute",
        fields(
            name = crate::consts::NAME,
            service_name = crate::consts::PAYMENT_SERVICE,
            service_method = FlowName::AcceptDispute.to_string(),
            request_body = tracing::field::Empty,
            response_body = tracing::field::Empty,
            error_message = tracing::field::Empty,
            merchant_id = tracing::field::Empty,
            gateway = tracing::field::Empty,
            request_id = tracing::field::Empty,
            time_stamp = tracing::field::Empty,
            status_code = tracing::field::Empty,
            message_ = "Golden Log Line (incoming)",
            response_time = tracing::field::Empty,
            tenant_id = tracing::field::Empty,
            flow = FlowName::AcceptDispute.to_string(),
            flow_specific_fields.status = tracing::field::Empty,
        )
        skip(self, request)
    )]
    async fn accept_dispute(
        &self,
        request: tonic::Request<AcceptDisputeRequest>,
    ) -> Result<tonic::Response<AcceptDisputeResponse>, tonic::Status> {
        info!("DISPUTE_FLOW: initiated");
        let current_span = tracing::Span::current();
        let (gateway, merchant_id, tenant_id, request_id) =
            connector_merchant_id_tenant_id_request_id_from_metadata(request.metadata())
                .map_err(|e| e.into_grpc_status())?;
        let req_body = request.get_ref();
        let req_body_json =
            serde_json::to_string(req_body).unwrap_or_else(|_| "<serialization error>".to_string());
        current_span.record("request_body", req_body_json);
        current_span.record("time_stamp", chrono::Utc::now().to_rfc3339());
        current_span.record("gateway", gateway.to_string());
        current_span.record("merchant_id", merchant_id);
        current_span.record("tenant_id", tenant_id);
        current_span.record("request_id", request_id);

        let start_time = tokio::time::Instant::now();
        let result: Result<tonic::Response<AcceptDisputeResponse>, tonic::Status> = async {
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

            let dispute_flow_data = DisputeFlowData::foreign_try_from((
                payload.clone(),
                self.config.connectors.clone(),
            ))
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
                None,
            )
            .await
            .switch()
            .map_err(|e| e.into_grpc_status())?;

            let dispute_response =
                generate_accept_dispute_response(response).map_err(|e| e.into_grpc_status())?;

            Ok(tonic::Response::new(dispute_response))
        }
        .await;
        let duration = start_time.elapsed().as_millis();
        current_span.record("response_time", duration);

        match &result {
            Ok(response) => {
                current_span.record("response_body", tracing::field::debug(response.get_ref()));
            }
            Err(status) => {
                current_span.record("error_message", status.message());
                current_span.record("status_code", status.code().to_string());
            }
        }
        result
    }

    #[tracing::instrument(
        name = "submit_evidence",
        fields(
            name = crate::consts::NAME,
            service_name = crate::consts::PAYMENT_SERVICE,
            service_method = FlowName::SubmitEvidence.to_string(),
            request_body = tracing::field::Empty,
            response_body = tracing::field::Empty,
            error_message = tracing::field::Empty,
            merchant_id = tracing::field::Empty,
            gateway = tracing::field::Empty,
            request_id = tracing::field::Empty,
            time_stamp = tracing::field::Empty,
            status_code = tracing::field::Empty,
            message_ = "Golden Log Line (incoming)",
            response_time = tracing::field::Empty,
            tenant_id = tracing::field::Empty,
            flow = FlowName::SubmitEvidence.to_string(),
            flow_specific_fields.status = tracing::field::Empty,
        )
        skip(self, request)
    )]
    async fn submit_evidence(
        &self,
        request: tonic::Request<SubmitEvidenceRequest>,
    ) -> Result<tonic::Response<SubmitEvidenceResponse>, tonic::Status> {
        info!("DISPUTE_FLOW: initiated");
        let current_span = tracing::Span::current();
        let (gateway, merchant_id, tenant_id, request_id) =
            connector_merchant_id_tenant_id_request_id_from_metadata(request.metadata())
                .map_err(|e| e.into_grpc_status())?;
        let req_body = request.get_ref();
        let req_body_json =
            serde_json::to_string(req_body).unwrap_or_else(|_| "<serialization error>".to_string());
        current_span.record("request_body", req_body_json);
        current_span.record("time_stamp", chrono::Utc::now().to_rfc3339());
        current_span.record("gateway", gateway.to_string());
        current_span.record("merchant_id", merchant_id);
        current_span.record("tenant_id", tenant_id);
        current_span.record("request_id", request_id);

        let start_time = tokio::time::Instant::now();
        let result: Result<tonic::Response<SubmitEvidenceResponse>, tonic::Status> = async {
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

            let dispute_flow_data = DisputeFlowData::foreign_try_from((
                payload.clone(),
                self.config.connectors.clone(),
            ))
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
                None,
            )
            .await
            .switch()
            .map_err(|e| e.into_grpc_status())?;

            let dispute_response =
                generate_submit_evidence_response(response).map_err(|e| e.into_grpc_status())?;

            Ok(tonic::Response::new(dispute_response))
        }
        .await;
        let duration = start_time.elapsed().as_millis();
        current_span.record("response_time", duration);
        match &result {
            Ok(response) => {
                current_span.record("response_body", tracing::field::debug(response.get_ref()));
            }
            Err(status) => {
                current_span.record("error_message", status.message());
                current_span.record("status_code", status.code().to_string());
            }
        }
        result
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

    // Generate response
    let response = DisputesSyncResponse::foreign_try_from(webhook_details).change_context(
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
