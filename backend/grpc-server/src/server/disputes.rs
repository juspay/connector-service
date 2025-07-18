use std::sync::Arc;

use common_utils::errors::CustomResult;
use connector_integration::types::ConnectorData;
use domain_types::{
    connector_flow::{Accept, DefendDispute, FlowName, SubmitEvidence},
    connector_types::{
        AcceptDisputeData, DisputeDefendData, DisputeFlowData, DisputeResponseData,
        SubmitEvidenceData,
    },
    errors::{ApiError, ApplicationErrorResponse},
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    types::{
        generate_accept_dispute_response, generate_defend_dispute_response,
        generate_submit_evidence_response,
    },
    utils::ForeignTryFrom,
};
use error_stack::ResultExt;
use external_services;
use grpc_api_types::payments::{
    dispute_service_server::DisputeService, AcceptDisputeRequest, AcceptDisputeResponse,
    DisputeDefendRequest, DisputeDefendResponse, DisputeResponse, DisputeServiceGetRequest,
    DisputeServiceSubmitEvidenceRequest, DisputeServiceSubmitEvidenceResponse,
    DisputeServiceTransformRequest, DisputeServiceTransformResponse, WebhookEventType,
    WebhookResponseContent,
};
use interfaces::connector_integration_v2::BoxedConnectorIntegrationV2;
use tracing::info;

use crate::{
    configs::Config,
    error::{IntoGrpcStatus, ReportSwitchExt, ResultExtGrpc},
    implement_connector_operation,
    utils::{auth_from_metadata, connector_from_metadata, grpc_logging_wrapper},
};

// Helper trait for dispute operations
trait DisputeOperationsInternal {
    async fn internal_defend(
        &self,
        request: tonic::Request<DisputeDefendRequest>,
    ) -> Result<tonic::Response<DisputeDefendResponse>, tonic::Status>;
}

pub struct Disputes {
    pub config: Arc<Config>,
}

impl DisputeOperationsInternal for Disputes {
    implement_connector_operation!(
        fn_name: internal_defend,
        log_prefix: "DEFEND_DISPUTE",
        request_type: DisputeDefendRequest,
        response_type: DisputeDefendResponse,
        flow_marker: DefendDispute,
        resource_common_data_type: DisputeFlowData,
        request_data_type: DisputeDefendData,
        response_data_type: DisputeResponseData,
        request_data_constructor: DisputeDefendData::foreign_try_from,
        common_flow_data_constructor: DisputeFlowData::foreign_try_from,
        generate_response_fn: generate_defend_dispute_response,
        all_keys_required: None
    );
}

#[tonic::async_trait]
impl DisputeService for Disputes {
    #[tracing::instrument(
        name = "dispute_submit_evidence",
        fields(
            name = common_utils::consts::NAME,
            service_name = tracing::field::Empty,
            service_method = FlowName::SubmitEvidence.to_string(),
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
            flow = FlowName::SubmitEvidence.to_string(),
            flow_specific_fields.status = tracing::field::Empty,
        )
        skip(self, request)
    )]
    async fn submit_evidence(
        &self,
        request: tonic::Request<DisputeServiceSubmitEvidenceRequest>,
    ) -> Result<tonic::Response<DisputeServiceSubmitEvidenceResponse>, tonic::Status> {
        info!("DISPUTE_FLOW: initiated");
        let service_name = request
            .extensions()
            .get::<String>()
            .cloned()
            .unwrap_or_else(|| "unknown_service".to_string());
        grpc_logging_wrapper(request, &service_name, |request| async {
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
                &connector.to_string(),
                &service_name,
            )
            .await
            .switch()
            .map_err(|e| e.into_grpc_status())?;

            let dispute_response =
                generate_submit_evidence_response(response).map_err(|e| e.into_grpc_status())?;

            Ok(tonic::Response::new(dispute_response))
        })
        .await
    }

    #[tracing::instrument(
        name = "dispute_sync",
        fields(
            name = common_utils::consts::NAME,
            service_name = tracing::field::Empty,
            service_method = FlowName::Dsync.to_string(),
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
            flow = FlowName::Dsync.to_string(),
            flow_specific_fields.status = tracing::field::Empty,
        )
        skip(self, request)
    )]
    async fn get(
        &self,
        request: tonic::Request<DisputeServiceGetRequest>,
    ) -> Result<tonic::Response<DisputeResponse>, tonic::Status> {
        // For now, return a basic dispute response
        // This will need proper implementation based on domain logic
        let service_name = request
            .extensions()
            .get::<String>()
            .cloned()
            .unwrap_or_else(|| "unknown_service".to_string());
        grpc_logging_wrapper(request, &service_name, |request| async {
            let _payload = request.into_inner();
            let response = DisputeResponse {
                ..Default::default()
            };
            Ok(tonic::Response::new(response))
        })
        .await
    }

    #[tracing::instrument(
        name = "dispute_defend",
        fields(
            name = common_utils::consts::NAME,
            service_name = tracing::field::Empty,
            service_method = FlowName::DefendDispute.to_string(),
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
            flow = FlowName::DefendDispute.to_string(),
            flow_specific_fields.status = tracing::field::Empty,
        )
        skip(self, request)
    )]
    async fn defend(
        &self,
        request: tonic::Request<DisputeDefendRequest>,
    ) -> Result<tonic::Response<DisputeDefendResponse>, tonic::Status> {
        self.internal_defend(request).await
    }

    #[tracing::instrument(
        name = "dispute_accept",
        fields(
            name = common_utils::consts::NAME,
            service_name = tracing::field::Empty,
            service_method = FlowName::AcceptDispute.to_string(),
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
            flow = FlowName::AcceptDispute.to_string(),
            flow_specific_fields.status = tracing::field::Empty,
        )
        skip(self, request)
    )]
    async fn accept(
        &self,
        request: tonic::Request<AcceptDisputeRequest>,
    ) -> Result<tonic::Response<AcceptDisputeResponse>, tonic::Status> {
        info!("DISPUTE_FLOW: initiated");
        let service_name = request
            .extensions()
            .get::<String>()
            .cloned()
            .unwrap_or_else(|| "unknown_service".to_string());
        grpc_logging_wrapper(request, &service_name, |request| async {
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
                &connector.to_string(),
                &service_name,
            )
            .await
            .switch()
            .map_err(|e| e.into_grpc_status())?;

            let dispute_response =
                generate_accept_dispute_response(response).map_err(|e| e.into_grpc_status())?;

            Ok(tonic::Response::new(dispute_response))
        })
        .await
    }

    #[tracing::instrument(
        name = "distpute_transform",
        fields(
            name = common_utils::consts::NAME,
            service_name = tracing::field::Empty,
            service_method = FlowName::IncomingWebhook.to_string(),
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
            flow = FlowName::IncomingWebhook.to_string(),
            flow_specific_fields.status = tracing::field::Empty,
        )
        skip(self, request)
    )]
    async fn transform(
        &self,
        request: tonic::Request<DisputeServiceTransformRequest>,
    ) -> Result<tonic::Response<DisputeServiceTransformResponse>, tonic::Status> {
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

            // Get connector data
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

            let content = get_disputes_webhook_content(
                connector_data,
                request_details,
                webhook_secrets,
                Some(connector_auth_details),
            )
            .await
            .map_err(|e| e.into_grpc_status())?;

            let response = DisputeServiceTransformResponse {
                event_type: WebhookEventType::WebhookDispute.into(),
                content: Some(content),
                source_verified,
                response_ref_id: None,
            };

            Ok(tonic::Response::new(response))
        })
        .await
    }
}

async fn get_disputes_webhook_content(
    connector_data: ConnectorData,
    request_details: domain_types::connector_types::RequestDetails,
    webhook_secrets: Option<domain_types::connector_types::ConnectorWebhookSecrets>,
    connector_auth_details: Option<ConnectorAuthType>,
) -> CustomResult<WebhookResponseContent, ApplicationErrorResponse> {
    let webhook_details = connector_data
        .connector
        .process_dispute_webhook(request_details, webhook_secrets, connector_auth_details)
        .switch()?;

    // Generate response
    let response = DisputeResponse::foreign_try_from(webhook_details).change_context(
        ApplicationErrorResponse::InternalServerError(ApiError {
            sub_code: "RESPONSE_CONSTRUCTION_ERROR".to_string(),
            error_identifier: 500,
            error_message: "Error while constructing response".to_string(),
            error_object: None,
        }),
    )?;

    Ok(WebhookResponseContent {
        content: Some(
            grpc_api_types::payments::webhook_response_content::Content::DisputesResponse(response),
        ),
    })
}
