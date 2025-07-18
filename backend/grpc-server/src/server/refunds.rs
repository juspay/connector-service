use std::sync::Arc;

use common_utils::errors::CustomResult;
use connector_integration::types::ConnectorData;
use domain_types::{
    connector_flow::{FlowName, RSync},
    connector_types::{RefundFlowData, RefundSyncData, RefundsResponseData},
    errors::{ApiError, ApplicationErrorResponse},
    router_data::ConnectorAuthType,
    types::generate_refund_sync_response,
    utils::ForeignTryFrom,
};
use error_stack::ResultExt;
use external_services;
use grpc_api_types::payments::{
    refund_service_server::RefundService, RefundResponse, RefundServiceGetRequest,
    RefundServiceTransformRequest, RefundServiceTransformResponse, WebhookEventType,
    WebhookResponseContent,
};

use crate::{
    configs::Config,
    error::{IntoGrpcStatus, ReportSwitchExt, ResultExtGrpc},
    implement_connector_operation,
    utils::{auth_from_metadata, connector_from_metadata, grpc_logging_wrapper},
};
// Helper trait for refund operations
trait RefundOperationsInternal {
    async fn internal_get(
        &self,
        request: tonic::Request<RefundServiceGetRequest>,
    ) -> Result<tonic::Response<RefundResponse>, tonic::Status>;
}

#[derive(Debug)]
pub struct Refunds {
    pub config: Arc<Config>,
}

impl RefundOperationsInternal for Refunds {
    implement_connector_operation!(
        fn_name: internal_get,
        log_prefix: "REFUND_SYNC",
        request_type: RefundServiceGetRequest,
        response_type: RefundResponse,
        flow_marker: RSync,
        resource_common_data_type: RefundFlowData,
        request_data_type: RefundSyncData,
        response_data_type: RefundsResponseData,
        request_data_constructor: RefundSyncData::foreign_try_from,
        common_flow_data_constructor: RefundFlowData::foreign_try_from,
        generate_response_fn: generate_refund_sync_response,
        all_keys_required: None
    );
}

#[tonic::async_trait]
impl RefundService for Refunds {
    #[tracing::instrument(
        name = "refunds_sync",
        fields(
            name = common_utils::consts::NAME,
            service_name = tracing::field::Empty,
            service_method = FlowName::Rsync.to_string(),
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
            flow = FlowName::Rsync.to_string(),
            flow_specific_fields.status = tracing::field::Empty,
        )
        skip(self, request)
    )]
    async fn get(
        &self,
        request: tonic::Request<RefundServiceGetRequest>,
    ) -> Result<tonic::Response<RefundResponse>, tonic::Status> {
        self.internal_get(request).await
    }

    #[tracing::instrument(
        name = "refunds_transform",
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
        )
    )]
    async fn transform(
        &self,
        request: tonic::Request<RefundServiceTransformRequest>,
    ) -> Result<tonic::Response<RefundServiceTransformResponse>, tonic::Status> {
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

            let content = get_refunds_webhook_content(
                connector_data,
                request_details,
                webhook_secrets,
                Some(connector_auth_details),
            )
            .await
            .map_err(|e| e.into_grpc_status())?;

            let response = RefundServiceTransformResponse {
                event_type: WebhookEventType::WebhookRefund.into(),
                content: Some(content),
                source_verified,
                response_ref_id: None,
            };

            Ok(tonic::Response::new(response))
        })
        .await
    }
}

async fn get_refunds_webhook_content(
    connector_data: ConnectorData,
    request_details: domain_types::connector_types::RequestDetails,
    webhook_secrets: Option<domain_types::connector_types::ConnectorWebhookSecrets>,
    connector_auth_details: Option<ConnectorAuthType>,
) -> CustomResult<WebhookResponseContent, ApplicationErrorResponse> {
    let webhook_details = connector_data
        .connector
        .process_refund_webhook(request_details, webhook_secrets, connector_auth_details)
        .switch()?;

    // Generate response
    let response = RefundResponse::foreign_try_from(webhook_details).change_context(
        ApplicationErrorResponse::InternalServerError(ApiError {
            sub_code: "RESPONSE_CONSTRUCTION_ERROR".to_string(),
            error_identifier: 500,
            error_message: "Error while constructing response".to_string(),
            error_object: None,
        }),
    )?;

    Ok(WebhookResponseContent {
        content: Some(
            grpc_api_types::payments::webhook_response_content::Content::RefundsResponse(response),
        ),
    })
}
