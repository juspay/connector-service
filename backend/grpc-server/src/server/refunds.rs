use crate::implement_connector_operation;
use crate::{
    configs::Config,
    error::{IntoGrpcStatus, ReportSwitchExt, ResultExtGrpc},
    utils::{auth_from_metadata, connector_from_metadata},
};
use common_utils::errors::CustomResult;
use connector_integration::types::ConnectorData;
use domain_types::router_data::ConnectorAuthType;
use domain_types::{
    connector_flow::RSync,
    connector_types::{RefundFlowData, RefundSyncData, RefundsResponseData},
    errors::{ApiError, ApplicationErrorResponse},
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

// Helper trait for refund operations
trait RefundOperationsInternal {
    async fn internal_get(
        &self,
        request: tonic::Request<RefundServiceGetRequest>,
    ) -> Result<tonic::Response<RefundResponse>, tonic::Status>;
}

pub struct Refunds {
    pub config: Config,
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
    async fn get(
        &self,
        request: tonic::Request<RefundServiceGetRequest>,
    ) -> Result<tonic::Response<RefundResponse>, tonic::Status> {
        self.internal_get(request).await
    }

    async fn transform(
        &self,
        request: tonic::Request<RefundServiceTransformRequest>,
    ) -> Result<tonic::Response<RefundServiceTransformResponse>, tonic::Status> {
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
