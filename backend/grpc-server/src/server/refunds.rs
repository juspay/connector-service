use std::{fmt::Debug, sync::Arc};

use common_enums;
use common_utils::errors::CustomResult;
use connector_integration::types::ConnectorData;
use domain_types::{
    connector_flow::{FlowName as DomainFlowName, RSync},
    connector_types::{
        AccessTokenResponseData, RefundFlowData, RefundSyncData, RefundsResponseData,
    },
    errors::{ApiError, ApplicationErrorResponse},
    payment_method_data::DefaultPCIHolder,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    utils::ForeignTryFrom,
};
use error_stack::ResultExt;
use external_services::{self, service::EventProcessingParams};
use grpc_api_types::payments::{
    refund_service_server::RefundService, RefundResponse, RefundServiceGetRequest,
    RefundServiceTransformRequest, RefundServiceTransformResponse, WebhookEventType,
    WebhookResponseContent,
};
use interfaces::connector_integration_v2::BoxedConnectorIntegrationV2;

use crate::{
    configs::Config,
    error::{IntoGrpcStatus, ReportSwitchExt, ResultExtGrpc},
    request::RequestData,
    utils,
};
// Helper trait for refund operations
trait RefundOperationsInternal {
    async fn internal_get(
        &self,
        request: RequestData<RefundServiceGetRequest>,
    ) -> Result<tonic::Response<RefundResponse>, tonic::Status>;
}

#[derive(Debug)]
pub struct Refunds {
    pub config: Arc<Config>,
}

impl RefundOperationsInternal for Refunds {
    async fn internal_get(
        &self,
        request: RequestData<RefundServiceGetRequest>,
    ) -> Result<tonic::Response<RefundResponse>, tonic::Status> {
        tracing::info!("REFUND_SYNC_FLOW: initiated");

        let service_name = request
            .extensions
            .get::<String>()
            .cloned()
            .unwrap_or_else(|| "unknown_service".to_string());

        let RequestData {
            payload,
            extracted_metadata: metadata_payload,
            masked_metadata,
            extensions: _,
        } = request;

        let (connector, request_id, connector_auth_details) = (
            metadata_payload.connector,
            &metadata_payload.request_id,
            metadata_payload.connector_auth_type.clone(),
        );

        // Get connector data
        let connector_data: ConnectorData<DefaultPCIHolder> =
            ConnectorData::get_connector_by_name(&connector);

        // Get connector integration
        let connector_integration: BoxedConnectorIntegrationV2<
            '_,
            RSync,
            RefundFlowData,
            RefundSyncData,
            RefundsResponseData,
        > = connector_data.connector.get_connector_integration_v2();

        // Create common request data
        let mut refund_flow_data = RefundFlowData::foreign_try_from((
            payload.clone(),
            self.config.connectors.clone(),
            &masked_metadata,
        ))
        .into_grpc_status()?;

        let lineage_ids = &metadata_payload.lineage_ids;
        let reference_id = &metadata_payload.reference_id;

        // Extract access token from Hyperswitch request
        let cached_access_token = payload
            .state
            .as_ref()
            .and_then(|state| state.access_token.as_ref())
            .map(|access| (access.token.clone(), access.expires_in_seconds));

        // Check if connector supports access tokens
        let should_do_access_token = connector_data.connector.should_do_access_token();

        // For refund flows, OAuth tokens must be provided in request.state by Hyperswitch
        if should_do_access_token {
            let access_token_data = match cached_access_token {
                Some((token, expires_in)) => {
                    // Use cached token
                    tracing::info!("Using cached access token from Hyperswitch");
                    Some(AccessTokenResponseData {
                        access_token: token,
                        token_type: None,
                        expires_in,
                    })
                }
                None => {
                    // OAuth tokens must be provided for refund flows
                    tracing::error!("OAuth access token required but not provided in request state");
                    return Err(tonic::Status::internal(
                        "OAuth access token required but not provided for refund operation",
                    ));
                }
            };

            // Store in flow data for connector API calls
            refund_flow_data = refund_flow_data.set_access_token(access_token_data);
        }

        // Create connector request data
        let refund_sync_data =
            RefundSyncData::foreign_try_from(payload.clone()).into_grpc_status()?;

        // Construct router data
        let router_data = RouterDataV2::<RSync, RefundFlowData, RefundSyncData, RefundsResponseData> {
            flow: std::marker::PhantomData,
            resource_common_data: refund_flow_data,
            connector_auth_type: connector_auth_details,
            request: refund_sync_data,
            response: Err(ErrorResponse::default()),
        };

        // Execute connector processing
        let event_params = EventProcessingParams {
            connector_name: &connector.to_string(),
            service_name: &service_name,
            flow_name: common_utils::events::FlowName::Rsync,
            event_config: &self.config.events,
            request_id,
            lineage_ids,
            reference_id,
            shadow_mode: metadata_payload.shadow_mode,
        };

        let response_result = external_services::service::execute_connector_processing_step(
            &self.config.proxy,
            connector_integration,
            router_data,
            None,
            event_params,
            None,
            common_enums::CallConnectorAction::Trigger,
        )
        .await
        .switch()
        .into_grpc_status()?;

        // Generate response
        let final_response =
            domain_types::types::generate_refund_sync_response(response_result)
                .into_grpc_status()?;

        Ok(tonic::Response::new(final_response))
    }
}

#[tonic::async_trait]
impl RefundService for Refunds {
    #[tracing::instrument(
        name = "refunds_sync",
        fields(
            name = common_utils::consts::NAME,
            service_name = tracing::field::Empty,
            service_method = DomainFlowName::Rsync.to_string(),
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
            flow = DomainFlowName::Rsync.to_string(),
            flow_specific_fields.status = tracing::field::Empty,
        )
        skip(self, request)
    )]
    async fn get(
        &self,
        request: tonic::Request<RefundServiceGetRequest>,
    ) -> Result<tonic::Response<RefundResponse>, tonic::Status> {
        let service_name = request
            .extensions()
            .get::<String>()
            .cloned()
            .unwrap_or_else(|| "RefundService".to_string());
        utils::grpc_logging_wrapper(
            request,
            &service_name,
            self.config.clone(),
            common_utils::events::FlowName::Rsync,
            |request_data| async move { self.internal_get(request_data).await },
        )
        .await
    }

    #[tracing::instrument(
        name = "refunds_transform",
        fields(
            name = common_utils::consts::NAME,
            service_name = tracing::field::Empty,
            service_method = DomainFlowName::IncomingWebhook.to_string(),
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
            flow = DomainFlowName::IncomingWebhook.to_string(),
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
            .unwrap_or_else(|| "RefundService".to_string());
        utils::grpc_logging_wrapper(
            request,
            &service_name,
            self.config.clone(),
            common_utils::events::FlowName::IncomingWebhook,
            |request_data| async move {
                let payload = request_data.payload;
                let connector = request_data.extracted_metadata.connector;
                let connector_auth_details = request_data.extracted_metadata.connector_auth_type;

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
                    event_type: WebhookEventType::WebhookRefundSuccess.into(),
                    content: Some(content),
                    source_verified,
                    response_ref_id: None,
                };

                Ok(tonic::Response::new(response))
            },
        )
        .await
    }
}

async fn get_refunds_webhook_content(
    connector_data: ConnectorData<DefaultPCIHolder>,
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
