use common_utils::events::FlowName;
use connector_integration::types::ConnectorData;
use domain_types::{
    connector_flow::VerifyTopupWebhook, connector_types::VerifyTopupWebhookFlowData,
    payment_method_data::DefaultPCIHolder, router_data::ErrorResponse,
    router_data_v2::RouterDataV2, router_request_types::VerifyTopupWebhookData,
    router_response_types::VerifyTopupWebhookResponseData,
    types::generate_verify_topup_webhook_response, utils::ForeignTryFrom,
};
use external_services::service::EventProcessingParams;
use grpc_api_types::payments::{
    wallet_service_server::WalletService, WalletServiceVerifyTopupWebhookRequest,
    WalletServiceVerifyTopupWebhookResponse,
};
use interfaces::connector_integration_v2::BoxedConnectorIntegrationV2;
use ucs_env::error::{IntoGrpcStatus, ReportSwitchExt, ResultExtGrpc};

use crate::utils::{self, get_config_from_request, grpc_logging_wrapper};

pub struct Wallet;

#[tonic::async_trait]
impl WalletService for Wallet {
    async fn verify_topup_webhook(
        &self,
        request: tonic::Request<WalletServiceVerifyTopupWebhookRequest>,
    ) -> Result<tonic::Response<WalletServiceVerifyTopupWebhookResponse>, tonic::Status> {
        let config = get_config_from_request(&request)?;
        let service_name = request
            .extensions()
            .get::<String>()
            .cloned()
            .unwrap_or_else(|| "WalletService".to_string());
        grpc_logging_wrapper(
            request,
            &service_name,
            config.clone(),
            FlowName::VerifyTopupWebhook,
            |request_data| {
                let config = config.clone();
                let service_name = service_name.clone();
                async move {
                    let payload = request_data.payload;
                    let metadata_payload = request_data.extracted_metadata;
                    let masked_metadata = request_data.masked_metadata;
                    let connector = metadata_payload.connector;
                    let connector_config = metadata_payload.connector_config;

                    let connector_data: ConnectorData<DefaultPCIHolder> =
                        ConnectorData::get_connector_by_name(&connector);

                    let connectors = utils::get_resolved_connectors(
                        &config,
                        &connector,
                        &connector_config,
                        metadata_payload.environment.as_deref(),
                    )
                    .map_err(|e| error_stack::Report::new(e).into_grpc_status())?;

                    let request_data_domain =
                        VerifyTopupWebhookData::foreign_try_from(payload.clone())
                            .into_grpc_status()?;

                    let flow_data = VerifyTopupWebhookFlowData::foreign_try_from((
                        payload,
                        connectors,
                        &masked_metadata,
                    ))
                    .into_grpc_status()?;

                    let router_data = RouterDataV2::<
                        VerifyTopupWebhook,
                        VerifyTopupWebhookFlowData,
                        VerifyTopupWebhookData,
                        VerifyTopupWebhookResponseData,
                    > {
                        flow: std::marker::PhantomData,
                        resource_common_data: flow_data,
                        connector_config,
                        request: request_data_domain,
                        response: Err(ErrorResponse::default()),
                    };

                    let connector_integration: BoxedConnectorIntegrationV2<
                        '_,
                        VerifyTopupWebhook,
                        VerifyTopupWebhookFlowData,
                        VerifyTopupWebhookData,
                        VerifyTopupWebhookResponseData,
                    > = connector_data.connector.get_connector_integration_v2();

                    let flow_name = utils::flow_marker_to_flow_name::<VerifyTopupWebhook>();

                    let event_params = EventProcessingParams {
                        connector_name: &connector.to_string(),
                        service_name: &service_name,
                        service_type: utils::service_type_str(&config.server.type_),
                        flow_name,
                        event_config: &config.events,
                        request_id: &metadata_payload.request_id,
                        lineage_ids: &metadata_payload.lineage_ids,
                        reference_id: &metadata_payload.reference_id,
                        resource_id: &metadata_payload.resource_id,
                        shadow_mode: metadata_payload.shadow_mode,
                    };

                    // For in-memory verification, use HandleResponse with empty body
                    // This calls the connector's handle_response_v2 without making an HTTP call
                    let response_result = Box::pin(
                        external_services::service::execute_connector_processing_step(
                            &config.proxy,
                            connector_integration,
                            router_data,
                            None,
                            event_params,
                            None,
                            common_enums::CallConnectorAction::HandleResponse(b"{}".to_vec()),
                            None,
                            None,
                        ),
                    )
                    .await
                    .switch()
                    .into_grpc_status()?;

                    let final_response = generate_verify_topup_webhook_response(response_result)
                        .into_grpc_status()?;

                    Ok(tonic::Response::new(final_response))
                }
            },
        )
        .await
    }
}
