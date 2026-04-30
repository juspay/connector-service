use common_utils::events::FlowName;
use common_utils::lineage::LineageIds;
use connector_integration::types::ConnectorData;
use domain_types::{
    connector_flow::{
        PayoutCreate, PayoutCreateLink, PayoutCreateRecipient, PayoutEnrollDisburseAccount,
        PayoutGet, PayoutStage, PayoutTransfer, PayoutVoid, ServerAuthenticationToken,
    },
    connector_types::{
        ConnectorEnum, PaymentFlowData, ServerAuthenticationTokenRequestData,
        ServerAuthenticationTokenResponseData,
    },
    payouts::payouts_types::{
        PayoutCreateLinkRequest, PayoutCreateLinkResponse, PayoutCreateRecipientRequest,
        PayoutCreateRecipientResponse, PayoutCreateRequest, PayoutCreateResponse,
        PayoutEnrollDisburseAccountRequest, PayoutEnrollDisburseAccountResponse, PayoutFlowData,
        PayoutGetRequest, PayoutGetResponse, PayoutStageRequest, PayoutStageResponse,
        PayoutTransferRequest, PayoutTransferResponse, PayoutVoidRequest, PayoutVoidResponse,
    },
    payouts::types::{
        generate_payout_create_link_response, generate_payout_create_recipient_response,
        generate_payout_create_response, generate_payout_enroll_disburse_account_response,
        generate_payout_get_response, generate_payout_stage_response,
        generate_payout_transfer_response, generate_payout_void_response,
    },
    router_data::{ConnectorSpecificConfig, ErrorResponse},
    router_data_v2::RouterDataV2,
    utils::ForeignTryFrom,
};
use external_services::service::EventProcessingParams;
use interfaces::connector_integration_v2::BoxedConnectorIntegrationV2;
use grpc_api_types::payouts::{
    payout_service_server::PayoutService, PayoutServiceCreateLinkRequest,
    PayoutServiceCreateLinkResponse, PayoutServiceCreateRecipientRequest,
    PayoutServiceCreateRecipientResponse, PayoutServiceCreateRequest, PayoutServiceCreateResponse,
    PayoutServiceEnrollDisburseAccountRequest, PayoutServiceEnrollDisburseAccountResponse,
    PayoutServiceGetRequest, PayoutServiceGetResponse, PayoutServiceStageRequest,
    PayoutServiceStageResponse, PayoutServiceTransferRequest, PayoutServiceTransferResponse,
    PayoutServiceVoidRequest, PayoutServiceVoidResponse,
};
use ucs_env::error::ResultExtGrpc;

use crate::{
    implement_connector_operation,
    request::RequestData,
    utils::{get_config_from_request, grpc_logging_wrapper},
};

async fn fetch_oauth_access_token(
    connector: &ConnectorEnum,
    connector_config: &ConnectorSpecificConfig,
    config: &std::sync::Arc<ucs_env::configs::Config>,
    masked_metadata: &common_utils::metadata::MaskedMetadata,
    service_name: &str,
    log_prefix: &str,
) -> Result<Option<ServerAuthenticationTokenResponseData>, tonic::Status> {
    let connector_data: ConnectorData<
        domain_types::payment_method_data::DefaultPCIHolder,
    > = ConnectorData::get_connector_by_name(connector);

    let should_do_access_token = connector_data.connector.should_do_access_token(None);

    if !should_do_access_token {
        return Ok(None);
    }

    tracing::info!("{}: Fetching OAuth access token...", log_prefix);
    let connectors = crate::utils::connectors_with_connector_config_overrides(
        connector_config,
        config,
    )
    .into_grpc_status()?;

    let auth_flow_data = PaymentFlowData::foreign_try_from((connectors, masked_metadata))
        .into_grpc_status()?;

    let access_token_request_data =
        ServerAuthenticationTokenRequestData::foreign_try_from(connector_config)
            .into_grpc_status()?;

    let connector_integration: BoxedConnectorIntegrationV2<
        '_,
        ServerAuthenticationToken,
        PaymentFlowData,
        ServerAuthenticationTokenRequestData,
        ServerAuthenticationTokenResponseData,
    > = connector_data.connector.get_connector_integration_v2();

    let access_token_router_data = RouterDataV2::<
        ServerAuthenticationToken,
        PaymentFlowData,
        ServerAuthenticationTokenRequestData,
        ServerAuthenticationTokenResponseData,
    > {
        flow: std::marker::PhantomData,
        resource_common_data: auth_flow_data,
        connector_config: connector_config.clone(),
        request: access_token_request_data,
        response: Err(ErrorResponse::default()),
    };

    let event_params = EventProcessingParams {
        connector_name: &connector.to_string(),
        service_name,
        service_type: crate::utils::service_type_str(&config.server.type_),
        flow_name: FlowName::ServerAuthenticationToken,
        event_config: &config.events,
        request_id: &format!("{}_token", log_prefix),
        lineage_ids: &LineageIds::empty(""),
        reference_id: &None,
        resource_id: &None,
        shadow_mode: false,
        tenant_id: "default",
    };

    let access_token_result = external_services::service::execute_connector_processing_step(
        &config.proxy,
        connector_integration,
        access_token_router_data,
        None,
        event_params,
        None,
        common_enums::CallConnectorAction::Trigger,
        None,
        None,
    )
    .await;

    match access_token_result {
        Ok(result) => match result.response {
            Ok(token_response) => Ok(Some(token_response)),
            Err(err) => {
                tracing::error!(
                    error = ?err,
                    flow = log_prefix,
                    stage = "access_token_fetch",
                    "Access token fetch failed"
                );
                Err(tonic::Status::internal(format!(
                    "Access token fetch failed: {}",
                    err.message
                )))
            }
        },
        Err(err) => {
            tracing::error!(
                error = ?err,
                flow = log_prefix,
                stage = "access_token_execution",
                "Access token execution failed"
            );
            Err(tonic::Status::internal(format!(
                "Access token execution failed: {}",
                err
            )))
        }
    }
}

pub struct Payouts;

#[tonic::async_trait]
impl PayoutService for Payouts {
    async fn create(
        &self,
        request: tonic::Request<PayoutServiceCreateRequest>,
    ) -> Result<tonic::Response<PayoutServiceCreateResponse>, tonic::Status> {
        let config = get_config_from_request(&request)?;
        let service_name = request
            .extensions()
            .get::<String>()
            .cloned()
            .unwrap_or_else(|| "PayoutService".to_string());
        grpc_logging_wrapper(
            request,
            &service_name,
            config,
            FlowName::PayoutCreate,
            |request_data| self.internal_payout_create(request_data),
        )
        .await
    }

    async fn transfer(
        &self,
        mut request: tonic::Request<PayoutServiceTransferRequest>,
    ) -> Result<tonic::Response<PayoutServiceTransferResponse>, tonic::Status> {
        let config = get_config_from_request(&request)?;
        let service_name = request
            .extensions()
            .get::<String>()
            .cloned()
            .unwrap_or_else(|| "PayoutService".to_string());

        let metadata_payload = crate::utils::extract_metadata_from_request(&request)?;

        let access_token = fetch_oauth_access_token(
            &metadata_payload.connector,
            &metadata_payload.connector_config,
            &config,
            &metadata_payload.masked_metadata,
            &service_name,
            "PAYOUT_TRANSFER",
        )
        .await?;

        if let Some(token) = access_token {
            request.get_mut().access_token = Some(token.access_token);
        }

        grpc_logging_wrapper(
            request,
            &service_name,
            config,
            FlowName::PayoutTransfer,
            |request_data| self.internal_payout_transfer(request_data),
        )
        .await
    }

    async fn get(
        &self,
        mut request: tonic::Request<PayoutServiceGetRequest>,
    ) -> Result<tonic::Response<PayoutServiceGetResponse>, tonic::Status> {
        let config = get_config_from_request(&request)?;
        let service_name = request
            .extensions()
            .get::<String>()
            .cloned()
            .unwrap_or_else(|| "PayoutService".to_string());

        let metadata_payload = crate::utils::extract_metadata_from_request(&request)?;

        let access_token = fetch_oauth_access_token(
            &metadata_payload.connector,
            &metadata_payload.connector_config,
            &config,
            &metadata_payload.masked_metadata,
            &service_name,
            "PAYOUT_GET",
        )
        .await?;

        if let Some(token) = access_token {
            request.get_mut().access_token = Some(token.access_token);
        }

        grpc_logging_wrapper(
            request,
            &service_name,
            config,
            FlowName::PayoutGet,
            |request_data| self.internal_payout_get(request_data),
        )
        .await
    }

    async fn void(
        &self,
        request: tonic::Request<PayoutServiceVoidRequest>,
    ) -> Result<tonic::Response<PayoutServiceVoidResponse>, tonic::Status> {
        let config = get_config_from_request(&request)?;
        let service_name = request
            .extensions()
            .get::<String>()
            .cloned()
            .unwrap_or_else(|| "PayoutService".to_string());
        grpc_logging_wrapper(
            request,
            &service_name,
            config,
            FlowName::PayoutVoid,
            |request_data| self.internal_payout_void(request_data),
        )
        .await
    }

    async fn stage(
        &self,
        request: tonic::Request<PayoutServiceStageRequest>,
    ) -> Result<tonic::Response<PayoutServiceStageResponse>, tonic::Status> {
        let config = get_config_from_request(&request)?;
        let service_name = request
            .extensions()
            .get::<String>()
            .cloned()
            .unwrap_or_else(|| "PayoutService".to_string());
        grpc_logging_wrapper(
            request,
            &service_name,
            config,
            FlowName::PayoutStage,
            |request_data| self.internal_payout_stage(request_data),
        )
        .await
    }

    async fn create_link(
        &self,
        request: tonic::Request<PayoutServiceCreateLinkRequest>,
    ) -> Result<tonic::Response<PayoutServiceCreateLinkResponse>, tonic::Status> {
        let config = get_config_from_request(&request)?;
        let service_name = request
            .extensions()
            .get::<String>()
            .cloned()
            .unwrap_or_else(|| "PayoutService".to_string());
        grpc_logging_wrapper(
            request,
            &service_name,
            config,
            FlowName::PayoutCreateLink,
            |request_data| self.internal_payout_create_link(request_data),
        )
        .await
    }

    async fn create_recipient(
        &self,
        request: tonic::Request<PayoutServiceCreateRecipientRequest>,
    ) -> Result<tonic::Response<PayoutServiceCreateRecipientResponse>, tonic::Status> {
        let config = get_config_from_request(&request)?;
        let service_name = request
            .extensions()
            .get::<String>()
            .cloned()
            .unwrap_or_else(|| "PayoutService".to_string());
        grpc_logging_wrapper(
            request,
            &service_name,
            config,
            FlowName::PayoutCreateRecipient,
            |request_data| self.internal_payout_create_recipient(request_data),
        )
        .await
    }

    async fn enroll_disburse_account(
        &self,
        request: tonic::Request<PayoutServiceEnrollDisburseAccountRequest>,
    ) -> Result<tonic::Response<PayoutServiceEnrollDisburseAccountResponse>, tonic::Status> {
        let config = get_config_from_request(&request)?;
        let service_name = request
            .extensions()
            .get::<String>()
            .cloned()
            .unwrap_or_else(|| "PayoutService".to_string());
        grpc_logging_wrapper(
            request,
            &service_name,
            config,
            FlowName::PayoutEnrollDisburseAccount,
            |request_data| self.internal_payout_enroll_disburse_account(request_data),
        )
        .await
    }
}

pub(crate) trait PayoutOperationsInternal {
    fn internal_payout_create(
        &self,
        request: RequestData<PayoutServiceCreateRequest>,
    ) -> impl std::future::Future<
        Output = Result<tonic::Response<PayoutServiceCreateResponse>, tonic::Status>,
    > + Send;

    fn internal_payout_transfer(
        &self,
        request: RequestData<PayoutServiceTransferRequest>,
    ) -> impl std::future::Future<
        Output = Result<tonic::Response<PayoutServiceTransferResponse>, tonic::Status>,
    > + Send;

    fn internal_payout_get(
        &self,
        request: RequestData<PayoutServiceGetRequest>,
    ) -> impl std::future::Future<
        Output = Result<tonic::Response<PayoutServiceGetResponse>, tonic::Status>,
    > + Send;

    fn internal_payout_void(
        &self,
        request: RequestData<PayoutServiceVoidRequest>,
    ) -> impl std::future::Future<
        Output = Result<tonic::Response<PayoutServiceVoidResponse>, tonic::Status>,
    > + Send;

    fn internal_payout_stage(
        &self,
        request: RequestData<PayoutServiceStageRequest>,
    ) -> impl std::future::Future<
        Output = Result<tonic::Response<PayoutServiceStageResponse>, tonic::Status>,
    > + Send;

    fn internal_payout_create_link(
        &self,
        request: RequestData<PayoutServiceCreateLinkRequest>,
    ) -> impl std::future::Future<
        Output = Result<tonic::Response<PayoutServiceCreateLinkResponse>, tonic::Status>,
    > + Send;

    fn internal_payout_create_recipient(
        &self,
        request: RequestData<PayoutServiceCreateRecipientRequest>,
    ) -> impl std::future::Future<
        Output = Result<tonic::Response<PayoutServiceCreateRecipientResponse>, tonic::Status>,
    > + Send;

    fn internal_payout_enroll_disburse_account(
        &self,
        request: RequestData<PayoutServiceEnrollDisburseAccountRequest>,
    ) -> impl std::future::Future<
        Output = Result<tonic::Response<PayoutServiceEnrollDisburseAccountResponse>, tonic::Status>,
    > + Send;
}

impl PayoutOperationsInternal for Payouts {
    implement_connector_operation!(
        fn_name: internal_payout_create,
        log_prefix: "PAYOUT_CREATE",
        request_type: PayoutServiceCreateRequest,
        response_type: PayoutServiceCreateResponse,
        flow_marker: PayoutCreate,
        resource_common_data_type: PayoutFlowData,
        request_data_type: PayoutCreateRequest,
        response_data_type: PayoutCreateResponse,
        request_data_constructor: PayoutCreateRequest::foreign_try_from,
        common_flow_data_constructor: PayoutFlowData::foreign_try_from,
        generate_response_fn: generate_payout_create_response,
        all_keys_required: None
    );

    implement_connector_operation!(
        fn_name: internal_payout_transfer,
        log_prefix: "PAYOUT_TRANSFER",
        request_type: PayoutServiceTransferRequest,
        response_type: PayoutServiceTransferResponse,
        flow_marker: PayoutTransfer,
        resource_common_data_type: PayoutFlowData,
        request_data_type: PayoutTransferRequest,
        response_data_type: PayoutTransferResponse,
        request_data_constructor: PayoutTransferRequest::foreign_try_from,
        common_flow_data_constructor: PayoutFlowData::foreign_try_from,
        generate_response_fn: generate_payout_transfer_response,
        all_keys_required: None
    );

    implement_connector_operation!(
        fn_name: internal_payout_get,
        log_prefix: "PAYOUT_GET",
        request_type: PayoutServiceGetRequest,
        response_type: PayoutServiceGetResponse,
        flow_marker: PayoutGet,
        resource_common_data_type: PayoutFlowData,
        request_data_type: PayoutGetRequest,
        response_data_type: PayoutGetResponse,
        request_data_constructor: PayoutGetRequest::foreign_try_from,
        common_flow_data_constructor: PayoutFlowData::foreign_try_from,
        generate_response_fn: generate_payout_get_response,
        all_keys_required: None
    );

    implement_connector_operation!(
        fn_name: internal_payout_void,
        log_prefix: "PAYOUT_VOID",
        request_type: PayoutServiceVoidRequest,
        response_type: PayoutServiceVoidResponse,
        flow_marker: PayoutVoid,
        resource_common_data_type: PayoutFlowData,
        request_data_type: PayoutVoidRequest,
        response_data_type: PayoutVoidResponse,
        request_data_constructor: PayoutVoidRequest::foreign_try_from,
        common_flow_data_constructor: PayoutFlowData::foreign_try_from,
        generate_response_fn: generate_payout_void_response,
        all_keys_required: None
    );

    implement_connector_operation!(
        fn_name: internal_payout_stage,
        log_prefix: "PAYOUT_STAGE",
        request_type: PayoutServiceStageRequest,
        response_type: PayoutServiceStageResponse,
        flow_marker: PayoutStage,
        resource_common_data_type: PayoutFlowData,
        request_data_type: PayoutStageRequest,
        response_data_type: PayoutStageResponse,
        request_data_constructor: PayoutStageRequest::foreign_try_from,
        common_flow_data_constructor: PayoutFlowData::foreign_try_from,
        generate_response_fn: generate_payout_stage_response,
        all_keys_required: None
    );

    implement_connector_operation!(
        fn_name: internal_payout_create_link,
        log_prefix: "PAYOUT_CREATE_LINK",
        request_type: PayoutServiceCreateLinkRequest,
        response_type: PayoutServiceCreateLinkResponse,
        flow_marker: PayoutCreateLink,
        resource_common_data_type: PayoutFlowData,
        request_data_type: PayoutCreateLinkRequest,
        response_data_type: PayoutCreateLinkResponse,
        request_data_constructor: PayoutCreateLinkRequest::foreign_try_from,
        common_flow_data_constructor: PayoutFlowData::foreign_try_from,
        generate_response_fn: generate_payout_create_link_response,
        all_keys_required: None
    );

    implement_connector_operation!(
        fn_name: internal_payout_create_recipient,
        log_prefix: "PAYOUT_CREATE_RECIPIENT",
        request_type: PayoutServiceCreateRecipientRequest,
        response_type: PayoutServiceCreateRecipientResponse,
        flow_marker: PayoutCreateRecipient,
        resource_common_data_type: PayoutFlowData,
        request_data_type: PayoutCreateRecipientRequest,
        response_data_type: PayoutCreateRecipientResponse,
        request_data_constructor: PayoutCreateRecipientRequest::foreign_try_from,
        common_flow_data_constructor: PayoutFlowData::foreign_try_from,
        generate_response_fn: generate_payout_create_recipient_response,
        all_keys_required: None
    );

    implement_connector_operation!(
        fn_name: internal_payout_enroll_disburse_account,
        log_prefix: "PAYOUT_ENROLL_DISBURSE_ACCOUNT",
        request_type: PayoutServiceEnrollDisburseAccountRequest,
        response_type: PayoutServiceEnrollDisburseAccountResponse,
        flow_marker: PayoutEnrollDisburseAccount,
        resource_common_data_type: PayoutFlowData,
        request_data_type: PayoutEnrollDisburseAccountRequest,
        response_data_type: PayoutEnrollDisburseAccountResponse,
        request_data_constructor: PayoutEnrollDisburseAccountRequest::foreign_try_from,
        common_flow_data_constructor: PayoutFlowData::foreign_try_from,
        generate_response_fn: generate_payout_enroll_disburse_account_response,
        all_keys_required: None
    );
}
