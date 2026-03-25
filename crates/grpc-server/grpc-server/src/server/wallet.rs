use common_utils::events::FlowName;
use connector_integration::types::ConnectorData;
use domain_types::{
    connector_flow::InitiateTopup,
    connector_types::{InitiateTopupData, InitiateTopupResponseData, WalletFlowData},
    types::generate_initiate_topup_response,
    utils::ForeignTryFrom,
};
use grpc_api_types::payments::{
    wallet_service_server::WalletService, WalletServiceInitiateTopupRequest,
    WalletServiceInitiateTopupResponse,
};
use ucs_env::error::{ReportSwitchExt, ResultExtGrpc};

use crate::{
    implement_connector_operation,
    request::RequestData,
    utils::{get_config_from_request, grpc_logging_wrapper},
};

#[derive(Clone)]
pub struct Wallet;

#[tonic::async_trait]
impl WalletService for Wallet {
    async fn initiate_topup(
        &self,
        request: tonic::Request<WalletServiceInitiateTopupRequest>,
    ) -> Result<tonic::Response<WalletServiceInitiateTopupResponse>, tonic::Status> {
        let config = get_config_from_request(&request)?;
        let service_name = request
            .extensions()
            .get::<String>()
            .cloned()
            .unwrap_or_else(|| "WalletService".to_string());
        grpc_logging_wrapper(
            request,
            &service_name,
            config,
            FlowName::InitiateTopup,
            |request_data| self.internal_initiate_topup(request_data),
        )
        .await
    }
}

pub(crate) trait WalletOperationsInternal {
    fn internal_initiate_topup(
        &self,
        request: RequestData<WalletServiceInitiateTopupRequest>,
    ) -> impl std::future::Future<
        Output = Result<tonic::Response<WalletServiceInitiateTopupResponse>, tonic::Status>,
    > + Send;
}

impl WalletOperationsInternal for Wallet {
    implement_connector_operation!(
        fn_name: internal_initiate_topup,
        log_prefix: "INITIATE_TOPUP",
        request_type: WalletServiceInitiateTopupRequest,
        response_type: WalletServiceInitiateTopupResponse,
        flow_marker: InitiateTopup,
        resource_common_data_type: WalletFlowData,
        request_data_type: InitiateTopupData,
        response_data_type: InitiateTopupResponseData,
        request_data_constructor: InitiateTopupData::foreign_try_from,
        common_flow_data_constructor: WalletFlowData::foreign_try_from,
        generate_response_fn: generate_initiate_topup_response,
        all_keys_required: None
    );
}
