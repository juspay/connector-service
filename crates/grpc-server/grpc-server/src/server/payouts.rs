use common_utils::events::FlowName;
use connector_integration::types::ConnectorData;
use domain_types::{
    connector_flow::PayoutCreate,
    payouts::payouts_types::{PayoutCreateRequest, PayoutCreateResponse, PayoutFlowData},
    types::generate_payout_create_response,
    utils::ForeignTryFrom,
};
use grpc_api_types::payouts::{
    payout_service_server::PayoutService, PayoutServiceCreateLinkRequest,
    PayoutServiceCreateLinkResponse, PayoutServiceCreateRecipientRequest,
    PayoutServiceCreateRecipientResponse, PayoutServiceCreateRequest, PayoutServiceCreateResponse,
    PayoutServiceEnrollDisburseAccountRequest, PayoutServiceEnrollDisburseAccountResponse,
    PayoutServiceGetRequest, PayoutServiceGetResponse, PayoutServiceStageRequest,
    PayoutServiceStageResponse, PayoutServiceTransferRequest, PayoutServiceTransferResponse,
    PayoutServiceVoidRequest, PayoutServiceVoidResponse,
};
use ucs_env::error::{ReportSwitchExt, ResultExtGrpc};

use crate::{
    implement_connector_operation,
    request::RequestData,
    utils::{get_config_from_request, grpc_logging_wrapper},
};

pub struct Payouts;

#[tonic::async_trait]
impl PayoutService for Payouts {
    async fn create(
        &self,
        request: tonic::Request<PayoutServiceCreateRequest>,
    ) -> Result<tonic::Response<PayoutServiceCreateResponse>, tonic::Status> {
        let config = get_config_from_request(&request)?;
        grpc_logging_wrapper(
            request,
            "PAYOUT_CREATE",
            config,
            FlowName::PayoutCreate,
            |request_data| self.internal_payout_create(request_data),
        )
        .await
    }

    async fn transfer(
        &self,
        _request: tonic::Request<PayoutServiceTransferRequest>,
    ) -> Result<tonic::Response<PayoutServiceTransferResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("transfer is not implemented"))
    }

    async fn get(
        &self,
        _request: tonic::Request<PayoutServiceGetRequest>,
    ) -> Result<tonic::Response<PayoutServiceGetResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("get is not implemented"))
    }

    async fn void(
        &self,
        _request: tonic::Request<PayoutServiceVoidRequest>,
    ) -> Result<tonic::Response<PayoutServiceVoidResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("void is not implemented"))
    }

    async fn stage(
        &self,
        _request: tonic::Request<PayoutServiceStageRequest>,
    ) -> Result<tonic::Response<PayoutServiceStageResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("stage is not implemented"))
    }

    async fn create_link(
        &self,
        _request: tonic::Request<PayoutServiceCreateLinkRequest>,
    ) -> Result<tonic::Response<PayoutServiceCreateLinkResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented(
            "create_link is not implemented",
        ))
    }

    async fn create_recipient(
        &self,
        _request: tonic::Request<PayoutServiceCreateRecipientRequest>,
    ) -> Result<tonic::Response<PayoutServiceCreateRecipientResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented(
            "create_recipient is not implemented",
        ))
    }

    async fn enroll_disburse_account(
        &self,
        _request: tonic::Request<PayoutServiceEnrollDisburseAccountRequest>,
    ) -> Result<tonic::Response<PayoutServiceEnrollDisburseAccountResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented(
            "enroll_disburse_account is not implemented",
        ))
    }
}

pub(crate) trait PayoutOperationsInternal {
    fn internal_payout_create(
        &self,
        request: RequestData<PayoutServiceCreateRequest>,
    ) -> impl std::future::Future<
        Output = Result<tonic::Response<PayoutServiceCreateResponse>, tonic::Status>,
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
}
