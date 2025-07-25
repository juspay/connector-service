#[allow(unused_imports)]
use crate::connectors::macros::{
    Bridge, BridgeRequestResponse, FlowTypes, GetFormData, NoRequestBody, NoRequestBodyTemplating,
};
use std::marker::PhantomData;
#[allow(unused_imports)]
mod macro_types {
    pub(super) use crate::types::*;
    pub(super) use common_utils::{errors::CustomResult, request::RequestContent};
    pub(super) use domain_types::{
        errors::ConnectorError, router_data::ErrorResponse, router_data_v2::RouterDataV2,
        router_response_types::Response,
    };
    pub(super) use hyperswitch_masking::Maskable;
    pub(super) use interfaces::events::connector_api_logs::ConnectorEvent;
}
pub struct AdyenRouterData<
    RD: FlowTypes,
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static,
> {
    pub connector: Adyen<T>,
    pub router_data: RD,
}
impl<
        RD: FlowTypes,
        T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static,
    > FlowTypes for AdyenRouterData<RD, T>
{
    type Flow = RD::Flow;
    type FlowCommonData = RD::FlowCommonData;
    type Request = RD::Request;
    type Response = RD::Response;
}
pub struct AdyenPaymentRequestTemplating;

pub struct AdyenPaymentResponseTemplating;

impl<
        T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static,
    > BridgeRequestResponse
    for Bridge<AdyenPaymentRequestTemplating, AdyenPaymentResponseTemplating, T>
{
    type RequestBody = AdyenPaymentRequest;
    type ResponseBody = AdyenPaymentResponse;
    type ConnectorInputData = AdyenRouterData<
        RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        T,
    >;
}
pub struct AdyenRedirectRequestTemplating;

pub struct AdyenPSyncResponseTemplating;

impl<
        T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static,
    > BridgeRequestResponse
    for Bridge<AdyenRedirectRequestTemplating, AdyenPSyncResponseTemplating, T>
{
    type RequestBody = AdyenRedirectRequest;
    type ResponseBody = AdyenPSyncResponse;
    type ConnectorInputData = AdyenRouterData<
        RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        T,
    >;
}
pub struct AdyenCaptureRequestTemplating;

pub struct AdyenCaptureResponseTemplating;

impl<
        T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static,
    > BridgeRequestResponse
    for Bridge<AdyenCaptureRequestTemplating, AdyenCaptureResponseTemplating, T>
{
    type RequestBody = AdyenCaptureRequest;
    type ResponseBody = AdyenCaptureResponse;
    type ConnectorInputData = AdyenRouterData<
        RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        T,
    >;
}
pub struct AdyenVoidRequestTemplating;

pub struct AdyenVoidResponseTemplating;

impl<
        T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static,
    > BridgeRequestResponse for Bridge<AdyenVoidRequestTemplating, AdyenVoidResponseTemplating, T>
{
    type RequestBody = AdyenVoidRequest;
    type ResponseBody = AdyenVoidResponse;
    type ConnectorInputData = AdyenRouterData<
        RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        T,
    >;
}
pub struct AdyenRefundRequestTemplating;

pub struct AdyenRefundResponseTemplating;

impl<
        T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static,
    > BridgeRequestResponse
    for Bridge<AdyenRefundRequestTemplating, AdyenRefundResponseTemplating, T>
{
    type RequestBody = AdyenRefundRequest;
    type ResponseBody = AdyenRefundResponse;
    type ConnectorInputData =
        AdyenRouterData<RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>, T>;
}
pub struct SetupMandateRequestTemplating;

pub struct SetupMandateResponseTemplating;

impl<
        T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static,
    > BridgeRequestResponse
    for Bridge<SetupMandateRequestTemplating, SetupMandateResponseTemplating, T>
{
    type RequestBody = SetupMandateRequest;
    type ResponseBody = SetupMandateResponse;
    type ConnectorInputData = AdyenRouterData<
        RouterDataV2<
            SetupMandate,
            PaymentFlowData,
            SetupMandateRequestData<T>,
            PaymentsResponseData,
        >,
        T,
    >;
}
pub struct AdyenDisputeAcceptRequestTemplating;

pub struct AdyenDisputeAcceptResponseTemplating;

impl<
        T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static,
    > BridgeRequestResponse
    for Bridge<AdyenDisputeAcceptRequestTemplating, AdyenDisputeAcceptResponseTemplating, T>
{
    type RequestBody = AdyenDisputeAcceptRequest;
    type ResponseBody = AdyenDisputeAcceptResponse;
    type ConnectorInputData = AdyenRouterData<
        RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>,
        T,
    >;
}
pub struct AdyenDisputeSubmitEvidenceRequestTemplating;

pub struct AdyenSubmitEvidenceResponseTemplating;

impl<
        T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static,
    > BridgeRequestResponse
    for Bridge<
        AdyenDisputeSubmitEvidenceRequestTemplating,
        AdyenSubmitEvidenceResponseTemplating,
        T,
    >
{
    type RequestBody = AdyenDisputeSubmitEvidenceRequest;
    type ResponseBody = AdyenSubmitEvidenceResponse;
    type ConnectorInputData = AdyenRouterData<
        RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>,
        T,
    >;
}
pub struct AdyenDefendDisputeRequestTemplating;

pub struct AdyenDefendDisputeResponseTemplating;

impl<
        T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static,
    > BridgeRequestResponse
    for Bridge<AdyenDefendDisputeRequestTemplating, AdyenDefendDisputeResponseTemplating, T>
{
    type RequestBody = AdyenDefendDisputeRequest;
    type ResponseBody = AdyenDefendDisputeResponse;
    type ConnectorInputData = AdyenRouterData<
        RouterDataV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>,
        T,
    >;
}
#[derive(Clone)]
pub struct Adyen<
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static,
> {
    authorize: &'static (dyn BridgeRequestResponse<
        RequestBody = AdyenPaymentRequest,
        ResponseBody = AdyenPaymentResponse,
        ConnectorInputData = AdyenRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    >),
    p_sync: &'static (dyn BridgeRequestResponse<
        RequestBody = AdyenRedirectRequest,
        ResponseBody = AdyenPSyncResponse,
        ConnectorInputData = AdyenRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    >),
    capture: &'static (dyn BridgeRequestResponse<
        RequestBody = AdyenCaptureRequest,
        ResponseBody = AdyenCaptureResponse,
        ConnectorInputData = AdyenRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    >),
    void: &'static (dyn BridgeRequestResponse<
        RequestBody = AdyenVoidRequest,
        ResponseBody = AdyenVoidResponse,
        ConnectorInputData = AdyenRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    >),
    refund: &'static (dyn BridgeRequestResponse<
        RequestBody = AdyenRefundRequest,
        ResponseBody = AdyenRefundResponse,
        ConnectorInputData = AdyenRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    >),
    setup_mandate: &'static (dyn BridgeRequestResponse<
        RequestBody = SetupMandateRequest,
        ResponseBody = SetupMandateResponse,
        ConnectorInputData = AdyenRouterData<
            RouterDataV2<
                SetupMandate,
                PaymentFlowData,
                SetupMandateRequestData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    >),
    accept: &'static (dyn BridgeRequestResponse<
        RequestBody = AdyenDisputeAcceptRequest,
        ResponseBody = AdyenDisputeAcceptResponse,
        ConnectorInputData = AdyenRouterData<
            RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>,
            T,
        >,
    >),
    submit_evidence: &'static (dyn BridgeRequestResponse<
        RequestBody = AdyenDisputeSubmitEvidenceRequest,
        ResponseBody = AdyenSubmitEvidenceResponse,
        ConnectorInputData = AdyenRouterData<
            RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>,
            T,
        >,
    >),
    defend_dispute: &'static (dyn BridgeRequestResponse<
        RequestBody = AdyenDefendDisputeRequest,
        ResponseBody = AdyenDefendDisputeResponse,
        ConnectorInputData = AdyenRouterData<
            RouterDataV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>,
            T,
        >,
    >),
}
impl<
        T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static,
    > Adyen<T>
{
    pub const fn new() -> &'static Self {
        &Self {
            authorize: &Bridge::<AdyenPaymentRequestTemplating, AdyenPaymentResponseTemplating, T>(
                PhantomData,
            ),
            p_sync: &Bridge::<AdyenRedirectRequestTemplating, AdyenPSyncResponseTemplating, T>(
                PhantomData,
            ),
            capture: &Bridge::<AdyenCaptureRequestTemplating, AdyenCaptureResponseTemplating, T>(
                PhantomData,
            ),
            void: &Bridge::<AdyenVoidRequestTemplating, AdyenVoidResponseTemplating, T>(
                PhantomData,
            ),
            refund: &Bridge::<AdyenRefundRequestTemplating, AdyenRefundResponseTemplating, T>(
                PhantomData,
            ),
            setup_mandate: &Bridge::<
                SetupMandateRequestTemplating,
                SetupMandateResponseTemplating,
                T,
            >(PhantomData),
            accept: &Bridge::<
                AdyenDisputeAcceptRequestTemplating,
                AdyenDisputeAcceptResponseTemplating,
                T,
            >(PhantomData),
            submit_evidence: &Bridge::<
                AdyenDisputeSubmitEvidenceRequestTemplating,
                AdyenSubmitEvidenceResponseTemplating,
                T,
            >(PhantomData),
            defend_dispute: &Bridge::<
                AdyenDefendDisputeRequestTemplating,
                AdyenDefendDisputeResponseTemplating,
                T,
            >(PhantomData),
        }
    }
    pub fn build_headers<F, FCD, Req, Res>(
        &self,
        req: &RouterDataV2<F, FCD, Req, Res>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let mut header = <[_]>::into_vec(
            #[rustc_box]
            alloc::boxed::Box::new([(
                headers::CONTENT_TYPE.to_string(),
                "application/json".to_string().into(),
            )]),
        );
        let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
        header.append(&mut api_key);
        Ok(header)
    }
    pub fn connector_base_url_payments<'a, F, Req, Res>(
        &self,
        req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
    ) -> &'a str {
        &req.resource_common_data.connectors.adyen.base_url
    }
    pub fn connector_base_url_refunds<'a, F, Req, Res>(
        &self,
        req: &'a RouterDataV2<F, RefundFlowData, Req, Res>,
    ) -> &'a str {
        &req.resource_common_data.connectors.adyen.base_url
    }
    pub fn connector_base_url_disputes<'a, F, Req, Res>(
        &self,
        req: &'a RouterDataV2<F, DisputeFlowData, Req, Res>,
    ) -> Option<&'a str> {
        req.resource_common_data
            .connectors
            .adyen
            .dispute_base_url
            .as_deref()
    }
}
