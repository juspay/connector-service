pub mod constants;
pub mod test;
pub mod transformers;

use std::marker::PhantomData;

use domain_types::{
    connector_types::ConnectorSpecifications,
    payment_method_data::PaymentMethodDataTypes,
};
use interfaces::{
    api::ConnectorCommon,
    connector_types::{ConnectorServiceTrait, PaymentAuthorizeV2, PaymentSyncV2, ValidationTrait},
};

#[derive(Debug, Clone)]
pub struct Tpsl<T> {
    connector_name: &'static str,
    payment_method_data: PhantomData<T>,
}

impl<T> Tpsl<T> {
    pub fn new() -> Self {
        Self {
            connector_name: "tpsl",
            payment_method_data: PhantomData,
        }
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    ConnectorCommon for Tpsl<T>
{
    fn id(&self) -> &'static str {
        self.connector_name
    }

    fn base_url<'a>(&self, _connectors: &'a domain_types::types::Connectors) -> &'a str {
        constants::get_base_url()
    }
}

// Stub types for unsupported flows
#[derive(Debug, Clone, serde::Serialize)]
pub struct TpslVoidRequest;
#[derive(Debug, Clone)]
pub struct TpslVoidResponse;

#[derive(Debug, Clone, serde::Serialize)]
pub struct TpslCaptureRequest;
#[derive(Debug, Clone)]
pub struct TpslCaptureResponse;

#[derive(Debug, Clone, serde::Serialize)]
pub struct TpslRefundRequest;
#[derive(Debug, Clone)]
pub struct TpslRefundResponse;

#[derive(Debug, Clone, serde::Serialize)]
pub struct TpslRsyncRequest;
#[derive(Debug, Clone)]
pub struct TpslRsyncResponse;

#[derive(Debug, Clone, serde::Serialize)]
pub struct TpslCreateOrderRequest;
#[derive(Debug, Clone)]
pub struct TpslCreateOrderResponse;

#[derive(Debug, Clone, serde::Serialize)]
pub struct TpslSessionTokenRequest;
#[derive(Debug, Clone)]
pub struct TpslSessionTokenResponse;

#[derive(Debug, Clone, serde::Serialize)]
pub struct TpslSetupMandateRequest;
#[derive(Debug, Clone)]
pub struct TpslSetupMandateResponse;

#[derive(Debug, Clone, serde::Serialize)]
pub struct TpslRepeatPaymentRequest;
#[derive(Debug, Clone)]
pub struct TpslRepeatPaymentResponse;

#[derive(Debug, Clone, serde::Serialize)]
pub struct TpslAcceptDisputeRequest;
#[derive(Debug, Clone)]
pub struct TpslAcceptDisputeResponse;

#[derive(Debug, Clone, serde::Serialize)]
pub struct TpslDefendDisputeRequest;
#[derive(Debug, Clone)]
pub struct TpslDefendDisputeResponse;

#[derive(Debug, Clone, serde::Serialize)]
pub struct TpslSubmitEvidenceRequest;
#[derive(Debug, Clone)]
pub struct TpslSubmitEvidenceResponse;



// Implement connector types traits - simplified for compilation

// Validation implementation
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    ValidationTrait for Tpsl<T>
{
}

// ConnectorSpecifications implementation
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    ConnectorSpecifications for Tpsl<T>
{
}

// Default implementation
impl<T> Default for Tpsl<T> {
    fn default() -> Self {
        Self::new()
    }
}

// Implement required traits for ConnectorServiceTrait
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    ConnectorServiceTrait<T> for Tpsl<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    PaymentAuthorizeV2<T> for Tpsl<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    PaymentSyncV2 for Tpsl<T>
{
}

// Implement empty traits for unsupported flows
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    SourceVerification<domain_types::connector_flow::Void, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::PaymentVoidData, domain_types::connector_types::PaymentsResponseData> for Tpsl<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    SourceVerification<domain_types::connector_flow::Capture, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::PaymentsCaptureData, domain_types::connector_types::PaymentsResponseData> for Tpsl<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    SourceVerification<domain_types::connector_flow::Refund, domain_types::connector_types::RefundFlowData, domain_types::connector_types::RefundsData, domain_types::connector_types::RefundsResponseData> for Tpsl<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    SourceVerification<domain_types::connector_flow::RSync, domain_types::connector_types::RefundSyncData, domain_types::connector_types::RefundSyncData, domain_types::connector_types::RefundsResponseData> for Tpsl<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    SourceVerification<domain_types::connector_flow::CreateOrder, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::PaymentCreateOrderData, domain_types::connector_types::PaymentCreateOrderResponse> for Tpsl<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    SourceVerification<domain_types::connector_flow::CreateSessionToken, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::SessionTokenRequestData, domain_types::connector_types::SessionTokenResponseData> for Tpsl<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    SourceVerification<domain_types::connector_flow::SetupMandate, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::SetupMandateRequestData<T>, domain_types::connector_types::PaymentsResponseData> for Tpsl<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    SourceVerification<domain_types::connector_flow::RepeatPayment, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::RepeatPaymentData, domain_types::connector_types::PaymentsResponseData> for Tpsl<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    SourceVerification<domain_types::connector_flow::Accept, domain_types::connector_types::DisputeFlowData, domain_types::connector_types::AcceptDisputeData, domain_types::connector_types::DisputeResponseData> for Tpsl<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    SourceVerification<domain_types::connector_flow::DefendDispute, domain_types::connector_types::DisputeFlowData, domain_types::connector_types::DisputeDefendData, domain_types::connector_types::DisputeResponseData> for Tpsl<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    SourceVerification<domain_types::connector_flow::SubmitEvidence, domain_types::connector_types::DisputeFlowData, domain_types::connector_types::SubmitEvidenceData, domain_types::connector_types::DisputeResponseData> for Tpsl<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    SourceVerification<domain_types::connector_flow::PaymentMethodToken, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::PaymentMethodTokenizationData<T>, domain_types::connector_types::PaymentMethodTokenResponse> for Tpsl<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    SourceVerification<domain_types::connector_flow::CreateAccessToken, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::AccessTokenRequestData, domain_types::connector_types::AccessTokenResponseData> for Tpsl<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    SourceVerification<domain_types::connector_flow::CreateConnectorCustomer, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::ConnectorCustomerData, domain_types::connector_types::ConnectorCustomerResponse> for Tpsl<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    SourceVerification<domain_types::connector_flow::PaymentVoidPostCapture, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::PaymentsCancelPostCaptureData, domain_types::connector_types::PaymentsResponseData> for Tpsl<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    SourceVerification<domain_types::connector_flow::RefundSync, domain_types::connector_types::RefundSyncData, domain_types::connector_types::RefundSyncData, domain_types::connector_types::RefundsResponseData> for Tpsl<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    SourceVerification<domain_types::connector_flow::PreAuthenticate, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::PaymentsPreAuthenticateData<T>, domain_types::connector_types::PaymentsResponseData> for Tpsl<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    SourceVerification<domain_types::connector_flow::Authenticate, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::PaymentsAuthenticateData<T>, domain_types::connector_types::PaymentsResponseData> for Tpsl<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    SourceVerification<domain_types::connector_flow::PostAuthenticate, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::PaymentsPostAuthenticateData<T>, domain_types::connector_types::PaymentsResponseData> for Tpsl<T>
{
}



#[derive(Debug, Default)]
pub struct ErrorResponse {
    pub status_code: u16,
    pub code: String,
    pub message: String,
    pub reason: Option<String>,
    pub status_message: Option<String>,
}