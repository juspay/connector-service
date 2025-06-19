use domain_types::{connector_flow, connector_types::{AcceptDisputeData, ConnectorWebhookSecrets, DisputeDefendData, DisputeFlowData, DisputeResponseData, DisputeWebhookDetailsResponse, IncomingWebhook, MandateReference, MultipleCaptureRequestData, PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundSyncData, RefundWebhookDetailsResponse, RefundsData, RefundsResponseData, RequestDetails, SetupMandateRequestData, SubmitEvidenceData, WebhookDetailsResponse}};

use crate::{api::ConnectorCommon, connector_integration_v2::ConnectorIntegrationV2};

pub trait ConnectorServiceTrait:
    ConnectorCommon
    + ValidationTrait
    + PaymentAuthorizeV2
    + PaymentSyncV2
    + PaymentOrderCreate
    + PaymentVoidV2
    + IncomingWebhook
    + RefundV2
    + PaymentCapture
    + SetupMandateV2
    + AcceptDispute
    + RefundSyncV2
    // + DisputeDefend
    + SubmitEvidenceV2
{
}

pub trait PaymentVoidV2:
    ConnectorIntegrationV2<connector_flow::Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
}

pub type BoxedConnector = Box<&'static (dyn ConnectorServiceTrait + Sync)>;

pub trait ValidationTrait {
    fn should_do_order_create(&self) -> bool {
        false
    }
}

pub trait PaymentOrderCreate:
    ConnectorIntegrationV2<
    connector_flow::CreateOrder,
    PaymentFlowData,
    PaymentCreateOrderData,
    PaymentCreateOrderResponse,
>
{
}

pub trait PaymentAuthorizeV2:
    ConnectorIntegrationV2<connector_flow::Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>
{
}

pub trait PaymentSyncV2:
    ConnectorIntegrationV2<connector_flow::PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
}

pub trait RefundV2:
    ConnectorIntegrationV2<connector_flow::Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
}

pub trait RefundSyncV2:
    ConnectorIntegrationV2<connector_flow::RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
}

pub trait PaymentCapture:
    ConnectorIntegrationV2<connector_flow::Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
}

pub trait SetupMandateV2:
    ConnectorIntegrationV2<connector_flow::SetupMandate, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData>
{
}

pub trait AcceptDispute:
    ConnectorIntegrationV2<connector_flow::Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
{
}

pub trait SubmitEvidenceV2:
    ConnectorIntegrationV2<connector_flow::SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
{
}