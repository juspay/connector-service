pub mod transformers;

use std::fmt::Debug;

use common_utils::{errors::CustomResult, events, ext_traits::{ByteSliceExt, XmlExt}, request::RequestContent};
use domain_types::{
    connector_flow::Authorize,
    connector_types::{
        PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData,
    },
    errors::{self, ConnectorError},
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
};
use error_stack::ResultExt;
use hyperswitch_masking::Maskable;
use interfaces::{
    api::ConnectorCommon, connector_integration_v2::ConnectorIntegrationV2, connector_types,
};
use serde::Serialize;
use transformers::{BamboraapacErrorResponse, BamboraapacPaymentRequest};

use crate::types::ResponseRouterData;

pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
}

// Trait implementations with generic type parameters
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::ConnectorServiceTrait<T> for Bamboraapac<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::PaymentAuthorizeV2<T> for Bamboraapac<T>
{
}

// Stub implementations for all required flows (minimal connector with Authorize only)
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ValidationTrait for Bamboraapac<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentSyncV2 for Bamboraapac<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentVoidV2 for Bamboraapac<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundV2 for Bamboraapac<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundSyncV2 for Bamboraapac<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentCapture for Bamboraapac<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentSessionToken for Bamboraapac<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentOrderCreate for Bamboraapac<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAccessToken for Bamboraapac<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::CreateConnectorCustomer for Bamboraapac<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentTokenV2<T> for Bamboraapac<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentVoidPostCaptureV2 for Bamboraapac<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::IncomingWebhook for Bamboraapac<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::SetupMandateV2<T> for Bamboraapac<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RepeatPaymentV2 for Bamboraapac<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::AcceptDispute for Bamboraapac<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::SubmitEvidenceV2 for Bamboraapac<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::DisputeDefend for Bamboraapac<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAuthenticateV2<T> for Bamboraapac<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentPreAuthenticateV2<T> for Bamboraapac<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentPostAuthenticateV2<T> for Bamboraapac<T>
{
}

// Connector struct
#[derive(Clone)]
pub struct Bamboraapac<T> {
    _phantom: std::marker::PhantomData<T>,
}

impl<T> Bamboraapac<T> {
    pub const fn new() -> &'static Self {
        &Self {
            _phantom: std::marker::PhantomData,
        }
    }

    fn build_headers<F, FCD, Req, Res>(
        &self,
        _req: &RouterDataV2<F, FCD, Req, Res>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        let header = vec![
            (
                headers::CONTENT_TYPE.to_string(),
                "text/xml".to_string().into(),
            ),
        ];
        Ok(header)
    }

    fn connector_base_url_payments<'a, F, Req, Res>(
        &self,
        req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
    ) -> &'a str {
        &req.resource_common_data.connectors.bamboraapac.base_url
    }

    fn connector_base_url_refunds<'a, F, Req, Res>(
        &self,
        req: &'a RouterDataV2<F, RefundFlowData, Req, Res>,
    ) -> &'a str {
        &req.resource_common_data.connectors.bamboraapac.base_url
    }
}

// Implement ConnectorCommon trait
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > ConnectorCommon for Bamboraapac<T>
{
    fn id(&self) -> &'static str {
        "bamboraapac"
    }

    fn get_currency_unit(&self) -> common_enums::CurrencyUnit {
        common_enums::CurrencyUnit::Minor
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        &connectors.bamboraapac.base_url
    }

    fn get_auth_header(
        &self,
        _auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        // Bambora APAC includes auth in the request body (SOAP), not headers
        Ok(vec![])
    }

    fn build_error_response(
        &self,
        res: Response,
        _event_builder: Option<&mut events::Event>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: BamboraapacErrorResponse = if res.response.is_empty() {
            BamboraapacErrorResponse::default()
        } else {
            // Try to parse as error response, fallback to default
            res.response
                .parse_struct("BamboraapacErrorResponse")
                .unwrap_or_else(|_| BamboraapacErrorResponse::default())
        };

        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response.error_code.unwrap_or_else(|| "UNKNOWN".to_string()),
            message: response
                .error_message
                .clone()
                .unwrap_or_else(|| "Unknown error".to_string()),
            reason: response.error_message,
            attempt_status: None,
            connector_transaction_id: response.transaction_id,
            network_decline_code: None,
            network_advice_code: None,
            network_error_message: None,
        })
    }
}

// Implement Authorize flow
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    ConnectorIntegrationV2<
        Authorize,
        PaymentFlowData,
        PaymentsAuthorizeData<T>,
        PaymentsResponseData,
    > for Bamboraapac<T>
{
    fn get_headers(
        &self,
        req: &RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData<T>,
            PaymentsResponseData,
        >,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        self.build_headers(req)
    }

    fn get_url(
        &self,
        req: &RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData<T>,
            PaymentsResponseData,
        >,
    ) -> CustomResult<String, ConnectorError> {
        Ok(format!("{}/dts.asmx", self.connector_base_url_payments(req)))
    }

    fn get_content_type(&self) -> &'static str {
        "text/xml"
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData<T>,
            PaymentsResponseData,
        >,
    ) -> CustomResult<Option<RequestContent>, ConnectorError> {
        let connector_req = BamboraapacPaymentRequest::<T>::try_from(req)?;

        // Convert to SOAP XML
        let soap_xml = connector_req.to_soap_xml();

        // Log the complete raw SOAP XML being sent
        tracing::info!(
            target: "bamboraapac_authorize_request",
            "Raw SOAP XML Request (Authorize):\n{}", soap_xml
        );

        Ok(Some(RequestContent::RawBytes(soap_xml.into_bytes())))
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData<T>,
            PaymentsResponseData,
        >,
        _event_builder: Option<&mut events::Event>,
        res: Response,
    ) -> CustomResult<
        RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ConnectorError,
    > {
        // Convert HTML entities to XML
        let response_str = String::from_utf8(res.response.to_vec())
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        let xml_response = response_str.replace("&lt;", "<").replace("&gt;", ">");

        // Parse XML response
        let response: transformers::BamboraapacPaymentResponse = xml_response
            .as_str()
            .parse_xml()
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        RouterDataV2::try_from(ResponseRouterData {
            response,
            router_data: data.clone(),
            http_code: res.status_code,
        })
        .change_context(errors::ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut events::Event>,
    ) -> CustomResult<ErrorResponse, ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

// Add Source Verification stub for Authorize flow
use interfaces::verification::SourceVerification;

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    SourceVerification<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
    for Bamboraapac<T>
{
}

// Stub implementations for all other required flows
use domain_types::connector_flow::{
    Accept, Authenticate, Capture, CreateConnectorCustomer, CreateOrder, CreateSessionToken,
    CreateAccessToken, DefendDispute, PaymentMethodToken, PostAuthenticate, PreAuthenticate,
    PSync, RSync, Refund, RepeatPayment, SetupMandate, SubmitEvidence, Void, VoidPC,
};
use domain_types::connector_types::{
    AcceptDisputeData, AccessTokenRequestData, AccessTokenResponseData, ConnectorCustomerData,
    ConnectorCustomerResponse, DisputeDefendData, DisputeFlowData, DisputeResponseData,
    PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentMethodTokenResponse,
    PaymentMethodTokenizationData, PaymentVoidData, PaymentsCancelPostCaptureData,
    PaymentsCaptureData, PaymentsAuthenticateData, PaymentsPostAuthenticateData,
    PaymentsPreAuthenticateData, PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData,
    RefundsResponseData, RepeatPaymentData, SessionTokenRequestData, SessionTokenResponseData,
    SetupMandateRequestData, SubmitEvidenceData,
};

// PSync (Payment Sync)
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    for Bamboraapac<T>
{
    fn get_headers(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        self.build_headers(req)
    }

    fn get_url(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<String, ConnectorError> {
        Ok(format!("{}/dts.asmx", self.connector_base_url_payments(req)))
    }

    fn get_content_type(&self) -> &'static str {
        "text/xml"
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<Option<RequestContent>, ConnectorError> {
        let connector_req = transformers::BamboraapacSyncRequest::try_from(req)?;
        let soap_xml = connector_req.to_soap_xml();

        // Log the complete raw SOAP XML being sent
        tracing::info!(
            target: "bamboraapac_psync_request",
            "Raw SOAP XML Request (PSync):\n{}", soap_xml
        );

        Ok(Some(RequestContent::RawBytes(soap_xml.into_bytes())))
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        _event_builder: Option<&mut events::Event>,
        res: Response,
    ) -> CustomResult<
        RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ConnectorError,
    > {
        let response_str = String::from_utf8(res.response.to_vec())
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        let xml_response = response_str.replace("&lt;", "<").replace("&gt;", ">");

        let response: transformers::BamboraapacSyncResponse = xml_response
            .as_str()
            .parse_xml()
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        RouterDataV2::try_from(ResponseRouterData {
            response,
            router_data: data.clone(),
            http_code: res.status_code,
        })
        .change_context(errors::ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut events::Event>,
    ) -> CustomResult<ErrorResponse, ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

// Void (Payment Void)
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
    for Bamboraapac<T>
{
}

// Refund
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
    for Bamboraapac<T>
{
    fn get_headers(
        &self,
        req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        self.build_headers(req)
    }

    fn get_url(
        &self,
        req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> CustomResult<String, ConnectorError> {
        Ok(format!("{}/dts.asmx", self.connector_base_url_refunds(req)))
    }

    fn get_content_type(&self) -> &'static str {
        "text/xml"
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> CustomResult<Option<RequestContent>, ConnectorError> {
        let connector_req = transformers::BamboraapacRefundRequest::try_from(req)?;
        let soap_xml = connector_req.to_soap_xml();

        // Log the complete raw SOAP XML being sent
        tracing::info!(
            target: "bamboraapac_refund_request",
            "Raw SOAP XML Request (Refund):\n{}", soap_xml
        );

        Ok(Some(RequestContent::RawBytes(soap_xml.into_bytes())))
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        _event_builder: Option<&mut events::Event>,
        res: Response,
    ) -> CustomResult<
        RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ConnectorError,
    > {
        // Parse the outer SOAP envelope
        let response_str = String::from_utf8(res.response.to_vec())
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        let outer_response: transformers::BamboraapacRefundResponse = response_str
            .as_str()
            .parse_xml()
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        // Extract and decode the HTML-encoded XML from submit_single_refund_result
        let inner_xml = outer_response
            .body
            .submit_single_refund_response
            .submit_single_refund_result
            .replace("&lt;", "<")
            .replace("&gt;", ">");

        // Parse the inner Response XML
        let inner_response: transformers::RefundResponseInner = inner_xml
            .as_str()
            .parse_xml()
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        RouterDataV2::try_from(ResponseRouterData {
            response: inner_response,
            router_data: data.clone(),
            http_code: res.status_code,
        })
        .change_context(errors::ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut events::Event>,
    ) -> CustomResult<ErrorResponse, ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

// RSync (Refund Sync)
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
    for Bamboraapac<T>
{
    fn get_headers(
        &self,
        req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        self.build_headers(req)
    }

    fn get_url(
        &self,
        req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
    ) -> CustomResult<String, ConnectorError> {
        Ok(format!("{}/dts.asmx", self.connector_base_url_refunds(req)))
    }

    fn get_content_type(&self) -> &'static str {
        "text/xml"
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
    ) -> CustomResult<Option<RequestContent>, ConnectorError> {
        let connector_req = transformers::BamboraapacSyncRequest::try_from(req)?;
        let soap_xml = connector_req.to_soap_xml();

        // Log the complete raw SOAP XML being sent
        tracing::info!(
            target: "bamboraapac_rsync_request",
            "Raw SOAP XML Request (RSync):\n{}", soap_xml
        );

        Ok(Some(RequestContent::RawBytes(soap_xml.into_bytes())))
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        _event_builder: Option<&mut events::Event>,
        res: Response,
    ) -> CustomResult<
        RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ConnectorError,
    > {
        let response_str = String::from_utf8(res.response.to_vec())
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        let xml_response = response_str.replace("&lt;", "<").replace("&gt;", ">");

        let response: transformers::BamboraapacSyncResponse = xml_response
            .as_str()
            .parse_xml()
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        RouterDataV2::try_from(ResponseRouterData {
            response,
            router_data: data.clone(),
            http_code: res.status_code,
        })
        .change_context(errors::ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut events::Event>,
    ) -> CustomResult<ErrorResponse, ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

// Capture
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
    for Bamboraapac<T>
{
    fn get_headers(
        &self,
        req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        self.build_headers(req)
    }

    fn get_url(
        &self,
        req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
    ) -> CustomResult<String, ConnectorError> {
        Ok(format!("{}/dts.asmx", self.connector_base_url_payments(req)))
    }

    fn get_content_type(&self) -> &'static str {
        "text/xml"
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
    ) -> CustomResult<Option<RequestContent>, ConnectorError> {
        let connector_req = transformers::BamboraapacCaptureRequest::try_from(req)?;
        let soap_xml = connector_req.to_soap_xml();

        // Log the complete raw SOAP XML being sent
        tracing::info!(
            target: "bamboraapac_capture_request",
            "Raw SOAP XML Request (Capture):\n{}", soap_xml
        );

        Ok(Some(RequestContent::RawBytes(soap_xml.into_bytes())))
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        _event_builder: Option<&mut events::Event>,
        res: Response,
    ) -> CustomResult<
        RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ConnectorError,
    > {
        // Convert HTML entities to XML
        let response_str = String::from_utf8(res.response.to_vec())
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        let xml_response = response_str.replace("&lt;", "<").replace("&gt;", ">");

        // Parse XML response (same as authorize since capture uses SubmitSinglePayment)
        let response: transformers::BamboraapacPaymentResponse = xml_response
            .as_str()
            .parse_xml()
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        RouterDataV2::try_from(ResponseRouterData {
            response,
            router_data: data.clone(),
            http_code: res.status_code,
        })
        .change_context(errors::ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut events::Event>,
    ) -> CustomResult<ErrorResponse, ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

// CreateSessionToken
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        CreateSessionToken,
        PaymentFlowData,
        SessionTokenRequestData,
        SessionTokenResponseData,
    > for Bamboraapac<T>
{
}

// CreateOrder
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for Bamboraapac<T>
{
}

// CreateAccessToken
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        CreateAccessToken,
        PaymentFlowData,
        AccessTokenRequestData,
        AccessTokenResponseData,
    > for Bamboraapac<T>
{
}

// CreateConnectorCustomer
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        CreateConnectorCustomer,
        PaymentFlowData,
        ConnectorCustomerData,
        ConnectorCustomerResponse,
    > for Bamboraapac<T>
{
}

// PaymentMethodToken
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        PaymentMethodToken,
        PaymentFlowData,
        PaymentMethodTokenizationData<T>,
        PaymentMethodTokenResponse,
    > for Bamboraapac<T>
{
}

// VoidPC (Void Post Capture)
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        VoidPC,
        PaymentFlowData,
        PaymentsCancelPostCaptureData,
        PaymentsResponseData,
    > for Bamboraapac<T>
{
}

// SetupMandate
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData<T>,
        PaymentsResponseData,
    > for Bamboraapac<T>
{
    fn get_headers(
        &self,
        req: &RouterDataV2<
            SetupMandate,
            PaymentFlowData,
            SetupMandateRequestData<T>,
            PaymentsResponseData,
        >,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        self.build_headers(req)
    }

    fn get_url(
        &self,
        req: &RouterDataV2<
            SetupMandate,
            PaymentFlowData,
            SetupMandateRequestData<T>,
            PaymentsResponseData,
        >,
    ) -> CustomResult<String, ConnectorError> {
        // SIPP API endpoint for customer registration
        Ok(format!("{}/sipp.asmx", self.connector_base_url_payments(req)))
    }

    fn get_content_type(&self) -> &'static str {
        "text/xml"
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<
            SetupMandate,
            PaymentFlowData,
            SetupMandateRequestData<T>,
            PaymentsResponseData,
        >,
    ) -> CustomResult<Option<RequestContent>, ConnectorError> {
        let connector_req = transformers::BamboraapacSetupMandateRequest::<T>::try_from(req)?;
        let soap_xml = connector_req.to_soap_xml();

        // Log the complete raw SOAP XML being sent
        tracing::info!(
            target: "bamboraapac_setupmandate_request",
            "Raw SOAP XML Request (SetupMandate):\n{}", soap_xml
        );

        Ok(Some(RequestContent::RawBytes(soap_xml.into_bytes())))
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<
            SetupMandate,
            PaymentFlowData,
            SetupMandateRequestData<T>,
            PaymentsResponseData,
        >,
        _event_builder: Option<&mut events::Event>,
        res: Response,
    ) -> CustomResult<
        RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>,
        ConnectorError,
    > {
        // Parse the outer SOAP envelope
        let response_str = String::from_utf8(res.response.to_vec())
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        let outer_response: transformers::BamboraapacSetupMandateResponse = response_str
            .as_str()
            .parse_xml()
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        // Extract and decode the HTML-encoded XML from register_single_customer_result
        let inner_xml = outer_response
            .body
            .register_single_customer_response
            .register_single_customer_result
            .replace("&lt;", "<")
            .replace("&gt;", ">");

        // Parse the inner RegisterSingleCustomerResponse XML
        let inner_response: transformers::RegisterSingleCustomerResponseInner = inner_xml
            .as_str()
            .parse_xml()
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        RouterDataV2::try_from(ResponseRouterData {
            response: inner_response,
            router_data: data.clone(),
            http_code: res.status_code,
        })
        .change_context(errors::ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut events::Event>,
    ) -> CustomResult<ErrorResponse, ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

// RepeatPayment
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>
    for Bamboraapac<T>
{
    fn get_headers(
        &self,
        req: &RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        self.build_headers(req)
    }

    fn get_url(
        &self,
        req: &RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>,
    ) -> CustomResult<String, ConnectorError> {
        Ok(format!("{}/dts.asmx", self.connector_base_url_payments(req)))
    }

    fn get_content_type(&self) -> &'static str {
        "text/xml"
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>,
    ) -> CustomResult<Option<RequestContent>, ConnectorError> {
        let connector_req = transformers::BamboraapacRepeatPaymentRequest::try_from(req)?;
        let soap_xml = connector_req.to_soap_xml();

        // Log the complete raw SOAP XML being sent
        tracing::info!(
            target: "bamboraapac_repeatpayment_request",
            "Raw SOAP XML Request (RepeatPayment):\n{}", soap_xml
        );

        Ok(Some(RequestContent::RawBytes(soap_xml.into_bytes())))
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>,
        _event_builder: Option<&mut events::Event>,
        res: Response,
    ) -> CustomResult<
        RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>,
        ConnectorError,
    > {
        // Convert HTML entities to XML
        let response_str = String::from_utf8(res.response.to_vec())
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        let xml_response = response_str.replace("&lt;", "<").replace("&gt;", ">");

        // Parse XML response (reuses BamboraapacPaymentResponse)
        let response: transformers::BamboraapacPaymentResponse = xml_response
            .as_str()
            .parse_xml()
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        RouterDataV2::try_from(ResponseRouterData {
            response,
            router_data: data.clone(),
            http_code: res.status_code,
        })
        .change_context(errors::ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut events::Event>,
    ) -> CustomResult<ErrorResponse, ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

// Accept (Dispute)
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    for Bamboraapac<T>
{
}

// SubmitEvidence
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
    for Bamboraapac<T>
{
}

// DefendDispute
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
    for Bamboraapac<T>
{
}

// PreAuthenticate
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        PreAuthenticate,
        PaymentFlowData,
        PaymentsPreAuthenticateData<T>,
        PaymentsResponseData,
    > for Bamboraapac<T>
{
}

// Authenticate
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        Authenticate,
        PaymentFlowData,
        PaymentsAuthenticateData<T>,
        PaymentsResponseData,
    > for Bamboraapac<T>
{
}

// PostAuthenticate
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        PostAuthenticate,
        PaymentFlowData,
        PaymentsPostAuthenticateData<T>,
        PaymentsResponseData,
    > for Bamboraapac<T>
{
}

// SourceVerification stub implementations for all flows
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    SourceVerification<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    for Bamboraapac<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    SourceVerification<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
    for Bamboraapac<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    SourceVerification<Refund, RefundFlowData, RefundsData, RefundsResponseData>
    for Bamboraapac<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    SourceVerification<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
    for Bamboraapac<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    SourceVerification<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
    for Bamboraapac<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    SourceVerification<CreateSessionToken, PaymentFlowData, SessionTokenRequestData, SessionTokenResponseData>
    for Bamboraapac<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    SourceVerification<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>
    for Bamboraapac<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    SourceVerification<CreateAccessToken, PaymentFlowData, AccessTokenRequestData, AccessTokenResponseData>
    for Bamboraapac<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    SourceVerification<CreateConnectorCustomer, PaymentFlowData, ConnectorCustomerData, ConnectorCustomerResponse>
    for Bamboraapac<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    SourceVerification<PaymentMethodToken, PaymentFlowData, PaymentMethodTokenizationData<T>, PaymentMethodTokenResponse>
    for Bamboraapac<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    SourceVerification<VoidPC, PaymentFlowData, PaymentsCancelPostCaptureData, PaymentsResponseData>
    for Bamboraapac<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    SourceVerification<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>
    for Bamboraapac<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    SourceVerification<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>
    for Bamboraapac<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    SourceVerification<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    for Bamboraapac<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    SourceVerification<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
    for Bamboraapac<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    SourceVerification<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
    for Bamboraapac<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    SourceVerification<PreAuthenticate, PaymentFlowData, PaymentsPreAuthenticateData<T>, PaymentsResponseData>
    for Bamboraapac<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    SourceVerification<Authenticate, PaymentFlowData, PaymentsAuthenticateData<T>, PaymentsResponseData>
    for Bamboraapac<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    SourceVerification<PostAuthenticate, PaymentFlowData, PaymentsPostAuthenticateData<T>, PaymentsResponseData>
    for Bamboraapac<T>
{
}
