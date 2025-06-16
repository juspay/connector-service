//! Paytm UPI Payment Connector
//!
//! This module implements the connector integration for Paytm v2, focusing on UPI payment methods
//! in the Indian market.
//!
//! # UPI Payment Methods
//!
//! ## UPI Intent
//! UPI Intent allows users to select a UPI app (Google Pay, PhonePe, etc.) for payment.
//! The flow involves redirecting the user to their chosen UPI app to complete the payment.
//!
//! ## UPI Collect
//! UPI Collect allows merchants to collect payments directly from a customer's UPI ID (VPA).
//! The customer receives a payment request in their UPI app and approves it.
//!
//! ## UPI QR
//! UPI QR generates a QR code that can be scanned by any UPI app to make payment.
//!
//! # Implementation Details
//!
//! This connector implements:
//! - Two-phase payment flow: CreateSessionToken (initiate transaction) + Authorize (process transaction)
//! - Hash-based security verification with SHA-256 signatures
//! - Error handling for UPI-specific error codes
//! - Support for UPI Intent, Collect, and QR payment flows

use domain_types::{
    connector_flow::{
        Accept, Authorize, Capture, CreateOrder, CreateSessionToken, DefendDispute, PSync, RSync,
        Refund, SetupMandate, SubmitEvidence, Void,
    },
    connector_types::{
        AcceptDispute, AcceptDisputeData, ConnectorServiceTrait, DisputeDefend, DisputeDefendData,
        DisputeFlowData, DisputeResponseData, PaymentAuthorizeV2, PaymentCapture,
        PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData, PaymentOrderCreate,
        PaymentSessionToken, PaymentSyncV2, PaymentVoidData, PaymentVoidV2, PaymentsAuthorizeData,
        PaymentsCaptureData, PaymentsResponseData, PaymentsSyncData, RefundFlowData,
        RefundSyncData, RefundSyncV2, RefundV2, RefundsData, RefundsResponseData,
        SessionTokenRequestData, SessionTokenResponseData, SetupMandateRequestData, SetupMandateV2,
        SubmitEvidenceData, SubmitEvidenceV2, ValidationTrait,
    },
};
use hyperswitch_domain_models::router_data::{ConnectorAuthType, ErrorResponse};
use hyperswitch_interfaces::{
    api::{ConnectorCommon, CurrencyUnit},
    configs::Connectors,
    connector_integration_v2::ConnectorIntegrationV2,
    errors,
    events::connector_api_logs::ConnectorEvent,
    types::Response,
};

use common_enums::AttemptStatus;
use common_utils::{
    errors::CustomResult,
    ext_traits::ByteSliceExt,
    request::RequestContent,
    types::{AmountConvertor, MinorUnit, MinorUnitForConnector},
};
use error_stack::ResultExt;
use hyperswitch_domain_models::router_data_v2::RouterDataV2;
use masking::{Maskable, PeekInterface};

pub mod test;
pub mod transformers;

#[derive(Clone)]
pub struct Paytm {
    #[allow(dead_code)]
    pub(crate) amount_converter: &'static (dyn AmountConvertor<Output = MinorUnit> + Sync),
}

impl ValidationTrait for Paytm {
    fn should_do_session_token(&self) -> bool {
        true
    }
}

impl ConnectorServiceTrait for Paytm {}
impl PaymentAuthorizeV2 for Paytm {}
impl PaymentSyncV2 for Paytm {}
impl PaymentOrderCreate for Paytm {}
impl PaymentSessionToken for Paytm {}
impl PaymentVoidV2 for Paytm {}
impl RefundSyncV2 for Paytm {}
impl RefundV2 for Paytm {}
impl PaymentCapture for Paytm {}
impl SetupMandateV2 for Paytm {}
impl AcceptDispute for Paytm {}
impl SubmitEvidenceV2 for Paytm {}
impl DisputeDefend for Paytm {}

impl Paytm {
    pub const fn new() -> &'static Self {
        &Self {
            amount_converter: &MinorUnitForConnector,
        }
    }
}

impl ConnectorCommon for Paytm {
    fn id(&self) -> &'static str {
        "paytm"
    }

    fn get_currency_unit(&self) -> CurrencyUnit {
        CurrencyUnit::Minor
    }

    fn get_auth_header(
        &self,
        _auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        // Paytm uses signature-based authentication in request headers, not Authorization header
        Ok(vec![])
    }

    fn base_url<'a>(&self, _connectors: &'a Connectors) -> &'a str {
        // For now, use a placeholder since Paytm is not in hyperswitch_domain_models::configs::Connectors
        // URLs are handled directly in get_url methods using req.resource_common_data.connectors.paytm
        "https://securestage.paytmpayments.com"
    }

    fn build_error_response(
        &self,
        res: Response,
        _event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: transformers::PaytmErrorResponse = res
            .response
            .parse_struct("PaytmErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        // Map Paytm error codes to appropriate attempt status
        let attempt_status = match response.body.result_info.result_code.as_str() {
            "01" => AttemptStatus::Charged,
            "227" => AttemptStatus::Pending, // Transaction pending
            "325" => AttemptStatus::Failure, // Duplicate order id
            "400" => AttemptStatus::Failure, // Bad request
            "401" => AttemptStatus::AuthenticationFailed, // Authentication failed
            "402" => AttemptStatus::Failure, // Invalid checksum
            "501" => AttemptStatus::Failure, // System error
            _ => AttemptStatus::Failure,
        };

        Ok(ErrorResponse {
            code: response.body.result_info.result_code.clone(),
            message: response.body.result_info.result_msg.clone(),
            reason: Some(response.body.result_info.result_msg.clone()),
            status_code: res.status_code,
            attempt_status: Some(attempt_status),
            connector_transaction_id: None,
            network_decline_code: None,
            network_advice_code: None,
            network_error_message: None,
        })
    }
}

// Stub implementations for unsupported flows
impl
    ConnectorIntegrationV2<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for Paytm
{
}

impl
    ConnectorIntegrationV2<
        CreateSessionToken,
        PaymentFlowData,
        SessionTokenRequestData,
        SessionTokenResponseData,
    > for Paytm
{
    fn get_headers(
        &self,
        _req: &RouterDataV2<
            CreateSessionToken,
            PaymentFlowData,
            SessionTokenRequestData,
            SessionTokenResponseData,
        >,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        Ok(vec![(
            "Content-Type".to_string(),
            "application/json".into(),
        )])
    }

    fn get_url(
        &self,
        req: &RouterDataV2<
            CreateSessionToken,
            PaymentFlowData,
            SessionTokenRequestData,
            SessionTokenResponseData,
        >,
    ) -> CustomResult<String, errors::ConnectorError> {
        let auth = transformers::PaytmAuthType::try_from(&req.connector_auth_type)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;

        let order_id = &req.resource_common_data.connector_request_reference_id;
        let base_url = &req.resource_common_data.connectors.paytm.base_url;

        Ok(format!(
            "{}/theia/api/v1/initiateTransaction?mid={}&orderId={}",
            base_url,
            auth.merchant_id.peek(),
            order_id
        ))
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<
            CreateSessionToken,
            PaymentFlowData,
            SessionTokenRequestData,
            SessionTokenResponseData,
        >,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let connector_router_data = transformers::PaytmRouterData::try_from(req)?;
        let connector_req =
            transformers::PaytmInitiateTransactionRequest::try_from(&connector_router_data)?;
        Ok(Some(RequestContent::Json(Box::new(connector_req))))
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<
            CreateSessionToken,
            PaymentFlowData,
            SessionTokenRequestData,
            SessionTokenResponseData,
        >,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<
        RouterDataV2<
            CreateSessionToken,
            PaymentFlowData,
            SessionTokenRequestData,
            SessionTokenResponseData,
        >,
        errors::ConnectorError,
    > {
        let response: transformers::PaytmInitiateTransactionResponse = res
            .response
            .parse_struct("Paytm InitiateTransactionResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        event_builder.map(|i| i.set_response_body(&response));
        // Log the response if needed
        // TODO: Use proper logging when router_env is available

        RouterDataV2::try_from(transformers::ResponseRouterData {
            response,
            data: data.clone(),
            http_code: res.status_code,
        })
        .change_context(errors::ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
    for Paytm
{
}

impl ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
    for Paytm
{
}

impl ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    for Paytm
{
}

impl ConnectorIntegrationV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>
    for Paytm
{
    fn get_headers(
        &self,
        _req: &RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData,
            PaymentsResponseData,
        >,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        // Process transaction request doesn't need signature as it uses txn_token for authentication
        Ok(vec![(
            "Content-Type".to_string(),
            "application/json".into(),
        )])
    }

    fn get_url(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        let auth = transformers::PaytmAuthType::try_from(&req.connector_auth_type)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;

        let order_id = &req.resource_common_data.connector_request_reference_id;
        let base_url = &req.resource_common_data.connectors.paytm.base_url;

        Ok(format!(
            "{}/theia/api/v1/processTransaction?mid={}&orderId={}",
            base_url,
            auth.merchant_id.peek(),
            order_id
        ))
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let connector_router_data = transformers::PaytmRouterData::try_from(req)?;
        let connector_req =
            transformers::PaytmProcessTransactionRequest::try_from(&connector_router_data)?;
        Ok(Some(RequestContent::Json(Box::new(connector_req))))
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData,
            PaymentsResponseData,
        >,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<
        RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        errors::ConnectorError,
    > {
        let response: transformers::PaytmProcessTransactionResponse = res
            .response
            .parse_struct("Paytm ProcessTransactionResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        event_builder.map(|i| i.set_response_body(&response));

        RouterDataV2::try_from(transformers::ResponseRouterData {
            response,
            data: data.clone(),
            http_code: res.status_code,
        })
        .change_context(errors::ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData> for Paytm {}

impl ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData> for Paytm {}

impl ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    for Paytm
{
}

impl ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
    for Paytm
{
}

impl
    ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
    for Paytm
{
}

impl
    ConnectorIntegrationV2<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData,
        PaymentsResponseData,
    > for Paytm
{
}

// Now implement the trait aliases
impl domain_types::connector_types::IncomingWebhook for Paytm {}
