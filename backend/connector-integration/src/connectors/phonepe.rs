pub mod constants;
pub mod headers;
pub mod transformers;

use common_enums as enums;
use common_utils::{
    errors::CustomResult,
    ext_traits::BytesExt,
    request::RequestContent,
    types::{AmountConvertor, MinorUnit, MinorUnitForConnector},
};
use domain_types::{
    connector_flow::{
        Accept, Authorize, Capture, CreateOrder, DefendDispute, PSync, RSync, Refund, SetupMandate,
        SubmitEvidence, Void,
    },
    connector_types::{
        AcceptDisputeData, ConnectorSpecifications, DisputeFlowData, DisputeResponseData,
        PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData, PaymentVoidData,
        PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData, PaymentsSyncData,
        RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData, SetupMandateRequestData,
        SubmitEvidenceData,
    },
    errors,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::{ConnectorInfo, Connectors},
};
use error_stack::ResultExt;
use hyperswitch_masking::Maskable;
use interfaces::{
    api::ConnectorCommon, connector_integration_v2::ConnectorIntegrationV2, connector_types,
    events::connector_api_logs::ConnectorEvent, verification::SourceVerification,
};
use transformers as phonepe;

#[derive(Clone)]
pub struct Phonepe {
    #[allow(dead_code)]
    pub(crate) amount_converter: &'static (dyn AmountConvertor<Output = MinorUnit> + Sync),
}

impl connector_types::ValidationTrait for Phonepe {}

impl connector_types::PaymentAuthorizeV2 for Phonepe {}

// Default empty implementations for unsupported flows
impl connector_types::PaymentSyncV2 for Phonepe {}
impl connector_types::PaymentOrderCreate for Phonepe {}
impl connector_types::PaymentVoidV2 for Phonepe {}
impl connector_types::IncomingWebhook for Phonepe {}
impl connector_types::RefundV2 for Phonepe {}
impl connector_types::PaymentCapture for Phonepe {}
impl connector_types::SetupMandateV2 for Phonepe {}
impl connector_types::AcceptDispute for Phonepe {}
impl connector_types::RefundSyncV2 for Phonepe {}
impl connector_types::DisputeDefend for Phonepe {}
impl connector_types::SubmitEvidenceV2 for Phonepe {}

// Implement ConnectorServiceTrait by virtue of implementing all required traits
impl connector_types::ConnectorServiceTrait for Phonepe {}

// SourceVerification implementations for all flows
impl SourceVerification<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>
    for Phonepe
{
}

impl SourceVerification<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    for Phonepe
{
}

impl
    SourceVerification<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for Phonepe
{
}

impl SourceVerification<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData> for Phonepe {}

impl SourceVerification<Refund, RefundFlowData, RefundsData, RefundsResponseData> for Phonepe {}

impl SourceVerification<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
    for Phonepe
{
}

impl
    SourceVerification<SetupMandate, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData>
    for Phonepe
{
}

impl SourceVerification<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    for Phonepe
{
}

impl SourceVerification<RSync, RefundFlowData, RefundSyncData, RefundsResponseData> for Phonepe {}

impl
    SourceVerification<
        DefendDispute,
        DisputeFlowData,
        domain_types::connector_types::DisputeDefendData,
        DisputeResponseData,
    > for Phonepe
{
}

impl SourceVerification<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
    for Phonepe
{
}

impl Phonepe {
    pub const fn new() -> &'static Self {
        &Self {
            amount_converter: &MinorUnitForConnector,
        }
    }
}

impl ConnectorCommon for Phonepe {
    fn id(&self) -> &'static str {
        "phonepe"
    }

    fn get_currency_unit(&self) -> enums::CurrencyUnit {
        enums::CurrencyUnit::Minor
    }

    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let _auth = phonepe::PhonepeAuthType::try_from(auth_type)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        Ok(vec![(
            "Content-Type".to_string(),
            "application/json".to_string().into(),
        )])
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.phonepe.base_url.as_ref()
    }

    fn build_error_response(
        &self,
        res: Response,
        _event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: phonepe::PhonepePaymentsResponse = res
            .response
            .parse_struct("PhonePe ErrorResponse")
            .map_err(|_| errors::ConnectorError::ResponseDeserializationFailed)?;

        let error_message = response.message.clone();
        let error_code = response.code.clone();

        Ok(ErrorResponse {
            status_code: res.status_code,
            code: error_code,
            message: error_message.clone(),
            reason: Some(error_message),
            attempt_status: None,
            connector_transaction_id: None,
            network_decline_code: None,
            network_advice_code: None,
            network_error_message: None,
            raw_connector_response: Some(String::from_utf8_lossy(&res.response).to_string()),
        })
    }
}

impl ConnectorIntegrationV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>
    for Phonepe
{
    fn get_headers(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError>
    where
        Self: ConnectorIntegrationV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData,
            PaymentsResponseData,
        >,
    {
        // Build the request to get the checksum
        let amount = req.request.minor_amount;
        let connector_router_data = phonepe::PhonepeRouterData::try_from((amount, req))?;
        let connector_req = phonepe::PhonepePaymentsRequest::try_from(&connector_router_data)?;

        let mut header = vec![(
            "Content-Type".to_string(),
            "application/json".to_string().into(),
        )];

        // Add the checksum header
        header.push(("X-VERIFY".to_string(), connector_req.checksum.into()));

        Ok(header)
    }

    fn get_url(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(format!(
            "{}{}",
            req.resource_common_data.connectors.phonepe.base_url,
            constants::API_PAY_ENDPOINT
        ))
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let amount = req.request.minor_amount;
        let connector_router_data = phonepe::PhonepeRouterData::try_from((amount, req))?;
        let connector_req = phonepe::PhonepePaymentsRequest::try_from(&connector_router_data)?;
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
        _event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<
        RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        errors::ConnectorError,
    > {
        let response: phonepe::PhonepePaymentsResponse = res
            .response
            .parse_struct("Phonepe PaymentsResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        <RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData> as phonepe::ForeignTryFrom<_>>::foreign_try_from((
            phonepe::ResponseRouterData {
                response,
                data: data.clone(),
                http_code: res.status_code,
            },
            Some(self.amount_converter),
        ))
        .change_context(errors::ConnectorError::ResponseHandlingFailed)
    }
}

// Default empty implementations for unsupported flows - the traits will use default implementations
impl ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    for Phonepe
{
}
impl
    ConnectorIntegrationV2<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for Phonepe
{
}
impl ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
    for Phonepe
{
}
impl ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData> for Phonepe {}
impl ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
    for Phonepe
{
}
impl
    ConnectorIntegrationV2<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData,
        PaymentsResponseData,
    > for Phonepe
{
}
impl ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    for Phonepe
{
}
impl ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
    for Phonepe
{
}
impl
    ConnectorIntegrationV2<
        DefendDispute,
        DisputeFlowData,
        domain_types::connector_types::DisputeDefendData,
        DisputeResponseData,
    > for Phonepe
{
}
impl
    ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
    for Phonepe
{
}

impl ConnectorSpecifications for Phonepe {
    fn get_supported_payment_methods(
        &self,
    ) -> Option<&'static domain_types::types::SupportedPaymentMethods> {
        None // TODO: Add UPI payment methods support
    }

    fn get_supported_webhook_flows(&self) -> Option<&'static [enums::EventClass]> {
        None // TODO: Add webhook support
    }

    fn get_connector_about(&self) -> Option<&'static ConnectorInfo> {
        None // TODO: Add connector info
    }
}
