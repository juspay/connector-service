pub mod transformers;
use common_utils::Maskable;

use std::fmt::Debug;
use common_enums::CurrencyUnit;
use common_utils::{errors::CustomResult, ext_traits::ByteSliceExt, StringMajorUnit};
use domain_types::{
    connector_flow::{
        Accept, Authenticate, Authorize, Capture, CreateAccessToken, CreateConnectorCustomer,
        CreateOrder, CreateSessionToken, DefendDispute, PSync, PaymentMethodToken,
        PostAuthenticate, PreAuthenticate, RSync, Refund, RepeatPayment, SetupMandate,
        SubmitEvidence, Void, VoidPC,
    },
    connector_types::{
        AcceptDisputeData, AccessTokenRequestData, AccessTokenResponseData, ConnectorCustomerData,
        ConnectorCustomerResponse, DisputeDefendData, DisputeFlowData, DisputeResponseData,
        PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData,
        PaymentMethodTokenResponse, PaymentMethodTokenizationData, PaymentVoidData,
        PaymentsAuthenticateData, PaymentsAuthorizeData, PaymentsCancelPostCaptureData,
        PaymentsCaptureData, PaymentsPostAuthenticateData, PaymentsPreAuthenticateData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData,
        RefundsResponseData, RepeatPaymentData, SessionTokenRequestData, SessionTokenResponseData,
        SetupMandateRequestData, SubmitEvidenceData,
    },
    errors::{self, ConnectorError},
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
};
use error_stack::{Report, ResultExt};
// use crate::masking::{ExposeInterface, Mask, Maskable};
use interfaces::{
    api::ConnectorCommon, connector_integration_v2::ConnectorIntegrationV2, connector_types,
    events::connector_api_logs::ConnectorEvent,
};
use serde::Serialize;
use super::macros;
use crate::{
    connectors::mifinity::transformers::{
        auth_headers, MifinityAuthType, MifinityErrorResponse, MifinityPaymentsRequest,
        MifinityPaymentsResponse, MifinityPsyncResponse,
    },
    types::ResponseRouterData,
};

pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
}

#[derive(Clone)]
pub struct Mifinity<T> {
    _phantom: std::marker::PhantomData<T>,
}

impl<T> Mifinity<T> {
    pub const fn new() -> &'static Self {
        &Self {
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentPreAuthenticateV2<T> for Mifinity<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAuthenticateV2<T> for Mifinity<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentPostAuthenticateV2<T> for Mifinity<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ConnectorServiceTrait<T> for Mifinity<T>
{
    type Error = errors::ConnectorError;
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAuthorizeV2<T> for Mifinity<T>
{
}

impl<T> connector_types::PaymentSyncV2 for Mifinity<T> {
}

impl<T> connector_types::PaymentVoidV2 for Mifinity<T> {
}

impl<T> connector_types::RefundSyncV2 for Mifinity<T> {
}

impl<T> connector_types::RefundV2 for Mifinity<T> {
}

impl<T> connector_types::PaymentCapture for Mifinity<T> {
}

impl<T> connector_types::ValidationTrait for Mifinity<T> {
    fn should_do_order_create(&self) -> bool {
        true
    }
}

impl<T> connector_types::SetupMandateV2<T> for Mifinity<T> {
}

impl<T> connector_types::RepeatPaymentV2 for Mifinity<T> {
}

impl<T> connector_types::PaymentVoidPostCaptureV2 for Mifinity<T> {
}

impl<T> connector_types::AcceptDispute for Mifinity<T> {
}

impl<T> connector_types::SubmitEvidenceV2 for Mifinity<T> {
}

impl<T> connector_types::DisputeDefend for Mifinity<T> {
}

impl<T> connector_types::IncomingWebhook for Mifinity<T> {
}

impl<T> connector_types::PaymentOrderCreate for Mifinity<T> {
}

impl<T> connector_types::PaymentSessionToken for Mifinity<T> {
}

impl<T> connector_types::PaymentAccessToken for Mifinity<T> {
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::CreateConnectorCustomer for Mifinity<T>
{
}

impl<T> connector_types::PaymentTokenV2<T> for Mifinity<T> {
}

const API_VERSION: &str = "1";

impl<T> ConnectorCommon for Mifinity<T> {
    fn id(&self) -> &'static str {
        "mifinity"
    }
    
    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }
    
    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth = MifinityAuthType::try_from(auth_type)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        Ok(auth_headers(&auth))
    }
    
    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        &connectors.mifinity.base_url
    }
    
    fn build_error_response(
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: MifinityErrorResponse = res
            .response
            .parse_struct("MifinityErrorResponse")
            .map_err(|_| ConnectorError::ResponseDeserializationFailed)?;
        if let Some(event) = event_builder {
            event.set_error_response_body(&response);
        }
        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response.error_code.unwrap_or_else(|| "UNKNOWN_ERROR".to_string()),
            message: response.error_message.unwrap_or_else(|| "Unknown error".to_string()),
            reason: response.error_detail,
            attempt_status: None,
            connector_transaction_id: None,
            network_decline_code: None,
            network_advice_code: None,
            network_error_message: None,
        })
    }
    
    fn get_currency_unit(&self) -> CurrencyUnit {
        CurrencyUnit::Base
    }
    
    fn build_headers<F, FCD, Req, Res>(
        &self,
        req: &RouterDataV2<F, FCD, Req, Res>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        let mut header = vec![(
            (
                headers::CONTENT_TYPE.to_string(),
                "application/json".to_string().into(),
            ),
        )];
        let mut auth_header = self.get_auth_header(&req.connector_auth_type)?;
        header.append(&mut auth_header);
        Ok(header)
    }
}

// Implement the main flows
impl<T> ConnectorIntegrationV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData> for Mifinity<T> {
    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Post
    }
    
    fn get_headers(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        self.build_headers(req)
    }
    
    fn get_url(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(format!(
            "{}/v{}/payments",
            self.base_url(&req.resource_common_data.connectors),
            API_VERSION
        ))
    }
    
    fn get_request_body(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<Option<common_utils::request::RequestContent>, errors::ConnectorError> {
        let connector_req = MifinityPaymentsRequest::try_from(req)?;
        Ok(Some(common_utils::request::RequestContent::Json(Box::new(connector_req))))
    }
    
    fn handle_response_v2(
        &self,
        data: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<
        RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        errors::ConnectorError,
    > {
        let response: MifinityPaymentsResponse = res
            .response
            .parse_struct("MifinityPaymentsResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        if let Some(i) = event_builder {
            i.set_response_body(&response);
        }
        RouterDataV2::foreign_try_from((response, data.clone(), res.status_code))
            .change_context(errors::ConnectorError::ResponseHandlingFailed)
    }
    
    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
    
    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
}

impl<T> ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData> for Mifinity<T> {
    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Get
    }
    
    fn get_headers(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        self.build_headers(req)
    }
    
    fn get_url(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        let payment_id = req.request.connector_transaction_id.get_connector_transaction_id()
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;
        Ok(format!(
            "{}/v{}/payments/{}",
            self.base_url(&req.resource_common_data.connectors),
            API_VERSION,
            payment_id
        ))
    }
    
    fn handle_response_v2(
        &self,
        data: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<
        RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        errors::ConnectorError,
    > {
        let response: MifinityPsyncResponse = res
            .response
            .parse_struct("MifinityPsyncResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        if let Some(i) = event_builder {
            i.set_response_body(&response);
        }
        RouterDataV2::foreign_try_from((response, data.clone(), res.status_code))
            .change_context(errors::ConnectorError::ResponseHandlingFailed)
    }
    
    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
    
    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
}

// Stub implementations for all other flows
impl<T> ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData> for Mifinity<T> {
    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Post
    }
    
    fn get_headers(
        &self,
        req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        self.build_headers(req)
    }
    
    fn get_url(
        &self,
        req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        let payment_id = req.request.connector_transaction_id.get_connector_transaction_id()
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;
        Ok(format!(
            "{}/v{}/payments/{}/capture",
            self.base_url(&req.resource_common_data.connectors),
            API_VERSION,
            payment_id
        ))
    }
    
    fn get_request_body(
        &self,
        req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<Option<common_utils::request::RequestContent>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("Capture flow not supported".to_string()).into())
    }
    
    fn handle_response_v2(
        &self,
        _data: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        _res: Response,
        _event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<
        RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        errors::ConnectorError,
    > {
        Err(errors::ConnectorError::NotImplemented("Capture flow not supported".to_string()).into())
    }
    
    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
    
    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
}

impl<T> ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData> for Mifinity<T> {
    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Post
    }
    
    fn get_headers(
        &self,
        req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        self.build_headers(req)
    }
    
    fn get_url(
        &self,
        req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        let payment_id = req.request.connector_transaction_id.get_connector_transaction_id()
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;
        Ok(format!(
            "{}/v{}/payments/{}/void",
            self.base_url(&req.resource_common_data.connectors),
            API_VERSION,
            payment_id
        ))
    }
    
    fn get_request_body(
        &self,
        _req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<Option<common_utils::request::RequestContent>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("Void flow not supported".to_string()).into())
    }
    
    fn handle_response_v2(
        &self,
        _data: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        _res: Response,
        _event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<
        RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        errors::ConnectorError,
    > {
        Err(errors::ConnectorError::NotImplemented("Void flow not supported".to_string()).into())
    }
    
    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
    
    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
}

impl<T> ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData> for Mifinity<T> {
    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Post
    }
    
    fn get_headers(
        &self,
        req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        self.build_headers(req)
    }
    
    fn get_url(
        &self,
        req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        let payment_id = req.request.connector_transaction_id.get_connector_transaction_id()
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;
        Ok(format!(
            "{}/v{}/payments/{}/refund",
            self.base_url(&req.resource_common_data.connectors),
            API_VERSION,
            payment_id
        ))
    }
    
    fn get_request_body(
        &self,
        _req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<Option<common_utils::request::RequestContent>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("Refund flow not supported".to_string()).into())
    }
    
    fn handle_response_v2(
        &self,
        _data: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        _res: Response,
        _event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<
        RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        errors::ConnectorError,
    > {
        Err(errors::ConnectorError::NotImplemented("Refund flow not supported".to_string()).into())
    }
    
    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
    
    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
}

impl<T> ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData> for Mifinity<T> {
    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Get
    }
    
    fn get_headers(
        &self,
        req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        self.build_headers(req)
    }
    
    fn get_url(
        &self,
        req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        let refund_id = &req.request.connector_refund_id;
        Ok(format!(
            "{}/v{}/refunds/{}",
            self.base_url(&req.resource_common_data.connectors),
            API_VERSION,
            refund_id
        ))
    }
    
    fn handle_response_v2(
        &self,
        _data: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        _res: Response,
        _event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<
        RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        errors::ConnectorError,
    > {
        Err(errors::ConnectorError::NotImplemented("RSync flow not supported".to_string()).into())
    }
    
    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
    
    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
}

// Stub implementations for all other flows
impl<T> ConnectorIntegrationV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse> for Mifinity<T> {
    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Post
    }
    
    fn get_headers(
        &self,
        req: &RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        self.build_headers(req)
    }
    
    fn get_url(
        &self,
        _req: &RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>,
        _connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("CreateOrder flow not supported".to_string()).into())
    }
    
    fn get_request_body(
        &self,
        _req: &RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>,
        _connectors: &Connectors,
    ) -> CustomResult<Option<common_utils::request::RequestContent>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("CreateOrder flow not supported".to_string()).into())
    }
    
    fn handle_response_v2(
        &self,
        _data: &RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>,
        _res: Response,
        _event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<
        RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>,
        errors::ConnectorError,
    > {
        Err(errors::ConnectorError::NotImplemented("CreateOrder flow not supported".to_string()).into())
    }
    
    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
    
    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
}

// Stub implementations for all remaining flows
impl<T> ConnectorIntegrationV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData> for Mifinity<T> {
    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Post
    }
    
    fn get_headers(
        &self,
        req: &RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        self.build_headers(req)
    }
    
    fn get_url(
        &self,
        _req: &RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("SetupMandate flow not supported".to_string()).into())
    }
    
    fn get_request_body(
        &self,
        _req: &RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<Option<common_utils::request::RequestContent>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("SetupMandate flow not supported".to_string()).into())
    }
    
    fn handle_response_v2(
        &self,
        _data: &RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>,
        _res: Response,
        _event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<
        RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>,
        errors::ConnectorError,
    > {
        Err(errors::ConnectorError::NotImplemented("SetupMandate flow not supported".to_string()).into())
    }
    
    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
    
    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
}

impl<T> ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData> for Mifinity<T> {
    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Post
    }
    
    fn get_headers(
        &self,
        req: &RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        self.build_headers(req)
    }
    
    fn get_url(
        &self,
        _req: &RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("Accept dispute flow not supported".to_string()).into())
    }
    
    fn get_request_body(
        &self,
        _req: &RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<Option<common_utils::request::RequestContent>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("Accept dispute flow not supported".to_string()).into())
    }
    
    fn handle_response_v2(
        &self,
        _data: &RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>,
        _res: Response,
        _event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<
        RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>,
        errors::ConnectorError,
    > {
        Err(errors::ConnectorError::NotImplemented("Accept dispute flow not supported".to_string()).into())
    }
    
    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
    
    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
}

impl<T> ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData> for Mifinity<T> {
    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Post
    }
    
    fn get_headers(
        &self,
        req: &RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        self.build_headers(req)
    }
    
    fn get_url(
        &self,
        _req: &RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("SubmitEvidence flow not supported".to_string()).into())
    }
    
    fn get_request_body(
        &self,
        _req: &RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<Option<common_utils::request::RequestContent>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("SubmitEvidence flow not supported".to_string()).into())
    }
    
    fn handle_response_v2(
        &self,
        _data: &RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>,
        _res: Response,
        _event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<
        RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>,
        errors::ConnectorError,
    > {
        Err(errors::ConnectorError::NotImplemented("SubmitEvidence flow not supported".to_string()).into())
    }
    
    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
    
    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
}

impl<T> ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData> for Mifinity<T> {
    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Post
    }
    
    fn get_headers(
        &self,
        req: &RouterDataV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        self.build_headers(req)
    }
    
    fn get_url(
        &self,
        _req: &RouterDataV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("DefendDispute flow not supported".to_string()).into())
    }
    
    fn get_request_body(
        &self,
        _req: &RouterDataV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<Option<common_utils::request::RequestContent>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("DefendDispute flow not supported".to_string()).into())
    }
    
    fn handle_response_v2(
        &self,
        _data: &RouterDataV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>,
        _res: Response,
        _event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<
        RouterDataV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>,
        errors::ConnectorError,
    > {
        Err(errors::ConnectorError::NotImplemented("DefendDispute flow not supported".to_string()).into())
    }
    
    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
    
    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
}

// Stub implementations for tokenization flows
impl<T> ConnectorIntegrationV2<PaymentMethodToken, PaymentMethodTokenizationData<T>, PaymentMethodTokenResponse> for Mifinity<T> {
    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Post
    }
    
    fn get_headers(
        &self,
        req: &RouterDataV2<PaymentMethodToken, PaymentMethodTokenizationData<T>, PaymentMethodTokenResponse>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        self.build_headers(req)
    }
    
    fn get_url(
        &self,
        _req: &RouterDataV2<PaymentMethodToken, PaymentMethodTokenizationData<T>, PaymentMethodTokenResponse>,
        _connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("PaymentMethodToken flow not supported".to_string()).into())
    }
    
    fn get_request_body(
        &self,
        _req: &RouterDataV2<PaymentMethodToken, PaymentMethodTokenizationData<T>, PaymentMethodTokenResponse>,
        _connectors: &Connectors,
    ) -> CustomResult<Option<common_utils::request::RequestContent>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("PaymentMethodToken flow not supported".to_string()).into())
    }
    
    fn handle_response_v2(
        &self,
        _data: &RouterDataV2<PaymentMethodToken, PaymentMethodTokenizationData<T>, PaymentMethodTokenResponse>,
        _res: Response,
        _event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<
        RouterDataV2<PaymentMethodToken, PaymentMethodTokenizationData<T>, PaymentMethodTokenResponse>,
        errors::ConnectorError,
    > {
        Err(errors::ConnectorError::NotImplemented("PaymentMethodToken flow not supported".to_string()).into())
    }
    
    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
    
    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
}

impl<T> ConnectorIntegrationV2<PreAuthenticate, PaymentsPreAuthenticateData<T>, PaymentsResponseData> for Mifinity<T> {
    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Post
    }
    
    fn get_headers(
        &self,
        req: &RouterDataV2<PreAuthenticate, PaymentsPreAuthenticateData<T>, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        self.build_headers(req)
    }
    
    fn get_url(
        &self,
        _req: &RouterDataV2<PreAuthenticate, PaymentsPreAuthenticateData<T>, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("PreAuthenticate flow not supported".to_string()).into())
    }
    
    fn get_request_body(
        &self,
        _req: &RouterDataV2<PreAuthenticate, PaymentsPreAuthenticateData<T>, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<Option<common_utils::request::RequestContent>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("PreAuthenticate flow not supported".to_string()).into())
    }
    
    fn handle_response_v2(
        &self,
        _data: &RouterDataV2<PreAuthenticate, PaymentsPreAuthenticateData<T>, PaymentsResponseData>,
        _res: Response,
        _event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<
        RouterDataV2<PreAuthenticate, PaymentsPreAuthenticateData<T>, PaymentsResponseData>,
        errors::ConnectorError,
    > {
        Err(errors::ConnectorError::NotImplemented("PreAuthenticate flow not supported".to_string()).into())
    }
    
    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
    
    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
}

impl<T> ConnectorIntegrationV2<Authenticate, PaymentsAuthenticateData<T>, PaymentsResponseData> for Mifinity<T> {
    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Post
    }
    
    fn get_headers(
        &self,
        req: &RouterDataV2<Authenticate, PaymentsAuthenticateData<T>, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        self.build_headers(req)
    }
    
    fn get_url(
        &self,
        _req: &RouterDataV2<Authenticate, PaymentsAuthenticateData<T>, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("Authenticate flow not supported".to_string()).into())
    }
    
    fn get_request_body(
        &self,
        _req: &RouterDataV2<Authenticate, PaymentsAuthenticateData<T>, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<Option<common_utils::request::RequestContent>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("Authenticate flow not supported".to_string()).into())
    }
    
    fn handle_response_v2(
        &self,
        _data: &RouterDataV2<Authenticate, PaymentsAuthenticateData<T>, PaymentsResponseData>,
        _res: Response,
        _event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<
        RouterDataV2<Authenticate, PaymentsAuthenticateData<T>, PaymentsResponseData>,
        errors::ConnectorError,
    > {
        Err(errors::ConnectorError::NotImplemented("Authenticate flow not supported".to_string()).into())
    }
    
    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
    
    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
}

impl<T> ConnectorIntegrationV2<PostAuthenticate, PaymentsPostAuthenticateData<T>, PaymentsResponseData> for Mifinity<T> {
    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Post
    }
    
    fn get_headers(
        &self,
        req: &RouterDataV2<PostAuthenticate, PaymentsPostAuthenticateData<T>, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        self.build_headers(req)
    }
    
    fn get_url(
        &self,
        _req: &RouterDataV2<PostAuthenticate, PaymentsPostAuthenticateData<T>, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("PostAuthenticate flow not supported".to_string()).into())
    }
    
    fn get_request_body(
        &self,
        _req: &RouterDataV2<PostAuthenticate, PaymentsPostAuthenticateData<T>, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<Option<common_utils::request::RequestContent>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("PostAuthenticate flow not supported".to_string()).into())
    }
    
    fn handle_response_v2(
        &self,
        _data: &RouterDataV2<PostAuthenticate, PaymentsPostAuthenticateData<T>, PaymentsResponseData>,
        _res: Response,
        _event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<
        RouterDataV2<PostAuthenticate, PaymentsPostAuthenticateData<T>, PaymentsResponseData>,
        errors::ConnectorError,
    > {
        Err(errors::ConnectorError::NotImplemented("PostAuthenticate flow not supported".to_string()).into())
    }
    
    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
    
    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
}

impl<T> ConnectorIntegrationV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData> for Mifinity<T> {
    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Post
    }
    
    fn get_headers(
        &self,
        req: &RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        self.build_headers(req)
    }
    
    fn get_url(
        &self,
        _req: &RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("RepeatPayment flow not supported".to_string()).into())
    }
    
    fn get_request_body(
        &self,
        _req: &RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<Option<common_utils::request::RequestContent>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("RepeatPayment flow not supported".to_string()).into())
    }
    
    fn handle_response_v2(
        &self,
        _data: &RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>,
        _res: Response,
        _event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<
        RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>,
        errors::ConnectorError,
    > {
        Err(errors::ConnectorError::NotImplemented("RepeatPayment flow not supported".to_string()).into())
    }
    
    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
    
    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
}

impl<T> ConnectorIntegrationV2<CreateConnectorCustomer, PaymentFlowData, ConnectorCustomerData, ConnectorCustomerResponse> for Mifinity<T> {
    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Post
    }
    
    fn get_headers(
        &self,
        req: &RouterDataV2<CreateConnectorCustomer, PaymentFlowData, ConnectorCustomerData, ConnectorCustomerResponse>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        self.build_headers(req)
    }
    
    fn get_url(
        &self,
        _req: &RouterDataV2<CreateConnectorCustomer, PaymentFlowData, ConnectorCustomerData, ConnectorCustomerResponse>,
        _connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("CreateConnectorCustomer flow not supported".to_string()).into())
    }
    
    fn get_request_body(
        &self,
        _req: &RouterDataV2<CreateConnectorCustomer, PaymentFlowData, ConnectorCustomerData, ConnectorCustomerResponse>,
        _connectors: &Connectors,
    ) -> CustomResult<Option<common_utils::request::RequestContent>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("CreateConnectorCustomer flow not supported".to_string()).into())
    }
    
    fn handle_response_v2(
        &self,
        _data: &RouterDataV2<CreateConnectorCustomer, PaymentFlowData, ConnectorCustomerData, ConnectorCustomerResponse>,
        _res: Response,
        _event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<
        RouterDataV2<CreateConnectorCustomer, PaymentFlowData, ConnectorCustomerData, ConnectorCustomerResponse>,
        errors::ConnectorError,
    > {
        Err(errors::ConnectorError::NotImplemented("CreateConnectorCustomer flow not supported".to_string()).into())
    }
    
    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
    
    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
}

impl<T> ConnectorIntegrationV2<VoidPC, PaymentFlowData, PaymentsCancelPostCaptureData, PaymentsResponseData> for Mifinity<T> {
    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Post
    }
    
    fn get_headers(
        &self,
        req: &RouterDataV2<VoidPC, PaymentFlowData, PaymentsCancelPostCaptureData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        self.build_headers(req)
    }
    
    fn get_url(
        &self,
        _req: &RouterDataV2<VoidPC, PaymentFlowData, PaymentsCancelPostCaptureData, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("VoidPC flow not supported".to_string()).into())
    }
    
    fn get_request_body(
        &self,
        _req: &RouterDataV2<VoidPC, PaymentFlowData, PaymentsCancelPostCaptureData, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<Option<common_utils::request::RequestContent>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("VoidPC flow not supported".to_string()).into())
    }
    
    fn handle_response_v2(
        &self,
        _data: &RouterDataV2<VoidPC, PaymentFlowData, PaymentsCancelPostCaptureData, PaymentsResponseData>,
        _res: Response,
        _event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<
        RouterDataV2<VoidPC, PaymentFlowData, PaymentsCancelPostCaptureData, PaymentsResponseData>,
        errors::ConnectorError,
    > {
        Err(errors::ConnectorError::NotImplemented("VoidPC flow not supported".to_string()).into())
    }
    
    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
    
    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
}

impl<T> ConnectorSpecifications for Mifinity<T> {
    fn get_connector_about(&self) -> Option<&'static domain_types::types::ConnectorInfo> {
        None
    }
    
    fn get_supported_webhook_flows(&self) -> Option<&'static [common_enums::EventClass]> {
        None
    }
    
    fn get_supported_payment_methods(&self) -> Option<&'static domain_types::types::SupportedPaymentMethods> {
        None
    }
}