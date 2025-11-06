pub mod transformers;
use common_utils::Maskable;

use std::fmt::Debug;
use common_utils::{consts, errors::CustomResult, ext_traits::ByteSliceExt};
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
        RefundsResponseData, RepeatPaymentData, ResponseId, SessionTokenRequestData,
        SessionTokenResponseData, SetupMandateRequestData, SubmitEvidenceData,
    },
    errors::{self, ConnectorError},
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
};
// use crate::masking::{Mask, Maskable, PeekInterface};
use interfaces::{
    api::ConnectorCommon, connector_integration_v2::ConnectorIntegrationV2, connector_types,
    events::connector_api_logs::ConnectorEvent,
};
use serde::Serialize;
use transformers::{
    ActionResponse, CheckoutAuthorizeResponse, CheckoutErrorResponse, CheckoutPSyncResponse,
    CheckoutPaymentsRequest, CheckoutRefundSyncRequest, CheckoutSyncRequest, PaymentCaptureRequest,
    PaymentCaptureResponse, PaymentVoidRequest, PaymentVoidResponse, RefundRequest, RefundResponse,
};

use super::macros;
use crate::types::ResponseRouterData;

pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const AUTHORIZATION: &str = "Authorization";
}

#[derive(Clone)]
pub struct Checkout<T> {
    _phantom: std::marker::PhantomData<T>,
}

impl<T> Checkout<T> {
    pub const fn new() -> &'static Self {
        &Self {
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::ConnectorServiceTrait<T> for Checkout<T>
{
    type Error = errors::ConnectorError;
}

impl<T> ConnectorCommon for Checkout<T> {
    fn id(&self) -> &'static str {
        "checkout"
    }
    
    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }
    
    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth = transformers::CheckoutAuthType::try_from(auth_type)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        Ok(vec![(
            headers::AUTHORIZATION.to_string(),
            auth.get_authorization_header().into_masked(),
        )])
    }
    
    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        &connectors.checkout.base_url
    }
    
    fn build_error_response(
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: CheckoutErrorResponse = res
            .response
            .parse_struct("CheckoutErrorResponse")
            .map_err(|_| ConnectorError::ResponseDeserializationFailed)?;
        if let Some(i) = event_builder {
            i.set_error_response_body(&response);
        }
        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response.error_code.unwrap_or_else(|| consts::NO_ERROR_CODE.to_string()),
            message: response.error_message.unwrap_or_else(|| consts::NO_ERROR_MESSAGE.to_string()),
            reason: None,
            attempt_status: None,
            connector_transaction_id: None,
            network_decline_code: None,
            network_advice_code: None,
            network_error_message: None,
        })
    }
    
    fn get_currency_unit(&self) -> common_enums::CurrencyUnit {
        common_enums::CurrencyUnit::Base
    }
    
    fn connector_base_url_payments<'a, F, Req, Res>(
        &self,
        req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
    ) -> &'a str {
        &req.resource_common_data.connectors.checkout.base_url
    }
    
    fn connector_base_url_refunds<'a, F, Req, Res>(
        &self,
        req: &'a RouterDataV2<F, RefundFlowData, Req, Res>,
    ) -> &'a str {
        &req.resource_common_data.connectors.checkout.base_url
    }
}

// Implement the main flows
impl<T> ConnectorIntegrationV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData> for Checkout<T> {
    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Post
    }
    
    fn get_url(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(format!(
            "{}/v2/sessions",
            self.connector_base_url_payments(req)
        ))
    }
    
    fn get_request_body(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<Option<common_utils::request::RequestContent>, errors::ConnectorError> {
        let connector_req = CheckoutPaymentsRequest::try_from(req)?;
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
        let response: CheckoutAuthorizeResponse = res
            .response
            .parse_struct("CheckoutAuthorizeResponse")
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

impl<T> ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData> for Checkout<T> {
    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Get
    }
    
    fn get_url(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        let payment_id = req.request.connector_transaction_id.get_connector_transaction_id()
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;
        Ok(format!(
            "{}/v2/sessions/{}",
            self.connector_base_url_payments(req),
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
        let response: CheckoutPSyncResponse = res
            .response
            .parse_struct("CheckoutPSyncResponse")
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

impl<T> ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData> for Checkout<T> {
    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Post
    }
    
    fn get_url(
        &self,
        req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        let payment_id = req.request.connector_transaction_id.get_connector_transaction_id()
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;
        Ok(format!(
            "{}/v2/sessions/{}/capture",
            self.connector_base_url_payments(req),
            payment_id
        ))
    }
    
    fn get_request_body(
        &self,
        req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<Option<common_utils::request::RequestContent>, errors::ConnectorError> {
        let connector_req = PaymentCaptureRequest::try_from(req)?;
        Ok(Some(common_utils::request::RequestContent::Json(Box::new(connector_req))))
    }
    
    fn handle_response_v2(
        &self,
        data: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<
        RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        errors::ConnectorError,
    > {
        let response: PaymentCaptureResponse = res
            .response
            .parse_struct("PaymentCaptureResponse")
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

impl<T> ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData> for Checkout<T> {
    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Post
    }
    
    fn get_url(
        &self,
        req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        let payment_id = req.request.connector_transaction_id.get_connector_transaction_id()
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;
        Ok(format!(
            "{}/v2/sessions/{}/void",
            self.connector_base_url_payments(req),
            payment_id
        ))
    }
    
    fn get_request_body(
        &self,
        req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<Option<common_utils::request::RequestContent>, errors::ConnectorError> {
        let connector_req = PaymentVoidRequest::try_from(req)?;
        Ok(Some(common_utils::request::RequestContent::Json(Box::new(connector_req))))
    }
    
    fn handle_response_v2(
        &self,
        data: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<
        RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        errors::ConnectorError,
    > {
        let response: PaymentVoidResponse = res
            .response
            .parse_struct("PaymentVoidResponse")
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

impl<T> ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData> for Checkout<T> {
    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Post
    }
    
    fn get_url(
        &self,
        req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        let payment_id = req.request.connector_transaction_id.get_connector_transaction_id()
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;
        Ok(format!(
            "{}/v2/sessions/{}/refund",
            self.connector_base_url_refunds(req),
            payment_id
        ))
    }
    
    fn get_request_body(
        &self,
        req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<Option<common_utils::request::RequestContent>, errors::ConnectorError> {
        let connector_req = RefundRequest::try_from(req)?;
        Ok(Some(common_utils::request::RequestContent::Json(Box::new(connector_req))))
    }
    
    fn handle_response_v2(
        &self,
        data: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<
        RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        errors::ConnectorError,
    > {
        let response: RefundResponse = res
            .response
            .parse_struct("RefundResponse")
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

impl<T> ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData> for Checkout<T> {
    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Get
    }
    
    fn get_url(
        &self,
        req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        let refund_id = &req.request.connector_refund_id;
        Ok(format!(
            "{}/v2/refunds/{}",
            self.connector_base_url_refunds(req),
            refund_id
        ))
    }
    
    fn handle_response_v2(
        &self,
        data: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<
        RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        errors::ConnectorError,
    > {
        let response: CheckoutRefundSyncResponse = res
            .response
            .parse_struct("CheckoutRefundSyncResponse")
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
impl<T> ConnectorIntegrationV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse> for Checkout<T> {
    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Post
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
impl<T> ConnectorIntegrationV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData> for Checkout<T> {
    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Post
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

impl<T> ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData> for Checkout<T> {
    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Post
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

impl<T> ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData> for Checkout<T> {
    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Post
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

impl<T> ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData> for Checkout<T> {
    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Post
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
impl<T> ConnectorIntegrationV2<PaymentMethodToken, PaymentMethodTokenizationData<T>, PaymentMethodTokenResponse> for Checkout<T> {
    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Post
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

impl<T> ConnectorIntegrationV2<PreAuthenticate, PaymentsPreAuthenticateData<T>, PaymentsResponseData> for Checkout<T> {
    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Post
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

impl<T> ConnectorIntegrationV2<Authenticate, PaymentsAuthenticateData<T>, PaymentsResponseData> for Checkout<T> {
    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Post
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

impl<T> ConnectorIntegrationV2<PostAuthenticate, PaymentsPostAuthenticateData<T>, PaymentsResponseData> for Checkout<T> {
    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Post
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

impl<T> ConnectorIntegrationV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData> for Checkout<T> {
    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Post
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

impl<T> ConnectorIntegrationV2<CreateConnectorCustomer, PaymentFlowData, ConnectorCustomerData, ConnectorCustomerResponse> for Checkout<T> {
    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Post
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

impl<T> ConnectorIntegrationV2<VoidPC, PaymentFlowData, PaymentsCancelPostCaptureData, PaymentsResponseData> for Checkout<T> {
    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Post
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

impl<T> ConnectorSpecifications for Checkout<T> {
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