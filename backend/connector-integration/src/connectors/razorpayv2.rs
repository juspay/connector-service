pub mod test;
use common_utils::Maskable;
pub mod transformers;
use common_enums::AttemptStatus;
use common_utils::{
    errors::CustomResult,
    ext_traits::BytesExt,
    request::RequestContent,
    types::{AmountConvertor, MinorUnit},
};
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
    errors,
    payment_method_data::{DefaultPCIHolder, PaymentMethodData, PaymentMethodDataTypes},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
};
use error_stack::ResultExt;
// use crate::masking::Maskable;
use interfaces::{
    api::ConnectorCommon,
    connector_integration_v2::ConnectorIntegrationV2,
    connector_types::{self},
    events::connector_api_logs::ConnectorEvent,
};
use serde::Serialize;
use transformers as razorpayv2;

use crate::connectors::razorpay::transformers::ForeignTryFrom;

pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const AUTHORIZATION: &str = "Authorization";
}

#[derive(Clone)]
pub struct RazorpayV2<T> {
    #[allow(dead_code)]
    pub(crate) amount_converter: &'static (dyn AmountConvertor<Output = MinorUnit> + Sync),
    _phantom: std::marker::PhantomData<T>,
}

impl<T> RazorpayV2<T> {
    pub const fn new() -> &'static Self {
        &Self {
            amount_converter: &common_utils::types::MinorUnitForConnector,
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
    > interfaces::connector_types::ValidationTrait for RazorpayV2<T>
{
    fn should_do_order_create(&self) -> bool {
        true
    }
}

impl<T> ConnectorCommon for RazorpayV2<T> {
    fn id(&self) -> &'static str {
        "razorpayv2"
    }
    
    fn get_currency_unit(&self) -> common_enums::CurrencyUnit {
        common_enums::CurrencyUnit::Base
    }
    
    fn get_auth_header(
        &self,
        auth_type: &domain_types::router_data::ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth = razorpayv2::RazorpayV2AuthType::try_from(auth_type)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        Ok(vec![(
            headers::AUTHORIZATION.to_string(),
            auth.generate_authorization_header().into(),
        )])
    }
    
    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        &connectors.razorpayv2.base_url
    }
    
    fn build_error_response(
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        let response: razorpayv2::RazorpayV2ErrorResponse = res
            .response
            .parse_struct("RazorpayV2ErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        if let Some(i) = event_builder {
            i.set_error_response_body(&response);
        }
        let (code, message, attempt_status) = match response {
            razorpayv2::RazorpayV2ErrorResponse::StandardError { error } => {
                let attempt_status = match error.code.as_str() {
                    "BAD_REQUEST_ERROR" => AttemptStatus::Failure,
                    "GATEWAY_ERROR" => AttemptStatus::Failure,
                    "AUTHENTICATION_ERROR" => AttemptStatus::AuthenticationFailed,
                    "AUTHORIZATION_ERROR" => AttemptStatus::AuthorizationFailed,
                    "SERVER_ERROR" => AttemptStatus::Pending,
                    _ => AttemptStatus::Pending,
                };
                (error.code, error.description, Some(attempt_status))
            }
            razorpayv2::RazorpayV2ErrorResponse::SimpleError { message } => {
                (message.clone(), message.clone(), None)
            }
        };
        Ok(domain_types::router_data::ErrorResponse {
            status_code: res.status_code,
            code,
            message,
            reason: None,
            attempt_status,
            connector_transaction_id: None,
            network_decline_code: None,
            network_advice_code: None,
            network_error_message: None,
        })
    }
}

// Stub implementations for all flows
impl<T> ConnectorIntegrationV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData> for RazorpayV2<T> {
    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Post
    }
    
    fn get_url(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(format!(
            "{}/payments",
            self.base_url(&req.resource_common_data.connectors)
        ))
    }
    
    fn get_request_body(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let connector_req = razorpayv2::RazorpayV2PaymentsRequest::try_from(req)?;
        Ok(Some(RequestContent::Json(Box::new(connector_req))))
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
        let response: razorpayv2::RazorpayV2PaymentsResponse = res
            .response
            .parse_struct("RazorpayV2PaymentsResponse")
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
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
    
    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
}

impl<T> ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData> for RazorpayV2<T> {
    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Get
    }
    
    fn get_url(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        let payment_id = match &req.request.connector_transaction_id {
            ResponseId::ConnectorTransactionId(id) => id,
            ResponseId::NoResponseId => {
                return Err(errors::ConnectorError::MissingConnectorTransactionID.into())
            }
        };
        Ok(format!(
            "{}/payments/{}",
            self.base_url(&req.resource_common_data.connectors),
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
        let response: razorpayv2::RazorpayV2SyncResponse = res
            .response
            .parse_struct("RazorpayV2SyncResponse")
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
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
    
    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
}

impl<T> ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData> for RazorpayV2<T> {
    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Post
    }
    
    fn get_url(
        &self,
        req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        let payment_id = match &req.request.connector_transaction_id {
            ResponseId::ConnectorTransactionId(id) => id,
            ResponseId::NoResponseId => {
                return Err(errors::ConnectorError::MissingConnectorTransactionID.into())
            }
        };
        Ok(format!(
            "{}/payments/{}/capture",
            self.base_url(&req.resource_common_data.connectors),
            payment_id
        ))
    }
    
    fn get_request_body(
        &self,
        req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let connector_req = razorpayv2::RazorpayV2CaptureRequest::try_from(req)?;
        Ok(Some(RequestContent::Json(Box::new(connector_req))))
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
        let response: razorpayv2::RazorpayV2CaptureResponse = res
            .response
            .parse_struct("RazorpayV2CaptureResponse")
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
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
    
    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
}

impl<T> ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData> for RazorpayV2<T> {
    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Post
    }
    
    fn get_url(
        &self,
        req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        let payment_id = match &req.request.connector_transaction_id {
            ResponseId::ConnectorTransactionId(id) => id,
            ResponseId::NoResponseId => {
                return Err(errors::ConnectorError::MissingConnectorTransactionID.into())
            }
        };
        Ok(format!(
            "{}/payments/{}/refund",
            self.base_url(&req.resource_common_data.connectors),
            payment_id
        ))
    }
    
    fn get_request_body(
        &self,
        req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let connector_req = razorpayv2::RazorpayV2RefundRequest::try_from(req)?;
        Ok(Some(RequestContent::Json(Box::new(connector_req))))
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
        let response: razorpayv2::RazorpayV2RefundResponse = res
            .response
            .parse_struct("RazorpayV2RefundResponse")
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
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
    
    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
}

impl<T> ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData> for RazorpayV2<T> {
    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Post
    }
    
    fn get_url(
        &self,
        req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        let payment_id = match &req.request.connector_transaction_id {
            ResponseId::ConnectorTransactionId(id) => id,
            ResponseId::NoResponseId => {
                return Err(errors::ConnectorError::MissingConnectorTransactionID.into())
            }
        };
        Ok(format!(
            "{}/payments/{}/refund",
            self.base_url(&req.resource_common_data.connectors),
            payment_id
        ))
    }
    
    fn get_request_body(
        &self,
        req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let connector_req = razorpayv2::RazorpayV2RefundRequest::try_from(req)?;
        Ok(Some(RequestContent::Json(Box::new(connector_req))))
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
        let response: razorpayv2::RazorpayV2RefundResponse = res
            .response
            .parse_struct("RazorpayV2RefundResponse")
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
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
    
    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
}

impl<T> ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData> for RazorpayV2<T> {
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
            "{}/refunds/{}",
            self.base_url(&req.resource_common_data.connectors),
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
        let response: razorpayv2::RazorpayV2RefundSyncResponse = res
            .response
            .parse_struct("RazorpayV2RefundSyncResponse")
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
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
    
    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
}

// Stub implementations for all other flows
impl<T> ConnectorIntegrationV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse> for RazorpayV2<T> {
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
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
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
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
    
    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
}

impl<T> ConnectorIntegrationV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData> for RazorpayV2<T> {
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
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
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
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
    
    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
}

impl<T> ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData> for RazorpayV2<T> {
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
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
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
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
    
    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
}

impl<T> ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData> for RazorpayV2<T> {
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
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
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
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
    
    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
}

impl<T> ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData> for RazorpayV2<T> {
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
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
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
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
    
    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
}

// Stub implementations for tokenization flows
impl<T> ConnectorIntegrationV2<PaymentMethodToken, PaymentMethodTokenizationData<T>, PaymentMethodTokenResponse> for RazorpayV2<T> {
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
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
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
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
    
    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
}

impl<T> ConnectorIntegrationV2<PreAuthenticate, PaymentsPreAuthenticateData<T>, PaymentsResponseData> for RazorpayV2<T> {
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
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
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
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
    
    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
}

impl<T> ConnectorIntegrationV2<Authenticate, PaymentsAuthenticateData<T>, PaymentsResponseData> for RazorpayV2<T> {
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
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
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
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
    
    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
}

impl<T> ConnectorIntegrationV2<PostAuthenticate, PaymentsPostAuthenticateData<T>, PaymentsResponseData> for RazorpayV2<T> {
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
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
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
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
    
    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
}

impl<T> ConnectorIntegrationV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData> for RazorpayV2<T> {
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
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
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
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
    
    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
}

impl<T> ConnectorIntegrationV2<CreateConnectorCustomer, PaymentFlowData, ConnectorCustomerData, ConnectorCustomerResponse> for RazorpayV2<T> {
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
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
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
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
    
    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
}

impl<T> ConnectorIntegrationV2<VoidPC, PaymentFlowData, PaymentsCancelPostCaptureData, PaymentsResponseData> for RazorpayV2<T> {
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
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
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
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
    
    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        Self::build_error_response(res, event_builder)
    }
}

impl<T> ConnectorSpecifications for RazorpayV2<T> {
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