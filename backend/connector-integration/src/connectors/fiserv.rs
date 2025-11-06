use std::fmt::Debug;
use common_utils::Maskable;

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD_ENGINE, Engine};
use common_utils::{
    consts::{NO_ERROR_CODE, NO_ERROR_MESSAGE},
    errors::CustomResult,
    ext_traits::BytesExt,
    request::RequestContent,
    types::FloatMajorUnit,
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
        ConnectorCustomerResponse, ConnectorSpecifications, DisputeDefendData, DisputeFlowData,
        DisputeResponseData, PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData,
        PaymentMethodTokenResponse, PaymentMethodTokenizationData, PaymentVoidData,
        PaymentsAuthenticateData, PaymentsAuthorizeData, PaymentsCancelPostCaptureData,
        PaymentsCaptureData, PaymentsPostAuthenticateData, PaymentsPreAuthenticateData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData,
        RefundsResponseData, RepeatPaymentData, SessionTokenRequestData, SessionTokenResponseData,
        SetupMandateRequestData, SubmitEvidenceData,
    },
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
};
use error_stack::ResultExt;
// use crate::masking::{ExposeInterface, Mask, Maskable, PeekInterface};
use interfaces::{
    api::ConnectorCommon, connector_integration_v2::ConnectorIntegrationV2, connector_types,
    events::connector_api_logs::ConnectorEvent,
};
use ring::hmac;
use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;

pub mod transformers;
use transformers::{
    FiservCaptureRequest, FiservCaptureResponse, FiservPaymentsRequest, FiservPaymentsResponse,
    FiservRefundRequest, FiservRefundResponse, FiservRefundSyncRequest, FiservRefundSyncResponse,
    FiservSyncRequest, FiservSyncResponse, FiservVoidRequest, FiservVoidResponse,
    FiservAuthType,
};

use super::macros;
use crate::{types::ResponseRouterData, with_error_response_body};

// Local headers module
mod headers {
    pub const API_KEY: &str = "Api-Key";
    pub const CONTENT_TYPE: &str = "Content-Type";
    pub const TIMESTAMP: &str = "Timestamp";
    pub const CLIENT_REQUEST_ID: &str = "Client-Request-Id";
    pub const AUTH_TOKEN_TYPE: &str = "Auth-Token-Type";
    pub const AUTHORIZATION: &str = "Authorization";
}

#[derive(Clone)]
pub struct Fiserv<T> {
    _phantom: std::marker::PhantomData<T>,
}

impl<T> Fiserv<T> {
    pub const fn new() -> &'static Self {
        &Self {
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    connector_types::ValidationTrait for Fiserv<T>
{
    fn should_do_order_create(&self) -> bool {
        true
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    connector_types::ConnectorServiceTrait<T> for Fiserv<T>
{
    type Error = errors::ConnectorError;
}

impl<T> ConnectorCommon for Fiserv<T> {
    fn id(&self) -> &'static str {
        "fiserv"
    }
    
    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }
    
    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.fiserv.base_url.as_ref()
    }
    
    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth = FiservAuthType::try_from(auth_type)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        Ok(vec![(
            headers::API_KEY.to_string(),
            auth.api_key.into_masked(),
        )])
    }
    
    fn build_error_response(
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: transformers::FiservErrorResponse = res
            .response
            .parse_struct("FiservErrorResponse")
            .map_err(|_| errors::ConnectorError::ResponseDeserializationFailed)?;
        with_error_response_body!(event_builder, response);
        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response
                .error_code
                .unwrap_or_else(|| NO_ERROR_CODE.to_string()),
            message: response
                .error_message
                .unwrap_or_else(|| NO_ERROR_MESSAGE.to_string()),
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
}

impl<T> Fiserv<T> {
    pub fn generate_authorization_signature(
        &self,
        auth: &FiservAuthType,
        client_request_id: &str,
        payload_str: &str,
        timestamp_ms: i128,
    ) -> CustomResult<String, errors::ConnectorError> {
        let raw_signature = format!(
            "{}{}{}{}",
            auth.api_key.peek(),
            client_request_id,
            timestamp_ms,
            payload_str
        );
        let key = hmac::Key::new(hmac::HMAC_SHA256, auth.api_secret.clone().expose().as_bytes());
        let tag = hmac::sign(&key, raw_signature.as_bytes());
        Ok(BASE64_STANDARD_ENGINE.encode(tag.as_ref()))
    }
    
    pub fn build_headers<F, FCD, Req, Res>(
        &self,
        req: &RouterDataV2<F, FCD, Req, Res>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError>
    where
        Self: ConnectorIntegrationV2<F, FCD, Req, Res>,
    {
        let temp_request_body_for_sig = self.get_request_body(req)?;
        let payload_string_for_sig = match temp_request_body_for_sig {
            Some(RequestContent::Json(json_body)) => serde_json::to_string(&json_body)
                .change_context(errors::ConnectorError::RequestEncodingFailed)
                .attach_printable("Failed to serialize JSON request body for signature")?,
            Some(RequestContent::FormUrlEncoded(form_body)) => serde_urlencoded::to_string(&form_body)
                .attach_printable("Failed to serialize form request body for signature")?,
            None => "".to_string(),
            _ => return Err(errors::ConnectorError::RequestEncodingFailed)
                .attach_printable("Unsupported request body type for signature generation")?,
        };
        let timestamp_ms = OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000;
        let client_request_id = Uuid::new_v4().to_string();
        let auth_type_for_sig = FiservAuthType::try_from(&req.connector_auth_type)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        let signature = self.generate_authorization_signature(
            &auth_type_for_sig,
            &client_request_id,
            &payload_string_for_sig,
            timestamp_ms,
        )?;
        // Step 4: Build and return the headers
        let mut http_headers = vec![
            (headers::CONTENT_TYPE.to_string(), self.common_get_content_type().into()),
            (headers::CLIENT_REQUEST_ID.to_string(), client_request_id.into()),
            (headers::TIMESTAMP.to_string(), timestamp_ms.to_string().into()),
            (headers::AUTH_TOKEN_TYPE.to_string(), "HMAC".to_string().into()),
            (headers::AUTHORIZATION.to_string(), signature.into_masked()),
        ];
        let mut api_key_header = self.get_auth_header(&req.connector_auth_type)?;
        http_headers.append(&mut api_key_header);
        Ok(http_headers)
    }
    
    pub fn connector_base_url_payments<'a, F, Req, Res>(
        &self,
        req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
    ) -> &'a str {
        &req.resource_common_data.connectors.fiserv.base_url
    }
    
    pub fn connector_base_url_refunds<'a, F, Req, Res>(
        &self,
        req: &'a RouterDataV2<F, RefundFlowData, Req, Res>,
    ) -> &'a str {
        &req.resource_common_data.connectors.fiserv.base_url
    }
}

// Implement the main flows
impl<T> ConnectorIntegrationV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData> for Fiserv<T> {
    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Post
    }
    
    fn get_headers(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        self.build_headers(req)
    }
    
    fn get_url(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(format!(
            "{}/payments",
            self.connector_base_url_payments(req)
        ))
    }
    
    fn get_request_body(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let connector_req = FiservPaymentsRequest::try_from(req)?;
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
        let response: FiservPaymentsResponse = res
            .response
            .parse_struct("FiservPaymentsResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        with_error_response_body!(event_builder, response);
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

impl<T> ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData> for Fiserv<T> {
    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Post
    }
    
    fn get_headers(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        self.build_headers(req)
    }
    
    fn get_url(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(format!(
            "{}/payments/sync",
            self.connector_base_url_payments(req)
        ))
    }
    
    fn get_request_body(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let connector_req = FiservSyncRequest::try_from(req)?;
        Ok(Some(RequestContent::Json(Box::new(connector_req))))
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
        let response: FiservSyncResponse = res
            .response
            .parse_struct("FiservSyncResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        with_error_response_body!(event_builder, response);
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

impl<T> ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData> for Fiserv<T> {
    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Post
    }
    
    fn get_headers(
        &self,
        req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        self.build_headers(req)
    }
    
    fn get_url(
        &self,
        req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(format!(
            "{}/payments/capture",
            self.connector_base_url_payments(req)
        ))
    }
    
    fn get_request_body(
        &self,
        req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let connector_req = FiservCaptureRequest::try_from(req)?;
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
        let response: FiservCaptureResponse = res
            .response
            .parse_struct("FiservCaptureResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        with_error_response_body!(event_builder, response);
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

impl<T> ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData> for Fiserv<T> {
    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Post
    }
    
    fn get_headers(
        &self,
        req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        self.build_headers(req)
    }
    
    fn get_url(
        &self,
        req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(format!(
            "{}/payments/void",
            self.connector_base_url_payments(req)
        ))
    }
    
    fn get_request_body(
        &self,
        req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let connector_req = FiservVoidRequest::try_from(req)?;
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
        let response: FiservVoidResponse = res
            .response
            .parse_struct("FiservVoidResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        with_error_response_body!(event_builder, response);
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

impl<T> ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData> for Fiserv<T> {
    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Post
    }
    
    fn get_headers(
        &self,
        req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        self.build_headers(req)
    }
    
    fn get_url(
        &self,
        req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(format!(
            "{}/refunds",
            self.connector_base_url_refunds(req)
        ))
    }
    
    fn get_request_body(
        &self,
        req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let connector_req = FiservRefundRequest::try_from(req)?;
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
        let response: FiservRefundResponse = res
            .response
            .parse_struct("FiservRefundResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        with_error_response_body!(event_builder, response);
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

impl<T> ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData> for Fiserv<T> {
    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Post
    }
    
    fn get_headers(
        &self,
        req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        self.build_headers(req)
    }
    
    fn get_url(
        &self,
        req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(format!(
            "{}/refunds/sync",
            self.connector_base_url_refunds(req)
        ))
    }
    
    fn get_request_body(
        &self,
        req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let connector_req = FiservRefundSyncRequest::try_from(req)?;
        Ok(Some(RequestContent::Json(Box::new(connector_req))))
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
        let response: FiservRefundSyncResponse = res
            .response
            .parse_struct("FiservRefundSyncResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        with_error_response_body!(event_builder, response);
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

// Stub implementations for unsupported flows
impl<T> ConnectorIntegrationV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse> for Fiserv<T> {
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
impl<T> ConnectorIntegrationV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData> for Fiserv<T> {
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

impl<T> ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData> for Fiserv<T> {
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

impl<T> ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData> for Fiserv<T> {
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

impl<T> ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData> for Fiserv<T> {
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
impl<T> ConnectorIntegrationV2<PaymentMethodToken, PaymentMethodTokenizationData<T>, PaymentMethodTokenResponse> for Fiserv<T> {
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

impl<T> ConnectorIntegrationV2<PreAuthenticate, PaymentsPreAuthenticateData<T>, PaymentsResponseData> for Fiserv<T> {
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

impl<T> ConnectorIntegrationV2<Authenticate, PaymentsAuthenticateData<T>, PaymentsResponseData> for Fiserv<T> {
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

impl<T> ConnectorIntegrationV2<PostAuthenticate, PaymentsPostAuthenticateData<T>, PaymentsResponseData> for Fiserv<T> {
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

impl<T> ConnectorIntegrationV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData> for Fiserv<T> {
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

impl<T> ConnectorIntegrationV2<CreateConnectorCustomer, PaymentFlowData, ConnectorCustomerData, ConnectorCustomerResponse> for Fiserv<T> {
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

impl<T> ConnectorIntegrationV2<VoidPC, PaymentFlowData, PaymentsCancelPostCaptureData, PaymentsResponseData> for Fiserv<T> {
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

impl<T> ConnectorSpecifications for Fiserv<T> {
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