pub mod transformers;
use common_utils::Maskable;

use common_enums;
use common_utils::{
    consts, errors::CustomResult, ext_traits::ByteSliceExt, request::RequestContent,
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
        ConnectorCustomerResponse, ConnectorSpecifications, ConnectorWebhookSecrets,
        DisputeDefendData, DisputeFlowData, DisputeResponseData, EventType, PaymentCreateOrderData,
        PaymentCreateOrderResponse, PaymentFlowData, PaymentMethodTokenResponse,
        PaymentMethodTokenizationData, PaymentVoidData, PaymentsAuthenticateData,
        PaymentsAuthorizeData, PaymentsCancelPostCaptureData, PaymentsCaptureData,
        PaymentsPostAuthenticateData, PaymentsPreAuthenticateData, PaymentsResponseData,
        PaymentsSyncData, RefundFlowData, RefundSyncData, RefundWebhookDetailsResponse,
        RefundsData, RefundsResponseData, RepeatPaymentData, RequestDetails, ResponseId,
        SessionTokenRequestData, SessionTokenResponseData, SetupMandateRequestData,
        SubmitEvidenceData, WebhookDetailsResponse,
    },
    errors::{self, ConnectorError},
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
};
use error_stack::ResultExt;
// use crate::masking::Maskable;
use interfaces::{
    api::ConnectorCommon,
    connector_integration_v2::ConnectorIntegrationV2,
    connector_types::{self, AcceptDispute, ConnectorServiceTrait, DisputeDefend, IncomingWebhook},
    events::connector_api_logs::ConnectorEvent,
    verification::SourceVerification,
};
use serde::Serialize;
use self::transformers::{
    get_trans_id, AuthorizedotnetAuthorizeResponse, AuthorizedotnetCaptureRequest,
    AuthorizedotnetCaptureResponse, AuthorizedotnetCreateConnectorCustomerRequest,
    AuthorizedotnetCreateConnectorCustomerResponse, AuthorizedotnetCreateSyncRequest,
    AuthorizedotnetIncomingWebhookEventType, AuthorizedotnetWebhookObjectId,
    AuthorizedotnetPaymentsRequest, AuthorizedotnetPSyncResponse, AuthorizedotnetRefundRequest,
    AuthorizedotnetRefundResponse, AuthorizedotnetRSyncRequest, AuthorizedotnetRSyncResponse,
    AuthorizedotnetSetupMandateRequest, AuthorizedotnetSetupMandateResponse,
    AuthorizedotnetVoidRequest, AuthorizedotnetVoidResponse, AuthorizedotnetRepeatPaymentRequest,
    AuthorizedotnetRepeatPaymentResponse, SyncStatus,
};

pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const AUTHORIZATION: &str = "Authorization";
}

#[derive(Clone)]
pub struct Authorizedotnet<T> {
    _phantom: std::marker::PhantomData<T>,
}

impl<T> Authorizedotnet<T> {
    pub const fn new() -> &'static Self {
        &Self {
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    connector_types::ValidationTrait for Authorizedotnet<T>
{
    fn should_do_order_create(&self) -> bool {
        true
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    connector_types::ConnectorServiceTrait<T> for Authorizedotnet<T>
{
    type Error = errors::ConnectorError;
}

impl<T> ConnectorCommon for Authorizedotnet<T> {
    fn id(&self) -> &'static str {
        "authorizedotnet"
    }
    
    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }
    
    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.authorizedotnet.base_url.as_ref()
    }
    
    fn build_error_response(
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: transformers::ResponseMessages = res
            .response
            .parse_struct("ResponseMessages")
            .map_err(|_| ConnectorError::ResponseDeserializationFailed)?;
        with_response_body!(event_builder, response);
        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response
                .message
                .first()
                .map(|m| m.code.clone())
                .unwrap_or_else(|| consts::NO_ERROR_CODE.to_string()),
            message: response
                .message
                .first()
                .map(|m| m.text.clone())
                .unwrap_or_else(|| consts::NO_ERROR_MESSAGE.to_string()),
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

impl<T> connector_types::IncomingWebhook for Authorizedotnet<T> {
    fn get_event_type(
        request: RequestDetails,
        _connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorAuthType>,
    ) -> Result<EventType, error_stack::Report<ConnectorError>> {
        let webhook_body: AuthorizedotnetWebhookObjectId = request
            .parse_struct("AuthorizedotnetWebhookObjectId")
            .change_context(ConnectorError::WebhookResourceObjectNotFound)
            .attach_printable("Failed to parse Authorize.Net webhook body structure")?;
        
        Ok(match webhook_body.event_type {
            AuthorizedotnetIncomingWebhookEventType::AuthorizationCreated => {
                EventType::PaymentIntentAuthorizationSuccess
            }
            AuthorizedotnetIncomingWebhookEventType::PriorAuthCapture
            | AuthorizedotnetIncomingWebhookEventType::CaptureCreated => {
                EventType::PaymentIntentCaptureSuccess
            }
            AuthorizedotnetIncomingWebhookEventType::AuthCapCreated => {
                EventType::PaymentIntentSuccess // Combined auth+capture
            }
            AuthorizedotnetIncomingWebhookEventType::VoidCreated => {
                EventType::PaymentIntentCancelled
            }
            AuthorizedotnetIncomingWebhookEventType::RefundCreated => {
                EventType::RefundSuccess
            }
            AuthorizedotnetIncomingWebhookEventType::CustomerCreated
            | AuthorizedotnetIncomingWebhookEventType::CustomerPaymentProfileCreated => {
                EventType::MandateActive
            }
            AuthorizedotnetIncomingWebhookEventType::Unknown => {
                return Err(
                    error_stack::report!(ConnectorError::WebhookEventTypeNotFound)
                        .attach_printable("Unknown webhook event type"),
                )
            }
        })
    }
    
    fn process_payment_webhook(
        request: RequestDetails,
        _connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorAuthType>,
    ) -> Result<WebhookDetailsResponse, error_stack::Report<ConnectorError>> {
        let request_body_copy = request.body.clone();
        let webhook_body: AuthorizedotnetWebhookObjectId = request
            .parse_struct("AuthorizedotnetWebhookObjectId")
            .change_context(ConnectorError::WebhookResourceObjectNotFound)
            .attach_printable("Failed to parse Authorize.Net payment webhook body structure")?;
        let transaction_id = get_trans_id(&webhook_body).attach_printable_lazy(|| {
            format!(
                "Failed to extract transaction ID from payment webhook for event: {:?}",
                webhook_body.event_type
            )
        })?;
        let status = SyncStatus::from(webhook_body.event_type.clone());
        Ok(WebhookDetailsResponse {
            resource_id: Some(ResponseId::ConnectorTransactionId(transaction_id.clone())),
            status: common_enums::AttemptStatus::from(status),
            status_code: 200,
            mandate_reference: None,
            connector_response_reference_id: Some(transaction_id),
            error_code: None,
            error_message: None,
            raw_connector_response: Some(String::from_utf8_lossy(&request_body_copy).to_string()),
            response_headers: None,
            minor_amount_captured: None,
            amount_captured: None,
            error_reason: None,
            network_txn_id: None,
            transformation_status: common_enums::WebhookTransformationStatus::Complete,
        })
    }
    
    fn process_refund_webhook(
        request: RequestDetails,
        _connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorAuthType>,
    ) -> Result<RefundWebhookDetailsResponse, error_stack::Report<ConnectorError>> {
        let webhook_body: AuthorizedotnetWebhookObjectId = request
            .parse_struct("AuthorizedotnetWebhookObjectId")
            .change_context(ConnectorError::WebhookResourceObjectNotFound)
            .attach_printable("Failed to parse Authorize.Net refund webhook body structure")?;
        let transaction_id = get_trans_id(&webhook_body).attach_printable_lazy(|| {
            format!(
                "Failed to extract transaction ID from refund webhook for event: {:?}",
                webhook_body.event_type
            )
        })?;
        Ok(RefundWebhookDetailsResponse {
            connector_refund_id: Some(transaction_id.clone()),
            status: common_enums::RefundStatus::Success, // Authorize.Net only sends successful refund webhooks
            error_code: None,
            error_message: None,
        })
    }
}

// Stub implementations for unsupported flows
impl<T> ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData> for Authorizedotnet<T> {
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

impl<T> ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData> for Authorizedotnet<T> {
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

impl<T> ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData> for Authorizedotnet<T> {
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

impl<T> ConnectorIntegrationV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData> for Authorizedotnet<T> {
    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Post
    }
    
    fn get_url(
        &self,
        req: &RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(self.connector_base_url_payments(req).to_string())
    }
    
    fn get_request_body(
        &self,
        req: &RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let connector_req = AuthorizedotnetRepeatPaymentRequest::try_from(req)?;
        Ok(Some(RequestContent::Json(Box::new(connector_req))))
    }
    
    fn handle_response_v2(
        &self,
        data: &RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<
        RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>,
        errors::ConnectorError,
    > {
        let response: AuthorizedotnetRepeatPaymentResponse = res
            .response
            .parse_struct("AuthorizedotnetRepeatPaymentResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        with_response_body!(event_builder, response);
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
    
    fn connector_base_url_payments<F, Req, Res>(
        &self,
        req: &RouterDataV2<F, PaymentFlowData, Req, Res>,
    ) -> String {
        let base_url = &req.resource_common_data.connectors.authorizedotnet.base_url;
        base_url.to_string()
    }
}

impl<T> ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData> for Authorizedotnet<T> {
    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Post
    }
    
    fn get_url(
        &self,
        req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(self.connector_base_url_payments(req).to_string())
    }
    
    fn get_request_body(
        &self,
        req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let connector_req = AuthorizedotnetVoidRequest::try_from(req)?;
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
        let response: AuthorizedotnetVoidResponse = res
            .response
            .parse_struct("AuthorizedotnetVoidResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        with_response_body!(event_builder, response);
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
    
    fn connector_base_url_payments<F, Req, Res>(
        &self,
        req: &RouterDataV2<F, PaymentFlowData, Req, Res>,
    ) -> String {
        let base_url = &req.resource_common_data.connectors.authorizedotnet.base_url;
        base_url.to_string()
    }
}

// Empty implementation for Refund flow to satisfy trait bounds
// The actual refund logic is handled by the specific implementations in transformers.rs
impl<T> ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
    for Authorizedotnet<T>
{
    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Post
    }
    
    fn get_headers(
        &self,
        req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        self.build_headers(req)
    }
    
    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }
    
    fn get_url(
        &self,
        req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> CustomResult<String, ConnectorError> {
        Ok(self.connector_base_url_refunds(req).to_string())
    }
    
    fn get_request_body(
        &self,
        _req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> CustomResult<Option<RequestContent>, ConnectorError> {
        // This is a placeholder implementation
        // The actual refund logic should be handled by specific implementations
        Err(ConnectorError::NotImplemented("Refund not implemented for generic type".into()).into())
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
        Err(errors::ConnectorError::NotImplemented("Refund response handling not implemented".to_string()).into())
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
    
    fn build_headers<F, FCD, Req, Res>(
        &self,
        req: &RouterDataV2<F, FCD, Req, Res>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        let mut header = vec![(
            headers::CONTENT_TYPE.to_string(),
            "application/json".to_string().into(),
        )];
        let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
        header.append(&mut api_key);
        Ok(header)
    }
    
    fn connector_base_url_refunds<F, Req, Res>(
        &self,
        req: &RouterDataV2<F, RefundFlowData, Req, Res>,
    ) -> String {
        req.resource_common_data.connectors.authorizedotnet.base_url.to_string()
    }
    
    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        // Implementation for getting auth header
        Ok(vec![])
    }
}

// Implement RSync flow
impl<T> ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData> for Authorizedotnet<T> {
    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Post
    }
    
    fn get_url(
        &self,
        req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(self.connector_base_url_refunds(req).to_string())
    }
    
    fn get_request_body(
        &self,
        req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let connector_req = AuthorizedotnetRSyncRequest::try_from(req)?;
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
        let response: AuthorizedotnetRSyncResponse = res
            .response
            .parse_struct("AuthorizedotnetRSyncResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        with_response_body!(event_builder, response);
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
    
    fn connector_base_url_refunds<F, Req, Res>(
        &self,
        req: &RouterDataV2<F, RefundFlowData, Req, Res>,
    ) -> String {
        req.resource_common_data.connectors.authorizedotnet.base_url.to_string()
    }
}

// Implement SetupMandate flow
impl<T> ConnectorIntegrationV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData> for Authorizedotnet<T> {
    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Post
    }
    
    fn get_url(
        &self,
        req: &RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(self.connector_base_url_payments(req).to_string())
    }
    
    fn get_request_body(
        &self,
        req: &RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let connector_req = AuthorizedotnetSetupMandateRequest::try_from(req)?;
        Ok(Some(RequestContent::Json(Box::new(connector_req))))
    }
    
    fn handle_response_v2(
        &self,
        data: &RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<
        RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>,
        errors::ConnectorError,
    > {
        let response: AuthorizedotnetSetupMandateResponse = res
            .response
            .parse_struct("AuthorizedotnetSetupMandateResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        with_response_body!(event_builder, response);
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
    
    fn connector_base_url_payments<F, Req, Res>(
        &self,
        req: &RouterDataV2<F, PaymentFlowData, Req, Res>,
    ) -> String {
        let base_url = &req.resource_common_data.connectors.authorizedotnet.base_url;
        base_url.to_string()
    }
}

// Implement CreateConnectorCustomer flow
impl<T> ConnectorIntegrationV2<CreateConnectorCustomer, PaymentFlowData, ConnectorCustomerData, ConnectorCustomerResponse> for Authorizedotnet<T> {
    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Post
    }
    
    fn get_url(
        &self,
        req: &RouterDataV2<CreateConnectorCustomer, PaymentFlowData, ConnectorCustomerData, ConnectorCustomerResponse>,
        _connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(self.connector_base_url_payments(req).to_string())
    }
    
    fn get_request_body(
        &self,
        req: &RouterDataV2<CreateConnectorCustomer, PaymentFlowData, ConnectorCustomerData, ConnectorCustomerResponse>,
        _connectors: &Connectors,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let connector_req = AuthorizedotnetCreateConnectorCustomerRequest::try_from(req)?;
        Ok(Some(RequestContent::Json(Box::new(connector_req))))
    }
    
    fn handle_response_v2(
        &self,
        data: &RouterDataV2<CreateConnectorCustomer, PaymentFlowData, ConnectorCustomerData, ConnectorCustomerResponse>,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<
        RouterDataV2<CreateConnectorCustomer, PaymentFlowData, ConnectorCustomerData, ConnectorCustomerResponse>,
        errors::ConnectorError,
    > {
        let response: AuthorizedotnetCreateConnectorCustomerResponse = res
            .response
            .parse_struct("AuthorizedotnetCreateConnectorCustomerResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        with_response_body!(event_builder, response);
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
    
    fn connector_base_url_payments<F, Req, Res>(
        &self,
        req: &RouterDataV2<F, PaymentFlowData, Req, Res>,
    ) -> String {
        let base_url = &req.resource_common_data.connectors.authorizedotnet.base_url;
        base_url.to_string()
    }
}

// Stub implementations for unsupported flows
impl<T> ConnectorIntegrationV2<
    CreateOrder,
    PaymentFlowData,
    PaymentCreateOrderData,
    PaymentCreateOrderResponse,
> for Authorizedotnet<T> {
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

// Stub implementations for tokenization flows
impl<T> ConnectorIntegrationV2<PaymentMethodToken, PaymentMethodTokenizationData<T>, PaymentMethodTokenResponse> for Authorizedotnet<T> {
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

impl<T> ConnectorIntegrationV2<PreAuthenticate, PaymentsPreAuthenticateData<T>, PaymentsResponseData> for Authorizedotnet<T> {
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

impl<T> ConnectorIntegrationV2<Authenticate, PaymentsAuthenticateData<T>, PaymentsResponseData> for Authorizedotnet<T> {
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

impl<T> ConnectorIntegrationV2<PostAuthenticate, PaymentsPostAuthenticateData<T>, PaymentsResponseData> for Authorizedotnet<T> {
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

// SourceVerification implementations for all flows
impl<T> interfaces::verification::SourceVerification<
    Authorize,
    PaymentFlowData,
    PaymentsAuthorizeData<T>,
    PaymentsResponseData,
> for Authorizedotnet<T> {
    fn verify_source(
        &self,
        _request: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<bool, errors::ConnectorError> {
        Ok(true)
    }
}

impl<T> interfaces::verification::SourceVerification<
    PSync,
    PaymentFlowData,
    PaymentsSyncData,
    PaymentsResponseData,
> for Authorizedotnet<T> {
    fn verify_source(
        &self,
        _request: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<bool, errors::ConnectorError> {
        Ok(true)
    }
}

impl<T> interfaces::verification::SourceVerification<
    Capture,
    PaymentFlowData,
    PaymentsCaptureData,
    PaymentsResponseData,
> for Authorizedotnet<T> {
    fn verify_source(
        &self,
        _request: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<bool, errors::ConnectorError> {
        Ok(true)
    }
}

impl<T> interfaces::verification::SourceVerification<
    Void,
    PaymentFlowData,
    PaymentVoidData,
    PaymentsResponseData,
> for Authorizedotnet<T> {
    fn verify_source(
        &self,
        _request: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<bool, errors::ConnectorError> {
        Ok(true)
    }
}

impl<T> interfaces::verification::SourceVerification<
    Refund,
    RefundFlowData,
    RefundsData,
    RefundsResponseData,
> for Authorizedotnet<T> {
    fn verify_source(
        &self,
        _request: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<bool, errors::ConnectorError> {
        Ok(true)
    }
}

impl<T> interfaces::verification::SourceVerification<
    RSync,
    RefundFlowData,
    RefundSyncData,
    RefundsResponseData,
> for Authorizedotnet<T> {
    fn verify_source(
        &self,
        _request: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<bool, errors::ConnectorError> {
        Ok(true)
    }
}

impl<T> interfaces::verification::SourceVerification<
    SetupMandate,
    PaymentFlowData,
    SetupMandateRequestData<T>,
    PaymentsResponseData,
> for Authorizedotnet<T> {
    fn verify_source(
        &self,
        _request: &RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<bool, errors::ConnectorError> {
        Ok(true)
    }
}

impl<T> interfaces::verification::SourceVerification<
    RepeatPayment,
    PaymentFlowData,
    RepeatPaymentData,
    PaymentsResponseData,
> for Authorizedotnet<T> {
    fn verify_source(
        &self,
        _request: &RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<bool, errors::ConnectorError> {
        Ok(true)
    }
}

impl<T> interfaces::verification::SourceVerification<
    CreateConnectorCustomer,
    PaymentFlowData,
    ConnectorCustomerData,
    ConnectorCustomerResponse,
> for Authorizedotnet<T> {
    fn verify_source(
        &self,
        _request: &RouterDataV2<CreateConnectorCustomer, PaymentFlowData, ConnectorCustomerData, ConnectorCustomerResponse>,
        _connectors: &Connectors,
    ) -> CustomResult<bool, errors::ConnectorError> {
        Ok(true)
    }
}

impl<T> interfaces::verification::SourceVerification<
    Accept,
    DisputeFlowData,
    AcceptDisputeData,
    DisputeResponseData,
> for Authorizedotnet<T> {
    fn verify_source(
        &self,
        _request: &RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<bool, errors::ConnectorError> {
        Ok(true)
    }
}

impl<T> interfaces::verification::SourceVerification<
    SubmitEvidence,
    DisputeFlowData,
    SubmitEvidenceData,
    DisputeResponseData,
> for Authorizedotnet<T> {
    fn verify_source(
        &self,
        _request: &RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<bool, errors::ConnectorError> {
        Ok(true)
    }
}

impl<T> interfaces::verification::SourceVerification<
    DefendDispute,
    DisputeFlowData,
    DisputeDefendData,
    DisputeResponseData,
> for Authorizedotnet<T> {
    fn verify_source(
        &self,
        _request: &RouterDataV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<bool, errors::ConnectorError> {
        Ok(true)
    }
}

impl<T> interfaces::verification::SourceVerification<
    VoidPC,
    PaymentFlowData,
    PaymentsCancelPostCaptureData,
    PaymentsResponseData,
> for Authorizedotnet<T> {
    fn verify_source(
        &self,
        _request: &RouterDataV2<VoidPC, PaymentFlowData, PaymentsCancelPostCaptureData, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<bool, errors::ConnectorError> {
        Ok(true)
    }
}

impl<T> ConnectorSpecifications for Authorizedotnet<T> {
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