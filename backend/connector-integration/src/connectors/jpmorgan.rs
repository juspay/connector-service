use domain_types::{
    connector_flow::{self, Authorize, Capture, CreateOrder, PSync, RSync, Refund, Void},
    connector_types::{
        ConnectorEnum, EventType, PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData,
        PaymentsCaptureData, PaymentsResponseData, RefundFlowData, RefundsData, PaymentsSyncData as DomainPaymentsSyncData,
        RefundsResponseData, ConnectorServiceTrait, PaymentAuthorizeV2, PaymentSyncV2, PaymentOrderCreate, PaymentVoidV2, RefundSyncV2, RefundV2, ValidationTrait, IncomingWebhook, PaymentCreateOrderData, PaymentCreateOrderResponse, RefundSyncData as DomainRefundSyncData,
        PaymentCapture as DomainPaymentCapture,
    },
    types::Connectors as DomainConnectors,
    utils::ForeignTryFrom,
};
use error_stack::ResultExt;
use hyperswitch_api_models::enums::{self as api_enums, AttemptStatus, RefundStatus};
use hyperswitch_common_utils::{
    errors::CustomResult,
    request::{Method, RequestBuilder, RequestContent},
    headers,
    types::MinorUnit,
    ext_traits::ByteSliceExt,
};
use hyperswitch_domain_models::{
    router_data::{ConnectorAuthType, ErrorResponse, RouterData},
    router_data_v2::RouterDataV2,
    router_request_types::{PaymentsSyncData, ResponseId, RefundSyncData as HyperswitchDomainRefundSyncData},
    router_response_types::{MandateReference, RedirectForm},
};
use hyperswitch_interfaces::{
    api::{self, ConnectorCommon},
    consts::{NO_ERROR_CODE, NO_ERROR_MESSAGE},
    connector_integration_v2::ConnectorIntegrationV2,
    errors::{self, ConnectorError},
    events::connector_api_logs::ConnectorEvent,
    types::Response,
    configs::Connectors as HyperswitchConnectors,
};
use hyperswitch_masking::{Maskable, PeekInterface, Secret};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use url::Url;

pub mod transformers;

pub struct Jpmorgan;

impl Jpmorgan {
    pub fn new() -> &'static Self {
        &Self
    }
}

impl ConnectorCommon for Jpmorgan {
    fn id(&self) -> &'static str {
        "jpmorgan"
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn base_url<'a>(&self, _connectors: &'a HyperswitchConnectors) -> &'a str {
        "https://placeholder.jpmorgan.com"
    }

    fn build_error_response(
        &self,
        res: Response,
        _event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, ConnectorError> {
        let response: Result<transformers::JpmorganErrorResponse, _> = res
            .response
            .parse_struct("JpmorganErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed);

        match response {
            Ok(error_response) => Ok(ErrorResponse {
                status_code: res.status_code,
                code: error_response.response_code.unwrap_or_else(|| NO_ERROR_CODE.to_string()),
                message: error_response.response_message.unwrap_or_else(|| NO_ERROR_MESSAGE.to_string()),
                reason: error_response.reason,
                attempt_status: None,
                connector_transaction_id: None,
            }),
            Err(e) => {
                Ok(ErrorResponse {
                    status_code: res.status_code,
                    code: NO_ERROR_CODE.to_string(),
                    message: NO_ERROR_MESSAGE.to_string(),
                    reason: Some(format!("Failed to deserialize JPM error response: {:?}", e)),
                    attempt_status: None,
                    connector_transaction_id: None,
                })
            }
        }
    }
}

impl ValidationTrait for Jpmorgan {}

impl PaymentAuthorizeV2 for Jpmorgan {}
impl PaymentSyncV2 for Jpmorgan {}
impl PaymentOrderCreate for Jpmorgan {}
impl PaymentVoidV2 for Jpmorgan {}
impl RefundSyncV2 for Jpmorgan {}
impl RefundV2 for Jpmorgan {}
impl DomainPaymentCapture for Jpmorgan {}
impl IncomingWebhook for Jpmorgan {}

impl ConnectorServiceTrait for Jpmorgan {}

impl ConnectorIntegrationV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>
    for Jpmorgan
{
    fn get_headers(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let mut header = vec![(
            headers::CONTENT_TYPE.to_string(),
            self.common_get_content_type().to_string().into(),
        )];
        let access_token = req.resource_common_data.access_token.clone().ok_or(
            errors::ConnectorError::FailedToObtainAuthType
        )?;

        let auth_header = (
            headers::AUTHORIZATION.to_string(),
            format!("Bearer {}", access_token).into(),
        );
        header.push(auth_header);
        Ok(header)
    }

    fn get_url(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(format!(
            "{}{}",
            req.resource_common_data.connectors.jpmorgan.base_url,
            "/payments/authorizations"
        ))
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let connector_router_data = transformers::JpmorganRouterData::try_from((req.request.minor_amount, req))?;

        let connector_req = transformers::JpmorganPaymentsRequest::try_from(&connector_router_data)?;
        Ok(Some(RequestContent::Json(Box::new(connector_req))))
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        _event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>, errors::ConnectorError> {
        let response: transformers::JpmorganPaymentsResponse = res
            .response
            .parse_struct("JpmorganPaymentsResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        
        let response_wrapper = transformers::JpmorganResponseTransformWrapper {
            response,
            original_router_data_v2_authorize: data.clone(),
            http_status_code: res.status_code,
        };
        RouterDataV2::foreign_try_from(response_wrapper)
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

impl ConnectorIntegrationV2<PSync, PaymentFlowData, DomainPaymentsSyncData, PaymentsResponseData>
    for Jpmorgan
{
    fn get_headers(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, DomainPaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let mut header = vec![(
            headers::CONTENT_TYPE.to_string(),
            self.common_get_content_type().to_string().into(),
        )];
        let access_token = req.resource_common_data.access_token.clone().ok_or(
            errors::ConnectorError::FailedToObtainAuthType
        )?;

        let auth_header = (
            headers::AUTHORIZATION.to_string(),
            format!("Bearer {}", access_token).into(),
        );
        header.push(auth_header);
        Ok(header)
    }

    fn get_url(
        &self,
        _req: &RouterDataV2<PSync, PaymentFlowData, DomainPaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("get_url for PSync".to_string()).into())
    }

    fn get_request_body(
        &self,
        _req: &RouterDataV2<PSync, PaymentFlowData, DomainPaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        Ok(None)
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<PSync, PaymentFlowData, DomainPaymentsSyncData, PaymentsResponseData>,
        _event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<RouterDataV2<PSync, PaymentFlowData, DomainPaymentsSyncData, PaymentsResponseData>, errors::ConnectorError> {
        let response: transformers::JpmorganPaymentsResponse = res
            .response
            .parse_struct("JpmorganPaymentsResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        
        let temp_psync_auth_data_placeholder = PaymentsAuthorizeData {
            payment_method_data: data.request.payment_method_type.map(|pmt| match pmt {
                 _ => hyperswitch_domain_models::payment_method_data::PaymentMethodData::Card(Default::default())
            }).unwrap_or_default(), 
            amount: 0, minor_amount: MinorUnit::new(0), currency: data.request.currency, confirm: false, 
            webhook_url: None, customer_name: None, email: None, statement_descriptor: None, 
            statement_descriptor_suffix: None, capture_method: data.request.capture_method, router_return_url: None, 
            complete_authorize_url: None, mandate_id: data.request.mandate_id.clone(), setup_future_usage: None, off_session: None, 
            browser_info: None, order_category: None, session_token: None, enrolled_for_3ds: false, related_transaction_id: None, 
            payment_experience: data.request.payment_experience, payment_method_type: data.request.payment_method_type, customer_id: None, 
            request_incremental_authorization: false, metadata: None, merchant_order_reference_id: None, 
            order_tax_amount: None, shipping_cost: None, merchant_account_id: None, merchant_config_currency: None
        };
        let temp_rd_v2_auth = RouterDataV2 {
            flow: std::marker::PhantomData::<Authorize>,
            request: temp_psync_auth_data_placeholder,
            response: Err(ErrorResponse::default()),
            resource_common_data: data.resource_common_data.clone(),
            connector_auth_type: data.connector_auth_type.clone(),
        };

        let response_wrapper_psync = transformers::JpmorganResponseTransformWrapper {
            response,
            original_router_data_v2_authorize: temp_rd_v2_auth,
            http_status_code: res.status_code,
        };

        Err(errors::ConnectorError::NotImplemented("PSync response handling".to_string()).into())
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl
    ConnectorIntegrationV2<
        connector_flow::CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for Jpmorgan
{
    fn get_headers(&self, _req: &RouterDataV2<connector_flow::CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("CreateOrder get_headers".to_string()).into())
    }
    fn get_url(&self, _req: &RouterDataV2<connector_flow::CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>) -> CustomResult<String, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("CreateOrder get_url".to_string()).into())
    }
    fn get_request_body(&self, _req: &RouterDataV2<connector_flow::CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("CreateOrder get_request_body".to_string()).into())
    }
    fn handle_response_v2(&self, _data: &RouterDataV2<connector_flow::CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>, _event_builder: Option<&mut ConnectorEvent>, _res: Response) -> CustomResult<RouterDataV2<connector_flow::CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("CreateOrder handle_response_v2".to_string()).into())
    }
    fn get_error_response_v2(&self, res: Response, event_builder: Option<&mut ConnectorEvent>) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl ConnectorIntegrationV2<RSync, RefundFlowData, DomainRefundSyncData, RefundsResponseData>
    for Jpmorgan
{
    fn get_headers(&self, _req: &RouterDataV2<RSync, RefundFlowData, DomainRefundSyncData, RefundsResponseData>) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("RSync get_headers".to_string()).into())
    }
    fn get_url(&self, _req: &RouterDataV2<RSync, RefundFlowData, DomainRefundSyncData, RefundsResponseData>) -> CustomResult<String, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("RSync get_url".to_string()).into())
    }
    fn get_request_body(&self, _req: &RouterDataV2<RSync, RefundFlowData, DomainRefundSyncData, RefundsResponseData>) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("RSync get_request_body".to_string()).into())
    }
    fn handle_response_v2(&self, _data: &RouterDataV2<RSync, RefundFlowData, DomainRefundSyncData, RefundsResponseData>, _event_builder: Option<&mut ConnectorEvent>, _res: Response) -> CustomResult<RouterDataV2<RSync, RefundFlowData, DomainRefundSyncData, RefundsResponseData>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("RSync handle_response_v2".to_string()).into())
    }
    fn get_error_response_v2(&self, res: Response, event_builder: Option<&mut ConnectorEvent>) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
    for Jpmorgan
{
    fn get_headers(&self, _req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("Void get_headers".to_string()).into())
    }
    fn get_url(&self, _req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>) -> CustomResult<String, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("Void get_url".to_string()).into())
    }
    fn get_request_body(&self, _req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("Void get_request_body".to_string()).into())
    }
    fn handle_response_v2(&self, _data: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>, _event_builder: Option<&mut ConnectorEvent>, _res: Response) -> CustomResult<RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("Void handle_response_v2".to_string()).into())
    }
    fn get_error_response_v2(&self, res: Response, event_builder: Option<&mut ConnectorEvent>) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData> for Jpmorgan {
    fn get_headers(&self, _req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("Refund get_headers".to_string()).into())
    }
    fn get_url(&self, _req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>) -> CustomResult<String, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("Refund get_url".to_string()).into())
    }
    fn get_request_body(&self, _req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("Refund get_request_body".to_string()).into())
    }
    fn handle_response_v2(&self, _data: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>, _event_builder: Option<&mut ConnectorEvent>, _res: Response) -> CustomResult<RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("Refund handle_response_v2".to_string()).into())
    }
    fn get_error_response_v2(&self, res: Response, event_builder: Option<&mut ConnectorEvent>) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
    for Jpmorgan
{
    fn get_headers(&self, _req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("Capture get_headers".to_string()).into())
    }
    fn get_url(&self, _req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>) -> CustomResult<String, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("Capture get_url".to_string()).into())
    }
    fn get_request_body(&self, _req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("Capture get_request_body".to_string()).into())
    }
    fn handle_response_v2(&self, _data: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>, _event_builder: Option<&mut ConnectorEvent>, _res: Response) -> CustomResult<RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("Capture handle_response_v2".to_string()).into())
    }
    fn get_error_response_v2(&self, res: Response, event_builder: Option<&mut ConnectorEvent>) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
} 