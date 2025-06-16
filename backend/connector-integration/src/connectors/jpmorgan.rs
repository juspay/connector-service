use domain_types::{
    connector_flow::{self, Authorize, Capture, CreateOrder, PSync, RSync, Refund, Void},
    connector_types::{
        ConnectorEnum, EventType, PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData,
        PaymentsCaptureData, PaymentsResponseData, RefundFlowData, RefundsData, PaymentsSyncData as DomainPaymentsSyncData,
        RefundsResponseData, ConnectorServiceTrait, PaymentAuthorizeV2, PaymentSyncV2, PaymentOrderCreate, PaymentVoidV2, RefundSyncV2, RefundV2, ValidationTrait, IncomingWebhook, PaymentCreateOrderData, PaymentCreateOrderResponse, RefundSyncData as DomainRefundSyncData,
        PaymentCapture as DomainPaymentCapture,
    },
};
use error_stack::ResultExt;
use hyperswitch_api_models::enums::{self as api_enums, AttemptStatus, RefundStatus};
use hyperswitch_common_utils::{
    errors::CustomResult,
    request::{Method, RequestBuilder, RequestContent},
    types::{AmountConvertor, MinorUnit, MinorUnitForConnector},
    ext_traits::ByteSliceExt,
};
use hyperswitch_domain_models::{
    payment_method_data::PaymentMethodData, router_data::{ConnectorAuthType, ErrorResponse, RouterData}, router_data_v2::RouterDataV2, router_request_types::{PaymentsSyncData, ResponseId}, router_response_types::{MandateReference, RedirectForm}
};
use hyperswitch_interfaces::{
    api::{self, ConnectorCommon},
    consts::{NO_ERROR_CODE, NO_ERROR_MESSAGE},
    connector_integration_v2::ConnectorIntegrationV2,
    errors::{self, ConnectorError},
    events::connector_api_logs::ConnectorEvent,
    types::Response,
    configs::Connectors,
};
use hyperswitch_masking::{Mask, Maskable, PeekInterface};
use time::{Duration, OffsetDateTime};
use url::Url;

pub mod transformers;
use transformers::{self as jpmorgan, JpmorganErrorResponse, ForeignTryFrom};

use crate::{with_error_response_body, with_response_body};

fn convert_amount<T>(
    amount_convertor: &dyn AmountConvertor<Output = T>,
    amount: MinorUnit,
    currency: hyperswitch_common_enums::Currency,
) -> Result<T, error_stack::Report<errors::ConnectorError>> {
    amount_convertor
        .convert(amount, currency)
        .change_context(errors::ConnectorError::AmountConversionFailed)
}

pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const AUTHORIZATION: &str = "Authorization";
    pub(crate) const MERCHANT_ID: &str = "Merchant-ID";
    pub(crate) const REQUEST_ID: &str = "request-id";
}

#[derive(Clone)]
pub struct Jpmorgan {
    amount_converter: &'static (dyn AmountConvertor<Output = MinorUnit> + Sync),
}

impl Jpmorgan {
    pub fn new() -> &'static Self {
        &Self {
            amount_converter: &MinorUnitForConnector,
        }
    }
}

impl ConnectorCommon for Jpmorgan {
    fn id(&self) -> &'static str {
        "jpmorgan"
    }

    fn get_currency_unit(&self) -> api::CurrencyUnit {
        api::CurrencyUnit::Minor
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        &connectors.jpmorgan.base_url.as_ref()
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: JpmorganErrorResponse = res
            .response
            .parse_struct("JpmorganErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        with_error_response_body!(event_builder, response);

        let response_message = response
            .response_message
            .as_ref()
            .map_or_else(|| "NO_ERROR_MESSAGE".to_string(), ToString::to_string);

        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response.response_code,
            message: response_message.clone(),
            reason: Some(response_message),
            attempt_status: None,
            connector_transaction_id: None,
            // network_advice_code: None,
            // network_decline_code: None,
            // network_error_message: None,
        })
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
        let mut headers = vec![(
            headers::CONTENT_TYPE.to_string(),
            self.common_get_content_type().to_string().into(),
        )];
        let auth_header = (
            headers::AUTHORIZATION.to_string(),
            format!(
                "Bearer {}",
                req.resource_common_data.access_token
                    .clone()
                    .ok_or(errors::ConnectorError::FailedToObtainAuthType)?
            )
            .into_masked(),
        );
        let request_id = (
            headers::REQUEST_ID.to_string(),
            req.resource_common_data.connector_request_reference_id
                .clone()
                .to_string()
                .into_masked(),
        );
        let merchant_id = (
            headers::MERCHANT_ID.to_string(),
            req.resource_common_data.merchant_id.get_string_repr().to_string().into_masked(),
        );
        headers.push(auth_header);
        headers.push(request_id);
        headers.push(merchant_id);
        Ok(headers)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(format!("{}/payments", req.resource_common_data.connectors.jpmorgan.base_url))
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let amount: MinorUnit = convert_amount(
            self.amount_converter,
            req.request.minor_amount,
            req.request.currency,
        )?;

        let connector_router_data = jpmorgan::JpmorganRouterData::from((amount, req));
        let connector_req = jpmorgan::JpmorganPaymentsRequest::try_from(&connector_router_data)?;
        Ok(Some(RequestContent::Json(Box::new(connector_req))))
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>, errors::ConnectorError> {
        let response: jpmorgan::JpmorganPaymentsResponse = res
            .response
            .parse_struct("Jpmorgan PaymentsAuthorizeResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        
        with_response_body!(event_builder, response);
        
        RouterDataV2::foreign_try_from((
            response,
            data.clone(),
            res.status_code,
        ))
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
            payment_method_data: data.request.payment_method_type
    .map(|_pmt| PaymentMethodData::Card(Default::default()))
    .unwrap_or(PaymentMethodData::Card(Default::default())),
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