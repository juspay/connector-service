pub mod transformers;

use hyperswitch_common_utils::{
    errors::CustomResult,
    ext_traits::ByteSliceExt,
    request::RequestContent,
};

use hyperswitch_domain_models::{
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_request_types::ResponseId,
    router_flow_types::payments::Authorize as HyperswitchRouterAuthorize,
    router_request_types::PaymentsAuthorizeData as HyperswitchRouterPaymentsAuthorizeData,
    router_response_types::PaymentsResponseData as HyperswitchRouterPaymentsResponseData,
    router_data::RouterData,
};

use hyperswitch_interfaces::{
    api::{self, ConnectorCommon, PaymentAuthorize},
    connector_integration_v2::ConnectorIntegrationV2,
    errors,
    events::connector_api_logs::ConnectorEvent,
    types::Response,
    configs::Connectors,
};
use hyperswitch_masking::{ExposeInterface, Maskable};
use error_stack::ResultExt;
use hyperswitch_common_enums::enums;

use domain_types::{
    connector_flow::{Authorize, PSync, Void, CreateOrder, Refund, RSync},
    connector_types::{
        ConnectorServiceTrait, ConnectorWebhookSecrets, IncomingWebhook,
        PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData,
        PaymentOrderCreate, PaymentSyncV2, PaymentVoidData, PaymentVoidV2, PaymentsAuthorizeData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundsData, RefundsResponseData,
        RefundSyncData, RequestDetails, WebhookDetailsResponse, RefundWebhookDetailsResponse,
    },
};

use crate::connectors::checkout::transformers::{CheckoutAuthType, CheckoutPaymentRequest, CheckoutPaymentResponse, CheckoutPaymentStatus};

pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const AUTHORIZATION: &str = "Authorization";
}

#[derive(Debug, Clone)]
pub struct Checkout;

impl Checkout {
    pub fn new() -> &'static Self {
        static INSTANCE: Checkout = Checkout;
        &INSTANCE
    }
}

impl ConnectorCommon for Checkout {
    fn id(&self) -> &'static str {
        "checkout"
    }

    fn get_currency_unit(&self) -> api::CurrencyUnit {
        api::CurrencyUnit::Minor
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.checkout.base_url.as_ref()
    }

    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth = CheckoutAuthType::try_from(auth_type)
            .map_err(|_| errors::ConnectorError::FailedToObtainAuthType)?;
        Ok(vec![(
            "Authorization".to_string(),
            format!("Bearer {}", auth.api_key.expose()).into(),
        )])
    }
}

impl PaymentAuthorize for Checkout {}
impl ConnectorServiceTrait for Checkout {}

impl ConnectorIntegrationV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData> for Checkout {
    fn get_headers(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        self.get_auth_header(&req.connector_auth_type)
    }

    fn get_url(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(format!("{}/payments", self.base_url(&req.resource_common_data.connectors)))
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let router_data = transformers::CheckoutRouterData::try_from((req.request.minor_amount, req))?;
        let request = CheckoutPaymentRequest::try_from(&router_data)?;
        Ok(Some(RequestContent::Json(Box::new(request))))
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>, errors::ConnectorError> {
        let response: CheckoutPaymentResponse = res
            .response
            .parse_struct("CheckoutPaymentResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        let response_data = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(response.id.clone()),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            charge_id: Some(response.id),
            status: enums::AttemptStatus::from(response.status),
            network_txn_id: None,
            connector_response_reference_id: Some(response.reference),
            incremental_authorization_allowed: None,
        };

        Ok(RouterDataV2 {
            flow: data.flow.clone(),
            resource_common_data: data.resource_common_data.clone(),
            connector_auth_type: data.connector_auth_type.clone(),
            request: data.request.clone(),
            response: response_data,
        })
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        _event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: CheckoutPaymentResponse = res
            .response
            .parse_struct("CheckoutPaymentResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        Ok(ErrorResponse {
            code: response.status.to_string(),
            message: response.status.to_string(),
            reason: Some(response.status.to_string()),
            status_code: res.status_code,
            attempt_status: None,
            connector_transaction_id: None,
        })
    }
}

impl ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    for Checkout
{
}

impl ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
    for Checkout
{
}

impl ConnectorIntegrationV2<
    CreateOrder,
    PaymentFlowData,
    PaymentCreateOrderData,
    PaymentCreateOrderResponse,
> for Checkout
{
}

impl ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData> for Checkout {
}

impl ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
    for Checkout
{
}

impl IncomingWebhook for Checkout {
    fn verify_webhook_source(
        &self,
        _request: RequestDetails,
        _connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorAuthType>,
    ) -> Result<bool, error_stack::Report<errors::ConnectorError>> {
        Ok(true)
    }

    fn get_event_type(
        &self,
        _request: RequestDetails,
        _connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorAuthType>,
    ) -> Result<domain_types::connector_types::EventType, error_stack::Report<errors::ConnectorError>>
    {
        Ok(domain_types::connector_types::EventType::Payment)
    }

    fn process_payment_webhook(
        &self,
        _request: RequestDetails,
        _connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorAuthType>,
    ) -> Result<WebhookDetailsResponse, error_stack::Report<errors::ConnectorError>> {
        Err(errors::ConnectorError::WebhooksNotImplemented.into())
    }

    fn process_refund_webhook(
        &self,
        _request: RequestDetails,
        _connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorAuthType>,
    ) -> Result<RefundWebhookDetailsResponse, error_stack::Report<errors::ConnectorError>> {
        Err(errors::ConnectorError::WebhooksNotImplemented.into())
    }
}

impl api::ConnectorIntegration<
    hyperswitch_domain_models::router_flow_types::payments::Authorize, 
    hyperswitch_domain_models::router_request_types::PaymentsAuthorizeData, 
    hyperswitch_domain_models::router_response_types::PaymentsResponseData
> for Checkout {
    fn get_headers(
        &self,
        req: &RouterData<
            hyperswitch_domain_models::router_flow_types::payments::Authorize, 
            hyperswitch_domain_models::router_request_types::PaymentsAuthorizeData, 
            hyperswitch_domain_models::router_response_types::PaymentsResponseData
        >,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        self.get_auth_header(&req.connector_auth_type)
    }

    fn get_url(
        &self,
        req: &RouterData<
            hyperswitch_domain_models::router_flow_types::payments::Authorize, 
            hyperswitch_domain_models::router_request_types::PaymentsAuthorizeData, 
            hyperswitch_domain_models::router_response_types::PaymentsResponseData
        >,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(format!("{}/payments", self.base_url(connectors)))
    }

    fn get_request_body(
        &self,
        req: &RouterData<
            hyperswitch_domain_models::router_flow_types::payments::Authorize, 
            hyperswitch_domain_models::router_request_types::PaymentsAuthorizeData, 
            hyperswitch_domain_models::router_response_types::PaymentsResponseData
        >,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        let checkout_request = transformers::CheckoutPaymentRequest::try_from(req)?;
        Ok(RequestContent::Json(Box::new(checkout_request)))
    }

    fn build_request(
        &self,
        req: &RouterData<
            hyperswitch_domain_models::router_flow_types::payments::Authorize, 
            hyperswitch_domain_models::router_request_types::PaymentsAuthorizeData, 
            hyperswitch_domain_models::router_response_types::PaymentsResponseData
        >,
        connectors: &Connectors,
    ) -> CustomResult<Option<hyperswitch_common_utils::request::Request>, errors::ConnectorError> {
        let request_body = api::ConnectorIntegration::get_request_body(self, req, connectors)?;
        let headers = api::ConnectorIntegration::get_headers(self, req, connectors)?;
        let url = api::ConnectorIntegration::get_url(self, req, connectors)?;

        let http_method = api::ConnectorIntegration::get_http_method(self);

        Ok(Some(
            hyperswitch_common_utils::request::Request::new(http_method, &url)
                .set_headers(headers)
                .set_body(request_body)
        ))
    }

    fn handle_response(
        &self,
        data: &RouterData<
            hyperswitch_domain_models::router_flow_types::payments::Authorize, 
            hyperswitch_domain_models::router_request_types::PaymentsAuthorizeData, 
            hyperswitch_domain_models::router_response_types::PaymentsResponseData
        >,
        mut event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<RouterData<
            hyperswitch_domain_models::router_flow_types::payments::Authorize, 
            hyperswitch_domain_models::router_request_types::PaymentsAuthorizeData, 
            hyperswitch_domain_models::router_response_types::PaymentsResponseData
        >, errors::ConnectorError> {
        let checkout_payment_response: transformers::CheckoutPaymentResponse = res
            .response
            .parse_struct("CheckoutPaymentResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        let hyperswitch_response_data = HyperswitchRouterPaymentsResponseData::try_from(checkout_payment_response.clone())?;

        event_builder.as_mut().map(|e| e.set_response_body(&checkout_payment_response));

        let mut router_data_updated = data.clone();
        router_data_updated.response = Ok(hyperswitch_response_data);

        Ok(router_data_updated)
    }

    fn get_error_response(
        &self,
        res: Response,
        mut event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let checkout_specific_error: transformers::CheckoutPaymentResponse = 
            match res.response.parse_struct("CheckoutErrorResponse") {
                Ok(r) => r,
                Err(_) => { 
                    res.response.parse_struct("CheckoutPaymentResponse")
                       .change_context(errors::ConnectorError::ResponseDeserializationFailed)?
                }
            };

        event_builder.as_mut().map(|e| e.set_error_response_body(&checkout_specific_error));

        let error_response = ErrorResponse {
            code: checkout_specific_error.status.to_string(),
            message: checkout_specific_error.status.to_string(),
            reason: Some(format!("Connector Error: Status {} - ID: {}", checkout_specific_error.status, checkout_specific_error.id)),
            status_code: res.status_code,
            attempt_status: Some(enums::AttemptStatus::from(checkout_specific_error.status)), 
            connector_transaction_id: Some(checkout_specific_error.id),
        };
        
        Ok(error_response)
    }
} 