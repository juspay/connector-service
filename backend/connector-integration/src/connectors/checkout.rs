use domain_types::connector_types::ConnectorServiceTrait;
use hyperswitch_interfaces::configs::Connectors as DomainConnectors; // Renamed to avoid conflict
use error_stack::ResultExt;
// use crate::connectors::checkout::transformers::ForeignTryFrom; // Keep local trait, but remove import from checkout.rs
// use domain_types::connector_types::PaymentsAuthorizeData; // Removed import
// use domain_types::connector_flow::Authorize; // Removed import

pub struct Checkout;

impl Checkout {
    pub fn new() -> &'static Self {
        &Self {}
    }
}

impl ConnectorServiceTrait for Checkout {}

// Basic trait implementations
use hyperswitch_interfaces::{
    api::ConnectorCommon,
    connector_integration_v2::ConnectorIntegrationV2,
    errors,
};
use domain_types::connector_flow::{Authorize, Capture, PSync, RSync, Refund, Void, CreateOrder};
use domain_types::connector_types::{
    PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData,
    RefundFlowData, RefundsData, RefundsResponseData, PaymentsSyncData, PaymentCreateOrderData, PaymentCreateOrderResponse, RefundSyncData, ValidationTrait, IncomingWebhook,
    PaymentAuthorizeV2, PaymentSyncV2, PaymentVoidV2, RefundV2, PaymentCapture as PaymentCaptureV2, RefundSyncV2 as RefundSyncV2Trait, PaymentOrderCreate // Aliases for traits
};
use hyperswitch_common_utils::{errors::CustomResult, request::RequestContent, ext_traits::ByteSliceExt};
use hyperswitch_domain_models::{router_data_v2::RouterDataV2, router_data::ErrorResponse as BaseErrorResponse};
use hyperswitch_interfaces::events::connector_api_logs::ConnectorEvent;

impl ConnectorCommon for Checkout {
    fn id(&self) -> &'static str {
        "checkout"
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }

    // Added base_url method
    fn base_url<'a>(&self, connectors: &'a DomainConnectors) -> &'a str {
        &connectors.checkout.base_url
    }

    fn build_error_response(
        &self,
        res: hyperswitch_interfaces::types::Response,
        _event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<BaseErrorResponse, errors::ConnectorError> {
        let response: transformers::CheckoutErrorResponse = res
            .response
            .parse_struct("CheckoutErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        Ok(BaseErrorResponse {
            status_code: res.status_code,
            code: response.error_type.clone(), // Use error_type as code
            message: response.error_codes.map(|codes| codes.join(", ")).unwrap_or_else(|| response.error_type.clone()), // Join error codes for message
            reason: None, // Reason might be derivable from error_type or codes in some cases
            attempt_status: None, // Attempt status cannot be determined from error response alone
            connector_transaction_id: None, // Usually not available in error response
        })
    }

}

impl ValidationTrait for Checkout {}

// Implementing marker traits
impl PaymentAuthorizeV2 for Checkout {}
impl PaymentSyncV2 for Checkout {}
impl PaymentOrderCreate for Checkout {}
impl PaymentVoidV2 for Checkout {}
impl IncomingWebhook for Checkout {}
impl RefundV2 for Checkout {}
impl PaymentCaptureV2 for Checkout {}
impl RefundSyncV2Trait for Checkout {}


impl ConnectorIntegrationV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>
    for Checkout
{
    fn get_headers(
        &self,
        _req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        // Removed _connectors
    ) -> CustomResult<Vec<(String, hyperswitch_masking::Maskable<String>)>, errors::ConnectorError> {
        Ok(vec![]) // Placeholder
    }

    fn get_url(
        &self,
        _req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
         // Removed _connectors
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(String::new()) // Placeholder
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let connector_req = transformers::CheckoutPaymentRequest::try_from(req)?;
        Ok(Some(RequestContent::Json(Box::new(connector_req))))
    }

    // Renamed to handle_response_v2 and updated signature and body
    fn handle_response_v2(
        &self,
        data: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        _event_builder: Option<&mut ConnectorEvent>,
        res: hyperswitch_interfaces::types::Response,
    ) -> CustomResult<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>, errors::ConnectorError> {
        let response_payload: transformers::CheckoutPaymentsResponse = res
            .response
            .parse_struct("CheckoutPaymentsResponse")
            .map_err(|_| errors::ConnectorError::ResponseDeserializationFailed)?;

        transformers::ForeignTryFrom::foreign_try_from((
            response_payload,
            data.clone(),
            res.status_code,
            data.request.capture_method,
            false, // is_three_ds placeholder or general boolean flag
            data.request.payment_method_type,
        ))
    }

    // Renamed to get_error_response_v2
    fn get_error_response_v2(
        &self,
        res: hyperswitch_interfaces::types::Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<BaseErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }

    // Helper for building error response
   
}

// Add other trait impls as placeholders
impl ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData> for Checkout {}
impl ConnectorIntegrationV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse> for Checkout {}
impl ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData> for Checkout {}
// IncomingWebhook already impl separately
impl ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData> for Checkout {}
impl ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData> for Checkout {}
impl ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData> for Checkout {}

pub mod transformers; 