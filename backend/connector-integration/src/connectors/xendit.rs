pub mod transformers; 

use transformers::{self as xendit,ForeignTryFrom};

use domain_types::{
    connector_types::{
        PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundsData, RefundsResponseData,
        PaymentCreateOrderData, PaymentCreateOrderResponse,
        ConnectorServiceTrait, IncomingWebhook, PaymentAuthorizeV2, 
        PaymentCapture, PaymentOrderCreate, PaymentSyncV2, PaymentVoidV2, 
        RefundSyncData, RefundSyncV2, RefundV2, ValidationTrait
    },
    connector_flow::{
        Authorize, Capture, PSync, RSync, Refund, Void, CreateOrder,
    }
};

use hyperswitch_common_utils::{
    errors::CustomResult, 
    request::{RequestContent, Method},
    types::{AmountConvertor, FloatMajorUnit, FloatMajorUnitForConnector,MinorUnit},
    ext_traits::ByteSliceExt,
};

use hyperswitch_domain_models::{
    router_data_v2::RouterDataV2, 
    router_data::{ConnectorAuthType, ErrorResponse}
};

use hyperswitch_interfaces::{
    api::{self, ConnectorCommon},
    connector_integration_v2::ConnectorIntegrationV2,
    errors,
    events::connector_api_logs::ConnectorEvent,
    types::Response,
    configs::Connectors,
};

use hyperswitch_masking::{Mask, Maskable, PeekInterface};

use hyperswitch_common_enums::Currency;

use crate::{ with_response_body};

use base64::Engine;

pub const BASE64_ENGINE: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

use error_stack::ResultExt;

pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const AUTHORIZATION: &str = "Authorization";
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct XenditPaymentRequest {
    // Define fields based on Xendit API for payment request
    pub amount: i64,
    pub currency: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct XenditPaymentResponse {
    // Define fields based on Xendit API for payment response
    pub id: String,
    pub status: String,
}

#[derive(Clone)]
pub struct Xendit {
    amount_converter: &'static (dyn AmountConvertor<Output = FloatMajorUnit> + Sync),
}

impl Xendit {
    pub fn new() -> &'static Self {
        &Self {
            amount_converter: &FloatMajorUnitForConnector,
        }
    }
}

impl ConnectorCommon for Xendit {
    fn id(&self) -> &'static str {
        "xendit"
    }

    fn get_currency_unit(&self) -> api::CurrencyUnit {
        api::CurrencyUnit::Base
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth = xendit::XenditAuthType::try_from(auth_type)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        let encoded_api_key = BASE64_ENGINE.encode(format!("{}:", auth.api_key.peek()));

        Ok(vec![(
            headers::AUTHORIZATION.to_string(),
            format!("Basic {encoded_api_key}").into_masked(),
        )])
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        &connectors.checkout.base_url.as_ref()
    }

    fn build_error_response(
        &self,
        res: Response,
        _event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: transformers::XenditErrorResponse = res
            .response
            .parse_struct("XenditErrorResponse")
            .map_err(|_| errors::ConnectorError::ResponseDeserializationFailed)?;

        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response.error_code.unwrap_or_else(|| "HS_XENDIT_FAILURE".to_string()),
            message: response.message.unwrap_or_else(|| "Payment failed at Xendit".to_string()),
            reason: response.reason,
            attempt_status: None,
            connector_transaction_id: None,
        })
    }
}

//marker traits
impl ConnectorServiceTrait for Xendit {}
impl ValidationTrait for Xendit {}
impl PaymentAuthorizeV2 for Xendit {}
impl PaymentSyncV2 for Xendit {}
impl PaymentOrderCreate for Xendit {}
impl PaymentVoidV2 for Xendit {}
impl RefundSyncV2 for Xendit {}
impl RefundV2 for Xendit {}
impl PaymentCapture for Xendit {}
impl IncomingWebhook for Xendit {}

fn convert_amount<T>(
    amount_convertor: &dyn AmountConvertor<Output = T>,
    amount: MinorUnit,
    currency: Currency,
) -> Result<T, error_stack::Report<errors::ConnectorError>> {
    amount_convertor
        .convert(amount, currency)
        .change_context(errors::ConnectorError::AmountConversionFailed)
}

impl ConnectorIntegrationV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>
    for Xendit
{
    fn get_headers(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let mut header = vec![(
            headers::CONTENT_TYPE.to_string(),
            "application/json".to_string().into(),
        )];
        let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
        header.append(&mut api_key);
        Ok(header)
    }

    fn get_url(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(format!(
            "{}/payment_requests",
            req.resource_common_data.connectors.xendit.base_url,
        ))
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let amount = convert_amount(
            self.amount_converter,
            req.request.minor_amount,
            req.request.currency,
        )?;
        let connector_router_data = xendit::XenditRouterData::from((amount, req));
        let connector_req = xendit::XenditPaymentsRequest::try_from((&connector_router_data,))?;
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
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<
        RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        errors::ConnectorError,
    > {
        let response: xendit::XenditPaymentResponse = res
            .response
            .parse_struct("XenditPaymentResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        
        with_response_body!(event_builder, response);

        RouterDataV2::foreign_try_from((
            response,
            data.clone(),
            res.status_code
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

impl ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData> for Xendit {
    fn get_headers(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let mut header = vec![(
            headers::CONTENT_TYPE.to_string(),
            "application/json".to_string().into(),
        )];
        let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
        header.append(&mut api_key);
        Ok(header)
    }

    fn get_url(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        let connector_payment_id = req
            .request
            .connector_transaction_id
            .get_connector_transaction_id()
            .change_context(errors::ConnectorError::MissingConnectorTransactionID)?;

        Ok(format!(
            "{}/payment_requests/{connector_payment_id}",
            req.resource_common_data.connectors.xendit.base_url,
        ))
    }

    fn get_http_method(&self) -> Method {
        Method::Get
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<
        RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        errors::ConnectorError,
    > {
        let response: xendit::XenditResponse = res
            .response
            .clone()
            .parse_struct("xendit XenditResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        with_response_body!(event_builder, response);

        RouterDataV2::foreign_try_from((
            response,
            data.clone(),
            res.status_code
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

impl ConnectorIntegrationV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse> for Xendit {
    // ... implementation ...
    fn get_headers(
        &self,
        _req: &RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("get_headers for CreateOrder".to_string()).into())
    }

    fn get_url(
        &self,
        _req: &RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>,
    ) -> CustomResult<String, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("get_url for CreateOrder".to_string()).into())
    }

    fn get_request_body(
        &self,
        _req: &RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("get_request_body for CreateOrder".to_string()).into())
    }

    fn handle_response_v2(
        &self,
        _data: &RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>,
        _event_builder: Option<&mut ConnectorEvent>,
        _res: Response,
    ) -> CustomResult<RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("handle_response_v2 for CreateOrder".to_string()).into())
    }
    
    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl ConnectorIntegrationV2<RSync, RefundFlowData, RefundsData, RefundsResponseData> for Xendit {
    // ... implementation ...
    fn get_headers(
        &self,
        _req: &RouterDataV2<RSync, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("get_headers for RSync".to_string()).into())
    }

    fn get_url(
        &self,
        _req: &RouterDataV2<RSync, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("get_url for RSync".to_string()).into())
    }

    fn get_request_body(
        &self,
        _req: &RouterDataV2<RSync, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("get_request_body for RSync".to_string()).into())
    }

    fn handle_response_v2(
        &self,
        _data: &RouterDataV2<RSync, RefundFlowData, RefundsData, RefundsResponseData>,
        _event_builder: Option<&mut ConnectorEvent>,
        _res: Response,
    ) -> CustomResult<RouterDataV2<RSync, RefundFlowData, RefundsData, RefundsResponseData>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("handle_response_v2 for RSync".to_string()).into())
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData> for Xendit {
    // ... implementation ...
    fn get_headers(
        &self,
        _req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("get_headers for Void".to_string()).into())
    }

    fn get_url(
        &self,
        _req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("get_url for Void".to_string()).into())
    }

    fn get_request_body(
        &self,
        _req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("get_request_body for Void".to_string()).into())
    }

    fn handle_response_v2(
        &self,
        _data: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        _event_builder: Option<&mut ConnectorEvent>,
        _res: Response,
    ) -> CustomResult<RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("handle_response_v2 for Void".to_string()).into())
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData> for Xendit {
    // ... implementation ...
    fn get_headers(
        &self,
        _req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("get_headers for Refund".to_string()).into())
    }

    fn get_url(
        &self,
        _req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("get_url for Refund".to_string()).into())
    }

    fn get_request_body(
        &self,
        _req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("get_request_body for Refund".to_string()).into())
    }

    fn handle_response_v2(
        &self,
        _data: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        _event_builder: Option<&mut ConnectorEvent>,
        _res: Response,
    ) -> CustomResult<RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("handle_response_v2 for Refund".to_string()).into())
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}
impl ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData> for Xendit {
    // ... implementation ...
    fn get_headers(
        &self,
        _req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("get_headers for Capture".to_string()).into())
    }

    fn get_url(
        &self,
        _req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("get_url for Capture".to_string()).into())
    }

    fn get_request_body(
        &self,
        _req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("get_request_body for Capture".to_string()).into())
    }

    fn handle_response_v2(
        &self,
        _data: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        _event_builder: Option<&mut ConnectorEvent>,
        _res: Response,
    ) -> CustomResult<RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("handle_response_v2 for Capture".to_string()).into())
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

// Basic IncomingWebhook trait implementation (Verify/GetEvent/ProcessPayment/ProcessRefund)
// These will need actual logic based on Xendit webhooks
// Refer to Hyperswitch xendit.rs for webhook structure and logic

// use domain_types::connector_types::{RequestDetails, ConnectorWebhookSecrets, EventType, WebhookDetailsResponse, RefundWebhookDetailsResponse};
// use hyperswitch_domain_models::router_data::ConnectorAuthType;

// impl IncomingWebhook for Xendit {
//     fn verify_webhook_source(
//         &self,
//         request: RequestDetails,
//         connector_webhook_secrets: Option<ConnectorWebhookSecrets>,
//         _connector_account_details: Option<ConnectorAuthType>,
//     ) -> CustomResult<bool, errors::ConnectorError> {
//         // Xendit uses a 'x-callback-token' header for webhook verification.
//         // See: https://developers.xendit.co/api-reference/#webhook-verification
//         let provided_token = request
//             .headers
//             .iter()
//             .find(|(k, _)| k.eq_ignore_ascii_case("x-callback-token"))
//             .map(|(_, v)| v.as_str());

//         let expected_token = connector_webhook_secrets.map(|s| s.secret.as_str()); // Assuming secret is the callback token

//         match (provided_token, expected_token) {
//             (Some(p_token), Some(e_token)) => Ok(p_token == e_token),
//             _ => {
//                 // hyperswitch_common_utils::logger::error!("Webhook source verification failed: Token missing or not configured.");
//                 Ok(false) // Or return an error
//             }
//         }
//     }

//     fn get_event_type(
//         &self,
//         request: RequestDetails,
//         _connector_webhook_secrets: Option<ConnectorWebhookSecrets>,
//         _connector_account_details: Option<ConnectorAuthType>,
//     ) -> CustomResult<EventType, errors::ConnectorError> {
//         // Parse the event from request.body
//         // Hyperswitch Xendit uses a XenditWebhookEvent struct
//         let webhook_event: transformers::XenditWebhookEvent = request
//             .body
//             .parse_struct("XenditWebhookEvent")
//             .change_context(errors::ConnectorError::WebhookEventTypeNotFound)?;

//         match webhook_event.event.as_str() {
//             // Map Xendit event types to your EventType enum
//             // Example from Hyperswitch:
//             "payment.succeeded" | "payment.failed" | "invoice.paid" | "invoice.expired" |
//             "credit.created" | "credit.succeeded" | "credit.failed" |
//             "disbursement.sent" | "disbursement.failed" |
//             "payment_request.succeeded" | "payment_request.failed" | "payment_request.pending" |
//             "payment_method.activated" | "payment_method.expired" | "payment_method.failed_activation"
//             => Ok(EventType::Payment),
//             "refund.succeeded" | "refund.failed" => Ok(EventType::Refund),
//             _ => Err(errors::ConnectorError::WebhookEventTypeNotFound.into()),
//         }
//     }

//     fn process_payment_webhook(
//         &self,
//         request: RequestDetails,
//         _connector_webhook_secrets: Option<ConnectorWebhookSecrets>,
//         _connector_account_details: Option<ConnectorAuthType>,
//     ) -> CustomResult<WebhookDetailsResponse, errors::ConnectorError> {
//         let webhook_event: transformers::XenditWebhookEvent = request
//             .body
//             .parse_struct("XenditWebhookEvent")
//             .change_context(errors::ConnectorError::WebhookResourceObjectNotFound)?;

//         // Extract relevant data from webhook_event.data
//         // Map to WebhookDetailsResponse
//         // This is highly dependent on the structure of XenditWebhookEvent and its data field
//         // Example based on a generic structure:
//         // let resource_id = webhook_event.data.get("id").and_then(|v| v.as_str()).map(|s| hyperswitch_domain_models::router_request_types::ResponseId::ConnectorTransactionId(s.to_string()));
//         // let status = webhook_event.data.get("status").and_then(|v| v.as_str()).map_or(hyperswitch_common_enums::AttemptStatus::Pending, |s| {
//         //     // Map Xendit status to AttemptStatus
//         //     match s {
//         //         "SUCCEEDED" | "PAID" => hyperswitch_common_enums::AttemptStatus::Charged,
//         //         "PENDING" => hyperswitch_common_enums::AttemptStatus::Pending,
//         //         "FAILED" => hyperswitch_common_enums::AttemptStatus::Failure,
//         //         _ => hyperswitch_common_enums::AttemptStatus::Pending,
//         //     }
//         // });

//         // Ok(WebhookDetailsResponse {
//         //     resource_id,
//         //     status,
//         //     connector_response_reference_id: webhook_event.data.get("external_id").and_then(|v| v.as_str()).map(String::from),
//         //     error_code: webhook_event.data.get("failure_code").and_then(|v| v.as_str()).map(String::from),
//         //     error_message: webhook_event.data.get("failure_reason").and_then(|v| v.as_str()).map(String::from),
//         // })
//         Err(errors::ConnectorError::NotImplemented("process_payment_webhook for Xendit".to_string()).into())
//     }

//     fn process_refund_webhook(
//         &self,
//         _request: RequestDetails,
//         _connector_webhook_secrets: Option<ConnectorWebhookSecrets>,
//         _connector_account_details: Option<ConnectorAuthType>,
//     ) -> CustomResult<RefundWebhookDetailsResponse, errors::ConnectorError> {
//         Err(errors::ConnectorError::NotImplemented("process_refund_webhook for Xendit".to_string()).into())
//     }
// }

// Helper for auth, if not part of a shared trait
// impl Xendit {
//     fn get_auth_header(
//         &self,
//         auth_type: &hyperswitch_domain_models::router_data::ConnectorAuthType,
//     ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
//         match auth_type {
//             hyperswitch_domain_models::router_data::ConnectorAuthType::HeaderKey { api_key } => {
//                 let encoded_api_key = hyperswitch_common_utils::consts::BASE64_ENGINE
//                     .encode(format!("{}:", api_key.peek()));
//                 Ok(vec![(
//                     hyperswitch_common_utils::consts::headers::AUTHORIZATION.to_string(),
//                     format!("Basic {}", encoded_api_key).into_masked(),
//                 )])
//             }
//             _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
//         }
//     }
// } 
impl ConnectorIntegrationV2<
    RSync,
    RefundFlowData,
    RefundSyncData,
    RefundsResponseData,
> for Xendit {
    // Implement the required trait functions here
}