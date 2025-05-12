use domain_types::connector_types::{
    ConnectorServiceTrait, IncomingWebhook, PaymentAuthorizeV2, PaymentCapture, PaymentOrderCreate, PaymentSyncV2, PaymentVoidV2, RefundSyncData, RefundSyncV2, RefundV2, ValidationTrait
};
use domain_types::connector_flow::{Authorize, Capture, PSync, RSync, Refund, Void, CreateOrder};
use domain_types::connector_types::{
    PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData,
    PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundsData, RefundsResponseData,
    PaymentCreateOrderData, PaymentCreateOrderResponse
};
use hyperswitch_interfaces::configs::Connectors as DomainConnectors;
use hyperswitch_common_utils::ext_traits::ByteSliceExt;
use hyperswitch_common_utils::{errors::CustomResult, request::RequestContent};
use hyperswitch_domain_models::{router_data_v2::RouterDataV2, router_data::ErrorResponse};
use hyperswitch_interfaces::{
    api::ConnectorCommon,
    connector_integration_v2::ConnectorIntegrationV2,
    errors,
    events::connector_api_logs::ConnectorEvent,
    types::Response,
    configs::Connectors,
};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use hyperswitch_masking::{Mask, Maskable, PeekInterface};
use error_stack::ResultExt;


pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const AUTHORIZATION: &str = "Authorization";
}

//TODO: Define actual Xendit structs based on Hyperswitch reference or API docs
// These are placeholders for now.
pub mod transformers; // Assuming transformers will be in a sub-module

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct XenditPaymentRequest {
    // Define fields based on Xendit API for payment request
    pub amount: i64,
    pub currency: String,
}

pub trait ForeignTryFrom<F>: Sized {
    type Error;

    fn foreign_try_from(from: F) -> Result<Self, Self::Error>;
}


#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct XenditPaymentResponse {
    // Define fields based on Xendit API for payment response
    pub id: String,
    pub status: String,
}


#[derive(Clone)]
pub struct Xendit {}

impl Xendit {
    pub fn new() -> &'static Self {
        static INSTANCE: Xendit = Xendit {};
        &INSTANCE
    }

    fn get_auth_header(
        &self,
        auth_type: &hyperswitch_domain_models::router_data::ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        match auth_type {
            hyperswitch_domain_models::router_data::ConnectorAuthType::HeaderKey { api_key } => {
                let encoded_api_key = STANDARD.encode(format!("{}:", api_key.peek()));
                Ok(vec![(
                    headers::AUTHORIZATION.to_string(),
                    format!("Basic {}", encoded_api_key).into_masked(),
                )])
            }
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

impl ConnectorCommon for Xendit {
    fn id(&self) -> &'static str {
        "xendit"
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }
    fn base_url<'a>(&self, connectors: &'a DomainConnectors) -> &'a str {
        &connectors.checkout.base_url
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
            "{}{}",
            req.resource_common_data.connectors.xendit.base_url,
            "/payment_requests"
        ))
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        // Transform RouterData to XenditPaymentRequest
        // let xendit_req = XenditPaymentRequest {
        //     amount: req.request.minor_amount.get_amount_as_i64(),
        //     currency: req.request.currency.to_string().to_uppercase(),
        //     // ... other fields
        // };
        // Ok(Some(RequestContent::Json(Box::new(xendit_req))))
        // Using transformers
        let connector_req = transformers::XenditPaymentsRequest::try_from(req)?;
        Ok(Some(RequestContent::Json(Box::new(connector_req))))
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>, errors::ConnectorError> {
        // Parse XenditPaymentResponse from res.response
        // let response: XenditPaymentResponse = res
        //     .response
        //     .parse_struct("XenditPaymentResponse")
        //     .map_err(|_| errors::ConnectorError::ResponseDeserializationFailed)?;
        // with_response_body!(event_builder, response); // Macro might not be available, use direct logging/event building
        // hyperswitch_common_utils::events::connector_api_log_response(event_builder, &response); // Example if direct function exists

        // Transform XenditPaymentResponse to PaymentsResponseData and update RouterData
        // let payments_response_data = PaymentsResponseData::TransactionResponse {
        //     resource_id: hyperswitch_domain_models::router_request_types::ResponseId::ConnectorTransactionId(response.id),
        //     redirection_data: None, // Xendit might have redirection, check API docs
        //     connector_metadata: None,
        //     network_txn_id: None,
        //     connector_response_reference_id: None,
        //     incremental_authorization_allowed: None,
        // };

        // let router_data = RouterDataV2 {
        //     response: Ok(payments_response_data),
        //     resource_common_data: hyperswitch_domain_models::router_data::RouterData {
        //         status: match response.status.as_str() { // map Xendit status to common status
        //             "SUCCEEDED" | "PAID" => hyperswitch_common_enums::AttemptStatus::Charged, // Example statuses
        //             "PENDING" => hyperswitch_common_enums::AttemptStatus::Pending,
        //             "FAILED" => hyperswitch_common_enums::AttemptStatus::Failure,
        //             _ => hyperswitch_common_enums::AttemptStatus::Pending, // Default or map more statuses
        //         },
        //         ..data.resource_common_data.clone()
        //     },
        //     ..data.clone()
        // };
        // Ok(router_data)
        // Using transformers
        let response: transformers::XenditPaymentsResponse = res
            .response
            .parse_struct("XenditPaymentsResponse")
            .map_err(|e| {
                // Log the deserialization error
                // eprintln!("XenditPaymentsResponse deserialization error: {:?}", e);
                errors::ConnectorError::ResponseDeserializationFailed
            })?;
        
        // hyperswitch_common_utils::events::connector_api_log_response(event_builder, &response);

        RouterDataV2::foreign_try_from((response, data.clone()))
            .change_context(errors::ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }

    // Optional: Implement get_5xx_error_response if specific handling is needed
    // fn get_5xx_error_response(
    //     &self,
    //     res: Response,
    //     event_builder: Option<&mut ConnectorEvent>,
    // ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
    //     self.build_error_response(res, event_builder)
    // }
}


// Implement ConnectorIntegrationV2 for other flows (PSync, Capture, Void, Refund, RSync, CreateOrder)
// For each, you'll need to:
// 1. Define request/response structs in transformers.rs (if not already for Authorize)
// 2. Implement TryFrom to convert between RouterData and connector-specific types
// 3. Implement get_headers, get_url, get_request_body, handle_response_v2, get_error_response_v2

impl ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData> for Xendit {
    // ... implementation ...
    fn get_headers(
        &self,
        _req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("get_headers for PSync".to_string()).into())
    }

    fn get_url(
        &self,
        _req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("get_url for PSync".to_string()).into())
    }

    fn get_request_body(
        &self,
        _req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("get_request_body for PSync".to_string()).into())
    }

    fn handle_response_v2(
        &self,
        _data: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        _event_builder: Option<&mut ConnectorEvent>,
        _res: Response,
    ) -> CustomResult<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("handle_response_v2 for PSync".to_string()).into())
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
