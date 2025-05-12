use domain_types::connector_flow::Authorize;
use domain_types::connector_types::{
    PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData,
};
use error_stack::{ResultExt, Report};
use hyperswitch_common_utils::errors::CustomResult;
use hyperswitch_common_utils::request::Method;
use hyperswitch_domain_models::{
    payment_method_data::PaymentMethodData,
    router_data::ErrorResponse, // Added for XenditErrorResponse
    router_data_v2::RouterDataV2,
    router_request_types::ResponseId,
    router_response_types::{self as hyperswitch_router_response_types}, // aliased
};
use crate::connectors::xendit::ForeignTryFrom;
use hyperswitch_interfaces::errors;
use serde::{Deserialize, Serialize};
use hyperswitch_masking::{ExposeInterface, Secret};

// Basic Request Structure from Hyperswitch Xendit
#[derive(Debug, Clone, Serialize)]
pub struct XenditPaymentsRequest {
    pub amount: i64,
    pub currency: String, // Should be hyperswitch_common_enums::Currency, but matching Hyperswitch for now
    pub payment_method: XenditPaymentMethod,
    #[serde(rename = "external_id")]
    pub merchant_payment_id: String,
    pub description: Option<String>,
    pub customer_id: Option<String>,
    // Add other fields like billing_address, shipping_address, metadata, etc. as needed
    // and based on Xendit API documentation for Payment Requests
    // Example: some fields from Hyperswitch XenditPaymentRequest
    pub statement_descriptor_suffix: Option<String>,
    pub items: Option<Vec<XenditLineItem>>,
    pub channel_properties: Option<XenditChannelProperties>,
    // redirect URLs might be needed
    pub success_redirect_url: Option<String>,
    pub failure_redirect_url: Option<String>,
    // metadata: Option<serde_json::Value> // if using direct serde_json::Value
}

#[derive(Debug, Clone, Serialize)]
pub struct XenditPaymentMethod {
    #[serde(rename = "type")]
    pub payment_method_type: XenditPaymentMethodType,
    pub card: Option<XenditCard>,
    // other payment method types like ewallet, direct_debit etc.
    pub reusability: String, // DIRECT_DEBIT, ONE_TIME_USE - from Hyperswitch
}

#[derive(Debug, Clone, Serialize)]pub enum XenditPaymentMethodType {
    #[serde(rename = "CARD")]
    Card,
    // ... other types like EWALLET, DIRECT_DEBIT etc.
}

#[derive(Debug, Clone, Serialize)]
pub struct XenditCard {
    pub currency: String, // Should be hyperswitch_common_enums::Currency
    pub channel_properties: XenditCardChannelProperties,
    // card specific fields if any apart from channel_properties
    // E.g., if tokenizing: token_id
}

#[derive(Debug, Clone, Serialize)]
pub struct XenditCardChannelProperties {
    pub skip_three_d_secure: Option<bool>,
    // cvv, card_number, expiry_month, expiry_year are part of PaymentMethodData in RouterData
    // but Xendit might expect them here for non-tokenized card payments.
    // In Hyperswitch, these are obtained from PaymentMethodData::Card and put into the Xendit request.
    // For direct card details, the struct would be different:
    // card_number: Secret<String>,
    // expiry_month: Secret<String>,
    // expiry_year: Secret<String>,
    // cvv: Secret<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct XenditLineItem {
    pub name: String,
    pub quantity: i32,
    pub price: i64,
    pub category: Option<String>,
    pub url: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct XenditChannelProperties {
    // Fields for specific channels if required, e.g., for redirect flows
    // mobile_number: Option<String> for some eWallets etc.
    // success_return_url, failure_return_url are at top level in Hyperswitch Xendit
    // but some connectors put them here.
    // For cards, often skip_three_d_secure is here, but Hyperswitch Xendit has it in XenditCard.channel_properties
    pub customer_name: Option<String>, // Example, might not be Xendit specific
}

// Basic Response Structure from Hyperswitch Xendit
#[derive(Debug, Clone, Deserialize)]
pub struct XenditPaymentsResponse {
    pub id: String,
    pub status: String, // e.g., PENDING, SUCCEEDED, FAILED
    pub amount: i64,
    pub currency: String, // Should be hyperswitch_common_enums::Currency
    #[serde(rename = "external_id")]
    pub merchant_payment_id: String,
    pub payment_method: Option<XenditPaymentMethodResponseDetails>,
    pub actions: Option<XenditPaymentActions>,
    pub failure_code: Option<String>,
    pub failure_reason: Option<String>,
    // other fields like created, updated, description, customer_id etc.
    // based on Xendit API documentation for Payment Requests response
}

#[derive(Debug, Clone, Deserialize)]
pub struct XenditPaymentMethodResponseDetails {
    #[serde(rename = "type")]
    pub payment_method_type: String, // CARD, EWALLET etc.
    // card specific details
    pub card: Option<XenditCardResponseDetails>,
    // other payment method details
}

#[derive(Debug, Clone, Deserialize)]
pub struct XenditCardResponseDetails {
    pub last_four_digits: Option<String>,
    pub brand: Option<String>,
    // other card details
}

#[derive(Debug, Clone, Deserialize)]
pub struct XenditPaymentActions {
    #[serde(rename = "desktop_web_checkout_url")]
    pub desktop_redirect_url: Option<String>,
    #[serde(rename = "mobile_web_checkout_url")]
    pub mobile_redirect_url: Option<String>,
    #[serde(rename = "mobile_deeplink_checkout_url")]
    pub mobile_deeplink_url: Option<String>,
    // QR code URL if applicable
    #[serde(rename = "qr_checkout_string")]
    pub qr_code_url: Option<String>,
}

// Xendit Error Response Structure (from Hyperswitch xendit.rs)
#[derive(Debug, Deserialize)]
pub struct XenditErrorResponse {
    pub error_code: Option<String>,
    pub message: Option<String>,
    pub reason: Option<String>, // This might not be standard, check Xendit docs
    // Xendit might have more structured errors, e.g. a list of errors
    // errors: Option<Vec<XenditErrorDetail>>
}

// #[derive(Debug, Deserialize)]
// pub struct XenditErrorDetail {
//     pub field: String,
//     pub message: String,
// }


// Transformer for Request: RouterData -> XenditPaymentsRequest
impl TryFrom<&RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>>
    for XenditPaymentsRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let card_details = match &req.request.payment_method_data {
            PaymentMethodData::Card(cc) => Ok(cc),
            _ => Err(errors::ConnectorError::NotImplemented(
                "Only card payments are supported for Xendit Authorize".to_string(),
            )),
        }?;        

        let xendit_card_channel_properties = XenditCardChannelProperties {
            // Xendit needs to know if 3DS should be skipped. 
            // This might come from req.request.enrolled_for_3ds or connector metadata
            // Hyperswitch example: !xendit_card.three_ds.unwrap_or(true)
            // Assuming false means skip_three_d_secure = true
            skip_three_d_secure: if req.request.enrolled_for_3ds { Some(false) } else { Some(true) }, 
        };

        let xendit_card = XenditCard {
            currency: req.request.currency.to_string().to_uppercase(), // Xendit expects currency here for cards
            channel_properties: xendit_card_channel_properties,
        };

        let payment_method = XenditPaymentMethod {
            payment_method_type: XenditPaymentMethodType::Card,
            card: Some(xendit_card),
            reusability: "ONE_TIME_USE".to_string(), // Or based on req.request.setup_future_usage
        };

        Ok(Self {
            amount: req.request.minor_amount.get_amount_as_i64(),
            currency: req.request.currency.to_string().to_uppercase(),
            merchant_payment_id: req.resource_common_data.connector_request_reference_id.clone(),
            description: req.resource_common_data.description.clone(),
            customer_id: req.resource_common_data.customer_id.as_ref().map(|c| c.get_string_repr().to_string()),
            payment_method,
            statement_descriptor_suffix: req.request.statement_descriptor_suffix.clone(),
            items: None, // TODO: Map if items are provided in RouterData and Xendit supports them
            channel_properties: Some(XenditChannelProperties { // Basic channel props
                 customer_name: req.request.customer_name.clone(),
            }),
            // Populate based on req.request.router_return_url or similar
            success_redirect_url: req.request.router_return_url.clone(), 
            failure_redirect_url: req.request.router_return_url.clone(), // Often same as success, or a specific failure URL
        })
    }
}

// Transformer for Response: (XenditPaymentsResponse, RouterData) -> RouterDataV2 (for Authorize)
impl ForeignTryFrom<(XenditPaymentsResponse, RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>)> 
    for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData> 
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn foreign_try_from(
        (xendit_response, mut router_data): 
        (XenditPaymentsResponse, RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>)
    ) -> Result<Self, Self::Error> {
        let status = match xendit_response.status.to_uppercase().as_str() {
            "PENDING" => hyperswitch_common_enums::AttemptStatus::AuthenticationPending, // If redirection is present
            "SUCCEEDED" | "PAID" => hyperswitch_common_enums::AttemptStatus::Charged,
            "FAILED" => hyperswitch_common_enums::AttemptStatus::Failure,
            _ => hyperswitch_common_enums::AttemptStatus::Pending, // Default, or map more specific Xendit statuses
        };

        let redirection_data = xendit_response.actions.as_ref().and_then(|actions| {
            actions.desktop_redirect_url.as_ref().map(|url| {
                hyperswitch_router_response_types::RedirectForm::Form {
                    endpoint: url.clone(),
                    method: Method::Get, // Xendit redirects are usually GET
                    form_fields: std::collections::HashMap::new(), // No form fields for simple redirect
                }
            })
        });

        let payments_response_data = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(xendit_response.id.clone()),
            redirection_data: Box::new(redirection_data),
            connector_metadata: None, // Can populate with raw response if needed
            network_txn_id: None, // If Xendit provides this
            connector_response_reference_id: Some(xendit_response.merchant_payment_id.clone()),
            incremental_authorization_allowed: None, // Xendit specific?
        };
        
        router_data.response = Ok(payments_response_data);
        router_data.resource_common_data.status = status;
        // If error, populate error fields
        if status == hyperswitch_common_enums::AttemptStatus::Failure {
            router_data.response = Err(ErrorResponse {
                code: xendit_response.failure_code.unwrap_or_else(|| "HS_XENDIT_FAILURE".to_string()),
                message: xendit_response.failure_reason.unwrap_or_else(|| "Payment failed at Xendit".to_string()),
                reason: None,
                status_code: 0, // This should be http status code from connector if available
                attempt_status: Some(status),
                connector_transaction_id: Some(xendit_response.id),
            });
        }

        Ok(router_data)
    }
} 