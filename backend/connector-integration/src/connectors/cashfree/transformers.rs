//! Cashfree UPI Transformers
//!
//! This module contains request/response transformations for Cashfree UPI payment flows.
//! It implements the UPI flow differentiation logic based on the Cashfree UPI Implementation Guide.

use common_enums::AttemptStatus;
use hyperswitch_domain_models::{
    payment_method_data::{PaymentMethodData, UpiData},
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
};
use masking::{ExposeInterface, Secret};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use domain_types::{
    connector_flow::Authorize,
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData},
};

/// Cashfree Authentication Type
/// Based on Cashfree UPI Implementation Guide authentication requirements
#[derive(Debug, Clone)]
pub struct CashfreeAuthType {
    pub app_id: Secret<String>,
    pub secret_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for CashfreeAuthType {
    type Error = hyperswitch_interfaces::errors::ConnectorError;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey {
                api_key,
                key1: _,
                api_secret,
            } => Ok(Self {
                app_id: api_key.to_owned(),
                secret_key: api_secret.to_owned(),
            }),
            _ => Err(hyperswitch_interfaces::errors::ConnectorError::FailedToObtainAuthType),
        }
    }
}

/// Cashfree UPI Payment Request
/// Supports UPI Intent, QR, and Collect flows based on the implementation guide
#[derive(Debug, Serialize)]
pub struct CashfreePaymentRequest {
    #[serde(rename = "appId")]
    pub app_id: Secret<String>,
    #[serde(rename = "orderId")]
    pub order_id: String,
    #[serde(rename = "orderAmount")]
    pub order_amount: String,
    #[serde(rename = "orderCurrency")]
    pub order_currency: String,
    #[serde(rename = "orderNote")]
    pub order_note: String,
    #[serde(rename = "customerName")]
    pub customer_name: String,
    #[serde(rename = "customerPhone")]
    pub customer_phone: String,
    #[serde(rename = "customerEmail")]
    pub customer_email: String,
    #[serde(rename = "returnUrl")]
    pub return_url: String,
    #[serde(rename = "notifyUrl")]
    pub notify_url: String,
    pub signature: String,
    #[serde(rename = "paymentOption")]
    pub payment_option: String, // Always "upi" for UPI flows
    #[serde(rename = "upiMode", skip_serializing_if = "Option::is_none")]
    pub upi_mode: Option<String>, // "link" for Intent/QR, null for Collect
    #[serde(rename = "upi_vpa", skip_serializing_if = "String::is_empty")]
    pub upi_vpa: String, // VPA for Collect flow, empty for Intent/QR
    #[serde(rename = "secretKey", skip_serializing_if = "Option::is_none")]
    pub secret_key: Option<Secret<String>>, // Conditional inclusion
    #[serde(rename = "responseType", skip_serializing_if = "Option::is_none")]
    pub response_type: Option<String>, // "json" for specific flows
}

/// Cashfree UPI Payment Response
/// Handles responses for all UPI flow types
#[derive(Debug, Deserialize, Serialize)]
pub struct CashfreePaymentResponse {
    pub status: String,
    pub message: String,
    #[serde(rename = "txStatus")]
    pub tx_status: Option<String>,
    #[serde(rename = "orderAmount")]
    pub order_amount: Option<String>,
    #[serde(rename = "orderCurrency")]
    pub order_currency: Option<String>,
    #[serde(rename = "txMsg")]
    pub tx_msg: Option<String>,
    #[serde(rename = "txTime")]
    pub tx_time: Option<String>,
    #[serde(rename = "referenceId")]
    pub reference_id: Option<String>,
    #[serde(rename = "type")]
    pub response_type: Option<String>,
    pub link: Option<String>, // UPI intent deep link or QR data
}

/// UPI Flow Type based on source object
#[derive(Debug, Clone)]
pub enum UpiFlowType {
    Intent,  // UPI_PAY
    QR,      // UPI_QR
    Collect, // Other values
}

impl UpiFlowType {
    /// Determine UPI flow type from payment method data
    pub fn from_payment_method_data(payment_method_data: &PaymentMethodData) -> Self {
        match payment_method_data {
            PaymentMethodData::Upi(upi_data) => {
                match upi_data {
                    UpiData::UpiIntent(_) => Self::Intent,
                    UpiData::UpiCollect(_) => Self::Collect,
                    // Default to Intent for other UPI types
                    _ => Self::Intent,
                }
            }
            _ => Self::Collect, // Default fallback
        }
    }

    /// Get UPI mode for the flow type
    pub fn get_upi_mode(&self) -> Option<String> {
        match self {
            Self::Intent | Self::QR => Some("link".to_string()),
            Self::Collect => None,
        }
    }

    /// Check if secret key should be included
    pub fn should_include_secret_key(&self) -> bool {
        matches!(self, Self::Intent | Self::QR)
    }

    /// Check if response type should be JSON
    pub fn should_use_json_response(&self) -> bool {
        matches!(self, Self::Intent | Self::QR)
    }
}

impl TryFrom<&RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>>
    for CashfreePaymentRequest
{
    type Error = hyperswitch_interfaces::errors::ConnectorError;

    fn try_from(
        item: &RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData,
            PaymentsResponseData,
        >,
    ) -> Result<Self, Self::Error> {
        // Extract auth details
        let auth = CashfreeAuthType::try_from(&item.connector_auth_type)?;

        // Determine UPI flow type based on payment method
        let upi_flow = UpiFlowType::from_payment_method_data(&item.request.payment_method_data);

        // Extract real customer details from PaymentsAuthorizeData
        let customer_name = item
            .request
            .customer_name
            .as_ref()
            .map(|name| name.clone())
            .or_else(|| {
                // Try to extract from billing address.address
                item.resource_common_data
                    .address
                    .get_payment_billing()
                    .and_then(|billing| {
                        billing.address.as_ref().and_then(|addr| {
                            addr.first_name.as_ref().map(|f| f.clone().expose())
                        })
                    })
            })
            .unwrap_or_else(|| "Customer".to_string());

        let customer_email: String = item
            .request
            .email
            .as_ref()
            .map(|email| email.clone().expose().expose())
            .unwrap_or_else(|| "customer@example.com".to_string());

        // Extract customer phone from billing address
        let customer_phone = item
            .resource_common_data
            .address
            .get_payment_billing()
            .and_then(|billing| {
                billing.phone.as_ref().and_then(|phone| {
                    phone.number.as_ref().map(|number| number.clone().expose())
                })
            })
            .unwrap_or_else(|| "9999999999".to_string());

        // Extract VPA for collect flow
        let upi_vpa = match &upi_flow {
            UpiFlowType::Collect => match &item.request.payment_method_data {
                PaymentMethodData::Upi(UpiData::UpiCollect(collect_data)) => collect_data
                    .vpa_id
                    .as_ref()
                    .map(|vpa| vpa.clone().expose())
                    .unwrap_or_default(),
                _ => String::new(),
            },
            _ => String::new(),
        };

        // Build a temporary request to generate signature
        let temp_request = CashfreeLegacySessionRequest {
            app_id: auth.app_id.clone(),
            order_id: item.attempt_id.clone(),
            order_amount: item.request.amount.to_string(),
            order_currency: item.request.currency.to_string(),
            order_note: format!("Payment for order {}", item.attempt_id),
            customer_name: customer_name.clone(),
            customer_phone: customer_phone.clone(),
            customer_email: customer_email.clone(),
            return_url: item
                .request
                .complete_authorize_url
                .clone()
                .unwrap_or_default(),
            notify_url: item.request.webhook_url.clone().unwrap_or_default(),
            signature: String::new(), // Will be filled after generation
            payment_option: "upi".to_string(),
            upi_mode: upi_flow.get_upi_mode(),
            upi_vpa: upi_vpa.clone(),
            secret_key: if upi_flow.should_include_secret_key() {
                Some(auth.secret_key.clone())
            } else {
                None
            },
            response_type: if upi_flow.should_use_json_response() {
                Some("json".to_string())
            } else {
                None
            },
        };

        // Generate proper HMAC-SHA256 signature
        let signature = generate_cashfree_signature(&temp_request, &auth.secret_key.clone().expose())?;

        Ok(Self {
            app_id: auth.app_id,
            order_id: item.attempt_id.clone(),
            order_amount: item.request.amount.to_string(),
            order_currency: item.request.currency.to_string(),
            order_note: format!("Payment for order {}", item.attempt_id),
            customer_name,
            customer_phone,
            customer_email,
            return_url: item
                .request
                .complete_authorize_url
                .clone()
                .unwrap_or_default(),
            notify_url: item.request.webhook_url.clone().unwrap_or_default(),
            signature,
            payment_option: "upi".to_string(),
            upi_mode: upi_flow.get_upi_mode(),
            upi_vpa,
            secret_key: if upi_flow.should_include_secret_key() {
                Some(auth.secret_key)
            } else {
                None
            },
            response_type: if upi_flow.should_use_json_response() {
                Some("json".to_string())
            } else {
                None
            },
        })
    }
}

/// Cashfree Order Creation Request (New API)
/// Used for creating orders before payment authorization in the new API flow
#[derive(Debug, Serialize)]
pub struct CashfreeOrderRequest {
    #[serde(rename = "order_id")]
    pub order_id: String,
    #[serde(rename = "order_amount")]
    pub order_amount: f64,
    #[serde(rename = "order_currency")]
    pub order_currency: String,
    #[serde(rename = "order_note")]
    pub order_note: String,
    #[serde(rename = "customer_details")]
    pub customer_details: CashfreeCustomerDetails,
    #[serde(rename = "order_meta", skip_serializing_if = "Option::is_none")]
    pub order_meta: Option<serde_json::Value>,
}

/// Customer details for order creation
#[derive(Debug, Serialize)]
pub struct CashfreeCustomerDetails {
    #[serde(rename = "customer_id")]
    pub customer_id: String,
    #[serde(rename = "customer_name")]
    pub customer_name: String,
    #[serde(rename = "customer_email")]
    pub customer_email: String,
    #[serde(rename = "customer_phone")]
    pub customer_phone: String,
}

/// Cashfree Order Creation Response (New API)
/// Can be either V2 or V3 format based on Cashfree's response
#[derive(Debug, Deserialize, Serialize)]
pub struct CashfreeOrderResponse {
    #[serde(rename = "cf_order_id")]
    pub cf_order_id: Option<String>,
    #[serde(rename = "order_id")]
    pub order_id: String,
    #[serde(rename = "entity")]
    pub entity: String,
    #[serde(rename = "order_currency")]
    pub order_currency: String,
    #[serde(rename = "order_amount")]
    pub order_amount: f64,
    #[serde(rename = "order_status")]
    pub order_status: String,
    #[serde(rename = "payment_session_id")]
    pub payment_session_id: String,
    #[serde(rename = "order_token")]
    pub order_token: String,
    #[serde(rename = "order_expiry_time")]
    pub order_expiry_time: Option<String>,
    #[serde(rename = "order_note")]
    pub order_note: Option<String>,
    /// API version indicator - helps determine V2 vs V3 flow
    #[serde(rename = "api_version")]
    pub api_version: Option<String>,
    /// Order type indicator for sub-variation detection
    #[serde(rename = "order_type")]
    pub order_type: Option<String>,
}

impl CashfreeOrderResponse {
    /// Determine if this is a V3 order based on response fields
    /// According to the implementation guide, V3 orders have different structure
    pub fn is_v3_order(&self) -> bool {
        // V3 detection logic based on Cashfree implementation guide
        // V3 orders typically have api_version field or specific order_type
        self.api_version.as_ref().map_or(false, |v| v.contains("v3")) ||
        self.order_type.as_ref().map_or(false, |t| t == "v3") ||
        // Additional detection: V3 orders may have different entity types
        self.entity == "order_v3"
    }
    
    /// Get the appropriate order type enum for processing
    pub fn get_order_type(&self) -> CashfreeOrderType {
        if self.is_v3_order() {
            CashfreeOrderType::V3 {
                order_id: self.order_id.clone(),
                payment_session_id: self.payment_session_id.clone(),
                order_token: self.order_token.clone(),
            }
        } else {
            CashfreeOrderType::V2 {
                order_id: self.order_id.clone(),
                payment_session_id: self.payment_session_id.clone(),
                order_token: self.order_token.clone(),
            }
        }
    }
}

/// Order type enum to differentiate between V2 and V3 processing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CashfreeOrderType {
    V2 {
        order_id: String,
        payment_session_id: String,
        order_token: String,
    },
    V3 {
        order_id: String,
        payment_session_id: String,
        order_token: String,
    },
}

/// New API Payment Request using order token
#[derive(Debug, Serialize)]
pub struct CashfreeNewApiPaymentRequest {
    #[serde(rename = "payment_session_id")]
    pub payment_session_id: String,
    #[serde(rename = "payment_method")]
    pub payment_method: CashfreeNewApiPaymentMethod,
}

/// Payment method for new API
#[derive(Debug, Serialize)]
pub struct CashfreeNewApiPaymentMethod {
    pub upi: CashfreeNewApiUpiMethod,
}

/// UPI method configuration for new API
#[derive(Debug, Serialize)]
pub struct CashfreeNewApiUpiMethod {
    pub channel: String, // "link" or "collect"
    #[serde(rename = "upi_id", skip_serializing_if = "String::is_empty")]
    pub upi_id: String, // VPA for collect, empty for intent/QR
}

/// New API Payment Response
#[derive(Debug, Deserialize, Serialize)]
pub struct CashfreeNewApiPaymentResponse {
    #[serde(rename = "cf_payment_id")]
    pub cf_payment_id: Option<String>,
    #[serde(rename = "payment_status")]
    pub payment_status: String,
    #[serde(rename = "payment_amount")]
    pub payment_amount: Option<f64>,
    #[serde(rename = "payment_currency")]
    pub payment_currency: Option<String>,
    #[serde(rename = "payment_message")]
    pub payment_message: Option<String>,
    #[serde(rename = "payment_time")]
    pub payment_time: Option<String>,
    #[serde(rename = "bank_reference")]
    pub bank_reference: Option<String>,
    #[serde(rename = "auth_id")]
    pub auth_id: Option<String>,
    #[serde(rename = "payment_method")]
    pub payment_method: Option<serde_json::Value>,
    #[serde(rename = "data")]
    pub data: Option<CashfreePaymentData>,
}

/// Payment data containing UPI deep links or QR data
#[derive(Debug, Deserialize, Serialize)]
pub struct CashfreePaymentData {
    pub url: Option<String>, // UPI intent URL or payment URL
    pub payload: Option<serde_json::Value>, // Additional payment data
}

/// Legacy API Session Token Request (equivalent to makeCollectingPaymentDetailsRequest)
/// This prepares the complete payment request with signatures for the legacy API
#[derive(Debug, Serialize, Deserialize)]
pub struct CashfreeLegacySessionRequest {
    #[serde(rename = "appId")]
    pub app_id: Secret<String>,
    #[serde(rename = "orderId")]
    pub order_id: String,
    #[serde(rename = "orderAmount")]
    pub order_amount: String,
    #[serde(rename = "orderCurrency")]
    pub order_currency: String,
    #[serde(rename = "orderNote")]
    pub order_note: String,
    #[serde(rename = "customerName")]
    pub customer_name: String,
    #[serde(rename = "customerPhone")]
    pub customer_phone: String,
    #[serde(rename = "customerEmail")]
    pub customer_email: String,
    #[serde(rename = "returnUrl")]
    pub return_url: String,
    #[serde(rename = "notifyUrl")]
    pub notify_url: String,
    pub signature: String,
    #[serde(rename = "paymentOption")]
    pub payment_option: String, // Always "upi" for UPI flows
    #[serde(rename = "upiMode", skip_serializing_if = "Option::is_none")]
    pub upi_mode: Option<String>, // "link" for Intent/QR, null for Collect
    #[serde(rename = "upi_vpa", skip_serializing_if = "String::is_empty")]
    pub upi_vpa: String, // VPA for Collect flow, empty for Intent/QR
    #[serde(rename = "secretKey", skip_serializing_if = "Option::is_none")]
    pub secret_key: Option<Secret<String>>, // Conditional inclusion for UPI flows
    #[serde(rename = "responseType", skip_serializing_if = "Option::is_none")]
    pub response_type: Option<String>, // "json" for UPI flows
}

/// Legacy API Session Token Response
/// Contains the prepared payment request to be used in authorize call
#[derive(Debug, Deserialize, Serialize)]
pub struct CashfreeLegacySessionResponse {
    pub status: String,
    pub message: String,
    /// The prepared payment request (serialized as session token)
    pub prepared_request: serde_json::Value,
    /// Additional metadata
    pub metadata: Option<serde_json::Value>,
}

/// HMAC-SHA256 signature generation for Cashfree Legacy API
/// Implements the exact algorithm from Cashfree UPI Implementation Guide
pub fn generate_cashfree_signature(
    request: &CashfreeLegacySessionRequest,
    secret_key: &str,
) -> Result<String, hyperswitch_interfaces::errors::ConnectorError> {
    // Step 1: Convert request to key-value pairs (following Haskell jsonStringify approach)
    let mut params = HashMap::new();
    
    params.insert("appId".to_string(), request.app_id.clone().expose());
    params.insert("orderId".to_string(), request.order_id.clone());
    params.insert("orderAmount".to_string(), request.order_amount.clone());
    params.insert("orderCurrency".to_string(), request.order_currency.clone());
    params.insert("orderNote".to_string(), request.order_note.clone());
    params.insert("customerName".to_string(), request.customer_name.clone());
    params.insert("customerPhone".to_string(), request.customer_phone.clone());
    params.insert("customerEmail".to_string(), request.customer_email.clone());
    params.insert("returnUrl".to_string(), request.return_url.clone());
    params.insert("notifyUrl".to_string(), request.notify_url.clone());
    params.insert("paymentOption".to_string(), request.payment_option.clone());
    
    // Add conditional fields (only if present, matching Haskell logic)
    if let Some(upi_mode) = &request.upi_mode {
        params.insert("upiMode".to_string(), upi_mode.clone());
    }
    if !request.upi_vpa.is_empty() {
        params.insert("upi_vpa".to_string(), request.upi_vpa.clone());
    }
    if let Some(secret) = &request.secret_key {
        params.insert("secretKey".to_string(), secret.clone().expose());
    }
    if let Some(response_type) = &request.response_type {
        params.insert("responseType".to_string(), response_type.clone());
    }
    
    // Step 2: Sort parameters alphabetically by key (matching generateKeyValue)
    let mut sorted_params: Vec<(String, String)> = params.into_iter().collect();
    sorted_params.sort_by(|a, b| a.0.cmp(&b.0));
    
    // Step 3: Create key-value string format (matching Haskell generateKeyValue)
    let key_value_string = sorted_params
        .iter()
        .map(|(key, value)| format!("{}={}", key, value))
        .collect::<Vec<String>>()
        .join("&");
    
    // Step 4: Generate HMAC-SHA256 signature (matching Haskell hmac256base64)
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    
    type HmacSha256 = Hmac<Sha256>;
    
    let mut mac = HmacSha256::new_from_slice(secret_key.as_bytes())
        .map_err(|_| hyperswitch_interfaces::errors::ConnectorError::RequestEncodingFailed)?;
    
    mac.update(key_value_string.as_bytes());
    let result = mac.finalize().into_bytes();
    
    // Step 5: Convert to Base64 (matching Haskell base64 encoding)
    use base64::{engine::general_purpose, Engine as _};
    Ok(general_purpose::STANDARD.encode(result))
}

// TryFrom implementations for Session Token Creation

impl TryFrom<&RouterDataV2<domain_types::connector_flow::CreateSessionToken, PaymentFlowData, domain_types::connector_types::SessionTokenRequestData, domain_types::connector_types::SessionTokenResponseData>> for CashfreeLegacySessionRequest {
    type Error = hyperswitch_interfaces::errors::ConnectorError;

    fn try_from(
        item: &RouterDataV2<
            domain_types::connector_flow::CreateSessionToken,
            PaymentFlowData,
            domain_types::connector_types::SessionTokenRequestData,
            domain_types::connector_types::SessionTokenResponseData,
        >,
    ) -> Result<Self, Self::Error> {
        // Extract auth details
        let auth = CashfreeAuthType::try_from(&item.connector_auth_type)?;

        // Convert MinorUnit to string (divide by 100 to get major units)
        let order_amount = (item.request.amount.get_amount_as_i64() as f64 / 100.0).to_string();

        // For session token creation, we need to prepare the payment request
        // We'll use placeholder UPI flow type since this will be determined later in authorize
        let upi_flow = UpiFlowType::Intent; // Default for session token creation

        // Extract customer details from available data
        let billing_address = item.resource_common_data.address.get_payment_billing();
        
        let customer_name = billing_address
            .and_then(|billing| {
                billing.address.as_ref().and_then(|addr| {
                    addr.first_name.as_ref().map(|f| f.clone().expose())
                })
            })
            .unwrap_or_else(|| "Customer".to_string());
            
        let customer_email: String = match billing_address {
            Some(billing) => match billing.email.as_ref() {
                Some(email) => email.clone().expose().expose(),
                None => "customer@example.com".to_string(),
            },
            None => "customer@example.com".to_string(),
        };
            
        let customer_phone = billing_address
            .and_then(|billing| {
                billing.phone.as_ref().and_then(|phone| {
                    phone.number.as_ref().map(|number| number.clone().expose())
                })
            })
            .unwrap_or_else(|| "9999999999".to_string());

        // Create initial request without signature
        let mut request = Self {
            app_id: auth.app_id.clone(),
            order_id: item.attempt_id.clone(),
            order_amount,
            order_currency: item.request.currency.to_string(),
            order_note: format!("Payment for order {}", item.attempt_id),
            customer_name,
            customer_phone,
            customer_email,
            return_url: "https://example.com/return".to_string(), // Default, will be updated in authorize
            notify_url: "https://example.com/notify".to_string(), // Default, will be updated in authorize
            signature: String::new(), // Will be generated below
            payment_option: "upi".to_string(),
            upi_mode: upi_flow.get_upi_mode(),
            upi_vpa: String::new(), // Will be set in authorize for collect flows
            secret_key: if upi_flow.should_include_secret_key() {
                Some(auth.secret_key.clone())
            } else {
                None
            },
            response_type: if upi_flow.should_use_json_response() {
                Some("json".to_string())
            } else {
                None
            },
        };

        // Generate signature using the secret key
        let signature = generate_cashfree_signature(&request, &auth.secret_key.expose())?;
        request.signature = signature;

        Ok(request)
    }
}

// TryFrom implementations for Order Creation (New API)

impl TryFrom<&RouterDataV2<domain_types::connector_flow::CreateOrder, PaymentFlowData, domain_types::connector_types::PaymentCreateOrderData, domain_types::connector_types::PaymentCreateOrderResponse>> for CashfreeOrderRequest {
    type Error = hyperswitch_interfaces::errors::ConnectorError;

    fn try_from(
        item: &RouterDataV2<
            domain_types::connector_flow::CreateOrder,
            PaymentFlowData,
            domain_types::connector_types::PaymentCreateOrderData,
            domain_types::connector_types::PaymentCreateOrderResponse,
        >,
    ) -> Result<Self, Self::Error> {
        // Convert MinorUnit to f64 (divide by 100 to get major units)
        let order_amount = item.request.amount.get_amount_as_i64() as f64 / 100.0;

        // Extract real customer details for order creation
        let billing_address = item.resource_common_data.address.get_payment_billing();
        
        let customer_name = billing_address
            .and_then(|billing| {
                billing.address.as_ref().and_then(|addr| {
                    addr.first_name.as_ref().map(|f| f.clone().expose())
                })
            })
            .unwrap_or_else(|| "Customer".to_string());
            
        let customer_email: String = match billing_address {
            Some(billing) => match billing.email.as_ref() {
                Some(email) => email.clone().expose().expose(),
                None => "customer@example.com".to_string(),
            },
            None => "customer@example.com".to_string(),
        };
            
        let customer_phone = billing_address
            .and_then(|billing| {
                billing.phone.as_ref().and_then(|phone| {
                    phone.number.as_ref().map(|number| number.clone().expose())
                })
            })
            .unwrap_or_else(|| "9999999999".to_string());

        Ok(Self {
            order_id: item.attempt_id.clone(),
            order_amount,
            order_currency: item.request.currency.to_string(),
            order_note: format!("Payment for order {}", item.attempt_id),
            customer_details: CashfreeCustomerDetails {
                customer_id: item.attempt_id.clone(),
                customer_name,
                customer_email,
                customer_phone,
            },
            order_meta: None,
        })
    }
}

impl TryFrom<&RouterDataV2<domain_types::connector_flow::Authorize, PaymentFlowData, domain_types::connector_types::PaymentsAuthorizeData, domain_types::connector_types::PaymentsResponseData>> for CashfreeNewApiPaymentRequest {
    type Error = hyperswitch_interfaces::errors::ConnectorError;

    fn try_from(
        item: &RouterDataV2<
            domain_types::connector_flow::Authorize,
            PaymentFlowData,
            domain_types::connector_types::PaymentsAuthorizeData,
            domain_types::connector_types::PaymentsResponseData,
        >,
    ) -> Result<Self, Self::Error> {
        // Extract payment session ID from session_token (which contains order_id/order_token from CreateOrder)
        let payment_session_id = item
            .resource_common_data
            .session_token
            .clone()
            .unwrap_or_else(|| "session_placeholder".to_string()); // This should come from CreateOrder response

        // Determine UPI flow type based on payment method
        let upi_flow = UpiFlowType::from_payment_method_data(&item.request.payment_method_data);

        // Extract VPA for collect flow
        let upi_id = match &upi_flow {
            UpiFlowType::Collect => match &item.request.payment_method_data {
                PaymentMethodData::Upi(UpiData::UpiCollect(collect_data)) => collect_data
                    .vpa_id
                    .as_ref()
                    .map(|vpa| vpa.clone().expose())
                    .unwrap_or_default(),
                _ => String::new(),
            },
            _ => String::new(),
        };

        // For v2 requests, we use standard channels - the actual v2/v3 differentiation
        // will be handled by different API calls based on the order type  
        let channel = match upi_flow {
            UpiFlowType::Intent | UpiFlowType::QR => "link",
            UpiFlowType::Collect => "collect",
        };

        Ok(Self {
            payment_session_id,
            payment_method: CashfreeNewApiPaymentMethod {
                upi: CashfreeNewApiUpiMethod {
                    channel: channel.to_string(),
                    upi_id,
                },
            },
        })
    }
}

/// Error Response from Cashfree
#[derive(Debug, Deserialize)]
pub struct CashfreeErrorResponse {
    pub status: String,
    pub message: String,
    pub subcode: Option<String>,
}

impl From<CashfreeErrorResponse> for ErrorResponse {
    fn from(error_response: CashfreeErrorResponse) -> Self {
        Self {
            status_code: 400, // Default status code
            code: error_response.status,
            message: error_response.message,
            reason: error_response.subcode,
            attempt_status: Some(AttemptStatus::Failure),
            connector_transaction_id: None,
            network_decline_code: None,
            network_advice_code: None,
            network_error_message: None,
        }
    }
}
