//! FFI layer for connector-service transformation logic.
//!
//! This crate exposes the core transformation logic via C-compatible FFI,
//! allowing foreign languages (JS, Java, Python, etc.) to:
//!
//! 1. Transform payment requests into connector-specific HTTP requests
//! 2. Transform connector HTTP responses back into standardized payment responses
//!
//! The foreign language is responsible for executing the actual HTTP request
//! using its native HTTP client.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

// =============================================================================
// Data Types
// =============================================================================

/// Supported connectors
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Connector {
    Stripe,
    Adyen,
    Checkout,
    Braintree,
    Razorpay,
    Phonepe,
    Forte,
}

impl Connector {
    fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "stripe" => Some(Self::Stripe),
            "adyen" => Some(Self::Adyen),
            "checkout" => Some(Self::Checkout),
            "braintree" => Some(Self::Braintree),
            "razorpay" => Some(Self::Razorpay),
            "phonepe" => Some(Self::Phonepe),
            "forte" => Some(Self::Forte),
            _ => None,
        }
    }

    fn base_url(&self) -> &'static str {
        match self {
            Self::Stripe => "https://api.stripe.com/v1",
            Self::Adyen => "https://checkout-test.adyen.com/v71",
            Self::Checkout => "https://api.sandbox.checkout.com",
            Self::Braintree => "https://payments.sandbox.braintree-api.com/graphql",
            Self::Razorpay => "https://api.razorpay.com/v1",
            Self::Phonepe => "https://api.phonepe.com/apis/hermes",
            Self::Forte => "https://sandbox.forte.net/api/v3",
        }
    }
}

/// Supported payment flows
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Flow {
    Authorize,
    Capture,
    Void,
    Refund,
    Sync,
}

impl Flow {
    fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "authorize" | "auth" => Some(Self::Authorize),
            "capture" => Some(Self::Capture),
            "void" | "cancel" => Some(Self::Void),
            "refund" => Some(Self::Refund),
            "sync" | "status" => Some(Self::Sync),
            _ => None,
        }
    }
}

/// HTTP method
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
}

/// Request transformation input
#[derive(Debug, Deserialize)]
pub struct TransformRequestInput {
    pub connector: String,
    pub flow: String,
    pub auth: AuthCredentials,
    pub payment: PaymentData,
    #[serde(default)]
    pub config: Option<ConnectorConfig>,
}

/// Connector authentication credentials
#[derive(Debug, Deserialize)]
pub struct AuthCredentials {
    pub api_key: Option<String>,
    pub api_secret: Option<String>,
    pub merchant_id: Option<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, String>,
}

/// Connector-specific configuration
#[derive(Debug, Deserialize)]
pub struct ConnectorConfig {
    pub base_url: Option<String>,
}

/// Payment data for transformation
#[derive(Debug, Deserialize)]
pub struct PaymentData {
    /// Amount in minor units (cents)
    pub amount: i64,
    /// 3-letter currency code
    pub currency: String,
    /// Reference ID for this payment
    #[serde(default)]
    pub reference_id: Option<String>,
    /// Payment method details
    #[serde(default)]
    pub payment_method: Option<PaymentMethodData>,
    /// For capture/void/refund: the original transaction ID
    #[serde(default)]
    pub transaction_id: Option<String>,
    /// Additional metadata
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Payment method data
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum PaymentMethodData {
    Card {
        number: String,
        exp_month: u32,
        exp_year: u32,
        cvc: String,
        #[serde(default)]
        holder_name: Option<String>,
    },
    Wallet {
        wallet_type: String,
        token: String,
    },
    BankTransfer {
        bank_code: Option<String>,
        account_number: Option<String>,
    },
}

/// HTTP request components (output of transform_request)
#[derive(Debug, Serialize)]
pub struct HttpRequest {
    pub url: String,
    pub method: HttpMethod,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub body_type: String,
}

/// Transformation result
#[derive(Debug, Serialize)]
pub struct TransformResult<T> {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorInfo>,
}

/// Error information
#[derive(Debug, Serialize)]
pub struct ErrorInfo {
    pub code: String,
    pub message: String,
}

/// Response transformation input
#[derive(Debug, Deserialize)]
pub struct TransformResponseInput {
    pub connector: String,
    pub flow: String,
    pub status_code: u16,
    pub body: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
}

/// Standardized payment response
#[derive(Debug, Serialize)]
pub struct PaymentResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_response: Option<serde_json::Value>,
}

// =============================================================================
// Core Transformation Logic
// =============================================================================

/// Transform a payment request to connector-specific HTTP request
pub fn transform_request(input: &TransformRequestInput) -> TransformResult<HttpRequest> {
    let connector = match Connector::from_str(&input.connector) {
        Some(c) => c,
        None => {
            return TransformResult {
                success: false,
                data: None,
                error: Some(ErrorInfo {
                    code: "UNKNOWN_CONNECTOR".to_string(),
                    message: format!("Unknown connector: {}", input.connector),
                }),
            }
        }
    };

    let flow = match Flow::from_str(&input.flow) {
        Some(f) => f,
        None => {
            return TransformResult {
                success: false,
                data: None,
                error: Some(ErrorInfo {
                    code: "UNKNOWN_FLOW".to_string(),
                    message: format!("Unknown flow: {}", input.flow),
                }),
            }
        }
    };

    let base_url = input
        .config
        .as_ref()
        .and_then(|c| c.base_url.as_deref())
        .unwrap_or_else(|| connector.base_url());

    match connector {
        Connector::Stripe => transform_stripe_request(base_url, flow, &input.auth, &input.payment),
        Connector::Adyen => transform_adyen_request(base_url, flow, &input.auth, &input.payment),
        Connector::Forte => transform_forte_request(base_url, flow, &input.auth, &input.payment),
        _ => transform_generic_request(connector, base_url, flow, &input.auth, &input.payment),
    }
}

/// Transform connector response to standardized payment response
pub fn transform_response(input: &TransformResponseInput) -> TransformResult<PaymentResponse> {
    let connector = match Connector::from_str(&input.connector) {
        Some(c) => c,
        None => {
            return TransformResult {
                success: false,
                data: None,
                error: Some(ErrorInfo {
                    code: "UNKNOWN_CONNECTOR".to_string(),
                    message: format!("Unknown connector: {}", input.connector),
                }),
            }
        }
    };

    match connector {
        Connector::Stripe => transform_stripe_response(input),
        Connector::Adyen => transform_adyen_response(input),
        Connector::Forte => transform_forte_response(input),
        _ => transform_generic_response(input),
    }
}

// =============================================================================
// Stripe Transformations
// =============================================================================

fn transform_stripe_request(
    base_url: &str,
    flow: Flow,
    auth: &AuthCredentials,
    payment: &PaymentData,
) -> TransformResult<HttpRequest> {
    let api_key = match &auth.api_key {
        Some(k) => k,
        None => {
            return TransformResult {
                success: false,
                data: None,
                error: Some(ErrorInfo {
                    code: "MISSING_API_KEY".to_string(),
                    message: "Stripe requires api_key".to_string(),
                }),
            }
        }
    };

    let mut headers = HashMap::new();
    headers.insert("Authorization".to_string(), format!("Bearer {}", api_key));
    headers.insert(
        "Content-Type".to_string(),
        "application/x-www-form-urlencoded".to_string(),
    );

    let (url, method, body) = match flow {
        Flow::Authorize => {
            let url = format!("{}/payment_intents", base_url);

            let mut params = vec![
                format!("amount={}", payment.amount),
                format!("currency={}", payment.currency.to_lowercase()),
            ];

            if let Some(ref pm) = payment.payment_method {
                match pm {
                    PaymentMethodData::Card {
                        number,
                        exp_month,
                        exp_year,
                        cvc,
                        ..
                    } => {
                        params.push(format!("payment_method_data[type]=card"));
                        params.push(format!("payment_method_data[card][number]={}", number));
                        params.push(format!("payment_method_data[card][exp_month]={}", exp_month));
                        params.push(format!("payment_method_data[card][exp_year]={}", exp_year));
                        params.push(format!("payment_method_data[card][cvc]={}", cvc));
                    }
                    _ => {}
                }
            }

            params.push("confirm=true".to_string());

            (url, HttpMethod::Post, Some(params.join("&")))
        }
        Flow::Capture => {
            let txn_id = payment
                .transaction_id
                .as_deref()
                .unwrap_or("pi_unknown");
            let url = format!("{}/payment_intents/{}/capture", base_url, txn_id);
            let body = format!("amount_to_capture={}", payment.amount);
            (url, HttpMethod::Post, Some(body))
        }
        Flow::Void => {
            let txn_id = payment
                .transaction_id
                .as_deref()
                .unwrap_or("pi_unknown");
            let url = format!("{}/payment_intents/{}/cancel", base_url, txn_id);
            (url, HttpMethod::Post, None)
        }
        Flow::Refund => {
            let url = format!("{}/refunds", base_url);
            let txn_id = payment
                .transaction_id
                .as_deref()
                .unwrap_or("pi_unknown");
            let body = format!("payment_intent={}&amount={}", txn_id, payment.amount);
            (url, HttpMethod::Post, Some(body))
        }
        Flow::Sync => {
            let txn_id = payment
                .transaction_id
                .as_deref()
                .unwrap_or("pi_unknown");
            let url = format!("{}/payment_intents/{}", base_url, txn_id);
            (url, HttpMethod::Get, None)
        }
    };

    TransformResult {
        success: true,
        data: Some(HttpRequest {
            url,
            method,
            headers,
            body,
            body_type: "form".to_string(),
        }),
        error: None,
    }
}

fn transform_stripe_response(input: &TransformResponseInput) -> TransformResult<PaymentResponse> {
    let raw: serde_json::Value = match serde_json::from_str(&input.body) {
        Ok(v) => v,
        Err(e) => {
            return TransformResult {
                success: false,
                data: None,
                error: Some(ErrorInfo {
                    code: "PARSE_ERROR".to_string(),
                    message: format!("Failed to parse response: {}", e),
                }),
            }
        }
    };

    if input.status_code >= 400 {
        let error_code = raw["error"]["code"]
            .as_str()
            .unwrap_or("unknown")
            .to_string();
        let error_message = raw["error"]["message"]
            .as_str()
            .unwrap_or("Unknown error")
            .to_string();

        return TransformResult {
            success: true,
            data: Some(PaymentResponse {
                status: "failed".to_string(),
                transaction_id: None,
                amount: None,
                currency: None,
                error_code: Some(error_code),
                error_message: Some(error_message),
                raw_response: Some(raw),
            }),
            error: None,
        };
    }

    let status = match raw["status"].as_str() {
        Some("succeeded") => "succeeded",
        Some("requires_capture") => "authorized",
        Some("requires_action") => "requires_action",
        Some("canceled") => "cancelled",
        Some("processing") => "pending",
        _ => "unknown",
    };

    TransformResult {
        success: true,
        data: Some(PaymentResponse {
            status: status.to_string(),
            transaction_id: raw["id"].as_str().map(|s| s.to_string()),
            amount: raw["amount"].as_i64(),
            currency: raw["currency"].as_str().map(|s| s.to_uppercase()),
            error_code: None,
            error_message: None,
            raw_response: Some(raw),
        }),
        error: None,
    }
}

// =============================================================================
// Adyen Transformations
// =============================================================================

fn transform_adyen_request(
    base_url: &str,
    flow: Flow,
    auth: &AuthCredentials,
    payment: &PaymentData,
) -> TransformResult<HttpRequest> {
    let api_key = match &auth.api_key {
        Some(k) => k,
        None => {
            return TransformResult {
                success: false,
                data: None,
                error: Some(ErrorInfo {
                    code: "MISSING_API_KEY".to_string(),
                    message: "Adyen requires api_key".to_string(),
                }),
            }
        }
    };

    let merchant_account = auth
        .merchant_id
        .as_deref()
        .unwrap_or("TestMerchant");

    let mut headers = HashMap::new();
    headers.insert("X-API-Key".to_string(), api_key.clone());
    headers.insert("Content-Type".to_string(), "application/json".to_string());

    let (url, method, body) = match flow {
        Flow::Authorize => {
            let url = format!("{}/payments", base_url);

            let mut request = serde_json::json!({
                "merchantAccount": merchant_account,
                "amount": {
                    "value": payment.amount,
                    "currency": payment.currency.to_uppercase()
                },
                "reference": payment.reference_id.as_deref().unwrap_or("ref_001")
            });

            if let Some(ref pm) = payment.payment_method {
                match pm {
                    PaymentMethodData::Card {
                        number,
                        exp_month,
                        exp_year,
                        cvc,
                        holder_name,
                    } => {
                        request["paymentMethod"] = serde_json::json!({
                            "type": "scheme",
                            "number": number,
                            "expiryMonth": format!("{:02}", exp_month),
                            "expiryYear": format!("{}", exp_year),
                            "cvc": cvc,
                            "holderName": holder_name.as_deref().unwrap_or("Card Holder")
                        });
                    }
                    _ => {}
                }
            }

            (url, HttpMethod::Post, Some(serde_json::to_string(&request).unwrap_or_default()))
        }
        Flow::Capture => {
            let txn_id = payment
                .transaction_id
                .as_deref()
                .unwrap_or("unknown");
            let url = format!("{}/payments/{}/captures", base_url, txn_id);
            let body = serde_json::json!({
                "merchantAccount": merchant_account,
                "amount": {
                    "value": payment.amount,
                    "currency": payment.currency.to_uppercase()
                }
            });
            (url, HttpMethod::Post, Some(serde_json::to_string(&body).unwrap_or_default()))
        }
        Flow::Void => {
            let txn_id = payment
                .transaction_id
                .as_deref()
                .unwrap_or("unknown");
            let url = format!("{}/payments/{}/cancels", base_url, txn_id);
            let body = serde_json::json!({
                "merchantAccount": merchant_account
            });
            (url, HttpMethod::Post, Some(serde_json::to_string(&body).unwrap_or_default()))
        }
        Flow::Refund => {
            let txn_id = payment
                .transaction_id
                .as_deref()
                .unwrap_or("unknown");
            let url = format!("{}/payments/{}/refunds", base_url, txn_id);
            let body = serde_json::json!({
                "merchantAccount": merchant_account,
                "amount": {
                    "value": payment.amount,
                    "currency": payment.currency.to_uppercase()
                }
            });
            (url, HttpMethod::Post, Some(serde_json::to_string(&body).unwrap_or_default()))
        }
        Flow::Sync => {
            // Adyen doesn't have a direct sync endpoint, use notifications
            let txn_id = payment
                .transaction_id
                .as_deref()
                .unwrap_or("unknown");
            let url = format!("{}/payments/{}", base_url, txn_id);
            (url, HttpMethod::Get, None)
        }
    };

    TransformResult {
        success: true,
        data: Some(HttpRequest {
            url,
            method,
            headers,
            body,
            body_type: "json".to_string(),
        }),
        error: None,
    }
}

fn transform_adyen_response(input: &TransformResponseInput) -> TransformResult<PaymentResponse> {
    let raw: serde_json::Value = match serde_json::from_str(&input.body) {
        Ok(v) => v,
        Err(e) => {
            return TransformResult {
                success: false,
                data: None,
                error: Some(ErrorInfo {
                    code: "PARSE_ERROR".to_string(),
                    message: format!("Failed to parse response: {}", e),
                }),
            }
        }
    };

    if input.status_code >= 400 {
        let error_code = raw["errorCode"]
            .as_str()
            .unwrap_or("unknown")
            .to_string();
        let error_message = raw["message"]
            .as_str()
            .unwrap_or("Unknown error")
            .to_string();

        return TransformResult {
            success: true,
            data: Some(PaymentResponse {
                status: "failed".to_string(),
                transaction_id: None,
                amount: None,
                currency: None,
                error_code: Some(error_code),
                error_message: Some(error_message),
                raw_response: Some(raw),
            }),
            error: None,
        };
    }

    let status = match raw["resultCode"].as_str() {
        Some("Authorised") => "succeeded",
        Some("Pending") | Some("Received") => "pending",
        Some("Cancelled") => "cancelled",
        Some("Refused") | Some("Error") => "failed",
        Some("RedirectShopper") => "requires_action",
        _ => "unknown",
    };

    TransformResult {
        success: true,
        data: Some(PaymentResponse {
            status: status.to_string(),
            transaction_id: raw["pspReference"].as_str().map(|s| s.to_string()),
            amount: raw["amount"]["value"].as_i64(),
            currency: raw["amount"]["currency"].as_str().map(|s| s.to_string()),
            error_code: raw["refusalReasonCode"].as_str().map(|s| s.to_string()),
            error_message: raw["refusalReason"].as_str().map(|s| s.to_string()),
            raw_response: Some(raw),
        }),
        error: None,
    }
}

// =============================================================================
// Forte Transformations
// =============================================================================

fn transform_forte_request(
    base_url: &str,
    flow: Flow,
    auth: &AuthCredentials,
    payment: &PaymentData,
) -> TransformResult<HttpRequest> {
    let api_access_id = match &auth.api_key {
        Some(k) => k,
        None => {
            return TransformResult {
                success: false,
                data: None,
                error: Some(ErrorInfo {
                    code: "MISSING_API_KEY".to_string(),
                    message: "Forte requires api_key (api_access_id)".to_string(),
                }),
            }
        }
    };

    let api_secret = match &auth.api_secret {
        Some(k) => k,
        None => {
            return TransformResult {
                success: false,
                data: None,
                error: Some(ErrorInfo {
                    code: "MISSING_API_SECRET".to_string(),
                    message: "Forte requires api_secret".to_string(),
                }),
            }
        }
    };

    let org_id = auth.extra.get("organization_id").map(|s| s.as_str()).unwrap_or("org_default");
    let loc_id = auth.extra.get("location_id").map(|s| s.as_str()).unwrap_or("loc_default");

    let mut headers = HashMap::new();
    let auth_string = base64_encode(&format!("{}:{}", api_access_id, api_secret));
    headers.insert("Authorization".to_string(), format!("Basic {}", auth_string));
    headers.insert("Content-Type".to_string(), "application/json".to_string());
    headers.insert("X-Forte-Auth-Organization-Id".to_string(), org_id.to_string());

    let (url, method, body) = match flow {
        Flow::Authorize => {
            let url = format!("{}/organizations/{}/locations/{}/transactions", base_url, org_id, loc_id);

            let amount_str = format!("{:.2}", payment.amount as f64 / 100.0);

            let mut request = serde_json::json!({
                "action": "sale",
                "authorization_amount": amount_str
            });

            if let Some(ref pm) = payment.payment_method {
                match pm {
                    PaymentMethodData::Card {
                        number,
                        exp_month,
                        exp_year,
                        cvc,
                        holder_name,
                    } => {
                        request["card"] = serde_json::json!({
                            "card_type": detect_card_type(number),
                            "name_on_card": holder_name.as_deref().unwrap_or("Card Holder"),
                            "account_number": number,
                            "expire_month": format!("{:02}", exp_month),
                            "expire_year": format!("{}", exp_year % 100),
                            "card_verification_value": cvc
                        });
                    }
                    _ => {}
                }
            }

            (url, HttpMethod::Post, Some(serde_json::to_string(&request).unwrap_or_default()))
        }
        Flow::Capture => {
            let url = format!("{}/organizations/{}/locations/{}/transactions", base_url, org_id, loc_id);
            let txn_id = payment.transaction_id.as_deref().unwrap_or("unknown");
            let amount_str = format!("{:.2}", payment.amount as f64 / 100.0);
            let body = serde_json::json!({
                "action": "capture",
                "transaction_id": txn_id,
                "authorization_amount": amount_str
            });
            (url, HttpMethod::Put, Some(serde_json::to_string(&body).unwrap_or_default()))
        }
        Flow::Void => {
            let txn_id = payment.transaction_id.as_deref().unwrap_or("unknown");
            let url = format!("{}/organizations/{}/locations/{}/transactions/{}", base_url, org_id, loc_id, txn_id);
            let body = serde_json::json!({
                "action": "void",
                "transaction_id": txn_id
            });
            (url, HttpMethod::Put, Some(serde_json::to_string(&body).unwrap_or_default()))
        }
        Flow::Refund => {
            let url = format!("{}/organizations/{}/locations/{}/transactions", base_url, org_id, loc_id);
            let txn_id = payment.transaction_id.as_deref().unwrap_or("unknown");
            let amount_str = format!("{:.2}", payment.amount as f64 / 100.0);
            let body = serde_json::json!({
                "action": "credit",
                "original_transaction_id": txn_id,
                "authorization_amount": amount_str
            });
            (url, HttpMethod::Post, Some(serde_json::to_string(&body).unwrap_or_default()))
        }
        Flow::Sync => {
            let txn_id = payment.transaction_id.as_deref().unwrap_or("unknown");
            let url = format!("{}/organizations/{}/locations/{}/transactions/{}", base_url, org_id, loc_id, txn_id);
            (url, HttpMethod::Get, None)
        }
    };

    TransformResult {
        success: true,
        data: Some(HttpRequest {
            url,
            method,
            headers,
            body,
            body_type: "json".to_string(),
        }),
        error: None,
    }
}

fn transform_forte_response(input: &TransformResponseInput) -> TransformResult<PaymentResponse> {
    let raw: serde_json::Value = match serde_json::from_str(&input.body) {
        Ok(v) => v,
        Err(e) => {
            return TransformResult {
                success: false,
                data: None,
                error: Some(ErrorInfo {
                    code: "PARSE_ERROR".to_string(),
                    message: format!("Failed to parse response: {}", e),
                }),
            }
        }
    };

    if input.status_code >= 400 {
        let error_code = raw["response"]["response_code"]
            .as_str()
            .unwrap_or("unknown")
            .to_string();
        let error_message = raw["response"]["response_desc"]
            .as_str()
            .unwrap_or("Unknown error")
            .to_string();

        return TransformResult {
            success: true,
            data: Some(PaymentResponse {
                status: "failed".to_string(),
                transaction_id: None,
                amount: None,
                currency: None,
                error_code: Some(error_code),
                error_message: Some(error_message),
                raw_response: Some(raw),
            }),
            error: None,
        };
    }

    let response_code = raw["response"]["response_code"].as_str().unwrap_or("");
    let status = if response_code.starts_with("A") {
        "succeeded"
    } else if response_code.starts_with("U") {
        "pending"
    } else {
        "failed"
    };

    TransformResult {
        success: true,
        data: Some(PaymentResponse {
            status: status.to_string(),
            transaction_id: raw["transaction_id"].as_str().map(|s| s.to_string()),
            amount: raw["authorization_amount"]
                .as_str()
                .and_then(|s| s.parse::<f64>().ok())
                .map(|f| (f * 100.0) as i64),
            currency: Some("USD".to_string()), // Forte is USD-only
            error_code: if status == "failed" {
                raw["response"]["response_code"].as_str().map(|s| s.to_string())
            } else {
                None
            },
            error_message: if status == "failed" {
                raw["response"]["response_desc"].as_str().map(|s| s.to_string())
            } else {
                None
            },
            raw_response: Some(raw),
        }),
        error: None,
    }
}

// =============================================================================
// Generic Transformations
// =============================================================================

fn transform_generic_request(
    _connector: Connector,
    base_url: &str,
    flow: Flow,
    auth: &AuthCredentials,
    payment: &PaymentData,
) -> TransformResult<HttpRequest> {
    let mut headers = HashMap::new();

    if let Some(ref api_key) = auth.api_key {
        headers.insert("Authorization".to_string(), format!("Bearer {}", api_key));
    }
    headers.insert("Content-Type".to_string(), "application/json".to_string());

    let (url, method, body) = match flow {
        Flow::Authorize => {
            let url = format!("{}/payments", base_url);
            let body = serde_json::json!({
                "amount": payment.amount,
                "currency": payment.currency,
                "reference": payment.reference_id
            });
            (url, HttpMethod::Post, Some(serde_json::to_string(&body).unwrap_or_default()))
        }
        Flow::Capture => {
            let txn_id = payment.transaction_id.as_deref().unwrap_or("unknown");
            let url = format!("{}/payments/{}/capture", base_url, txn_id);
            let body = serde_json::json!({ "amount": payment.amount });
            (url, HttpMethod::Post, Some(serde_json::to_string(&body).unwrap_or_default()))
        }
        Flow::Void => {
            let txn_id = payment.transaction_id.as_deref().unwrap_or("unknown");
            let url = format!("{}/payments/{}/cancel", base_url, txn_id);
            (url, HttpMethod::Post, None)
        }
        Flow::Refund => {
            let txn_id = payment.transaction_id.as_deref().unwrap_or("unknown");
            let url = format!("{}/payments/{}/refund", base_url, txn_id);
            let body = serde_json::json!({ "amount": payment.amount });
            (url, HttpMethod::Post, Some(serde_json::to_string(&body).unwrap_or_default()))
        }
        Flow::Sync => {
            let txn_id = payment.transaction_id.as_deref().unwrap_or("unknown");
            let url = format!("{}/payments/{}", base_url, txn_id);
            (url, HttpMethod::Get, None)
        }
    };

    TransformResult {
        success: true,
        data: Some(HttpRequest {
            url,
            method,
            headers,
            body,
            body_type: "json".to_string(),
        }),
        error: None,
    }
}

fn transform_generic_response(input: &TransformResponseInput) -> TransformResult<PaymentResponse> {
    let raw: serde_json::Value = serde_json::from_str(&input.body).unwrap_or(serde_json::json!({}));

    let status = if input.status_code >= 400 {
        "failed"
    } else if input.status_code == 202 {
        "pending"
    } else {
        "succeeded"
    };

    TransformResult {
        success: true,
        data: Some(PaymentResponse {
            status: status.to_string(),
            transaction_id: raw["id"]
                .as_str()
                .or_else(|| raw["transaction_id"].as_str())
                .map(|s| s.to_string()),
            amount: raw["amount"].as_i64(),
            currency: raw["currency"].as_str().map(|s| s.to_string()),
            error_code: raw["error"]["code"].as_str().map(|s| s.to_string()),
            error_message: raw["error"]["message"].as_str().map(|s| s.to_string()),
            raw_response: Some(raw),
        }),
        error: None,
    }
}

// =============================================================================
// Utility Functions
// =============================================================================

fn base64_encode(input: &str) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_bytes();
    let mut result = String::new();

    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = chunk.get(1).copied().unwrap_or(0) as usize;
        let b2 = chunk.get(2).copied().unwrap_or(0) as usize;

        result.push(ALPHABET[b0 >> 2] as char);
        result.push(ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)] as char);

        if chunk.len() > 1 {
            result.push(ALPHABET[((b1 & 0x0f) << 2) | (b2 >> 6)] as char);
        } else {
            result.push('=');
        }

        if chunk.len() > 2 {
            result.push(ALPHABET[b2 & 0x3f] as char);
        } else {
            result.push('=');
        }
    }

    result
}

fn detect_card_type(number: &str) -> &'static str {
    let digits: String = number.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.starts_with('4') {
        "visa"
    } else if digits.starts_with("51")
        || digits.starts_with("52")
        || digits.starts_with("53")
        || digits.starts_with("54")
        || digits.starts_with("55")
    {
        "mast"
    } else if digits.starts_with("34") || digits.starts_with("37") {
        "amex"
    } else if digits.starts_with("6011") || digits.starts_with("65") {
        "disc"
    } else {
        "visa"
    }
}

// =============================================================================
// FFI Interface
// =============================================================================

/// Transform a payment request to connector-specific HTTP request (JSON API)
///
/// # Safety
/// Input must be a valid null-terminated UTF-8 JSON string.
/// The returned string must be freed with `ffi_string_free`.
#[no_mangle]
pub unsafe extern "C" fn connector_transform_request_json(
    request_json: *const c_char,
) -> *const c_char {
    if request_json.is_null() {
        return to_c_string(&TransformResult::<HttpRequest> {
            success: false,
            data: None,
            error: Some(ErrorInfo {
                code: "NULL_INPUT".to_string(),
                message: "Input is null".to_string(),
            }),
        });
    }

    let input_str = match CStr::from_ptr(request_json).to_str() {
        Ok(s) => s,
        Err(_) => {
            return to_c_string(&TransformResult::<HttpRequest> {
                success: false,
                data: None,
                error: Some(ErrorInfo {
                    code: "INVALID_UTF8".to_string(),
                    message: "Input is not valid UTF-8".to_string(),
                }),
            });
        }
    };

    let input: TransformRequestInput = match serde_json::from_str(input_str) {
        Ok(i) => i,
        Err(e) => {
            return to_c_string(&TransformResult::<HttpRequest> {
                success: false,
                data: None,
                error: Some(ErrorInfo {
                    code: "PARSE_ERROR".to_string(),
                    message: format!("Failed to parse input: {}", e),
                }),
            });
        }
    };

    let result = transform_request(&input);
    to_c_string(&result)
}

/// Transform a connector response to standardized payment response (JSON API)
///
/// # Safety
/// Input must be a valid null-terminated UTF-8 JSON string.
/// The returned string must be freed with `ffi_string_free`.
#[no_mangle]
pub unsafe extern "C" fn connector_transform_response_json(
    response_json: *const c_char,
) -> *const c_char {
    if response_json.is_null() {
        return to_c_string(&TransformResult::<PaymentResponse> {
            success: false,
            data: None,
            error: Some(ErrorInfo {
                code: "NULL_INPUT".to_string(),
                message: "Input is null".to_string(),
            }),
        });
    }

    let input_str = match CStr::from_ptr(response_json).to_str() {
        Ok(s) => s,
        Err(_) => {
            return to_c_string(&TransformResult::<PaymentResponse> {
                success: false,
                data: None,
                error: Some(ErrorInfo {
                    code: "INVALID_UTF8".to_string(),
                    message: "Input is not valid UTF-8".to_string(),
                }),
            });
        }
    };

    let input: TransformResponseInput = match serde_json::from_str(input_str) {
        Ok(i) => i,
        Err(e) => {
            return to_c_string(&TransformResult::<PaymentResponse> {
                success: false,
                data: None,
                error: Some(ErrorInfo {
                    code: "PARSE_ERROR".to_string(),
                    message: format!("Failed to parse input: {}", e),
                }),
            });
        }
    };

    let result = transform_response(&input);
    to_c_string(&result)
}

/// Get list of supported connectors
///
/// # Safety
/// The returned string must be freed with `ffi_string_free`.
#[no_mangle]
pub unsafe extern "C" fn connector_list_supported() -> *const c_char {
    let connectors = vec!["stripe", "adyen", "checkout", "braintree", "razorpay", "phonepe", "forte"];
    match CString::new(serde_json::to_string(&connectors).unwrap_or_default()) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null(),
    }
}

/// Get list of supported flows
///
/// # Safety
/// The returned string must be freed with `ffi_string_free`.
#[no_mangle]
pub unsafe extern "C" fn connector_list_flows() -> *const c_char {
    let flows = vec!["authorize", "capture", "void", "refund", "sync"];
    match CString::new(serde_json::to_string(&flows).unwrap_or_default()) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null(),
    }
}

/// Free a string returned by the FFI layer
///
/// # Safety
/// Must only be called with pointers returned by FFI functions.
#[no_mangle]
pub unsafe extern "C" fn ffi_string_free(s: *mut c_char) {
    if !s.is_null() {
        drop(CString::from_raw(s));
    }
}

/// Get the library version
#[no_mangle]
pub extern "C" fn connector_ffi_version() -> *const c_char {
    static VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");
    VERSION.as_ptr() as *const c_char
}

fn to_c_string<T: Serialize>(value: &T) -> *const c_char {
    match serde_json::to_string(value) {
        Ok(json) => match CString::new(json) {
            Ok(s) => s.into_raw(),
            Err(_) => std::ptr::null(),
        },
        Err(_) => std::ptr::null(),
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stripe_authorize_transform() {
        let input = TransformRequestInput {
            connector: "stripe".to_string(),
            flow: "authorize".to_string(),
            auth: AuthCredentials {
                api_key: Some("sk_test_123".to_string()),
                api_secret: None,
                merchant_id: None,
                extra: HashMap::new(),
            },
            payment: PaymentData {
                amount: 1000,
                currency: "USD".to_string(),
                reference_id: Some("order_123".to_string()),
                payment_method: Some(PaymentMethodData::Card {
                    number: "4242424242424242".to_string(),
                    exp_month: 12,
                    exp_year: 2025,
                    cvc: "123".to_string(),
                    holder_name: Some("Test User".to_string()),
                }),
                transaction_id: None,
                metadata: HashMap::new(),
            },
            config: None,
        };

        let result = transform_request(&input);
        assert!(result.success);
        let request = result.data.unwrap();
        assert_eq!(request.url, "https://api.stripe.com/v1/payment_intents");
        assert_eq!(request.method, HttpMethod::Post);
        assert!(request.headers.contains_key("Authorization"));
        assert!(request.body.unwrap().contains("amount=1000"));
    }

    #[test]
    fn test_stripe_response_transform() {
        let input = TransformResponseInput {
            connector: "stripe".to_string(),
            flow: "authorize".to_string(),
            status_code: 200,
            body: r#"{"id":"pi_123","status":"succeeded","amount":1000,"currency":"usd"}"#.to_string(),
            headers: HashMap::new(),
        };

        let result = transform_response(&input);
        assert!(result.success);
        let response = result.data.unwrap();
        assert_eq!(response.status, "succeeded");
        assert_eq!(response.transaction_id, Some("pi_123".to_string()));
        assert_eq!(response.amount, Some(1000));
    }

    #[test]
    fn test_adyen_authorize_transform() {
        let input = TransformRequestInput {
            connector: "adyen".to_string(),
            flow: "authorize".to_string(),
            auth: AuthCredentials {
                api_key: Some("test_api_key".to_string()),
                api_secret: None,
                merchant_id: Some("TestMerchant".to_string()),
                extra: HashMap::new(),
            },
            payment: PaymentData {
                amount: 1000,
                currency: "EUR".to_string(),
                reference_id: Some("order_456".to_string()),
                payment_method: Some(PaymentMethodData::Card {
                    number: "4111111111111111".to_string(),
                    exp_month: 3,
                    exp_year: 2030,
                    cvc: "737".to_string(),
                    holder_name: Some("John Doe".to_string()),
                }),
                transaction_id: None,
                metadata: HashMap::new(),
            },
            config: None,
        };

        let result = transform_request(&input);
        assert!(result.success);
        let request = result.data.unwrap();
        assert!(request.url.contains("/payments"));
        assert!(request.headers.contains_key("X-API-Key"));
    }

    #[test]
    fn test_unknown_connector() {
        let input = TransformRequestInput {
            connector: "unknown_connector".to_string(),
            flow: "authorize".to_string(),
            auth: AuthCredentials {
                api_key: None,
                api_secret: None,
                merchant_id: None,
                extra: HashMap::new(),
            },
            payment: PaymentData {
                amount: 100,
                currency: "USD".to_string(),
                reference_id: None,
                payment_method: None,
                transaction_id: None,
                metadata: HashMap::new(),
            },
            config: None,
        };

        let result = transform_request(&input);
        assert!(!result.success);
        assert_eq!(result.error.unwrap().code, "UNKNOWN_CONNECTOR");
    }

    #[test]
    fn test_base64_encode() {
        assert_eq!(base64_encode("hello"), "aGVsbG8=");
        assert_eq!(base64_encode("hello world"), "aGVsbG8gd29ybGQ=");
    }

    #[test]
    fn test_card_type_detection() {
        assert_eq!(detect_card_type("4242424242424242"), "visa");
        assert_eq!(detect_card_type("5555555555554444"), "mast");
        assert_eq!(detect_card_type("378282246310005"), "amex");
        assert_eq!(detect_card_type("6011111111111117"), "disc");
    }
}
