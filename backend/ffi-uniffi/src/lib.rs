//! UniFFI-based FFI bindings for connector transformation logic.
//!
//! This crate provides automatically generated bindings for Python, Kotlin, Swift,
//! and other languages using Mozilla's UniFFI framework.
//!
//! # Usage
//!
//! Generate bindings with:
//! ```bash
//! cargo run --bin uniffi-bindgen -- generate src/connector_ffi.udl \
//!     --language python --out-dir bindings/python
//! ```

use std::collections::HashMap;

// Include the UniFFI scaffolding generated from the UDL file
uniffi::include_scaffolding!("connector_ffi");

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during connector operations
#[derive(Debug, thiserror::Error)]
pub enum ConnectorError {
    #[error("Unknown connector: {name}")]
    UnknownConnector { name: String },

    #[error("Unsupported flow '{flow}' for connector '{connector}'")]
    UnsupportedFlow { connector: String, flow: String },

    #[error("Missing required authentication field: {field}")]
    MissingAuthField { field: String },

    #[error("Missing required payment field: {field}")]
    MissingPaymentField { field: String },

    #[error("Transform error: {message}")]
    TransformError { message: String },

    #[error("Parse error: {message}")]
    ParseError { message: String },

    #[error("Invalid input: {message}")]
    InvalidInput { message: String },
}

// ============================================================================
// Enums
// ============================================================================

/// HTTP methods supported for connector requests
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
}

impl std::fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpMethod::Get => write!(f, "GET"),
            HttpMethod::Post => write!(f, "POST"),
            HttpMethod::Put => write!(f, "PUT"),
            HttpMethod::Delete => write!(f, "DELETE"),
            HttpMethod::Patch => write!(f, "PATCH"),
        }
    }
}

/// Payment status after processing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymentStatus {
    Succeeded,
    Authorized,
    Pending,
    Failed,
    Cancelled,
    RequiresAction,
    Processing,
    Unknown,
}

impl std::fmt::Display for PaymentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PaymentStatus::Succeeded => write!(f, "succeeded"),
            PaymentStatus::Authorized => write!(f, "authorized"),
            PaymentStatus::Pending => write!(f, "pending"),
            PaymentStatus::Failed => write!(f, "failed"),
            PaymentStatus::Cancelled => write!(f, "cancelled"),
            PaymentStatus::RequiresAction => write!(f, "requires_action"),
            PaymentStatus::Processing => write!(f, "processing"),
            PaymentStatus::Unknown => write!(f, "unknown"),
        }
    }
}

/// Supported payment flows
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymentFlow {
    Authorize,
    Capture,
    Void,
    Refund,
    Sync,
    SetupMandate,
}

impl PaymentFlow {
    fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "authorize" | "auth" => Some(PaymentFlow::Authorize),
            "capture" => Some(PaymentFlow::Capture),
            "void" | "cancel" => Some(PaymentFlow::Void),
            "refund" => Some(PaymentFlow::Refund),
            "sync" | "psync" | "rsync" => Some(PaymentFlow::Sync),
            "setup_mandate" | "mandate" => Some(PaymentFlow::SetupMandate),
            _ => None,
        }
    }
}

impl std::fmt::Display for PaymentFlow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PaymentFlow::Authorize => write!(f, "authorize"),
            PaymentFlow::Capture => write!(f, "capture"),
            PaymentFlow::Void => write!(f, "void"),
            PaymentFlow::Refund => write!(f, "refund"),
            PaymentFlow::Sync => write!(f, "sync"),
            PaymentFlow::SetupMandate => write!(f, "setup_mandate"),
        }
    }
}

/// Body format for HTTP requests
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyFormat {
    Json,
    FormUrlEncoded,
    Xml,
    Raw,
}

impl std::fmt::Display for BodyFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BodyFormat::Json => write!(f, "json"),
            BodyFormat::FormUrlEncoded => write!(f, "form"),
            BodyFormat::Xml => write!(f, "xml"),
            BodyFormat::Raw => write!(f, "raw"),
        }
    }
}

/// Authentication type used by connector
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthType {
    HeaderKey,
    BasicAuth,
    BodyKey,
    SignatureKey,
    MultiAuthKey,
    CertificateAuth,
    NoKey,
}

impl std::fmt::Display for AuthType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthType::HeaderKey => write!(f, "header_key"),
            AuthType::BasicAuth => write!(f, "basic_auth"),
            AuthType::BodyKey => write!(f, "body_key"),
            AuthType::SignatureKey => write!(f, "signature_key"),
            AuthType::MultiAuthKey => write!(f, "multi_auth_key"),
            AuthType::CertificateAuth => write!(f, "certificate_auth"),
            AuthType::NoKey => write!(f, "no_key"),
        }
    }
}

// ============================================================================
// Data Structures
// ============================================================================

/// Credit/debit card data
#[derive(Debug, Clone)]
pub struct CardData {
    pub number: String,
    pub exp_month: u32,
    pub exp_year: u32,
    pub cvc: String,
    pub holder_name: Option<String>,
}

/// Wallet payment data (Apple Pay, Google Pay, etc.)
#[derive(Debug, Clone)]
pub struct WalletData {
    pub wallet_type: String,
    pub token: Option<String>,
    pub email: Option<String>,
}

/// Bank transfer data
#[derive(Debug, Clone)]
pub struct BankTransferData {
    pub bank_name: Option<String>,
    pub account_number: Option<String>,
    pub routing_number: Option<String>,
    pub iban: Option<String>,
    pub bic: Option<String>,
}

/// Payment method information
#[derive(Debug, Clone)]
pub struct PaymentMethod {
    pub method_type: String,
    pub card: Option<CardData>,
    pub wallet: Option<WalletData>,
    pub bank_transfer: Option<BankTransferData>,
}

/// Payment data for a transaction
#[derive(Debug, Clone)]
pub struct PaymentData {
    pub amount: i64,
    pub currency: String,
    pub payment_method: Option<PaymentMethod>,
    pub reference_id: Option<String>,
    pub transaction_id: Option<String>,
    pub return_url: Option<String>,
    pub metadata: Option<String>,
}

/// HTTP request to be sent to connector
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub url: String,
    pub method: HttpMethod,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub body_format: BodyFormat,
}

/// Response from payment processing
#[derive(Debug, Clone)]
pub struct PaymentResult {
    pub success: bool,
    pub status: PaymentStatus,
    pub transaction_id: Option<String>,
    pub connector_transaction_id: Option<String>,
    pub amount: Option<i64>,
    pub currency: Option<String>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub raw_response: Option<String>,
}

impl PaymentResult {
    fn failure(error_code: Option<String>, error_message: Option<String>) -> Self {
        PaymentResult {
            success: false,
            status: PaymentStatus::Failed,
            transaction_id: None,
            connector_transaction_id: None,
            amount: None,
            currency: None,
            error_code,
            error_message,
            raw_response: None,
        }
    }
}

/// Information about a connector
#[derive(Debug, Clone)]
pub struct ConnectorInfo {
    pub name: String,
    pub display_name: String,
    pub base_url: String,
    pub auth_type: AuthType,
    pub auth_fields: Vec<String>,
    pub supported_flows: Vec<PaymentFlow>,
    pub supported_currencies: Vec<String>,
    pub body_format: BodyFormat,
    pub supports_webhooks: bool,
    pub supports_3ds: bool,
}

/// Input for request transformation
#[derive(Debug, Clone)]
pub struct TransformRequestInput {
    pub connector: String,
    pub flow: String,
    pub auth: HashMap<String, String>,
    pub payment: PaymentData,
}

/// Input for response transformation
#[derive(Debug, Clone)]
pub struct TransformResponseInput {
    pub connector: String,
    pub flow: String,
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
}

// ============================================================================
// Connector Registry
// ============================================================================

/// Thread-safe connector registry
pub struct ConnectorRegistry {
    connectors: HashMap<String, ConnectorInfo>,
}

impl ConnectorRegistry {
    pub fn new() -> Self {
        let mut connectors = HashMap::new();

        // Stripe
        connectors.insert(
            "stripe".to_string(),
            ConnectorInfo {
                name: "stripe".to_string(),
                display_name: "Stripe".to_string(),
                base_url: "https://api.stripe.com/v1".to_string(),
                auth_type: AuthType::HeaderKey,
                auth_fields: vec!["api_key".to_string()],
                supported_flows: vec![
                    PaymentFlow::Authorize,
                    PaymentFlow::Capture,
                    PaymentFlow::Void,
                    PaymentFlow::Refund,
                    PaymentFlow::Sync,
                ],
                supported_currencies: vec![
                    "USD", "EUR", "GBP", "CAD", "AUD", "JPY", "INR", "SGD",
                ]
                .into_iter()
                .map(String::from)
                .collect(),
                body_format: BodyFormat::FormUrlEncoded,
                supports_webhooks: true,
                supports_3ds: true,
            },
        );

        // Adyen
        connectors.insert(
            "adyen".to_string(),
            ConnectorInfo {
                name: "adyen".to_string(),
                display_name: "Adyen".to_string(),
                base_url: "https://checkout-test.adyen.com/v71".to_string(),
                auth_type: AuthType::HeaderKey,
                auth_fields: vec!["api_key".to_string(), "merchant_account".to_string()],
                supported_flows: vec![
                    PaymentFlow::Authorize,
                    PaymentFlow::Capture,
                    PaymentFlow::Void,
                    PaymentFlow::Refund,
                    PaymentFlow::Sync,
                ],
                supported_currencies: vec![
                    "USD", "EUR", "GBP", "CAD", "AUD", "JPY", "INR", "SGD", "AED",
                ]
                .into_iter()
                .map(String::from)
                .collect(),
                body_format: BodyFormat::Json,
                supports_webhooks: true,
                supports_3ds: true,
            },
        );

        // Forte
        connectors.insert(
            "forte".to_string(),
            ConnectorInfo {
                name: "forte".to_string(),
                display_name: "Forte".to_string(),
                base_url: "https://sandbox.forte.net/api/v3".to_string(),
                auth_type: AuthType::BasicAuth,
                auth_fields: vec![
                    "api_access_id".to_string(),
                    "api_secret_key".to_string(),
                    "organization_id".to_string(),
                    "location_id".to_string(),
                ],
                supported_flows: vec![
                    PaymentFlow::Authorize,
                    PaymentFlow::Capture,
                    PaymentFlow::Void,
                    PaymentFlow::Refund,
                ],
                supported_currencies: vec!["USD".to_string()],
                body_format: BodyFormat::Json,
                supports_webhooks: true,
                supports_3ds: false,
            },
        );

        // Checkout.com
        connectors.insert(
            "checkout".to_string(),
            ConnectorInfo {
                name: "checkout".to_string(),
                display_name: "Checkout.com".to_string(),
                base_url: "https://api.sandbox.checkout.com".to_string(),
                auth_type: AuthType::HeaderKey,
                auth_fields: vec!["api_key".to_string()],
                supported_flows: vec![
                    PaymentFlow::Authorize,
                    PaymentFlow::Capture,
                    PaymentFlow::Void,
                    PaymentFlow::Refund,
                    PaymentFlow::Sync,
                ],
                supported_currencies: vec![
                    "USD", "EUR", "GBP", "CAD", "AUD", "JPY", "INR", "SGD",
                ]
                .into_iter()
                .map(String::from)
                .collect(),
                body_format: BodyFormat::Json,
                supports_webhooks: true,
                supports_3ds: true,
            },
        );

        // Braintree
        connectors.insert(
            "braintree".to_string(),
            ConnectorInfo {
                name: "braintree".to_string(),
                display_name: "Braintree".to_string(),
                base_url: "https://payments.sandbox.braintree-api.com/graphql".to_string(),
                auth_type: AuthType::BasicAuth,
                auth_fields: vec![
                    "public_key".to_string(),
                    "private_key".to_string(),
                    "merchant_id".to_string(),
                ],
                supported_flows: vec![
                    PaymentFlow::Authorize,
                    PaymentFlow::Capture,
                    PaymentFlow::Void,
                    PaymentFlow::Refund,
                ],
                supported_currencies: vec!["USD", "EUR", "GBP", "CAD", "AUD"]
                    .into_iter()
                    .map(String::from)
                    .collect(),
                body_format: BodyFormat::Json,
                supports_webhooks: true,
                supports_3ds: true,
            },
        );

        ConnectorRegistry { connectors }
    }

    /// List all supported connector names
    pub fn list_connectors(&self) -> Vec<String> {
        self.connectors.keys().cloned().collect()
    }

    /// Get information about a specific connector
    pub fn get_connector_info(&self, name: String) -> Option<ConnectorInfo> {
        self.connectors.get(&name.to_lowercase()).cloned()
    }

    /// Get supported flows for a connector
    pub fn get_supported_flows(&self, name: String) -> Result<Vec<PaymentFlow>, ConnectorError> {
        self.connectors
            .get(&name.to_lowercase())
            .map(|info| info.supported_flows.clone())
            .ok_or_else(|| ConnectorError::UnknownConnector { name })
    }
}

impl Default for ConnectorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for ConnectorRegistry {
    fn clone(&self) -> Self {
        ConnectorRegistry {
            connectors: self.connectors.clone(),
        }
    }
}

// ============================================================================
// Public API Functions
// ============================================================================

/// Transform a payment request into an HTTP request for the connector
pub fn transform_request(input: TransformRequestInput) -> Result<HttpRequest, ConnectorError> {
    let connector = input.connector.to_lowercase();
    let flow = PaymentFlow::from_str(&input.flow).ok_or_else(|| ConnectorError::InvalidInput {
        message: format!("Unknown flow: {}", input.flow),
    })?;

    match connector.as_str() {
        "stripe" => transform_stripe_request(&input, flow),
        "adyen" => transform_adyen_request(&input, flow),
        "forte" => transform_forte_request(&input, flow),
        "checkout" => transform_checkout_request(&input, flow),
        "braintree" => transform_braintree_request(&input, flow),
        _ => Err(ConnectorError::UnknownConnector { name: connector }),
    }
}

/// Transform a connector HTTP response into a standardized payment result
pub fn transform_response(input: TransformResponseInput) -> Result<PaymentResult, ConnectorError> {
    let connector = input.connector.to_lowercase();
    let flow = PaymentFlow::from_str(&input.flow).ok_or_else(|| ConnectorError::InvalidInput {
        message: format!("Unknown flow: {}", input.flow),
    })?;

    match connector.as_str() {
        "stripe" => transform_stripe_response(&input, flow),
        "adyen" => transform_adyen_response(&input, flow),
        "forte" => transform_forte_response(&input, flow),
        "checkout" => transform_checkout_response(&input, flow),
        "braintree" => transform_braintree_response(&input, flow),
        _ => Err(ConnectorError::UnknownConnector { name: connector }),
    }
}

/// List all supported connectors
pub fn list_supported_connectors() -> Vec<String> {
    vec![
        "stripe".to_string(),
        "adyen".to_string(),
        "forte".to_string(),
        "checkout".to_string(),
        "braintree".to_string(),
    ]
}

/// Get connector information by name
pub fn get_connector_info(name: String) -> Option<ConnectorInfo> {
    let registry = ConnectorRegistry::new();
    registry.get_connector_info(name)
}

/// Create a card payment method
pub fn create_card_payment_method(
    number: String,
    exp_month: u32,
    exp_year: u32,
    cvc: String,
    holder_name: Option<String>,
) -> PaymentMethod {
    PaymentMethod {
        method_type: "card".to_string(),
        card: Some(CardData {
            number,
            exp_month,
            exp_year,
            cvc,
            holder_name,
        }),
        wallet: None,
        bank_transfer: None,
    }
}

/// Create a wallet payment method
pub fn create_wallet_payment_method(
    wallet_type: String,
    token: Option<String>,
    email: Option<String>,
) -> PaymentMethod {
    PaymentMethod {
        method_type: "wallet".to_string(),
        card: None,
        wallet: Some(WalletData {
            wallet_type,
            token,
            email,
        }),
        bank_transfer: None,
    }
}

// ============================================================================
// Stripe Implementation
// ============================================================================

fn transform_stripe_request(
    input: &TransformRequestInput,
    flow: PaymentFlow,
) -> Result<HttpRequest, ConnectorError> {
    let api_key = input
        .auth
        .get("api_key")
        .ok_or_else(|| ConnectorError::MissingAuthField {
            field: "api_key".to_string(),
        })?;

    let mut headers = HashMap::new();
    headers.insert(
        "Authorization".to_string(),
        format!("Bearer {}", api_key),
    );
    headers.insert(
        "Content-Type".to_string(),
        "application/x-www-form-urlencoded".to_string(),
    );

    match flow {
        PaymentFlow::Authorize => {
            let payment = &input.payment;
            let mut body_params = vec![
                format!("amount={}", payment.amount),
                format!("currency={}", payment.currency.to_lowercase()),
                "capture_method=manual".to_string(),
            ];

            if let Some(ref pm) = payment.payment_method {
                if let Some(ref card) = pm.card {
                    body_params.push("payment_method_data[type]=card".to_string());
                    body_params.push(format!(
                        "payment_method_data[card][number]={}",
                        card.number
                    ));
                    body_params.push(format!(
                        "payment_method_data[card][exp_month]={}",
                        card.exp_month
                    ));
                    body_params.push(format!(
                        "payment_method_data[card][exp_year]={}",
                        card.exp_year
                    ));
                    body_params.push(format!("payment_method_data[card][cvc]={}", card.cvc));
                }
            }

            body_params.push("confirm=true".to_string());
            body_params.push("automatic_payment_methods[enabled]=true".to_string());
            body_params.push("automatic_payment_methods[allow_redirects]=never".to_string());

            Ok(HttpRequest {
                url: "https://api.stripe.com/v1/payment_intents".to_string(),
                method: HttpMethod::Post,
                headers,
                body: Some(body_params.join("&")),
                body_format: BodyFormat::FormUrlEncoded,
            })
        }
        PaymentFlow::Capture => {
            let txn_id = input
                .payment
                .transaction_id
                .as_ref()
                .ok_or_else(|| ConnectorError::MissingPaymentField {
                    field: "transaction_id".to_string(),
                })?;

            let body = format!("amount_to_capture={}", input.payment.amount);

            Ok(HttpRequest {
                url: format!("https://api.stripe.com/v1/payment_intents/{}/capture", txn_id),
                method: HttpMethod::Post,
                headers,
                body: Some(body),
                body_format: BodyFormat::FormUrlEncoded,
            })
        }
        PaymentFlow::Void => {
            let txn_id = input
                .payment
                .transaction_id
                .as_ref()
                .ok_or_else(|| ConnectorError::MissingPaymentField {
                    field: "transaction_id".to_string(),
                })?;

            Ok(HttpRequest {
                url: format!("https://api.stripe.com/v1/payment_intents/{}/cancel", txn_id),
                method: HttpMethod::Post,
                headers,
                body: None,
                body_format: BodyFormat::FormUrlEncoded,
            })
        }
        PaymentFlow::Refund => {
            let txn_id = input
                .payment
                .transaction_id
                .as_ref()
                .ok_or_else(|| ConnectorError::MissingPaymentField {
                    field: "transaction_id".to_string(),
                })?;

            let body = format!(
                "payment_intent={}&amount={}",
                txn_id, input.payment.amount
            );

            Ok(HttpRequest {
                url: "https://api.stripe.com/v1/refunds".to_string(),
                method: HttpMethod::Post,
                headers,
                body: Some(body),
                body_format: BodyFormat::FormUrlEncoded,
            })
        }
        PaymentFlow::Sync => {
            let txn_id = input
                .payment
                .transaction_id
                .as_ref()
                .ok_or_else(|| ConnectorError::MissingPaymentField {
                    field: "transaction_id".to_string(),
                })?;

            Ok(HttpRequest {
                url: format!("https://api.stripe.com/v1/payment_intents/{}", txn_id),
                method: HttpMethod::Get,
                headers,
                body: None,
                body_format: BodyFormat::FormUrlEncoded,
            })
        }
        _ => Err(ConnectorError::UnsupportedFlow {
            connector: "stripe".to_string(),
            flow: flow.to_string(),
        }),
    }
}

fn transform_stripe_response(
    input: &TransformResponseInput,
    _flow: PaymentFlow,
) -> Result<PaymentResult, ConnectorError> {
    let json: serde_json::Value =
        serde_json::from_str(&input.body).map_err(|e| ConnectorError::ParseError {
            message: e.to_string(),
        })?;

    if input.status_code >= 400 {
        let error_message = json["error"]["message"]
            .as_str()
            .unwrap_or("Unknown error")
            .to_string();
        let error_code = json["error"]["code"]
            .as_str()
            .unwrap_or("unknown")
            .to_string();

        return Ok(PaymentResult {
            success: false,
            status: PaymentStatus::Failed,
            transaction_id: None,
            connector_transaction_id: json["error"]["payment_intent"]["id"]
                .as_str()
                .map(String::from),
            amount: None,
            currency: None,
            error_code: Some(error_code),
            error_message: Some(error_message),
            raw_response: Some(input.body.clone()),
        });
    }

    let status_str = json["status"].as_str().unwrap_or("unknown");
    let status = match status_str {
        "succeeded" => PaymentStatus::Succeeded,
        "requires_capture" => PaymentStatus::Authorized,
        "processing" => PaymentStatus::Processing,
        "requires_action" => PaymentStatus::RequiresAction,
        "canceled" => PaymentStatus::Cancelled,
        "requires_payment_method" => PaymentStatus::Failed,
        _ => PaymentStatus::Unknown,
    };

    Ok(PaymentResult {
        success: matches!(
            status,
            PaymentStatus::Succeeded | PaymentStatus::Authorized | PaymentStatus::Processing
        ),
        status,
        transaction_id: json["id"].as_str().map(String::from),
        connector_transaction_id: json["id"].as_str().map(String::from),
        amount: json["amount"].as_i64(),
        currency: json["currency"].as_str().map(|s| s.to_uppercase()),
        error_code: None,
        error_message: None,
        raw_response: Some(input.body.clone()),
    })
}

// ============================================================================
// Adyen Implementation
// ============================================================================

fn transform_adyen_request(
    input: &TransformRequestInput,
    flow: PaymentFlow,
) -> Result<HttpRequest, ConnectorError> {
    let api_key = input
        .auth
        .get("api_key")
        .ok_or_else(|| ConnectorError::MissingAuthField {
            field: "api_key".to_string(),
        })?;
    let merchant_account = input
        .auth
        .get("merchant_account")
        .ok_or_else(|| ConnectorError::MissingAuthField {
            field: "merchant_account".to_string(),
        })?;

    let mut headers = HashMap::new();
    headers.insert("X-API-Key".to_string(), api_key.clone());
    headers.insert("Content-Type".to_string(), "application/json".to_string());

    match flow {
        PaymentFlow::Authorize => {
            let payment = &input.payment;

            let mut body_json = serde_json::json!({
                "amount": {
                    "value": payment.amount,
                    "currency": payment.currency.to_uppercase()
                },
                "merchantAccount": merchant_account,
                "reference": payment.reference_id.clone().unwrap_or_else(|| format!("ref_{}", chrono_lite_timestamp())),
            });

            if let Some(ref pm) = payment.payment_method {
                if let Some(ref card) = pm.card {
                    body_json["paymentMethod"] = serde_json::json!({
                        "type": "scheme",
                        "number": card.number,
                        "expiryMonth": format!("{:02}", card.exp_month),
                        "expiryYear": format!("{}", card.exp_year),
                        "cvc": card.cvc,
                        "holderName": card.holder_name.clone().unwrap_or_default()
                    });
                }
            }

            if let Some(ref return_url) = payment.return_url {
                body_json["returnUrl"] = serde_json::json!(return_url);
            }

            Ok(HttpRequest {
                url: "https://checkout-test.adyen.com/v71/payments".to_string(),
                method: HttpMethod::Post,
                headers,
                body: Some(body_json.to_string()),
                body_format: BodyFormat::Json,
            })
        }
        PaymentFlow::Capture => {
            let txn_id = input
                .payment
                .transaction_id
                .as_ref()
                .ok_or_else(|| ConnectorError::MissingPaymentField {
                    field: "transaction_id".to_string(),
                })?;

            let body_json = serde_json::json!({
                "merchantAccount": merchant_account,
                "amount": {
                    "value": input.payment.amount,
                    "currency": input.payment.currency.to_uppercase()
                }
            });

            Ok(HttpRequest {
                url: format!(
                    "https://checkout-test.adyen.com/v71/payments/{}/captures",
                    txn_id
                ),
                method: HttpMethod::Post,
                headers,
                body: Some(body_json.to_string()),
                body_format: BodyFormat::Json,
            })
        }
        PaymentFlow::Void => {
            let txn_id = input
                .payment
                .transaction_id
                .as_ref()
                .ok_or_else(|| ConnectorError::MissingPaymentField {
                    field: "transaction_id".to_string(),
                })?;

            let body_json = serde_json::json!({
                "merchantAccount": merchant_account
            });

            Ok(HttpRequest {
                url: format!(
                    "https://checkout-test.adyen.com/v71/payments/{}/cancels",
                    txn_id
                ),
                method: HttpMethod::Post,
                headers,
                body: Some(body_json.to_string()),
                body_format: BodyFormat::Json,
            })
        }
        PaymentFlow::Refund => {
            let txn_id = input
                .payment
                .transaction_id
                .as_ref()
                .ok_or_else(|| ConnectorError::MissingPaymentField {
                    field: "transaction_id".to_string(),
                })?;

            let body_json = serde_json::json!({
                "merchantAccount": merchant_account,
                "amount": {
                    "value": input.payment.amount,
                    "currency": input.payment.currency.to_uppercase()
                }
            });

            Ok(HttpRequest {
                url: format!(
                    "https://checkout-test.adyen.com/v71/payments/{}/refunds",
                    txn_id
                ),
                method: HttpMethod::Post,
                headers,
                body: Some(body_json.to_string()),
                body_format: BodyFormat::Json,
            })
        }
        _ => Err(ConnectorError::UnsupportedFlow {
            connector: "adyen".to_string(),
            flow: flow.to_string(),
        }),
    }
}

fn transform_adyen_response(
    input: &TransformResponseInput,
    _flow: PaymentFlow,
) -> Result<PaymentResult, ConnectorError> {
    let json: serde_json::Value =
        serde_json::from_str(&input.body).map_err(|e| ConnectorError::ParseError {
            message: e.to_string(),
        })?;

    if input.status_code >= 400 {
        let error_message = json["message"]
            .as_str()
            .or_else(|| json["errorMessage"].as_str())
            .unwrap_or("Unknown error")
            .to_string();
        let error_code = json["errorCode"]
            .as_str()
            .or_else(|| json["status"].as_str())
            .unwrap_or("unknown")
            .to_string();

        return Ok(PaymentResult::failure(Some(error_code), Some(error_message)));
    }

    let result_code = json["resultCode"]
        .as_str()
        .or_else(|| json["status"].as_str())
        .unwrap_or("Unknown");

    let status = match result_code {
        "Authorised" | "authorised" => PaymentStatus::Authorized,
        "Captured" | "captured" | "received" => PaymentStatus::Succeeded,
        "Pending" | "pending" => PaymentStatus::Pending,
        "Refused" | "refused" | "Error" | "error" => PaymentStatus::Failed,
        "Cancelled" | "cancelled" => PaymentStatus::Cancelled,
        "RedirectShopper" | "IdentifyShopper" | "ChallengeShopper" => PaymentStatus::RequiresAction,
        _ => PaymentStatus::Unknown,
    };

    let psp_reference = json["pspReference"]
        .as_str()
        .map(String::from);

    Ok(PaymentResult {
        success: matches!(
            status,
            PaymentStatus::Authorized | PaymentStatus::Succeeded | PaymentStatus::Pending
        ),
        status,
        transaction_id: psp_reference.clone(),
        connector_transaction_id: psp_reference,
        amount: json["amount"]["value"].as_i64(),
        currency: json["amount"]["currency"].as_str().map(String::from),
        error_code: json["refusalReasonCode"].as_str().map(String::from),
        error_message: json["refusalReason"].as_str().map(String::from),
        raw_response: Some(input.body.clone()),
    })
}

// ============================================================================
// Forte Implementation
// ============================================================================

fn transform_forte_request(
    input: &TransformRequestInput,
    flow: PaymentFlow,
) -> Result<HttpRequest, ConnectorError> {
    let api_access_id = input
        .auth
        .get("api_access_id")
        .ok_or_else(|| ConnectorError::MissingAuthField {
            field: "api_access_id".to_string(),
        })?;
    let api_secret_key = input
        .auth
        .get("api_secret_key")
        .ok_or_else(|| ConnectorError::MissingAuthField {
            field: "api_secret_key".to_string(),
        })?;
    let organization_id = input
        .auth
        .get("organization_id")
        .ok_or_else(|| ConnectorError::MissingAuthField {
            field: "organization_id".to_string(),
        })?;
    let location_id = input
        .auth
        .get("location_id")
        .ok_or_else(|| ConnectorError::MissingAuthField {
            field: "location_id".to_string(),
        })?;

    let auth_string = base64_encode(&format!("{}:{}", api_access_id, api_secret_key));

    let mut headers = HashMap::new();
    headers.insert("Authorization".to_string(), format!("Basic {}", auth_string));
    headers.insert("Content-Type".to_string(), "application/json".to_string());
    headers.insert("X-Forte-Auth-Organization-Id".to_string(), format!("org_{}", organization_id));

    let base_url = format!(
        "https://sandbox.forte.net/api/v3/organizations/org_{}/locations/loc_{}",
        organization_id, location_id
    );

    match flow {
        PaymentFlow::Authorize => {
            let payment = &input.payment;
            let amount_dollars = payment.amount as f64 / 100.0;

            let mut body_json = serde_json::json!({
                "action": "authorize",
                "authorization_amount": amount_dollars
            });

            if let Some(ref pm) = payment.payment_method {
                if let Some(ref card) = pm.card {
                    body_json["card"] = serde_json::json!({
                        "card_type": "visa",
                        "name_on_card": card.holder_name.clone().unwrap_or_else(|| "Cardholder".to_string()),
                        "account_number": card.number,
                        "expire_month": card.exp_month,
                        "expire_year": card.exp_year,
                        "card_verification_value": card.cvc
                    });
                }
            }

            Ok(HttpRequest {
                url: format!("{}/transactions", base_url),
                method: HttpMethod::Post,
                headers,
                body: Some(body_json.to_string()),
                body_format: BodyFormat::Json,
            })
        }
        PaymentFlow::Capture => {
            let txn_id = input
                .payment
                .transaction_id
                .as_ref()
                .ok_or_else(|| ConnectorError::MissingPaymentField {
                    field: "transaction_id".to_string(),
                })?;

            let amount_dollars = input.payment.amount as f64 / 100.0;

            let body_json = serde_json::json!({
                "action": "capture",
                "authorization_code": txn_id,
                "transaction_amount": amount_dollars
            });

            Ok(HttpRequest {
                url: format!("{}/transactions", base_url),
                method: HttpMethod::Post,
                headers,
                body: Some(body_json.to_string()),
                body_format: BodyFormat::Json,
            })
        }
        PaymentFlow::Void => {
            let txn_id = input
                .payment
                .transaction_id
                .as_ref()
                .ok_or_else(|| ConnectorError::MissingPaymentField {
                    field: "transaction_id".to_string(),
                })?;

            Ok(HttpRequest {
                url: format!("{}/transactions/{}", base_url, txn_id),
                method: HttpMethod::Delete,
                headers,
                body: None,
                body_format: BodyFormat::Json,
            })
        }
        PaymentFlow::Refund => {
            let txn_id = input
                .payment
                .transaction_id
                .as_ref()
                .ok_or_else(|| ConnectorError::MissingPaymentField {
                    field: "transaction_id".to_string(),
                })?;

            let amount_dollars = input.payment.amount as f64 / 100.0;

            let body_json = serde_json::json!({
                "action": "reverse",
                "original_transaction_id": txn_id,
                "authorization_amount": amount_dollars
            });

            Ok(HttpRequest {
                url: format!("{}/transactions", base_url),
                method: HttpMethod::Post,
                headers,
                body: Some(body_json.to_string()),
                body_format: BodyFormat::Json,
            })
        }
        _ => Err(ConnectorError::UnsupportedFlow {
            connector: "forte".to_string(),
            flow: flow.to_string(),
        }),
    }
}

fn transform_forte_response(
    input: &TransformResponseInput,
    _flow: PaymentFlow,
) -> Result<PaymentResult, ConnectorError> {
    let json: serde_json::Value =
        serde_json::from_str(&input.body).map_err(|e| ConnectorError::ParseError {
            message: e.to_string(),
        })?;

    let response_code = json["response"]["response_code"].as_str().unwrap_or("");

    if input.status_code >= 400 || response_code.starts_with('U') || response_code.starts_with('D') {
        let error_message = json["response"]["response_desc"]
            .as_str()
            .unwrap_or("Unknown error")
            .to_string();

        return Ok(PaymentResult::failure(
            Some(response_code.to_string()),
            Some(error_message),
        ));
    }

    let status = if response_code == "A01" {
        PaymentStatus::Authorized
    } else if response_code.starts_with('A') {
        PaymentStatus::Succeeded
    } else {
        PaymentStatus::Unknown
    };

    Ok(PaymentResult {
        success: matches!(status, PaymentStatus::Authorized | PaymentStatus::Succeeded),
        status,
        transaction_id: json["transaction_id"].as_str().map(String::from),
        connector_transaction_id: json["transaction_id"].as_str().map(String::from),
        amount: json["authorization_amount"]
            .as_f64()
            .map(|a| (a * 100.0) as i64),
        currency: Some("USD".to_string()),
        error_code: None,
        error_message: None,
        raw_response: Some(input.body.clone()),
    })
}

// ============================================================================
// Checkout.com Implementation
// ============================================================================

fn transform_checkout_request(
    input: &TransformRequestInput,
    flow: PaymentFlow,
) -> Result<HttpRequest, ConnectorError> {
    let api_key = input
        .auth
        .get("api_key")
        .ok_or_else(|| ConnectorError::MissingAuthField {
            field: "api_key".to_string(),
        })?;

    let mut headers = HashMap::new();
    headers.insert("Authorization".to_string(), format!("Bearer {}", api_key));
    headers.insert("Content-Type".to_string(), "application/json".to_string());

    match flow {
        PaymentFlow::Authorize => {
            let payment = &input.payment;

            let mut body_json = serde_json::json!({
                "amount": payment.amount,
                "currency": payment.currency.to_uppercase(),
                "capture": false,
                "reference": payment.reference_id.clone().unwrap_or_else(|| format!("ref_{}", chrono_lite_timestamp()))
            });

            if let Some(ref pm) = payment.payment_method {
                if let Some(ref card) = pm.card {
                    body_json["source"] = serde_json::json!({
                        "type": "card",
                        "number": card.number,
                        "expiry_month": card.exp_month,
                        "expiry_year": card.exp_year,
                        "cvv": card.cvc,
                        "name": card.holder_name.clone().unwrap_or_default()
                    });
                }
            }

            Ok(HttpRequest {
                url: "https://api.sandbox.checkout.com/payments".to_string(),
                method: HttpMethod::Post,
                headers,
                body: Some(body_json.to_string()),
                body_format: BodyFormat::Json,
            })
        }
        PaymentFlow::Capture => {
            let txn_id = input
                .payment
                .transaction_id
                .as_ref()
                .ok_or_else(|| ConnectorError::MissingPaymentField {
                    field: "transaction_id".to_string(),
                })?;

            let body_json = serde_json::json!({
                "amount": input.payment.amount
            });

            Ok(HttpRequest {
                url: format!("https://api.sandbox.checkout.com/payments/{}/captures", txn_id),
                method: HttpMethod::Post,
                headers,
                body: Some(body_json.to_string()),
                body_format: BodyFormat::Json,
            })
        }
        PaymentFlow::Void => {
            let txn_id = input
                .payment
                .transaction_id
                .as_ref()
                .ok_or_else(|| ConnectorError::MissingPaymentField {
                    field: "transaction_id".to_string(),
                })?;

            Ok(HttpRequest {
                url: format!("https://api.sandbox.checkout.com/payments/{}/voids", txn_id),
                method: HttpMethod::Post,
                headers,
                body: Some("{}".to_string()),
                body_format: BodyFormat::Json,
            })
        }
        PaymentFlow::Refund => {
            let txn_id = input
                .payment
                .transaction_id
                .as_ref()
                .ok_or_else(|| ConnectorError::MissingPaymentField {
                    field: "transaction_id".to_string(),
                })?;

            let body_json = serde_json::json!({
                "amount": input.payment.amount
            });

            Ok(HttpRequest {
                url: format!("https://api.sandbox.checkout.com/payments/{}/refunds", txn_id),
                method: HttpMethod::Post,
                headers,
                body: Some(body_json.to_string()),
                body_format: BodyFormat::Json,
            })
        }
        PaymentFlow::Sync => {
            let txn_id = input
                .payment
                .transaction_id
                .as_ref()
                .ok_or_else(|| ConnectorError::MissingPaymentField {
                    field: "transaction_id".to_string(),
                })?;

            Ok(HttpRequest {
                url: format!("https://api.sandbox.checkout.com/payments/{}", txn_id),
                method: HttpMethod::Get,
                headers,
                body: None,
                body_format: BodyFormat::Json,
            })
        }
        _ => Err(ConnectorError::UnsupportedFlow {
            connector: "checkout".to_string(),
            flow: flow.to_string(),
        }),
    }
}

fn transform_checkout_response(
    input: &TransformResponseInput,
    _flow: PaymentFlow,
) -> Result<PaymentResult, ConnectorError> {
    let json: serde_json::Value =
        serde_json::from_str(&input.body).map_err(|e| ConnectorError::ParseError {
            message: e.to_string(),
        })?;

    if input.status_code >= 400 {
        let error_message = json["error_type"]
            .as_str()
            .or_else(|| json["message"].as_str())
            .unwrap_or("Unknown error")
            .to_string();
        let error_code = json["error_codes"]
            .as_array()
            .and_then(|arr| arr.first())
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        return Ok(PaymentResult::failure(Some(error_code), Some(error_message)));
    }

    let status_str = json["status"].as_str().unwrap_or("unknown");
    let status = match status_str {
        "Authorized" => PaymentStatus::Authorized,
        "Captured" | "Paid" => PaymentStatus::Succeeded,
        "Pending" => PaymentStatus::Pending,
        "Declined" => PaymentStatus::Failed,
        "Voided" | "Canceled" => PaymentStatus::Cancelled,
        _ => PaymentStatus::Unknown,
    };

    Ok(PaymentResult {
        success: matches!(
            status,
            PaymentStatus::Authorized | PaymentStatus::Succeeded | PaymentStatus::Pending
        ),
        status,
        transaction_id: json["id"].as_str().map(String::from),
        connector_transaction_id: json["id"].as_str().map(String::from),
        amount: json["amount"].as_i64(),
        currency: json["currency"].as_str().map(String::from),
        error_code: None,
        error_message: None,
        raw_response: Some(input.body.clone()),
    })
}

// ============================================================================
// Braintree Implementation
// ============================================================================

fn transform_braintree_request(
    input: &TransformRequestInput,
    flow: PaymentFlow,
) -> Result<HttpRequest, ConnectorError> {
    let public_key = input
        .auth
        .get("public_key")
        .ok_or_else(|| ConnectorError::MissingAuthField {
            field: "public_key".to_string(),
        })?;
    let private_key = input
        .auth
        .get("private_key")
        .ok_or_else(|| ConnectorError::MissingAuthField {
            field: "private_key".to_string(),
        })?;

    let auth_string = base64_encode(&format!("{}:{}", public_key, private_key));

    let mut headers = HashMap::new();
    headers.insert("Authorization".to_string(), format!("Basic {}", auth_string));
    headers.insert("Content-Type".to_string(), "application/json".to_string());
    headers.insert("Braintree-Version".to_string(), "2019-01-01".to_string());

    match flow {
        PaymentFlow::Authorize => {
            let payment = &input.payment;
            let amount_str = format!("{:.2}", payment.amount as f64 / 100.0);

            let mutation = r#"mutation chargePaymentMethod($input: ChargePaymentMethodInput!) {
                chargePaymentMethod(input: $input) {
                    transaction {
                        id
                        status
                        amount { value currencyCode }
                    }
                }
            }"#;

            let variables = if let Some(ref pm) = payment.payment_method {
                if pm.card.is_some() {
                    serde_json::json!({
                        "input": {
                            "paymentMethodId": "fake-valid-nonce",
                            "transaction": {
                                "amount": amount_str,
                                "merchantAccountId": input.auth.get("merchant_id").cloned().unwrap_or_default()
                            }
                        }
                    })
                } else {
                    serde_json::json!({
                        "input": {
                            "paymentMethodId": "fake-valid-nonce",
                            "transaction": {
                                "amount": amount_str
                            }
                        }
                    })
                }
            } else {
                serde_json::json!({
                    "input": {
                        "paymentMethodId": "fake-valid-nonce",
                        "transaction": {
                            "amount": amount_str
                        }
                    }
                })
            };

            let body_json = serde_json::json!({
                "query": mutation,
                "variables": variables
            });

            Ok(HttpRequest {
                url: "https://payments.sandbox.braintree-api.com/graphql".to_string(),
                method: HttpMethod::Post,
                headers,
                body: Some(body_json.to_string()),
                body_format: BodyFormat::Json,
            })
        }
        _ => Err(ConnectorError::UnsupportedFlow {
            connector: "braintree".to_string(),
            flow: flow.to_string(),
        }),
    }
}

fn transform_braintree_response(
    input: &TransformResponseInput,
    _flow: PaymentFlow,
) -> Result<PaymentResult, ConnectorError> {
    let json: serde_json::Value =
        serde_json::from_str(&input.body).map_err(|e| ConnectorError::ParseError {
            message: e.to_string(),
        })?;

    if let Some(errors) = json["errors"].as_array() {
        if !errors.is_empty() {
            let error_message = errors
                .first()
                .and_then(|e| e["message"].as_str())
                .unwrap_or("Unknown error")
                .to_string();
            return Ok(PaymentResult::failure(None, Some(error_message)));
        }
    }

    let txn = &json["data"]["chargePaymentMethod"]["transaction"];
    let status_str = txn["status"].as_str().unwrap_or("UNKNOWN");

    let status = match status_str {
        "AUTHORIZED" => PaymentStatus::Authorized,
        "SUBMITTED_FOR_SETTLEMENT" | "SETTLED" | "SETTLING" => PaymentStatus::Succeeded,
        "VOIDED" => PaymentStatus::Cancelled,
        "FAILED" | "GATEWAY_REJECTED" | "PROCESSOR_DECLINED" => PaymentStatus::Failed,
        _ => PaymentStatus::Unknown,
    };

    Ok(PaymentResult {
        success: matches!(status, PaymentStatus::Authorized | PaymentStatus::Succeeded),
        status,
        transaction_id: txn["id"].as_str().map(String::from),
        connector_transaction_id: txn["id"].as_str().map(String::from),
        amount: txn["amount"]["value"]
            .as_str()
            .and_then(|s| s.parse::<f64>().ok())
            .map(|v| (v * 100.0) as i64),
        currency: txn["amount"]["currencyCode"].as_str().map(String::from),
        error_code: None,
        error_message: None,
        raw_response: Some(input.body.clone()),
    })
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Simple base64 encoding (avoiding external dependency)
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

/// Simple timestamp generator (avoiding chrono dependency)
fn chrono_lite_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_connectors() {
        let connectors = list_supported_connectors();
        assert!(connectors.contains(&"stripe".to_string()));
        assert!(connectors.contains(&"adyen".to_string()));
    }

    #[test]
    fn test_get_connector_info() {
        let info = get_connector_info("stripe".to_string());
        assert!(info.is_some());
        let stripe = info.unwrap();
        assert_eq!(stripe.name, "stripe");
        assert_eq!(stripe.body_format, BodyFormat::FormUrlEncoded);
    }

    #[test]
    fn test_stripe_authorize_transform() {
        let mut auth = HashMap::new();
        auth.insert("api_key".to_string(), "sk_test_xxx".to_string());

        let payment_method = create_card_payment_method(
            "4242424242424242".to_string(),
            12,
            2025,
            "123".to_string(),
            Some("John Doe".to_string()),
        );

        let input = TransformRequestInput {
            connector: "stripe".to_string(),
            flow: "authorize".to_string(),
            auth,
            payment: PaymentData {
                amount: 1000,
                currency: "USD".to_string(),
                payment_method: Some(payment_method),
                reference_id: Some("test_ref".to_string()),
                transaction_id: None,
                return_url: None,
                metadata: None,
            },
        };

        let result = transform_request(input);
        assert!(result.is_ok());

        let http_req = result.unwrap();
        assert_eq!(http_req.url, "https://api.stripe.com/v1/payment_intents");
        assert_eq!(http_req.method, HttpMethod::Post);
        assert!(http_req.headers.contains_key("Authorization"));
        assert!(http_req.body.is_some());
    }

    #[test]
    fn test_stripe_response_transform() {
        let input = TransformResponseInput {
            connector: "stripe".to_string(),
            flow: "authorize".to_string(),
            status_code: 200,
            headers: HashMap::new(),
            body: r#"{
                "id": "pi_123",
                "status": "requires_capture",
                "amount": 1000,
                "currency": "usd"
            }"#
            .to_string(),
        };

        let result = transform_response(input);
        assert!(result.is_ok());

        let payment_result = result.unwrap();
        assert!(payment_result.success);
        assert_eq!(payment_result.status, PaymentStatus::Authorized);
        assert_eq!(payment_result.transaction_id, Some("pi_123".to_string()));
    }

    #[test]
    fn test_connector_registry() {
        let registry = ConnectorRegistry::new();
        let connectors = registry.list_connectors();
        assert!(!connectors.is_empty());

        let flows = registry.get_supported_flows("stripe".to_string());
        assert!(flows.is_ok());
        assert!(flows.unwrap().contains(&PaymentFlow::Authorize));
    }

    #[test]
    fn test_unknown_connector_error() {
        let mut auth = HashMap::new();
        auth.insert("api_key".to_string(), "test".to_string());

        let input = TransformRequestInput {
            connector: "unknown_connector".to_string(),
            flow: "authorize".to_string(),
            auth,
            payment: PaymentData {
                amount: 1000,
                currency: "USD".to_string(),
                payment_method: None,
                reference_id: None,
                transaction_id: None,
                return_url: None,
                metadata: None,
            },
        };

        let result = transform_request(input);
        assert!(result.is_err());
        match result {
            Err(ConnectorError::UnknownConnector { name }) => {
                assert_eq!(name, "unknown_connector");
            }
            _ => panic!("Expected UnknownConnector error"),
        }
    }
}
