//! Field-probe binary — discovers required fields and sample payloads for every
//! connector × flow × payment-method combination WITHOUT making any HTTP calls.
//!
//! Strategy:
//!   For each (connector, flow, pm_type):
//!     1. Build a maximally-populated proto request with all standard fields set.
//!     2. Call the ffi req_transformer directly (no HTTP).
//!     3. Ok(Some(req))  → supported; record (url, method, headers, body).
//!     4. Ok(None)       → connector skips this flow/pm (returns None intentionally).
//!     5. Err(e)         → parse error, patch proto request, retry up to MAX_ITERS.
//!
//! Output: JSON written to stdout (pipe to file as needed).
//!
//! Configuration: See probe-config.toml for OAuth connectors, payment methods,
//! and connector-specific metadata.

// This is a build-time tool, not production code. Allow certain patterns that would
// be problematic in production but are acceptable here.
#![allow(clippy::print_stdout)]
#![allow(clippy::print_stderr)]
#![allow(clippy::panic)] // Panics are acceptable in build tools
#![allow(clippy::unwrap_used)] // unwrap is fine in build tools
#![allow(clippy::expect_used)] // expect is fine in build tools
#![allow(clippy::as_conversions)] // as conversions are needed for proto enums
#![allow(clippy::type_complexity)] // Complex types are fine
#![allow(clippy::clone_on_copy)] // clone on Copy types is harmless

extern crate connector_service_ffi as ffi;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::OnceLock;

use common_utils::metadata::{HeaderMaskingConfig, MaskedMetadata};
use domain_types::{connector_types::ConnectorEnum, router_data::ConnectorSpecificConfig};
use grpc_api_types::payments::{
    self as proto, mandate_reference::MandateIdType, payment_method::PaymentMethod as PmVariant,
    AcceptanceType, Address, BrowserInformation, CaptureMethod, CardDetails,
    ConnectorMandateReferenceId, Customer, CustomerAcceptance, CustomerServiceCreateRequest,
    DisputeServiceAcceptRequest, DisputeServiceDefendRequest, DisputeServiceSubmitEvidenceRequest,
    EvidenceDocument, EvidenceType, MandateReference,
    MerchantAuthenticationServiceCreateAccessTokenRequest,
    MerchantAuthenticationServiceCreateSessionTokenRequest, Money, PaymentAddress, PaymentMethod,
    PaymentMethodAuthenticationServiceAuthenticateRequest,
    PaymentMethodAuthenticationServicePostAuthenticateRequest,
    PaymentMethodAuthenticationServicePreAuthenticateRequest, PaymentMethodServiceTokenizeRequest,
    PaymentServiceAuthorizeRequest, PaymentServiceCaptureRequest, PaymentServiceCreateOrderRequest,
    PaymentServiceGetRequest, PaymentServiceRefundRequest, PaymentServiceReverseRequest,
    PaymentServiceSetupRecurringRequest, PaymentServiceVoidRequest,
    RecurringPaymentServiceChargeRequest,
};
use hyperswitch_masking::Secret;

use rayon::prelude::*;
use serde::{Deserialize, Serialize};

mod flow_metadata;
use flow_metadata::{parse_services_proto, FlowMetadata};

// ---------------------------------------------------------------------------
// Proto JSON conversion helpers
// ---------------------------------------------------------------------------

/// Convert PascalCase to snake_case
fn pascal_to_snake(name: &str) -> String {
    let mut result = String::new();
    for (i, ch) in name.chars().enumerate() {
        if ch.is_uppercase() && i > 0 {
            result.push('_');
        }
        result.push(ch.to_ascii_lowercase());
    }
    result
}

/// Convert Rust serde JSON format to proper proto JSON format.
///
/// Transformations:
/// - oneof variant names: "ApplePay" → "apple_pay" (snake_case)
/// - Nested oneof: {"payment_method": {"ApplePay": {...}}} → {"payment_method": {"apple_pay": {...}}}
fn convert_rust_to_proto_json(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut result = serde_json::Map::new();
            for (key, val) in map {
                // Check if this is a oneof wrapper: key is PascalCase and value is a single-entry object
                if let serde_json::Value::Object(inner_map) = val {
                    if inner_map.len() == 1 {
                        let inner_key = inner_map.keys().next().unwrap();
                        // If inner key starts with uppercase and isn't all uppercase, it's a oneof variant
                        if inner_key
                            .chars()
                            .next()
                            .map(|c| c.is_uppercase())
                            .unwrap_or(false)
                            && !inner_key.chars().all(|c| c.is_uppercase() || c == '_')
                        {
                            let snake_key = pascal_to_snake(inner_key);
                            let converted_inner =
                                convert_rust_to_proto_json(inner_map.values().next().unwrap());
                            result.insert(
                                key.clone(),
                                serde_json::Value::Object({
                                    let mut m = serde_json::Map::new();
                                    m.insert(snake_key, converted_inner);
                                    m
                                }),
                            );
                            continue;
                        }
                    }
                }
                result.insert(key.clone(), convert_rust_to_proto_json(val));
            }
            serde_json::Value::Object(result)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(convert_rust_to_proto_json).collect())
        }
        other => other.clone(),
    }
}

/// Keys that are probe-internal and should be removed from the output
const PROBE_INTERNAL_KEYS: &[&str] = &["connector_feature_data"];

/// Check if a string value is a proto3 default enum value
fn is_default_enum(value: &str) -> bool {
    value.ends_with("_UNSPECIFIED") || value.ends_with("_UNKNOWN")
}

/// Flatten proto3 oneof wrappers that serde adds as an extra nesting level.
///
/// Prost generates oneof fields as `Option<Enum>` stored under a field with the
/// same name as the oneof itself. When serde serializes, we get:
///   {"payment_method": {"payment_method": {"card": {...}}}}
/// In proto3 JSON the oneof variant is inlined:
///   {"payment_method": {"card": {...}}}
fn flatten_oneof_wrappers(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut result = serde_json::Map::new();
            for (k, v) in map {
                let v = flatten_oneof_wrappers(v);
                // Collapse the oneof wrapper: {"k": {"k": inner}} → {"k": inner}
                if let serde_json::Value::Object(inner_map) = &v {
                    if inner_map.len() == 1
                        && inner_map.keys().next().map(|ik| ik == k).unwrap_or(false)
                    {
                        let inner_value = inner_map.values().next().unwrap();
                        result.insert(k.clone(), flatten_oneof_wrappers(inner_value));
                        continue;
                    }
                }
                result.insert(k.clone(), v);
            }
            serde_json::Value::Object(result)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(flatten_oneof_wrappers).collect())
        }
        other => other.clone(),
    }
}

/// Clean a proto_request for documentation output:
///   1. Remove probe-internal keys (connector_feature_data, etc.)
///   2. Remove null values and empty arrays
///   3. Remove proto3 default enum values (*_UNSPECIFIED / *_UNKNOWN)
///   4. Collapse proto3 oneof wrappers
fn clean_proto_request(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut result = serde_json::Map::new();
            for (k, v) in map {
                // Skip probe-internal keys
                if PROBE_INTERNAL_KEYS.contains(&k.as_str()) {
                    continue;
                }
                // Skip null values
                if v.is_null() {
                    continue;
                }
                // Skip empty arrays
                if let serde_json::Value::Array(arr) = v {
                    if arr.is_empty() {
                        continue;
                    }
                }
                // Skip default enum values
                if let serde_json::Value::String(s) = v {
                    if is_default_enum(s) {
                        continue;
                    }
                }
                result.insert(k.clone(), clean_proto_request(v));
            }
            flatten_oneof_wrappers(&serde_json::Value::Object(result))
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(clean_proto_request).collect())
        }
        other => other.clone(),
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the field-probe, loaded from probe-config.toml
#[derive(Debug, Deserialize, Clone)]
struct ProbeConfig {
    probe: ProbeSettings,
    access_token: AccessTokenConfig,
    oauth_connectors: Vec<OAuthConnector>,
    /// Connectors to skip (exclude from probing). All others are probed.
    skip_connectors: Vec<String>,
    payment_methods: HashMap<String, bool>,
    connector_metadata: HashMap<String, String>,
}

#[derive(Debug, Deserialize, Clone)]
struct ProbeSettings {
    max_iterations: usize,
}

#[derive(Debug, Deserialize, Clone)]
struct AccessTokenConfig {
    token: String,
    token_type: String,
    expires_in_seconds: i64,
}

#[derive(Debug, Deserialize, Clone)]
struct OAuthConnector {
    name: String,
}

impl ProbeConfig {
    /// Load configuration from probe-config.toml in the same directory as the binary
    fn load() -> Self {
        // Try to find the config file
        let config_paths = [
            "backend/field-probe/probe-config.toml",
            "probe-config.toml",
            concat!(env!("CARGO_MANIFEST_DIR"), "/probe-config.toml"),
        ];

        for path in &config_paths {
            if let Ok(contents) = std::fs::read_to_string(path) {
                eprintln!("Loaded config from: {path}");
                return toml::from_str(&contents)
                    .unwrap_or_else(|e| panic!("Failed to parse {path}: {e}"));
            }
        }

        // Fallback to defaults if no config file found
        eprintln!("Warning: No probe-config.toml found, using defaults");
        Self::default()
    }

    /// Check if a connector is an OAuth connector that needs a cached access token
    fn is_oauth_connector(&self, connector: &ConnectorEnum) -> bool {
        let name = format!("{connector:?}").to_lowercase();
        self.oauth_connectors
            .iter()
            .any(|c| c.name.to_lowercase() == name)
    }

    /// Get payment methods enabled in config
    fn get_enabled_payment_methods(&self) -> Vec<(&'static str, fn() -> PaymentMethod)> {
        let all_methods = authorize_pm_variants_static();
        all_methods
            .into_iter()
            .filter(|(name, _)| self.payment_methods.get(*name).copied().unwrap_or(true))
            .collect()
    }
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            probe: ProbeSettings { max_iterations: 30 },
            access_token: AccessTokenConfig {
                token: "probe_access_token".to_string(),
                token_type: "Bearer".to_string(),
                expires_in_seconds: 3600,
            },
            oauth_connectors: vec![
                OAuthConnector {
                    name: "airwallex".to_string(),
                },
                OAuthConnector {
                    name: "globalpay".to_string(),
                },
                OAuthConnector {
                    name: "jpmorgan".to_string(),
                },
                OAuthConnector {
                    name: "iatapay".to_string(),
                },
                OAuthConnector {
                    name: "getnet".to_string(),
                },
                OAuthConnector {
                    name: "payload".to_string(),
                },
                OAuthConnector {
                    name: "paypal".to_string(),
                },
                OAuthConnector {
                    name: "truelayer".to_string(),
                },
                OAuthConnector {
                    name: "volt".to_string(),
                },
            ],
            skip_connectors: vec![],
            payment_methods: HashMap::new(),
            connector_metadata: HashMap::new(),
        }
    }
}

/// Global config instance
static PROBE_CONFIG: OnceLock<ProbeConfig> = OnceLock::new();

fn get_config() -> &'static ProbeConfig {
    PROBE_CONFIG.get_or_init(ProbeConfig::load)
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

fn max_iterations() -> usize {
    get_config().probe.max_iterations
}

// ---------------------------------------------------------------------------
// Output types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
struct SamplePayload {
    url: String,
    method: String,
    headers: HashMap<String, String>,
    body: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
struct FlowResult {
    status: String, // "supported" | "not_supported" | "error"
    required_fields: Vec<String>,
    /// The proto JSON request that produced a successful transformer call.
    /// This is what the SDK user should send to UCS.
    proto_request: Option<serde_json::Value>,
    sample: Option<SamplePayload>,
    error: Option<String>,
    /// Full gRPC service.rpc name (e.g., "PaymentService.Authorize")
    service_rpc: Option<String>,
    /// Human-readable description from proto comments
    description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct ConnectorResult {
    connector: String,
    flows: BTreeMap<String, BTreeMap<String, FlowResult>>,
}

/// Top-level output structure for the manifest file
#[derive(Debug, Serialize, Deserialize)]
struct ProbeManifest {
    /// Flow metadata for all probed flows (generated from services.proto)
    flow_metadata: Vec<FlowMetadata>,
    /// List of connector names that were probed
    connectors: Vec<String>,
    /// Schema version for future compatibility
    schema_version: String,
}

/// Compact flow result that omits null fields and not_supported status
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
struct CompactFlowResult {
    status: String, // "supported" | "error" (not_supported is omitted entirely)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    required_fields: Vec<String>,
    /// The proto JSON request that produced a successful transformer call.
    #[serde(skip_serializing_if = "Option::is_none")]
    proto_request: Option<serde_json::Value>,
    /// Sample payload for the request
    #[serde(skip_serializing_if = "Option::is_none")]
    sample: Option<SamplePayload>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl From<FlowResult> for Option<CompactFlowResult> {
    fn from(result: FlowResult) -> Self {
        // Skip not_supported entries entirely
        if result.status == "not_supported" {
            return None;
        }
        Some(CompactFlowResult {
            status: result.status,
            required_fields: result.required_fields,
            proto_request: result.proto_request,
            sample: result.sample,
            error: result.error,
        })
    }
}

/// Compact connector result with omitted null fields
#[derive(Debug, Serialize, Deserialize, Default)]
struct CompactConnectorResult {
    connector: String,
    flows: BTreeMap<String, BTreeMap<String, CompactFlowResult>>,
}

// ---------------------------------------------------------------------------
// Config / metadata helpers
// ---------------------------------------------------------------------------

fn load_config() -> Arc<ucs_env::configs::Config> {
    ffi::utils::load_config(ffi::handlers::payments::EMBEDDED_DEVELOPMENT_CONFIG)
        .expect("Failed to load dev config")
}

fn make_masked_metadata() -> MaskedMetadata {
    MaskedMetadata::new(
        tonic::metadata::MetadataMap::new(),
        HeaderMaskingConfig::default(),
    )
}

// ---------------------------------------------------------------------------
// Proto helpers
// ---------------------------------------------------------------------------

fn usd_money(minor: i64) -> Money {
    Money {
        minor_amount: minor,
        currency: proto::Currency::Usd as i32,
    }
}

fn full_address() -> Address {
    Address {
        first_name: Some(Secret::new("John".to_string())),
        last_name: Some(Secret::new("Doe".to_string())),
        line1: Some(Secret::new("123 Main St".to_string())),
        line2: None,
        line3: None,
        city: Some(Secret::new("Seattle".to_string())),
        state: Some(Secret::new("WA".to_string())),
        zip_code: Some(Secret::new("98101".to_string())),
        country_alpha2_code: Some(proto::CountryAlpha2::Us as i32),
        email: Some(Secret::new("test@example.com".to_string())),
        phone_number: Some(Secret::new("4155552671".to_string())),
        phone_country_code: Some("+1".to_string()),
    }
}

fn full_browser_info() -> BrowserInformation {
    BrowserInformation {
        color_depth: Some(24),
        screen_height: Some(900),
        screen_width: Some(1440),
        java_enabled: Some(false),
        java_script_enabled: Some(true),
        language: Some("en-US".to_string()),
        time_zone_offset_minutes: Some(-480),
        accept_header: Some("application/json".to_string()),
        user_agent: Some("Mozilla/5.0 (probe-bot)".to_string()),
        accept_language: Some("en-US,en;q=0.9".to_string()),
        referer: None,
        ip_address: Some("1.2.3.4".to_string()),
        os_type: None,
        os_version: None,
        device_model: None,
    }
}

fn full_customer() -> Customer {
    Customer {
        name: Some("John Doe".to_string()),
        email: Some(Secret::new("test@example.com".to_string())),
        id: Some("cust_probe_123".to_string()),
        connector_customer_id: None,
        phone_number: Some("4155552671".to_string()),
        phone_country_code: Some("+1".to_string()),
    }
}

// ---------------------------------------------------------------------------
// Payment method builders
// ---------------------------------------------------------------------------

fn card_payment_method() -> PaymentMethod {
    PaymentMethod {
        payment_method: Some(PmVariant::Card(CardDetails {
            card_number: Some(
                cards::CardNumber::from_str("4111111111111111").expect("static test card"),
            ),
            card_exp_month: Some(Secret::new("03".to_string())),
            card_exp_year: Some(Secret::new("2030".to_string())),
            card_cvc: Some(Secret::new("737".to_string())),
            card_holder_name: Some(Secret::new("John Doe".to_string())),
            ..Default::default()
        })),
    }
}

fn sepa_payment_method() -> PaymentMethod {
    PaymentMethod {
        payment_method: Some(PmVariant::Sepa(proto::Sepa {
            iban: Some(Secret::new("DE89370400440532013000".to_string())),
            bank_account_holder_name: Some(Secret::new("John Doe".to_string())),
        })),
    }
}

fn bacs_payment_method() -> PaymentMethod {
    PaymentMethod {
        payment_method: Some(PmVariant::Bacs(proto::Bacs {
            sort_code: Some(Secret::new("200000".to_string())),
            account_number: Some(Secret::new("55779911".to_string())),
            bank_account_holder_name: Some(Secret::new("John Doe".to_string())),
        })),
    }
}

fn ach_payment_method() -> PaymentMethod {
    PaymentMethod {
        payment_method: Some(PmVariant::Ach(proto::Ach {
            routing_number: Some(Secret::new("110000000".to_string())),
            account_number: Some(Secret::new("000123456789".to_string())),
            bank_account_holder_name: Some(Secret::new("John Doe".to_string())),
            ..Default::default()
        })),
    }
}

fn becs_payment_method() -> PaymentMethod {
    PaymentMethod {
        payment_method: Some(PmVariant::Becs(proto::Becs {
            bsb_number: Some(Secret::new("000000".to_string())),
            account_number: Some(Secret::new("000123456".to_string())),
            bank_account_holder_name: Some(Secret::new("John Doe".to_string())),
        })),
    }
}

fn google_pay_decrypted_method() -> PaymentMethod {
    use proto::google_wallet::{tokenization_data::TokenizationData as TD, TokenizationData};
    PaymentMethod {
        payment_method: Some(PmVariant::GooglePay(proto::GoogleWallet {
            r#type: "CARD".to_string(),
            description: "Visa •••• 1111".to_string(),
            info: Some(proto::google_wallet::PaymentMethodInfo {
                card_network: "VISA".to_string(),
                card_details: "1111".to_string(),
                assurance_details: None,
            }),
            tokenization_data: Some(TokenizationData {
                tokenization_data: Some(TD::DecryptedData(proto::GooglePayDecryptedData {
                    card_exp_month: Some(Secret::new("03".to_string())),
                    card_exp_year: Some(Secret::new("2030".to_string())),
                    application_primary_account_number: Some(
                        cards::CardNumber::from_str("4111111111111111").expect("static test card"),
                    ),
                    cryptogram: Some(Secret::new("AAAAAA==".to_string())),
                    eci_indicator: Some("05".to_string()),
                })),
            }),
        })),
    }
}

/// Google Pay using encrypted token format (needed by connectors like Stripe that call
/// `get_encrypted_google_pay_token()` and parse it as a JSON struct with a token `id`).
fn google_pay_encrypted_method() -> PaymentMethod {
    use proto::google_wallet::{tokenization_data::TokenizationData as TD, TokenizationData};
    // Stripe parses this as StripeGpayToken { id: String } — provide a minimal JSON.
    let encrypted_token = r#"{"id":"tok_probe_gpay","object":"token","type":"card"}"#;
    PaymentMethod {
        payment_method: Some(PmVariant::GooglePay(proto::GoogleWallet {
            r#type: "CARD".to_string(),
            description: "Visa •••• 1111".to_string(),
            info: Some(proto::google_wallet::PaymentMethodInfo {
                card_network: "VISA".to_string(),
                card_details: "1111".to_string(),
                assurance_details: None,
            }),
            tokenization_data: Some(TokenizationData {
                tokenization_data: Some(TD::EncryptedData(
                    proto::GooglePayEncryptedTokenizationData {
                        token: encrypted_token.to_string(),
                        token_type: "PAYMENT_GATEWAY".to_string(),
                    },
                )),
            }),
        })),
    }
}

fn google_pay_method() -> PaymentMethod {
    google_pay_decrypted_method()
}

/// Apple Pay using the encrypted token format (required by connectors like Nexinets/Novalnet
/// that call `get_apple_pay_encrypted_data()` rather than using decrypted card data).
fn apple_pay_encrypted_method() -> PaymentMethod {
    use proto::apple_wallet::{payment_data::PaymentData as PD, PaymentData};
    PaymentMethod {
        payment_method: Some(PmVariant::ApplePay(proto::AppleWallet {
            payment_data: Some(PaymentData {
                payment_data: Some(PD::EncryptedData(
                    // Valid base64 encoding of a minimal Apple Pay token JSON stub.
                    // Decodes to: {"version":"EC_v1","data":"probe","signature":"probe"}
                    "eyJ2ZXJzaW9uIjoiRUNfdjEiLCJkYXRhIjoicHJvYmUiLCJzaWduYXR1cmUiOiJwcm9iZSJ9"
                        .to_string(),
                )),
            }),
            payment_method: Some(proto::apple_wallet::PaymentMethod {
                display_name: "Visa 1111".to_string(),
                network: "Visa".to_string(),
                r#type: "debit".to_string(),
            }),
            transaction_identifier: "probe_txn_id".to_string(),
        })),
    }
}

fn ideal_payment_method() -> PaymentMethod {
    PaymentMethod {
        payment_method: Some(PmVariant::Ideal(proto::Ideal { bank_name: None })),
    }
}

fn paypal_redirect_method() -> PaymentMethod {
    PaymentMethod {
        payment_method: Some(PmVariant::PaypalRedirect(proto::PaypalRedirectWallet {
            email: Some(Secret::new("test@example.com".to_string())),
        })),
    }
}

fn blik_payment_method() -> PaymentMethod {
    PaymentMethod {
        payment_method: Some(PmVariant::Blik(proto::Blik {
            blik_code: Some("777124".to_string()),
        })),
    }
}

fn klarna_payment_method() -> PaymentMethod {
    PaymentMethod {
        payment_method: Some(PmVariant::Klarna(proto::Klarna {})),
    }
}

fn afterpay_payment_method() -> PaymentMethod {
    PaymentMethod {
        payment_method: Some(PmVariant::AfterpayClearpay(proto::AfterpayClearpay {})),
    }
}

fn upi_collect_payment_method() -> PaymentMethod {
    PaymentMethod {
        payment_method: Some(PmVariant::UpiCollect(proto::UpiCollect {
            vpa_id: Some(Secret::new("test@upi".to_string())),
            upi_source: None,
        })),
    }
}

fn affirm_payment_method() -> PaymentMethod {
    PaymentMethod {
        payment_method: Some(PmVariant::Affirm(proto::Affirm {})),
    }
}

fn samsung_pay_payment_method() -> PaymentMethod {
    PaymentMethod {
        payment_method: Some(PmVariant::SamsungPay(proto::SamsungWallet {
            payment_credential: None,
        })),
    }
}

fn apple_pay_method() -> PaymentMethod {
    use proto::apple_wallet::{payment_data::PaymentData as PD, PaymentData};
    // Use pre-decrypted format so connectors that support it (e.g. Stripe) can build
    // the request using card-like data without needing real decryption.
    // Connectors that require the encrypted path will fall through to their own error.
    PaymentMethod {
        payment_method: Some(PmVariant::ApplePay(proto::AppleWallet {
            payment_data: Some(PaymentData {
                payment_data: Some(PD::DecryptedData(proto::ApplePayDecryptedData {
                    application_primary_account_number: Some(
                        cards::CardNumber::from_str("4111111111111111").expect("static test card"),
                    ),
                    application_expiration_month: Some(Secret::new("03".to_string())),
                    application_expiration_year: Some(Secret::new("2030".to_string())),
                    payment_data: Some(proto::ApplePayCryptogramData {
                        online_payment_cryptogram: Some(Secret::new("AAAAAA==".to_string())),
                        eci_indicator: Some("05".to_string()),
                    }),
                })),
            }),
            payment_method: Some(proto::apple_wallet::PaymentMethod {
                display_name: "Visa 1111".to_string(),
                network: "Visa".to_string(),
                r#type: "debit".to_string(),
            }),
            transaction_identifier: "probe_txn_id".to_string(),
        })),
    }
}

// ---------------------------------------------------------------------------
// Base request builders
// ---------------------------------------------------------------------------

fn base_authorize_request_with_meta(
    pm: PaymentMethod,
    connector_meta: Option<String>,
) -> PaymentServiceAuthorizeRequest {
    PaymentServiceAuthorizeRequest {
        amount: Some(usd_money(1000)),
        payment_method: Some(pm),
        capture_method: Some(CaptureMethod::Automatic as i32),
        address: Some(PaymentAddress {
            billing_address: Some(full_address()),
            shipping_address: Some(full_address()),
        }),
        customer: Some(full_customer()),
        browser_info: Some(full_browser_info()),
        auth_type: proto::AuthenticationType::NoThreeDs as i32,
        return_url: Some("https://example.com/return".to_string()),
        webhook_url: Some("https://example.com/webhook".to_string()),
        complete_authorize_url: Some("https://example.com/complete".to_string()),
        merchant_transaction_id: Some("probe_txn_001".to_string()),
        connector_feature_data: connector_meta.map(Secret::new),
        ..Default::default()
    }
}

/// Build an authorize request with OAuth state (access token) for OAuth connectors.
fn base_authorize_request_with_state(
    pm: PaymentMethod,
    connector_meta: Option<String>,
    state: proto::ConnectorState,
) -> PaymentServiceAuthorizeRequest {
    PaymentServiceAuthorizeRequest {
        amount: Some(usd_money(1000)),
        payment_method: Some(pm),
        capture_method: Some(CaptureMethod::Automatic as i32),
        address: Some(PaymentAddress {
            billing_address: Some(full_address()),
            shipping_address: Some(full_address()),
        }),
        customer: Some(full_customer()),
        browser_info: Some(full_browser_info()),
        auth_type: proto::AuthenticationType::NoThreeDs as i32,
        return_url: Some("https://example.com/return".to_string()),
        webhook_url: Some("https://example.com/webhook".to_string()),
        complete_authorize_url: Some("https://example.com/complete".to_string()),
        merchant_transaction_id: Some("probe_txn_001".to_string()),
        connector_feature_data: connector_meta.map(Secret::new),
        state: Some(state),
        ..Default::default()
    }
}

fn base_capture_request() -> PaymentServiceCaptureRequest {
    PaymentServiceCaptureRequest {
        connector_transaction_id: "probe_connector_txn_001".to_string(),
        amount_to_capture: Some(usd_money(1000)),
        merchant_capture_id: Some("probe_capture_001".to_string()),
        ..Default::default()
    }
}

fn base_refund_request() -> PaymentServiceRefundRequest {
    PaymentServiceRefundRequest {
        connector_transaction_id: "probe_connector_txn_001".to_string(),
        payment_amount: 1000,
        refund_amount: Some(usd_money(1000)),
        merchant_refund_id: Some("probe_refund_001".to_string()),
        reason: Some("customer_request".to_string()),
        ..Default::default()
    }
}

fn base_void_request() -> PaymentServiceVoidRequest {
    PaymentServiceVoidRequest {
        connector_transaction_id: "probe_connector_txn_001".to_string(),
        merchant_void_id: Some("probe_void_001".to_string()),
        ..Default::default()
    }
}

fn base_get_request() -> PaymentServiceGetRequest {
    PaymentServiceGetRequest {
        connector_transaction_id: "probe_connector_txn_001".to_string(),
        amount: Some(usd_money(1000)),
        ..Default::default()
    }
}

fn base_reverse_request() -> PaymentServiceReverseRequest {
    PaymentServiceReverseRequest {
        connector_transaction_id: "probe_connector_txn_001".to_string(),
        merchant_reverse_id: Some("probe_reverse_001".to_string()),
        ..Default::default()
    }
}

fn base_create_order_request() -> PaymentServiceCreateOrderRequest {
    PaymentServiceCreateOrderRequest {
        amount: Some(usd_money(1000)),
        merchant_order_id: Some("probe_order_001".to_string()),
        ..Default::default()
    }
}

fn base_setup_recurring_request() -> PaymentServiceSetupRecurringRequest {
    PaymentServiceSetupRecurringRequest {
        amount: Some(usd_money(0)),
        payment_method: Some(card_payment_method()),
        customer: Some(full_customer()),
        address: Some(PaymentAddress {
            billing_address: Some(full_address()),
            shipping_address: None,
        }),
        auth_type: proto::AuthenticationType::NoThreeDs as i32,
        return_url: Some("https://example.com/mandate-return".to_string()),
        merchant_recurring_payment_id: "probe_mandate_001".to_string(),
        setup_future_usage: Some(proto::FutureUsage::OffSession as i32),
        customer_acceptance: Some(CustomerAcceptance {
            acceptance_type: AcceptanceType::Offline as i32,
            accepted_at: 0,
            online_mandate_details: None,
        }),
        browser_info: Some(full_browser_info()),
        ..Default::default()
    }
}

fn base_recurring_charge_request() -> RecurringPaymentServiceChargeRequest {
    RecurringPaymentServiceChargeRequest {
        amount: Some(usd_money(1000)),
        payment_method: Some(PaymentMethod {
            payment_method: Some(PmVariant::Token(proto::TokenPaymentMethodType {
                token: Some(Secret::new("probe_pm_token".to_string())),
            })),
        }),
        off_session: Some(true),
        connector_customer_id: Some("probe_cust_connector_001".to_string()),
        return_url: Some("https://example.com/recurring-return".to_string()),
        payment_method_type: Some(proto::PaymentMethodType::PayPal as i32),
        connector_recurring_payment_id: Some(MandateReference {
            mandate_id_type: Some(MandateIdType::ConnectorMandateId(
                ConnectorMandateReferenceId {
                    connector_mandate_id: Some("probe_mandate_123".to_string()),
                    payment_method_id: None,
                    connector_mandate_request_reference_id: None,
                },
            )),
        }),
        ..Default::default()
    }
}

fn base_create_customer_request() -> CustomerServiceCreateRequest {
    CustomerServiceCreateRequest {
        customer_name: Some("John Doe".to_string()),
        email: Some(Secret::new("test@example.com".to_string())),
        phone_number: Some("4155552671".to_string()),
        address: Some(PaymentAddress {
            billing_address: Some(full_address()),
            shipping_address: None,
        }),
        ..Default::default()
    }
}

fn base_tokenize_request() -> PaymentMethodServiceTokenizeRequest {
    PaymentMethodServiceTokenizeRequest {
        amount: Some(usd_money(1000)),
        payment_method: Some(card_payment_method()),
        customer: Some(full_customer()),
        address: Some(PaymentAddress {
            billing_address: Some(full_address()),
            shipping_address: None,
        }),
        ..Default::default()
    }
}

fn base_create_access_token_request() -> MerchantAuthenticationServiceCreateAccessTokenRequest {
    MerchantAuthenticationServiceCreateAccessTokenRequest {
        ..Default::default()
    }
}

fn base_create_session_token_request() -> MerchantAuthenticationServiceCreateSessionTokenRequest {
    MerchantAuthenticationServiceCreateSessionTokenRequest {
        amount: Some(usd_money(1000)),
        ..Default::default()
    }
}

fn base_pre_authenticate_request() -> PaymentMethodAuthenticationServicePreAuthenticateRequest {
    PaymentMethodAuthenticationServicePreAuthenticateRequest {
        payment_method: Some(card_payment_method()),
        amount: Some(usd_money(1000)),
        customer: Some(full_customer()),
        browser_info: Some(full_browser_info()),
        return_url: Some("https://example.com/3ds-return".to_string()),
        ..Default::default()
    }
}

fn base_authenticate_request() -> PaymentMethodAuthenticationServiceAuthenticateRequest {
    PaymentMethodAuthenticationServiceAuthenticateRequest {
        payment_method: Some(card_payment_method()),
        amount: Some(usd_money(1000)),
        browser_info: Some(full_browser_info()),
        return_url: Some("https://example.com/3ds-return".to_string()),
        ..Default::default()
    }
}

fn base_post_authenticate_request() -> PaymentMethodAuthenticationServicePostAuthenticateRequest {
    PaymentMethodAuthenticationServicePostAuthenticateRequest {
        payment_method: Some(card_payment_method()),
        amount: Some(usd_money(1000)),
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// Auth builders — one dummy variant per connector
// ---------------------------------------------------------------------------

fn dummy_auth(connector: &ConnectorEnum) -> ConnectorSpecificConfig {
    let k = || Secret::new("probe_key".to_string());
    let s = || Secret::new("probe_secret".to_string());
    let m = || Secret::new("probe_merchant".to_string());
    let u = || Secret::new("probe_user".to_string());
    let p = || Secret::new("probe_pass".to_string());
    let id = || Secret::new("probe_id".to_string());

    match connector {
        ConnectorEnum::Stripe => ConnectorSpecificConfig::Stripe {
            api_key: k(),
            base_url: None,
        },
        ConnectorEnum::Calida => ConnectorSpecificConfig::Calida {
            api_key: k(),
            base_url: None,
        },
        ConnectorEnum::Celero => ConnectorSpecificConfig::Celero {
            api_key: k(),
            base_url: None,
        },
        ConnectorEnum::Helcim => ConnectorSpecificConfig::Helcim {
            api_key: k(),
            base_url: None,
        },
        ConnectorEnum::Mifinity => ConnectorSpecificConfig::Mifinity {
            key: k(),
            base_url: None,
        },
        ConnectorEnum::Multisafepay => ConnectorSpecificConfig::Multisafepay {
            api_key: k(),
            base_url: None,
        },
        ConnectorEnum::Nexixpay => ConnectorSpecificConfig::Nexixpay {
            api_key: k(),
            base_url: None,
        },
        ConnectorEnum::Shift4 => ConnectorSpecificConfig::Shift4 {
            api_key: k(),
            base_url: None,
        },
        ConnectorEnum::Stax => ConnectorSpecificConfig::Stax {
            api_key: k(),
            base_url: None,
        },
        ConnectorEnum::Xendit => ConnectorSpecificConfig::Xendit {
            api_key: k(),
            base_url: None,
        },
        ConnectorEnum::Revolut => ConnectorSpecificConfig::Revolut {
            secret_api_key: k(),
            signing_secret: None,
            base_url: None,
        },
        ConnectorEnum::Bambora => ConnectorSpecificConfig::Bambora {
            merchant_id: m(),
            api_key: k(),
            base_url: None,
        },
        ConnectorEnum::Nexinets => ConnectorSpecificConfig::Nexinets {
            merchant_id: m(),
            api_key: k(),
            base_url: None,
        },
        ConnectorEnum::Razorpay => ConnectorSpecificConfig::Razorpay {
            api_key: k(),
            api_secret: Some(s()),
            base_url: None,
        },
        ConnectorEnum::RazorpayV2 => ConnectorSpecificConfig::RazorpayV2 {
            api_key: k(),
            api_secret: Some(s()),
            base_url: None,
        },
        ConnectorEnum::Aci => ConnectorSpecificConfig::Aci {
            api_key: k(),
            entity_id: id(),
            base_url: None,
        },
        ConnectorEnum::Airwallex => ConnectorSpecificConfig::Airwallex {
            api_key: k(),
            client_id: id(),
            base_url: None,
        },
        ConnectorEnum::Authorizedotnet => ConnectorSpecificConfig::Authorizedotnet {
            name: u(),
            transaction_key: k(),
            base_url: None,
        },
        ConnectorEnum::Billwerk => ConnectorSpecificConfig::Billwerk {
            api_key: k(),
            public_api_key: Secret::new("probe_pub_key".to_string()),
            base_url: None,
            secondary_base_url: None,
        },
        ConnectorEnum::Bluesnap => ConnectorSpecificConfig::Bluesnap {
            username: u(),
            password: p(),
            base_url: None,
        },
        ConnectorEnum::Cashfree => ConnectorSpecificConfig::Cashfree {
            app_id: id(),
            secret_key: k(),
            base_url: None,
        },
        ConnectorEnum::Cryptopay => ConnectorSpecificConfig::Cryptopay {
            api_key: k(),
            api_secret: s(),
            base_url: None,
        },
        ConnectorEnum::Datatrans => ConnectorSpecificConfig::Datatrans {
            merchant_id: m(),
            password: p(),
            base_url: None,
        },
        ConnectorEnum::Globalpay => ConnectorSpecificConfig::Globalpay {
            app_id: id(),
            app_key: k(),
            base_url: None,
        },
        ConnectorEnum::Hipay => ConnectorSpecificConfig::Hipay {
            api_key: k(),
            api_secret: s(),
            base_url: None,
            secondary_base_url: None,
            third_base_url: None,
        },
        ConnectorEnum::Jpmorgan => ConnectorSpecificConfig::Jpmorgan {
            client_id: id(),
            client_secret: s(),
            base_url: None,
            secondary_base_url: None,
            company_name: None,
            product_name: None,
            merchant_purchase_description: None,
            statement_descriptor: None,
        },
        ConnectorEnum::Loonio => ConnectorSpecificConfig::Loonio {
            merchant_id: m(),
            merchant_token: k(),
            base_url: None,
        },
        ConnectorEnum::Paysafe => ConnectorSpecificConfig::Paysafe {
            username: u(),
            password: p(),
            base_url: None,
            account_id: None,
        },
        ConnectorEnum::Payu => ConnectorSpecificConfig::Payu {
            api_key: k(),
            api_secret: s(),
            base_url: None,
        },
        ConnectorEnum::Placetopay => ConnectorSpecificConfig::Placetopay {
            login: u(),
            tran_key: k(),
            base_url: None,
        },
        ConnectorEnum::Powertranz => ConnectorSpecificConfig::Powertranz {
            power_tranz_id: id(),
            power_tranz_password: p(),
            base_url: None,
        },
        ConnectorEnum::Rapyd => ConnectorSpecificConfig::Rapyd {
            access_key: k(),
            secret_key: s(),
            base_url: None,
        },
        ConnectorEnum::Authipay => ConnectorSpecificConfig::Authipay {
            api_key: k(),
            api_secret: s(),
            base_url: None,
        },
        ConnectorEnum::Fiservemea => ConnectorSpecificConfig::Fiservemea {
            api_key: k(),
            api_secret: s(),
            base_url: None,
        },
        ConnectorEnum::Mollie => ConnectorSpecificConfig::Mollie {
            api_key: k(),
            profile_token: None,
            base_url: None,
            secondary_base_url: None,
        },
        ConnectorEnum::Nmi => ConnectorSpecificConfig::Nmi {
            api_key: k(),
            public_key: None,
            base_url: None,
        },
        ConnectorEnum::Payme => ConnectorSpecificConfig::Payme {
            seller_payme_id: id(),
            payme_client_key: None,
            base_url: None,
        },
        ConnectorEnum::Peachpayments => ConnectorSpecificConfig::Peachpayments {
            api_key: k(),
            tenant_id: id(),
            base_url: None,
        },
        ConnectorEnum::Braintree => ConnectorSpecificConfig::Braintree {
            public_key: k(),
            private_key: s(),
            base_url: None,
            merchant_account_id: None,
            merchant_config_currency: None,
        },
        ConnectorEnum::Truelayer => ConnectorSpecificConfig::Truelayer {
            client_id: id(),
            client_secret: s(),
            base_url: None,
            secondary_base_url: None,
        },
        ConnectorEnum::Worldpay => ConnectorSpecificConfig::Worldpay {
            username: u(),
            password: p(),
            entity_id: id(),
            base_url: None,
            merchant_name: None,
        },
        ConnectorEnum::Adyen => ConnectorSpecificConfig::Adyen {
            api_key: k(),
            merchant_account: m(),
            review_key: None,
            base_url: None,
            dispute_base_url: None,
        },
        ConnectorEnum::Bankofamerica => ConnectorSpecificConfig::BankOfAmerica {
            api_key: k(),
            merchant_account: m(),
            api_secret: s(),
            base_url: None,
        },
        ConnectorEnum::Bamboraapac => ConnectorSpecificConfig::Bamboraapac {
            username: u(),
            password: p(),
            account_number: Secret::new("probe_acct_num".to_string()),
            base_url: None,
        },
        ConnectorEnum::Barclaycard => ConnectorSpecificConfig::Barclaycard {
            api_key: k(),
            merchant_account: m(),
            // Must be valid base64 — used for HMAC-SHA256 signing
            api_secret: Secret::new("cHJvYmVfc2VjcmV0".to_string()),
            base_url: None,
        },
        ConnectorEnum::Checkout => ConnectorSpecificConfig::Checkout {
            api_key: k(),
            api_secret: s(),
            processing_channel_id: id(),
            base_url: None,
        },
        ConnectorEnum::Cybersource => ConnectorSpecificConfig::Cybersource {
            api_key: k(),
            merchant_account: m(),
            // Must be valid base64 — used for HMAC-SHA256 signing in header generation
            api_secret: Secret::new("cHJvYmVfc2VjcmV0".to_string()),
            base_url: None,
            disable_avs: None,
            disable_cvn: None,
        },
        ConnectorEnum::Dlocal => ConnectorSpecificConfig::Dlocal {
            x_login: u(),
            x_trans_key: k(),
            secret: s(),
            base_url: None,
        },
        ConnectorEnum::Elavon => ConnectorSpecificConfig::Elavon {
            ssl_merchant_id: m(),
            ssl_user_id: u(),
            ssl_pin: Secret::new("probe_pin".to_string()),
            base_url: None,
        },
        ConnectorEnum::Fiserv => ConnectorSpecificConfig::Fiserv {
            api_key: k(),
            merchant_account: m(),
            api_secret: s(),
            base_url: None,
            terminal_id: None,
        },
        ConnectorEnum::Fiuu => ConnectorSpecificConfig::Fiuu {
            merchant_id: m(),
            verify_key: k(),
            secret_key: s(),
            base_url: None,
            secondary_base_url: None,
        },
        ConnectorEnum::Getnet => ConnectorSpecificConfig::Getnet {
            api_key: k(),
            api_secret: s(),
            seller_id: id(),
            base_url: None,
        },
        ConnectorEnum::Gigadat => ConnectorSpecificConfig::Gigadat {
            security_token: k(),
            access_token: Secret::new("probe_access_token".to_string()),
            campaign_id: id(),
            base_url: None,
        },
        ConnectorEnum::Hyperpg => ConnectorSpecificConfig::Hyperpg {
            username: u(),
            password: p(),
            merchant_id: m(),
            base_url: None,
        },
        ConnectorEnum::Iatapay => ConnectorSpecificConfig::Iatapay {
            client_id: id(),
            merchant_id: m(),
            client_secret: s(),
            base_url: None,
        },
        ConnectorEnum::Noon => ConnectorSpecificConfig::Noon {
            api_key: k(),
            business_identifier: id(),
            application_identifier: Secret::new("probe_app_id".to_string()),
            base_url: None,
        },
        ConnectorEnum::Novalnet => ConnectorSpecificConfig::Novalnet {
            product_activation_key: k(),
            payment_access_key: Secret::new("probe_payment_access".to_string()),
            tariff_id: id(),
            base_url: None,
        },
        ConnectorEnum::Nuvei => ConnectorSpecificConfig::Nuvei {
            merchant_id: m(),
            merchant_site_id: id(),
            merchant_secret: s(),
            base_url: None,
        },
        ConnectorEnum::Phonepe => ConnectorSpecificConfig::Phonepe {
            merchant_id: m(),
            salt_key: k(),
            salt_index: Secret::new("1".to_string()),
            base_url: None,
        },
        ConnectorEnum::Redsys => ConnectorSpecificConfig::Redsys {
            merchant_id: m(),
            terminal_id: id(),
            sha256_pwd: s(),
            base_url: None,
        },
        ConnectorEnum::Silverflow => ConnectorSpecificConfig::Silverflow {
            api_key: k(),
            api_secret: s(),
            merchant_acceptor_key: m(),
            base_url: None,
        },
        ConnectorEnum::Trustpay => ConnectorSpecificConfig::Trustpay {
            api_key: k(),
            project_id: id(),
            secret_key: s(),
            base_url: None,
            base_url_bank_redirects: None,
        },
        ConnectorEnum::Trustpayments => ConnectorSpecificConfig::Trustpayments {
            username: u(),
            password: p(),
            site_reference: Secret::new("probe_site_ref".to_string()),
            base_url: None,
        },
        ConnectorEnum::Tsys => ConnectorSpecificConfig::Tsys {
            device_id: id(),
            transaction_key: k(),
            developer_id: Secret::new("probe_dev_id".to_string()),
            base_url: None,
        },
        ConnectorEnum::Wellsfargo => ConnectorSpecificConfig::Wellsfargo {
            api_key: k(),
            merchant_account: m(),
            // Must be valid base64 — used for HMAC-SHA256 signing
            api_secret: Secret::new("cHJvYmVfc2VjcmV0".to_string()),
            base_url: None,
        },
        ConnectorEnum::Worldpayvantiv => ConnectorSpecificConfig::Worldpayvantiv {
            user: u(),
            password: p(),
            merchant_id: m(),
            base_url: None,
            report_group: None,
            merchant_config_currency: None,
            secondary_base_url: None,
        },
        ConnectorEnum::Worldpayxml => ConnectorSpecificConfig::Worldpayxml {
            api_username: u(),
            api_password: p(),
            merchant_code: Secret::new("probe_merchant_code".to_string()),
            base_url: None,
        },
        ConnectorEnum::Zift => ConnectorSpecificConfig::Zift {
            user_name: u(),
            password: p(),
            account_id: id(),
            base_url: None,
        },
        ConnectorEnum::Paypal => ConnectorSpecificConfig::Paypal {
            client_id: id(),
            client_secret: s(),
            payer_id: None,
            base_url: None,
        },
        ConnectorEnum::Forte => ConnectorSpecificConfig::Forte {
            api_access_id: id(),
            organization_id: Secret::new("probe_org_id".to_string()),
            location_id: Secret::new("probe_loc_id".to_string()),
            api_secret_key: k(),
            base_url: None,
        },
        ConnectorEnum::Paybox => ConnectorSpecificConfig::Paybox {
            site: Secret::new("probe_site".to_string()),
            rank: Secret::new("probe_rank".to_string()),
            key: k(),
            merchant_id: m(),
            base_url: None,
        },
        ConnectorEnum::Paytm => ConnectorSpecificConfig::Paytm {
            merchant_id: m(),
            merchant_key: k(),
            website: Secret::new("probe_website".to_string()),
            client_id: None,
            base_url: None,
        },
        ConnectorEnum::Volt => ConnectorSpecificConfig::Volt {
            username: u(),
            password: p(),
            client_id: id(),
            client_secret: s(),
            base_url: None,
            secondary_base_url: None,
        },
        ConnectorEnum::Cashtocode => ConnectorSpecificConfig::Cashtocode {
            auth_key_map: HashMap::new(),
            base_url: None,
        },
        ConnectorEnum::Payload => ConnectorSpecificConfig::Payload {
            auth_key_map: HashMap::new(),
            base_url: None,
        },
        ConnectorEnum::Revolv3 => ConnectorSpecificConfig::Revolv3 {
            api_key: k(),
            base_url: None,
        },
        ConnectorEnum::Finix => ConnectorSpecificConfig::Finix {
            finix_user_name: u(),
            finix_password: p(),
            merchant_identity_id: id(),
            merchant_id: m(),
            base_url: None,
        },
    }
}

// ---------------------------------------------------------------------------
// Error parsing
// ---------------------------------------------------------------------------

fn parse_missing_field(msg: &str) -> Option<String> {
    // Match both "Missing required param: X" and "Missing required field: X"
    for needle in &["Missing required param: ", "Missing required field: "] {
        if let Some(pos) = msg.find(needle) {
            let rest = &msg[pos + needle.len()..];
            // Field name ends at " (" (parenthetical note) or newline
            let field = rest
                .split(" (")
                .next()
                .unwrap_or(rest)
                .lines()
                .next()
                .unwrap_or("")
                .trim()
                .to_string();
            if !field.is_empty() {
                return Some(field);
            }
        }
    }
    None
}

fn parse_missing_field_alt(msg: &str) -> Option<String> {
    if msg.contains("Amount is required") || msg.contains("MISSING_AMOUNT") {
        return Some("amount".to_string());
    }
    if msg.contains("Payment method data is required")
        || msg.contains("INVALID_PAYMENT_METHOD_DATA")
    {
        return Some("payment_method".to_string());
    }
    // Wallet token is missing — connectors that require a prior PaymentMethodToken flow
    // (e.g. Stripe Apple Pay) report this as InvalidWalletToken rather than a missing field.
    // Patching payment_method_token lets the probe proceed and produce a wire sample.
    if msg.contains("Failed to parse") && msg.contains("wallet token") {
        return Some("payment_method_token".to_string());
    }
    // Cybersource and similar connectors fail with "Invalid Configuration" when
    // connector_feature_data (metadata) is missing or cannot be parsed.
    if msg.contains("Invalid Configuration") && msg.contains("metadata") {
        return Some("connector_feature_data".to_string());
    }
    None
}

/// Returns true when the error message clearly signals the connector does not support
/// this payment method / flow combination.  These should be recorded as
/// `not_supported` rather than `error`.
fn is_pm_not_supported(msg: &str) -> bool {
    let lower = msg.to_lowercase();
    lower.contains("not been implemented")
        || lower.contains("not supported")
        || lower.contains("not configured with the given connector")
        || lower.contains("only card payment")
        || lower.contains("only interac")
        || lower.contains("only upi")
        || lower.contains("payment method not supported")
        || lower.contains("does not support this payment")
        // Generic BadRequest with no missing-field information means the connector
        // rejected the PM type entirely (e.g. SamsungPay returned BadRequest on all connectors).
        || lower == "integration error: badrequest"
}

/// Returns true when this connector requires an OAuth access token (prior CreateAccessToken step).
fn is_oauth_connector(connector: &ConnectorEnum) -> bool {
    let config = get_config();
    let name = format!("{connector:?}").to_lowercase();
    config.oauth_connectors.iter().any(|c| c.name == name)
}

// ---------------------------------------------------------------------------
// Request patching — map field_name → proto field setter
// ---------------------------------------------------------------------------

fn patch_authorize_request(req: &mut PaymentServiceAuthorizeRequest, field_name: &str) {
    match field_name {
        "amount" => req.amount = Some(usd_money(1000)),
        "payment_method" => req.payment_method = Some(card_payment_method()),
        "capture_method" => req.capture_method = Some(CaptureMethod::Automatic as i32),
        "return_url" | "router_return_url" => {
            req.return_url = Some("https://example.com/return".to_string());
        }
        "webhook_url" => req.webhook_url = Some("https://example.com/webhook".to_string()),
        "complete_authorize_url" => {
            req.complete_authorize_url = Some("https://example.com/complete".to_string());
        }
        "browser_info"
        | "browser_info.accept_header"
        | "browser_info.user_agent"
        | "browser_info.ip_address"
        | "browser_info.language"
        | "browser_info.java_script_enabled"
        | "ip_address" => {
            req.browser_info = Some(full_browser_info());
        }
        "billing_address"
        | "billing_address.country"
        | "billing_address.email"
        | "billing_address.first_name"
        | "billing_address.last_name"
        | "billing_address.city"
        | "billing_address.zip"
        | "billing_address.state"
        | "billing_address.line1"
        | "billing_address.phone" => {
            if let Some(ref mut addr) = req.address {
                addr.billing_address = Some(full_address());
            } else {
                req.address = Some(PaymentAddress {
                    billing_address: Some(full_address()),
                    shipping_address: None,
                });
            }
        }
        "shipping.address"
        | "shipping_address"
        | "shipping_address.country"
        | "shipping_address.first_name"
        | "shipping_address.last_name" => {
            if let Some(ref mut addr) = req.address {
                addr.shipping_address = Some(full_address());
            } else {
                req.address = Some(PaymentAddress {
                    billing_address: None,
                    shipping_address: Some(full_address()),
                });
            }
        }
        "address" => {
            req.address = Some(PaymentAddress {
                billing_address: Some(full_address()),
                shipping_address: Some(full_address()),
            });
        }
        "email" | "billing_email" | "customer.email" => {
            if req.customer.is_none() {
                req.customer = Some(full_customer());
            }
        }
        "customer" => req.customer = Some(full_customer()),
        "billing_name" | "card_holder_name" | "payment_method_data.card.card_holder_name" => {
            if let Some(ref mut pm) = req.payment_method {
                if let Some(PmVariant::Card(ref mut card)) = pm.payment_method {
                    card.card_holder_name = Some(Secret::new("John Doe".to_string()));
                }
            }
        }
        // Connector needs the encrypted Google Pay token format (e.g. Stripe).
        // First attempt uses DecryptedData; when that raises "gpay wallet_token"
        // it means the connector calls get_encrypted_google_pay_token(), so switch
        // to EncryptedData with a token JSON that has an `id` field.
        "gpay wallet_token" => {
            req.payment_method = Some(google_pay_encrypted_method());
        }
        "online" | "online.ip_address" => {
            req.browser_info = Some(full_browser_info());
        }
        "order_details" => {
            req.order_details = vec![grpc_api_types::payments::OrderDetailsWithAmount {
                product_name: "Test Product".to_string(),
                quantity: 1,
                amount: 1000,
                ..Default::default()
            }];
        }
        "merchant_order_id" | "reference_id" => {
            req.merchant_order_id = Some("probe_order_001".to_string());
        }
        "setup_future_usage" => {
            req.setup_future_usage = Some(proto::FutureUsage::OffSession as i32);
        }
        "description" => {
            req.description = Some("Probe payment".to_string());
        }
        "statement_descriptor_name" | "statement_descriptor" => {
            req.statement_descriptor_name = Some("Probe".to_string());
        }
        // Connectors that read an order/session reference from metadata
        "connector_request_id" | "connector_metadata" | "connector_meta_data" => {
            req.metadata = Some(Secret::new(
                r#"{"reference_id":"probe_ref_001","connector_request_id":"probe_req_001"}"#
                    .to_string(),
            ));
        }
        // A stored payment method token (e.g. from PaymentMethodToken flow)
        "payment_method_token" => {
            req.payment_method_token = Some(Secret::new("probe_pm_token".to_string()));
        }
        // Session-based connectors: Cashfree uses reference_id (from merchant_order_id)
        // as the payment_session_id set by a prior CreateOrder step.
        "payment_session_id" => {
            req.merchant_order_id = Some("probe_session_id".to_string());
        }
        // session_token and payment_handle_token come from prior multi-step flows
        // (CreateSessionToken / CreatePaymentHandle) and are propagated via
        // resource_common_data which is NOT populated from proto authorize fields in the
        // current domain layer.  Setting payment_method_token is the best we can do.
        "session_token" | "payment_handle_token" => {
            req.payment_method_token = Some(Secret::new("probe_session_token".to_string()));
        }
        // Connectors that require the Apple Pay encrypted token path (e.g. Nexinets, Novalnet).
        // The probe normally sends DecryptedData; switch to EncryptedData so the transformer
        // can build the request it expects.
        "Apple pay encrypted data" => {
            req.payment_method = Some(apple_pay_encrypted_method());
        }
        // order_category is a direct proto field (field 18 in PaymentServiceAuthorizeRequest).
        "order_category" => {
            req.order_category = Some("mobile".to_string());
        }
        "order_id" => {
            req.merchant_order_id = Some("probe_order_001".to_string());
        }
        // customer_id in the domain layer reads from customer.connector_customer_id
        // (not customer.id), so set the connector_customer_id field.
        "customer_id" | "customer.id" => match req.customer {
            Some(ref mut c) => {
                c.connector_customer_id = Some("probe_cust_connector_001".to_string())
            }
            None => {
                let mut c = full_customer();
                c.connector_customer_id = Some("probe_cust_connector_001".to_string());
                req.customer = Some(c);
            }
        },
        "customer_name" => {
            if req.customer.is_none() {
                req.customer = Some(full_customer());
            }
        }
        // Ideal bank name — needed by ACI and some other bank-redirect connectors.
        // BankNames::Ing = 29 in the proto enum.
        "ideal.bank_name" => {
            if let Some(ref mut pm) = req.payment_method {
                if let Some(PmVariant::Ideal(ref mut ideal)) = pm.payment_method {
                    ideal.bank_name = Some(proto::BankNames::Ing as i32);
                }
            }
        }
        // Connectors that require a cached access token in the request state (e.g. TrustPay).
        "access_token" => {
            if req.state.is_none() {
                req.state = Some(mock_connector_state());
            }
        }
        // 3DS authentication data for connectors that require it (e.g. NexixPay).
        // connector_transaction_id (field 8) maps to domain's transaction_id (operationId).
        "authentication_data" | "authentication_data.transaction_id" => {
            req.auth_type = proto::AuthenticationType::ThreeDs as i32;
            req.authentication_data = Some(proto::AuthenticationData {
                eci: Some("05".to_string()),
                cavv: Some("AAAAAA==".to_string()),
                threeds_server_transaction_id: Some("probe_3ds_txn_id".to_string()),
                message_version: Some("2.1.0".to_string()),
                ds_transaction_id: Some("probe_ds_txn_id".to_string()),
                acs_transaction_id: Some("probe_acs_txn_id".to_string()),
                connector_transaction_id: Some("probe_connector_txn_id".to_string()),
                ..Default::default()
            });
        }
        // amount/currency asked as top-level fields (already set, but re-set to be safe)
        "Amount" | "currency" => {
            req.amount = Some(usd_money(1000));
        }
        // Cybersource and similar connectors need connector_feature_data (metadata)
        // Provide empty JSON object as default
        "connector_feature_data" => {
            req.connector_feature_data = Some(Secret::new("{}".to_string()));
        }
        _ => {}
    }
}

fn patch_capture_request(req: &mut PaymentServiceCaptureRequest, field_name: &str) {
    match field_name {
        "amount" => req.amount_to_capture = Some(usd_money(1000)),
        "currency" => req.amount_to_capture = Some(usd_money(1000)),
        // Capture request doesn't have a top-level description — store in metadata.
        "description" => {
            req.metadata = Some(Secret::new(
                r#"{"description":"Probe payment","reference_id":"probe_ref_001"}"#.to_string(),
            ));
        }
        "browser_info" | "browser_info.ip_address" | "ip_address" => {
            req.browser_info = Some(full_browser_info());
        }
        "connector_meta_data"
        | "connector_metadata"
        | "connector_request_id"
        | "connector_transaction_id" => {
            req.metadata = Some(Secret::new(
                r#"{"reference_id":"probe_ref_001","connector_request_id":"probe_req_001","transaction_id":"probe_txn_001"}"#
                    .to_string(),
            ));
        }
        "connector_feature_data" => {
            req.connector_feature_data = Some(Secret::new("{}".to_string()));
        }
        _ => {}
    }
}

fn patch_refund_request(req: &mut PaymentServiceRefundRequest, field_name: &str) {
    match field_name {
        "amount" => req.refund_amount = Some(usd_money(1000)),
        "currency" => req.refund_amount = Some(usd_money(1000)),
        "webhook_url" => {
            req.webhook_url = Some("https://example.com/webhook".to_string());
        }
        "description" => {
            req.reason = Some("customer_request".to_string());
        }
        "customer_id" => {
            req.customer_id = Some("probe_customer_001".to_string());
        }
        "connector_meta_data" | "connector_metadata" => {
            req.metadata = Some(Secret::new(
                r#"{"reference_id":"probe_ref_001","connector_request_id":"probe_req_001","transaction_id":"probe_txn_001"}"#
                    .to_string(),
            ));
        }
        "connector_feature_data" => {
            req.connector_feature_data = Some(Secret::new("{}".to_string()));
        }
        _ => {}
    }
}

fn patch_get_request(req: &mut PaymentServiceGetRequest, field_name: &str) {
    match field_name {
        "reference_id" | "connector_order_reference_id" => {
            req.connector_order_reference_id = Some("probe_order_ref_001".to_string());
        }
        "connector_meta_data" | "connector_metadata" | "connector_request_id" => {
            req.metadata = Some(Secret::new(
                r#"{"reference_id":"probe_ref_001","connector_request_id":"probe_req_001","transaction_id":"probe_txn_001"}"#
                    .to_string(),
            ));
        }
        "connector_feature_data" => {
            req.connector_feature_data = Some(Secret::new("{}".to_string()));
        }
        _ => {}
    }
}

fn patch_void_request(req: &mut PaymentServiceVoidRequest, field_name: &str) {
    match field_name {
        "amount" | "Amount" | "amount for void operation" => {
            req.amount = Some(usd_money(1000));
        }
        "currency" => {
            req.amount = Some(usd_money(1000));
        }
        "browser_info" | "browser_info.ip_address" => {
            req.browser_info = Some(full_browser_info());
        }
        "cancellation_reason" | "Cancellation Reason" => {
            req.cancellation_reason = Some("requested_by_customer".to_string());
        }
        "connector_meta_data" | "connector_metadata" | "connector_request_id" => {
            req.metadata = Some(Secret::new(
                r#"{"reference_id":"probe_ref_001","connector_request_id":"probe_req_001","transaction_id":"probe_txn_001"}"#
                    .to_string(),
            ));
        }
        "connector_feature_data" => {
            req.connector_feature_data = Some(Secret::new("{}".to_string()));
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Capture sample payload from a connector Request
// ---------------------------------------------------------------------------

fn extract_sample(req: &common_utils::request::Request) -> SamplePayload {
    use hyperswitch_masking::ExposeInterface;
    let method = format!("{:?}", req.method);
    let headers = req.get_headers_map();
    let body = req.body.as_ref().map(|b| b.get_inner_value().expose());

    SamplePayload {
        url: req.url.clone(),
        method,
        headers,
        body,
    }
}

// ---------------------------------------------------------------------------
// Core probe logic
// ---------------------------------------------------------------------------

type PciFfi = domain_types::payment_method_data::DefaultPCIHolder;

fn run_probe<Req, F>(mut req: Req, mut call: F, mut patch: impl FnMut(&mut Req, &str)) -> FlowResult
where
    Req: Clone + Serialize,
    F: FnMut(
        Req,
    ) -> Result<
        Option<common_utils::request::Request>,
        grpc_api_types::payments::RequestError,
    >,
{
    let mut required_fields: Vec<String> = Vec::new();
    let mut seen_fields: HashSet<String> = HashSet::new();

    for _i in 0..max_iterations() {
        match call(req.clone()) {
            Ok(Some(connector_req)) => {
                // If the connector returned a request with no URL, treat it as not_supported.
                // This happens when ConnectorIntegrationV2 is implemented as an empty default
                // impl (no get_url override), so the default build_request_v2 produces a
                // Request with an empty URL string.
                if connector_req.url.is_empty() {
                    return FlowResult {
                        status: "not_supported".to_string(),
                        required_fields,
                        proto_request: None,
                        sample: None,
                        error: None,
                        service_rpc: None,
                        description: None,
                    };
                }

                // Convert Rust serde JSON to proper proto JSON format, then clean it
                let proto_json = serde_json::to_value(&req)
                    .ok()
                    .map(|v| convert_rust_to_proto_json(&v))
                    .map(|v| clean_proto_request(&v));
                return FlowResult {
                    status: "supported".to_string(),
                    required_fields,
                    proto_request: proto_json,
                    sample: Some(extract_sample(&connector_req)),
                    error: None,
                    service_rpc: None,
                    description: None,
                };
            }
            Ok(None) => {
                return FlowResult {
                    status: "not_supported".to_string(),
                    required_fields,
                    proto_request: None,
                    sample: None,
                    error: None,
                    service_rpc: None,
                    description: None,
                };
            }
            Err(ref e) => {
                let msg = e.error_message.as_deref().unwrap_or("");
                if is_pm_not_supported(msg) {
                    return FlowResult {
                        status: "not_supported".to_string(),
                        required_fields,
                        proto_request: None,
                        sample: None,
                        error: None,
                        service_rpc: None,
                        description: None,
                    };
                } else if let Some(field) =
                    parse_missing_field(msg).or_else(|| parse_missing_field_alt(msg))
                {
                    if seen_fields.contains(&field) {
                        return FlowResult {
                            status: "error".to_string(),
                            required_fields,
                            proto_request: None,
                            sample: None,
                            error: Some(format!("Stuck on field: {field} — {msg}")),
                            service_rpc: None,
                            description: None,
                        };
                    }
                    seen_fields.insert(field.clone());
                    required_fields.push(field.clone());
                    patch(&mut req, &field);
                } else {
                    return FlowResult {
                        status: "error".to_string(),
                        required_fields,
                        proto_request: None,
                        sample: None,
                        error: Some(msg.to_string()),
                        service_rpc: None,
                        description: None,
                    };
                }
            }
        }
    }

    FlowResult {
        status: "error".to_string(),
        required_fields,
        proto_request: None,
        sample: None,
        error: Some("Max iterations reached".to_string()),
        service_rpc: None,
        description: None,
    }
}

fn probe_capture(
    connector: &ConnectorEnum,
    config: &Arc<ucs_env::configs::Config>,
    auth: ConnectorSpecificConfig,
    metadata: &MaskedMetadata,
) -> FlowResult {
    let mut req = base_capture_request();
    if is_oauth_connector(connector) {
        req.state = Some(mock_connector_state());
    }
    if let Some(meta) = connector_feature_data_json(connector) {
        req.connector_feature_data = Some(Secret::new(meta));
    }
    run_probe(
        req,
        |req| {
            ffi::services::payments::capture_req_transformer::<PciFfi>(
                req,
                config,
                connector.clone(),
                auth.clone(),
                metadata,
            )
        },
        patch_capture_request,
    )
}

fn probe_refund(
    connector: &ConnectorEnum,
    config: &Arc<ucs_env::configs::Config>,
    auth: ConnectorSpecificConfig,
    metadata: &MaskedMetadata,
) -> FlowResult {
    let mut req = base_refund_request();
    if is_oauth_connector(connector) {
        req.state = Some(mock_connector_state());
    }
    if let Some(meta) = connector_feature_data_json(connector) {
        req.connector_feature_data = Some(Secret::new(meta));
    }
    run_probe(
        req,
        |req| {
            ffi::services::payments::refund_req_transformer::<PciFfi>(
                req,
                config,
                connector.clone(),
                auth.clone(),
                metadata,
            )
        },
        patch_refund_request,
    )
}

fn probe_void(
    connector: &ConnectorEnum,
    config: &Arc<ucs_env::configs::Config>,
    auth: ConnectorSpecificConfig,
    metadata: &MaskedMetadata,
) -> FlowResult {
    let mut req = base_void_request();
    if is_oauth_connector(connector) {
        req.state = Some(mock_connector_state());
    }
    if let Some(meta) = connector_feature_data_json(connector) {
        req.connector_feature_data = Some(Secret::new(meta));
    }
    run_probe(
        req,
        |req| {
            ffi::services::payments::void_req_transformer::<PciFfi>(
                req,
                config,
                connector.clone(),
                auth.clone(),
                metadata,
            )
        },
        patch_void_request,
    )
}

fn probe_get(
    connector: &ConnectorEnum,
    config: &Arc<ucs_env::configs::Config>,
    auth: ConnectorSpecificConfig,
    metadata: &MaskedMetadata,
) -> FlowResult {
    let mut req = base_get_request();
    if is_oauth_connector(connector) {
        req.state = Some(mock_connector_state());
    }
    if let Some(meta) = connector_feature_data_json(connector) {
        req.connector_feature_data = Some(Secret::new(meta));
    }
    run_probe(
        req,
        |req| {
            ffi::services::payments::get_req_transformer::<PciFfi>(
                req,
                config,
                connector.clone(),
                auth.clone(),
                metadata,
            )
        },
        patch_get_request,
    )
}

fn probe_reverse(
    connector: &ConnectorEnum,
    config: &Arc<ucs_env::configs::Config>,
    auth: ConnectorSpecificConfig,
    metadata: &MaskedMetadata,
) -> FlowResult {
    let mut req = base_reverse_request();
    if let Some(meta) = connector_feature_data_json(connector) {
        req.connector_feature_data = Some(Secret::new(meta));
    }
    run_probe(
        req,
        |req| {
            ffi::services::payments::reverse_req_transformer::<PciFfi>(
                req,
                config,
                connector.clone(),
                auth.clone(),
                metadata,
            )
        },
        |_, _| {},
    )
}

fn probe_create_order(
    connector: &ConnectorEnum,
    config: &Arc<ucs_env::configs::Config>,
    auth: ConnectorSpecificConfig,
    metadata: &MaskedMetadata,
) -> FlowResult {
    let mut req = base_create_order_request();
    if is_oauth_connector(connector) {
        req.state = Some(mock_connector_state());
    }
    if let Some(meta) = connector_feature_data_json(connector) {
        req.connector_feature_data = Some(Secret::new(meta));
    }
    run_probe(
        req,
        |req| {
            ffi::services::payments::create_order_req_transformer::<PciFfi>(
                req,
                config,
                connector.clone(),
                auth.clone(),
                metadata,
            )
        },
        |_, _| {},
    )
}

fn patch_setup_recurring_request(req: &mut PaymentServiceSetupRecurringRequest, field_name: &str) {
    match field_name {
        // Cybersource and similar connectors read `request.metadata` for connector-specific
        // configuration (e.g. disable_avs, disable_cvn). Provide an empty JSON object so the
        // parse succeeds when no specific values are needed.
        "connector_feature_data" | "connector_meta_data" => {
            if req.metadata.is_none() {
                req.metadata = Some(Secret::new("{}".to_string()));
            }
        }
        _ => {}
    }
}

fn probe_setup_recurring(
    connector: &ConnectorEnum,
    config: &Arc<ucs_env::configs::Config>,
    auth: ConnectorSpecificConfig,
    metadata: &MaskedMetadata,
) -> FlowResult {
    let mut req = base_setup_recurring_request();
    if is_oauth_connector(connector) {
        req.state = Some(mock_connector_state());
    }
    if let Some(meta) = connector_feature_data_json(connector) {
        req.connector_feature_data = Some(Secret::new(meta));
    }
    let result = run_probe(
        req,
        |req| {
            ffi::services::payments::setup_recurring_req_transformer::<PciFfi>(
                req,
                config,
                connector.clone(),
                auth.clone(),
                metadata,
            )
        },
        patch_setup_recurring_request,
    );
    // Debug: log setup_recurring result for Stripe
    if format!("{connector:?}").to_lowercase() == "stripe" && result.status != "supported" {
        eprintln!(
            "  DEBUG setup_recurring for {:?}: status={}, error={:?}",
            connector, result.status, result.error
        );
    }
    result
}

fn probe_recurring_charge(
    connector: &ConnectorEnum,
    config: &Arc<ucs_env::configs::Config>,
    auth: ConnectorSpecificConfig,
    metadata: &MaskedMetadata,
) -> FlowResult {
    let mut req = base_recurring_charge_request();
    if is_oauth_connector(connector) {
        req.state = Some(mock_connector_state());
    }
    if let Some(meta) = connector_feature_data_json(connector) {
        req.connector_feature_data = Some(Secret::new(meta));
    }
    run_probe(
        req,
        |req| {
            ffi::services::payments::charge_req_transformer::<PciFfi>(
                req,
                config,
                connector.clone(),
                auth.clone(),
                metadata,
            )
        },
        |_, _| {},
    )
}

fn probe_create_customer(
    connector: &ConnectorEnum,
    config: &Arc<ucs_env::configs::Config>,
    auth: ConnectorSpecificConfig,
    metadata: &MaskedMetadata,
) -> FlowResult {
    let mut req = base_create_customer_request();
    if let Some(meta) = connector_feature_data_json(connector) {
        req.connector_feature_data = Some(Secret::new(meta));
    }
    run_probe(
        req,
        |req| {
            ffi::services::payments::create_req_transformer::<PciFfi>(
                req,
                config,
                connector.clone(),
                auth.clone(),
                metadata,
            )
        },
        |_, _| {},
    )
}

fn probe_tokenize(
    connector: &ConnectorEnum,
    config: &Arc<ucs_env::configs::Config>,
    auth: ConnectorSpecificConfig,
    metadata: &MaskedMetadata,
) -> FlowResult {
    let mut req = base_tokenize_request();
    if let Some(meta) = connector_feature_data_json(connector) {
        req.connector_feature_data = Some(Secret::new(meta));
    }
    run_probe(
        req,
        |req| {
            ffi::services::payments::tokenize_req_transformer::<PciFfi>(
                req,
                config,
                connector.clone(),
                auth.clone(),
                metadata,
            )
        },
        |_, _| {},
    )
}

fn probe_create_access_token(
    connector: &ConnectorEnum,
    config: &Arc<ucs_env::configs::Config>,
    auth: ConnectorSpecificConfig,
    metadata: &MaskedMetadata,
) -> FlowResult {
    let req = base_create_access_token_request();
    run_probe(
        req,
        |req| {
            ffi::services::payments::create_access_token_req_transformer::<PciFfi>(
                req,
                config,
                connector.clone(),
                auth.clone(),
                metadata,
            )
        },
        |_, _| {},
    )
}

fn probe_create_session_token(
    connector: &ConnectorEnum,
    config: &Arc<ucs_env::configs::Config>,
    auth: ConnectorSpecificConfig,
    metadata: &MaskedMetadata,
) -> FlowResult {
    let mut req = base_create_session_token_request();
    if let Some(meta) = connector_feature_data_json(connector) {
        req.connector_feature_data = Some(Secret::new(meta));
    }
    run_probe(
        req,
        |req| {
            ffi::services::payments::create_session_token_req_transformer::<PciFfi>(
                req,
                config,
                connector.clone(),
                auth.clone(),
                metadata,
            )
        },
        |_, _| {},
    )
}

fn probe_pre_authenticate(
    connector: &ConnectorEnum,
    config: &Arc<ucs_env::configs::Config>,
    auth: ConnectorSpecificConfig,
    metadata: &MaskedMetadata,
) -> FlowResult {
    let mut req = base_pre_authenticate_request();
    if is_oauth_connector(connector) {
        req.state = Some(mock_connector_state());
    }
    if let Some(meta) = connector_feature_data_json(connector) {
        req.connector_feature_data = Some(Secret::new(meta));
    }
    run_probe(
        req,
        |req| {
            ffi::services::payments::pre_authenticate_req_transformer::<PciFfi>(
                req,
                config,
                connector.clone(),
                auth.clone(),
                metadata,
            )
        },
        |_, _| {},
    )
}

fn probe_authenticate(
    connector: &ConnectorEnum,
    config: &Arc<ucs_env::configs::Config>,
    auth: ConnectorSpecificConfig,
    metadata: &MaskedMetadata,
) -> FlowResult {
    let mut req = base_authenticate_request();
    if is_oauth_connector(connector) {
        req.state = Some(mock_connector_state());
    }
    if let Some(meta) = connector_feature_data_json(connector) {
        req.connector_feature_data = Some(Secret::new(meta));
    }
    run_probe(
        req,
        |req| {
            ffi::services::payments::authenticate_req_transformer::<PciFfi>(
                req,
                config,
                connector.clone(),
                auth.clone(),
                metadata,
            )
        },
        |_, _| {},
    )
}

fn probe_post_authenticate(
    connector: &ConnectorEnum,
    config: &Arc<ucs_env::configs::Config>,
    auth: ConnectorSpecificConfig,
    metadata: &MaskedMetadata,
) -> FlowResult {
    let mut req = base_post_authenticate_request();
    if is_oauth_connector(connector) {
        req.state = Some(mock_connector_state());
    }
    if let Some(meta) = connector_feature_data_json(connector) {
        req.connector_feature_data = Some(Secret::new(meta));
    }
    run_probe(
        req,
        |req| {
            ffi::services::payments::post_authenticate_req_transformer::<PciFfi>(
                req,
                config,
                connector.clone(),
                auth.clone(),
                metadata,
            )
        },
        |_, _| {},
    )
}

/// Get connector-specific metadata JSON for connectors that require it
fn connector_feature_data_json(connector: &ConnectorEnum) -> Option<String> {
    let config = get_config();
    let name = format!("{connector:?}").to_lowercase();

    // First check if config has metadata for this connector
    if let Some(meta) = config.connector_metadata.get(&name) {
        return Some(meta.clone());
    }

    // Fall back to default if available
    config.connector_metadata.get("default").cloned()
}

// ---------------------------------------------------------------------------
// Doc-format overrides for wallet payment methods
// ---------------------------------------------------------------------------
//
// The probe uses internal workaround formats (pre-decrypted Apple Pay data,
// fake Stripe GPay tokens) to make probe runs succeed, but users integrating
// the SDK always receive ENCRYPTED tokens from the device wallets. These
// functions return the correct real-world `payment_method` JSON that should
// appear in the published documentation proto_request.

fn doc_payment_method_override(pm_name: &str) -> Option<serde_json::Value> {
    // Produce the correct proto3 JSON format for wallet payment methods.
    // In proto3 JSON, oneof variants are inlined at the containing-message level
    // (no extra wrapper with the oneof field name). So the value stored in
    // proto_req["payment_method"] should already be the variant, not
    // {"payment_method": {"apple_pay": {...}}}.
    match pm_name {
        "ApplePay" => Some(serde_json::json!({
            // payment_data is inlined — no "payment_data" oneof wrapper
            "apple_pay": {
                "payment_data": {
                    "encrypted_data": "<base64_encoded_apple_pay_payment_token>"
                },
                "payment_method": {
                    "display_name": "Visa 1111",
                    "network": "Visa",
                    "type": "debit"
                },
                "transaction_identifier": "<apple_pay_transaction_identifier>"
            }
        })),
        "GooglePay" => Some(serde_json::json!({
            // tokenization_data is inlined — no "tokenization_data" oneof wrapper.
            // "token" is the full JSON string returned by the Google Pay API.
            "google_pay": {
                "type": "CARD",
                "description": "Visa 1111",
                "info": {
                    "card_network": "VISA",
                    "card_details": "1111"
                },
                "tokenization_data": {
                    "encrypted_data": {
                        "token": "{\"version\":\"ECv2\",\"signature\":\"<sig>\",\"intermediateSigningKey\":{\"signedKey\":\"<signed_key>\",\"signatures\":[\"<sig>\"]},\"signedMessage\":\"<signed_message>\"}",
                        "token_type": "PAYMENT_GATEWAY"
                    }
                }
            }
        })),
        _ => None,
    }
}

/// Authorize probe — handles a single PM type
fn probe_authorize(
    connector: &ConnectorEnum,
    pm_name: &str,
    pm: PaymentMethod,
    config: &Arc<ucs_env::configs::Config>,
    auth: ConnectorSpecificConfig,
    metadata: &MaskedMetadata,
) -> FlowResult {
    // Pre-populate connector_feature_data for connectors that require it
    let connector_meta = connector_feature_data_json(connector);

    // Check if this is an OAuth connector that needs a cached access token
    let is_oauth = get_config().is_oauth_connector(connector);

    let mut result = if is_oauth {
        run_probe(
            base_authorize_request_with_state(pm, connector_meta, mock_connector_state()),
            |req| {
                ffi::services::payments::authorize_req_transformer::<PciFfi>(
                    req,
                    config,
                    connector.clone(),
                    auth.clone(),
                    metadata,
                )
            },
            patch_authorize_request,
        )
    } else {
        run_probe(
            base_authorize_request_with_meta(pm, connector_meta),
            |req| {
                ffi::services::payments::authorize_req_transformer::<PciFfi>(
                    req,
                    config,
                    connector.clone(),
                    auth.clone(),
                    metadata,
                )
            },
            patch_authorize_request,
        )
    };

    // For wallet PM types the probe uses internal workaround formats (decrypted
    // Apple Pay data, connector-specific fake GPay tokens) that users would never
    // send in production. Replace the payment_method part of the proto_request with
    // the correct real-world encrypted format so the published docs are accurate.
    if result.status == "supported" {
        if let Some(doc_pm) = doc_payment_method_override(pm_name) {
            if let Some(ref mut proto_req) = result.proto_request {
                proto_req["payment_method"] = doc_pm;
            }
        }
    }

    result
}

// ---------------------------------------------------------------------------
// Payment method types to probe for authorize
// ---------------------------------------------------------------------------

fn authorize_pm_variants() -> Vec<(&'static str, fn() -> PaymentMethod)> {
    vec![
        ("Card", card_payment_method as fn() -> PaymentMethod),
        ("Sepa", sepa_payment_method as fn() -> PaymentMethod),
        ("Bacs", bacs_payment_method as fn() -> PaymentMethod),
        ("Ach", ach_payment_method as fn() -> PaymentMethod),
        ("Becs", becs_payment_method as fn() -> PaymentMethod),
        ("GooglePay", google_pay_method as fn() -> PaymentMethod),
        ("ApplePay", apple_pay_method as fn() -> PaymentMethod),
        ("Ideal", ideal_payment_method as fn() -> PaymentMethod),
        (
            "PaypalRedirect",
            paypal_redirect_method as fn() -> PaymentMethod,
        ),
        ("Blik", blik_payment_method as fn() -> PaymentMethod),
        ("Klarna", klarna_payment_method as fn() -> PaymentMethod),
        ("Afterpay", afterpay_payment_method as fn() -> PaymentMethod),
        (
            "UpiCollect",
            upi_collect_payment_method as fn() -> PaymentMethod,
        ),
        ("Affirm", affirm_payment_method as fn() -> PaymentMethod),
        (
            "SamsungPay",
            samsung_pay_payment_method as fn() -> PaymentMethod,
        ),
    ]
}

/// Static variant for config filtering (same as authorize_pm_variants but usable at config load time)
fn authorize_pm_variants_static() -> Vec<(&'static str, fn() -> PaymentMethod)> {
    authorize_pm_variants()
}

/// Build a mock ConnectorState with an access token for OAuth connectors.
fn mock_connector_state() -> proto::ConnectorState {
    let config = get_config();
    proto::ConnectorState {
        access_token: Some(proto::AccessToken {
            token: Some(Secret::new(config.access_token.token.clone())),
            token_type: Some(config.access_token.token_type.clone()),
            expires_in_seconds: Some(config.access_token.expires_in_seconds),
        }),
        connector_customer_id: None,
    }
}

// ---------------------------------------------------------------------------
// All connectors list
// ---------------------------------------------------------------------------

fn all_connectors() -> Vec<ConnectorEnum> {
    vec![
        ConnectorEnum::Adyen,
        ConnectorEnum::Forte,
        ConnectorEnum::Razorpay,
        ConnectorEnum::RazorpayV2,
        ConnectorEnum::Fiserv,
        ConnectorEnum::Elavon,
        ConnectorEnum::Xendit,
        ConnectorEnum::Checkout,
        ConnectorEnum::Authorizedotnet,
        ConnectorEnum::Bamboraapac,
        ConnectorEnum::Mifinity,
        ConnectorEnum::Phonepe,
        ConnectorEnum::Cashfree,
        ConnectorEnum::Paytm,
        ConnectorEnum::Fiuu,
        ConnectorEnum::Payu,
        ConnectorEnum::Cashtocode,
        ConnectorEnum::Novalnet,
        ConnectorEnum::Nexinets,
        ConnectorEnum::Noon,
        ConnectorEnum::Braintree,
        ConnectorEnum::Volt,
        ConnectorEnum::Calida,
        ConnectorEnum::Cryptopay,
        ConnectorEnum::Helcim,
        ConnectorEnum::Dlocal,
        ConnectorEnum::Placetopay,
        ConnectorEnum::Rapyd,
        ConnectorEnum::Aci,
        ConnectorEnum::Trustpay,
        ConnectorEnum::Stripe,
        ConnectorEnum::Cybersource,
        ConnectorEnum::Worldpay,
        ConnectorEnum::Worldpayvantiv,
        ConnectorEnum::Worldpayxml,
        ConnectorEnum::Multisafepay,
        ConnectorEnum::Payload,
        ConnectorEnum::Fiservemea,
        ConnectorEnum::Paysafe,
        ConnectorEnum::Datatrans,
        ConnectorEnum::Bluesnap,
        ConnectorEnum::Authipay,
        ConnectorEnum::Silverflow,
        ConnectorEnum::Celero,
        ConnectorEnum::Paypal,
        ConnectorEnum::Stax,
        ConnectorEnum::Billwerk,
        ConnectorEnum::Hipay,
        ConnectorEnum::Trustpayments,
        ConnectorEnum::Redsys,
        ConnectorEnum::Globalpay,
        ConnectorEnum::Nuvei,
        ConnectorEnum::Iatapay,
        ConnectorEnum::Nmi,
        ConnectorEnum::Shift4,
        ConnectorEnum::Paybox,
        ConnectorEnum::Barclaycard,
        ConnectorEnum::Nexixpay,
        ConnectorEnum::Mollie,
        ConnectorEnum::Airwallex,
        ConnectorEnum::Tsys,
        ConnectorEnum::Bankofamerica,
        ConnectorEnum::Powertranz,
        ConnectorEnum::Getnet,
        ConnectorEnum::Jpmorgan,
        ConnectorEnum::Bambora,
        ConnectorEnum::Payme,
        ConnectorEnum::Revolut,
        ConnectorEnum::Gigadat,
        ConnectorEnum::Loonio,
        ConnectorEnum::Wellsfargo,
        ConnectorEnum::Hyperpg,
        ConnectorEnum::Zift,
        ConnectorEnum::Revolv3,
        ConnectorEnum::Truelayer,
        ConnectorEnum::Finix,
    ]
}

// ---------------------------------------------------------------------------
// Dispute base requests
// ---------------------------------------------------------------------------

fn base_accept_dispute_request() -> DisputeServiceAcceptRequest {
    DisputeServiceAcceptRequest {
        merchant_dispute_id: Some("probe_dispute_001".to_string()),
        connector_transaction_id: "probe_txn_001".to_string(),
        dispute_id: "probe_dispute_id_001".to_string(),
    }
}

fn base_submit_evidence_request() -> DisputeServiceSubmitEvidenceRequest {
    DisputeServiceSubmitEvidenceRequest {
        merchant_dispute_id: Some("probe_dispute_001".to_string()),
        connector_transaction_id: Some("probe_txn_001".to_string()),
        dispute_id: "probe_dispute_id_001".to_string(),
        evidence_documents: vec![EvidenceDocument {
            evidence_type: EvidenceType::ServiceDocumentation as i32,
            file_content: Some(b"probe evidence content".to_vec()),
            file_mime_type: Some("application/pdf".to_string()),
            provider_file_id: None,
            text_content: None,
        }],
        ..Default::default()
    }
}

fn base_defend_dispute_request() -> DisputeServiceDefendRequest {
    DisputeServiceDefendRequest {
        merchant_dispute_id: Some("probe_dispute_001".to_string()),
        connector_transaction_id: "probe_txn_001".to_string(),
        dispute_id: "probe_dispute_id_001".to_string(),
        reason_code: Some("probe_reason".to_string()),
    }
}

fn patch_accept_dispute_request(_req: &mut DisputeServiceAcceptRequest, _field_name: &str) {}

fn patch_submit_evidence_request(
    _req: &mut DisputeServiceSubmitEvidenceRequest,
    _field_name: &str,
) {
}

fn patch_defend_dispute_request(_req: &mut DisputeServiceDefendRequest, _field_name: &str) {}

fn probe_accept_dispute(
    connector: &ConnectorEnum,
    config: &Arc<ucs_env::configs::Config>,
    auth: ConnectorSpecificConfig,
    metadata: &MaskedMetadata,
) -> FlowResult {
    let req = base_accept_dispute_request();
    run_probe(
        req,
        |req| {
            ffi::services::payments::accept_req_transformer::<PciFfi>(
                req,
                config,
                connector.clone(),
                auth.clone(),
                metadata,
            )
        },
        patch_accept_dispute_request,
    )
}

fn probe_submit_evidence(
    connector: &ConnectorEnum,
    config: &Arc<ucs_env::configs::Config>,
    auth: ConnectorSpecificConfig,
    metadata: &MaskedMetadata,
) -> FlowResult {
    let req = base_submit_evidence_request();
    run_probe(
        req,
        |req| {
            ffi::services::payments::submit_evidence_req_transformer::<PciFfi>(
                req,
                config,
                connector.clone(),
                auth.clone(),
                metadata,
            )
        },
        patch_submit_evidence_request,
    )
}

fn probe_defend_dispute(
    connector: &ConnectorEnum,
    config: &Arc<ucs_env::configs::Config>,
    auth: ConnectorSpecificConfig,
    metadata: &MaskedMetadata,
) -> FlowResult {
    let req = base_defend_dispute_request();
    run_probe(
        req,
        |req| {
            ffi::services::payments::defend_req_transformer::<PciFfi>(
                req,
                config,
                connector.clone(),
                auth.clone(),
                metadata,
            )
        },
        patch_defend_dispute_request,
    )
}

// ---------------------------------------------------------------------------
// Probe one connector
// ---------------------------------------------------------------------------

fn probe_connector(connector: &ConnectorEnum) -> ConnectorResult {
    let name = format!("{connector:?}").to_lowercase();
    let config = load_config();
    let metadata = make_masked_metadata();
    // Use enabled payment methods from config
    let pm_variants = get_config().get_enabled_payment_methods();

    let mut flows: BTreeMap<String, BTreeMap<String, FlowResult>> = BTreeMap::new();

    // --- authorize ---
    let mut authorize_results: BTreeMap<String, FlowResult> = BTreeMap::new();
    for (pm_name, pm_fn) in &pm_variants {
        let auth = dummy_auth(connector);
        let result = probe_authorize(connector, pm_name, pm_fn(), &config, auth, &metadata);
        authorize_results.insert(pm_name.to_string(), result);
    }
    flows.insert("authorize".to_string(), authorize_results);

    // --- capture ---
    {
        let auth = dummy_auth(connector);
        let result = probe_capture(connector, &config, auth, &metadata);
        let mut m = BTreeMap::new();
        m.insert("default".to_string(), result);
        flows.insert("capture".to_string(), m);
    }

    // --- refund ---
    {
        let auth = dummy_auth(connector);
        let result = probe_refund(connector, &config, auth, &metadata);
        let mut m = BTreeMap::new();
        m.insert("default".to_string(), result);
        flows.insert("refund".to_string(), m);
    }

    // --- void ---
    {
        let auth = dummy_auth(connector);
        let result = probe_void(connector, &config, auth, &metadata);
        let mut m = BTreeMap::new();
        m.insert("default".to_string(), result);
        flows.insert("void".to_string(), m);
    }

    // --- get (psync) ---
    {
        let auth = dummy_auth(connector);
        let result = probe_get(connector, &config, auth, &metadata);
        let mut m = BTreeMap::new();
        m.insert("default".to_string(), result);
        flows.insert("get".to_string(), m);
    }

    // --- reverse (void post-capture) ---
    {
        let auth = dummy_auth(connector);
        let result = probe_reverse(connector, &config, auth, &metadata);
        let mut m = BTreeMap::new();
        m.insert("default".to_string(), result);
        flows.insert("reverse".to_string(), m);
    }

    // --- create_order ---
    {
        let auth = dummy_auth(connector);
        let result = probe_create_order(connector, &config, auth, &metadata);
        let mut m = BTreeMap::new();
        m.insert("default".to_string(), result);
        flows.insert("create_order".to_string(), m);
    }

    // --- setup_recurring ---
    {
        let auth = dummy_auth(connector);
        let result = probe_setup_recurring(connector, &config, auth, &metadata);
        let mut m = BTreeMap::new();
        m.insert("default".to_string(), result);
        flows.insert("setup_recurring".to_string(), m);
    }

    // --- recurring_charge ---
    {
        let auth = dummy_auth(connector);
        let result = probe_recurring_charge(connector, &config, auth, &metadata);
        let mut m = BTreeMap::new();
        m.insert("default".to_string(), result);
        flows.insert("recurring_charge".to_string(), m);
    }

    // --- create_customer ---
    {
        let auth = dummy_auth(connector);
        let result = probe_create_customer(connector, &config, auth, &metadata);
        let mut m = BTreeMap::new();
        m.insert("default".to_string(), result);
        flows.insert("create_customer".to_string(), m);
    }

    // --- tokenize ---
    {
        let auth = dummy_auth(connector);
        let result = probe_tokenize(connector, &config, auth, &metadata);
        let mut m = BTreeMap::new();
        m.insert("default".to_string(), result);
        flows.insert("tokenize".to_string(), m);
    }

    // --- create_access_token ---
    {
        let auth = dummy_auth(connector);
        let result = probe_create_access_token(connector, &config, auth, &metadata);
        let mut m = BTreeMap::new();
        m.insert("default".to_string(), result);
        flows.insert("create_access_token".to_string(), m);
    }

    // --- create_session_token ---
    {
        let auth = dummy_auth(connector);
        let result = probe_create_session_token(connector, &config, auth, &metadata);
        let mut m = BTreeMap::new();
        m.insert("default".to_string(), result);
        flows.insert("create_session_token".to_string(), m);
    }

    // --- pre_authenticate ---
    {
        let auth = dummy_auth(connector);
        let result = probe_pre_authenticate(connector, &config, auth, &metadata);
        let mut m = BTreeMap::new();
        m.insert("default".to_string(), result);
        flows.insert("pre_authenticate".to_string(), m);
    }

    // --- authenticate ---
    {
        let auth = dummy_auth(connector);
        let result = probe_authenticate(connector, &config, auth, &metadata);
        let mut m = BTreeMap::new();
        m.insert("default".to_string(), result);
        flows.insert("authenticate".to_string(), m);
    }

    // --- post_authenticate ---
    {
        let auth = dummy_auth(connector);
        let result = probe_post_authenticate(connector, &config, auth, &metadata);
        let mut m = BTreeMap::new();
        m.insert("default".to_string(), result);
        flows.insert("post_authenticate".to_string(), m);
    }

    // --- accept_dispute ---
    {
        let auth = dummy_auth(connector);
        let result = probe_accept_dispute(connector, &config, auth, &metadata);
        let mut m = BTreeMap::new();
        m.insert("default".to_string(), result);
        flows.insert("accept_dispute".to_string(), m);
    }

    // --- submit_evidence ---
    {
        let auth = dummy_auth(connector);
        let result = probe_submit_evidence(connector, &config, auth, &metadata);
        let mut m = BTreeMap::new();
        m.insert("default".to_string(), result);
        flows.insert("submit_evidence".to_string(), m);
    }

    // --- defend_dispute ---
    {
        let auth = dummy_auth(connector);
        let result = probe_defend_dispute(connector, &config, auth, &metadata);
        let mut m = BTreeMap::new();
        m.insert("default".to_string(), result);
        flows.insert("defend_dispute".to_string(), m);
    }

    ConnectorResult {
        connector: name,
        flows,
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() {
    // Load config first (initializes PROBE_CONFIG)
    let config = get_config();
    let skip_set: HashSet<String> = config
        .skip_connectors
        .iter()
        .map(|s| s.to_lowercase())
        .collect();

    let connectors: Vec<ConnectorEnum> = all_connectors()
        .into_iter()
        .filter(|c| {
            let name = format!("{c:?}").to_lowercase();
            !skip_set.contains(&name)
        })
        .collect();

    eprintln!(
        "Probing {} connectors ({} skipped)...",
        connectors.len(),
        skip_set.len()
    );

    // Generate flow metadata from services.proto
    eprintln!("Generating flow metadata from services.proto...");
    let flow_metadata = parse_services_proto();
    eprintln!("Generated {} flow metadata entries", flow_metadata.len());

    let results: Vec<ConnectorResult> = connectors
        .par_iter()
        .map(|c| {
            let name = format!("{c:?}");
            eprintln!("Probing {name}...");
            probe_connector(c)
        })
        .collect();

    // Determine output directory
    let output_dir = if let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") {
        Path::new(&manifest_dir)
            .parent()
            .and_then(|p| p.parent())
            .map(|p| p.join("data/field_probe"))
            .unwrap_or_else(|| Path::new("data/field_probe").to_path_buf())
    } else {
        Path::new("data/field_probe").to_path_buf()
    };

    // Create output directory
    if let Err(e) = std::fs::create_dir_all(&output_dir) {
        eprintln!(
            "Error: Failed to create output directory {:?}: {e}",
            output_dir
        );
        std::process::exit(1);
    }

    // Convert to compact format and write per-connector files
    let mut connector_names: Vec<String> = Vec::new();
    let mut total_supported = 0;
    let mut total_not_supported = 0;

    for result in results {
        let connector_name = result.connector.clone();
        connector_names.push(connector_name.clone());

        // Convert to compact format (omits not_supported entries and null fields)
        let mut compact_flows: BTreeMap<String, BTreeMap<String, CompactFlowResult>> =
            BTreeMap::new();
        let mut supported_count = 0;
        let mut not_supported_count = 0;

        for (flow_name, flow_data) in result.flows {
            let mut compact_flow_data: BTreeMap<String, CompactFlowResult> = BTreeMap::new();
            for (entry_name, flow_result) in flow_data {
                if flow_result.status == "not_supported" {
                    not_supported_count += 1;
                } else {
                    supported_count += 1;
                }
                if let Some(compact) = Option::<CompactFlowResult>::from(flow_result) {
                    compact_flow_data.insert(entry_name, compact);
                }
            }
            // Only include flows that have at least one supported/error entry
            if !compact_flow_data.is_empty() {
                compact_flows.insert(flow_name, compact_flow_data);
            }
        }

        total_supported += supported_count;
        total_not_supported += not_supported_count;

        let compact_result = CompactConnectorResult {
            connector: result.connector,
            flows: compact_flows,
        };

        // Write formatted JSON with proper indentation
        let connector_json = serde_json::to_string_pretty(&compact_result)
            .expect("Failed to serialize connector results");

        let connector_file = output_dir.join(format!("{}.json", connector_name));
        match std::fs::write(&connector_file, &connector_json) {
            Ok(()) => eprintln!(
                "  Wrote {:?} ({} supported, {} not_supported)",
                connector_file, supported_count, not_supported_count
            ),
            Err(e) => eprintln!("  Warning: Failed to write {:?}: {e}", connector_file),
        }
    }

    // Write manifest file with flow metadata and connector list
    let manifest = ProbeManifest {
        flow_metadata,
        connectors: connector_names,
        schema_version: "2.0.0".to_string(),
    };

    let manifest_json = serde_json::to_string(&manifest).expect("Failed to serialize manifest");

    let manifest_path = output_dir.join("manifest.json");
    match std::fs::write(&manifest_path, &manifest_json) {
        Ok(()) => eprintln!("Wrote manifest to {:?}", manifest_path),
        Err(e) => eprintln!("Warning: Failed to write manifest: {e}"),
    }

    eprintln!(
        "\nSummary: {} connectors, {} supported entries, {} not_supported entries omitted",
        connectors.len(),
        total_supported,
        total_not_supported
    );
}
