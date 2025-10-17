// Domain types and enums
use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConnectorType {
    PaymentGateway,
    BankTransfer,
    Wallet,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConnectorFlow {
    Authorize,
    Capture,
    Void,
    Refund,
    PaymentSync,
    RefundSync,
    CreateOrder,
    SessionToken,
    SetupMandate,
    RepeatPayment,
    Accept,
    DefendDispute,
    SubmitEvidence,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorSpecifications {
    pub connector_name: String,
    pub connector_type: ConnectorType,
    pub supported_payment_methods: Vec<String>,
    pub supported_flows: Vec<ConnectorFlow>,
    pub supported_currencies: Vec<String>,
    pub supported_countries: Vec<CountryAlpha2>,
    pub connector_metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CountryAlpha2 {
    #[serde(rename = "IN")]
    India,
    #[serde(rename = "US")]
    UnitedStates,
    #[serde(rename = "GB")]
    UnitedKingdom,
    #[serde(rename = "EU")]
    EuropeanUnion,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConnectorAuthType {
    SignatureKey {
        api_key: String,
        key1: Option<String>,
        key2: Option<String>,
    },
    BodyKey {
        api_key: String,
    },
    HeaderKey {
        api_key: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WebhookSourceVerificationAlgorithm {
    HmacSha512,
    HmacSha256,
    Sha512,
    Sha256,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorWebhookSecrets {
    pub secret: String,
    pub webhook_url: String,
}

// Connector enum for type system integration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConnectorEnum {
    Payu,
    // Add other connectors here
}

impl fmt::Display for ConnectorEnum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectorEnum::Payu => write!(f, "payu"),
        }
    }
}

impl From<&str> for ConnectorEnum {
    fn from(s: &str) -> Self {
        match s {
            "payu" => ConnectorEnum::Payu,
            _ => panic!("Unknown connector: {}", s),
        }
    }
}