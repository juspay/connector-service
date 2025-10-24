// Stub implementations for domain_types

use hyperswitch_masking::{Mask, Maskable, Secret};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub mod connector_flow {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Authorize;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct PSync;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RSync;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Refund;
}

pub mod connector_types {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ConnectorCommon;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ConnectorCommonV2;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ConnectorIntegrationV2;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ConnectorSpecifications {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub connector_name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub connector_type: ConnectorType,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub supported_payment_methods: Vec<crate::stubs::PaymentMethodType>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub supported_currencies: Vec<crate::stubs::Currency>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub supported_countries: Vec<Country>,
    }

    impl Default for ConnectorSpecifications {
        fn default() -> Self {
            Self {
                connector_name: String::new(),
                connector_type: ConnectorType::PaymentGateway,
                supported_payment_methods: Vec::new(),
                supported_currencies: Vec::new(),
                supported_countries: Vec::new(),
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ConnectorWebhookSecrets {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub secret: Option<Secret<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub algorithm: Option<String>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct PaymentFlowData {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub test_mode: Option<bool>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct PaymentsAuthorizeData<T> {
        pub payment_method_data: T,
        pub amount: u64,
        pub currency: crate::stubs::Currency,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct PaymentsResponseData {
        pub status: crate::stubs::AttemptStatus,
        pub amount: u64,
        pub currency: crate::stubs::Currency,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
    }

    impl Default for PaymentsResponseData {
        fn default() -> Self {
            Self {
                status: crate::stubs::AttemptStatus::Pending,
                amount: 0,
                currency: crate::stubs::Currency::Inr,
                error: None,
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct PaymentsSyncData {
        pub payment_id: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RefundFlowData {
        pub payment_id: String,
        pub refund_amount: u64,
        pub currency: crate::stubs::Currency,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RefundsData {
        pub refund_id: String,
        pub amount: u64,
        pub currency: crate::stubs::Currency,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RefundsResponseData {
        pub status: crate::stubs::AttemptStatus,
        pub refund_id: String,
        pub amount: u64,
        pub currency: crate::stubs::Currency,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RefundSyncData {
        pub refund_id: String,
    }

    // Trait stubs
    pub trait ConnectorServiceTrait<T> {}
    pub trait PaymentAuthorizeV2<T> {}
    pub trait PaymentSyncV2 {}
    pub trait RefundV2 {}
    pub trait RefundSyncV2 {}

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct PaymentsAuthorizeType;
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct PaymentsSyncType;
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RefundType;
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RefundSyncType;
}

pub mod payment_method_data {
    use serde::{Deserialize, Serialize};

    pub trait PaymentMethodDataTypes: std::fmt::Debug + Send + Sync + 'static {}

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct UpiData {
        pub vpa: String,
    }

    impl PaymentMethodDataTypes for UpiData {}
}

pub mod router_data_v2 {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RouterDataV2<F, FCD, Req, Res> {
        pub flow: F,
        pub resource_common_data: FCD,
        pub request: Req,
        pub response: Option<Res>,
    }
}

pub mod router_data {
    use hyperswitch_masking::Secret;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum ConnectorAuthType {
        ApiKey { api_key: Secret<String> },
        Signature { key: Secret<String> },
        NoAuth,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ErrorResponse {
        pub status_code: u16,
        pub code: Option<String>,
        pub message: Option<String>,
        pub reason: Option<String>,
    }
}

pub mod router_response_types {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Response {
        pub status_code: u16,
        pub response: serde_json::Value,
    }
}

pub mod types {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum Connectors {
        EaseBuzz,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum ConnectorType {
        PaymentGateway,
        BankTransfer,
        Wallet,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ConnectorMetadata {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub website: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub supported_payment_methods: Vec<super::PaymentMethodType>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub supported_currencies: Vec<super::Currency>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub supported_countries: Vec<Country>,
    }

    impl Default for ConnectorMetadata {
        fn default() -> Self {
            Self {
                description: None,
                website: None,
                supported_payment_methods: Vec::new(),
                supported_currencies: Vec::new(),
                supported_countries: Vec::new(),
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Country {
    #[serde(rename = "US")]
    Us,
    #[serde(rename = "IN")]
    In,
    #[serde(rename = "GB")]
    Gb,
}

impl std::str::FromStr for Country {
    type Err = thiserror::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "US" => Ok(Country::Us),
            "IN" => Ok(Country::In),
            "GB" => Ok(Country::Gb),
            _ => Err(thiserror::Error::msg(format!("Invalid country: {}", s))),
        }
    }
}

// Re-export for convenience
pub use connector_types::*;
pub use payment_method_data::*;
pub use router_data_v2::*;
pub use router_data::*;
pub use router_response_types::*;
pub use types::*;