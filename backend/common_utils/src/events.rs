use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{
    global_id::{
        customer::GlobalCustomerId,
        payment::GlobalPaymentId,
        payment_methods::{GlobalPaymentMethodId, GlobalPaymentMethodSessionId},
        refunds::GlobalRefundId,
        token::GlobalTokenId,
    },
    id_type::{self, ApiKeyId, MerchantConnectorAccountId, ProfileAcquirerId},
    lineage,
    types::TimeRange,
    SecretSerdeValue,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "flow_type", rename_all = "snake_case")]
pub enum ApiEventsType {
    Payout {
        payout_id: String,
    },

    Payment {
        payment_id: GlobalPaymentId,
    },

    Refund {
        payment_id: Option<GlobalPaymentId>,
        refund_id: GlobalRefundId,
    },

    PaymentMethod {
        payment_method_id: GlobalPaymentMethodId,
        payment_method_type: Option<common_enums::PaymentMethod>,
        payment_method_subtype: Option<common_enums::PaymentMethodType>,
    },

    PaymentMethodCreate,

    Customer {
        customer_id: Option<GlobalCustomerId>,
    },

    BusinessProfile {
        profile_id: id_type::ProfileId,
    },
    ApiKey {
        key_id: ApiKeyId,
    },
    User {
        user_id: String,
    },
    PaymentMethodList {
        payment_id: Option<String>,
    },

    PaymentMethodListForPaymentMethods {
        payment_method_id: GlobalPaymentMethodId,
    },

    Webhooks {
        connector: MerchantConnectorAccountId,
        payment_id: Option<GlobalPaymentId>,
    },
    Routing,
    ResourceListAPI,

    PaymentRedirectionResponse {
        payment_id: GlobalPaymentId,
    },
    Gsm,
    // TODO: This has to be removed once the corresponding apiEventTypes are created
    Miscellaneous,
    Keymanager,
    RustLocker,
    ApplePayCertificatesMigration,
    FraudCheck,
    Recon,
    ExternalServiceAuth,
    Dispute {
        dispute_id: String,
    },
    Events {
        merchant_id: id_type::MerchantId,
    },
    PaymentMethodCollectLink {
        link_id: String,
    },
    Poll {
        poll_id: String,
    },
    Analytics,

    ClientSecret {
        key_id: id_type::ClientSecretId,
    },

    PaymentMethodSession {
        payment_method_session_id: GlobalPaymentMethodSessionId,
    },

    Token {
        token_id: Option<GlobalTokenId>,
    },
    ProcessTracker,
    ProfileAcquirer {
        profile_acquirer_id: ProfileAcquirerId,
    },
    ThreeDsDecisionRule,
}

pub trait ApiEventMetric {
    fn get_api_event_type(&self) -> Option<ApiEventsType> {
        None
    }
}

impl ApiEventMetric for serde_json::Value {}
impl ApiEventMetric for () {}

impl ApiEventMetric for GlobalPaymentId {
    fn get_api_event_type(&self) -> Option<ApiEventsType> {
        Some(ApiEventsType::Payment {
            payment_id: self.clone(),
        })
    }
}

impl<Q: ApiEventMetric, E> ApiEventMetric for Result<Q, E> {
    fn get_api_event_type(&self) -> Option<ApiEventsType> {
        match self {
            Ok(q) => q.get_api_event_type(),
            Err(_) => None,
        }
    }
}

// TODO: Ideally all these types should be replaced by newtype responses
impl<T> ApiEventMetric for Vec<T> {
    fn get_api_event_type(&self) -> Option<ApiEventsType> {
        Some(ApiEventsType::Miscellaneous)
    }
}

#[macro_export]
macro_rules! impl_api_event_type {
    ($event: ident, ($($type:ty),+))=> {
        $(
            impl ApiEventMetric for $type {
                fn get_api_event_type(&self) -> Option<ApiEventsType> {
                    Some(ApiEventsType::$event)
                }
            }
        )+
     };
}

impl_api_event_type!(
    Miscellaneous,
    (
        String,
        id_type::MerchantId,
        (Option<i64>, Option<i64>, String),
        (Option<i64>, Option<i64>, id_type::MerchantId),
        bool
    )
);

impl<T: ApiEventMetric> ApiEventMetric for &T {
    fn get_api_event_type(&self) -> Option<ApiEventsType> {
        T::get_api_event_type(self)
    }
}

impl ApiEventMetric for TimeRange {}

#[derive(Debug, Clone, Serialize)]
pub struct Event {
    pub request_id: String,
    pub timestamp: i128,
    pub flow_type: FlowName,
    pub connector: String,
    pub url: Option<String>,
    pub stage: EventStage,
    pub latency: Option<u64>,
    pub status_code: Option<u16>,
    pub request_data: Option<SecretSerdeValue>,
    pub connector_request_data: Option<SecretSerdeValue>,
    pub connector_response_data: Option<SecretSerdeValue>,
    #[serde(flatten)]
    pub additional_fields: HashMap<String, SecretSerdeValue>,
    #[serde(flatten)]
    pub lineage_ids: lineage::LineageIds<'static>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FlowName {
    Authorize,
    Refund,
    Capture,
    Void,
    Psync,
    Rsync,
    AcceptDispute,
    SubmitEvidence,
    DefendDispute,
    Dsync,
    IncomingWebhook,
    SetupMandate,
    RepeatPayment,
    CreateOrder,
    CreateSessionToken,
    Unknown,
}

impl FlowName {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Authorize => "Authorize",
            Self::Refund => "Refund",
            Self::Capture => "Capture",
            Self::Void => "Void",
            Self::Psync => "Psync",
            Self::Rsync => "Rsync",
            Self::AcceptDispute => "AcceptDispute",
            Self::SubmitEvidence => "SubmitEvidence",
            Self::DefendDispute => "DefendDispute",
            Self::Dsync => "Dsync",
            Self::IncomingWebhook => "IncomingWebhook",
            Self::SetupMandate => "SetupMandate",
            Self::RepeatPayment => "RepeatPayment",
            Self::CreateOrder => "CreateOrder",
            Self::CreateSessionToken => "CreateSessionToken",
            Self::Unknown => "Unknown",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventStage {
    ConnectorCall,
}

impl EventStage {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ConnectorCall => "CONNECTOR_CALL",
        }
    }
}

/// Configuration for events system
#[derive(Debug, Clone, Deserialize)]
pub struct EventConfig {
    pub enabled: bool,
    pub topic: String,
    pub brokers: Vec<String>,
    pub partition_key_field: String,
    #[serde(default)]
    pub transformations: HashMap<String, String>, // target_path → source_field
    #[serde(default)]
    pub static_values: HashMap<String, String>, // target_path → static_value
    #[serde(default)]
    pub extractions: HashMap<String, String>, // target_path → extraction_path
}

impl Default for EventConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            topic: "events".to_string(),
            brokers: vec!["localhost:9092".to_string()],
            partition_key_field: "request_id".to_string(),
            transformations: HashMap::new(),
            static_values: HashMap::new(),
            extractions: HashMap::new(),
        }
    }
}
