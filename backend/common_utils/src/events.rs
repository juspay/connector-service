use serde::Serialize;

use crate::{
    global_id::{
        customer::GlobalCustomerId,
        payment::GlobalPaymentId,
        payment_methods::{GlobalPaymentMethodId, GlobalPaymentMethodSessionId},
        refunds::GlobalRefundId,
        token::GlobalTokenId,
    },
    id_type::{self, ApiKeyId, MerchantConnectorAccountId, ProfileAcquirerId},
    types::TimeRange,
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
