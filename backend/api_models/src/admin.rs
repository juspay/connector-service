use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MerchantConnectorWebhookDetails {
    pub merchant_secret: Secret<String>,

    pub additional_secret: Option<Secret<String>>,
}
