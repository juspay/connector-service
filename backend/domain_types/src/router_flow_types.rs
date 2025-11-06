use serde::Serialize;

#[derive(Clone, Debug)]
pub struct VerifyWebhookSource;

#[derive(Debug, Clone, Serialize)]
pub struct ConnectorMandateDetails {
    pub connector_mandate_id: common_utils::Secret<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConnectorNetworkTxnId(common_utils::Secret<String>);

impl ConnectorNetworkTxnId {
    pub fn new(txn_id: common_utils::Secret<String>) -> Self {
        Self(txn_id)
    }
    pub fn get_id(&self) -> &common_utils::Secret<String> {
        &self.0
    }
}
