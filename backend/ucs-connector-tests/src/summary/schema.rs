use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct CapabilityRow {
    pub capability_id: String,
    pub connector: String,
    pub layer: String,
    pub flow: String,
    pub payment_method: String,
    pub payment_method_subtype: Option<String>,
    pub scenario: String,
    pub support: String,
    pub expected: String,
    pub fallback: Option<String>,
    pub test_name: String,
}
