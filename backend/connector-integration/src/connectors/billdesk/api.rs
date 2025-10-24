use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BilldeskApiEndpoints;

impl BilldeskApiEndpoints {
    pub fn get_endpoint_url(req_id: &str, is_test_mode: bool) -> String {
        let base_url = if is_test_mode {
            crate::connectors::billdesk::constants::UAT_BASE_URL
        } else {
            crate::connectors::billdesk::constants::PROD_BASE_URL
        };
        
        format!("{}?reqid={}", base_url, req_id)
    }
}