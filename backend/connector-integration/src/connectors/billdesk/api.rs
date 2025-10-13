use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BilldeskApiMessage {
    pub merchant_id: String,
    pub txn_reference_no: String,
    pub amount: String,
    pub currency: String,
    pub customer_id: String,
    pub txn_type: String,
    pub item_code: String,
    pub txn_date: String,
    pub additional_info_1: Option<String>,
    pub additional_info_2: Option<String>,
    pub additional_info_3: Option<String>,
    pub additional_info_4: Option<String>,
    pub additional_info_5: Option<String>,
    pub additional_info_6: Option<String>,
    pub additional_info_7: Option<String>,
    pub checksum: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BilldeskUpiRequest {
    pub msg: String,
    pub useragent: Option<String>,
    pub ipaddress: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BilldeskStatusRequest {
    pub msg: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BilldeskRefundRequest {
    pub msg: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BilldeskRefundStatusRequest {
    pub msg: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BilldeskResponseMessage {
    pub merchant_id: String,
    pub customer_id: String,
    pub txn_reference_no: String,
    pub bank_reference_no: Option<String>,
    pub txn_amount: String,
    pub bank_id: Option<String>,
    pub filler1: Option<String>,
    pub txn_type: Option<String>,
    pub currency_type: String,
    pub item_code: String,
    pub filler2: Option<String>,
    pub filler3: Option<String>,
    pub filler4: Option<String>,
    pub txn_date: Option<String>,
    pub auth_status: String,
    pub filler5: Option<String>,
    pub additional_info_1: Option<String>,
    pub additional_info_2: Option<String>,
    pub additional_info_3: Option<String>,
    pub additional_info_4: Option<String>,
    pub additional_info_5: Option<String>,
    pub additional_info_6: Option<String>,
    pub additional_info_7: Option<String>,
    pub error_status: String,
    pub error_description: String,
    pub checksum: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BilldeskUpiResponse {
    pub msg: Option<String>,
    pub rdata: Option<BilldeskRdata>,
    pub txnrefno: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BilldeskRdata {
    pub parameters: std::collections::HashMap<String, String>,
    pub url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BilldeskErrorResponse {
    pub error: serde_json::Value,
    pub error_description: String,
    pub errors: Option<Vec<BilldeskErrorDetail>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BilldeskErrorDetail {
    pub message: String,
    pub path: String,
    #[serde(rename = "type")]
    pub error_type: String,
}