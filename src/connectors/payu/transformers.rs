use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

use super::{PayuAuthType, PayuPaymentsRequest, PayuPaymentsResponse, PayuPaymentsSyncRequest, PayuPaymentsSyncResponse, PayuRefundSyncRequest, PayuRefundSyncResponse};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentFlowData {
    pub customer_id: String,
    pub connector_request_reference_id: String,
    pub test_mode: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentsAuthorizeData<T> {
    pub minor_amount: i64,
    pub currency: String,
    pub connector_transaction_id: String,
    pub description: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub payment_method_type: String,
    pub payment_method_data: T,
    pub return_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentsResponseData {
    pub status: String,
    pub gateway_transaction_id: Option<String>,
    pub connector_transaction_id: Option<String>,
    pub amount_received: Option<i64>,
    pub error_message: Option<String>,
    pub error_code: Option<String>,
    pub redirection_data: Option<String>,
    pub network_transaction_id: Option<String>,
    pub connector_response: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentsSyncData {
    pub connector_transaction_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefundSyncData {
    pub connector_transaction_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefundsResponseData {
    pub status: String,
    pub refund_id: Option<String>,
    pub connector_transaction_id: Option<String>,
    pub amount_received: Option<i64>,
    pub error_message: Option<String>,
    pub error_code: Option<String>,
    pub network_transaction_id: Option<String>,
    pub connector_response: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouterDataV2<FCD, Req> {
    pub connector_auth_type: ConnectorAuthType,
    pub amount: AmountConverter,
    pub router_data: RouterData<FCD, Req>,
    _phantom: PhantomData<()>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouterData<FCD, Req> {
    pub request: Req,
    pub resource_common_data: FCD,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorAuthType {
    pub api_key: String,
    pub salt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmountConverter {
    pub amount: i64,
}

impl AmountConverter {
    pub fn get_amount_as_string(&self) -> String {
        self.amount.to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentMethodData {
    pub upi_vpa: Option<String>,
}

impl PaymentMethodData {
    pub fn get_upi_vpa(&self) -> Result<String, String> {
        self.upi_vpa.clone().ok_or("UPI VPA not found".to_string())
    }
}

impl<T> TryFrom<&RouterDataV2<PaymentFlowData, PaymentsAuthorizeData<T>>>
    for PayuPaymentsRequest
where
    T: PaymentMethodDataTypes,
{
    type Error = String;

    fn try_from(
        item: &RouterDataV2<PaymentFlowData, PaymentsAuthorizeData<T>>,
    ) -> Result<Self, Self::Error> {
        let auth = PayuAuthType::KeySecret {
            key: item.connector_auth_type.api_key.clone(),
            salt: item.connector_auth_type.salt.clone(),
        };

        let key = auth.get_auth_header();
        let amount = item.amount.get_amount_as_string();
        let transaction_id = item.router_data.request.connector_transaction_id.clone();

        let product_info = item
            .router_data
            .request
            .description
            .clone()
            .unwrap_or_else(|| "Payment".to_string());

        let customer_id = item.router_data.resource_common_data.customer_id.clone();

        let email = item
            .router_data
            .request
            .email
            .clone()
            .unwrap_or_else(|| "customer@example.com".to_string());

        let phone = item
            .router_data
            .request
            .phone
            .clone()
            .unwrap_or_else(|| "9999999999".to_string());

        let surl = item
            .router_data
            .request
            .return_url
            .clone()
            .unwrap_or_else(|| "https://example.com/success".to_string());

        let furl = item
            .router_data
            .request
            .return_url
            .clone()
            .unwrap_or_else(|| "https://example.com/failure".to_string());

        // For UPI payments
        let payment_method = match item.router_data.request.payment_method_type.as_str() {
            "upi_collect" => {
                let vpa = item
                    .router_data
                    .request
                    .payment_method_data
                    .get_upi_vpa()
                    .map_err(|e| format!("Failed to get UPI VPA: {}", e))?;
                format!("UPI|{}", vpa)
            }
            "upi_intent" => "UPI_INTENT".to_string(),
            _ => "NB".to_string(),
        };

        let hash_string = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            key,
            transaction_id,
            amount,
            product_info,
            customer_id,
            customer_id,
            email,
            phone,
            surl,
            furl,
            "UDF1",
            "UDF2",
            "UDF3"
        );

        let hash = auth.generate_hash(&hash_string);

        let var1 = serde_json::json!({
            "txnid": transaction_id,
            "amount": amount,
            "productinfo": product_info,
            "firstname": customer_id,
            "email": email,
            "phone": phone,
            "surl": surl,
            "furl": furl,
            "udf1": "UDF1",
            "udf2": "UDF2",
            "udf3": "UDF3",
            "udf4": "UDF4",
            "pg": payment_method
        })
        .to_string();

        Ok(Self {
            key,
            command: "create_transaction".to_string(),
            hash,
            var1,
        })
    }
}

impl TryFrom<&RouterDataV2<PaymentFlowData, PaymentsSyncData>>
    for PayuPaymentsSyncRequest
{
    type Error = String;

    fn try_from(
        item: &RouterDataV2<PaymentFlowData, PaymentsSyncData>,
    ) -> Result<Self, Self::Error> {
        let auth = PayuAuthType::KeySecret {
            key: item.connector_auth_type.api_key.clone(),
            salt: item.connector_auth_type.salt.clone(),
        };

        let key = auth.get_auth_header();
        let transaction_id = item.router_data.request.connector_transaction_id.clone();

        let hash_string = format!("{}|{}|{}", key, "verify_payment", transaction_id);
        let hash = auth.generate_hash(&hash_string);

        Ok(Self {
            key,
            command: "verify_payment".to_string(),
            hash,
            var1: transaction_id,
        })
    }
}

impl TryFrom<&RouterDataV2<PaymentFlowData, RefundSyncData>>
    for PayuRefundSyncRequest
{
    type Error = String;

    fn try_from(
        item: &RouterDataV2<PaymentFlowData, RefundSyncData>,
    ) -> Result<Self, Self::Error> {
        let auth = PayuAuthType::KeySecret {
            key: item.connector_auth_type.api_key.clone(),
            salt: item.connector_auth_type.salt.clone(),
        };

        let key = auth.get_auth_header();
        let transaction_id = item.router_data.request.connector_transaction_id.clone();

        let hash_string = format!("{}|{}|{}", key, "get_all_refunds_from_txn_id", transaction_id);
        let hash = auth.generate_hash(&hash_string);

        Ok(Self {
            key,
            command: "get_all_refunds_from_txn_id".to_string(),
            hash,
            var1: transaction_id,
        })
    }
}

pub trait PaymentMethodDataTypes {
    fn get_upi_vpa(&self) -> Result<String, String>;
}

impl PaymentMethodDataTypes for PaymentMethodData {
    fn get_upi_vpa(&self) -> Result<String, String> {
        self.upi_vpa.clone().ok_or("UPI VPA not found".to_string())
    }
}

impl TryFrom<PayuPaymentsResponse> for PaymentsResponseData {
    type Error = String;

    fn try_from(response: PayuPaymentsResponse) -> Result<Self, Self::Error> {
        let status = match response.status.as_str() {
            "success" => "charged",
            "failure" => "failure",
            "pending" => "pending",
            _ => "authentication_pending",
        };

        let amount_received = response.amount.as_ref().and_then(|amt| amt.parse::<f64>().ok()).map(|amt| (amt * 100.0) as i64);

        Ok(Self {
            status: status.to_string(),
            gateway_transaction_id: response.mihpayid.clone(),
            connector_transaction_id: response.txnid.clone(),
            amount_received,
            error_message: response.error_message.clone(),
            error_code: response.error_code.clone(),
            redirection_data: None,
            network_transaction_id: None,
            connector_response: Some(serde_json::json!({
                "status": response.status,
                "mihpayid": response.mihpayid,
                "txnid": response.txnid,
                "amount": response.amount,
                "error_message": response.error_message,
                "error_code": response.error_code
            })),
        })
    }
}

impl TryFrom<PayuPaymentsSyncResponse> for PaymentsResponseData {
    type Error = String;

    fn try_from(response: PayuPaymentsSyncResponse) -> Result<Self, Self::Error> {
        let status = match response.status.as_str() {
            "success" => "charged",
            "failure" => "failure",
            "pending" => "pending",
            _ => "authentication_pending",
        };

        let (gateway_transaction_id, connector_transaction_id, amount_received, error_message, error_code, network_transaction_id) =
            if let Some(ref txn_details) = response.txn_details {
                let amount_received = txn_details.amount.parse::<f64>().ok().map(|amt| (amt * 100.0) as i64);
                (
                    Some(txn_details.mihpayid.clone()),
                    Some(txn_details.txnid.clone()),
                    amount_received,
                    txn_details.error_message.clone(),
                    txn_details.error_code.clone(),
                    txn_details.bank_ref_num.clone(),
                )
            } else {
                (None, None, None, response.msg.clone(), None, None)
            };

        Ok(Self {
            status: status.to_string(),
            gateway_transaction_id,
            connector_transaction_id,
            amount_received,
            error_message,
            error_code,
            redirection_data: None,
            network_transaction_id,
            connector_response: Some(serde_json::json!({
                "status": response.status,
                "txn_details": response.txn_details,
                "msg": response.msg
            })),
        })
    }
}

impl TryFrom<PayuRefundSyncResponse> for RefundsResponseData {
    type Error = String;

    fn try_from(response: PayuRefundSyncResponse) -> Result<Self, Self::Error> {
        let status = match response.status.as_str() {
            "success" => "success",
            "failure" => "failure",
            "pending" => "pending",
            _ => "pending",
        };

        let (refund_id, connector_transaction_id, amount_received, error_message, error_code, network_transaction_id) =
            if let Some(ref refund_details) = response.refund_details {
                if let Some(refund) = refund_details.first() {
                    let amount_received = refund.amount.parse::<f64>().ok().map(|amt| (amt * 100.0) as i64);
                    (
                        Some(refund.refund_id.clone()),
                        Some(refund.txnid.clone()),
                        amount_received,
                        refund.error_message.clone(),
                        refund.error_code.clone(),
                        refund.bank_ref_num.clone(),
                    )
                } else {
                    (None, None, None, response.msg.clone(), None, None)
                }
            } else {
                (None, None, None, response.msg.clone(), None, None)
            };

        Ok(Self {
            status: status.to_string(),
            refund_id,
            connector_transaction_id,
            amount_received,
            error_message,
            error_code,
            network_transaction_id,
            connector_response: Some(serde_json::json!({
                "status": response.status,
                "refund_details": response.refund_details,
                "msg": response.msg
            })),
        })
    }
}