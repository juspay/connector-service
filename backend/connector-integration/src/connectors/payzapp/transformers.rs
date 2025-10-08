use std::collections::HashMap;

use common_utils::{
    errors::CustomResult, ext_traits::ValueExt, request::Method, types::StringMinorUnit,
    Email,
};
use domain_types::{
    connector_flow::{Authorize, PSync},
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, ResponseId},
    errors::{self, ConnectorError},
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
    utils,
};
use error_stack::ResultExt;
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};

use crate::{connectors::payzapp::PayZappRouterData, types::ResponseRouterData};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PayZappPaymentsRequest {
    mer_name: Option<String>,
    mer_id: String,
    mer_country_code: String,
    mer_app_id: String,
    txn_amount: String,
    txn_currency: String,
    txn_desc: String,
    supported_payment_type: String,
    restricted_payment_type: Option<String>,
    mer_app_data: String,
    mer_txn_id: String,
    mer_data_field: Option<String>,
    txn_date: Option<String>,
    txn_amt_known: bool,
    charge_later: bool,
    cust_email: Option<Email>,
    cust_mobile: Option<String>,
    cust_name: Option<String>,
    cust_dob: Option<String>,
    merchant_return_url: String,
    msg_hash: String,
    txn_type: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PayZappPaymentsResponse {
    txn_amt: String,
    mer_app_data: Option<String>,
    res_code: String,
    data_pick_up_code: Option<String>,
    mer_txn_id: Option<String>,
    msg_hash: Option<String>,
    res_desc: Option<String>,
    wibmo_txn_id: Option<String>,
    collect_email: Option<String>,
    is_billing_address_allowed: Option<String>,
    is_shipping_address_allowed: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PayZappPaymentsSyncRequest {
    merchant_info: MerchantInfo,
    transaction_info: TransactionInfo,
    msg_hash: String,
    charge_card: bool,
    txn_type: String,
    wibmo_txn_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PayZappPaymentsSyncResponse {
    res_code: String,
    res_desc: Option<String>,
    data: Option<ChargeRespData>,
    authentication_successful: bool,
    charge_successful: bool,
    charge_attempted: bool,
    msg_hash: Option<String>,
    data_pick_up_code: Option<String>,
    txn_status_code: Option<String>,
    txn_status_desc: Option<String>,
    wibmo_txn_id: Option<String>,
    mer_txn_id: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MerchantInfo {
    mer_name: Option<String>,
    mer_id: String,
    mer_country_code: String,
    mer_app_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionInfo {
    txn_amount: String,
    txn_currency: String,
    mer_txn_id: String,
    txn_date: String,
    txn_amt_known: bool,
    charge_later: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChargeRespData {
    wibmo_txn_id: Option<String>,
    msg_hash: String,
    mer_id: String,
    mer_txn_id: String,
    mer_app_data: Option<String>,
    pan: Option<String>,
    expiry_mm: Option<String>,
    expiry_yyyy: Option<String>,
    pg_status_code: Option<String>,
    card_type: Option<String>,
    txn_amt: serde_json::Value,
    card_classification_type: Option<String>,
    card_hash: Option<String>,
    card_masked: Option<String>,
    bin: Option<String>,
    pg_error_code: Option<String>,
    pg_auth_code: Option<String>,
}

// Stub types for unsupported flows
#[derive(Debug, Clone, Serialize)]
pub struct PayZappVoidRequest;
#[derive(Debug, Clone)]
pub struct PayZappVoidResponse;

#[derive(Debug, Clone, Serialize)]
pub struct PayZappCaptureRequest;
#[derive(Debug, Clone)]
pub struct PayZappCaptureResponse;

#[derive(Debug, Clone, Serialize)]
pub struct PayZappRefundRequest;
#[derive(Debug, Clone)]
pub struct PayZappRefundResponse;

#[derive(Debug, Clone, Serialize)]
pub struct PayZappRefundSyncRequest;
#[derive(Debug, Clone)]
pub struct PayZappRefundSyncResponse;

#[derive(Debug, Clone, Serialize)]
pub struct PayZappCreateOrderRequest;
#[derive(Debug, Clone)]
pub struct PayZappCreateOrderResponse;

#[derive(Debug, Clone, Serialize)]
pub struct PayZappSessionTokenRequest;
#[derive(Debug, Clone)]
pub struct PayZappSessionTokenResponse;

#[derive(Debug, Clone, Serialize)]
pub struct PayZappSetupMandateRequest;
#[derive(Debug, Clone)]
pub struct PayZappSetupMandateResponse;

#[derive(Debug, Clone, Serialize)]
pub struct PayZappRepeatPaymentRequest;
#[derive(Debug, Clone)]
pub struct PayZappRepeatPaymentResponse;

#[derive(Debug, Clone, Serialize)]
pub struct PayZappAcceptDisputeRequest;
#[derive(Debug, Clone)]
pub struct PayZappAcceptDisputeResponse;

#[derive(Debug, Clone, Serialize)]
pub struct PayZappDefendDisputeRequest;
#[derive(Debug, Clone)]
pub struct PayZappDefendDisputeResponse;

#[derive(Debug, Clone, Serialize)]
pub struct PayZappSubmitEvidenceRequest;
#[derive(Debug, Clone)]
pub struct PayZappSubmitEvidenceResponse;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PayZappErrorResponse {
    res_code: String,
    res_desc: String,
}

fn get_merchant_credentials(
    connector_auth_type: &ConnectorAuthType,
    currency: common_enums::Currency,
) -> Result<(String, String, String), errors::ConnectorError> {
    match connector_auth_type {
        ConnectorAuthType::HeaderKey { api_key, key1 } => {
            let merchant_id = api_key.peek().clone();
            let app_id = key1.peek().clone();
            let country_code = "IN".to_string(); // Default to India for PayZapp
            Ok((merchant_id, app_id, country_code))
        }
        _ => Err(errors::ConnectorError::FailedToObtainAuthType),
    }
}

fn generate_message_hash(data: &str) -> String {
    // This is a placeholder - actual implementation would use proper hashing
    format!("hash_{}", data)
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> TryFrom<
    PayZappRouterData<
        RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData<T>,
            PaymentsResponseData,
        >,
        T,
    >,
> for PayZappPaymentsRequest
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: PayZappRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let (merchant_id, app_id, country_code) = get_merchant_credentials(
            &item.router_data.connector_auth_type,
            item.router_data.request.currency,
        )?;
        
        let amount = item.amount.get_amount_as_string();
        let currency = item.router_data.request.currency.to_string();
        
        let customer_id = item.router_data.resource_common_data.get_customer_id()?;
        let transaction_id = item.router_data.resource_common_data.connector_request_reference_id.clone();
        let return_url = item.router_data.request.get_router_return_url()?;
        
        let email = item.router_data.request.email.clone();
        let customer_name = item.router_data.request.get_customer_name().ok();
        
        // Generate message hash based on transaction data
        let hash_data = format!("{}{}{}{}", merchant_id, transaction_id, amount, currency);
        let msg_hash = generate_message_hash(&hash_data);
        
        Ok(Self {
            mer_name: Some("PayZapp Merchant".to_string()),
            mer_id: merchant_id,
            mer_country_code: country_code,
            mer_app_id: app_id,
            txn_amount: amount,
            txn_currency: currency,
            txn_desc: item.router_data.request.description.clone().unwrap_or_else(|| "Payment Transaction".to_string()),
            supported_payment_type: "UPI".to_string(), // UPI only as per requirements
            restricted_payment_type: None,
            mer_app_data: "{}".to_string(),
            mer_txn_id: transaction_id,
            mer_data_field: None,
            txn_date: Some(chrono::Utc::now().format("%Y%m%d").to_string()),
            txn_amt_known: true,
            charge_later: false,
            cust_email: email,
            cust_mobile: None,
            cust_name: customer_name,
            cust_dob: None,
            merchant_return_url: return_url,
            msg_hash,
            txn_type: "PAY".to_string(),
        })
    }
}

impl<T> TryFrom<PayZappPaymentsResponse> for PaymentsResponseData {
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(response: PayZappPaymentsResponse) -> Result<Self, Self::Error> {
        let status = match response.res_code.as_str() {
            "00" | "0" => common_enums::AttemptStatus::AuthenticationPending,
            "01" | "1" => common_enums::AttemptStatus::Charged,
            _ => common_enums::AttemptStatus::Failure,
        };
        
        Ok(Self {
            status,
            amount_received: response.txn_amt.parse().ok().map(|amt: f64| {
                common_utils::types::MinorUnit::from_major_unit_as_i64(amt)
            }),
            currency: None,
            connector_transaction_id: response.wibmo_txn_id,
            error_message: response.res_desc,
            redirect: Some(RedirectForm {
                url: response.data_pick_up_code.unwrap_or_default(),
                method: Method::Get,
                form_body: None,
                is_native_app_redirect: false,
            }),
            ..Default::default()
        })
    }
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> TryFrom<
    PayZappRouterData<
        RouterDataV2<
            PSync,
            PaymentFlowData,
            PaymentsSyncData,
            PaymentsResponseData,
        >,
        T,
    >,
> for PayZappPaymentsSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: PayZappRouterData<
            RouterDataV2<
                PSync,
                PaymentFlowData,
                PaymentsSyncData,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let (merchant_id, app_id, country_code) = get_merchant_credentials(
            &item.router_data.connector_auth_type,
            item.router_data.request.currency,
        )?;
        
        let amount = item.amount.get_amount_as_string();
        let currency = item.router_data.request.currency.to_string();
        let transaction_id = item.router_data.request.connector_transaction_id.get_connector_transaction_id()
            .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?;
        
        // Generate message hash for sync request
        let hash_data = format!("{}{}{}{}", merchant_id, transaction_id, amount, currency);
        let msg_hash = generate_message_hash(&hash_data);
        
        Ok(Self {
            merchant_info: MerchantInfo {
                mer_name: Some("PayZapp Merchant".to_string()),
                mer_id: merchant_id,
                mer_country_code: country_code,
                mer_app_id: app_id,
            },
            transaction_info: TransactionInfo {
                txn_amount: amount,
                txn_currency: currency,
                mer_txn_id: transaction_id,
                txn_date: chrono::Utc::now().format("%Y%m%d").to_string(),
                txn_amt_known: true,
                charge_later: false,
            },
            msg_hash,
            charge_card: false,
            txn_type: "ENQ".to_string(),
            wibmo_txn_id: None,
        })
    }
}

impl<T> TryFrom<PayZappPaymentsSyncResponse> for PaymentsResponseData {
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(response: PayZappPaymentsSyncResponse) -> Result<Self, Self::Error> {
        let status = if response.charge_successful {
            common_enums::AttemptStatus::Charged
        } else if response.authentication_successful {
            common_enums::AttemptStatus::AuthenticationPending
        } else {
            common_enums::AttemptStatus::Failure
        };
        
        Ok(Self {
            status,
            amount_received: response.data.as_ref().and_then(|data| {
                data.txn_amt.as_str().and_then(|s| s.parse().ok()).map(|amt: f64| {
                    common_utils::types::MinorUnit::from_major_unit_as_i64(amt)
                })
            }),
            currency: None,
            connector_transaction_id: response.wibmo_txn_id.clone(),
            error_message: response.res_desc.clone(),
            ..Default::default()
        })
    }
}