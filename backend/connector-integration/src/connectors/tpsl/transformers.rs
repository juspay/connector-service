
use domain_types::{
    connector_flow::{Authorize, PSync},
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, ResponseId},
    errors::{self, ConnectorError},
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
};

use hyperswitch_masking::{ExposeInterface, Secret};
use serde::{Deserialize, Serialize};

use crate::{connectors::tpsl::TPSLRouterData, types::ResponseRouterData};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentsRequest {
    pub merchant: TpslMerchantPayload,
    pub cart: TpslCartPayload,
    pub payment: TpslPaymentPayload,
    pub transaction: TpslTransactionPayload,
    pub consumer: TpslConsumerPayload,
    pub merchant_input_flags: Option<TpslFlagsType>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslMerchantPayload {
    pub webhook_endpoint_url: String,
    pub response_type: String,
    pub response_endpoint_url: String,
    pub description: String,
    pub identifier: String,
    pub webhook_type: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslCartPayload {
    pub item: Vec<TpslItemPayload>,
    pub reference: String,
    pub identifier: String,
    pub description: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslItemPayload {
    pub description: String,
    pub provider_identifier: String,
    pub surcharge_or_discount_amount: String,
    pub amount: String,
    pub com_amt: String,
    pub s_k_u: String,
    pub reference: String,
    pub identifier: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentPayload {
    pub method: TpslMethodPayload,
    pub instrument: TpslInstrumentPayload,
    pub instruction: TpslInstructionPayload,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslMethodPayload {
    pub token: String,
    #[serde(rename = "type")]
    pub method_type: String,
    pub code: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslInstrumentPayload {
    pub expiry: Option<TpslExpiryPayload>,
    pub provider: String,
    pub i_f_s_c: String,
    pub holder: Option<TpslHolderPayload>,
    pub b_i_c: String,
    #[serde(rename = "type")]
    pub instrument_type: String,
    pub action: String,
    pub m_i_c_r: String,
    pub verification_code: String,
    pub i_b_a_n: String,
    pub processor: String,
    pub issuance: Option<TpslExpiryPayload>,
    pub alias: String,
    pub identifier: String,
    pub token: String,
    pub authentication: Option<TpslAuthenticationPayload>,
    pub sub_type: String,
    pub issuer: String,
    pub acquirer: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslExpiryPayload {
    pub year: String,
    pub month: String,
    pub date_time: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslHolderPayload {
    pub name: String,
    pub address: TpslAddressPayload,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslAddressPayload {
    pub country: String,
    pub street: String,
    pub state: String,
    pub city: String,
    pub zip_code: String,
    pub county: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslAuthenticationPayload {
    pub token: String,
    #[serde(rename = "type")]
    pub auth_type: String,
    pub sub_type: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslInstructionPayload {
    pub occurrence: String,
    pub amount: String,
    pub frequency: String,
    #[serde(rename = "type")]
    pub instruction_type: String,
    pub description: String,
    pub action: String,
    pub limit: String,
    pub end_date_time: String,
    pub debit_day: String,
    pub debit_flag: String,
    pub identifier: String,
    pub reference: String,
    pub start_date_time: String,
    pub validity: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslTransactionPayload {
    pub device_identifier: String,
    pub sms_sending: String,
    pub amount: String,
    pub forced_3_d_s_call: String,
    #[serde(rename = "type")]
    pub transaction_type: String,
    pub description: String,
    pub currency: String,
    pub is_registration: String,
    pub identifier: String,
    pub date_time: String,
    pub token: String,
    pub security_token: String,
    pub sub_type: String,
    pub request_type: String,
    pub reference: String,
    pub merchant_initiated: String,
    pub tenure_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslConsumerPayload {
    pub mobile_number: String,
    pub email_i_d: String,
    pub identifier: String,
    pub account_no: String,
    pub account_type: String,
    pub account_holder_name: String,
    pub aadhar_no: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslFlagsType {
    pub account_no: bool,
    pub mobile_number: bool,
    pub email_i_d: bool,
    pub card_details: bool,
    pub mandate_details: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslUPITokenRequest {
    pub merchant: TpslMerchantDataType,
    pub cart: TpslUPITokenCart,
    pub transaction: TpslUPITokenTxn,
    pub consumer: TpslConsumerDataType,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslMerchantDataType {
    pub identifier: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslUPITokenCart {
    pub item: Vec<TpslUPIItem>,
    pub description: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslUPIItem {
    pub amount: String,
    pub com_amt: String,
    pub s_k_u: String,
    pub reference: String,
    pub identifier: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslUPITokenTxn {
    pub amount: String,
    #[serde(rename = "type")]
    pub txn_type: String,
    pub currency: String,
    pub identifier: String,
    pub sub_type: String,
    pub request_type: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslConsumerDataType {
    pub identifier: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslUPITxnRequest {
    pub merchant: TpslMerchantPayload,
    pub cart: TpslUPITokenCart,
    pub payment: TpslPaymentIntentPayload,
    pub transaction: TpslTransactionPayload,
    pub consumer: TpslConsumerIntentPayload,
    pub merchant_input_flags: TpslFlagsType,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentIntentPayload {
    pub method: TpslMethodUPIPayload,
    pub instrument: TpslUPIInstrumentPayload,
    pub instruction: serde_json::Value,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslMethodUPIPayload {
    pub token: String,
    #[serde(rename = "type")]
    pub method_type: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslUPIInstrumentPayload {
    pub expiry: serde_json::Value,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslConsumerIntentPayload {
    pub mobile_number: String,
    pub email_i_d: String,
    pub identifier: String,
    pub account_no: String,
    pub account_type: String,
    pub account_holder_name: String,
    pub vpa: String,
    pub aadhar_no: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentsSyncRequest {
    pub merchant: TpslMerchantDataType,
    pub payment: TpslPaymentUPISyncType,
    pub transaction: TpslTransactionUPITxnType,
    pub consumer: TpslConsumerDataType,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentUPISyncType {
    pub instruction: serde_json::Value,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslTransactionUPITxnType {
    pub device_identifier: String,
    #[serde(rename = "type")]
    pub txn_type: Option<String>,
    pub sub_type: Option<String>,
    pub amount: String,
    pub currency: String,
    pub date_time: String,
    pub request_type: String,
    pub token: String,
}

// Response types
#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum TpslPaymentsResponse {
    TpslUPISuccessTxnResponse(TpslUPITxnResponse),
    TpslErrorResponse(TpslErrorResponse),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslUPITxnResponse {
    pub merchant_code: String,
    pub merchant_transaction_identifier: String,
    pub merchant_transaction_request_type: String,
    pub response_type: String,
    pub transaction_state: String,
    pub merchant_additional_details: serde_json::Value,
    pub payment_method: TpslUPIPaymentPayload,
    pub error: Option<serde_json::Value>,
    pub merchant_response_string: Option<serde_json::Value>,
    pub pdf_download_url: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslUPIPaymentPayload {
    pub token: Option<String>,
    pub instrument_alias_name: String,
    pub instrument_token: String,
    pub bank_selection_code: String,
    pub a_c_s: TpslAcsPayload,
    pub o_t_p: Option<serde_json::Value>,
    pub payment_transaction: TpslPaymentTxnPayload,
    pub authentication: Option<serde_json::Value>,
    pub error: TpslPaymentMethodErrorPayload,
    pub payment_mode: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslAcsPayload {
    pub bank_acs_form_name: String,
    pub bank_acs_http_method: serde_json::Value,
    pub bank_acs_params: Option<serde_json::Value>,
    pub bank_acs_url: serde_json::Value,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentTxnPayload {
    pub amount: String,
    pub balance_amount: Option<String>,
    pub bank_reference_identifier: Option<String>,
    pub date_time: Option<String>,
    pub error_message: Option<String>,
    pub identifier: Option<String>,
    pub refund_identifier: String,
    pub status_code: String,
    pub status_message: String,
    pub instruction: Option<serde_json::Value>,
    pub reference: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentMethodErrorPayload {
    pub code: String,
    pub desc: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslErrorResponse {
    pub error_code: String,
    pub error_message: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslUPISyncResponse {
    pub merchant_code: String,
    pub merchant_transaction_identifier: String,
    pub merchant_transaction_request_type: String,
    pub response_type: String,
    pub transaction_state: String,
    pub payment_method: TpslUPIPaymentPayload,
    pub error: Option<serde_json::Value>,
    pub merchant_response_string: Option<serde_json::Value>,
    pub status_code: Option<String>,
    pub status_message: Option<String>,
    pub identifier: Option<String>,
    pub bank_reference_identifier: Option<String>,
    pub merchant_additional_details: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslAuthType {
    pub merchant_code: String,
    pub secret_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for TpslAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey { api_key, .. } => {
                // For now, create a simple auth type from the API key
                // In a real implementation, this would parse the JSON structure
                Ok(TpslAuthType {
                    merchant_code: "default".to_string(),
                    secret_key: api_key.clone(),
                })
            }
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > TryFrom<TPSLRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>>
    for TpslPaymentsRequest
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: TPSLRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let auth = TpslAuthType::try_from(&item.router_data.connector_auth_type)?;
        let return_url = item.router_data.request.get_router_return_url()?;
        let amount = item.router_data.request.minor_amount.to_string();
        let currency = item.router_data.request.currency.to_string();
        let transaction_id = item.router_data.resource_common_data.connector_request_reference_id.clone();
        
        // For UPI payments, create UPI transaction request
        match item.router_data.request.payment_method_type {
            Some(common_enums::PaymentMethodType::UpiCollect) => {
                let upi_request = TpslUPITxnRequest {
                    merchant: TpslMerchantPayload {
                        webhook_endpoint_url: return_url.clone(),
                        response_type: "URL".to_string(),
                        response_endpoint_url: return_url.clone(),
                        description: "UPI Payment".to_string(),
                        identifier: auth.merchant_code,
                        webhook_type: "HTTP".to_string(),
                    },
                    cart: TpslUPITokenCart {
                        item: vec![TpslUPIItem {
                            amount: amount.clone(),
                            com_amt: "0".to_string(),
                            s_k_u: "UPI".to_string(),
                            reference: transaction_id.clone(),
                            identifier: "1".to_string(),
                        }],
                        description: Some("UPI Payment".to_string()),
                    },
                    payment: TpslPaymentIntentPayload {
                        method: TpslMethodUPIPayload {
                            token: "UPI".to_string(),
                            method_type: "UPI".to_string(),
                        },
                        instrument: TpslUPIInstrumentPayload {
                            expiry: serde_json::Value::Null,
                        },
                        instruction: serde_json::Value::Null,
                    },
                    transaction: TpslTransactionPayload {
                        device_identifier: "WEB".to_string(),
                        sms_sending: "N".to_string(),
                        amount,
                        forced_3_d_s_call: "N".to_string(),
                        transaction_type: "SALE".to_string(),
                        description: "UPI Payment".to_string(),
                        currency,
                        is_registration: "N".to_string(),
                        identifier: transaction_id.clone(),
                        date_time: "2025-01-01 00:00:00".to_string(),
                        token: "".to_string(),
                        security_token: auth.secret_key.expose().clone(),
                        sub_type: "SALE".to_string(),
                        request_type: "TXN".to_string(),
                        reference: transaction_id,
                        merchant_initiated: "N".to_string(),
                        tenure_id: "".to_string(),
                    },
                    consumer: TpslConsumerIntentPayload {
                        mobile_number: "".to_string(), // Phone not available in current structure
                        email_i_d: item.router_data.request.email.as_ref().map(|e| e.expose().to_string()).unwrap_or_default(),
                        identifier: item.router_data.resource_common_data.get_customer_id()?.get_string_repr().to_string(),
                        account_no: "".to_string(),
                        account_type: "".to_string(),
                        account_holder_name: "".to_string(),
                        vpa: "".to_string(), // Will be filled from payment method data
                        aadhar_no: "".to_string(),
                    },
                    merchant_input_flags: TpslFlagsType {
                        account_no: false,
                        mobile_number: true,
                        email_i_d: true,
                        card_details: false,
                        mandate_details: false,
                    },
                };

                // Convert UPI request to generic request
                Ok(Self {
                    merchant: upi_request.merchant,
                    cart: TpslCartPayload {
                        item: upi_request.cart.item.into_iter().map(|item| TpslItemPayload {
                            description: "UPI Payment".to_string(),
                            provider_identifier: "UPI".to_string(),
                            surcharge_or_discount_amount: "0".to_string(),
                            amount: item.amount,
                            com_amt: item.com_amt,
                            s_k_u: item.s_k_u,
                            reference: item.reference,
                            identifier: item.identifier,
                        }).collect(),
                        reference: transaction_id.clone(),
                        identifier: "1".to_string(),
                        description: "UPI Payment".to_string(),
                    },
                    payment: TpslPaymentPayload {
                        method: TpslMethodPayload {
                            token: upi_request.payment.method.token,
                            method_type: upi_request.payment.method.method_type,
                            code: "UPI".to_string(),
                        },
                        instrument: TpslInstrumentPayload {
                            expiry: None,
                            provider: "UPI".to_string(),
                            i_f_s_c: "".to_string(),
                            holder: None,
                            b_i_c: "".to_string(),
                            instrument_type: "UPI".to_string(),
                            action: "SALE".to_string(),
                            m_i_c_r: "".to_string(),
                            verification_code: "".to_string(),
                            i_b_a_n: "".to_string(),
                            processor: "UPI".to_string(),
                            issuance: None,
                            alias: "".to_string(),
                            identifier: "".to_string(),
                            token: "".to_string(),
                            authentication: None,
                            sub_type: "COLLECT".to_string(),
                            issuer: "".to_string(),
                            acquirer: "".to_string(),
                        },
                        instruction: TpslInstructionPayload {
                            occurrence: "".to_string(),
                            amount: "".to_string(),
                            frequency: "".to_string(),
                            instruction_type: "".to_string(),
                            description: "".to_string(),
                            action: "".to_string(),
                            limit: "".to_string(),
                            end_date_time: "".to_string(),
                            debit_day: "".to_string(),
                            debit_flag: "".to_string(),
                            identifier: "".to_string(),
                            reference: "".to_string(),
                            start_date_time: "".to_string(),
                            validity: "".to_string(),
                        },
                    },
                    transaction: upi_request.transaction,
                    consumer: TpslConsumerPayload {
                        mobile_number: upi_request.consumer.mobile_number,
                        email_i_d: upi_request.consumer.email_i_d,
                        identifier: upi_request.consumer.identifier,
                        account_no: upi_request.consumer.account_no,
                        account_type: upi_request.consumer.account_type,
                        account_holder_name: upi_request.consumer.account_holder_name,
                        aadhar_no: upi_request.consumer.aadhar_no,
                    },
                    merchant_input_flags: Some(upi_request.merchant_input_flags),
                })
            }
            _ => Err(errors::ConnectorError::NotImplemented("Payment method".to_string()).into()),
        }
    }
}

impl TryFrom<TPSLRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>>
    for TpslPaymentsSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: TPSLRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let auth = TpslAuthType::try_from(&item.router_data.connector_auth_type)?;
        let transaction_id = item.router_data.resource_common_data.connector_request_reference_id.clone();
        
        Ok(Self {
            merchant: TpslMerchantDataType {
                identifier: auth.merchant_code,
            },
            payment: TpslPaymentUPISyncType {
                instruction: serde_json::Value::Null,
            },
            transaction: TpslTransactionUPITxnType {
                device_identifier: "WEB".to_string(),
                txn_type: Some("SALE".to_string()),
                sub_type: Some("SALE".to_string()),
                amount: item.router_data.request.amount.to_string(),
                currency: item.router_data.request.currency.to_string(),
                date_time: "2025-01-01 00:00:00".to_string(),
                request_type: "STATUS".to_string(),
                token: auth.secret_key.expose().clone(),
            },
            consumer: TpslConsumerDataType {
                identifier: item.router_data.resource_common_data.get_customer_id()?.get_string_repr().to_string(),
            },
        })
    }
}

impl<
        F,
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > TryFrom<ResponseRouterData<TpslPaymentsResponse, RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>>
    for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: ResponseRouterData<TpslPaymentsResponse, RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;
        
        let (status, response) = match response {
            TpslPaymentsResponse::TpslUPISuccessTxnResponse(response_data) => {
                let attempt_status = match response_data.transaction_state.as_str() {
                    "SUCCESS" | "SUCCESSFUL" => common_enums::AttemptStatus::Charged,
                    "PENDING" | "INITIATED" => common_enums::AttemptStatus::AuthenticationPending,
                    "FAILED" => common_enums::AttemptStatus::Failure,
                    _ => common_enums::AttemptStatus::Pending,
                };
                
                let merchant_txn_id = response_data.merchant_transaction_identifier.clone();
                let network_txn_id = response_data.payment_method.payment_transaction.identifier.clone();
                
                (
                    attempt_status,
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(merchant_txn_id),
                        redirection_data: None,
                        mandate_reference: None,
                        connector_metadata: Some(serde_json::to_value(&response_data).unwrap_or_default()),
                        network_txn_id,
                        connector_response_reference_id: Some(response_data.merchant_transaction_identifier),
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                    }),
                )
            }
            TpslPaymentsResponse::TpslErrorResponse(error_data) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: error_data.error_code,
                    status_code: http_code,
                    message: error_data.error_message.clone(),
                    reason: Some(error_data.error_message),
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }),
            ),
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            response,
            ..router_data
        })
    }
}

impl TryFrom<ResponseRouterData<TpslUPISyncResponse, RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>>
    for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: ResponseRouterData<TpslUPISyncResponse, RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;
        
        let response_data = PaymentsResponseData::try_from(response)?;
        
        Ok(Self {
            resource_common_data: PaymentFlowData {
                status: common_enums::AttemptStatus::Charged, // This should be determined from response
                ..router_data.resource_common_data
            },
            response: Ok(response_data),
            ..router_data
        })
    }
}

impl TryFrom<TpslUPISyncResponse> for PaymentsResponseData
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(response: TpslUPISyncResponse) -> Result<Self, Self::Error> {
        let _attempt_status = match response.transaction_state.as_str() {
            "SUCCESS" | "SUCCESSFUL" => common_enums::AttemptStatus::Charged,
            "PENDING" | "INITIATED" => common_enums::AttemptStatus::AuthenticationPending,
            "FAILED" => common_enums::AttemptStatus::Failure,
            _ => common_enums::AttemptStatus::Pending,
        };

        Ok(PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(response.merchant_transaction_identifier.clone()),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: Some(serde_json::to_value(&response).unwrap_or_default()),
            network_txn_id: response.payment_method.payment_transaction.identifier,
            connector_response_reference_id: Some(response.merchant_transaction_identifier),
            incremental_authorization_allowed: None,
            status_code: 200,
        })
    }
}