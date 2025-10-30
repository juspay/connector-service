use std::collections::HashMap;

use common_utils::{
    errors::CustomResult, request::Method, types::StringMinorUnit,
    pii::IpAddress,
};
use domain_types::{
    connector_flow::{Authorize, PSync},
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, ResponseId},
    errors::{self, ConnectorError},
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
};
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};

use crate::{connectors::billdesk::BilldeskRouterData, types::ResponseRouterData};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BilldeskAuth {
    pub merchant_id: Secret<String>,
    pub checksum_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for BilldeskAuth {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey { api_key, key1, .. } => Ok(Self {
                merchant_id: api_key.clone(),
                checksum_key: key1.unwrap_or_else(|| Secret::new("".to_string())),
            }),
            ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self {
                merchant_id: api_key.clone(),
                checksum_key: key1,
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskPaymentsRequest {
    pub msg: String,
    pub useragent: String,
    pub ipaddress: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskPaymentsSyncRequest {
    pub msg: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum BilldeskPaymentsResponse {
    Success(BilldeskSuccessResponse),
    Error(BilldeskErrorResponse),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BilldeskPaymentsSyncResponse {
    pub msg: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskSuccessResponse {
    pub msg: Option<String>,
    pub rdata: Option<BilldeskResponseData>,
    pub txnrefno: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskResponseData {
    pub parameters: HashMap<String, String>,
    pub url: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskErrorResponse {
    pub error: String,
    pub error_description: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskAuthorizationResponseMsg {
    #[serde(rename = "_MerchantID")]
    pub merchant_id: String,
    #[serde(rename = "_CustomerID")]
    pub customer_id: String,
    #[serde(rename = "_TxnReferenceNo")]
    pub txn_reference_no: String,
    #[serde(rename = "_BankReferenceNo")]
    pub bank_reference_no: String,
    #[serde(rename = "_TxnAmount")]
    pub txn_amount: String,
    #[serde(rename = "_BankID")]
    pub bank_id: String,
    #[serde(rename = "_TxnType")]
    pub txn_type: String,
    #[serde(rename = "_CurrencyType")]
    pub currency_type: String,
    #[serde(rename = "_ItemCode")]
    pub item_code: String,
    #[serde(rename = "_TxnDate")]
    pub txn_date: String,
    #[serde(rename = "_AuthStatus")]
    pub auth_status: String,
    #[serde(rename = "_AdditionalInfo1")]
    pub additional_info_1: Option<String>,
    #[serde(rename = "_AdditionalInfo2")]
    pub additional_info_2: Option<String>,
    #[serde(rename = "_AdditionalInfo3")]
    pub additional_info_3: Option<String>,
    #[serde(rename = "_AdditionalInfo4")]
    pub additional_info_4: Option<String>,
    #[serde(rename = "_AdditionalInfo5")]
    pub additional_info_5: Option<String>,
    #[serde(rename = "_AdditionalInfo6")]
    pub additional_info_6: Option<String>,
    #[serde(rename = "_AdditionalInfo7")]
    pub additional_info_7: Option<String>,
    #[serde(rename = "_ErrorStatus")]
    pub error_status: String,
    #[serde(rename = "_ErrorDescription")]
    pub error_description: String,
    #[serde(rename = "_Checksum")]
    pub checksum: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskStatusResponseMsg {
    #[serde(rename = "_RequestType")]
    pub request_type: Option<String>,
    #[serde(rename = "_MerchantID")]
    pub merchant_id: String,
    #[serde(rename = "_CustomerID")]
    pub customer_id: String,
    #[serde(rename = "_TxnReferenceNo")]
    pub txn_reference_no: String,
    #[serde(rename = "_BankReferenceNo")]
    pub bank_reference_no: String,
    #[serde(rename = "_TxnAmount")]
    pub txn_amount: String,
    #[serde(rename = "_BankID")]
    pub bank_id: String,
    #[serde(rename = "_TxnType")]
    pub txn_type: Option<String>,
    #[serde(rename = "_CurrencyType")]
    pub currency_type: String,
    #[serde(rename = "_ItemCode")]
    pub item_code: String,
    #[serde(rename = "_TxnDate")]
    pub txn_date: Option<String>,
    #[serde(rename = "_AuthStatus")]
    pub auth_status: String,
    #[serde(rename = "_AdditionalInfo1")]
    pub additional_info_1: Option<String>,
    #[serde(rename = "_AdditionalInfo2")]
    pub additional_info_2: Option<String>,
    #[serde(rename = "_AdditionalInfo3")]
    pub additional_info_3: Option<String>,
    #[serde(rename = "_AdditionalInfo4")]
    pub additional_info_4: Option<String>,
    #[serde(rename = "_AdditionalInfo5")]
    pub additional_info_5: Option<String>,
    #[serde(rename = "_AdditionalInfo6")]
    pub additional_info_6: Option<String>,
    #[serde(rename = "_AdditionalInfo7")]
    pub additional_info_7: Option<String>,
    #[serde(rename = "_ErrorStatus")]
    pub error_status: String,
    #[serde(rename = "_ErrorDescription")]
    pub error_description: String,
    #[serde(rename = "_RefundStatus")]
    pub refund_status: String,
    #[serde(rename = "_TotalRefundAmount")]
    pub total_refund_amount: String,
    #[serde(rename = "_LastRefundDate")]
    pub last_refund_date: Option<String>,
    #[serde(rename = "_LastRefundRefNo")]
    pub last_refund_ref_no: Option<String>,
    #[serde(rename = "_QueryStatus")]
    pub query_status: String,
    #[serde(rename = "_Checksum")]
    pub checksum: String,
}

fn build_billdesk_message(
    auth: &BilldeskAuth,
    router_data: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<impl PaymentMethodDataTypes>, PaymentsResponseData>,
    amount_converter: &dyn common_utils::types::AmountConvertor<Output = common_utils::types::StringMajorUnit>,
) -> CustomResult<String, errors::ConnectorError> {
    let customer_id = router_data.resource_common_data.get_customer_id()?;
    let amount = amount_converter.convert(
        router_data.request.minor_amount,
        router_data.request.currency,
    ).map_err(|_| errors::ConnectorError::AmountConversionFailed)?;

    let mut message_data = HashMap::new();
    message_data.insert("merchantid".to_string(), auth.merchant_id.peek().to_string());
    message_data.insert("customerid".to_string(), customer_id.get_string_repr().to_string());
    message_data.insert("txnreferenceNo".to_string(), router_data.resource_common_data.connector_request_reference_id.clone());
    message_data.insert("txnamount".to_string(), amount);
    message_data.insert("currency".to_string(), router_data.request.currency.to_string());
    message_data.insert("itemcode".to_string(), "DIRECT".to_string());
    message_data.insert("txntype".to_string(), "UPI".to_string());
    
    // Add UPI specific fields
    if matches!(router_data.resource_common_data.payment_method, common_enums::PaymentMethod::Upi) {
        message_data.insert("additionalInfo1".to_string(), "UPI".to_string());
        message_data.insert("additionalInfo2".to_string(), "COLLECT".to_string());
    }

    // Create the message string in the format expected by Billdesk
    let message_parts: Vec<String> = [
        "merchantid", "customerid", "txnreferenceNo", "bankreferenceNo", "txnamount",
        "bankid", "txntype", "currencytype", "itemcode", "securitytype", "securityid",
        "securitypassword", "txndate", "authstatus", "settlementtype", "additionalInfo1",
        "additionalInfo2", "additionalInfo3", "additionalInfo4", "additionalInfo5",
        "additionalInfo6", "additionalInfo7", "errorstatus", "errordescription", "checksum"
    ]
    .iter()
    .map(|&key| message_data.get(key).cloned().unwrap_or_default())
    .collect();

    Ok(message_parts.join("|"))
}

fn build_status_message(
    auth: &BilldeskAuth,
    router_data: &RouterDataV2<PSync, PaymentFlowData, domain_types::connector_types::PaymentsSyncData, PaymentsResponseData>,
) -> CustomResult<String, errors::ConnectorError> {
    let mut message_data = HashMap::new();
    message_data.insert("merchantid".to_string(), auth.merchant_id.peek().to_string());
    message_data.insert("customerid".to_string(), "".to_string()); // Will be filled from response
    message_data.insert("txnreferenceNo".to_string(), router_data.resource_common_data.connector_request_reference_id.clone());
    message_data.insert("requesttype".to_string(), "STATUS".to_string());

    let message_parts: Vec<String> = [
        "requesttype", "merchantid", "customerid", "txnreferenceNo", "bankreferenceNo",
        "txnamount", "bankid", "txntype", "currencytype", "itemcode", "securitytype",
        "securityid", "securitypassword", "txndate", "authstatus", "settlementtype",
        "additionalInfo1", "additionalInfo2", "additionalInfo3", "additionalInfo4",
        "additionalInfo5", "additionalInfo6", "additionalInfo7", "errorstatus",
        "errordescription", "refundstatus", "totalrefundamount", "lastrefunddate",
        "lastrefundrefno", "querystatus", "checksum"
    ]
    .iter()
    .map(|&key| message_data.get(key).cloned().unwrap_or_default())
    .collect();

    Ok(message_parts.join("|"))
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    TryFrom<BilldeskRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>>
    for BilldeskPaymentsRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: BilldeskRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let auth = BilldeskAuth::try_from(&item.router_data.connector_auth_type)?;
        
        let msg = build_billdesk_message(&auth, &item.router_data, item.connector.amount_converter)?;
        
        let user_agent = item.router_data.request.browser_info
            .as_ref()
            .and_then(|info| info.user_agent.clone())
            .unwrap_or_else(|| "Mozilla/5.0".to_string());

        let ip_address = item.router_data.request.get_ip_address_as_optional()
            .map(|ip| ip.peek().to_string())
            .unwrap_or_else(|| "127.0.0.1".to_string());

        Ok(Self {
            msg,
            useragent: user_agent,
            ipaddress: ip_address,
        })
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    TryFrom<BilldeskRouterData<RouterDataV2<PSync, PaymentFlowData, domain_types::connector_types::PaymentsSyncData, PaymentsResponseData>, T>>
    for BilldeskPaymentsSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: BilldeskRouterData<RouterDataV2<PSync, PaymentFlowData, domain_types::connector_types::PaymentsSyncData, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let auth = BilldeskAuth::try_from(&item.router_data.connector_auth_type)?;
        
        let msg = build_status_message(&auth, &item.router_data)?;

        Ok(Self { msg })
    }
}

fn map_billdesk_status(status: &str) -> common_enums::AttemptStatus {
    match status {
        "0300" => common_enums::AttemptStatus::Charged,
        "0002" => common_enums::AttemptStatus::AuthenticationPending,
        "0399" => common_enums::AttemptStatus::Failure,
        _ => common_enums::AttemptStatus::Pending,
    }
}

impl<F, T> TryFrom<ResponseRouterData<BilldeskPaymentsResponse, RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>>
    for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize,
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<BilldeskPaymentsResponse, RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let (status, response) = match response {
            BilldeskPaymentsResponse::Success(success_response) => {
                if let Some(rdata) = success_response.rdata {
                    if let Some(url) = rdata.url {
                        let redirect_form = RedirectForm::Form {
                            endpoint: url,
                            method: Method::Get,
                            form_fields: rdata.parameters,
                        };
                        
                        (
                            common_enums::AttemptStatus::AuthenticationPending,
                            Ok(PaymentsResponseData::TransactionResponse {
                                resource_id: ResponseId::ConnectorTransactionId(
                                    router_data.resource_common_data.connector_request_reference_id.clone(),
                                ),
                                redirection_data: Some(Box::new(redirect_form)),
                                mandate_reference: None,
                                connector_metadata: None,
                                network_txn_id: success_response.txnrefno.clone(),
                                connector_response_reference_id: None,
                                incremental_authorization_allowed: None,
                                status_code: http_code,
                            }),
                        )
                    } else {
                        (
                            common_enums::AttemptStatus::Pending,
                            Ok(PaymentsResponseData::TransactionResponse {
                                resource_id: ResponseId::ConnectorTransactionId(
                                    router_data.resource_common_data.connector_request_reference_id.clone(),
                                ),
                                redirection_data: None,
                                mandate_reference: None,
                                connector_metadata: None,
                                network_txn_id: success_response.txnrefno.clone(),
                                connector_response_reference_id: None,
                                incremental_authorization_allowed: None,
                                status_code: http_code,
                            }),
                        )
                    }
                } else {
                    (
                        common_enums::AttemptStatus::Pending,
                        Ok(PaymentsResponseData::TransactionResponse {
                            resource_id: ResponseId::ConnectorTransactionId(
                                router_data.resource_common_data.connector_request_reference_id.clone(),
                            ),
                            redirection_data: None,
                            mandate_reference: None,
                            connector_metadata: None,
                            network_txn_id: success_response.txnrefno.clone(),
                            connector_response_reference_id: None,
                            incremental_authorization_allowed: None,
                            status_code: http_code,
                        }),
                    )
                }
            }
            BilldeskPaymentsResponse::Error(error_response) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: error_response.error,
                    status_code: http_code,
                    message: error_response.error_description.clone().unwrap_or_default(),
                    reason: error_response.error_description.clone(),
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

impl<F> TryFrom<ResponseRouterData<BilldeskPaymentsResponse, RouterDataV2<F, PaymentFlowData, domain_types::connector_types::PaymentsSyncData, PaymentsResponseData>>>
    for RouterDataV2<F, PaymentFlowData, domain_types::connector_types::PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<BilldeskPaymentsResponse, RouterDataV2<F, PaymentFlowData, domain_types::connector_types::PaymentsSyncData, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        // For sync, we need to parse the response differently
        let response_str = match response {
            BilldeskPaymentsResponse::Success(success) => {
                success.msg.unwrap_or_default()
            }
            BilldeskPaymentsResponse::Error(error) => {
                return Ok(Self {
                    resource_common_data: PaymentFlowData {
                        status: common_enums::AttemptStatus::Failure,
                        ..router_data.resource_common_data
                    },
                    response: Err(ErrorResponse {
                        code: error.error,
                        status_code: http_code,
                        message: error.error_description.clone(),
                        reason: error.error_description.clone(),
                        attempt_status: None,
                        connector_transaction_id: None,
                        network_advice_code: None,
                        network_decline_code: None,
                        network_error_message: None,
                    }),
                    ..router_data
                });
            }
        };

        // Parse the response message to extract status
        let parts: Vec<&str> = response_str.split('|').collect();
        let auth_status = parts.get(14).unwrap_or(&"0399"); // Default to failure
        
        let status = map_billdesk_status(auth_status);
        let txn_reference_no = parts.get(2).unwrap_or(&"").to_string();
        let bank_reference_no = parts.get(3).unwrap_or(&"").to_string();
        let txn_amount = parts.get(4).unwrap_or(&"0").to_string();

        let response_data = if status == common_enums::AttemptStatus::Charged {
            Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(txn_reference_no),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: Some(bank_reference_no),
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                status_code: http_code,
            })
        } else {
            Err(ErrorResponse {
                code: auth_status.to_string(),
                status_code: http_code,
                message: format!("Transaction status: {}", auth_status),
                reason: Some(format!("Transaction status: {}", auth_status)),
                attempt_status: Some(status),
                connector_transaction_id: Some(txn_reference_no),
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
            })
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            response: response_data,
            ..router_data
        })
    }
}