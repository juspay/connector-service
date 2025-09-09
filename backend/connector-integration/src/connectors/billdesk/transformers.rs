use std::collections::HashMap;

use common_utils::{
    errors::CustomResult, ext_traits::ValueExt, id_type, request::Method, types::StringMinorUnit,
    Email,
};
use domain_types::{
    connector_flow::{Authorize, PSync},
    connector_types::{PaymentFlowData, PaymentSyncData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, ResponseId},
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

use crate::{connectors::billdesk::BilldeskRouterData, types::ResponseRouterData};

#[derive(Default, Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskPaymentsRequest {
    pub msg: String,
    pub useragent: String,
    pub ipaddress: String,
}

#[derive(Default, Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskUPIInitiateResponse {
    pub msg: Option<String>,
}

#[derive(Default, Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskUPITransactionResponse {
    #[serde(rename = "_MerchantID")]
    pub merchant_id: String,
    #[serde(rename = "_CustomerID")]
    pub customer_id: String,
    #[serde(rename = "_TxnReferenceNo")]
    pub txn_reference_no: String,
    #[serde(rename = "_BankReferenceNo")]
    pub bank_reference_no: Option<String>,
    #[serde(rename = "_TxnAmount")]
    pub txn_amount: String,
    #[serde(rename = "_BankID")]
    pub bank_id: String,
    #[serde(rename = "_BankMerchantID")]
    pub bank_merchant_id: Option<String>,
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
    #[serde(rename = "_SettlementType")]
    pub settlement_type: Option<String>,
    #[serde(rename = "_AdditionalInfo1")]
    pub additional_info1: Option<String>,
    #[serde(rename = "_AdditionalInfo2")]
    pub additional_info2: Option<String>,
    #[serde(rename = "_AdditionalInfo3")]
    pub additional_info3: Option<String>,
    #[serde(rename = "_AdditionalInfo4")]
    pub additional_info4: Option<String>,
    #[serde(rename = "_AdditionalInfo5")]
    pub additional_info5: Option<String>,
    #[serde(rename = "_AdditionalInfo6")]
    pub additional_info6: Option<String>,
    #[serde(rename = "_AdditionalInfo7")]
    pub additional_info7: Option<String>,
    #[serde(rename = "_ErrorStatus")]
    pub error_status: String,
    #[serde(rename = "_ErrorDescription")]
    pub error_description: String,
    #[serde(rename = "_Checksum")]
    pub checksum: String,
}

#[derive(Default, Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskPaymentsSyncRequest {
    pub msg: String,
}

#[derive(Default, Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct StatusResponseMsg {
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
    #[serde(rename = "_Filler1")]
    pub filler1: Option<String>,
    #[serde(rename = "_TxnType")]
    pub txn_type: Option<String>,
    #[serde(rename = "_CurrencyType")]
    pub currency_type: String,
    #[serde(rename = "_ItemCode")]
    pub item_code: String,
    #[serde(rename = "_Filler2")]
    pub filler2: Option<String>,
    #[serde(rename = "_Filler3")]
    pub filler3: Option<String>,
    #[serde(rename = "_Filler4")]
    pub filler4: Option<String>,
    #[serde(rename = "_TxnDate")]
    pub txn_date: Option<String>,
    #[serde(rename = "_AuthStatus")]
    pub auth_status: String,
    #[serde(rename = "_Filler5")]
    pub filler5: Option<String>,
    #[serde(rename = "_AdditionalInfo1")]
    pub additional_info1: Option<String>,
    #[serde(rename = "_AdditionalInfo2")]
    pub additional_info2: Option<String>,
    #[serde(rename = "_AdditionalInfo3")]
    pub additional_info3: Option<String>,
    #[serde(rename = "_AdditionalInfo4")]
    pub additional_info4: Option<String>,
    #[serde(rename = "_AdditionalInfo5")]
    pub additional_info5: Option<String>,
    #[serde(rename = "_AdditionalInfo6")]
    pub additional_info6: Option<String>,
    #[serde(rename = "_AdditionalInfo7")]
    pub additional_info7: Option<String>,
    #[serde(rename = "_ErrorStatus")]
    pub error_status: String,
    #[serde(rename = "_ErrorDescription")]
    pub error_description: String,
    #[serde(rename = "_Filler6")]
    pub filler6: Option<String>,
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

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskErrorResponse {
    pub error: String,
    pub error_description: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum BilldeskPaymentsResponse {
    Success(BilldeskUPITransactionResponse),
    Error(BilldeskErrorResponse),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum BilldeskPaymentsSyncResponse {
    Success(StatusResponseMsg),
    Error(BilldeskErrorResponse),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpiObject {
    pub vpa: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpiVpa {
    pub vpa: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskAuth {
    pub merchant_id: Option<Secret<String>>,
    pub check_sum_key: Option<Secret<String>>,
}

impl TryFrom<&ConnectorAuthType> for BilldeskAuth {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey { api_key, key1 } => Ok(Self {
                merchant_id: api_key.clone(),
                check_sum_key: key1.clone(),
            }),
            ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self {
                merchant_id: api_key.clone(),
                check_sum_key: key1.clone(),
            }),
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
    >
    TryFrom<
        BilldeskRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for BilldeskPaymentsRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: BilldeskRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = BilldeskAuth::try_from(&item.router_data.connector_auth_type)?;
        
        // Extract UPI payment method data
        let upi_data = match &item.router_data.request.payment_method_data {
            Some(domain_types::payment_method_data::PaymentMethodData::Upi(upi)) => upi,
            _ => return Err(errors::ConnectorError::MissingRequiredField {
                field_name: "upi_payment_method",
            }
            .into()),
        };

        // Get amount in the correct format (string minor units)
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        // Build the message for UPI initiation
        let msg = build_upi_initiate_message(
            &auth,
            &item.router_data.resource_common_data.connector_request_reference_id,
            &amount,
            &item.router_data.request.currency.to_string(),
            &upi_data.vpa,
            &item.router_data.resource_common_data.get_customer_id()?,
        )?;

        Ok(Self {
            msg,
            useragent: item.router_data.request.get_user_agent()?,
            ipaddress: item.router_data.request.get_ip_address()?,
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
    >
    TryFrom<
        BilldeskRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    > for BilldeskPaymentsSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: BilldeskRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = BilldeskAuth::try_from(&item.router_data.connector_auth_type)?;
        
        // Build the message for status sync
        let msg = build_status_sync_message(
            &auth,
            &item.router_data.request.connector_transaction_id,
        )?;

        Ok(Self { msg })
    }
}

fn build_upi_initiate_message(
    auth: &BilldeskAuth,
    transaction_id: &str,
    amount: &str,
    currency: &str,
    vpa: &str,
    customer_id: &str,
) -> CustomResult<String, errors::ConnectorError> {
    // This is a simplified message construction
    // In reality, Billdesk expects a specific format with checksum
    let merchant_id = auth
        .merchant_id
        .as_ref()
        .ok_or(errors::ConnectorError::FailedToObtainAuthType)?
        .peek();

    let message = format!(
        "{}|{}|{}|{}|{}|UPI|{}",
        merchant_id, transaction_id, amount, currency, vpa, customer_id
    );

    // TODO: Add checksum calculation using check_sum_key
    // For now, return the message without checksum
    Ok(message)
}

fn build_status_sync_message(
    auth: &BilldeskAuth,
    transaction_id: &str,
) -> CustomResult<String, errors::ConnectorError> {
    let merchant_id = auth
        .merchant_id
        .as_ref()
        .ok_or(errors::ConnectorError::FailedToObtainAuthType)?
        .peek();

    let message = format!("{}|{}", merchant_id, transaction_id);

    // TODO: Add checksum calculation using check_sum_key
    // For now, return the message without checksum
    Ok(message)
}

impl<F, T> TryFrom<ResponseRouterData<BilldeskPaymentsResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
where
    F: Clone,
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<BilldeskPaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let (status, response) = match response {
            BilldeskPaymentsResponse::Success(transaction_response) => {
                let attempt_status = map_auth_status(&transaction_response.auth_status);
                
                (
                    attempt_status,
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(
                            transaction_response.txn_reference_no.clone(),
                        ),
                        redirection_data: None,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: transaction_response.bank_reference_no,
                        connector_response_reference_id: None,
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                    }),
                )
            }
            BilldeskPaymentsResponse::Error(error_response) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: error_response.error,
                    status_code: http_code,
                    message: error_response.error_description.clone(),
                    reason: error_response.error_description,
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

impl<F, T> TryFrom<ResponseRouterData<BilldeskPaymentsSyncResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
where
    F: Clone,
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<BilldeskPaymentsSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let (status, response) = match response {
            BilldeskPaymentsSyncResponse::Success(status_response) => {
                let attempt_status = map_auth_status(&status_response.auth_status);
                
                (
                    attempt_status,
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(
                            status_response.txn_reference_no.clone(),
                        ),
                        redirection_data: None,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: Some(status_response.bank_reference_no),
                        connector_response_reference_id: None,
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                    }),
                )
            }
            BilldeskPaymentsSyncResponse::Error(error_response) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: error_response.error,
                    status_code: http_code,
                    message: error_response.error_description.clone(),
                    reason: error_response.error_description,
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

fn map_auth_status(auth_status: &str) -> common_enums::AttemptStatus {
    match auth_status.to_uppercase().as_str() {
        "0300" | "SUCCESS" => common_enums::AttemptStatus::Charged,
        "0301" | "PENDING" => common_enums::AttemptStatus::Pending,
        "0399" | "FAILED" => common_enums::AttemptStatus::Failure,
        "0302" | "AUTHENTICATION_PENDING" => common_enums::AttemptStatus::AuthenticationPending,
        _ => common_enums::AttemptStatus::Pending,
    }
}