use std::collections::HashMap;

use common_utils::{
    request::Method, types::StringMinorUnit,
    Email,
};
use hyperswitch_masking::{ExposeInterface, Secret};
use domain_types::{
    connector_flow::{Authorize, PSync},
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, ResponseId},
    errors::{self, ConnectorError},
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
};
use error_stack::ResultExt;
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};

use crate::{connectors::easebuzz::EaseBuzzRouterData, types::ResponseRouterData};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzPaymentsRequest {
    pub txnid: String,
    pub amount: StringMinorUnit,
    pub productinfo: String,
    pub firstname: Option<String>,
    pub email: Option<Email>,
    pub phone: Option<String>,
    pub surl: String,
    pub furl: String,
    pub udf1: Option<String>,
    pub udf2: Option<String>,
    pub udf3: Option<String>,
    pub udf4: Option<String>,
    pub udf5: Option<String>,
    pub udf6: Option<String>,
    pub udf7: Option<String>,
    pub udf8: Option<String>,
    pub udf9: Option<String>,
    pub udf10: Option<String>,
    pub hash: Secret<String>,
    pub payment_source: String,
    pub pg: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzPaymentsSyncRequest {
    pub txnid: String,
    pub amount: StringMinorUnit,
    pub email: Option<Email>,
    pub phone: Option<String>,
    pub key: String,
    pub hash: Secret<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzPaymentsResponse {
    pub status: i32,
    pub error_desc: Option<String>,
    pub data: Option<EaseBuzzResponseData>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzResponseData {
    pub easebuzz_id: Option<String>,
    pub payment_source: Option<String>,
    pub txnid: Option<String>,
    pub amount: Option<String>,
    pub status: Option<String>,
    pub name_on_card: Option<String>,
    pub card_no: Option<String>,
    pub card_type: Option<String>,
    pub card_token: Option<String>,
    pub bank_ref_num: Option<String>,
    pub bankcode: Option<String>,
    pub error_message: Option<String>,
    pub net_amount_debit: Option<String>,
    pub addedon: Option<String>,
    pub card_category: Option<String>,
    pub emi_plan_id: Option<String>,
    pub emi_tenure_id: Option<String>,
    pub card_brand: Option<String>,
    pub card_issuer: Option<String>,
    pub card_issuer_country: Option<String>,
    pub settlement_date: Option<String>,
    pub surcharge_amount: Option<String>,
    pub gst_amount: Option<String>,
    pub pg_type: Option<String>,
    pub bank_txn_id: Option<String>,
    pub merchant_txn_id: Option<String>,
    pub upi_vpa: Option<String>,
    pub upi_intent_url: Option<String>,
    pub upi_qr_code: Option<String>,
    pub mandate_reg_ref_id: Option<String>,
    pub mandate_status: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzPaymentsSyncResponse {
    pub status: bool,
    pub msg: EaseBuzzTxnSyncMessageType,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum EaseBuzzTxnSyncMessageType {
    Success(EaseBuzzResponseData),
    Error(String),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzErrorResponse {
    pub status: i32,
    pub error_desc: String,
    pub data: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzAuth {
    pub key: Secret<String>,
    pub salt: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for EaseBuzzAuth {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey { api_key, key1, .. } => Ok(Self {
                key: api_key.clone(),
                salt: key1.clone().unwrap_or_else(|| Secret::new("".to_string())),
            }),
            ConnectorAuthType::Key { api_key } => Ok(Self {
                key: api_key.clone(),
                salt: Secret::new("".to_string()), // Default salt if not provided
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<EaseBuzzRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>>
    for EaseBuzzPaymentsRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: EaseBuzzRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let auth = EaseBuzzAuth::try_from(&item.router_data.connector_auth_type)?;
        let customer_id = item.router_data.resource_common_data.get_customer_id()?;
        let return_url = item.router_data.request.get_router_return_url()?;
        
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        // Generate hash - this would typically involve SHA512 hashing
        let hash_string = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            auth.key.expose(),
            item.router_data.resource_common_data.connector_request_reference_id,
            amount.to_string(),
            "Product Info", // productinfo
            customer_id.get_string_repr(), // firstname
            item.router_data.request.email.as_ref().map(|e| e.expose().clone()).unwrap_or_default(),
            "", // phone
            return_url, // surl
            return_url, // furl
            "", // udf1-10
            "", "", "", "", "", "", "", "", "",
            auth.salt.expose()
        );
        
        let hash = Secret::new(hash_string); // In real implementation, this would be SHA512 hash

        Ok(Self {
            txnid: item.router_data.resource_common_data.connector_request_reference_id.clone(),
            amount,
            productinfo: "Product Info".to_string(),
            firstname: Some(customer_id.get_string_repr().to_string()),
            email: item.router_data.request.email.clone(),
            phone: None,
            surl: return_url.clone(),
            furl: return_url,
            udf1: None,
            udf2: None,
            udf3: None,
            udf4: None,
            udf5: None,
            udf6: None,
            udf7: None,
            udf8: None,
            udf9: None,
            udf10: None,
            hash,
            payment_source: "upi".to_string(),
            pg: "upi".to_string(),
        })
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<EaseBuzzRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>>
    for EaseBuzzPaymentsSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: EaseBuzzRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let auth = EaseBuzzAuth::try_from(&item.router_data.connector_auth_type)?;
        
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        // Generate hash for sync request
        let hash_string = format!(
            "{}|{}|{}|{}|{}|{}|{}",
            auth.key.expose(),
            item.router_data.request.connector_transaction_id.get_connector_transaction_id()
                .map_err(|_| errors::ConnectorError::MissingRequiredField { field_name: "connector_transaction_id" })?,
            amount.to_string(),
            "", // email - not available in sync data
            "", // phone
            auth.salt.expose(),
            "ver1" // additional parameter
        );
        
        let hash = Secret::new(hash_string); // In real implementation, this would be SHA512 hash

        Ok(Self {
            txnid: item.router_data.request.connector_transaction_id.get_connector_transaction_id()
                .map_err(|_| errors::ConnectorError::MissingRequiredField { field_name: "connector_transaction_id" })?,
            amount,
            email: None,
            phone: None,
            key: auth.key.expose(),
            hash,
        })
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<ResponseRouterData<EaseBuzzPaymentsResponse, RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>>
    for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<EaseBuzzPaymentsResponse, RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let (status, response_data) = if response.status == 1 {
            // Success case
            if let Some(data) = response.data {
                let redirection_data = if let Some(upi_intent_url) = data.upi_intent_url {
                    Some(Box::new(RedirectForm::Form {
                        endpoint: upi_intent_url,
                        method: Method::Get,
                        form_fields: HashMap::new(),
                    }))
                } else if let Some(upi_qr_code) = data.upi_qr_code {
                    Some(Box::new(RedirectForm::Form {
                        endpoint: upi_qr_code,
                        method: Method::Get,
                        form_fields: HashMap::new(),
                    }))
                } else {
                    None
                };

                (
                    common_enums::AttemptStatus::AuthenticationPending,
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(
                            data.txnid.unwrap_or_else(|| router_data.resource_common_data.connector_request_reference_id.clone()),
                        ),
                        redirection_data,
                        mandate_reference: data.mandate_reg_ref_id.map(|id| ResponseId::ConnectorMandateId(id)),
                        connector_metadata: None,
                        network_txn_id: data.bank_txn_id,
                        connector_response_reference_id: data.easebuzz_id,
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                    }),
                )
            } else {
                (
                    common_enums::AttemptStatus::Failure,
                    Err(ErrorResponse {
                        status_code: http_code,
                        code: "NO_DATA".to_string(),
                        message: "No response data received".to_string(),
                        reason: Some("No response data received".to_string()),
                        attempt_status: None,
                        connector_transaction_id: None,
                        network_advice_code: None,
                        network_decline_code: None,
                        network_error_message: None,
                    }),
                )
            }
        } else {
            // Error case
            (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    status_code: http_code,
                    code: response.status.to_string(),
                    message: response.error_desc.unwrap_or_else(|| "Unknown error".to_string()),
                    reason: response.error_desc,
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }),
            )
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

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<ResponseRouterData<EaseBuzzPaymentsSyncResponse, RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>>
    for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<EaseBuzzPaymentsSyncResponse, RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let (status, response_data) = if response.status {
            match response.msg {
                EaseBuzzTxnSyncMessageType::Success(data) => {
                    let attempt_status = match data.status.as_deref() {
                        Some("success") => common_enums::AttemptStatus::Charged,
                        Some("pending") => common_enums::AttemptStatus::Pending,
                        Some("failure") | Some("failed") => common_enums::AttemptStatus::Failure,
                        _ => common_enums::AttemptStatus::Pending,
                    };

                    (
                        attempt_status,
                        Ok(PaymentsResponseData::TransactionResponse {
                            resource_id: ResponseId::ConnectorTransactionId(
                                data.txnid.unwrap_or_else(|| router_data.resource_common_data.connector_request_reference_id.clone()),
                            ),
                            redirection_data: None,
                            mandate_reference: data.mandate_reg_ref_id.map(|id| ResponseId::ConnectorMandateId(id)),
                            connector_metadata: None,
                            network_txn_id: data.bank_txn_id,
                            connector_response_reference_id: data.easebuzz_id,
                            incremental_authorization_allowed: None,
                            status_code: http_code,
                        }),
                    )
                }
                EaseBuzzTxnSyncMessageType::Error(error_msg) => (
                    common_enums::AttemptStatus::Failure,
                    Err(ErrorResponse {
                        status_code: http_code,
                        code: "SYNC_ERROR".to_string(),
                        message: error_msg,
                        reason: Some(error_msg),
                        attempt_status: None,
                        connector_transaction_id: None,
                        network_advice_code: None,
                        network_decline_code: None,
                        network_error_message: None,
                    }),
                ),
            }
        } else {
            (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    status_code: http_code,
                    code: "SYNC_FAILED".to_string(),
                    message: "Transaction sync failed".to_string(),
                    reason: Some("Transaction sync failed".to_string()),
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }),
            )
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