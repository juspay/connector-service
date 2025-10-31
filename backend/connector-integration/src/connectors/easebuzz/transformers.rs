use common_utils::{
    errors::CustomResult, types::StringMinorUnit,
    Email,
};
use domain_types::{
    connector_flow::{Authorize, PSync},
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, ResponseId},
    errors::{self, ConnectorError},
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
};
use error_stack::ResultExt;
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};

use crate::{connectors::easebuzz::EaseBuzzRouterData, types::ResponseRouterData};

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzPaymentsRequest {
    pub txnid: String,
    pub amount: String,
    pub currency: String,
    pub email: Option<Email>,
    pub phone: Option<String>,
    pub firstname: Option<String>,
    pub lastname: Option<String>,
    pub surl: String,
    pub furl: String,
    pub productinfo: String,
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
    pub key: Secret<String>,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzPaymentsSyncRequest {
    pub txnid: String,
    pub amount: String,
    pub email: String,
    pub phone: String,
    pub key: Secret<String>,
    pub hash: Secret<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum EaseBuzzPaymentsResponse {
    Success(EaseBuzzPaymentsResponseData),
    Error(EaseBuzzErrorResponse),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzPaymentsResponseData {
    pub status: bool,
    pub data: Option<serde_json::Value>,
    pub easebuzz_id: Option<String>,
    pub txnid: Option<String>,
    pub amount: Option<String>,
    pub productinfo: Option<String>,
    pub firstname: Option<String>,
    pub lastname: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
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
    pub hash: Option<String>,
    pub payment_source: Option<String>,
    pub card_no: Option<String>,
    pub card_name: Option<String>,
    pub bank_ref_num: Option<String>,
    pub bankcode: Option<String>,
    pub error: Option<String>,
    pub error_Message: Option<String>,
    pub vpa: Option<String>,
    pub status_code: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzPaymentsSyncResponse {
    pub status: bool,
    pub msg: EaseBuzzTxnSyncMessageType,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum EaseBuzzTxnSyncMessageType {
    Success(EaseBuzzPaymentsResponseData),
    Error(String),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzErrorResponse {
    pub status: i32,
    pub error_desc: Option<String>,
    pub data: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzAuthType {
    pub key: Secret<String>,
    pub salt: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for EaseBuzzAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey { api_key, key1, .. } => Ok(Self {
                key: api_key.clone(),
                salt: key1.clone(),
            }),
            ConnectorAuthType::BodyKey { api_key, .. } => Ok(Self {
                key: api_key.clone(),
                salt: Secret::new("".to_string()),
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
        let auth = EaseBuzzAuthType::try_from(&item.router_data.connector_auth_type)?;
        let customer_id = item.router_data.resource_common_data.get_customer_id()?;
        let return_url = item.router_data.request.get_router_return_url()?;
        
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        // Extract phone from payment method data if available
        let phone = item.router_data.request.payment_method_data.get_phone_number().ok().flatten();
        let email = item.router_data.request.email.clone();

        // Extract name from customer_name
        let (firstname, lastname) = if let Some(customer_name) = &item.router_data.request.customer_name {
            (customer_name.first_name.clone(), customer_name.last_name.clone())
        } else {
            (None, None)
        };

        Ok(Self {
            txnid: item.router_data.resource_common_data.connector_request_reference_id.clone(),
            amount: amount.to_string(),
            currency: item.router_data.request.currency.to_string(),
            email,
            phone,
            firstname,
            lastname,
            surl: return_url.clone(),
            furl: return_url,
            productinfo: format!("Payment for customer {}", customer_id.get_string_repr()),
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
            hash: Secret::new("".to_string()), // Will be calculated based on EaseBuzz requirements
            key: auth.key,
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
        let auth = EaseBuzzAuthType::try_from(&item.router_data.connector_auth_type)?;
        
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        // Extract phone from payment method data if available
        let phone = item.router_data.request.payment_method_data.get_phone_number().ok().flatten().unwrap_or_default();
        let email = item.router_data.request.email.as_ref().map(|e| e.to_string()).unwrap_or_default();

        Ok(Self {
            txnid: item.router_data.request.connector_transaction_id.get_connector_transaction_id()
                .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?,
            amount: amount.to_string(),
            email,
            phone,
            hash: Secret::new("".to_string()), // Will be calculated based on EaseBuzz requirements
            key: auth.key,
        })
    }
}

impl<F, T> TryFrom<ResponseRouterData<EaseBuzzPaymentsResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
    where
        T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize,
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<EaseBuzzPaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let (status, response) = match response {
            EaseBuzzPaymentsResponse::Success(response_data) => {
                let attempt_status = if response_data.status {
                    common_enums::AttemptStatus::Charged
                } else {
                    common_enums::AttemptStatus::Failure
                };

                (
                    attempt_status,
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(
                            response_data.txnid.clone().unwrap_or_default(),
                        ),
                        redirection_data: None,
                        mandate_reference: None,
                        connector_metadata: Some(serde_json::to_value(&response_data).unwrap_or_default()),
                        network_txn_id: response_data.bank_ref_num.clone(),
                        connector_response_reference_id: response_data.easebuzz_id.clone(),
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                    }),
                )
            }
            EaseBuzzPaymentsResponse::Error(error_data) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: error_data.status.to_string(),
                    status_code: http_code,
                    message: error_data.error_desc.clone().unwrap_or_default(),
                    reason: error_data.error_desc,
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

impl<F, T> TryFrom<ResponseRouterData<EaseBuzzPaymentsSyncResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    where
        T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize,
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<EaseBuzzPaymentsSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let (status, response) = match response.msg {
            EaseBuzzTxnSyncMessageType::Success(response_data) => {
                let attempt_status = if response_data.status {
                    common_enums::AttemptStatus::Charged
                } else {
                    common_enums::AttemptStatus::Failure
                };

                (
                    attempt_status,
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(
                            response_data.txnid.clone().unwrap_or_default(),
                        ),
                        redirection_data: None,
                        mandate_reference: None,
                        connector_metadata: Some(serde_json::to_value(&response_data).unwrap_or_default()),
                        network_txn_id: response_data.bank_ref_num.clone(),
                        connector_response_reference_id: response_data.easebuzz_id.clone(),
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                    }),
                )
            }
            EaseBuzzTxnSyncMessageType::Error(error_message) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: "SYNC_ERROR".to_string(),
                    status_code: http_code,
                    message: error_message.clone(),
                    reason: Some(error_message),
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