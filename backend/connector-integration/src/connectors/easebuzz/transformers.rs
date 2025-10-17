use std::collections::HashMap;

use common_utils::{
    ext_traits::ValueExt, request::Method, types::StringMinorUnit,
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
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, PeekInterface, Secret};
use serde::{Deserialize, Serialize};

use crate::{connectors::easebuzz::EaseBuzzRouterData, types::ResponseRouterData};

// Authentication Types
#[derive(Default, Debug, Deserialize)]
pub struct EaseBuzzAuthType {
    pub key: Secret<String>,
    pub salt: Secret<String>,
    pub auth_map: HashMap<common_enums::Currency, EaseBuzzAuth>,
}

#[derive(Default, Debug, Deserialize)]
pub struct EaseBuzzAuth {
    pub key: Secret<String>,
    pub salt: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for EaseBuzzAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::CurrencyAuthKey { auth_key_map } => {
                let transformed_auths = auth_key_map
                    .iter()
                    .map(|(currency, identity_auth_key)| {
                        let easebuzz_auth = identity_auth_key
                            .to_owned()
                            .parse_value::<EaseBuzzAuth>("EaseBuzzAuth")
                            .change_context(errors::ConnectorError::InvalidDataFormat {
                                field_name: "auth_key_map",
                            })?;

                        Ok((currency.to_owned(), easebuzz_auth))
                    })
                    .collect::<Result<_, Self::Error>>()?;

                Ok(Self {
                    key: Secret::new("".to_string()), // Will be extracted from currency auth
                    salt: Secret::new("".to_string()),
                    auth_map: transformed_auths,
                })
            }
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

impl TryFrom<(&ConnectorAuthType, &common_enums::Currency)> for EaseBuzzAuth {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(value: (&ConnectorAuthType, &common_enums::Currency)) -> Result<Self, Self::Error> {
        let (auth_type, currency) = value;

        if let ConnectorAuthType::CurrencyAuthKey { auth_key_map } = auth_type {
            if let Some(identity_auth_key) = auth_key_map.get(currency) {
                let easebuzz_auth: Self = identity_auth_key
                    .to_owned()
                    .parse_value("EaseBuzzAuth")
                    .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
                Ok(easebuzz_auth)
            } else {
                Err(errors::ConnectorError::CurrencyNotSupported {
                    message: currency.to_string(),
                    connector: "EaseBuzz",
                }
                .into())
            }
        } else {
            Err(errors::ConnectorError::FailedToObtainAuthType.into())
        }
    }
}

// Request Types
#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzPaymentsRequest {
    pub txnid: String,
    pub amount: StringMinorUnit,
    pub currency: common_enums::Currency,
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
    pub amount: StringMinorUnit,
    pub email: Option<Email>,
    pub phone: Option<String>,
    pub key: Secret<String>,
    pub hash: Secret<String>,
}

// Response Types
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
    Success(EaseBuzzSeamlessTxnResponse),
    Error(String),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzSeamlessTxnResponse {
    pub status: bool,
    pub txnid: Option<String>,
    pub amount: Option<String>,
    pub easebuzz_id: Option<String>,
    pub card_no: Option<String>,
    pub bank_ref_num: Option<String>,
    pub bankcode: Option<String>,
    pub error: Option<String>,
    pub error_message: Option<String>,
    pub payment_source: Option<String>,
    pub card_type: Option<String>,
    pub created_at: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzErrorResponse {
    pub status: i32,
    pub error_desc: Option<String>,
    pub data: Option<serde_json::Value>,
}

// Status Mapping
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EaseBuzzPaymentStatus {
    #[default]
    Pending,
    Success,
    Failure,
}

impl From<EaseBuzzPaymentStatus> for common_enums::AttemptStatus {
    fn from(item: EaseBuzzPaymentStatus) -> Self {
        match item {
            EaseBuzzPaymentStatus::Success => Self::Charged,
            EaseBuzzPaymentStatus::Failure => Self::Failure,
            EaseBuzzPaymentStatus::Pending => Self::AuthenticationPending,
        }
    }
}

// Request Transformations
impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> TryFrom<
    EaseBuzzRouterData<
        RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        T,
    >,
> for EaseBuzzPaymentsRequest
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: EaseBuzzRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let _customer_id = item.router_data.resource_common_data.get_customer_id()?;
        let return_url = item.router_data.request.get_router_return_url()?;
        
        let auth = EaseBuzzAuth::try_from((
            &item.router_data.connector_auth_type,
            &item.router_data.request.currency,
        ))?;
        
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        // Generate hash - this would typically involve SHA512 of specific fields
        let key_exposed = auth.key.clone().expose();
        let salt_exposed = auth.salt.clone().expose();
        let hash_string = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            key_exposed,
            item.router_data.resource_common_data.connector_request_reference_id,
            amount.to_string(),
            "", // product_name
            "", // customer_name
            item.router_data.request.email.as_ref().map(|e| e.peek().to_string()).unwrap_or_default(),
            "", // phone
            return_url,
            return_url, // furl same as surl
            "", // udf1
            "", // udf2
            "", // udf3
            "", // udf4
            "", // udf5
            "", // udf6
            "", // udf7
            "", // udf8
            "", // udf9
            "", // udf10
            "", // additional charges
            "", // customer authentication
            salt_exposed
        );

        // In a real implementation, you would hash this string
        let hash = Secret::new(hash_string);

        Ok(Self {
            txnid: item.router_data.resource_common_data.connector_request_reference_id.clone(),
            amount,
            currency: item.router_data.request.currency,
            email: item.router_data.request.email.clone(),
            phone: None, // Extract from router data if available
            firstname: None, // Extract from router data if available
            lastname: None,
            surl: return_url.clone(),
            furl: return_url,
            productinfo: "Payment".to_string(),
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
            key: auth.key,
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
    EaseBuzzRouterData<
        RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        T,
    >,
> for EaseBuzzPaymentsSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: EaseBuzzRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = EaseBuzzAuth::try_from((
            &item.router_data.connector_auth_type,
            &item.router_data.request.currency,
        ))?;
        
        // For sync, we need to get the amount from the connector response or use a default
        // This is a simplified approach - in practice you'd store this somewhere
        let amount = item.connector.amount_converter.convert(
            common_utils::types::MinorUnit::new(1000), // Default amount - should be retrieved from storage
            common_enums::Currency::INR, // Default currency
        ).change_context(ConnectorError::RequestEncodingFailed)?;

        // Generate hash for sync request
        let key_exposed = auth.key.clone().expose();
        let salt_exposed = auth.salt.clone().expose();
        let hash_string = format!(
            "{}|{}|{}|{}",
            key_exposed,
            item.router_data.request.connector_transaction_id.get_connector_transaction_id().map_err(|_| ConnectorError::MissingRequiredField { field_name: "connector_transaction_id" })?,
            amount.to_string(),
            salt_exposed
        );

        let hash = Secret::new(hash_string);

        Ok(Self {
            txnid: item.router_data.request.connector_transaction_id.get_connector_transaction_id().map_err(|_| ConnectorError::MissingRequiredField { field_name: "connector_transaction_id" })?,
            amount,
            email: None,
            phone: None,
            key: auth.key,
            hash,
        })
    }
}

// Response Transformations
impl<
    F,
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> TryFrom<ResponseRouterData<EaseBuzzPaymentsResponse, Self>>
for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
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
                let payment_method_type = router_data
                    .request
                    .payment_method_type
                    .ok_or(errors::ConnectorError::MissingPaymentMethodType)?;
                
                // For UPI payments, we typically get a redirect response
                let redirection_data = if payment_method_type == common_enums::PaymentMethodType::UpiCollect {
                    Some(Box::new(RedirectForm::Form {
                        endpoint: response_data.data.as_ref()
                            .and_then(|d| d.get("payment_url"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        method: Method::Get,
                        form_fields: Default::default(),
                    }))
                } else {
                    None
                };

                (
                    common_enums::AttemptStatus::AuthenticationPending,
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(
                            router_data
                                .resource_common_data
                                .connector_request_reference_id
                                .clone(),
                        ),
                        redirection_data,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: response_data.easebuzz_id,
                        connector_response_reference_id: None,
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                    }),
                )
            }
            EaseBuzzPaymentsResponse::Error(error_data) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: error_data.status.to_string(),
                    status_code: item.http_code,
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

impl TryFrom<ResponseRouterData<EaseBuzzPaymentsSyncResponse, Self>>
for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
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
            EaseBuzzTxnSyncMessageType::Success(txn_response) => {
                let attempt_status = if txn_response.status {
                    common_enums::AttemptStatus::Charged
                } else {
                    common_enums::AttemptStatus::Failure
                };

                (
                    attempt_status,
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(
                            txn_response.txnid.unwrap_or_default(),
                        ),
                        redirection_data: None,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: txn_response.easebuzz_id,
                        connector_response_reference_id: None,
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                    }),
                )
            }
            EaseBuzzTxnSyncMessageType::Error(error_message) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: "SYNC_ERROR".to_string(),
                    status_code: item.http_code,
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