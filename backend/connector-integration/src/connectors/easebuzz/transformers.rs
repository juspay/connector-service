use std::str::FromStr;

use common_utils::{
    crypto::{GenerateDigest, Sha512},
    errors::CustomResult,
    request::Method,

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
use hyperswitch_masking::{Secret, PeekInterface, ExposeInterface};
use serde::{Deserialize, Serialize};

use crate::{connectors::easebuzz::EasebuzzRouterData, types::ResponseRouterData};

#[derive(Default, Debug, Serialize)]
pub struct EasebuzzPaymentsRequest {
    pub txnid: String,
    pub amount: String,
    pub productinfo: String,
    pub firstname: Secret<String>,
    pub email: Email,
    pub phone: Secret<String>,
    pub surl: String,
    pub furl: String,
    pub hash: Secret<String>,
    pub key: Secret<String>,
    pub upi_va: Option<String>,
    pub sub_merchant_id: Option<String>,
}

#[derive(Default, Debug, Serialize)]
pub struct EasebuzzPaymentsSyncRequest {
    pub txnid: String,
    pub amount: String,
    pub email: Email,
    pub phone: Secret<String>,
    pub key: Secret<String>,
    pub hash: Secret<String>,
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
        EasebuzzRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for EasebuzzPaymentsRequest
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: EasebuzzRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let _customer_id = item.router_data.resource_common_data.get_customer_id()?;
        let return_url = item.router_data.request.get_router_return_url()?;
        
        let auth_type = EasebuzzAuth::try_from(&item.router_data.connector_auth_type)?;
        
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        let email = item.router_data.request.email.clone()
            .ok_or(ConnectorError::MissingRequiredField { field_name: "email" })?;

        // Use default values for phone and firstname
        let phone = Secret::new("9999999999".to_string());
        let firstname = Secret::new("Customer".to_string());

        // Generate hash for EaseBuzz
        let hash_string = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}",
            auth_type.api_key.peek(),
            item.router_data.resource_common_data.connector_request_reference_id,
            amount.to_string(),
            "UPI Payment",
            firstname.peek(),
            email.clone().expose().peek(),
            "||||||||||",
            auth_type.salt.peek()
        );
        
        let hash = Secret::new(
            hex::encode(Sha512.generate_digest(hash_string.as_bytes()).unwrap_or_default())
        );

        match item.router_data.request.payment_method_data {
            domain_types::payment_method_data::PaymentMethodData::Upi(ref upi_data) => {
                match upi_data {
                    domain_types::payment_method_data::UpiData::UpiIntent(_) => {
                        Ok(Self {
                            txnid: item.router_data.resource_common_data.connector_request_reference_id,
                            amount: amount.to_string(),
                            productinfo: "UPI Payment".to_string(),
                            firstname,
                            email,
                            phone,
                            surl: return_url.clone(),
                            furl: return_url,
                            hash,
                            key: auth_type.api_key,
                            upi_va: None,
                            sub_merchant_id: auth_type.sub_merchant_id.map(|s| s.peek().to_string()),
                        })
                    }
                    domain_types::payment_method_data::UpiData::UpiCollect(collect_data) => {
                        Ok(Self {
                            txnid: item.router_data.resource_common_data.connector_request_reference_id,
                            amount: amount.to_string(),
                            productinfo: "UPI Payment".to_string(),
                            firstname,
                            email,
                            phone,
                            surl: return_url.clone(),
                            furl: return_url,
                            hash,
                            key: auth_type.api_key,
                            upi_va: collect_data.vpa_id.clone().map(|s| s.peek().to_string()),
                            sub_merchant_id: auth_type.sub_merchant_id.map(|s| s.peek().to_string()),
                        })
                    }
                }
            }
            _ => Err(errors::ConnectorError::NotImplemented("Payment method".to_string()).into()),
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
        EasebuzzRouterData<
            RouterDataV2<
                PSync,
                PaymentFlowData,
                PaymentsSyncData,
                PaymentsResponseData,
            >,
            T,
        >,
    > for EasebuzzPaymentsSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: EasebuzzRouterData<
            RouterDataV2<
                PSync,
                PaymentFlowData,
                PaymentsSyncData,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth_type = EasebuzzAuth::try_from(&item.router_data.connector_auth_type)?;
        
        let connector_transaction_id = item.router_data.request.connector_transaction_id
            .get_connector_transaction_id()
            .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?;

        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        let email = Email::from_str("test@example.com")
            .map_err(|_| ConnectorError::MissingRequiredField { field_name: "email" })?;

        let phone = Secret::new("9999999999".to_string()); // Default phone for sync

        // Generate hash for sync request
        let hash_string = format!(
            "{}|{}|{}|{}|{}",
            auth_type.api_key.peek(),
            connector_transaction_id,
            amount.to_string(),
            email.clone().expose().peek(),
            auth_type.salt.peek()
        );
        
        let hash = Secret::new(
            hex::encode(Sha512.generate_digest(hash_string.as_bytes()).unwrap_or_default())
        );

        Ok(Self {
            txnid: connector_transaction_id,
            amount: amount.to_string(),
            email,
            phone,
            key: auth_type.api_key,
            hash,
        })
    }
}

#[derive(Default, Debug, Deserialize)]
pub struct EasebuzzAuth {
    pub api_key: Secret<String>,
    pub salt: Secret<String>,
    pub sub_merchant_id: Option<Secret<String>>,
}

impl TryFrom<&ConnectorAuthType> for EasebuzzAuth {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self {
                api_key: api_key.to_owned(),
                salt: key1.to_owned(),
                sub_merchant_id: None,
            }),
            ConnectorAuthType::MultiAuthKey { api_key, key1, key2, .. } => Ok(Self {
                api_key: api_key.to_owned(),
                salt: key1.to_owned(),
                sub_merchant_id: Some(key2.to_owned()),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EasebuzzPaymentStatus {
    Success,
    Failure,
    #[default]
    Pending,
}

impl From<EasebuzzPaymentStatus> for common_enums::AttemptStatus {
    fn from(item: EasebuzzPaymentStatus) -> Self {
        match item {
            EasebuzzPaymentStatus::Success => Self::Charged,
            EasebuzzPaymentStatus::Failure => Self::Failure,
            EasebuzzPaymentStatus::Pending => Self::Pending,
        }
    }
}

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct EasebuzzErrorResponse {
    pub status: Option<i32>,
    pub error_desc: Option<String>,
    pub error_code: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum EasebuzzPaymentsResponse {
    EasebuzzError(EasebuzzErrorResponse),
    EasebuzzData(EasebuzzPaymentsResponseData),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct EasebuzzPaymentsResponseData {
    pub status: bool,
    pub msg_desc: String,
    pub qr_link: Option<String>,
    pub msg_title: String,
    pub data: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum EasebuzzPaymentsSyncResponse {
    EasebuzzSyncError(EasebuzzErrorResponse),
    EasebuzzSyncData(EasebuzzPaymentsSyncResponseData),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct EasebuzzPaymentsSyncResponseData {
    pub status: bool,
    pub msg: EasebuzzSyncMessage,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum EasebuzzSyncMessage {
    SuccessMessage(EasebuzzTransactionDetails),
    ErrorMessage(String),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct EasebuzzTransactionDetails {
    pub txnid: String,
    pub mihpayid: Option<String>,
    pub mode: Option<String>,
    pub status: String,
    pub unmappedstatus: Option<String>,
    pub key: Option<String>,
    pub amount: String,
    pub addedon: Option<String>,
    pub productinfo: Option<String>,
    pub firstname: Option<String>,
    pub lastname: Option<String>,
    pub address1: Option<String>,
    pub address2: Option<String>,
    pub city: Option<String>,
    pub state: Option<String>,
    pub country: Option<String>,
    pub zipcode: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub udf1: Option<String>,
    pub udf2: Option<String>,
    pub udf3: Option<String>,
    pub udf4: Option<String>,
    pub udf5: Option<String>,
    pub field2: Option<String>,
    pub field9: Option<String>,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EasebuzzWebhookResponse {
    pub txnid: String,
    pub mihpayid: Option<String>,
    pub status: String,
    pub amount: String,
    pub productinfo: Option<String>,
    pub firstname: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
}

fn get_redirect_form_data(
    response_data: EasebuzzPaymentsResponseData,
) -> CustomResult<RedirectForm, errors::ConnectorError> {
    if let Some(qr_link) = response_data.qr_link {
        Ok(RedirectForm::Form {
            endpoint: qr_link,
            method: Method::Get,
            form_fields: Default::default(),
        })
    } else if let Some(data) = response_data.data {
        // Parse the data field which might contain redirect URL
        Ok(RedirectForm::Form {
            endpoint: data,
            method: Method::Get,
            form_fields: Default::default(),
        })
    } else {
        Err(errors::ConnectorError::ResponseDeserializationFailed)?
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
    > TryFrom<ResponseRouterData<EasebuzzPaymentsResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: ResponseRouterData<EasebuzzPaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;
        
        let (status, response) = match response {
            EasebuzzPaymentsResponse::EasebuzzError(error_data) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: error_data.error_code.unwrap_or_else(|| "UNKNOWN_ERROR".to_string()),
                    status_code: http_code,
                    message: error_data.error_desc.clone().unwrap_or_else(|| "Unknown error occurred".to_string()),
                    reason: error_data.error_desc,
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }),
            ),
            EasebuzzPaymentsResponse::EasebuzzData(response_data) => {
                if response_data.status {
                    let redirection_data = get_redirect_form_data(response_data)?;
                    (
                        common_enums::AttemptStatus::AuthenticationPending,
                        Ok(PaymentsResponseData::TransactionResponse {
                            resource_id: ResponseId::ConnectorTransactionId(
                                router_data
                                    .resource_common_data
                                    .connector_request_reference_id
                                    .clone(),
                            ),
                            redirection_data: Some(Box::new(redirection_data)),
                            mandate_reference: None,
                            connector_metadata: None,
                            network_txn_id: None,
                            connector_response_reference_id: None,
                            incremental_authorization_allowed: None,
                            status_code: http_code,
                        }),
                    )
                } else {
                    (
                        common_enums::AttemptStatus::Failure,
                        Err(ErrorResponse {
                            code: "PAYMENT_FAILED".to_string(),
                            status_code: http_code,
                            message: response_data.msg_desc.clone(),
                            reason: Some(response_data.msg_desc),
                            attempt_status: None,
                            connector_transaction_id: None,
                            network_advice_code: None,
                            network_decline_code: None,
                            network_error_message: None,
                        }),
                    )
                }
            }
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

impl TryFrom<ResponseRouterData<EasebuzzPaymentsSyncResponse, RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>>
    for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: ResponseRouterData<EasebuzzPaymentsSyncResponse, RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;
        
        let (status, response) = match response {
            EasebuzzPaymentsSyncResponse::EasebuzzSyncError(error_data) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: error_data.error_code.unwrap_or_else(|| "SYNC_ERROR".to_string()),
                    status_code: http_code,
                    message: error_data.error_desc.clone().unwrap_or_else(|| "Sync failed".to_string()),
                    reason: error_data.error_desc,
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }),
            ),
            EasebuzzPaymentsSyncResponse::EasebuzzSyncData(sync_data) => {
                match sync_data.msg {
                    EasebuzzSyncMessage::SuccessMessage(txn_details) => {
                        let status = match txn_details.status.to_lowercase().as_str() {
                            "success" => common_enums::AttemptStatus::Charged,
                            "failure" | "failed" => common_enums::AttemptStatus::Failure,
                            "pending" => common_enums::AttemptStatus::Pending,
                            _ => common_enums::AttemptStatus::Pending,
                        };

                        (
                            status,
                            Ok(PaymentsResponseData::TransactionResponse {
                                resource_id: ResponseId::ConnectorTransactionId(txn_details.txnid),
                                redirection_data: None,
                                mandate_reference: None,
                                connector_metadata: None,
                                network_txn_id: txn_details.mihpayid,
                                connector_response_reference_id: None,
                                incremental_authorization_allowed: None,
                                status_code: http_code,
                            }),
                        )
                    }
                    EasebuzzSyncMessage::ErrorMessage(error_msg) => (
                        common_enums::AttemptStatus::Failure,
                        Err(ErrorResponse {
                            code: "SYNC_ERROR".to_string(),
                            status_code: http_code,
                            message: error_msg.clone(),
                            reason: Some(error_msg),
                            attempt_status: None,
                            connector_transaction_id: None,
                            network_advice_code: None,
                            network_decline_code: None,
                            network_error_message: None,
                        }),
                    ),
                }
            }
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