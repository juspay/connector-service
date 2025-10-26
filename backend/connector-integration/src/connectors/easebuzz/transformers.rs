use std::collections::HashMap;

use common_utils::{
    errors::CustomResult, ext_traits::ValueExt, request::Method, types::StringMinorUnit,
    Email,
};
use domain_types::{
    connector_flow::{Authorize, PSync},
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, ResponseId},
    errors::{self, ConnectorError},
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
    utils,
};
use error_stack::ResultExt;
use hyperswitch_masking::{Mask, Maskable, PeekInterface, Secret};
use serde::{Deserialize, Serialize};

use crate::{connectors::easebuzz::EaseBuzzRouterData, types::ResponseRouterData};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzPaymentsRequest {
    pub txnid: String,
    pub amount: StringMinorUnit,
    pub currency: String,
    pub email: Option<Email>,
    pub phone: Option<String>,
    pub firstname: Option<Secret<String>>,
    pub lastname: Option<Secret<String>>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vpa: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzPaymentsSyncRequest {
    pub txnid: String,
    pub amount: StringMinorUnit,
    pub email: Option<Email>,
    pub phone: Option<String>,
    pub key: Secret<String>,
    pub hash: Secret<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzPaymentsResponse {
    pub status: bool,
    pub error_desc: Option<String>,
    pub data: EaseBuzzResponseData,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum EaseBuzzResponseData {
    Success(EaseBuzzSuccessData),
    Error(String),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzSuccessData {
    pub easebuzz_id: String,
    pub payment_url: Option<String>,
    pub transaction_id: String,
    pub status: String,
    pub amount: StringMinorUnit,
    pub currency: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzPaymentsSyncResponse {
    pub status: bool,
    pub msg: EaseBuzzSyncMessage,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum EaseBuzzSyncMessage {
    Success(EaseBuzzSuccessData),
    Error(String),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzErrorResponse {
    pub status: bool,
    pub error_desc: Option<String>,
    pub data: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct EaseBuzzAuth {
    pub key: Secret<String>,
    pub salt: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for EaseBuzzAuth {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey { api_key, api_secret } => Ok(Self {
                key: api_key.clone(),
                salt: api_secret.clone(),
            }),
            ConnectorAuthType::Key { api_key } => Err(errors::ConnectorError::FailedToObtainAuthType
                .attach_printable("EaseBuzz requires both key and salt for authentication")
                .into()),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

fn get_auth_credentials(
    connector_auth_type: &ConnectorAuthType,
) -> Result<EaseBuzzAuth, errors::ConnectorError> {
    EaseBuzzAuth::try_from(connector_auth_type)
}

fn generate_hash(
    key: &str,
    salt: &str,
    txnid: &str,
    amount: &str,
    productinfo: &str,
    firstname: Option<&str>,
    email: Option<&str>,
    udf1: Option<&str>,
    udf2: Option<&str>,
    udf3: Option<&str>,
    udf4: Option<&str>,
    udf5: Option<&str>,
    udf6: Option<&str>,
    udf7: Option<&str>,
    udf8: Option<&str>,
    udf9: Option<&str>,
    udf10: Option<&str>,
) -> String {
    use sha2::{Digest, Sha512};

    let hash_string = format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        key,
        txnid,
        amount,
        productinfo,
        firstname.unwrap_or(""),
        email.unwrap_or(""),
        udf1.unwrap_or(""),
        udf2.unwrap_or(""),
        udf3.unwrap_or(""),
        udf4.unwrap_or(""),
        udf5.unwrap_or(""),
        udf6.unwrap_or(""),
        udf7.unwrap_or(""),
        udf8.unwrap_or(""),
        udf9.unwrap_or(""),
        udf10.unwrap_or(""),
        salt
    );

    let mut hasher = Sha512::new();
    hasher.update(hash_string);
    format!("{:x}", hasher.finalize())
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> TryFrom<EaseBuzzRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>>
    for EaseBuzzPaymentsRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: EaseBuzzRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = get_auth_credentials(&item.router_data.connector_auth_type)?;
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

        let txnid = item
            .router_data
            .resource_common_data
            .connector_request_reference_id
            .clone();

        let email = item.router_data.request.email.clone();
        let phone = item.router_data.request.phone_number.as_ref().map(|p| p.to_string());

        // Extract payment method specific data
        let (payment_source, vpa) = match item.router_data.resource_common_data.payment_method {
            common_enums::PaymentMethod::Upi => {
                if let Some(payment_method_data) = &item.router_data.request.payment_method_data {
                    match payment_method_data {
                        domain_types::payment_method_data::PaymentMethodData::Upi(upi_data) => {
                            (Some("upi".to_string()), upi_data.vpa.clone())
                        }
                        _ => (None, None),
                    }
                } else {
                    (Some("upi".to_string()), None)
                }
            }
            _ => (None, None),
        };

        let hash = generate_hash(
            auth.key.peek(),
            auth.salt.peek(),
            &txnid,
            &amount.get_amount_as_string(),
            "Payment", // productinfo
            None, // firstname
            email.as_ref().map(|e| e.to_string().as_str()),
            None, // udf1
            None, // udf2
            None, // udf3
            None, // udf4
            None, // udf5
            None, // udf6
            None, // udf7
            None, // udf8
            None, // udf9
            None, // udf10
        );

        Ok(Self {
            txnid,
            amount,
            currency: item.router_data.request.currency.to_string(),
            email,
            phone,
            firstname: None,
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
            hash: Secret::new(hash),
            key: auth.key,
            payment_source,
            vpa,
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
> TryFrom<EaseBuzzRouterData<RouterDataV2<PSync, PaymentFlowData, domain_types::connector_types::PaymentsSyncData, PaymentsResponseData>, T>>
    for EaseBuzzPaymentsSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: EaseBuzzRouterData<
            RouterDataV2<PSync, PaymentFlowData, domain_types::connector_types::PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = get_auth_credentials(&item.router_data.connector_auth_type)?;
        
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        let txnid = item
            .router_data
            .resource_common_data
            .connector_request_reference_id
            .clone();

        let email = item.router_data.request.email.clone();
        let phone = item.router_data.request.phone_number.as_ref().map(|p| p.to_string());

        let hash = generate_hash(
            auth.key.peek(),
            auth.salt.peek(),
            &txnid,
            &amount.get_amount_as_string(),
            "Payment", // productinfo
            None, // firstname
            email.as_ref().map(|e| e.to_string().as_str()),
            None, // udf1
            None, // udf2
            None, // udf3
            None, // udf4
            None, // udf5
            None, // udf6
            None, // udf7
            None, // udf8
            None, // udf9
            None, // udf10
        );

        Ok(Self {
            txnid,
            amount,
            email,
            phone,
            key: auth.key,
            hash: Secret::new(hash),
        })
    }
}

impl<F, T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<ResponseRouterData<EaseBuzzPaymentsResponse, Self>>
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

        let (status, response) = match response.data {
            EaseBuzzResponseData::Success(success_data) => {
                let redirection_data = if let Some(payment_url) = success_data.payment_url {
                    Some(Box::new(RedirectForm::Form {
                        endpoint: payment_url,
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
                            success_data.transaction_id.clone(),
                        ),
                        redirection_data,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: Some(success_data.easebuzz_id),
                        connector_response_reference_id: None,
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                    }),
                )
            }
            EaseBuzzResponseData::Error(error_message) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: "PAYMENT_FAILED".to_string(),
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

impl<F, T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<ResponseRouterData<EaseBuzzPaymentsSyncResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, domain_types::connector_types::PaymentsSyncData, PaymentsResponseData>
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
            EaseBuzzSyncMessage::Success(success_data) => {
                let attempt_status = match success_data.status.as_str() {
                    "success" => common_enums::AttemptStatus::Charged,
                    "pending" => common_enums::AttemptStatus::Pending,
                    "failure" => common_enums::AttemptStatus::Failure,
                    "user_dropped" => common_enums::AttemptStatus::AuthorizationFailed,
                    _ => common_enums::AttemptStatus::Pending,
                };

                (
                    attempt_status,
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(
                            success_data.transaction_id.clone(),
                        ),
                        redirection_data: None,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: Some(success_data.easebuzz_id),
                        connector_response_reference_id: None,
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                    }),
                )
            }
            EaseBuzzSyncMessage::Error(error_message) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: "SYNC_FAILED".to_string(),
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