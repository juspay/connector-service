use std::collections::HashMap;

use common_utils::{
    request::Method, types::StringMinorUnit,
    Email,
};
use sha2::Digest;
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
use hyperswitch_masking::{PeekInterface, Secret};
use serde::{Deserialize, Serialize};

use crate::{connectors::easebuzz::EaseBuzzRouterData, types::ResponseRouterData};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzAuth {
    pub key: Secret<String>,
    pub salt: Secret<String>,
    pub merchant_id: Option<Secret<String>>,
}

impl TryFrom<&ConnectorAuthType> for EaseBuzzAuth {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey { api_key, key1, .. } => Ok(Self {
                key: api_key.clone(),
                salt: key1.clone(),
                merchant_id: None,
            }),
            ConnectorAuthType::MultiAuthKey { api_key, key1, .. } => Ok(Self {
                key: api_key.clone(),
                salt: key1.clone(),
                merchant_id: None,
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzPaymentsRequest {
    pub key: Secret<String>,
    pub txnid: String,
    pub amount: StringMinorUnit,
    pub productinfo: String,
    pub firstname: Option<Secret<String>>,
    pub email: Option<Email>,
    pub phone: Option<Secret<String>>,
    pub surl: String,
    pub furl: String,
    pub hash: Secret<String>,
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
    pub address1: Option<String>,
    pub address2: Option<String>,
    pub city: Option<String>,
    pub state: Option<String>,
    pub country: Option<String>,
    pub zipcode: Option<String>,
    pub pg: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzUpiIntentRequest {
    pub key: Secret<String>,
    pub txnid: String,
    pub amount: StringMinorUnit,
    pub vpa: Option<String>,
    pub customer_name: Option<Secret<String>>,
    pub customer_email: Option<Email>,
    pub customer_mobile: Option<Secret<String>>,
    pub hash: Secret<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzPaymentsSyncRequest {
    pub key: Secret<String>,
    pub txnid: String,
    pub amount: StringMinorUnit,
    pub email: Option<Email>,
    pub phone: Option<Secret<String>>,
    pub hash: Secret<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzPaymentsResponse {
    pub status: i32,
    pub error_desc: Option<String>,
    pub data: Option<EaseBuzzResponseData>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzResponseData {
    pub payment_url: Option<String>,
    pub transaction_id: Option<String>,
    pub easebuzz_id: Option<String>,
    pub status: Option<String>,
    pub amount: Option<String>,
    pub currency: Option<String>,
    pub name: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub productinfo: Option<String>,
    pub txnid: Option<String>,
    pub hash: Option<String>,
    pub payment_source: Option<String>,
    pub card_no: Option<String>,
    pub card_name: Option<String>,
    pub bank_ref_num: Option<String>,
    pub bankcode: Option<String>,
    pub error: Option<String>,
    pub error_message: Option<String>,
    pub unmappedstatus: Option<String>,
    pub additional_charges: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzUpiIntentResponse {
    pub status: bool,
    pub msg_desc: String,
    pub qr_link: Option<String>,
    pub msg_title: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzErrorResponse {
    pub status: i32,
    pub error_desc: Option<String>,
    pub error_code: Option<String>,
    pub message: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum EaseBuzzPaymentsResponseEnum {
    Success(EaseBuzzPaymentsResponse),
    Error(EaseBuzzErrorResponse),
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
                common_utils::types::MinorUnit(item.router_data.request.amount),
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        // Generate hash - this would typically involve SHA512 of parameters + salt
        let hash_string = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            auth.key.peek(),
            item.router_data.resource_common_data.connector_request_reference_id,
            amount.to_string(),
            "Payment", // productinfo
            customer_id.get_string_repr(),
            String::new(), // Email not available in sync request
            String::new(), // Phone number not available in standard flow
            return_url,
            return_url, // furl same as surl
            "", "", "", "", "", "", "", "", "", "", "", "", "", "", // udf fields
            auth.salt.peek()
        );
        
        let hash = Secret::new(format!("{:x}", sha2::Sha512::digest(hash_string)));

        Ok(Self {
            key: auth.key,
            txnid: item.router_data.resource_common_data.connector_request_reference_id.clone(),
            amount,
            productinfo: "Payment".to_string(),
            firstname: Some(Secret::new(customer_id.get_string_repr().to_string())),
            email: None, // Email not available in sync request
            phone: None, // Phone number not available in standard flow
            surl: return_url.clone(),
            furl: return_url,
            hash,
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
            address1: None,
            address2: None,
            city: None,
            state: None,
            country: None,
            zipcode: None,
            pg: Some("upi".to_string()),
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
            "{}|{}|{}|{}|{}|{}",
            auth.key.peek(),
            item.router_data.request.connector_transaction_id.get_connector_transaction_id().map_err(|_| ConnectorError::MissingRequiredField { field_name: "connector_transaction_id" })?,
            amount.to_string(),
            String::new(), // Email not available in sync request
            String::new(), // Phone number not available in sync request
            auth.salt.peek()
        );
        
        let hash = Secret::new(format!("{:x}", sha2::Sha512::digest(hash_string)));

        Ok(Self {
            key: auth.key,
            txnid: item.router_data.request.connector_transaction_id.get_connector_transaction_id().map_err(|_| ConnectorError::MissingRequiredField { field_name: "connector_transaction_id" })?,
            amount,
            email: None, // Email not available in sync request
            phone: None, // Phone number not available in sync request
            hash,
        })
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<ResponseRouterData<EaseBuzzPaymentsResponseEnum, RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>>
    for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<EaseBuzzPaymentsResponseEnum, RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let (status, response) = match response {
            EaseBuzzPaymentsResponseEnum::Success(success_data) => {
                if success_data.status == 1 {
                    if let Some(data) = success_data.data {
                        if let Some(payment_url) = data.payment_url {
                            let redirection_data = RedirectForm::Form {
                                endpoint: payment_url,
                                method: Method::Get,
                                form_fields: HashMap::new(),
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
                                    redirection_data: Some(Box::new(redirection_data)),
                                    mandate_reference: None,
                                    connector_metadata: None,
                                    network_txn_id: data.easebuzz_id,
                                    connector_response_reference_id: data.transaction_id,
                                    incremental_authorization_allowed: None,
                                    status_code: http_code,
                                }),
                            )
                        } else {
                            (
                                common_enums::AttemptStatus::Charged,
                                Ok(PaymentsResponseData::TransactionResponse {
                                    resource_id: ResponseId::ConnectorTransactionId(
                                        router_data
                                            .resource_common_data
                                            .connector_request_reference_id
                                            .clone(),
                                    ),
                                    redirection_data: None,
                                    mandate_reference: None,
                                    connector_metadata: None,
                                    network_txn_id: data.easebuzz_id,
                                    connector_response_reference_id: data.transaction_id,
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
                                    router_data
                                        .resource_common_data
                                        .connector_request_reference_id
                                        .clone(),
                                ),
                                redirection_data: None,
                                mandate_reference: None,
                                connector_metadata: None,
                                network_txn_id: None,
                                connector_response_reference_id: None,
                                incremental_authorization_allowed: None,
                                status_code: http_code,
                            }),
                        )
                    }
                } else {
                    (
                        common_enums::AttemptStatus::Failure,
                        Err(ErrorResponse {
                            status_code: http_code,
                            code: success_data.status.to_string(),
                            message: success_data.error_desc.clone().unwrap_or_default(),
                            reason: success_data.error_desc,
                            attempt_status: None,
                            connector_transaction_id: None,
                            network_advice_code: None,
                            network_decline_code: None,
                            network_error_message: None,
                        }),
                    )
                }
            }
            EaseBuzzPaymentsResponseEnum::Error(error_data) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    status_code: http_code,
                    code: error_data.status.to_string(),
                    message: error_data.error_desc.or(error_data.message).clone().unwrap_or_default(),
                    reason: error_data.error_desc.or(error_data.message),
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
            flow: router_data.flow,
            connector_auth_type: router_data.connector_auth_type,
            request: router_data.request,
        })
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<ResponseRouterData<EaseBuzzPaymentsResponseEnum, EaseBuzzRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>>>
    for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<EaseBuzzPaymentsResponseEnum, EaseBuzzRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let (status, response) = match response {
            EaseBuzzPaymentsResponseEnum::Success(success_data) => {
                if success_data.status == 1 {
                    if let Some(data) = success_data.data {
                        if let Some(payment_url) = data.payment_url {
                            let redirection_data = RedirectForm::Form {
                                endpoint: payment_url,
                                method: Method::Get,
                                form_fields: HashMap::new(),
                            };
                            
                            (
                                common_enums::AttemptStatus::AuthenticationPending,
                                Ok(PaymentsResponseData::TransactionResponse {
                                    resource_id: ResponseId::ConnectorTransactionId(
                                        router_data
                                            .router_data.resource_common_data
                                            .connector_request_reference_id
                                            .clone(),
                                    ),
                                    redirection_data: Some(Box::new(redirection_data)),
                                    mandate_reference: None,
                                    connector_metadata: None,
                                    network_txn_id: data.easebuzz_id,
                                    connector_response_reference_id: data.transaction_id,
                                    incremental_authorization_allowed: None,
                                    status_code: http_code,
                                }),
                            )
                        } else {
                            (
                                common_enums::AttemptStatus::Charged,
                                Ok(PaymentsResponseData::TransactionResponse {
                                    resource_id: ResponseId::ConnectorTransactionId(
                                        router_data
                                            .router_data.resource_common_data
                                            .connector_request_reference_id
                                            .clone(),
                                    ),
                                    redirection_data: None,
                                    mandate_reference: None,
                                    connector_metadata: None,
                                    network_txn_id: data.easebuzz_id,
                                    connector_response_reference_id: data.transaction_id,
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
                                    router_data
                                        .router_data.resource_common_data
                                        .connector_request_reference_id
                                        .clone(),
                                ),
                                redirection_data: None,
                                mandate_reference: None,
                                connector_metadata: None,
                                network_txn_id: None,
                                connector_response_reference_id: None,
                                incremental_authorization_allowed: None,
                                status_code: http_code,
                            }),
                        )
                    }
                } else {
                    (
                        common_enums::AttemptStatus::Failure,
                        Err(ErrorResponse {
                            status_code: http_code,
                            code: success_data.status.to_string(),
                            message: success_data.error_desc.clone().unwrap_or_default(),
                            reason: success_data.error_desc,
                            attempt_status: None,
                            connector_transaction_id: None,
                            network_advice_code: None,
                            network_decline_code: None,
                            network_error_message: None,
                        }),
                    )
                }
            }
            EaseBuzzPaymentsResponseEnum::Error(error_data) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    status_code: http_code,
                    code: error_data.status.to_string(),
                    message: error_data.error_desc.or(error_data.message).clone().unwrap_or_default(),
                    reason: error_data.error_desc.or(error_data.message),
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
                ..router_data.router_data.resource_common_data
            },
            response,
            flow: router_data.router_data.flow,
            connector_auth_type: router_data.router_data.connector_auth_type,
            request: router_data.router_data.request,
        })
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<ResponseRouterData<EaseBuzzPaymentsResponseEnum, RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>>
    for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<EaseBuzzPaymentsResponseEnum, RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let (status, response) = match response {
            EaseBuzzPaymentsResponseEnum::Success(success_data) => {
                if success_data.status == 1 {
                    if let Some(data) = success_data.data {
                        let attempt_status = match data.status.as_deref() {
                            Some("success") => common_enums::AttemptStatus::Charged,
                            Some("pending") => common_enums::AttemptStatus::Pending,
                            Some("failure") => common_enums::AttemptStatus::Failure,
                            _ => common_enums::AttemptStatus::Pending,
                        };

                        (
                            attempt_status,
                            Ok(PaymentsResponseData::TransactionResponse {
                                resource_id: ResponseId::ConnectorTransactionId(
                                    router_data
                                        .resource_common_data
                                        .connector_request_reference_id
                                        .clone(),
                                ),
                                redirection_data: None,
                                mandate_reference: None,
                                connector_metadata: None,
                                network_txn_id: data.easebuzz_id,
                                connector_response_reference_id: data.transaction_id,
                                incremental_authorization_allowed: None,
                                status_code: http_code,
                            }),
                        )
                    } else {
                        (
                            common_enums::AttemptStatus::Pending,
                            Ok(PaymentsResponseData::TransactionResponse {
                                resource_id: ResponseId::ConnectorTransactionId(
                                    router_data
                                        .resource_common_data
                                        .connector_request_reference_id
                                        .clone(),
                                ),
                                redirection_data: None,
                                mandate_reference: None,
                                connector_metadata: None,
                                network_txn_id: None,
                                connector_response_reference_id: None,
                                incremental_authorization_allowed: None,
                                status_code: http_code,
                            }),
                        )
                    }
                } else {
                    (
                        common_enums::AttemptStatus::Failure,
                        Err(ErrorResponse {
                            status_code: http_code,
                            code: success_data.status.to_string(),
                            message: success_data.error_desc.clone().unwrap_or_default(),
                            reason: success_data.error_desc,
                            attempt_status: None,
                            connector_transaction_id: None,
                            network_advice_code: None,
                            network_decline_code: None,
                            network_error_message: None,
                        }),
                    )
                }
            }
            EaseBuzzPaymentsResponseEnum::Error(error_data) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    status_code: http_code,
                    code: error_data.status.to_string(),
                    message: error_data.error_desc.or(error_data.message).clone().unwrap_or_default(),
                    reason: error_data.error_desc.or(error_data.message),
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
            flow: router_data.flow,
            connector_auth_type: router_data.connector_auth_type,
            request: router_data.request,
        })
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<ResponseRouterData<EaseBuzzPaymentsResponseEnum, EaseBuzzRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>>>
    for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<EaseBuzzPaymentsResponseEnum, EaseBuzzRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let (status, response) = match response {
            EaseBuzzPaymentsResponseEnum::Success(success_data) => {
                if success_data.status == 1 {
                    if let Some(data) = success_data.data {
                        let attempt_status = match data.status.as_deref() {
                            Some("success") => common_enums::AttemptStatus::Charged,
                            Some("pending") => common_enums::AttemptStatus::Pending,
                            Some("failure") => common_enums::AttemptStatus::Failure,
                            _ => common_enums::AttemptStatus::Pending,
                        };

                        (
                            attempt_status,
                            Ok(PaymentsResponseData::TransactionResponse {
                                resource_id: ResponseId::ConnectorTransactionId(
                                    router_data
                                        .router_data.resource_common_data
                                        .connector_request_reference_id
                                        .clone(),
                                ),
                                redirection_data: None,
                                mandate_reference: None,
                                connector_metadata: None,
                                network_txn_id: data.easebuzz_id,
                                connector_response_reference_id: data.transaction_id,
                                incremental_authorization_allowed: None,
                                status_code: http_code,
                            }),
                        )
                    } else {
                        (
                            common_enums::AttemptStatus::Pending,
                            Ok(PaymentsResponseData::TransactionResponse {
                                resource_id: ResponseId::ConnectorTransactionId(
                                    router_data
                                        .router_data.resource_common_data
                                        .connector_request_reference_id
                                        .clone(),
                                ),
                                redirection_data: None,
                                mandate_reference: None,
                                connector_metadata: None,
                                network_txn_id: None,
                                connector_response_reference_id: None,
                                incremental_authorization_allowed: None,
                                status_code: http_code,
                            }),
                        )
                    }
                } else {
                    (
                        common_enums::AttemptStatus::Failure,
                        Err(ErrorResponse {
                            status_code: http_code,
                            code: success_data.status.to_string(),
                            message: success_data.error_desc.clone().unwrap_or_default(),
                            reason: success_data.error_desc,
                            attempt_status: None,
                            connector_transaction_id: None,
                            network_advice_code: None,
                            network_decline_code: None,
                            network_error_message: None,
                        }),
                    )
                }
            }
            EaseBuzzPaymentsResponseEnum::Error(error_data) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    status_code: http_code,
                    code: error_data.status.to_string(),
                    message: error_data.error_desc.or(error_data.message).clone().unwrap_or_default(),
                    reason: error_data.error_desc.or(error_data.message),
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
                ..router_data.router_data.resource_common_data
            },
            response,
            flow: router_data.router_data.flow,
            connector_auth_type: router_data.router_data.connector_auth_type,
            request: router_data.router_data.request,
        })
    }
}

// Unique request types for each flow to avoid templating conflicts
#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzVoidRequest;
#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzVoidPostCaptureRequest;
#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzCaptureRequest;
#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzRefundRequest;
#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzRSyncRequest;
#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzCreateOrderRequest;
#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzSessionTokenRequest;
#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzAccessTokenRequest;
#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzCreateConnectorCustomerRequest;
#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzSetupMandateRequest;
#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzRepeatPaymentRequest;
#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzPaymentTokenRequest;
#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzAcceptDisputeRequest;
#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzSubmitEvidenceRequest;
#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzDefendDisputeRequest;
#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzPreAuthenticateRequest;
#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzAuthenticateRequest;
#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzPostAuthenticateRequest;

// Unique response types for each flow to avoid templating conflicts
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EaseBuzzPaymentsSyncResponse;
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EaseBuzzVoidResponse;
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EaseBuzzCaptureResponse;
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EaseBuzzRefundResponse;
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EaseBuzzRSyncResponse;
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EaseBuzzCreateOrderResponse;
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EaseBuzzSessionTokenResponse;
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EaseBuzzSetupMandateResponse;
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EaseBuzzRepeatPaymentResponse;
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EaseBuzzAcceptDisputeResponse;
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EaseBuzzSubmitEvidenceResponse;
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EaseBuzzDefendDisputeResponse;
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EaseBuzzAccessTokenResponse;
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EaseBuzzCreateConnectorCustomerResponse;
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EaseBuzzPaymentTokenResponse;
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EaseBuzzPreAuthenticateResponse;
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EaseBuzzAuthenticateResponse;
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EaseBuzzPostAuthenticateResponse;
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EaseBuzzVoidPostCaptureResponse;