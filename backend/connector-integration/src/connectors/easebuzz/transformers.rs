use base64::Engine as _;
use common_utils::{
    errors::CustomResult, request::Method, types::StringMinorUnit,
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
use hyperswitch_masking::{Mask, PeekInterface, Secret, Maskable};
use serde::{Deserialize, Serialize};

use crate::{connectors::easebuzz::EaseBuzzRouterData, types::ResponseRouterData};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzPaymentsRequest {
    key: Secret<String>,
    txnid: String,
    amount: StringMinorUnit,
    productinfo: String,
    firstname: Option<Secret<String>>,
    email: Option<Email>,
    phone: Option<Secret<String>>,
    surl: String,
    furl: String,
    hash: Secret<String>,
    udf1: Option<String>,
    udf2: Option<String>,
    udf3: Option<String>,
    udf4: Option<String>,
    udf5: Option<String>,
    address1: Option<String>,
    address2: Option<String>,
    city: Option<String>,
    state: Option<String>,
    country: Option<String>,
    zipcode: Option<String>,
    pg: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzPaymentsSyncRequest {
    key: Secret<String>,
    txnid: String,
    amount: StringMinorUnit,
    email: Option<Email>,
    phone: Option<Secret<String>>,
    hash: Secret<String>,
}

#[derive(Debug, Serialize)]
pub struct EaseBuzzAuth {
    pub api_key: Secret<String>,
    pub salt: Secret<String>,
    pub merchant_id: Option<Secret<String>>,
}

impl EaseBuzzAuth {
    pub fn get_auth_headers(
        connector_auth_type: &ConnectorAuthType,
        _currency: &common_enums::Currency,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        match EaseBuzzAuth::try_from(connector_auth_type) {
            Ok(auth) => {
                let auth_string = format!("Basic {}", 
                    base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", 
                        auth.api_key.peek(), 
                        auth.salt.peek()
                    ))
                );
                Ok(vec![(
                    "Authorization".to_string(),
                    auth_string.into_masked(),
                )])
            }
            Err(_) => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }

    pub fn generate_hash(&self, data: &str) -> String {
        use sha2::{Digest, Sha512};
        let mut hasher = Sha512::new();
        hasher.update(format!("{}|{}", data, self.salt.peek()));
        format!("{:x}", hasher.finalize())
    }
}

impl TryFrom<&ConnectorAuthType> for EaseBuzzAuth {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey { api_key, key1, .. } => {
                let auth = Self {
                    api_key: api_key.clone(),
                    salt: key1.clone(),
                    merchant_id: None,
                };
                Ok(auth)
            }
            ConnectorAuthType::BodyKey { api_key, key1 } => {
                let auth = Self {
                    api_key: api_key.clone(),
                    salt: key1.clone(),
                    merchant_id: None,
                };
                Ok(auth)
            }
            ConnectorAuthType::HeaderKey { api_key } => {
                let auth = Self {
                    api_key: api_key.clone(),
                    salt: Secret::new("".to_string()),
                    merchant_id: None,
                };
                Ok(auth)
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
    > TryFrom<
        EaseBuzzRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for EaseBuzzPaymentsRequest
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: EaseBuzzRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = EaseBuzzAuth::try_from(&item.router_data.connector_auth_type)?;
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

        // Generate hash string
        let hash_string = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}",
            auth.api_key.peek(),
            item.router_data.resource_common_data.connector_request_reference_id,
            amount.to_string(),
            "UPI Payment",
            customer_id,
            item.router_data.request.email.as_ref().map(|e| e.to_string()).unwrap_or_else(|| "".to_string()),
            
            return_url,
            return_url,
        );

        Ok(Self {
            key: auth.api_key,
            txnid: item.router_data.resource_common_data.connector_request_reference_id.clone(),
            amount,
            productinfo: "UPI Payment".to_string(),
            firstname: Some(Secret::new(customer_id.0.clone())),
            email: item.router_data.request.email.clone(),
            phone: None,
            surl: return_url.clone(),
            furl: return_url,
            hash: Secret::new(auth.generate_hash(&hash_string)),
            udf1: None,
            udf2: None,
            udf3: None,
            udf4: None,
            udf5: None,
            address1: None,
            address2: None,
            city: None,
            state: None,
            country: None,
            zipcode: None,
            pg: Some("UPI".to_string()),
        })
    }
}

// PSync implementation removed - only Authorize flow is supported
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: EaseBuzzRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = EaseBuzzAuth::try_from(&item.router_data.connector_auth_type)?;
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        // Generate hash string for sync
        let hash_string = format!(
            "{}|{}|{}|{}",
            auth.api_key.peek(),
            item.router_data.request.connector_transaction_id.get_connector_transaction_id().unwrap_or_else(|_| "".to_string()),
            amount.to_string(),
            item.router_data.request.email.as_ref().map(|e| e.to_string()).unwrap_or_else(|| "".to_string()),
        );

        Ok(Self {
            key: auth.api_key,
            txnid: item.router_data.request.connector_transaction_id.get_connector_transaction_id().unwrap_or_else(|_| "".to_string()),
            amount,
            email: None,
            phone: None,
            hash: Secret::new(auth.generate_hash(&hash_string)),
        })
    }
}

#[derive(Debug, Deserialize, Clone, Serialize)]
#[serde(untagged)]
pub enum EaseBuzzPaymentsResponse {
    Success(EaseBuzzSuccessResponse),
    Error(EaseBuzzErrorResponse),
}

#[derive(Debug, Deserialize, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzSuccessResponse {
    pub status: i32,
    pub data: EaseBuzzPaymentData,
    pub error_desc: Option<String>,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzPaymentData {
    pub payment_url: Option<String>,
    pub transaction_id: Option<String>,
    pub status: Option<String>,
    pub amount: Option<f64>,
    pub currency: Option<String>,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzErrorResponse {
    pub status: i32,
    pub error_desc: Option<String>,
    pub message: Option<String>,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzWebhookResponse {
    pub transaction_id: String,
    pub status: String,
    pub amount: Option<f64>,
    pub currency: Option<String>,
    #[serde(rename = "type")]
    pub event_type: Option<String>,
}

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
            EaseBuzzPaymentsResponse::Success(success_data) => {
                // For UPI payments, we typically get a payment URL for redirection
                if let Some(payment_url) = success_data.data.payment_url {
                    let redirection_data = RedirectForm::Form {
                        endpoint: payment_url,
                        method: Method::Get,
                        form_fields: Default::default(),
                    };
                    
                    (
                        common_enums::AttemptStatus::AuthenticationPending,
                        Ok(PaymentsResponseData::TransactionResponse {
                            resource_id: ResponseId::ConnectorTransactionId(
                                success_data.data.transaction_id.unwrap_or_else(|| 
                                    router_data.resource_common_data.connector_request_reference_id.clone()
                                ),
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
                    // Direct success case (for wallet payments, etc.)
                    (
                        common_enums::AttemptStatus::Charged,
                        Ok(PaymentsResponseData::TransactionResponse {
                            resource_id: ResponseId::ConnectorTransactionId(
                                success_data.data.transaction_id.unwrap_or_else(|| 
                                    router_data.resource_common_data.connector_request_reference_id.clone()
                                ),
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
            }
            EaseBuzzPaymentsResponse::Error(error_data) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    status_code: error_data.status as u16,
                    code: error_data.error_desc.clone().unwrap_or_default(),
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

impl<F> TryFrom<ResponseRouterData<EaseBuzzPaymentsResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
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
            EaseBuzzPaymentsResponse::Success(success_data) => {
                let attempt_status = match success_data.data.status.as_deref() {
                    Some("success") | Some("completed") => common_enums::AttemptStatus::Charged,
                    Some("pending") => common_enums::AttemptStatus::Pending,
                    Some("failed") => common_enums::AttemptStatus::Failure,
                    _ => common_enums::AttemptStatus::AuthenticationPending,
                };

                (
                    attempt_status,
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(
                            success_data.data.transaction_id.unwrap_or_else(|| 
                                router_data.request.connector_transaction_id.as_deref().unwrap_or("").to_string()
                            ),
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
            EaseBuzzPaymentsResponse::Error(error_data) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    status_code: error_data.status as u16,
                    code: error_data.error_desc.clone().unwrap_or_default(),
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