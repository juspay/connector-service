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
use hyperswitch_masking::{PeekInterface, Secret};
use serde::{Deserialize, Serialize};

use crate::{connectors::easebuzz::EaseBuzzRouterData, types::ResponseRouterData};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzAuth {
    pub key: Secret<String>,
    pub salt: Secret<String>,
    pub iv: Option<Secret<String>>,
}

impl TryFrom<&ConnectorAuthType> for EaseBuzzAuth {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey { api_key, key1, api_secret, .. } => {
                // For now, create a simple auth structure - in real implementation, parse from api_secret
                let auth_data = EaseBuzzAuth {
                    key: api_secret.clone(),
                    salt: Secret::new("default_salt".to_string()),
                    iv: None,
                };
                Ok(auth_data)
            }
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzPaymentsRequest {
    pub key: Secret<String>,
    pub txnid: String,
    pub amount: StringMinorUnit,
    pub productinfo: String,
    pub firstname: Option<String>,
    pub email: Option<Email>,
    pub phone: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address1: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address2: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zipcode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pg: Option<String>,
}

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzUpiIntentRequest {
    pub key: Secret<String>,
    pub txnid: String,
    pub amount: StringMinorUnit,
    pub surl: String,
    pub furl: String,
    pub hash: Secret<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub customer_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub customer_email: Option<Email>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub customer_mobile: Option<String>,
}

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzPaymentsSyncRequest {
    pub key: Secret<String>,
    pub txnid: String,
    pub amount: StringMinorUnit,
    pub email: Option<Email>,
    pub phone: Option<String>,
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
    pub data: EaseBuzzPaymentData,
    pub msg_desc: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzPaymentData {
    pub payment_url: Option<String>,
    pub easebuzz_id: Option<String>,
    pub transaction_id: Option<String>,
    pub status: Option<String>,
    pub amount: Option<String>,
    pub currency: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzUpiIntentResponse {
    pub status: bool,
    pub msg_desc: String,
    pub qr_link: Option<String>,
    pub msg_title: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzTxnSyncResponse {
    pub status: bool,
    pub msg: EaseBuzzTxnSyncMessage,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum EaseBuzzTxnSyncMessage {
    Success(EaseBuzzPaymentData),
    Error(String),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzErrorResponse {
    pub status: i32,
    pub error_desc: Option<String>,
    pub data: String,
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
        let return_url = item.router_data.request.get_router_return_url()?;
        
        // Extract amount using proper amount converter
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        // Generate hash (simplified - in real implementation, this would use proper hashing)
        let hash_string = format!(
            "{}|{}|{}|{}|{}|{}|{}",
            auth.key.peek(),
            item.router_data.resource_common_data.connector_request_reference_id,
            amount.to_string(),
            "Product", // productinfo
            item.router_data.request.email.as_ref().map(|e| e.peek().clone()).unwrap_or_default(),
            return_url,
            return_url
        );
        
        Ok(Self {
            key: auth.key,
            txnid: item.router_data.resource_common_data.connector_request_reference_id.clone(),
            amount,
            productinfo: "Product".to_string(),
            firstname: None, // TODO: Extract from customer data if available
            email: item.router_data.request.email.clone(),
            phone: None, // TODO: Extract from customer data if available
            surl: return_url.clone(),
            furl: return_url,
            hash: Secret::new(hash_string),
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
            pg: Some("UPI".to_string()),
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
        
        // For sync requests, we need to extract the amount from the connector metadata or use a default
        // This is a simplified implementation - in practice, you'd store the amount in the metadata
        let amount = StringMinorUnit::from(1000); // Default amount for sync

        // Generate hash for sync request
        let hash_string = format!(
            "{}|{}|{}|{}|{}",
            auth.key.peek(),
            item.router_data.request.connector_transaction_id.get_connector_transaction_id().map_err(|_| ConnectorError::MissingRequiredField { field_name: "connector_transaction_id" })?,
            amount.to_string(),
            "", // email - not available in sync request
            "" // phone - not available in sync request
        );

        Ok(Self {
            key: auth.key,
            txnid: item.router_data.request.connector_transaction_id.get_connector_transaction_id().map_err(|_| ConnectorError::MissingRequiredField { field_name: "connector_transaction_id" })?,
            amount,
            email: None,
            phone: None,
            hash: Secret::new(hash_string),
        })
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<ResponseRouterData<EaseBuzzPaymentsResponse, RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>>
    for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<EaseBuzzPaymentsResponse, RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let (status, response) = match response {
            EaseBuzzPaymentsResponse::Success(success_data) => {
                let redirection_data = success_data.data.payment_url.map(|url| {
                    Box::new(RedirectForm::Form {
                        endpoint: url,
                        method: Method::Get,
                        form_fields: HashMap::new(),
                    })
                });

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
                        network_txn_id: success_data.data.easebuzz_id,
                        connector_response_reference_id: success_data.data.transaction_id,
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

impl TryFrom<ResponseRouterData<EaseBuzzTxnSyncResponse, RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>>
    for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<EaseBuzzTxnSyncResponse, RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let (status, response) = match response.msg {
            EaseBuzzTxnSyncMessage::Success(success_data) => {
                let attempt_status = match success_data.status.as_deref() {
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
                        network_txn_id: success_data.easebuzz_id,
                        connector_response_reference_id: success_data.transaction_id,
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                    }),
                )
            }
            EaseBuzzTxnSyncMessage::Error(error_msg) => (
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

// Stub types for unsupported flows
#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzVoidRequest;

#[derive(Debug, Clone)]
pub struct EaseBuzzVoidResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzCaptureRequest;

#[derive(Debug, Clone)]
pub struct EaseBuzzCaptureResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzRefundRequest;

#[derive(Debug, Clone)]
pub struct EaseBuzzRefundResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzRefundSyncRequest;

#[derive(Debug, Clone)]
pub struct EaseBuzzRefundSyncResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzCreateOrderRequest;

#[derive(Debug, Clone)]
pub struct EaseBuzzCreateOrderResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzSessionTokenRequest;

#[derive(Debug, Clone)]
pub struct EaseBuzzSessionTokenResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzSetupMandateRequest<T> {
    #[serde(skip)]
    _phantom: std::marker::PhantomData<T>,
}

#[derive(Debug, Clone)]
pub struct EaseBuzzSetupMandateResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzRepeatPaymentRequest;

#[derive(Debug, Clone)]
pub struct EaseBuzzRepeatPaymentResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzAcceptDisputeRequest;

#[derive(Debug, Clone)]
pub struct EaseBuzzAcceptDisputeResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzSubmitEvidenceRequest;

#[derive(Debug, Clone)]
pub struct EaseBuzzSubmitEvidenceResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzDefendDisputeRequest;

#[derive(Debug, Clone)]
pub struct EaseBuzzDefendDisputeResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzPreAuthenticateRequest<T> {
    #[serde(skip)]
    _phantom: std::marker::PhantomData<T>,
}

#[derive(Debug, Clone)]
pub struct EaseBuzzPreAuthenticateResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzAuthenticateRequest<T> {
    #[serde(skip)]
    _phantom: std::marker::PhantomData<T>,
}

#[derive(Debug, Clone)]
pub struct EaseBuzzAuthenticateResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzPostAuthenticateRequest<T> {
    #[serde(skip)]
    _phantom: std::marker::PhantomData<T>,
}

#[derive(Debug, Clone)]
pub struct EaseBuzzPostAuthenticateResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzCreateAccessTokenRequest;

#[derive(Debug, Clone)]
pub struct EaseBuzzCreateAccessTokenResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzCreateConnectorCustomerRequest;

#[derive(Debug, Clone)]
pub struct EaseBuzzCreateConnectorCustomerResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzPaymentMethodTokenRequest<T> {
    #[serde(skip)]
    _phantom: std::marker::PhantomData<T>,
}

#[derive(Debug, Clone)]
pub struct EaseBuzzPaymentMethodTokenResponse;