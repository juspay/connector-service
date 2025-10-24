use std::collections::HashMap;

use common_utils::{
    errors::CustomResult, ext_traits::ValueExt, request::Method, types::StringMinorUnit,
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
    utils,
};
use error_stack::ResultExt;
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};

use crate::{connectors::easebuzz::EasebuzzRouterData, types::ResponseRouterData};

// Type alias for router data
pub type EasebuzzRouterData<R, T> = crate::connectors::ConnectorRouterData<R, T>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EasebuzzAuth {
    pub key: Secret<String>,
    pub salt: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for EasebuzzAuth {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey { api_key, key } => {
                let auth = EasebuzzAuth {
                    key: api_key.clone(),
                    salt: key.clone(),
                };
                Ok(auth)
            }
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EasebuzzPaymentsRequest {
    pub txnid: String,
    pub amount: StringMinorUnit,
    pub email: Option<Email>,
    pub phone: Option<String>,
    pub productinfo: String,
    pub firstname: Option<String>,
    pub lastname: Option<String>,
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
pub struct EasebuzzPaymentsSyncRequest {
    pub txnid: String,
    pub amount: StringMinorUnit,
    pub email: Option<Email>,
    pub phone: Option<String>,
    pub key: Secret<String>,
    pub hash: Secret<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EasebuzzPaymentsResponse {
    pub status: bool,
    pub message: Option<String>,
    pub txnid: Option<String>,
    pub easebuzz_id: Option<String>,
    pub amount: Option<StringMinorUnit>,
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
    pub card_hash: Option<String>,
    pub bank_ref_num: Option<String>,
    pub bankcode: Option<String>,
    pub error_message: Option<String>,
    pub name_on_card: Option<String>,
    pub card_bin: Option<String>,
    pub card_type: Option<String>,
    pub card_brand: Option<String>,
    pub card_issuer: Option<String>,
    pub card_issuer_country: Option<String>,
    pub card_vault: Option<String>,
    pub card_token: Option<String>,
    pub card_expiry: Option<String>,
    pub card_name: Option<String>,
    pub card_number: Option<String>,
    pub card_cvv: Option<String>,
    pub card_month: Option<String>,
    pub card_year: Option<String>,
    pub card_last4: Option<String>,
    pub card_first6: Option<String>,
    pub card_category: Option<String>,
    pub card_subcategory: Option<String>,
    pub card_level: Option<String>,
    pub card_class: Option<String>,
    pub card_type_code: Option<String>,
    pub card_brand_code: Option<String>,
    pub card_issuer_code: Option<String>,
    pub card_issuer_country_code: Option<String>,
    pub card_vault_code: Option<String>,
    pub card_token_code: Option<String>,
    pub card_expiry_code: Option<String>,
    pub card_name_code: Option<String>,
    pub card_number_code: Option<String>,
    pub card_cvv_code: Option<String>,
    pub card_month_code: Option<String>,
    pub card_year_code: Option<String>,
    pub card_last4_code: Option<String>,
    pub card_first6_code: Option<String>,
    pub card_category_code: Option<String>,
    pub card_subcategory_code: Option<String>,
    pub card_level_code: Option<String>,
    pub card_class_code: Option<String>,
    pub error: Option<EasebuzzError>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EasebuzzError {
    pub code: Option<String>,
    pub message: Option<String>,
    pub source: Option<String>,
    pub step: Option<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EasebuzzUpiIntentResponse {
    pub status: bool,
    pub msg_desc: String,
    pub qr_link: Option<String>,
    pub msg_title: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EasebuzzRefundResponse {
    pub status: bool,
    pub reason: Option<String>,
    pub easebuzz_id: Option<String>,
    pub refund_id: Option<String>,
    pub refund_amount: Option<StringMinorUnit>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EasebuzzRefundSyncResponse {
    pub code: i32,
    pub status: String,
    pub response: EasebuzzRefundSyncData,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EasebuzzRefundSyncData {
    pub txnid: String,
    pub easebuzz_id: String,
    pub net_amount_debit: String,
    pub amount: String,
    pub refunds: Option<Vec<EasebuzzRefundSyncType>>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EasebuzzRefundSyncType {
    pub refund_id: String,
    pub refund_status: String,
    pub merchant_refund_id: String,
    pub merchant_refund_date: String,
    pub refund_settled_date: Option<String>,
    pub refund_amount: String,
    pub arn_number: Option<String>,
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<&EasebuzzRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>>
    for EasebuzzPaymentsRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: &EasebuzzRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let auth = EasebuzzAuth::try_from(&item.router_data.connector_auth_type)?;
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

        // Generate hash - this would typically involve SHA512 of key|txnid|amount|productinfo|firstname|email|udf1|udf2|udf3|udf4|udf5|udf6|udf7|udf8|udf9|udf10|salt
        // For now, we'll use a placeholder
        let hash_string = format!(
            "{}|{}|{}|{}|{}|{}|||||||||||{}",
            auth.key.peek(),
            item.router_data.resource_common_data.connector_request_reference_id,
            amount.get_amount_as_string(),
            "Payment",
            customer_id.get_string_repr(),
            item.router_data.request.email.as_ref().map(|e| e.to_string()).unwrap_or_default(),
            auth.salt.peek()
        );
        let hash = Secret::new(hash_string); // In real implementation, this would be SHA512 hash

        Ok(Self {
            txnid: item.router_data.resource_common_data.connector_request_reference_id.clone(),
            amount,
            email: item.router_data.request.email.clone(),
            phone: item.router_data.request.get_phone_number().map(|p| p.to_string()),
            productinfo: "Payment".to_string(),
            firstname: Some(customer_id.get_string_repr()),
            lastname: None,
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
    TryFrom<&EasebuzzRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>>
    for EasebuzzPaymentsSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: &EasebuzzRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let auth = EasebuzzAuth::try_from(&item.router_data.connector_auth_type)?;
        
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        // Generate hash for sync
        let hash_string = format!(
            "{}|{}|{}|{}|{}|{}",
            auth.key.peek(),
            item.router_data.request.connector_transaction_id.get_connector_transaction_id().map_err(|_| ConnectorError::RequestEncodingFailed)?,
            amount.get_amount_as_string(),
            item.router_data.request.email.as_ref().map(|e| e.to_string()).unwrap_or_default(),
            item.router_data.request.get_phone_number().map(|p| p.to_string()).unwrap_or_default(),
            auth.salt.peek()
        );
        let hash = Secret::new(hash_string); // In real implementation, this would be SHA512 hash

        Ok(Self {
            txnid: item.router_data.request.connector_transaction_id.get_connector_transaction_id().map_err(|_| ConnectorError::RequestEncodingFailed)?,
            amount,
            email: item.router_data.request.email.clone(),
            phone: item.router_data.request.get_phone_number().map(|p| p.to_string()),
            key: auth.key,
            hash,
        })
    }
}

impl<F, T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<ResponseRouterData<EasebuzzPaymentsResponse, &RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>>
    for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<EasebuzzPaymentsResponse, &RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let status = if response.status {
            common_enums::AttemptStatus::Charged
        } else {
            common_enums::AttemptStatus::Failure
        };

        let response_data = if response.status {
            Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    response.txnid.unwrap_or_default(),
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: response.easebuzz_id.clone(),
                connector_response_reference_id: response.easebuzz_id,
                incremental_authorization_allowed: None,
                status_code: http_code,
            })
        } else {
            Err(ErrorResponse {
                status_code: http_code,
                code: response.error.as_ref().and_then(|e| e.code.clone()).unwrap_or_default(),
                message: response.error.as_ref().and_then(|e| e.message.clone()),
                reason: response.error.as_ref().and_then(|e| e.reason.clone()),
                attempt_status: None,
                connector_transaction_id: response.txnid,
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: response.error.as_ref().and_then(|e| e.message.clone()),
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

impl<F, T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<ResponseRouterData<EasebuzzPaymentsResponse, EasebuzzRouterData<RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>>>
    for RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<EasebuzzPaymentsResponse, EasebuzzRouterData<RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let status = if response.status {
            common_enums::AttemptStatus::Charged
        } else {
            common_enums::AttemptStatus::Failure
        };

        let response_data = if response.status {
            Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    response.txnid.unwrap_or_default(),
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: response.easebuzz_id.clone(),
                connector_response_reference_id: response.easebuzz_id,
                incremental_authorization_allowed: None,
                status_code: http_code,
            })
        } else {
            Err(ErrorResponse {
                status_code: http_code,
                code: response.error.as_ref().and_then(|e| e.code.clone()).unwrap_or_default(),
                message: response.error.as_ref().and_then(|e| e.message.clone()),
                reason: response.error.as_ref().and_then(|e| e.reason.clone()),
                attempt_status: None,
                connector_transaction_id: response.txnid,
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: response.error.as_ref().and_then(|e| e.message.clone()),
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

// Stub types for unsupported flows
#[derive(Debug, Clone, Serialize)]
pub struct EasebuzzVoidRequest;

#[derive(Debug, Clone)]
pub struct EasebuzzVoidResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EasebuzzCaptureRequest;

#[derive(Debug, Clone)]
pub struct EasebuzzCaptureResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EasebuzzRefundRequest;

#[derive(Debug, Clone)]
pub struct EasebuzzRefundRequestResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EasebuzzRefundSyncRequest;

#[derive(Debug, Clone)]
pub struct EasebuzzRefundSyncResponseWrapper;

#[derive(Debug, Clone, Serialize)]
pub struct EasebuzzCreateOrderRequest;

#[derive(Debug, Clone)]
pub struct EasebuzzCreateOrderResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EasebuzzSessionTokenRequest;

#[derive(Debug, Clone)]
pub struct EasebuzzSessionTokenResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EasebuzzSetupMandateRequest;

#[derive(Debug, Clone)]
pub struct EasebuzzSetupMandateResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EasebuzzRepeatPaymentRequest;

#[derive(Debug, Clone)]
pub struct EasebuzzRepeatPaymentResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EasebuzzAcceptDisputeRequest;

#[derive(Debug, Clone)]
pub struct EasebuzzAcceptDisputeResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EasebuzzSubmitEvidenceRequest;

#[derive(Debug, Clone)]
pub struct EasebuzzSubmitEvidenceResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EasebuzzDefendDisputeRequest;

#[derive(Debug, Clone)]
pub struct EasebuzzDefendDisputeResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EasebuzzPreAuthenticateRequest;

#[derive(Debug, Clone)]
pub struct EasebuzzPreAuthenticateResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EasebuzzAuthenticateRequest;

#[derive(Debug, Clone)]
pub struct EasebuzzAuthenticateResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EasebuzzPostAuthenticateRequest;

#[derive(Debug, Clone)]
pub struct EasebuzzPostAuthenticateResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EasebuzzCreateAccessTokenRequest;

#[derive(Debug, Clone)]
pub struct EasebuzzCreateAccessTokenResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EasebuzzCreateConnectorCustomerRequest;

#[derive(Debug, Clone)]
pub struct EasebuzzCreateConnectorCustomerResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EasebuzzPaymentMethodTokenRequest;

#[derive(Debug, Clone)]
pub struct EasebuzzPaymentMethodTokenResponse;