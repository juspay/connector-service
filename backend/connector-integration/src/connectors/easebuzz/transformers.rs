use std::collections::HashMap;

use common_utils::{
    errors::CustomResult,
    request::Method,
    types::StringMinorUnit,
    Email,
};
use domain_types::{
    connector_flow::{Authorize, PSync, RSync, Refund},
    connector_types::{
        PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData,
        RefundFlowData, RefundsData, RefundsResponseData, RefundSyncData,
    },
    errors::{self, ConnectorError},
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
};
use error_stack::ResultExt;
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};

// MD5 implementation for hash generation
fn md5_compute(input: &str) -> md5::Digest {
    md5::compute(input)
}

use crate::{connectors::easebuzz::EaseBuzzRouterData, types::ResponseRouterData};

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzPaymentsRequest {
    txnid: String,
    amount: StringMinorUnit,
    productinfo: String,
    firstname: Option<String>,
    email: Option<Email>,
    phone: Option<String>,
    surl: String,
    furl: String,
    udf1: Option<String>,
    udf2: Option<String>,
    udf3: Option<String>,
    udf4: Option<String>,
    udf5: Option<String>,
    udf6: Option<String>,
    udf7: Option<String>,
    udf8: Option<String>,
    udf9: Option<String>,
    udf10: Option<String>,
    hash: Secret<String>,
    address1: Option<String>,
    address2: Option<String>,
    city: Option<String>,
    state: Option<String>,
    country: Option<String>,
    zipcode: Option<String>,
    pg: Option<String>,
    customer_unique_id: Option<String>,
    split_payments: Option<String>,
    sub_merchant_id: Option<String>,
    merchant_name: Option<String>,
    merchant_logo_url: Option<String>,
    merchant_trn_id: Option<String>,
    custom_note: Option<String>,
    enforce_paymethod: Option<String>,
    surcharge: Option<String>,
    show_payment_modes: Option<String>,
    card_holder_name: Option<String>,
    card_number: Option<String>,
    card_cvv: Option<String>,
    card_expiry: Option<String>,
    card_bank_code: Option<String>,
    name_on_card: Option<String>,
    emi_plan_id: Option<String>,
    emi_tenure_id: Option<String>,
    bankcode: Option<String>,
    account_number: Option<String>,
    ifsc: Option<String>,
    account_holder_name: Option<String>,
    vpa: Option<String>,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzPaymentsSyncRequest {
    txnid: String,
    amount: StringMinorUnit,
    email: Option<Email>,
    phone: Option<String>,
    key: String,
    hash: Secret<String>,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzRefundRequest {
    txnid: String,
    refund_amount: StringMinorUnit,
    refund_note: Option<String>,
    key: String,
    hash: Secret<String>,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzRefundSyncRequest {
    key: String,
    easebuzz_id: String,
    hash: Secret<String>,
    merchant_refund_id: String,
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
pub struct EaseBuzzCreateOrderRequest;

#[derive(Debug, Clone)]
pub struct EaseBuzzCreateOrderResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzSessionTokenRequest;

#[derive(Debug, Clone)]
pub struct EaseBuzzSessionTokenResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzSetupMandateRequest;

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
pub struct EaseBuzzDefendDisputeRequest;

#[derive(Debug, Clone)]
pub struct EaseBuzzDefendDisputeResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzSubmitEvidenceRequest;

#[derive(Debug, Clone)]
pub struct EaseBuzzSubmitEvidenceResponse;

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
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

        // Extract payment method details
        let payment_method_data = item.router_data.request.payment_method_data.clone();
        
        let (vpa, phone, email) = match payment_method_data {
            Some(pm_data) => {
                match pm_data {
                    domain_types::payment_method_data::PaymentMethodData::Upi(upi_data) => {
                        (upi_data.vpa.clone(), None, item.router_data.request.email.clone())
                    }
                    _ => (None, None, item.router_data.request.email.clone()),
                }
            }
            None => (None, None, item.router_data.request.email.clone()),
        };

        // Generate hash - this would typically involve the merchant key and other parameters
        let hash = generate_easebuzz_hash(
            &item.router_data.connector_auth_type,
            &item.router_data.resource_common_data.connector_request_reference_id,
            &amount.get_amount_as_string(),
            &item.router_data.request.currency.to_string(),
        )?;

        match item.router_data.resource_common_data.payment_method {
            common_enums::PaymentMethod::Upi => Ok(Self {
                txnid: item
                    .router_data
                    .resource_common_data
                    .connector_request_reference_id,
                amount,
                productinfo: "Payment".to_string(),
                firstname: Some(customer_id.get_string_repr().to_string()),
                email,
                phone,
                surl: return_url.to_owned(),
                furl: return_url,
                vpa,
                hash,
                ..Default::default()
            }),
            _ => Err(errors::ConnectorError::NotImplemented(
                "Payment methods".to_string(),
            )
            .into()),
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
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        let key = get_merchant_key(&item.router_data.connector_auth_type)?;
        let hash = generate_easebuzz_hash(
            &item.router_data.connector_auth_type,
            &item.router_data.request.connector_transaction_id.get_connector_transaction_id()
                .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?,
            &amount.get_amount_as_string(),
            &item.router_data.request.currency.to_string(),
        )?;

        Ok(Self {
            txnid: item.router_data.request.connector_transaction_id
                .get_connector_transaction_id()
                .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?,
            amount,
            email: item.router_data.request.email.clone(),
            phone: None,
            key,
            hash,
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
        EaseBuzzRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    > for EaseBuzzRefundRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: EaseBuzzRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        let key = get_merchant_key(&item.router_data.connector_auth_type)?;
        let hash = generate_easebuzz_hash(
            &item.router_data.connector_auth_type,
            &item.router_data.request.connector_transaction_id.get_connector_transaction_id()
                .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?,
            &amount.get_amount_as_string(),
            &item.router_data.request.currency.to_string(),
        )?;

        Ok(Self {
            txnid: item.router_data.request.connector_transaction_id
                .get_connector_transaction_id()
                .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?,
            refund_amount: amount,
            refund_note: item.router_data.request.reason.clone(),
            key,
            hash,
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
        EaseBuzzRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    > for EaseBuzzRefundSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: EaseBuzzRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let key = get_merchant_key(&item.router_data.connector_auth_type)?;
        let hash = generate_easebuzz_hash(
            &item.router_data.connector_auth_type,
            &item.router_data.request.connector_transaction_id.get_connector_transaction_id()
                .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?,
            &"0".to_string(), // Dummy amount for hash
            &item.router_data.request.currency.to_string(),
        )?;

        Ok(Self {
            key,
            easebuzz_id: item.router_data.request.connector_transaction_id
                .get_connector_transaction_id()
                .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?,
            hash,
            merchant_refund_id: item.router_data.request.refund_id.clone(),
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzPaymentsResponse {
    pub status: i32,
    pub error_desc: Option<String>,
    pub data: EaseBuzzPaymentsResponseData,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzPaymentsResponseData {
    pub payment_url: Option<String>,
    pub transaction_id: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzPaymentsSyncResponse {
    pub txnid: String,
    pub status: bool,
    pub amount: StringMinorUnit,
    pub message: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzRefundResponse {
    pub status: bool,
    pub reason: Option<String>,
    pub easebuzz_id: Option<String>,
    pub refund_id: Option<String>,
    pub refund_amount: Option<StringMinorUnit>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzRefundSyncResponse {
    pub code: i32,
    pub status: String,
    pub response: EaseBuzzRefundSyncData,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzRefundSyncData {
    pub txnid: String,
    pub easebuzz_id: String,
    pub net_amount_debit: String,
    pub amount: String,
    pub refunds: Option<Vec<EaseBuzzRefundSyncType>>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzRefundSyncType {
    pub refund_id: String,
    pub refund_status: String,
    pub merchant_refund_id: String,
    pub merchant_refund_date: String,
    pub refund_settled_date: Option<String>,
    pub refund_amount: String,
    pub arn_number: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct EaseBuzzErrorResponse {
    pub status: i32,
    pub error_desc: Option<String>,
    pub data: serde_json::Value,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EaseBuzzPaymentStatus {
    Success,
    Pending,
    Failure,
    #[default]
    Unknown,
}

impl From<EaseBuzzPaymentStatus> for common_enums::AttemptStatus {
    fn from(item: EaseBuzzPaymentStatus) -> Self {
        match item {
            EaseBuzzPaymentStatus::Success => Self::Charged,
            EaseBuzzPaymentStatus::Pending => Self::AuthenticationPending,
            EaseBuzzPaymentStatus::Failure => Self::Failure,
            EaseBuzzPaymentStatus::Unknown => Self::AuthenticationPending,
        }
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

        let (status, response) = if response.status == 1 {
            // Success case
            let redirection_data = if let Some(payment_url) = response.data.payment_url {
                Some(Box::new(RedirectForm::Form {
                    endpoint: payment_url,
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
                    network_txn_id: response.data.transaction_id,
                    connector_response_reference_id: None,
                    incremental_authorization_allowed: None,
                    status_code: http_code,
                }),
            )
        } else {
            // Error case
            (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: response.status.to_string(),
                    status_code: http_code,
                    message: response.error_desc.clone(),
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
            response,
            ..router_data
        })
    }
}

impl<
        F,
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize
            + Serialize,
    > TryFrom<ResponseRouterData<EaseBuzzPaymentsSyncResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
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

        let status = if response.status {
            common_enums::AttemptStatus::Charged
        } else {
            common_enums::AttemptStatus::Failure
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(response.txnid),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: Some(response.txnid),
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                status_code: http_code,
            }),
            ..router_data
        })
    }
}

impl<
        F,
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize
            + Serialize,
    > TryFrom<ResponseRouterData<EaseBuzzRefundResponse, Self>>
    for RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<EaseBuzzRefundResponse, Self>,
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

        Ok(Self {
            resource_common_data: domain_types::connector_types::RefundFlowData {
                status,
                ..router_data.resource_common_data
            },
            response: Ok(RefundsResponseData {
                refund_id: response.refund_id,
                connector_refund_id: response.easebuzz_id,
                refund_amount_received: response.refund_amount,
                connector_response_reference_id: None,
                status_code: http_code,
            }),
            ..router_data
        })
    }
}

impl<
        F,
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize
            + Serialize,
    > TryFrom<ResponseRouterData<EaseBuzzRefundSyncResponse, Self>>
    for RouterDataV2<F, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<EaseBuzzRefundSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let status = if response.status == "success" {
            common_enums::AttemptStatus::Charged
        } else {
            common_enums::AttemptStatus::Failure
        };

        Ok(Self {
            resource_common_data: domain_types::connector_types::RefundFlowData {
                status,
                ..router_data.resource_common_data
            },
            response: Ok(RefundsResponseData {
                refund_id: response.response.refunds.first().map(|r| r.refund_id.clone()),
                connector_refund_id: Some(response.response.easebuzz_id),
                refund_amount_received: response.response.refunds.first().and_then(|r| {
                    r.refund_amount.parse::<i64>().ok().map(common_utils::types::MinorUnit)
                }),
                connector_response_reference_id: None,
                status_code: http_code,
            }),
            ..router_data
        })
    }
}

fn get_merchant_key(auth_type: &ConnectorAuthType) -> CustomResult<String, errors::ConnectorError> {
    match auth_type {
        ConnectorAuthType::SignatureKey { api_key, .. } => Ok(api_key.peek().to_string()),
        _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
    }
}

fn generate_easebuzz_hash(
    auth_type: &ConnectorAuthType,
    txnid: &str,
    amount: &str,
    currency: &str,
) -> CustomResult<Secret<String>, errors::ConnectorError> {
    // This is a simplified hash generation - in reality, EaseBuzz uses a specific hash algorithm
    // involving the merchant key, salt, and various parameters
    let key = get_merchant_key(auth_type)?;
    
    // Simplified hash generation - actual implementation would follow EaseBuzz's hash algorithm
    let hash_string = format!("{}|{}|{}|{}", key, txnid, amount, currency);
    let hash = format!("{:x}", md5_compute(&hash_string));
    
    Ok(Secret::new(hash))
}