use std::{collections::HashMap, fmt::Debug};

use crate::types::ResponseRouterData;
use common_enums::AttemptStatus;
use common_enums::RefundStatus;
use common_utils::types::StringMajorUnit;
use domain_types::{
    connector_flow::{
        Authorize, CreateOrder, MandateRevoke, PSync, RSync, Refund, RepeatPayment, SetupMandate,
    },
    connector_types::{
        EventType, MandateReference, MandateReferenceId, MandateRevokeRequestData,
        MandateRevokeResponseData, PaymentCreateOrderData, PaymentCreateOrderResponse,
        PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData,
        RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData, RepeatPaymentData,
        ResponseId, SetupMandateRequestData,
    },
    errors,
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes, UpiData, WalletData},
    router_data::ConnectorSpecificConfig,
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, PeekInterface, Secret};
use serde::{Deserialize, Serialize};

use super::EasebuzzRouterData;

// =============================================================================
// AUTH TYPE
// =============================================================================
#[derive(Debug, Clone)]
pub struct EasebuzzAuthType {
    pub api_key: Secret<String>,
}

impl TryFrom<&ConnectorSpecificConfig> for EasebuzzAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorSpecificConfig) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorSpecificConfig::Easebuzz { api_key, .. } => Ok(Self {
                api_key: api_key.to_owned(),
            }),
            _ => Err(error_stack::report!(
                errors::ConnectorError::FailedToObtainAuthType
            )),
        }
    }
}

// =============================================================================
// ERROR RESPONSE
// =============================================================================
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EasebuzzErrorResponse {
    pub code: String,
    pub message: String,
}

// =============================================================================
// CREATE ORDER - REQUEST
// =============================================================================
/// Request body for Easebuzz InitiatePayment API (form-urlencoded).
/// POST https://pay.easebuzz.in/payment/initiateLink
/// Hash: sha512(key|txnid|amount|productinfo|firstname|email|||||||||||salt)
#[derive(Debug, Serialize)]
pub struct EasebuzzCreateOrderRequest {
    pub key: String,
    pub txnid: String,
    pub amount: StringMajorUnit,
    pub productinfo: String,
    pub firstname: String,
    pub phone: String,
    pub email: String,
    pub surl: String,
    pub furl: String,
    pub hash: String,
}

/// Compute SHA-512 hash for Easebuzz InitiatePayment.
/// Formula: sha512(key|txnid|amount|productinfo|firstname|email|||||||||||salt)
/// The empty pipes represent udf1..udf10 fields which are empty.
fn compute_initiate_payment_hash(
    key: &str,
    txnid: &str,
    amount: &str,
    productinfo: &str,
    firstname: &str,
    email: &str,
    salt: &str,
) -> String {
    use sha2::{Digest, Sha512};

    // key|txnid|amount|productinfo|firstname|email|udf1|udf2|udf3|udf4|udf5|udf6|udf7|udf8|udf9|udf10|salt
    let hash_input =
        format!("{key}|{txnid}|{amount}|{productinfo}|{firstname}|{email}|||||||||||{salt}");

    let mut hasher = Sha512::new();
    hasher.update(hash_input.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        EasebuzzRouterData<
            RouterDataV2<
                CreateOrder,
                PaymentFlowData,
                PaymentCreateOrderData,
                PaymentCreateOrderResponse,
            >,
            T,
        >,
    > for EasebuzzCreateOrderRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: EasebuzzRouterData<
            RouterDataV2<
                CreateOrder,
                PaymentFlowData,
                PaymentCreateOrderData,
                PaymentCreateOrderResponse,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;

        // Get the merchant key from connector config
        let auth = EasebuzzAuthType::try_from(&router_data.connector_config)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        let key = auth.api_key.expose();

        // Convert amount to major unit string (e.g., "100.00")
        let amount = item
            .connector
            .amount_converter
            .convert(router_data.request.amount, router_data.request.currency)
            .change_context(errors::ConnectorError::AmountConversionFailed)?;

        let txnid = router_data
            .resource_common_data
            .connector_request_reference_id
            .clone();

        let productinfo = router_data
            .resource_common_data
            .description
            .clone()
            .unwrap_or_else(|| "Payment".to_string());

        // Extract customer details from billing address
        let billing = router_data
            .resource_common_data
            .address
            .get_payment_method_billing();

        let firstname = billing
            .and_then(|b| b.address.as_ref())
            .and_then(|a| a.first_name.as_ref())
            .map(|n| n.clone().expose())
            .unwrap_or_else(|| "Customer".to_string());

        let email = billing
            .and_then(|b| b.email.as_ref())
            .map(|e| e.peek().to_string())
            .unwrap_or_else(|| "customer@example.com".to_string());

        let phone = billing
            .and_then(|b| b.phone.as_ref())
            .and_then(|p| p.number.as_ref())
            .map(|n| n.clone().expose())
            .unwrap_or_else(|| "9999999999".to_string());

        // Return URL for surl/furl
        let return_url = router_data
            .resource_common_data
            .return_url
            .clone()
            .unwrap_or_else(|| "https://example.com/callback".to_string());

        let surl = return_url.clone();
        let furl = return_url;

        let amount_str = amount.get_amount_as_string();

        // Compute SHA-512 hash
        // For Easebuzz, the api_key serves as both key and salt since only api_key is available
        // in ConnectorSpecificConfig. The key is used directly as the merchant key field,
        // and also as the salt in the hash computation.
        let hash = compute_initiate_payment_hash(
            &key,
            &txnid,
            &amount_str,
            &productinfo,
            &firstname,
            &email,
            &key,
        );

        Ok(Self {
            key,
            txnid,
            amount,
            productinfo,
            firstname,
            phone,
            email,
            surl,
            furl,
            hash,
        })
    }
}

// =============================================================================
// CREATE ORDER - RESPONSE
// =============================================================================
/// Response from Easebuzz InitiatePayment API.
/// `status` = 1 means success, `data` contains the access_key.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EasebuzzCreateOrderResponse {
    pub status: i32,
    pub data: String,
    pub error_desc: Option<String>,
}

impl
    TryFrom<
        ResponseRouterData<
            EasebuzzCreateOrderResponse,
            RouterDataV2<
                CreateOrder,
                PaymentFlowData,
                PaymentCreateOrderData,
                PaymentCreateOrderResponse,
            >,
        >,
    >
    for RouterDataV2<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    >
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            EasebuzzCreateOrderResponse,
            RouterDataV2<
                CreateOrder,
                PaymentFlowData,
                PaymentCreateOrderData,
                PaymentCreateOrderResponse,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        let response = item.response;

        if response.status != 1 {
            let error_msg = response.error_desc.unwrap_or_else(|| response.data.clone());
            return Err(error_stack::report!(
                errors::ConnectorError::ResponseHandlingFailed
            ))
            .attach_printable(format!("Easebuzz CreateOrder failed: {error_msg}"));
        }

        // `data` contains the access_key which is used by the Authorize flow
        let access_key = response.data;

        Ok(Self {
            response: Ok(PaymentCreateOrderResponse {
                order_id: access_key.clone(),
                session_token: None,
            }),
            resource_common_data: PaymentFlowData {
                status: AttemptStatus::Pending,
                reference_id: Some(access_key),
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

// =============================================================================
// AUTHORIZE (Seamless Payment) - REQUEST
// =============================================================================
/// Request body for Easebuzz Seamless Payment API (form-urlencoded).
/// POST https://pay.easebuzz.in/initiate_seamless_payment/
/// Uses access_key from CreateOrder response.
#[derive(Debug, Serialize)]
pub struct EasebuzzAuthorizeRequest {
    pub access_key: String,
    pub payment_mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upi_va: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upi_qr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bank_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pay_later_app: Option<String>,
}

/// Easebuzz payment mode values for different payment methods
#[derive(Debug, Clone)]
pub enum EasebuzzPaymentMode {
    Upi,
    NetBanking,
    Wallet,
}

impl EasebuzzPaymentMode {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Upi => "UPI",
            Self::NetBanking => "NB",
            Self::Wallet => "WALLET",
        }
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
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
    > for EasebuzzAuthorizeRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

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
        let router_data = &item.router_data;

        // Get the access_key from CreateOrder response stored in reference_id
        let access_key = router_data
            .resource_common_data
            .reference_id
            .clone()
            .ok_or(errors::ConnectorError::MissingRequiredField {
                field_name: "reference_id (access_key from CreateOrder)",
            })?;

        // Determine payment mode and method-specific fields based on payment method data
        let (payment_mode, upi_va, upi_qr, bank_code, pay_later_app) =
            match &router_data.request.payment_method_data {
                PaymentMethodData::Upi(upi_data) => match upi_data {
                    UpiData::UpiCollect(collect_data) => {
                        let vpa = collect_data
                            .vpa_id
                            .as_ref()
                            .ok_or(errors::ConnectorError::MissingRequiredField {
                                field_name: "vpa_id",
                            })?
                            .peek()
                            .to_string();
                        (EasebuzzPaymentMode::Upi, Some(vpa), None, None, None)
                    }
                    UpiData::UpiIntent(_) => (EasebuzzPaymentMode::Upi, None, None, None, None),
                    UpiData::UpiQr(_) => (
                        EasebuzzPaymentMode::Upi,
                        None,
                        Some("1".to_string()),
                        None,
                        None,
                    ),
                },
                PaymentMethodData::Wallet(wallet_data) => {
                    let app_name = get_wallet_app_name(wallet_data)?;
                    (
                        EasebuzzPaymentMode::Wallet,
                        None,
                        None,
                        None,
                        Some(app_name),
                    )
                }
                PaymentMethodData::Netbanking(nb_data) => (
                    EasebuzzPaymentMode::NetBanking,
                    None,
                    None,
                    Some(nb_data.bank_code.clone()),
                    None,
                ),
                _ => {
                    return Err(errors::ConnectorError::NotImplemented(
                        "Payment method not supported for Easebuzz".to_string(),
                    )
                    .into())
                }
            };

        Ok(Self {
            access_key,
            payment_mode: payment_mode.as_str().to_string(),
            upi_va,
            upi_qr,
            bank_code,
            pay_later_app,
        })
    }
}

/// Maps WalletData variant to the Easebuzz pay_later_app name.
/// Easebuzz uses `pay_later_app` field for wallet payments with payment_mode = "WALLET".
fn get_wallet_app_name(wallet_data: &WalletData) -> Result<String, errors::ConnectorError> {
    match wallet_data {
        // For redirect-based wallet payments, we pass a generic identifier
        // The actual wallet app is determined by the redirect flow on Easebuzz side
        WalletData::Mifinity(_) => Ok("MIFINITY".to_string()),
        // Catch-all for other wallet variants that may be mapped through Easebuzz
        _ => Err(errors::ConnectorError::NotImplemented(
            "This wallet type is not supported by Easebuzz".to_string(),
        )),
    }
}

// =============================================================================
// AUTHORIZE (Seamless Payment) - RESPONSE
// =============================================================================
/// Response from Easebuzz Seamless Payment API.
/// This is `EaseBuzzSeamlessTxnResponse` from the techspec.
/// The response may contain a redirect URL for NB/Wallet flows, or
/// transaction status for UPI flows.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EasebuzzAuthorizeResponse {
    pub status: String,
    #[serde(default)]
    pub easepayid: Option<String>,
    #[serde(default)]
    pub txnid: Option<String>,
    #[serde(default)]
    pub bank_ref_num: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(rename = "error_Message")]
    #[serde(default)]
    pub error_message: Option<String>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub amount: Option<String>,
}

/// Maps Easebuzz status string to AttemptStatus.
/// Based on techspec Section 7.1 status mapping.
fn map_easebuzz_status(status: &str) -> AttemptStatus {
    match status {
        "success" => AttemptStatus::Charged,
        "initiated" | "pending" | "in_process" => AttemptStatus::AuthenticationPending,
        "failure" | "bounced" => AttemptStatus::AuthenticationFailed,
        _ => AttemptStatus::AuthenticationFailed,
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        ResponseRouterData<
            EasebuzzAuthorizeResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    > for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            EasebuzzAuthorizeResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let router_data = &item.router_data;

        let status = map_easebuzz_status(&response.status);

        // Check for error responses
        let is_error = matches!(status, AttemptStatus::AuthenticationFailed)
            || response
                .error
                .as_deref()
                .map_or(false, |e| !e.is_empty() && e != "NA");

        if is_error {
            let error_code = response
                .error
                .clone()
                .unwrap_or_else(|| "UNKNOWN_ERROR".to_string());
            let error_msg = response
                .error_message
                .clone()
                .unwrap_or_else(|| "Payment failed".to_string());

            return Ok(Self {
                resource_common_data: PaymentFlowData {
                    status,
                    ..router_data.resource_common_data.clone()
                },
                response: Err(domain_types::router_data::ErrorResponse {
                    code: error_code,
                    message: error_msg.clone(),
                    reason: Some(error_msg),
                    status_code: item.http_code,
                    attempt_status: Some(status),
                    connector_transaction_id: response.easepayid.clone(),
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                }),
                ..router_data.clone()
            });
        }

        // Build the connector transaction ID from easepayid
        let connector_transaction_id = response.easepayid.clone().unwrap_or_default();

        let payments_response_data = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(connector_transaction_id),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: response.txnid.clone(),
            incremental_authorization_allowed: None,
            status_code: item.http_code,
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data.clone()
            },
            response: Ok(payments_response_data),
            ..router_data.clone()
        })
    }
}

// =============================================================================
// PSync (Transaction Sync) - REQUEST
// =============================================================================
/// Request body for Easebuzz Transaction Sync API (form-urlencoded).
/// POST https://dashboard.easebuzz.in/transaction/v1/retrieve
/// Hash: sha512(key|txnid|amount|email|phone|salt)
#[derive(Debug, Serialize)]
pub struct EasebuzzSyncRequest {
    pub key: String,
    pub txnid: String,
    pub amount: StringMajorUnit,
    pub email: String,
    pub phone: String,
    pub hash: String,
}

/// Compute SHA-512 hash for Easebuzz Transaction Sync.
/// Formula: sha512(key|txnid|amount|email|phone|salt)
fn compute_txn_sync_hash(
    key: &str,
    txnid: &str,
    amount: &str,
    email: &str,
    phone: &str,
    salt: &str,
) -> String {
    use sha2::{Digest, Sha512};

    let hash_input = format!("{key}|{txnid}|{amount}|{email}|{phone}|{salt}");

    let mut hasher = Sha512::new();
    hasher.update(hash_input.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        EasebuzzRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    > for EasebuzzSyncRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: EasebuzzRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;

        // Get the merchant key from connector config
        let auth = EasebuzzAuthType::try_from(&router_data.connector_config)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        let key = auth.api_key.expose();

        // Use connector_request_reference_id as txnid (same as what was sent in CreateOrder)
        let txnid = router_data
            .resource_common_data
            .connector_request_reference_id
            .clone();

        // Convert amount to major unit string using the amount converter
        let amount = item
            .connector
            .amount_converter
            .convert(router_data.request.amount, router_data.request.currency)
            .change_context(errors::ConnectorError::AmountConversionFailed)?;

        // Extract email and phone from billing address
        let billing = router_data
            .resource_common_data
            .address
            .get_payment_method_billing();

        let email = billing
            .and_then(|b| b.email.as_ref())
            .map(|e| e.peek().to_string())
            .unwrap_or_else(|| "customer@example.com".to_string());

        let phone = billing
            .and_then(|b| b.phone.as_ref())
            .and_then(|p| p.number.as_ref())
            .map(|n| n.clone().expose())
            .unwrap_or_else(|| "9999999999".to_string());

        let amount_str = amount.get_amount_as_string();

        // Compute SHA-512 hash: sha512(key|txnid|amount|email|phone|salt)
        // api_key serves as both key and salt
        let hash = compute_txn_sync_hash(&key, &txnid, &amount_str, &email, &phone, &key);

        Ok(Self {
            key,
            txnid,
            amount,
            email,
            phone,
            hash,
        })
    }
}

// =============================================================================
// PSync (Transaction Sync) - RESPONSE
// =============================================================================
/// Response from Easebuzz Transaction Sync API.
/// The `msg` field can be either a success object (containing full transaction details)
/// or an error string/object.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EasebuzzSyncResponse {
    pub status: bool,
    pub msg: EasebuzzSyncMessage,
}

/// Represents the `msg` field in the sync response.
/// Can be a success response with full transaction details, a plain error string,
/// or a structured error object.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum EasebuzzSyncMessage {
    /// Success — contains full transaction details (same as EasebuzzAuthorizeResponse)
    Success(EasebuzzSyncSuccessData),
    /// Error — plain text error message
    Error(String),
}

/// The success variant of the sync response msg.
/// Contains the same fields as the authorize response.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EasebuzzSyncSuccessData {
    pub status: String,
    #[serde(default)]
    pub easepayid: Option<String>,
    #[serde(default)]
    pub txnid: Option<String>,
    #[serde(default)]
    pub bank_ref_num: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(rename = "error_Message")]
    #[serde(default)]
    pub error_message: Option<String>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub amount: Option<String>,
}

impl
    TryFrom<
        ResponseRouterData<
            EasebuzzSyncResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    > for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            EasebuzzSyncResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let router_data = &item.router_data;

        match &response.msg {
            EasebuzzSyncMessage::Success(txn_data) => {
                let status = map_easebuzz_status(&txn_data.status);

                // Check for error responses within the success data
                let is_error = matches!(status, AttemptStatus::AuthenticationFailed)
                    || txn_data
                        .error
                        .as_deref()
                        .map_or(false, |e| !e.is_empty() && e != "NA");

                if is_error {
                    let error_code = txn_data
                        .error
                        .clone()
                        .unwrap_or_else(|| "UNKNOWN_ERROR".to_string());
                    let error_msg = txn_data
                        .error_message
                        .clone()
                        .unwrap_or_else(|| "Transaction sync failed".to_string());

                    return Ok(Self {
                        resource_common_data: PaymentFlowData {
                            status,
                            ..router_data.resource_common_data.clone()
                        },
                        response: Err(domain_types::router_data::ErrorResponse {
                            code: error_code,
                            message: error_msg.clone(),
                            reason: Some(error_msg),
                            status_code: item.http_code,
                            attempt_status: Some(status),
                            connector_transaction_id: txn_data.easepayid.clone(),
                            network_decline_code: None,
                            network_advice_code: None,
                            network_error_message: None,
                        }),
                        ..router_data.clone()
                    });
                }

                let connector_transaction_id = txn_data.easepayid.clone().unwrap_or_default();

                let payments_response_data = PaymentsResponseData::TransactionResponse {
                    resource_id: ResponseId::ConnectorTransactionId(connector_transaction_id),
                    redirection_data: None,
                    mandate_reference: None,
                    connector_metadata: None,
                    network_txn_id: None,
                    connector_response_reference_id: txn_data.txnid.clone(),
                    incremental_authorization_allowed: None,
                    status_code: item.http_code,
                };

                Ok(Self {
                    resource_common_data: PaymentFlowData {
                        status,
                        ..router_data.resource_common_data.clone()
                    },
                    response: Ok(payments_response_data),
                    ..router_data.clone()
                })
            }
            EasebuzzSyncMessage::Error(error_msg) => Ok(Self {
                resource_common_data: PaymentFlowData {
                    status: AttemptStatus::Failure,
                    ..router_data.resource_common_data.clone()
                },
                response: Err(domain_types::router_data::ErrorResponse {
                    code: "SYNC_ERROR".to_string(),
                    message: error_msg.clone(),
                    reason: Some(error_msg.clone()),
                    status_code: item.http_code,
                    attempt_status: Some(AttemptStatus::Failure),
                    connector_transaction_id: None,
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                }),
                ..router_data.clone()
            }),
        }
    }
}

// =============================================================================
// REFUND - REQUEST
// =============================================================================
/// Request body for Easebuzz Refund API (form-urlencoded).
/// POST https://dashboard.easebuzz.in/transaction/v2/refund
/// Hash: sha512(key|merchant_refund_id|easebuzz_id|refund_amount|salt)
#[derive(Debug, Serialize)]
pub struct EasebuzzRefundRequest {
    pub key: String,
    pub merchant_refund_id: String,
    pub easebuzz_id: String,
    pub refund_amount: StringMajorUnit,
    pub hash: String,
}

/// Compute SHA-512 hash for Easebuzz Refund.
/// Formula: sha512(key|merchant_refund_id|easebuzz_id|refund_amount|salt)
fn compute_refund_hash(
    key: &str,
    merchant_refund_id: &str,
    easebuzz_id: &str,
    refund_amount: &str,
    salt: &str,
) -> String {
    use sha2::{Digest, Sha512};

    let hash_input = format!("{key}|{merchant_refund_id}|{easebuzz_id}|{refund_amount}|{salt}");

    let mut hasher = Sha512::new();
    hasher.update(hash_input.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        EasebuzzRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    > for EasebuzzRefundRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: EasebuzzRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;

        // Get the merchant key from connector config
        let auth = EasebuzzAuthType::try_from(&router_data.connector_config)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        let key = auth.api_key.expose();

        // merchant_refund_id is our internal refund reference ID
        let merchant_refund_id = router_data.request.refund_id.clone();

        // easebuzz_id is the connector_transaction_id from the original payment (easepayid)
        let easebuzz_id = router_data.request.connector_transaction_id.clone();

        // Convert refund amount to major unit string (e.g., "100.00")
        let refund_amount = item
            .connector
            .amount_converter
            .convert(
                router_data.request.minor_refund_amount,
                router_data.request.currency,
            )
            .change_context(errors::ConnectorError::AmountConversionFailed)?;

        let refund_amount_str = refund_amount.get_amount_as_string();

        // Compute SHA-512 hash: sha512(key|merchant_refund_id|easebuzz_id|refund_amount|salt)
        // api_key serves as both key and salt
        let hash = compute_refund_hash(
            &key,
            &merchant_refund_id,
            &easebuzz_id,
            &refund_amount_str,
            &key,
        );

        Ok(Self {
            key,
            merchant_refund_id,
            easebuzz_id,
            refund_amount,
            hash,
        })
    }
}

// =============================================================================
// REFUND - RESPONSE
// =============================================================================
/// Response from Easebuzz Refund API.
/// `status` is a bool indicating whether the refund was initiated successfully.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EasebuzzRefundResponse {
    pub status: bool,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub easebuzz_id: Option<String>,
    #[serde(default)]
    pub refund_id: Option<String>,
    #[serde(default)]
    pub refund_amount: Option<f64>,
}

impl
    TryFrom<
        ResponseRouterData<
            EasebuzzRefundResponse,
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    > for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            EasebuzzRefundResponse,
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let router_data = &item.router_data;

        if response.status {
            // Refund initiated successfully
            // Use refund_id from response, fallback to easebuzz_id
            let connector_refund_id = response
                .refund_id
                .clone()
                .or_else(|| response.easebuzz_id.clone())
                .unwrap_or_else(|| router_data.request.refund_id.clone());

            Ok(Self {
                response: Ok(RefundsResponseData {
                    connector_refund_id,
                    refund_status: RefundStatus::Pending,
                    status_code: item.http_code,
                }),
                ..router_data.clone()
            })
        } else {
            // Refund failed
            let error_reason = response
                .reason
                .clone()
                .unwrap_or_else(|| "Refund request failed".to_string());

            Ok(Self {
                response: Err(domain_types::router_data::ErrorResponse {
                    code: "REFUND_FAILED".to_string(),
                    message: error_reason.clone(),
                    reason: Some(error_reason),
                    status_code: item.http_code,
                    attempt_status: None,
                    connector_transaction_id: response.easebuzz_id.clone(),
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                }),
                ..router_data.clone()
            })
        }
    }
}

// =============================================================================
// REFUND SYNC (RSync) - REQUEST
// =============================================================================
/// Request body for Easebuzz Refund Sync API (form-urlencoded).
/// POST https://dashboard.easebuzz.in/refund/v1/retrieve
/// Hash: sha512(key|easebuzz_id|salt)
#[derive(Debug, Serialize)]
pub struct EasebuzzRefundSyncRequest {
    pub key: String,
    pub easebuzz_id: String,
    pub hash: String,
    pub merchant_refund_id: String,
}

/// Compute SHA-512 hash for Easebuzz Refund Sync.
/// Formula: sha512(key|easebuzz_id|salt)
fn compute_refund_sync_hash(key: &str, easebuzz_id: &str, salt: &str) -> String {
    use sha2::{Digest, Sha512};

    let hash_input = format!("{key}|{easebuzz_id}|{salt}");

    let mut hasher = Sha512::new();
    hasher.update(hash_input.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        EasebuzzRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    > for EasebuzzRefundSyncRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: EasebuzzRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;

        // Get the merchant key from connector config
        let auth = EasebuzzAuthType::try_from(&router_data.connector_config)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        let key = auth.api_key.expose();

        // easebuzz_id is the connector_transaction_id (easepayid from the original payment)
        let easebuzz_id = router_data.request.connector_transaction_id.clone();

        // merchant_refund_id is our internal refund reference ID (connector_refund_id from RSync data)
        let merchant_refund_id = router_data.request.connector_refund_id.clone();

        // Compute SHA-512 hash: sha512(key|easebuzz_id|salt)
        // api_key serves as both key and salt
        let hash = compute_refund_sync_hash(&key, &easebuzz_id, &key);

        Ok(Self {
            key,
            easebuzz_id,
            hash,
            merchant_refund_id,
        })
    }
}

// =============================================================================
// REFUND SYNC (RSync) - RESPONSE
// =============================================================================
/// Response from Easebuzz Refund Sync API.
/// The response is a union type: Success, Failure, or ValidationError.
/// We use `#[serde(untagged)]` to handle the different response shapes.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum EasebuzzRefundSyncResponse {
    /// Success response — contains refund details with refund_status
    Success(EasebuzzRefundSyncSuccessResponse),
    /// Failure / Validation error — has a msg or reason field
    Failure(EasebuzzRefundSyncFailureResponse),
}

/// Success variant of the refund sync response.
/// Contains refund status and bank reference number.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EasebuzzRefundSyncSuccessResponse {
    pub refund_status: String,
    #[serde(default)]
    pub bank_ref_num: Option<String>,
    #[serde(default)]
    pub easebuzz_id: Option<String>,
    #[serde(default)]
    pub refund_id: Option<String>,
    #[serde(default)]
    pub refund_amount: Option<String>,
}

/// Failure / validation error variant of the refund sync response.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EasebuzzRefundSyncFailureResponse {
    #[serde(default)]
    pub status: Option<serde_json::Value>,
    #[serde(default)]
    pub msg: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

/// Maps Easebuzz refund status string to internal RefundStatus.
/// Based on techspec status mapping.
fn map_easebuzz_refund_status(status: &str) -> RefundStatus {
    match status {
        "queued" | "approved" => RefundStatus::Pending,
        "refunded" => RefundStatus::Success,
        "cancelled" | "reverse chargeback" => RefundStatus::Failure,
        _ => RefundStatus::Pending,
    }
}

impl
    TryFrom<
        ResponseRouterData<
            EasebuzzRefundSyncResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    > for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            EasebuzzRefundSyncResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let router_data = &item.router_data;

        match response {
            EasebuzzRefundSyncResponse::Success(success_data) => {
                let refund_status = map_easebuzz_refund_status(&success_data.refund_status);

                // Use refund_id from response, fallback to connector_refund_id from request
                let connector_refund_id = success_data
                    .refund_id
                    .clone()
                    .unwrap_or_else(|| router_data.request.connector_refund_id.clone());

                Ok(Self {
                    response: Ok(RefundsResponseData {
                        connector_refund_id,
                        refund_status,
                        status_code: item.http_code,
                    }),
                    ..router_data.clone()
                })
            }
            EasebuzzRefundSyncResponse::Failure(failure_data) => {
                let error_msg = failure_data
                    .msg
                    .clone()
                    .or_else(|| failure_data.reason.clone())
                    .unwrap_or_else(|| "Refund sync failed".to_string());

                Ok(Self {
                    response: Err(domain_types::router_data::ErrorResponse {
                        code: "REFUND_SYNC_FAILED".to_string(),
                        message: error_msg.clone(),
                        reason: Some(error_msg),
                        status_code: item.http_code,
                        attempt_status: None,
                        connector_transaction_id: None,
                        network_decline_code: None,
                        network_advice_code: None,
                        network_error_message: None,
                    }),
                    ..router_data.clone()
                })
            }
        }
    }
}

// =============================================================================
// SETUP MANDATE - REQUEST
// =============================================================================
/// Request body for Easebuzz Mandate Access Key Generation API (JSON).
/// POST https://api.easebuzz.in/autocollect/v1/access-key/generate/
///
/// This is Step 1 of the mandate setup flow. The response access_key is then
/// used to build a redirect form for Step 2 (mandate creation).
///
/// Auth: Authorization header with SHA-512 hash, plus X-EB-MERCHANT-KEY header.
/// The authorization hash and key are included in the JSON body.
#[derive(Debug, Serialize)]
pub struct EasebuzzSetupMandateRequest {
    pub key: String,
    pub transaction_id: String,
    pub success_url: String,
    pub failure_url: String,
    pub request_type: String,
    pub amount: StringMajorUnit,
    pub email: String,
    pub phone: String,
    pub start_date: String,
    pub end_date: String,
    pub frequency: String,
    pub payment_modes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount_rule: Option<String>,
}

/// Determines the Easebuzz mandate request_type based on payment method.
/// - "UPIAD" for UPI Autopay mandates
/// - "EN" for eNACH/eMandate (Netbanking) mandates
/// - "SI" for Standing Instruction (Wallet/other) mandates
fn get_mandate_request_type(
    payment_method_data: &PaymentMethodData<
        impl PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize,
    >,
) -> &'static str {
    match payment_method_data {
        PaymentMethodData::Upi(_) => "UPIAD",
        PaymentMethodData::Netbanking(_) => "EN",
        PaymentMethodData::Wallet(_) => "SI",
        _ => "UPIAD",
    }
}

/// Gets the payment_modes array for the Easebuzz mandate request.
fn get_mandate_payment_modes(
    payment_method_data: &PaymentMethodData<
        impl PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize,
    >,
) -> Vec<String> {
    match payment_method_data {
        PaymentMethodData::Upi(_) => vec!["UPI".to_string()],
        PaymentMethodData::Netbanking(_) => vec!["NB".to_string()],
        PaymentMethodData::Wallet(_) => vec!["WALLET".to_string()],
        _ => vec!["UPI".to_string()],
    }
}

/// Format a PrimitiveDateTime as YYYY-MM-DD string for Easebuzz mandate API.
fn format_date_yyyy_mm_dd(date: time::PrimitiveDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02}",
        date.year(),
        date.month() as u8,
        date.day()
    )
}

/// Metadata stored in connector_metadata to carry payment method details for the redirect form.
/// This is serialized as JSON and stored in the response, then used to build the
/// Step 2 redirect form.
#[derive(Debug, Serialize, Deserialize)]
pub struct EasebuzzMandateMetadata {
    pub access_key: String,
    pub mandate_base_url: String,
    pub request_type: String,
    pub key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upi_handle: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bank_code: Option<String>,
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        EasebuzzRouterData<
            RouterDataV2<
                SetupMandate,
                PaymentFlowData,
                SetupMandateRequestData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for EasebuzzSetupMandateRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: EasebuzzRouterData<
            RouterDataV2<
                SetupMandate,
                PaymentFlowData,
                SetupMandateRequestData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;

        // Get the merchant key from connector config
        let auth = EasebuzzAuthType::try_from(&router_data.connector_config)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        let key = auth.api_key.expose();

        let transaction_id = router_data
            .resource_common_data
            .connector_request_reference_id
            .clone();

        // Determine request_type from payment method
        let request_type =
            get_mandate_request_type(&router_data.request.payment_method_data).to_string();

        // Determine payment_modes from payment method
        let payment_modes = get_mandate_payment_modes(&router_data.request.payment_method_data);

        // Convert amount using the amount converter
        let amount = item
            .connector
            .amount_converter
            .convert(
                router_data
                    .request
                    .minor_amount
                    .unwrap_or(common_utils::types::MinorUnit::new(0)),
                router_data.request.currency,
            )
            .change_context(errors::ConnectorError::AmountConversionFailed)?;

        // Extract email
        let email = router_data
            .request
            .email
            .as_ref()
            .map(|e| e.peek().to_string())
            .unwrap_or_else(|| {
                router_data
                    .resource_common_data
                    .address
                    .get_payment_method_billing()
                    .and_then(|b| b.email.as_ref())
                    .map(|e: &common_utils::pii::Email| e.peek().to_string())
                    .unwrap_or_else(|| "customer@example.com".to_string())
            });

        // Extract phone from billing
        let phone = router_data
            .resource_common_data
            .address
            .get_payment_method_billing()
            .and_then(|b| b.phone.as_ref())
            .and_then(|p| p.number.as_ref())
            .map(|n: &Secret<String>| n.clone().expose())
            .unwrap_or_else(|| "9999999999".to_string());

        // Extract mandate dates and frequency from setup_mandate_details
        let (start_date, end_date, frequency, amount_rule) =
            extract_mandate_details(&router_data.request.setup_mandate_details)?;

        // Return URLs
        let success_url = router_data
            .request
            .router_return_url
            .clone()
            .unwrap_or_else(|| "https://example.com/callback".to_string());
        let failure_url = success_url.clone();

        Ok(Self {
            key,
            transaction_id,
            success_url,
            failure_url,
            request_type,
            amount,
            email,
            phone,
            start_date,
            end_date,
            frequency,
            payment_modes,
            amount_rule,
        })
    }
}

/// Extract mandate details (start_date, end_date, frequency, amount_rule) from MandateData.
fn extract_mandate_details(
    mandate_data: &Option<domain_types::mandates::MandateData>,
) -> Result<(String, String, String, Option<String>), error_stack::Report<errors::ConnectorError>> {
    let mandate = mandate_data
        .as_ref()
        .ok_or(errors::ConnectorError::MissingRequiredField {
            field_name: "setup_mandate_details",
        })?;

    let mandate_type =
        mandate
            .mandate_type
            .as_ref()
            .ok_or(errors::ConnectorError::MissingRequiredField {
                field_name: "setup_mandate_details.mandate_type",
            })?;

    let (amount_data, amount_rule) = match mandate_type {
        domain_types::mandates::MandateDataType::SingleUse(data) => {
            (Some(data), Some("EXACT".to_string()))
        }
        domain_types::mandates::MandateDataType::MultiUse(data) => {
            (data.as_ref(), Some("MAX".to_string()))
        }
    };

    let amount_data = amount_data.ok_or(errors::ConnectorError::MissingRequiredField {
        field_name: "setup_mandate_details.mandate_type.amount_data",
    })?;

    // Format dates as YYYY-MM-DD
    let start_date = amount_data
        .start_date
        .map(format_date_yyyy_mm_dd)
        .unwrap_or_else(|| {
            // Default to today if not provided
            let now = common_utils::date_time::now();
            format_date_yyyy_mm_dd(now)
        });

    let end_date = amount_data
        .end_date
        .map(format_date_yyyy_mm_dd)
        .unwrap_or_else(|| {
            // Default to 10 years from now if not provided
            let now = common_utils::date_time::now();
            format!(
                "{:04}-{:02}-{:02}",
                now.year() + 10,
                now.month() as u8,
                now.day()
            )
        });

    // Use frequency from mandate data, default to "MONTHLY"
    let frequency = amount_data
        .frequency
        .clone()
        .unwrap_or_else(|| "MONTHLY".to_string());

    Ok((start_date, end_date, frequency, amount_rule))
}

// =============================================================================
// SETUP MANDATE - RESPONSE
// =============================================================================
/// Response from Easebuzz Mandate Access Key Generation API.
/// On success, returns an access_key which is used in Step 2.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EasebuzzSetupMandateResponse {
    pub success: bool,
    #[serde(default)]
    pub status: Option<bool>,
    #[serde(default)]
    pub access_key: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub request_id: Option<String>,
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        ResponseRouterData<
            EasebuzzSetupMandateResponse,
            RouterDataV2<
                SetupMandate,
                PaymentFlowData,
                SetupMandateRequestData<T>,
                PaymentsResponseData,
            >,
        >,
    >
    for RouterDataV2<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData<T>,
        PaymentsResponseData,
    >
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            EasebuzzSetupMandateResponse,
            RouterDataV2<
                SetupMandate,
                PaymentFlowData,
                SetupMandateRequestData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let router_data = &item.router_data;

        if !response.success {
            let error_msg = response
                .message
                .clone()
                .unwrap_or_else(|| "Mandate access key generation failed".to_string());

            return Ok(Self {
                resource_common_data: PaymentFlowData {
                    status: AttemptStatus::Failure,
                    ..router_data.resource_common_data.clone()
                },
                response: Err(domain_types::router_data::ErrorResponse {
                    code: "MANDATE_ACCESS_KEY_FAILED".to_string(),
                    message: error_msg.clone(),
                    reason: Some(error_msg),
                    status_code: item.http_code,
                    attempt_status: Some(AttemptStatus::Failure),
                    connector_transaction_id: response.request_id.clone(),
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                }),
                ..router_data.clone()
            });
        }

        let access_key =
            response
                .access_key
                .clone()
                .ok_or(errors::ConnectorError::MissingRequiredField {
                    field_name: "access_key",
                })?;

        // Build redirect form for Step 2: mandate creation
        // The redirect URL and form fields depend on the payment method type
        let (redirect_url, form_fields) = build_mandate_redirect(router_data, &access_key)?;

        let redirection_data = Some(Box::new(RedirectForm::Form {
            endpoint: redirect_url,
            method: common_utils::Method::Post,
            form_fields,
        }));

        let transaction_id = router_data
            .resource_common_data
            .connector_request_reference_id
            .clone();

        let payments_response_data = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(transaction_id.clone()),
            redirection_data,
            mandate_reference: Some(Box::new(MandateReference {
                connector_mandate_id: None, // Will be set after mandate creation via PSync/webhook
                payment_method_id: None,
                connector_mandate_request_reference_id: Some(transaction_id.clone()),
            })),
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: Some(transaction_id),
            incremental_authorization_allowed: None,
            status_code: item.http_code,
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status: AttemptStatus::AuthenticationPending,
                ..router_data.resource_common_data.clone()
            },
            response: Ok(payments_response_data),
            ..router_data.clone()
        })
    }
}

/// Build the mandate creation redirect URL and form fields for Step 2.
/// - For UPI Autopay: POST to /autocollect/v1/mandate/process/
/// - For eNACH/Netbanking: POST to /autocollect/v1/mandate/
/// - For Wallet (redirect): POST to /autocollect/v1/mandate/
fn build_mandate_redirect<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>(
    router_data: &RouterDataV2<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData<T>,
        PaymentsResponseData,
    >,
    access_key: &str,
) -> Result<(String, HashMap<String, String>), error_stack::Report<errors::ConnectorError>> {
    let auth = EasebuzzAuthType::try_from(&router_data.connector_config)
        .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
    let key = auth.api_key.expose();

    // Get the mandate API base URL from secondary_base_url
    let base_url = router_data
        .resource_common_data
        .connectors
        .easebuzz
        .secondary_base_url
        .as_deref()
        .ok_or(errors::ConnectorError::InvalidConnectorConfig {
            config: "secondary_base_url",
        })?;

    let mut form_fields = HashMap::new();
    form_fields.insert("key".to_string(), key.clone());
    form_fields.insert("access_key".to_string(), access_key.to_string());

    match &router_data.request.payment_method_data {
        PaymentMethodData::Upi(upi_data) => {
            // UPI Autopay: POST to /autocollect/v1/mandate/process/
            let endpoint = format!("{}/autocollect/v1/mandate/process/", base_url);
            form_fields.insert("mandate_type".to_string(), "CREATE".to_string());

            match upi_data {
                UpiData::UpiCollect(collect_data) => {
                    let vpa = collect_data
                        .vpa_id
                        .as_ref()
                        .ok_or(errors::ConnectorError::MissingRequiredField {
                            field_name: "vpa_id",
                        })?
                        .peek()
                        .to_string();
                    form_fields.insert("upi_handle".to_string(), vpa);
                    form_fields.insert("auth_mode".to_string(), "COLLECT".to_string());
                }
                UpiData::UpiIntent(_) => {
                    form_fields.insert("auth_mode".to_string(), "INTENT".to_string());
                }
                UpiData::UpiQr(_) => {
                    form_fields.insert("auth_mode".to_string(), "INTENT".to_string());
                }
            }

            // Compute authorization hash: sha512(key|accNo|ifsc|upihandle|salt)
            // For UPI, account number and ifsc are empty
            let upi_handle = form_fields.get("upi_handle").cloned().unwrap_or_default();
            let auth_hash = compute_mandate_auth_hash(&key, "", "", &upi_handle, &key);
            form_fields.insert("Authorization".to_string(), auth_hash);

            Ok((endpoint, form_fields))
        }
        PaymentMethodData::Netbanking(nb_data) => {
            // eNACH/eMandate: POST to /autocollect/v1/mandate/
            let endpoint = format!("{}/autocollect/v1/mandate/", base_url);
            form_fields.insert("mandate_type".to_string(), "NACH".to_string());
            form_fields.insert("auth_mode".to_string(), "NB".to_string());
            form_fields.insert("bank_code".to_string(), nb_data.bank_code.clone());
            form_fields.insert("ifsc".to_string(), String::new());
            form_fields.insert("account_number".to_string(), String::new());
            form_fields.insert("account_holder_name".to_string(), String::new());
            form_fields.insert("account_type".to_string(), "savings".to_string());

            // Compute authorization hash: sha512(key|accNo|ifsc|upihandle|salt)
            let auth_hash = compute_mandate_auth_hash(&key, "", "", "", &key);
            form_fields.insert("Authorization".to_string(), auth_hash);

            Ok((endpoint, form_fields))
        }
        PaymentMethodData::Wallet(_wallet_data) => {
            // Wallet mandate: POST to /autocollect/v1/mandate/
            let endpoint = format!("{}/autocollect/v1/mandate/", base_url);
            form_fields.insert("mandate_type".to_string(), "CREATE".to_string());
            form_fields.insert("auth_mode".to_string(), "NB".to_string());

            // Compute authorization hash
            let auth_hash = compute_mandate_auth_hash(&key, "", "", "", &key);
            form_fields.insert("Authorization".to_string(), auth_hash);

            Ok((endpoint, form_fields))
        }
        _ => Err(errors::ConnectorError::NotImplemented(
            "Payment method not supported for Easebuzz mandate setup".to_string(),
        )
        .into()),
    }
}

/// Public wrapper for compute_mandate_auth_hash, used by easebuzz.rs for RepeatPayment headers.
pub fn compute_mandate_auth_hash_pub(
    key: &str,
    acc_no: &str,
    ifsc: &str,
    upi_handle: &str,
    salt: &str,
) -> String {
    compute_mandate_auth_hash(key, acc_no, ifsc, upi_handle, salt)
}

/// Compute SHA-512 authorization hash for Easebuzz mandate operations.
/// Formula: sha512(key|accNo|ifsc|upihandle|salt)
fn compute_mandate_auth_hash(
    key: &str,
    acc_no: &str,
    ifsc: &str,
    upi_handle: &str,
    salt: &str,
) -> String {
    use sha2::{Digest, Sha512};

    let hash_input = format!("{key}|{acc_no}|{ifsc}|{upi_handle}|{salt}");

    let mut hasher = Sha512::new();
    hasher.update(hash_input.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

// =============================================================================
// REPEAT PAYMENT (Mandate Execute) - REQUEST
// =============================================================================
/// Request body for Easebuzz Mandate Execute API (JSON).
/// UPI mandates: POST https://api.easebuzz.in/autocollect/v1/mandate/execute/
/// eNACH mandates: POST https://api.easebuzz.in/autocollect/v1/mandate/presentment/
///
/// Auth: Authorization header with SHA-512 hash + X-EB-MERCHANT-KEY header.
///
/// The `transaction_id` is the mandate's connector_mandate_id (from SetupMandate).
/// The `merchant_request_number` is a unique debit request reference.
#[derive(Debug, Serialize)]
pub struct EasebuzzRepeatPaymentRequest {
    pub key: String,
    pub amount: StringMajorUnit,
    pub transaction_id: String,
    pub merchant_request_number: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notification_request_number: Option<String>,
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        EasebuzzRouterData<
            RouterDataV2<
                RepeatPayment,
                PaymentFlowData,
                RepeatPaymentData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for EasebuzzRepeatPaymentRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: EasebuzzRouterData<
            RouterDataV2<
                RepeatPayment,
                PaymentFlowData,
                RepeatPaymentData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;

        // Get the merchant key from connector config
        let auth = EasebuzzAuthType::try_from(&router_data.connector_config)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        let key = auth.api_key.expose();

        // Extract the mandate transaction_id from mandate_reference
        let transaction_id = extract_mandate_id(&router_data.request.mandate_reference)?;

        // Convert amount to major unit string (e.g., "100.00")
        let amount = item
            .connector
            .amount_converter
            .convert(
                router_data.request.minor_amount,
                router_data.request.currency,
            )
            .change_context(errors::ConnectorError::AmountConversionFailed)?;

        // Use connector_request_reference_id as the merchant_request_number
        let merchant_request_number = router_data
            .resource_common_data
            .connector_request_reference_id
            .clone();

        Ok(Self {
            key,
            amount,
            transaction_id,
            merchant_request_number,
            notification_request_number: None,
        })
    }
}

/// Extract mandate ID from MandateReferenceId for RepeatPayment/MandateRevoke.
/// Easebuzz mandate execute requires the connector_mandate_id (the mandate transaction_id
/// returned during SetupMandate).
pub fn extract_mandate_id(
    mandate_reference: &MandateReferenceId,
) -> Result<String, error_stack::Report<errors::ConnectorError>> {
    match mandate_reference {
        MandateReferenceId::ConnectorMandateId(connector_mandate_ref) => connector_mandate_ref
            .get_connector_mandate_id()
            .or_else(|| connector_mandate_ref.get_connector_mandate_request_reference_id())
            .ok_or_else(|| {
                error_stack::report!(errors::ConnectorError::MissingRequiredField {
                    field_name: "connector_mandate_id"
                })
            }),
        MandateReferenceId::NetworkMandateId(_) => Err(error_stack::report!(
            errors::ConnectorError::NotImplemented(
                "Network mandate ID not supported for repeat payments in easebuzz".to_string(),
            )
        )),
        MandateReferenceId::NetworkTokenWithNTI(_) => Err(error_stack::report!(
            errors::ConnectorError::NotImplemented(
                "Network token with NTI not supported for repeat payments in easebuzz".to_string(),
            )
        )),
    }
}

// =============================================================================
// REPEAT PAYMENT (Mandate Execute) - RESPONSE
// =============================================================================
/// Response from Easebuzz Mandate Execute / Presentment API.
/// Maps to EaseBuzzUpiExecutionResponse from the techspec.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EasebuzzRepeatPaymentResponse {
    pub success: bool,
    pub data: Option<EasebuzzDebitRequestResponseData>,
    #[serde(default)]
    pub request_id: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
}

/// Debit request response data — contains execution result details.
/// Maps to DebitRequestResponseData from the techspec.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EasebuzzDebitRequestResponseData {
    pub id: Option<String>,
    #[serde(default)]
    pub pg_transaction_id: Option<String>,
    #[serde(default)]
    pub amount: Option<serde_json::Number>,
    pub status: String,
    #[serde(default)]
    pub merchant_request_number: Option<String>,
    #[serde(default)]
    pub transaction_reference_number: Option<String>,
    #[serde(default)]
    pub bank_reference_number: Option<String>,
}

/// Maps Easebuzz mandate execute status string to AttemptStatus.
/// Based on techspec Section 7.5: mapTxnStatus
/// "success" → CHARGED, "failure" → AUTHORIZATION_FAILED, "in_process" → PENDING_VBV
fn map_easebuzz_mandate_execute_status(status: &str) -> AttemptStatus {
    match status {
        "success" => AttemptStatus::Charged,
        "failure" => AttemptStatus::AuthorizationFailed,
        "in_process" => AttemptStatus::Pending,
        _ => AttemptStatus::Pending,
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        ResponseRouterData<
            EasebuzzRepeatPaymentResponse,
            RouterDataV2<
                RepeatPayment,
                PaymentFlowData,
                RepeatPaymentData<T>,
                PaymentsResponseData,
            >,
        >,
    > for RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            EasebuzzRepeatPaymentResponse,
            RouterDataV2<
                RepeatPayment,
                PaymentFlowData,
                RepeatPaymentData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let router_data = &item.router_data;

        if !response.success {
            let error_msg = response
                .message
                .clone()
                .unwrap_or_else(|| "Mandate execute failed".to_string());

            return Ok(Self {
                resource_common_data: PaymentFlowData {
                    status: AttemptStatus::AuthorizationFailed,
                    ..router_data.resource_common_data.clone()
                },
                response: Err(domain_types::router_data::ErrorResponse {
                    code: "MANDATE_EXECUTE_FAILED".to_string(),
                    message: error_msg.clone(),
                    reason: Some(error_msg),
                    status_code: item.http_code,
                    attempt_status: Some(AttemptStatus::AuthorizationFailed),
                    connector_transaction_id: response.request_id.clone(),
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                }),
                ..router_data.clone()
            });
        }

        // Parse the data field
        let data = response
            .data
            .as_ref()
            .ok_or(errors::ConnectorError::MissingRequiredField { field_name: "data" })?;

        let status = map_easebuzz_mandate_execute_status(&data.status);

        // Use pg_transaction_id as the connector transaction ID, fallback to id
        let connector_transaction_id = data
            .pg_transaction_id
            .clone()
            .or_else(|| data.id.clone())
            .unwrap_or_default();

        // Build mandate reference to preserve the mandate ID for future repeat payments
        let mandate_reference = extract_mandate_id(&router_data.request.mandate_reference)
            .ok()
            .map(|mandate_id| {
                Box::new(MandateReference {
                    connector_mandate_id: Some(mandate_id),
                    payment_method_id: None,
                    connector_mandate_request_reference_id: data.merchant_request_number.clone(),
                })
            });

        let payments_response_data = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(connector_transaction_id),
            redirection_data: None,
            mandate_reference,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: data.merchant_request_number.clone(),
            incremental_authorization_allowed: None,
            status_code: item.http_code,
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data.clone()
            },
            response: Ok(payments_response_data),
            ..router_data.clone()
        })
    }
}

// =============================================================================
// MANDATE REVOKE - REQUEST
// =============================================================================
/// Request body for Easebuzz Mandate Revoke API (JSON).
/// POST https://api.easebuzz.in/autocollect/v1/mandate/{mandateId}/status_update/
///
/// Auth: Authorization header with SHA-512 hash + X-EB-MERCHANT-KEY header.
#[derive(Debug, Serialize)]
pub struct EasebuzzRevokeMandateRequest {
    pub key: String,
    pub status: String,
    pub remarks: String,
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        EasebuzzRouterData<
            RouterDataV2<
                MandateRevoke,
                PaymentFlowData,
                MandateRevokeRequestData,
                MandateRevokeResponseData,
            >,
            T,
        >,
    > for EasebuzzRevokeMandateRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: EasebuzzRouterData<
            RouterDataV2<
                MandateRevoke,
                PaymentFlowData,
                MandateRevokeRequestData,
                MandateRevokeResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;

        // Get the merchant key from connector config
        let auth = EasebuzzAuthType::try_from(&router_data.connector_config)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        let key = auth.api_key.expose();

        Ok(Self {
            key,
            status: "revoked".to_string(),
            remarks: "Mandate revoked by merchant".to_string(),
        })
    }
}

// =============================================================================
// MANDATE REVOKE - RESPONSE
// =============================================================================
/// Response from Easebuzz Mandate Revoke API.
/// Maps to EaseBuzzRevokeMandateResponse from the techspec.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EasebuzzRevokeMandateResponse {
    pub success: bool,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub data: Option<EasebuzzRevokeMandateData>,
    #[serde(default)]
    pub request_id: Option<String>,
}

/// The data field in the revoke mandate response.
/// Contains updated mandate details including the new status.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EasebuzzRevokeMandateData {
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub id: Option<String>,
}

impl
    TryFrom<
        ResponseRouterData<
            EasebuzzRevokeMandateResponse,
            RouterDataV2<
                MandateRevoke,
                PaymentFlowData,
                MandateRevokeRequestData,
                MandateRevokeResponseData,
            >,
        >,
    >
    for RouterDataV2<
        MandateRevoke,
        PaymentFlowData,
        MandateRevokeRequestData,
        MandateRevokeResponseData,
    >
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            EasebuzzRevokeMandateResponse,
            RouterDataV2<
                MandateRevoke,
                PaymentFlowData,
                MandateRevokeRequestData,
                MandateRevokeResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let router_data = &item.router_data;

        if response.success {
            Ok(Self {
                response: Ok(MandateRevokeResponseData {
                    mandate_status: common_enums::MandateStatus::Revoked,
                    status_code: item.http_code,
                }),
                ..router_data.clone()
            })
        } else {
            let error_msg = response
                .message
                .clone()
                .unwrap_or_else(|| "Mandate revocation failed".to_string());

            Err(errors::ConnectorError::ResponseHandlingFailed)
                .attach_printable(error_msg)
                .map_err(|e| e.into())
        }
    }
}

// =============================================================================
// WEBHOOK TYPES
// =============================================================================

/// Union type representing all possible Easebuzz webhook payloads.
/// Maps to `EaseBuzzWebhookTypes` from the techspec.
///
/// Easebuzz sends different webhook shapes depending on the event:
/// - SeamlessTxnResp: normal transaction status update (payment success/failure)
/// - RefundWebhook: refund status update
/// - MandateStatusUpdateWebhookResp: mandate status change (authorized, revoked, etc.)
/// - PresentmentStatusUpdateWebhookResp: mandate debit/presentment status update
/// - NotificationStatusUpdateWebhookResp: notification status update
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum EasebuzzWebhookBody {
    /// Normal transaction status update (same shape as SeamlessTxnResponse)
    Transaction(EasebuzzWebhookTransactionBody),
    /// Refund status update
    Refund(EasebuzzWebhookRefundBody),
    /// Mandate status update webhook
    MandateStatus(EasebuzzWebhookMandateStatusBody),
    /// Presentment (mandate debit) status update webhook
    PresentmentStatus(EasebuzzWebhookPresentmentStatusBody),
}

/// Normal transaction webhook body — same shape as EaseBuzzSeamlessTxnResponse.
/// Contains the standard transaction fields including status, txnid, easepayid, hash.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EasebuzzWebhookTransactionBody {
    pub status: String,
    pub txnid: String,
    pub easepayid: String,
    #[serde(default)]
    pub bank_ref_num: Option<String>,
    #[serde(default)]
    pub amount: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(rename = "error_Message")]
    #[serde(default)]
    pub error_message: Option<String>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub hash: Option<String>,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub phone: Option<String>,
    #[serde(default)]
    pub firstname: Option<String>,
    #[serde(default)]
    pub productinfo: Option<String>,
    #[serde(default)]
    pub surl: Option<String>,
    #[serde(default)]
    pub furl: Option<String>,
}

/// Refund webhook body — maps to EaseBuzzRefundWebhookResponse.
/// Contains the refund status information.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EasebuzzWebhookRefundBody {
    pub refund_id: String,
    pub easebuzz_id: String,
    pub refund_status: String,
    #[serde(default)]
    pub refund_amount: Option<String>,
    #[serde(default)]
    pub merchant_refund_id: Option<String>,
    #[serde(default)]
    pub bank_ref_num: Option<String>,
}

/// Mandate status update webhook body — maps to EaseBuzzMandateStatusUpdateWebhook.
/// Contains the mandate ID, transaction_id, and updated status.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EasebuzzWebhookMandateStatusBody {
    pub id: String,
    pub transaction_id: String,
    pub status: String,
    #[serde(default)]
    pub umrn: Option<String>,
    #[serde(default)]
    pub mandate_type: Option<String>,
    #[serde(default)]
    pub bank_code: Option<String>,
    #[serde(default)]
    pub auth_mode: Option<String>,
}

/// Presentment (mandate debit) status update webhook body — maps to EaseBuzzPresentmentStatusUpdateWebhook.
/// Contains the debit request status information.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EasebuzzWebhookPresentmentStatusBody {
    pub id: String,
    pub status: String,
    #[serde(default)]
    pub pg_transaction_id: Option<String>,
    #[serde(default)]
    pub amount: Option<serde_json::Number>,
    #[serde(default)]
    pub merchant_request_number: Option<String>,
    #[serde(default)]
    pub transaction_reference_number: Option<String>,
    #[serde(default)]
    pub bank_reference_number: Option<String>,
    /// Nested mandate reference if present
    #[serde(default)]
    pub mandate: Option<EasebuzzWebhookMandateRef>,
}

/// Mandate reference inside a presentment webhook body.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EasebuzzWebhookMandateRef {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub transaction_id: Option<String>,
}

/// Determine the EventType from a webhook body.
/// This maps each webhook variant to the appropriate internal event type.
pub fn get_easebuzz_webhook_event_type(
    webhook: &EasebuzzWebhookBody,
) -> Result<EventType, error_stack::Report<errors::ConnectorError>> {
    match webhook {
        EasebuzzWebhookBody::Transaction(txn) => {
            // Map transaction status to event type
            match txn.status.as_str() {
                "success" => Ok(EventType::PaymentIntentSuccess),
                "failure" | "bounced" => Ok(EventType::PaymentIntentFailure),
                "initiated" | "pending" | "in_process" => Ok(EventType::PaymentIntentProcessing),
                _ => Ok(EventType::PaymentIntentFailure),
            }
        }
        EasebuzzWebhookBody::Refund(refund) => {
            // Map refund status to event type
            match refund.refund_status.as_str() {
                "refunded" => Ok(EventType::RefundSuccess),
                "cancelled" | "reverse chargeback" => Ok(EventType::RefundFailure),
                "queued" | "approved" => Ok(EventType::RefundSuccess),
                _ => Ok(EventType::RefundFailure),
            }
        }
        EasebuzzWebhookBody::MandateStatus(mandate) => {
            // Map mandate status to event type using Section 7.4 mapping
            match mandate.status.as_str() {
                "authorized" => Ok(EventType::MandateActive),
                "expired" | "completed" | "paused" => Ok(EventType::MandateRevoked),
                "revoked" | "cancelled" | "user_cancelled" | "revoking" => {
                    Ok(EventType::MandateRevoked)
                }
                "failed" | "rejected" | "dropped" | "bounced" => Ok(EventType::MandateFailed),
                _ => Ok(EventType::MandateFailed),
            }
        }
        EasebuzzWebhookBody::PresentmentStatus(presentment) => {
            // Presentment status updates are payment status updates for mandate debits
            match presentment.status.as_str() {
                "success" => Ok(EventType::PaymentIntentSuccess),
                "failure" => Ok(EventType::PaymentIntentFailure),
                "in_process" => Ok(EventType::PaymentIntentProcessing),
                _ => Ok(EventType::PaymentIntentProcessing),
            }
        }
    }
}

/// Map Easebuzz webhook transaction status to AttemptStatus.
/// Uses the same mapping as the Authorize flow (Section 7.1).
pub fn map_easebuzz_webhook_txn_status(status: &str) -> AttemptStatus {
    match status {
        "success" => AttemptStatus::Charged,
        "initiated" | "pending" | "in_process" => AttemptStatus::AuthenticationPending,
        "failure" | "bounced" => AttemptStatus::AuthenticationFailed,
        _ => AttemptStatus::AuthenticationFailed,
    }
}

/// Map Easebuzz refund webhook status to RefundStatus.
pub fn map_easebuzz_webhook_refund_status(status: &str) -> RefundStatus {
    match status {
        "refunded" => RefundStatus::Success,
        "queued" | "approved" => RefundStatus::Pending,
        "cancelled" | "reverse chargeback" => RefundStatus::Failure,
        _ => RefundStatus::Pending,
    }
}

/// Map Easebuzz presentment webhook status to AttemptStatus.
/// Uses the same mapping as Section 7.5: mapTxnStatus for mandate execute.
pub fn map_easebuzz_webhook_presentment_status(status: &str) -> AttemptStatus {
    match status {
        "success" => AttemptStatus::Charged,
        "failure" => AttemptStatus::AuthorizationFailed,
        "in_process" => AttemptStatus::Pending,
        _ => AttemptStatus::Pending,
    }
}
