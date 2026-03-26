use common_enums::{AttemptStatus, RefundStatus};
use common_utils::types::MinorUnit;
use domain_types::{
    connector_flow::{Authorize, Capture, PSync, RSync, Refund},
    connector_types::{
        PaymentFlowData, PaymentsCaptureData, PaymentsAuthorizeData, PaymentsResponseData,
        PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData,
        ResponseId,
    },
    errors::{self, ConnectorError},
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes, UpiData},
    router_data::{ConnectorSpecificConfig, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, PeekInterface, Secret};
use serde::{Deserialize, Serialize};

use crate::{connectors::easebuzz::EasebuzzRouterData, types::ResponseRouterData};

// ============================================================================
// Authentication
// ============================================================================

#[derive(Debug, Clone)]
pub struct EasebuzzAuthType {
    pub api_key: Secret<String>,
    pub api_salt: Secret<String>,
}

impl TryFrom<&ConnectorSpecificConfig> for EasebuzzAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorSpecificConfig) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorSpecificConfig::Easebuzz { api_key, .. } => {
                // api_key contains "key|salt" format or just the key
                // We split on | to get key and salt
                let raw = api_key.peek().to_string();
                let parts: Vec<&str> = raw.splitn(2, '|').collect();
                if parts.len() == 2 {
                    Ok(Self {
                        api_key: Secret::new(parts[0].to_string()),
                        api_salt: Secret::new(parts[1].to_string()),
                    })
                } else {
                    // If no separator, use the key as both key and treat salt as empty
                    Ok(Self {
                        api_key: api_key.to_owned(),
                        api_salt: Secret::new(String::new()),
                    })
                }
            }
            _ => Err(error_stack::report!(
                errors::ConnectorError::FailedToObtainAuthType
            )),
        }
    }
}

// ============================================================================
// Error Response
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EasebuzzErrorResponse {
    #[serde(default)]
    pub code: String,
    #[serde(default)]
    pub message: String,
    pub status: Option<serde_json::Value>,
    pub error: Option<String>,
}

impl Default for EasebuzzErrorResponse {
    fn default() -> Self {
        Self {
            code: "UNKNOWN_ERROR".to_string(),
            message: "Unknown error occurred".to_string(),
            status: None,
            error: None,
        }
    }
}

// ============================================================================
// Payment Mode
// ============================================================================

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum EasebuzzPaymentMode {
    Upi,
    Nb,
    #[serde(rename = "WALLET")]
    Wallet,
}

// ============================================================================
// Request Types
// ============================================================================

/// Easebuzz Seamless Transaction Request
/// Sent to `POST /initiate_seamless_payment/`
#[derive(Debug, Serialize)]
pub struct EasebuzzPaymentsRequest {
    /// Access key obtained from InitiatePayment step (we pass key directly for simplified flow)
    pub access_key: String,
    /// Payment mode: UPI, NB, WALLET, CARD, etc.
    pub payment_mode: String,
    /// UPI VPA for UPI Collect flow
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upi_va: Option<Secret<String>>,
    /// UPI QR flag (set to "1" for QR flow)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upi_qr: Option<String>,
}

// ============================================================================
// Response Types
// ============================================================================

/// Status from EaseBuzz seamless transaction response
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EasebuzzPaymentStatus {
    Success,
    Failure,
    Bounced,
    #[serde(other)]
    Unknown,
}

/// EaseBuzz Seamless Transaction Response
#[derive(Debug, Deserialize, Serialize)]
pub struct EasebuzzPaymentsResponse {
    pub status: Option<String>,
    pub txnid: Option<String>,
    pub easepayid: Option<String>,
    pub error: Option<String>,
    #[serde(rename = "error_Message")]
    pub error_message: Option<String>,
    pub mode: Option<String>,
    // Redirect URL field (for UPI intent flow)
    pub return_url: Option<String>,
    // UPI specific
    pub upi_va: Option<String>,
    // Intent link for UPI intent
    pub intent_link: Option<String>,
    // QR code URL
    pub qr_url: Option<String>,
}

// ============================================================================
// Request Transformation
// ============================================================================

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        EasebuzzRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            T,
        >,
    > for EasebuzzPaymentsRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: EasebuzzRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let auth = EasebuzzAuthType::try_from(&router_data.connector_config)
            .change_context(ConnectorError::FailedToObtainAuthType)?;

        // Determine payment mode and UPI-specific fields
        let (payment_mode, upi_va, upi_qr) =
            match &router_data.request.payment_method_data {
                PaymentMethodData::Upi(upi_data) => match upi_data {
                    UpiData::UpiCollect(collect_data) => {
                        let vpa = collect_data
                            .vpa_id
                            .as_ref()
                            .map(|v| Secret::new(v.peek().to_string()));
                        ("UPI".to_string(), vpa, None)
                    }
                    UpiData::UpiIntent(_) => {
                        ("UPI".to_string(), None, None)
                    }
                    UpiData::UpiQr(_) => {
                        ("UPI".to_string(), None, Some("1".to_string()))
                    }
                },
                _ => {
                    return Err(error_stack::report!(ConnectorError::NotImplemented(
                        "Only UPI payment methods are currently supported for Easebuzz".to_string()
                    )));
                }
            };

        // Use the api_key as the access_key for the seamless transaction
        // In production, this would be obtained from the InitiatePayment step
        let access_key = auth.api_key.expose();

        Ok(Self {
            access_key,
            payment_mode,
            upi_va,
            upi_qr,
        })
    }
}

// ============================================================================
// Response Transformation
// ============================================================================

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        ResponseRouterData<
            EasebuzzPaymentsResponse,
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        >,
    >
    for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            EasebuzzPaymentsResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let router_data = item.router_data;

        // Map status
        let status = match response.status.as_deref() {
            Some("success") | Some("SUCCESS") => AttemptStatus::Charged,
            Some("failure") | Some("FAILURE") | Some("failed") | Some("FAILED") => {
                AttemptStatus::Failure
            }
            _ => AttemptStatus::AuthenticationPending,
        };

        // Check for error
        if let Some(ref err) = response.error {
            if !err.is_empty() && err != "0" {
                return Ok(Self {
                    resource_common_data: PaymentFlowData {
                        status: AttemptStatus::Failure,
                        ..router_data.resource_common_data
                    },
                    response: Err(ErrorResponse {
                        status_code: item.http_code,
                        code: err.clone(),
                        message: response
                            .error_message
                            .clone()
                            .unwrap_or_else(|| "Payment failed".to_string()),
                        reason: response.error_message.clone(),
                        attempt_status: Some(AttemptStatus::Failure),
                        connector_transaction_id: response.easepayid.clone(),
                        network_decline_code: None,
                        network_advice_code: None,
                        network_error_message: None,
                    }),
                    ..router_data
                });
            }
        }

        // Build redirect data if redirect URL is available
        let redirect_url = response
            .return_url
            .clone()
            .or_else(|| response.intent_link.clone())
            .or_else(|| response.qr_url.clone());

        let redirection_data = redirect_url.map(|url| {
            Box::new(RedirectForm::Form {
                endpoint: url,
                method: common_utils::request::Method::Get,
                form_fields: std::collections::HashMap::new(),
            })
        });

        let transaction_id = response
            .easepayid
            .clone()
            .or_else(|| response.txnid.clone())
            .unwrap_or_else(|| {
                router_data
                    .resource_common_data
                    .connector_request_reference_id
                    .clone()
            });

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(transaction_id),
                redirection_data,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: response.txnid.clone(),
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            ..router_data
        })
    }
}

// ============================================================================
// Capture Types
// ============================================================================

/// Easebuzz Direct Authorization Capture Request
/// POST to `/payment/v1/capture/direct`
#[derive(Debug, Serialize)]
pub struct EasebuzzCaptureRequest {
    /// Merchant API key
    pub key: Secret<String>,
    /// Easebuzz transaction ID (easepayid) from authorize step
    pub txnid: String,
    /// Transaction amount (as string in minor units / paise)
    pub amount: String,
    /// HMAC-SHA512 hash for authentication
    pub hash: String,
}

/// Compute SHA-512 hash for Easebuzz Capture
/// Formula: sha512(key|txnid|amount|salt)
fn compute_easebuzz_capture_hash(key: &str, txnid: &str, amount: &str, salt: &str) -> String {
    use sha2::{Digest, Sha512};
    let input = format!("{key}|{txnid}|{amount}|{salt}");
    let mut hasher = Sha512::new();
    hasher.update(input.as_bytes());
    format!("{:x}", hasher.finalize())
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        EasebuzzRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    > for EasebuzzCaptureRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: EasebuzzRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = item.router_data;
        let auth = EasebuzzAuthType::try_from(&router_data.connector_config)
            .change_context(ConnectorError::FailedToObtainAuthType)?;

        // Purpose: API requires original transaction reference for capture
        let txnid = router_data
            .request
            .get_connector_transaction_id()
            .change_context(ConnectorError::MissingConnectorTransactionID)?;

        let amount_i64 = router_data.request.minor_amount_to_capture.get_amount_as_i64();
        let amount_str = amount_i64.to_string();

        let key_str = auth.api_key.peek().to_string();
        let salt_str = auth.api_salt.peek().to_string();

        let hash = compute_easebuzz_capture_hash(&key_str, &txnid, &amount_str, &salt_str);

        Ok(Self {
            key: auth.api_key,
            txnid,
            amount: amount_str,
            hash,
        })
    }
}

/// Inner data payload within the successful AuthZ response
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct EasebuzzAuthZData {
    pub status: String,
    pub txnid: Option<String>,
    pub easepayid: Option<String>,
    pub error: Option<String>,
    #[serde(rename = "error_Message")]
    pub error_message: Option<String>,
}

/// Successful AuthZ capture response: ValidAuthZResponse(EasebuzzOnlyAuthZResponse)
#[derive(Debug, Deserialize, Serialize)]
pub struct EasebuzzOnlyAuthZResponse {
    #[serde(rename = "data")]
    pub data: EasebuzzAuthZData,
}

/// Error AuthZ capture response: EasebuzzRedirectAuthzErrorResponse
#[derive(Debug, Deserialize, Serialize)]
pub struct EasebuzzAuthZErrorResponse {
    #[serde(rename = "error_Message")]
    pub error_message: Option<String>,
    pub error: Option<String>,
    pub status: Option<String>,
}

/// Top-level response from POST /payment/v1/capture/direct
#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum EasebuzzCaptureResponse {
    /// Successful: contains nested _data with status
    Success(EasebuzzOnlyAuthZResponse),
    /// Error: authorization failed
    Error(EasebuzzAuthZErrorResponse),
}

impl
    TryFrom<
        ResponseRouterData<
            EasebuzzCaptureResponse,
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    > for RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            EasebuzzCaptureResponse,
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = item.router_data;

        match &item.response {
            EasebuzzCaptureResponse::Success(success_resp) => {
                let txn_data = &success_resp.data;

                // Check for error field in _data
                if let Some(ref err) = txn_data.error {
                    if !err.is_empty() && err != "0" {
                        return Ok(Self {
                            resource_common_data: PaymentFlowData {
                                status: AttemptStatus::Failure,
                                ..router_data.resource_common_data
                            },
                            response: Err(ErrorResponse {
                                status_code: item.http_code,
                                code: err.clone(),
                                message: txn_data
                                    .error_message
                                    .clone()
                                    .unwrap_or_else(|| "Capture failed".to_string()),
                                reason: txn_data.error_message.clone(),
                                attempt_status: Some(AttemptStatus::Failure),
                                connector_transaction_id: txn_data.easepayid.clone(),
                                network_decline_code: None,
                                network_advice_code: None,
                                network_error_message: None,
                            }),
                            ..router_data
                        });
                    }
                }

                // Map status from _data.status using getTxnStatus logic
                let status = match txn_data.status.to_lowercase().as_str() {
                    "success" => AttemptStatus::Charged,
                    "initiated" | "pending" | "in_process" => AttemptStatus::Pending,
                    _ => AttemptStatus::Failure,
                };

                let transaction_id = txn_data
                    .easepayid
                    .clone()
                    .or_else(|| txn_data.txnid.clone())
                    .unwrap_or_else(|| {
                        router_data
                            .resource_common_data
                            .connector_request_reference_id
                            .clone()
                    });

                Ok(Self {
                    resource_common_data: PaymentFlowData {
                        status,
                        ..router_data.resource_common_data
                    },
                    response: Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(transaction_id),
                        redirection_data: None,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: None,
                        connector_response_reference_id: txn_data.txnid.clone(),
                        incremental_authorization_allowed: None,
                        status_code: item.http_code,
                    }),
                    ..router_data
                })
            }
            EasebuzzCaptureResponse::Error(err_resp) => {
                let err_msg = err_resp
                    .error_message
                    .clone()
                    .or_else(|| err_resp.error.clone())
                    .unwrap_or_else(|| "Authorization capture failed".to_string());

                let err_code = err_resp
                    .status
                    .clone()
                    .unwrap_or_else(|| "AUTHORIZATION_FAILED".to_string());

                Ok(Self {
                    resource_common_data: PaymentFlowData {
                        status: AttemptStatus::Failure,
                        ..router_data.resource_common_data
                    },
                    response: Err(ErrorResponse {
                        status_code: item.http_code,
                        code: err_code,
                        message: err_msg.clone(),
                        reason: Some(err_msg),
                        attempt_status: Some(AttemptStatus::Failure),
                        connector_transaction_id: None,
                        network_decline_code: None,
                        network_advice_code: None,
                        network_error_message: None,
                    }),
                    ..router_data
                })
            }
        }
    }
}

// Helper to check if the request is a UPI collect flow (for response handling)
pub fn get_payment_mode_from_request<T: PaymentMethodDataTypes>(
    request: &PaymentsAuthorizeData<T>,
) -> &str {
    match &request.payment_method_data {
        PaymentMethodData::Upi(UpiData::UpiCollect(_)) => "upi_collect",
        PaymentMethodData::Upi(_) => "upi_intent",
        _ => "other",
    }
}

// ============================================================================
// Refund Types
// ============================================================================

/// Compute SHA-512 hash for Easebuzz Refund
/// Formula: sha512(key|merchantRefundId|easebuzzId|refundAmount|salt)
fn compute_easebuzz_refund_hash(
    key: &str,
    merchant_refund_id: &str,
    easebuzz_id: &str,
    refund_amount: &str,
    salt: &str,
) -> String {
    use sha2::{Digest, Sha512};
    let input = format!("{key}|{merchant_refund_id}|{easebuzz_id}|{refund_amount}|{salt}");
    let mut hasher = Sha512::new();
    hasher.update(input.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Easebuzz Refund Request
/// POST to `https://dashboard.easebuzz.in/transaction/v2/refund`
#[derive(Debug, Serialize)]
pub struct EasebuzzRefundRequest {
    /// Merchant API key
    pub key: Secret<String>,
    /// Merchant's refund reference ID
    pub merchant_refund_id: String,
    /// Easebuzz transaction ID (easepayid from authorize/capture)
    pub easebuzz_id: String,
    /// Amount to refund (as string in minor units / paise)
    pub refund_amount: String,
    /// HMAC-SHA512 hash: sha512(key|merchantRefundId|easebuzzId|refundAmount|salt)
    pub hash: String,
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
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
        let router_data = item.router_data;
        let auth = EasebuzzAuthType::try_from(&router_data.connector_config)
            .change_context(ConnectorError::FailedToObtainAuthType)?;

        // easebuzz_id is the connector transaction ID from the original payment
        let easebuzz_id = router_data.request.connector_transaction_id.clone();

        // merchant_refund_id is the internal refund ID
        let merchant_refund_id = router_data.request.refund_id.clone();

        // refund amount in minor units as string
        let refund_amount_i64 = router_data.request.minor_refund_amount.get_amount_as_i64();
        let refund_amount = refund_amount_i64.to_string();

        let key_str = auth.api_key.peek().to_string();
        let salt_str = auth.api_salt.peek().to_string();

        let hash = compute_easebuzz_refund_hash(
            &key_str,
            &merchant_refund_id,
            &easebuzz_id,
            &refund_amount,
            &salt_str,
        );

        Ok(Self {
            key: auth.api_key,
            merchant_refund_id,
            easebuzz_id,
            refund_amount,
            hash,
        })
    }
}

/// Easebuzz Refund Response
/// Response from POST /transaction/v2/refund
#[derive(Debug, Deserialize, Serialize)]
pub struct EasebuzzRefundResponse {
    /// Refund initiation success flag
    pub status: bool,
    /// Failure reason (if any)
    pub reason: Option<String>,
    /// Easebuzz transaction ID
    pub easebuzz_id: Option<String>,
    /// Easebuzz refund ID
    pub refund_id: Option<String>,
    /// Confirmed refund amount
    pub refund_amount: Option<serde_json::Value>,
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
        let router_data = item.router_data;

        if !response.status {
            let reason = response
                .reason
                .clone()
                .unwrap_or_else(|| "Refund initiation failed".to_string());

            return Ok(Self {
                resource_common_data: RefundFlowData {
                    status: RefundStatus::Failure,
                    ..router_data.resource_common_data
                },
                response: Err(ErrorResponse {
                    status_code: item.http_code,
                    code: "REFUND_FAILED".to_string(),
                    message: reason.clone(),
                    reason: Some(reason),
                    attempt_status: None,
                    connector_transaction_id: response.easebuzz_id.clone(),
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                }),
                ..router_data
            });
        }

        // status = true means refund initiated successfully (pending)
        let connector_refund_id = response
            .refund_id
            .clone()
            .or_else(|| response.easebuzz_id.clone())
            .unwrap_or_else(|| router_data.resource_common_data.connector_request_reference_id.clone());

        Ok(Self {
            resource_common_data: RefundFlowData {
                status: RefundStatus::Pending,
                ..router_data.resource_common_data
            },
            response: Ok(RefundsResponseData {
                connector_refund_id,
                refund_status: RefundStatus::Pending,
                status_code: item.http_code,
            }),
            ..router_data
        })
    }
}

// ============================================================================
// PSync Types
// ============================================================================

/// Easebuzz Transaction Sync Request
/// POST to `https://dashboard.easebuzz.in/transaction/v1/retrieve`
#[derive(Debug, Serialize)]
pub struct EasebuzzSyncRequest {
    /// Transaction ID (connector_transaction_id / easepayid)
    pub txnid: String,
    /// Transaction amount (in minor units as integer)
    pub amount: i64,
    /// Customer email
    pub email: String,
    /// Customer phone
    pub phone: String,
    /// Merchant API key
    pub key: Secret<String>,
    /// HMAC-SHA512 hash: sha512(key|txnid|amount|email|phone|salt)
    pub hash: String,
}

/// Easebuzz Seamless Txn Response (embedded in TxnSyncSuccessMessage)
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct EasebuzzSeamlessTxnResponse {
    pub status: String,
    pub txnid: Option<String>,
    pub easepayid: Option<String>,
    pub error: Option<String>,
    #[serde(rename = "error_Message")]
    pub error_message: Option<String>,
}

/// EaseBuzzTxnSyncResponse — top-level sync response
#[derive(Debug, Deserialize, Serialize)]
pub struct EasebuzzSyncResponse {
    /// API call success flag
    pub status: bool,
    /// Response payload: success message or error text
    pub msg: EasebuzzTxnSyncMsg,
}

/// TxnSyncMessageType — union of success/error variants
#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum EasebuzzTxnSyncMsg {
    /// Success variant: full transaction details
    Success(EasebuzzSeamlessTxnResponse),
    /// Error variant: plain text or structured error
    Error(serde_json::Value),
}

/// Compute SHA-512 hash for Easebuzz TxnSync
/// Formula: sha512(key|txnid|amount|email|phone|salt)
fn compute_easebuzz_sync_hash(
    key: &str,
    txnid: &str,
    amount: i64,
    email: &str,
    phone: &str,
    salt: &str,
) -> String {
    use sha2::{Digest, Sha512};
    let input = format!("{key}|{txnid}|{amount}|{email}|{phone}|{salt}");
    let mut hasher = Sha512::new();
    hasher.update(input.as_bytes());
    format!("{:x}", hasher.finalize())
}

// ============================================================================
// PSync Request Transformation
// ============================================================================

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
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
        let router_data = item.router_data;
        let auth = EasebuzzAuthType::try_from(&router_data.connector_config)
            .change_context(ConnectorError::FailedToObtainAuthType)?;

        let txnid = router_data
            .request
            .get_connector_transaction_id()
            .change_context(ConnectorError::MissingConnectorTransactionID)?;

        let amount = router_data.request.amount.get_amount_as_i64();

        // Get email and phone from billing address; fall back to empty strings if not provided
        let email = router_data
            .resource_common_data
            .get_optional_billing_email()
            .map(|e| e.peek().to_string())
            .unwrap_or_default();

        let phone = router_data
            .resource_common_data
            .get_optional_billing_phone_number()
            .map(|p| p.peek().to_string())
            .unwrap_or_default();

        let key_str = auth.api_key.peek().to_string();
        let salt_str = auth.api_salt.peek().to_string();

        let hash = compute_easebuzz_sync_hash(&key_str, &txnid, amount, &email, &phone, &salt_str);

        Ok(Self {
            txnid,
            amount,
            email,
            phone,
            key: auth.api_key,
            hash,
        })
    }
}

// ============================================================================
// PSync Response Transformation
// ============================================================================

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
        let router_data = item.router_data;

        match &response.msg {
            EasebuzzTxnSyncMsg::Success(txn_resp) => {
                // Check for error in the response
                if let Some(ref err) = txn_resp.error {
                    if !err.is_empty() && err != "0" {
                        return Ok(Self {
                            resource_common_data: PaymentFlowData {
                                status: AttemptStatus::Failure,
                                ..router_data.resource_common_data
                            },
                            response: Err(ErrorResponse {
                                status_code: item.http_code,
                                code: err.clone(),
                                message: txn_resp
                                    .error_message
                                    .clone()
                                    .unwrap_or_else(|| "Payment sync failed".to_string()),
                                reason: txn_resp.error_message.clone(),
                                attempt_status: Some(AttemptStatus::Failure),
                                connector_transaction_id: txn_resp.easepayid.clone(),
                                network_decline_code: None,
                                network_advice_code: None,
                                network_error_message: None,
                            }),
                            ..router_data
                        });
                    }
                }

                let attempt_status = match txn_resp.status.to_lowercase().as_str() {
                    "success" => AttemptStatus::Charged,
                    "initiated" | "pending" | "in_process" => AttemptStatus::Pending,
                    _ => AttemptStatus::Failure,
                };

                let transaction_id = txn_resp
                    .easepayid
                    .clone()
                    .or_else(|| txn_resp.txnid.clone())
                    .unwrap_or_else(|| {
                        router_data
                            .resource_common_data
                            .connector_request_reference_id
                            .clone()
                    });

                Ok(Self {
                    resource_common_data: PaymentFlowData {
                        status: attempt_status,
                        ..router_data.resource_common_data
                    },
                    response: Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(transaction_id),
                        redirection_data: None,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: None,
                        connector_response_reference_id: txn_resp.txnid.clone(),
                        incremental_authorization_allowed: None,
                        status_code: item.http_code,
                    }),
                    ..router_data
                })
            }
            EasebuzzTxnSyncMsg::Error(err_val) => {
                let err_msg = err_val.to_string();
                Ok(Self {
                    resource_common_data: PaymentFlowData {
                        status: AttemptStatus::Failure,
                        ..router_data.resource_common_data
                    },
                    response: Err(ErrorResponse {
                        status_code: item.http_code,
                        code: "SYNC_ERROR".to_string(),
                        message: err_msg.clone(),
                        reason: Some(err_msg),
                        attempt_status: Some(AttemptStatus::Failure),
                        connector_transaction_id: None,
                        network_decline_code: None,
                        network_advice_code: None,
                        network_error_message: None,
                    }),
                    ..router_data
                })
            }
        }
    }
}

// ============================================================================
// RSync Types
// ============================================================================

/// Compute SHA-512 hash for Easebuzz Refund Sync
/// Formula: sha512(key|easebuzzId|salt)
fn compute_easebuzz_refund_sync_hash(key: &str, easebuzz_id: &str, salt: &str) -> String {
    use sha2::{Digest, Sha512};
    let input = format!("{key}|{easebuzz_id}|{salt}");
    let mut hasher = Sha512::new();
    hasher.update(input.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Easebuzz Refund Sync Request
/// POST to `https://dashboard.easebuzz.in/refund/v1/retrieve`
#[derive(Debug, Serialize)]
pub struct EasebuzzRefundSyncRequest {
    /// Merchant API key
    pub key: Secret<String>,
    /// Easebuzz transaction ID (easepayid from original payment)
    pub easebuzz_id: String,
    /// HMAC-SHA512 hash: sha512(key|easebuzzId|salt)
    pub hash: String,
    /// Merchant refund reference ID
    pub merchant_refund_id: String,
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
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
        let router_data = item.router_data;
        let auth = EasebuzzAuthType::try_from(&router_data.connector_config)
            .change_context(ConnectorError::FailedToObtainAuthType)?;

        // easebuzz_id is the connector transaction ID from the original payment
        let easebuzz_id = router_data.request.connector_transaction_id.clone();

        // merchant_refund_id is the connector refund ID returned during Refund flow
        let merchant_refund_id = router_data.request.connector_refund_id.clone();

        let key_str = auth.api_key.peek().to_string();
        let salt_str = auth.api_salt.peek().to_string();

        let hash = compute_easebuzz_refund_sync_hash(&key_str, &easebuzz_id, &salt_str);

        Ok(Self {
            key: auth.api_key,
            easebuzz_id,
            hash,
            merchant_refund_id,
        })
    }
}

/// Easebuzz Refund Sync Success Response inner data
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct EasebuzzRefundSyncSuccessData {
    /// Refund status string from Easebuzz
    pub status: Option<String>,
    /// Easebuzz refund ID
    pub refund_id: Option<String>,
    /// Bank reference number (ARN)
    pub bank_ref_num: Option<String>,
    /// Easebuzz transaction ID
    pub easebuzz_id: Option<String>,
}

/// Top-level Easebuzz Refund Sync Response
/// The response is a union of Success / Failure / ValidationError variants
#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum EasebuzzRefundSyncResponse {
    /// Success variant: contains refund status data
    Success(EasebuzzRefundSyncSuccessData),
    /// Failure / validation-error variant
    Error(serde_json::Value),
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
        let router_data = item.router_data;

        match &item.response {
            EasebuzzRefundSyncResponse::Success(success_data) => {
                let refund_status = match success_data
                    .status
                    .as_deref()
                    .unwrap_or("")
                    .to_lowercase()
                    .as_str()
                {
                    "refunded" => RefundStatus::Success,
                    "cancelled" | "reverse chargeback" => RefundStatus::Failure,
                    // queued, approved, or any unknown status → Pending
                    _ => RefundStatus::Pending,
                };

                let connector_refund_id = success_data
                    .refund_id
                    .clone()
                    .or_else(|| success_data.easebuzz_id.clone())
                    .unwrap_or_else(|| router_data.request.connector_refund_id.clone());

                Ok(Self {
                    resource_common_data: RefundFlowData {
                        status: refund_status,
                        ..router_data.resource_common_data
                    },
                    response: Ok(RefundsResponseData {
                        connector_refund_id,
                        refund_status,
                        status_code: item.http_code,
                    }),
                    ..router_data
                })
            }
            EasebuzzRefundSyncResponse::Error(err_val) => {
                let err_msg = err_val.to_string();
                Ok(Self {
                    resource_common_data: RefundFlowData {
                        status: RefundStatus::Failure,
                        ..router_data.resource_common_data
                    },
                    response: Err(ErrorResponse {
                        status_code: item.http_code,
                        code: "REFUND_SYNC_ERROR".to_string(),
                        message: err_msg.clone(),
                        reason: Some(err_msg),
                        attempt_status: None,
                        connector_transaction_id: None,
                        network_decline_code: None,
                        network_advice_code: None,
                        network_error_message: None,
                    }),
                    ..router_data
                })
            }
        }
    }
}
