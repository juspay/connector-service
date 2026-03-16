use std::time::{SystemTime, UNIX_EPOCH};

use crate::types::ResponseRouterData;
use base64::{engine::general_purpose, Engine};
use common_enums::{AttemptStatus, RefundStatus};
use common_utils::{
    crypto::{self, RsaOaepSha256, SignMessage},
    FloatMajorUnit,
};
use domain_types::{
    connector_flow::{Authorize, CreateAccessToken, PSync, RSync, Refund, Void},
    connector_types::{
        AccessTokenRequestData, AccessTokenResponseData, PaymentFlowData, PaymentVoidData,
        PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, RefundFlowData,
        RefundSyncData, RefundsData, RefundsResponseData, ResponseId,
    },
    errors,
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes},
    router_data::ConnectorSpecificAuth,
    router_data_v2::RouterDataV2,
    utils,
};
use error_stack::ResultExt;
use hyperswitch_masking::{PeekInterface, Secret};
use rand::Rng;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct FiservcommercehubAuthType {
    pub api_key: Secret<String>,
    pub api_secret: Secret<String>,
    pub merchant_id: Secret<String>,
    pub terminal_id: Secret<String>,
}

impl FiservcommercehubAuthType {
    /// Computes the HMAC-SHA256 signature for the Authorization header.
    ///
    /// Raw signature message: `{api_key}{client_request_id}{timestamp}{request_body}`
    /// Signing key: `self.api_secret` (the HMAC secret, separate from the API key)
    pub fn generate_hmac_signature(
        &self,
        api_key: &str,
        client_request_id: &str,
        timestamp: &str,
        request_body: &str,
    ) -> Result<String, error_stack::Report<errors::ConnectorError>> {
        let raw_signature = format!("{api_key}{client_request_id}{timestamp}{request_body}");
        println!("$$Raw signature message: {raw_signature}");
        let signature = crypto::HmacSha256
            .sign_message(self.api_secret.peek().as_bytes(), raw_signature.as_bytes())
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;
        Ok(general_purpose::STANDARD.encode(signature))
    }

    pub fn generate_client_request_id() -> String {
        // Uuid::new_v4().to_string()
        let mut rng = rand::thread_rng();
        // Generates a number between 1 and 10,000,000
        let random_number: u32 = rng.gen_range(1..=10_000_000);
        random_number.to_string()
    }

    pub fn generate_timestamp() -> String {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .to_string()
    }
}

impl TryFrom<&ConnectorSpecificAuth> for FiservcommercehubAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorSpecificAuth) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorSpecificAuth::Fiservcommercehub {
                api_key,
                secret: api_secret,
                merchant_id,
                terminal_id,
            } => Ok(Self {
                api_key: api_key.to_owned(),
                api_secret: api_secret.to_owned(),
                merchant_id: merchant_id.to_owned(),
                terminal_id: terminal_id.to_owned(),
            }),
            _ => Err(error_stack::report!(
                errors::ConnectorError::FailedToObtainAuthType
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservcommercehubErrorResponse {
    pub gateway_response: Option<FiservcommercehubErrorGatewayResponse>,
    pub error: Vec<FiservcommercehubErrorDetail>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservcommercehubErrorGatewayResponse {
    pub transaction_state: Option<String>,
    pub transaction_processing_details: Option<FiservcommercehubErrorTxnDetails>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservcommercehubErrorTxnDetails {
    pub api_trace_id: Option<String>,
    pub client_request_id: Option<String>,
    pub transaction_id: Option<String>,
    pub order_id: Option<String>,
    pub transaction_timestamp: Option<String>,
    pub api_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FiservcommercehubErrorDetail {
    #[serde(rename = "type")]
    pub error_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    pub message: String,
}

// =============================================================================
// AUTHORIZE FLOW
// =============================================================================

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservcommercehubAuthorizeRequest {
    pub amount: FiservcommercehubAuthorizeAmount,
    pub source: FiservcommercehubSourceData,
    pub merchant_details: FiservcommercehubMerchantDetails,
    pub transaction_details: FiservcommercehubTransactionDetailsReq,
    pub transaction_interaction: FiservcommercehubTransactionInteractionReq,
}

#[derive(Debug, Serialize)]
pub struct FiservcommercehubAuthorizeAmount {
    pub currency: String,
    pub total: FloatMajorUnit,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservcommercehubSourceData {
    pub source_type: String,
    pub encryption_data: FiservcommercehubEncryptionData,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservcommercehubEncryptionData {
    /// Key ID from the CreateAccessToken response: the `{keyId}` portion of `{apiKey}_{keyId}`
    pub key_id: String,
    pub encryption_type: String,
    /// RSA-encrypted card data encoded as base64.
    /// Plaintext layout (per encryptionBlockFields):
    ///   card.cardData:16 | card.nameOnCard:11 | card.expirationMonth:2 | card.expirationYear:4
    /// NOTE: actual RSA encryption using Fiserv's asymmetric public key must be applied.
    pub encryption_block: Secret<String>,
    pub encryption_block_fields: String,
    pub encryption_target: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservcommercehubTransactionDetailsReq {
    pub capture_flag: bool,
    pub merchant_transaction_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservcommercehubTransactionInteractionReq {
    pub additional_pos_information: FiservcommercehubAdditionalPosInfo,
}

#[derive(Debug, Serialize)]
pub struct FiservcommercehubAdditionalPosInfo {
    pub origin: String,
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        super::FiservcommercehubRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for FiservcommercehubAuthorizeRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: super::FiservcommercehubRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = item.router_data;

        let total = utils::convert_amount(
            item.connector.amount_converter,
            router_data.request.minor_amount,
            router_data.request.currency,
        )?;

        // Access token format: "{keyId}|||{encodedPublicKey}"
        let access_token = router_data.resource_common_data.get_access_token()?;
        let parts: Vec<&str> = access_token.split("|||").collect();

        let key_id = parts
            .first()
            .ok_or_else(|| {
                error_stack::report!(errors::ConnectorError::MissingRequiredField {
                    field_name: "key_id"
                })
            })?
            .to_string();

        let encoded_public_key = parts.get(1).ok_or_else(|| {
            error_stack::report!(errors::ConnectorError::MissingRequiredField {
                field_name: "encoded_public_key"
            })
        })?;

        // Decode the Base64-encoded RSA public key (SPKI/DER format)
        let public_key_der = general_purpose::STANDARD
            .decode(encoded_public_key)
            .map_err(|_| error_stack::report!(errors::ConnectorError::RequestEncodingFailed))
            .attach_printable("Failed to decode Base64 RSA public key")?;

        let card = match &router_data.request.payment_method_data {
            PaymentMethodData::Card(card) => card,
            _ => {
                return Err(error_stack::report!(
                    errors::ConnectorError::NotImplemented(
                        "Only Card payment method is supported for Fiservcommercehub".to_string()
                    )
                ))
            }
        };

        // Extract card data values
        let card_data = card.card_number.peek().to_string();
        let name_on_card = card
            .card_holder_name
            .as_ref()
            .map(|n| n.peek().clone())
            .unwrap_or_default();
        let expiration_month = card.card_exp_month.peek().to_string();
        let expiration_year = card.card_exp_year.peek().to_string();

        // Build the plaintext block by concatenating all values (matching JS: Object.values(cardData).join(""))
        let plain_block = format!(
            "{}{}{}{}",
            card_data, name_on_card, expiration_month, expiration_year
        );

        // Build encryptionBlockFields dynamically based on actual byte lengths
        // Format: "card.cardData:{len},card.nameOnCard:{len},card.expirationMonth:{len},card.expirationYear:{len}"
        let encryption_block_fields = format!(
            "card.cardData:{},card.nameOnCard:{},card.expirationMonth:{},card.expirationYear:{}",
            card_data.len(),
            name_on_card.len(),
            expiration_month.len(),
            expiration_year.len()
        );

        // RSA encrypt the plaintext block using Fiserv's public key with OAEP-SHA256 padding
        let encrypted_bytes = RsaOaepSha256::encrypt(&public_key_der, plain_block.as_bytes())
            .change_context(errors::ConnectorError::RequestEncodingFailed)
            .attach_printable("RSA OAEP-SHA256 encryption of card data failed")?;

        // Base64 encode the encrypted bytes for the API request
        let encryption_block = Secret::new(general_purpose::STANDARD.encode(&encrypted_bytes));

        let auth_type = &router_data.connector_auth_type;

        let auth = FiservcommercehubAuthType::try_from(auth_type)?;

        let request = Self {
            amount: FiservcommercehubAuthorizeAmount {
                currency: router_data.request.currency.to_string(),
                total,
            },
            source: FiservcommercehubSourceData {
                source_type: "PaymentCard".to_string(),
                encryption_data: FiservcommercehubEncryptionData {
                    key_id,
                    encryption_type: "RSA".to_string(),
                    encryption_block,
                    encryption_block_fields,
                    encryption_target: "MANUAL".to_string(),
                },
            },
            merchant_details: FiservcommercehubMerchantDetails {
                merchant_id: auth.merchant_id.clone(),
                terminal_id: auth.terminal_id.clone(),
            },
            transaction_details: FiservcommercehubTransactionDetailsReq {
                capture_flag: true,
                merchant_transaction_id: router_data
                    .resource_common_data
                    .connector_request_reference_id
                    .clone(),
            },
            transaction_interaction: FiservcommercehubTransactionInteractionReq {
                additional_pos_information: FiservcommercehubAdditionalPosInfo {
                    origin: "ECOM".to_string(),
                },
            },
        };
        println!(
            "$$$[AUTHORIZE] Request body: {}",
            serde_json::to_string(&request).unwrap_or_else(|_| format!("{request:?}"))
        );
        Ok(request)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FiservcommercehubTransactionState {
    /// Transaction approved and captured by the issuer.
    Approved,
    /// Transaction captured (auto-capture after authorization).
    Captured,
    /// Transaction authorized; capture has not yet occurred.
    Authorized,
    /// Transaction is awaiting further action (e.g. async payment method).
    Pending,
    /// Transaction refused by the issuer or processor.
    Declined,
    /// Transaction rejected due to validation errors, fraud filters, or missing fields.
    Rejected,
    /// Transaction failed during processing.
    Failed,
    /// Transaction was voided or cancelled before completion.
    Cancelled,
}

impl From<&FiservcommercehubTransactionState> for AttemptStatus {
    fn from(state: &FiservcommercehubTransactionState) -> Self {
        match state {
            FiservcommercehubTransactionState::Approved
            | FiservcommercehubTransactionState::Captured => Self::Charged,
            FiservcommercehubTransactionState::Authorized => Self::Authorized,
            FiservcommercehubTransactionState::Pending => Self::Pending,
            FiservcommercehubTransactionState::Declined
            | FiservcommercehubTransactionState::Rejected
            | FiservcommercehubTransactionState::Failed => Self::Failure,
            FiservcommercehubTransactionState::Cancelled => Self::Voided,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservcommercehubAuthorizeResponse {
    pub gateway_response: FiservcommercehubGatewayResponseBody,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservcommercehubGatewayResponseBody {
    pub transaction_state: FiservcommercehubTransactionState,
    pub transaction_processing_details: FiservcommercehubTxnDetails,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservcommercehubTxnDetails {
    pub order_id: Option<String>,
    pub transaction_id: String,
}

impl<T: PaymentMethodDataTypes>
    TryFrom<
        ResponseRouterData<
            FiservcommercehubAuthorizeResponse,
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
            FiservcommercehubAuthorizeResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        let txn = &item
            .response
            .gateway_response
            .transaction_processing_details;
        let status = AttemptStatus::from(&item.response.gateway_response.transaction_state);

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(txn.transaction_id.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: txn.order_id.clone(),
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

// =============================================================================
// PSYNC FLOW
// =============================================================================

/// Merchant identification for the transaction-inquiry request (only merchantId is required).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservcommercehubPSyncMerchantDetails {
    pub merchant_id: Secret<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservcommercehubReferenceTransactionDetails {
    pub reference_transaction_id: String,
}

/// Request body for `POST /payments/v1/transaction-inquiry`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservcommercehubPSyncRequest {
    pub merchant_details: FiservcommercehubPSyncMerchantDetails,
    pub reference_transaction_details: FiservcommercehubReferenceTransactionDetails,
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        super::FiservcommercehubRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    > for FiservcommercehubPSyncRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: super::FiservcommercehubRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = item.router_data;
        let auth = FiservcommercehubAuthType::try_from(&router_data.connector_auth_type)?;
        let connector_transaction_id = router_data
            .request
            .connector_transaction_id
            .get_connector_transaction_id()
            .change_context(errors::ConnectorError::MissingConnectorTransactionID)?;
        Ok(Self {
            merchant_details: FiservcommercehubPSyncMerchantDetails {
                merchant_id: auth.merchant_id.clone(),
            },
            reference_transaction_details: FiservcommercehubReferenceTransactionDetails {
                reference_transaction_id: connector_transaction_id,
            },
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservcommercehubPSyncGatewayResponse {
    pub transaction_state: FiservcommercehubTransactionState,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservcommercehubPSyncItem {
    pub gateway_response: FiservcommercehubPSyncGatewayResponse,
}

/// The transaction-inquiry endpoint returns an array of transaction objects.
#[derive(Debug, Deserialize, Serialize)]
pub struct FiservcommercehubPSyncResponse(pub Vec<FiservcommercehubPSyncItem>);

impl
    TryFrom<
        ResponseRouterData<
            FiservcommercehubPSyncResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    > for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            FiservcommercehubPSyncResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let psync_item = item.response.0.into_iter().next().ok_or_else(|| {
            error_stack::report!(errors::ConnectorError::ResponseDeserializationFailed)
        })?;
        let status = AttemptStatus::from(&psync_item.gateway_response.transaction_state);
        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::NoResponseId,
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

// =============================================================================
// REFUND FLOW
// =============================================================================

impl From<&FiservcommercehubTransactionState> for RefundStatus {
    fn from(state: &FiservcommercehubTransactionState) -> Self {
        match state {
            FiservcommercehubTransactionState::Approved
            | FiservcommercehubTransactionState::Captured => Self::Success,
            FiservcommercehubTransactionState::Authorized
            | FiservcommercehubTransactionState::Pending => Self::Pending,
            FiservcommercehubTransactionState::Declined
            | FiservcommercehubTransactionState::Rejected
            | FiservcommercehubTransactionState::Failed
            | FiservcommercehubTransactionState::Cancelled => Self::Failure,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservcommercehubRefundTransactionDetails {
    pub capture_flag: bool,
    pub merchant_transaction_id: String,
}

/// Request body for `POST /payments/v1/refunds`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservcommercehubRefundRequest {
    pub amount: FiservcommercehubAuthorizeAmount,
    pub transaction_details: FiservcommercehubRefundTransactionDetails,
    pub merchant_details: FiservcommercehubMerchantDetails,
    pub reference_transaction_details: FiservcommercehubReferenceTransactionDetails,
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        super::FiservcommercehubRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    > for FiservcommercehubRefundRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: super::FiservcommercehubRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = item.router_data;
        let total = utils::convert_amount(
            item.connector.amount_converter,
            router_data.request.minor_refund_amount,
            router_data.request.currency,
        )?;
        let auth = FiservcommercehubAuthType::try_from(&router_data.connector_auth_type)?;
        Ok(Self {
            amount: FiservcommercehubAuthorizeAmount {
                currency: router_data.request.currency.to_string(),
                total,
            },
            transaction_details: FiservcommercehubRefundTransactionDetails {
                capture_flag: true,
                merchant_transaction_id: router_data
                    .resource_common_data
                    .connector_request_reference_id
                    .clone(),
            },
            merchant_details: FiservcommercehubMerchantDetails {
                merchant_id: auth.merchant_id.clone(),
                terminal_id: auth.terminal_id.clone(),
            },
            reference_transaction_details: FiservcommercehubReferenceTransactionDetails {
                reference_transaction_id: router_data.request.connector_transaction_id.clone(),
            },
        })
    }
}

/// Response body from `POST /payments/v1/refunds`.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservcommercehubRefundResponse {
    pub gateway_response: FiservcommercehubGatewayResponseBody,
}

impl
    TryFrom<
        ResponseRouterData<
            FiservcommercehubRefundResponse,
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    > for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            FiservcommercehubRefundResponse,
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let refund_status = RefundStatus::from(&item.response.gateway_response.transaction_state);
        let txn = &item
            .response
            .gateway_response
            .transaction_processing_details;
        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: txn.transaction_id.clone(),
                refund_status,
                status_code: item.http_code,
            }),
            resource_common_data: RefundFlowData {
                status: refund_status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

// =============================================================================
// RSYNC FLOW (Refund Sync)
// =============================================================================

/// Request body for `POST /payments/v1/transaction-inquiry` for refund sync.
/// Uses the same structure as PSync - queries by connector's transaction ID.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservcommercehubRSyncRequest {
    pub merchant_details: FiservcommercehubPSyncMerchantDetails,
    pub reference_transaction_details: FiservcommercehubReferenceTransactionDetails,
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        super::FiservcommercehubRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    > for FiservcommercehubRSyncRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: super::FiservcommercehubRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = item.router_data;
        let auth = FiservcommercehubAuthType::try_from(&router_data.connector_auth_type)?;
        // Use connector_refund_id which is the connector's refund transaction ID
        Ok(Self {
            merchant_details: FiservcommercehubPSyncMerchantDetails {
                merchant_id: auth.merchant_id.clone(),
            },
            reference_transaction_details: FiservcommercehubReferenceTransactionDetails {
                reference_transaction_id: router_data.request.connector_refund_id.clone(),
            },
        })
    }
}

/// Gateway response for RSync - contains refund transaction state and processing details.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservcommercehubRSyncGatewayResponse {
    pub transaction_state: FiservcommercehubTransactionState,
    pub transaction_processing_details: Option<FiservcommercehubRSyncTxnDetails>,
}

/// Transaction processing details in RSync response.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservcommercehubRSyncTxnDetails {
    pub transaction_id: String,
    pub order_id: Option<String>,
}

/// Item in the RSync response array.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservcommercehubRSyncItem {
    pub gateway_response: FiservcommercehubRSyncGatewayResponse,
}

/// The transaction-inquiry endpoint returns an array of transaction objects.
#[derive(Debug, Deserialize, Serialize)]
pub struct FiservcommercehubRSyncResponse(pub Vec<FiservcommercehubRSyncItem>);

impl
    TryFrom<
        ResponseRouterData<
            FiservcommercehubRSyncResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    > for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            FiservcommercehubRSyncResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let rsync_item = item.response.0.into_iter().next().ok_or_else(|| {
            error_stack::report!(errors::ConnectorError::ResponseDeserializationFailed)
        })?;
        let refund_status = RefundStatus::from(&rsync_item.gateway_response.transaction_state);
        // Get transaction_id from gateway_response.transaction_processing_details
        // Fall back to connector_refund_id from the request if not present
        let connector_refund_id = rsync_item
            .gateway_response
            .transaction_processing_details
            .map(|d| d.transaction_id)
            .unwrap_or_else(|| item.router_data.request.connector_refund_id.clone());
        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id,
                refund_status,
                status_code: item.http_code,
            }),
            resource_common_data: RefundFlowData {
                status: refund_status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

// =============================================================================
// VOID FLOW
// =============================================================================

/// Request body for `POST /payments/v1/cancels`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservcommercehubVoidRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<FiservcommercehubAuthorizeAmount>,
    pub transaction_details: FiservcommercehubRefundTransactionDetails,
    pub merchant_details: FiservcommercehubMerchantDetails,
    pub reference_transaction_details: FiservcommercehubReferenceTransactionDetails,
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        super::FiservcommercehubRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    > for FiservcommercehubVoidRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: super::FiservcommercehubRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = item.router_data;
        let auth = FiservcommercehubAuthType::try_from(&router_data.connector_auth_type)?;

        let amount = match (router_data.request.amount, router_data.request.currency) {
            (Some(minor_amount), Some(currency)) => {
                let total =
                    utils::convert_amount(item.connector.amount_converter, minor_amount, currency)?;
                Some(FiservcommercehubAuthorizeAmount {
                    currency: currency.to_string(),
                    total,
                })
            }
            _ => None,
        };

        Ok(Self {
            amount,
            transaction_details: FiservcommercehubRefundTransactionDetails {
                capture_flag: true,
                merchant_transaction_id: router_data
                    .resource_common_data
                    .connector_request_reference_id
                    .clone(),
            },
            merchant_details: FiservcommercehubMerchantDetails {
                merchant_id: auth.merchant_id.clone(),
                terminal_id: auth.terminal_id.clone(),
            },
            reference_transaction_details: FiservcommercehubReferenceTransactionDetails {
                reference_transaction_id: router_data.request.connector_transaction_id.clone(),
            },
        })
    }
}

/// Response body from `POST /payments/v1/cancels`.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservcommercehubVoidResponse {
    pub gateway_response: FiservcommercehubGatewayResponseBody,
}

impl
    TryFrom<
        ResponseRouterData<
            FiservcommercehubVoidResponse,
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        >,
    > for RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            FiservcommercehubVoidResponse,
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let status = AttemptStatus::from(&item.response.gateway_response.transaction_state);
        let txn = &item
            .response
            .gateway_response
            .transaction_processing_details;
        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(txn.transaction_id.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: txn.order_id.clone(),
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

// =============================================================================
// ACCESS TOKEN FLOW
// =============================================================================

/// Merchant identification details required for the key-generation request body.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservcommercehubMerchantDetails {
    pub merchant_id: Secret<String>,
    pub terminal_id: Secret<String>,
}

/// Request body for `POST /security/v1/keys/generate`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservcommercehubAccessTokenRequest {
    pub merchant_details: FiservcommercehubMerchantDetails,
}

impl TryFrom<&ConnectorSpecificAuth> for FiservcommercehubAccessTokenRequest {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorSpecificAuth) -> Result<Self, Self::Error> {
        let auth = FiservcommercehubAuthType::try_from(auth_type)?;
        Ok(Self {
            merchant_details: FiservcommercehubMerchantDetails {
                merchant_id: auth.merchant_id.clone(),
                terminal_id: auth.terminal_id.clone(),
            },
        })
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        super::FiservcommercehubRouterData<
            RouterDataV2<
                CreateAccessToken,
                PaymentFlowData,
                AccessTokenRequestData,
                AccessTokenResponseData,
            >,
            T,
        >,
    > for FiservcommercehubAccessTokenRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: super::FiservcommercehubRouterData<
            RouterDataV2<
                CreateAccessToken,
                PaymentFlowData,
                AccessTokenRequestData,
                AccessTokenResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Self::try_from(&item.router_data.connector_auth_type)
    }
}

/// Response body from `POST /security/v1/keys/generate`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservcommercehubTransactionProcessingDetails {
    pub api_key: Secret<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservcommercehubGatewayResponse {
    pub transaction_processing_details: FiservcommercehubTransactionProcessingDetails,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservcommercehubAsymmetricKeyDetails {
    pub key_id: String,
    /// Base64-encoded RSA public key in SubjectPublicKeyInfo (SPKI/DER) format
    pub encoded_public_key: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservcommercehubAccessTokenResponse {
    pub gateway_response: FiservcommercehubGatewayResponse,
    pub asymmetric_key_details: FiservcommercehubAsymmetricKeyDetails,
}

impl<F, T> TryFrom<ResponseRouterData<FiservcommercehubAccessTokenResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, T, AccessTokenResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<FiservcommercehubAccessTokenResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let key_id = &item.response.asymmetric_key_details.key_id;
        let encoded_public_key = &item.response.asymmetric_key_details.encoded_public_key;
        // Store as: "{keyId}|||{encodedPublicKey}"
        // Using ||| as delimiter since it won't appear in Base64 or keyId
        // The encodedPublicKey is Base64-encoded RSA public key in SPKI/DER format
        let combined_token = Secret::new(format!("{key_id}|||{encoded_public_key}"));
        Ok(Self {
            response: Ok(AccessTokenResponseData {
                access_token: combined_token,
                expires_in: None,
                token_type: None,
            }),
            ..item.router_data
        })
    }
}
