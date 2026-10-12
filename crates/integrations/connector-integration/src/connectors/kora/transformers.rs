use common_enums::{enums, AttemptStatus, RefundStatus};
use common_utils::{
    pii,
    request::Method,
    types::{FloatMajorUnit, StringMajorUnit},
};
type SecretSerdeValue = pii::SecretSerdeValue;
use domain_types::{
    connector_types::{
        PaymentFlowData, PaymentsAuthenticateData, PaymentsAuthorizeData, PaymentsResponseData,
        PaymentsSyncData, RawConnectorStatus, RefundFlowData, RefundSyncData, RefundsData,
        RefundsResponseData, ResponseId,
    },
    errors::{ConnectorError, IntegrationError},
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes},
    router_data::{ConnectorSpecificConfig, ErrorResponse, FlowStatus},
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
    utils::is_payment_failure,
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, PeekInterface, Secret};
use ring::aead::{self, LessSafeKey, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::types::ResponseRouterData;

use super::KoraRouterData;

// ============================================================
// Auth
// ============================================================

/// Kora (Korapay) authentication — a single merchant secret key used as a
/// Bearer token (`Authorization: Bearer sk_live_...`), plus the encryption
/// key used to AES-256-GCM encrypt direct card charge payloads.
pub struct KoraAuthType {
    pub(super) secret_key: Secret<String>,
    #[allow(dead_code)] // kept for parity with the config; encryption reads the key off router_data
    pub(super) encryption_key: Secret<String>,
}

impl TryFrom<&ConnectorSpecificConfig> for KoraAuthType {
    type Error = error_stack::Report<IntegrationError>;
    fn try_from(auth_type: &ConnectorSpecificConfig) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorSpecificConfig::Kora {
                secret_key,
                encryption_key,
                ..
            } => Ok(Self {
                secret_key: secret_key.to_owned(),
                encryption_key: encryption_key.to_owned(),
            }),
            _ => Err(IntegrationError::FailedToObtainAuthType {
                context: Default::default(),
            }
            .into()),
        }
    }
}

// ============================================================
// Direct card charge: encryption + request
// ============================================================

/// Encrypts the charge payload with AES-256-GCM using the merchant's Kora
/// encryption key, returning Kora's `ivHex:cipherTextHex:authTagHex` format.
///
/// Kora's docs say "random 16-byte IV"; GCM's standard nonce is 12 bytes and
/// Kora's own Node.js sample (`crypto.createCipheriv('aes-256-gcm', ...)`)
/// accepts both. We use the 12-byte GCM standard via `ring`.
fn encrypt_charge_data(
    encryption_key: &Secret<String>,
    payload: &str,
) -> Result<String, error_stack::Report<IntegrationError>> {
    let exposed_key = encryption_key.clone().expose();
    let key_bytes = exposed_key.as_bytes();
    let unbound_key = UnboundKey::new(&aead::AES_256_GCM, key_bytes).map_err(|_| {
        IntegrationError::RequestEncodingFailed {
            context: domain_types::errors::IntegrationErrorContext {
                suggested_action: Some(
                    "Kora encryption key must be exactly 32 bytes for AES-256-GCM".to_string(),
                ),
                ..Default::default()
            },
        }
    })?;
    let key = LessSafeKey::new(unbound_key);

    let mut nonce_bytes = [0u8; aead::NONCE_LEN];
    SystemRandom::new()
        .fill(&mut nonce_bytes)
        .map_err(|_| IntegrationError::RequestEncodingFailed {
            context: Default::default(),
        })?;
    let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

    let mut in_out = payload.as_bytes().to_vec();
    key.seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut in_out)
        .map_err(|_| IntegrationError::RequestEncodingFailed {
            context: Default::default(),
        })?;

    // in_out = ciphertext || tag; split the trailing 16-byte GCM tag
    let ciphertext = &in_out[..in_out.len() - aead::AES_256_GCM.tag_len()];
    let tag = &in_out[in_out.len() - aead::AES_256_GCM.tag_len()..];

    Ok(format!(
        "{}:{}:{}",
        hex::encode(nonce_bytes),
        hex::encode(ciphertext),
        hex::encode(tag)
    ))
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct KoraCustomer {
    // Kora rejects explicit `null` ("name must be a string") but treats an
    // absent field as optional — skip the key entirely when there's no name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub email: pii::Email,
}

/// Card block of the plaintext charge payload (pre-encryption).
#[derive(Debug, Serialize)]
pub struct KoraCardPayloadCard {
    // Same as KoraCustomer.name: omit rather than send `null`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub number: String,
    pub cvv: String,
    pub expiry_month: String,
    pub expiry_year: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin: Option<String>,
}

/// Plaintext payload for `POST /charges/card`, encrypted before sending.
#[derive(Debug, Serialize)]
pub struct KoraCardChargePayload {
    pub reference: String,
    pub card: KoraCardPayloadCard,
    pub amount: FloatMajorUnit,
    pub currency: enums::Currency,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub customer: Option<KoraCustomer>,
}

/// The wire request actually sent to Kora — the encrypted payload.
#[derive(Debug, Serialize)]
pub struct KoraCardChargeRequest {
    pub charge_data: String,
}

/// Helper: read a string field off the request metadata (payu-style).
fn get_metadata_field(
    metadata: &Option<SecretSerdeValue>,
    field: &str,
) -> Option<String> {
    metadata
        .as_ref()
        .and_then(|m| m.peek().get(field))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        KoraRouterData<
            RouterDataV2<
                domain_types::connector_flow::Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for KoraCardChargeRequest
{
    type Error = error_stack::Report<IntegrationError>;
    fn try_from(
        item: KoraRouterData<
            RouterDataV2<
                domain_types::connector_flow::Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;

        // The direct card API only supports card payments.
        let card = match &router_data.request.payment_method_data {
            PaymentMethodData::Card(card) => card,
            _ => {
                return Err(IntegrationError::NotImplemented(
                    "Kora direct card API only supports card payments".to_string(),
                    Default::default(),
                )
                .into())
            }
        };

        let amount = item
            .connector
            .amount_converter
            .convert(
                router_data.request.minor_amount,
                router_data.request.currency,
            )
            .change_context(IntegrationError::RequestEncodingFailed {
                context: Default::default(),
            })?;

        // Kora wants 2-digit expiry values ("12" / "32").
        let exp_month = card.card_exp_month.clone().expose();
        let exp_year = card.card_exp_year.clone().expose();
        let expiry_month = normalize_two_digits(&exp_month)?;
        let expiry_year = normalize_two_digits(&exp_year)?;

        // Optional card PIN can ride in request metadata (`"kora_pin"`).
        let pin = get_metadata_field(&router_data.request.metadata, "kora_pin");

        let payload = KoraCardChargePayload {
            reference: router_data
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            card: KoraCardPayloadCard {
                name: card
                    .card_holder_name
                    .as_ref()
                    .map(|n| n.clone().expose()),
                number: card.card_number.peek().to_string(),
                cvv: card.card_cvc.clone().expose(),
                expiry_month,
                expiry_year,
                pin,
            },
            amount,
            currency: router_data.request.currency,
            // Used by Kora to send the customer back after a 3DS page.
            redirect_url: router_data.request.router_return_url.clone(),
            customer: router_data
                .request
                .email
                .clone()
                .map(|email| KoraCustomer {
                    name: router_data.request.customer_name.clone(),
                    email,
                }),
        };

        let payload_str = serde_json::to_string(&payload).map_err(|_| {
            IntegrationError::RequestEncodingFailed {
                context: Default::default(),
            }
        })?;

        // Read the encryption key off the connector config carried by the router data.
        let encryption_key = match &router_data.connector_config {
            ConnectorSpecificConfig::Kora {
                encryption_key, ..
            } => encryption_key.clone(),
            _ => {
                return Err(IntegrationError::FailedToObtainAuthType {
                    context: Default::default(),
                }
                .into())
            }
        };

        let charge_data = encrypt_charge_data(&encryption_key, &payload_str)?;

        Ok(Self { charge_data })
    }
}

/// Kora expects 2-digit expiry month/year. Euler sends what the merchant sent,
/// which may be 2 or 4 digit year, 1 or 2 digit month — normalize by taking
/// the last two digits.
fn normalize_two_digits(value: &str) -> Result<String, error_stack::Report<IntegrationError>> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(IntegrationError::MissingRequiredField {
            field_name: "card expiry",
            context: domain_types::errors::IntegrationErrorContext {
                additional_context: Some(format!("got empty expiry value: {value}")),
                ..Default::default()
            },
        }
        .into());
    }
    if trimmed.len() <= 2 {
        Ok(format!("{trimmed:0>2}"))
    } else {
        Ok(trimmed.chars().rev().take(2).collect::<Vec<_>>().into_iter().rev().collect())
    }
}

// ============================================================
// Authorize continuation (PIN / OTP / AVS / CARD_ENROLL)
// ============================================================

/// Request for `POST /charges/card/authorize` — completes a charge that
/// returned `status: processing` with an auth_model.
///
/// `transaction_reference` is the KPY-CA-... reference from the charge
/// response; `authorization` is a JSON object whose shape depends on the
/// auth model: `{"pin": "1234"}`, `{"otp": "123456"}`, `{"avs": {...}}`,
/// `{"phone": "..."}`. The caller passes it via request metadata under
/// the `kora_authorization` key.
#[derive(Debug, Serialize)]
pub struct KoraCardAuthorizeRequest {
    pub transaction_reference: String,
    pub authorization: serde_json::Value,
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        KoraRouterData<
            RouterDataV2<
                domain_types::connector_flow::Authenticate,
                PaymentFlowData,
                PaymentsAuthenticateData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for KoraCardAuthorizeRequest
{
    type Error = error_stack::Report<IntegrationError>;
    fn try_from(
        item: KoraRouterData<
            RouterDataV2<
                domain_types::connector_flow::Authenticate,
                PaymentFlowData,
                PaymentsAuthenticateData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;

        // The KPY-CA-... transaction reference from the original charge is
        // passed back as the flow's reference_id, falling back to
        // connector_request_reference_id (populated from merchant_order_id) —
        // the Authenticate proto conversion leaves reference_id None.
        let transaction_reference = router_data
            .resource_common_data
            .reference_id
            .clone()
            .filter(|r| !r.is_empty())
            .or_else(|| {
                let crid = router_data
                    .resource_common_data
                    .connector_request_reference_id
                    .clone();
                (!crid.is_empty()).then_some(crid)
            })
            .ok_or_else(|| IntegrationError::MissingRequiredField {
                field_name: "merchant_order_id",
                context: domain_types::errors::IntegrationErrorContext {
                    additional_context: Some(
                        "Pass the Kora transaction_reference (KPY-CA-...) returned by the charge"
                            .to_string(),
                    ),
                    suggested_action: Some(
                        "Set merchant_order_id to the KPY-CA reference when calling Authenticate"
                            .to_string(),
                    ),
                    ..Default::default()
                },
            })?;

        // The authorization object ({"pin": ...} / {"otp": ...} / {"avs": {...}})
        // is passed via request metadata under `kora_authorization`.
        let authorization = router_data
            .request
            .metadata
            .as_ref()
            .and_then(|m| m.peek().get("kora_authorization").cloned())
            .unwrap_or(serde_json::Value::Null);

        if authorization.is_null() {
            return Err(IntegrationError::MissingRequiredField {
                field_name: "metadata.kora_authorization",
                context: domain_types::errors::IntegrationErrorContext {
                    suggested_action: Some(
                        "Pass an auth factor to complete the charge, e.g. \
                         {\"otp\": \"123456\"}, {\"pin\": \"1234\"}, or {\"avs\": {...}}"
                            .to_string(),
                    ),
                    ..Default::default()
                },
            }
            .into());
        }

        Ok(Self {
            transaction_reference,
            authorization,
        })
    }
}

// ============================================================
// Payment response (direct card charge)
// ============================================================

#[derive(Default, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KoraChargeStatus {
    Success,
    Pending,
    Processing,
    Expired,
    #[default]
    Failed,
    #[serde(other)]
    Unknown,
}

impl From<KoraChargeStatus> for AttemptStatus {
    fn from(status: KoraChargeStatus) -> Self {
        match status {
            KoraChargeStatus::Success => AttemptStatus::Charged,
            KoraChargeStatus::Pending | KoraChargeStatus::Processing => AttemptStatus::Pending,
            KoraChargeStatus::Expired => AttemptStatus::Expired,
            KoraChargeStatus::Failed | KoraChargeStatus::Unknown => AttemptStatus::Failure,
        }
    }
}

/// Kora's auth_model on a `processing` charge: which extra step completes it.
#[derive(Default, Debug, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum KoraAuthModel {
    NoAuth,
    Pin,
    Otp,
    #[serde(rename = "3DS")]
    ThreeDS,
    Avs,
    CardEnroll,
    #[default]
    #[serde(other)]
    Unknown,
}

/// Extra authorization info on the charge response — for 3DS this carries the
/// redirect URL the customer must be sent to.
#[derive(Default, Debug, Serialize, Deserialize)]
pub struct KoraAuthorization {
    pub redirect_url: Option<Url>,
    #[serde(default)]
    pub required_fields: Option<Vec<String>>,
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct KoraCard {
    #[serde(default)]
    pub card_type: Option<String>,
    #[serde(default)]
    pub first_six: Option<String>,
    #[serde(default)]
    pub last_four: Option<String>,
    #[serde(default)]
    pub expiry: Option<String>,
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct KoraCardChargeResponseData {
    /// The merchant reference we sent (payment reference).
    pub payment_reference: Option<String>,
    /// Kora's per-attempt reference (KPY-CA-...).
    pub transaction_reference: Option<String>,
    pub status: Option<KoraChargeStatus>,
    pub auth_model: Option<KoraAuthModel>,
    pub amount: Option<FloatMajorUnit>,
    pub amount_charged: Option<FloatMajorUnit>,
    pub currency: Option<String>,
    pub response_message: Option<String>,
    /// Top-level redirect URL — 3DS charges return the secure-page URL here
    /// (NOT inside `authorization`, which stays null for 3DS).
    pub redirect_url: Option<String>,
    pub authorization: Option<KoraAuthorization>,
    /// Extra issuer metadata returned on the charge response — contains
    /// `gateway_code`, and sometimes a nested `card` block with
    /// first_six / last_four / expiry. Present on both charge_response
    /// and authorize responses.
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct KoraPaymentResponse {
    pub status: bool,
    pub message: String,
    pub data: Option<KoraCardChargeResponseData>,
    pub error: Option<String>,
}

/// Response for the authorize continuation (`/charges/card/authorize`) —
/// same shape as the charge response. Kept as a distinct type so the
/// connector macros can generate per-flow plumbing without name collisions.
#[derive(Default, Debug, Serialize, Deserialize)]
pub struct KoraCardAuthorizeResponse(pub KoraPaymentResponse);

impl<F, T> TryFrom<ResponseRouterData<KoraPaymentResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, T, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(item: ResponseRouterData<KoraPaymentResponse, Self>) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        // On success the charge references live in `data`.
        let data = response.data.unwrap_or_default();
        let connector_reference = data.payment_reference.clone();
        // The charge API returns a status on every response; `processing`
        // means an authorization step (PIN/OTP/3DS/AVS) is still pending.
        let status = data
            .status
            .map(KoraChargeStatus::into)
            .unwrap_or(AttemptStatus::Pending);

        // For 3DS charges, Kora returns the secure-page URL at the TOP LEVEL
        // of `data` (data.redirect_url); `authorization` stays null. After the
        // customer completes 3DS Kora returns them to our redirect_url.
        let redirection_data = data
            .redirect_url
            .clone()
            .or_else(|| {
                data.authorization
                    .as_ref()
                    .and_then(|auth| auth.redirect_url.clone())
                    .map(|url| url.to_string())
            })
            .and_then(|url_str| Url::parse(&url_str).ok())
            .map(|url| Box::new(RedirectForm::from((url, Method::Get))));

        let resource_id = connector_reference
            .clone()
            .map(ResponseId::ConnectorTransactionId)
            .unwrap_or(ResponseId::NoResponseId);

        let response = if response.status {
            Ok(PaymentsResponseData::TransactionResponse {
                resource_id,
                redirection_data,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                network_txn_link_id: None,
                connector_response_reference_id: connector_reference,
                incremental_authorization_allowed: None,
                status_code: http_code,
                splits: None,
            })
        } else {
            Err(ErrorResponse {
                status_code: http_code,
                code: response.error.clone().unwrap_or_else(|| "KORA_ERROR".to_string()),
                message: response.message.clone(),
                reason: Some(response.message),
                attempt_status: Some(FlowStatus::Payment(status)),
                connector_transaction_id: data.transaction_reference.clone(),
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
                typed_connector_response: None,
                raw_connector_response: None,
                raw_connector_request: None,
                typed_connector_request: None,
            })
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                // Euler's UCS layer derives respCode/respMessage from
                // raw_connector_status — Kora exposes the issuer's
                // gateway_code / stan / receipt in data.metadata.
                raw_connector_status: kora_raw_connector_status(&data.metadata),
                ..router_data.resource_common_data
            },
            response,
            ..router_data
        })
    }
}

impl<F, T: PaymentMethodDataTypes> TryFrom<ResponseRouterData<KoraCardAuthorizeResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsAuthenticateData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<KoraCardAuthorizeResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;
        let response = response.0;

        let data = response.data.unwrap_or_default();
        let connector_reference = data.payment_reference.clone();
        let status = data
            .status
            .map(KoraChargeStatus::into)
            .unwrap_or(AttemptStatus::Pending);

        let response = if response.status {
            // The grpc response generator for the Authenticate flow
            // (generate_payment_authenticate_response) only accepts
            // AuthenticateResponse; TransactionResponse is rejected.
            Ok(PaymentsResponseData::AuthenticateResponse {
                resource_id: connector_reference
                    .clone()
                    .map(ResponseId::ConnectorTransactionId),
                // For 3DS continuation Kora returns the redirect_url at the
                // top level of `data` (authorization stays null for 3DS)
                redirection_data: data
                    .redirect_url
                    .clone()
                    .or_else(|| {
                        data.authorization
                            .as_ref()
                            .and_then(|auth| auth.redirect_url.clone())
                            .map(|url| url.to_string())
                    })
                    .and_then(|url_str| Url::parse(&url_str).ok())
                    .map(|url| Box::new(RedirectForm::from((url, Method::Get)))),
                authentication_data: None,
                connector_feature_data: None,
                connector_response_reference_id: connector_reference,
                status_code: http_code,
            })
        } else {
            Err(ErrorResponse {
                status_code: http_code,
                code: response.error.clone().unwrap_or_else(|| "KORA_ERROR".to_string()),
                message: response.message.clone(),
                reason: Some(response.message),
                attempt_status: Some(FlowStatus::Payment(status)),
                connector_transaction_id: data.transaction_reference.clone(),
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
                typed_connector_response: None,
                raw_connector_response: None,
                raw_connector_request: None,
                typed_connector_request: None,
            })
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                raw_connector_status: kora_raw_connector_status(&data.metadata),
                ..router_data.resource_common_data
            },
            response,
            ..router_data
        })
    }
}

// ============================================================
// Payment sync (query charge by reference)
// ============================================================

/// Build a `RawConnectorStatus` from Kora's `metadata` block so Euler's UCS
/// layer can surface respCode/respMessage in payment_gateway_response.
/// Kora returns `metadata.gateway_code` (issuer response code, e.g. "00"),
/// `metadata.stan`, `metadata.receipt` and `metadata.support_message` on
/// charge/authorize responses.
fn kora_raw_connector_status(
    metadata: &Option<serde_json::Value>,
) -> Option<RawConnectorStatus> {
    let obj = metadata.as_ref()?.as_object()?;
    let code = obj
        .get("gateway_code")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let message = obj
        .get("support_message")
        .or_else(|| obj.get("response_message"))
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let reason = obj
        .get("receipt")
        .and_then(|v| v.as_str())
        .map(str::to_string);

    (code.is_some() || message.is_some()).then_some(RawConnectorStatus {
        code,
        message,
        reason,
    })
}

/// The Query Charge (`GET /charges/:reference`) response uses DIFFERENT field
/// names and types from the charge response: the reference is `data.reference`
/// (not `payment_reference`) and the amount is a string (`"100.00"`), not a
/// number. It therefore needs its own data shape.
#[derive(Default, Debug, Serialize, Deserialize)]
pub struct KoraPaymentSyncResponseData {
    pub reference: Option<String>,
    pub status: Option<KoraChargeStatus>,
    pub amount: Option<StringMajorUnit>,
    pub amount_paid: Option<StringMajorUnit>,
    pub currency: Option<String>,
    pub transaction_date: Option<String>,
    /// Issuer metadata (gateway_code etc.) when present.
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct KoraPaymentSyncResponse {
    pub status: bool,
    pub message: String,
    pub data: Option<KoraPaymentSyncResponseData>,
    pub error: Option<String>,
}

impl<F> TryFrom<ResponseRouterData<KoraPaymentSyncResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<KoraPaymentSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let data = response.data.unwrap_or_default();
        // Query Charge looks up by the payment reference (the merchant
        // reference we sent at charge time) and echoes it back as `reference`.
        let connector_reference = data.reference.clone();
        // A charge still awaiting authorization (`processing`) returns a
        // non-terminal status; null status maps to Pending, not Failure.
        let status: AttemptStatus = data
            .status
            .map(KoraChargeStatus::into)
            .unwrap_or(AttemptStatus::Pending);

        let response = if !response.status || is_payment_failure(status) {
            Err(ErrorResponse {
                status_code: http_code,
                code: response.error.unwrap_or_else(|| "KORA_ERROR".to_string()),
                message: response.message.clone(),
                reason: Some(response.message),
                attempt_status: Some(FlowStatus::Payment(status)),
                connector_transaction_id: connector_reference.clone(),
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
                typed_connector_response: None,
                raw_connector_response: None,
                raw_connector_request: None,
                typed_connector_request: None,
            })
        } else {
            Ok(PaymentsResponseData::TransactionResponse {
                resource_id: connector_reference
                    .clone()
                    .map(ResponseId::ConnectorTransactionId)
                    .unwrap_or(ResponseId::NoResponseId),
                // The query-charge response carries no authorization object;
                // redirection is only set on charge/authorize responses.
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                network_txn_link_id: None,
                connector_response_reference_id: connector_reference,
                incremental_authorization_allowed: None,
                status_code: http_code,
                splits: None,
            })
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                raw_connector_status: kora_raw_connector_status(&data.metadata),
                ..router_data.resource_common_data
            },
            response,
            ..router_data
        })
    }
}

// ============================================================
// Refund request
// ============================================================

#[derive(Debug, Serialize)]
pub struct KoraRefundRequest {
    pub amount: FloatMajorUnit,
    pub payment_reference: String,
    pub reference: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook_url: Option<String>,
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        KoraRouterData<
            RouterDataV2<
                domain_types::connector_flow::Refund,
                RefundFlowData,
                RefundsData,
                RefundsResponseData,
            >,
            T,
        >,
    > for KoraRefundRequest
{
    type Error = error_stack::Report<IntegrationError>;
    fn try_from(
        item: KoraRouterData<
            RouterDataV2<
                domain_types::connector_flow::Refund,
                RefundFlowData,
                RefundsData,
                RefundsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let amount = item
            .connector
            .amount_converter
            .convert(
                router_data.request.minor_refund_amount,
                router_data.request.currency,
            )
            .change_context(IntegrationError::RequestEncodingFailed {
                context: Default::default(),
            })?;

        Ok(Self {
            amount,
            payment_reference: router_data.request.connector_transaction_id.clone(),
            reference: router_data.request.refund_id.clone(),
            reason: router_data.request.reason.clone(),
            webhook_url: router_data.request.webhook_url.clone(),
        })
    }
}

// ============================================================
// Refund response
// ============================================================

#[derive(Default, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KoraRefundStatus {
    Success,
    Pending,
    Processing,
    Reversed,
    #[default]
    Failed,
    #[serde(other)]
    Unknown,
}

impl From<KoraRefundStatus> for RefundStatus {
    fn from(status: KoraRefundStatus) -> Self {
        match status {
            KoraRefundStatus::Success => RefundStatus::Success,
            KoraRefundStatus::Pending
            | KoraRefundStatus::Processing
            | KoraRefundStatus::Unknown => RefundStatus::Pending,
            KoraRefundStatus::Failed | KoraRefundStatus::Reversed => RefundStatus::Failure,
        }
    }
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct KoraRefundResponseData {
    pub refund_reference: Option<String>,
    pub status: Option<KoraRefundStatus>,
    pub payment_reference: Option<String>,
    // Kora returns `amount_returned` as a JSON number (e.g. `100`), not a
    // string — use FloatMajorUnit so deserialization succeeds.
    pub amount_returned: Option<FloatMajorUnit>,
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct KoraRefundResponse {
    pub status: bool,
    pub message: String,
    pub data: Option<KoraRefundResponseData>,
    pub error: Option<String>,
    // Kora's error responses carry a `code` (e.g. "AA026") instead of `error`.
    #[serde(default)]
    pub code: Option<String>,
}

impl<F> TryFrom<ResponseRouterData<KoraRefundResponse, Self>>
    for RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(item: ResponseRouterData<KoraRefundResponse, Self>) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let data = response.data.unwrap_or_default();
        let refund_status: RefundStatus = data.status.unwrap_or_default().into();
        let connector_refund_id = data
            .refund_reference
            .clone()
            .unwrap_or_else(|| router_data.request.refund_id.clone());

        let response = if !response.status || matches!(refund_status, RefundStatus::Failure) {
            Err(ErrorResponse {
                status_code: http_code,
                code: response
                    .error
                    .or(response.code)
                    .unwrap_or_else(|| "KORA_ERROR".to_string()),
                message: response.message.clone(),
                reason: Some(response.message),
                attempt_status: None,
                connector_transaction_id: Some(connector_refund_id.clone()),
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
                typed_connector_response: None,
                raw_connector_response: None,
                raw_connector_request: None,
                typed_connector_request: None,
            })
        } else {
            Ok(RefundsResponseData {
                connector_refund_id,
                refund_status,
                status_code: http_code,
                acquirer_reference_number: None,
            })
        };

        Ok(Self {
            response,
            ..router_data
        })
    }
}

// ============================================================
// Refund sync (get refund by reference)
// ============================================================

// The retrieve-refund (`GET /refunds/:reference`) response uses DIFFERENT field
// names from the initiate-refund response: the reference is `data.reference`
// (not `refund_reference`) and the amount is `data.amount` as a string (not
// `amount_returned` as a number). It therefore needs its own data shape rather
// than reusing `KoraRefundResponse`.
#[derive(Default, Debug, Serialize, Deserialize)]
pub struct KoraRefundSyncResponseData {
    pub reference: Option<String>,
    pub status: Option<KoraRefundStatus>,
    pub payment_reference: Option<String>,
    pub amount: Option<StringMajorUnit>,
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct KoraRefundSyncResponse {
    pub status: bool,
    pub message: String,
    pub data: Option<KoraRefundSyncResponseData>,
    pub error: Option<String>,
    #[serde(default)]
    pub code: Option<String>,
}

impl<F> TryFrom<ResponseRouterData<KoraRefundSyncResponse, Self>>
    for RouterDataV2<F, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<KoraRefundSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let data = response.data.unwrap_or_default();
        let refund_status: RefundStatus = data.status.unwrap_or_default().into();
        let connector_refund_id = data
            .reference
            .clone()
            .unwrap_or_else(|| router_data.request.connector_refund_id.clone());

        let response = if !response.status || matches!(refund_status, RefundStatus::Failure) {
            Err(ErrorResponse {
                status_code: http_code,
                code: response
                    .error
                    .or(response.code)
                    .unwrap_or_else(|| "KORA_ERROR".to_string()),
                message: response.message.clone(),
                reason: Some(response.message),
                attempt_status: None,
                connector_transaction_id: Some(connector_refund_id.clone()),
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
                typed_connector_response: None,
                raw_connector_response: None,
                raw_connector_request: None,
                typed_connector_request: None,
            })
        } else {
            Ok(RefundsResponseData {
                connector_refund_id,
                refund_status,
                status_code: http_code,
                acquirer_reference_number: None,
            })
        };

        Ok(Self {
            response,
            ..router_data
        })
    }
}

// ============================================================
// Error response (for build_error_response on non-2xx)
// ============================================================

#[derive(Default, Debug, Deserialize, Serialize)]
pub struct KoraErrorResponse {
    pub status: bool,
    pub message: String,
    pub error: Option<String>,
    pub data: Option<serde_json::Value>,
}

impl KoraErrorResponse {
    pub fn error_code(&self) -> String {
        self.error
            .clone()
            .unwrap_or_else(|| "KORA_ERROR".to_string())
    }
}
