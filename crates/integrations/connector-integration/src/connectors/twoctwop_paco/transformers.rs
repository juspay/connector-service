use std::collections::HashMap;

use common_enums::{AttemptStatus, Currency, RefundStatus};
use common_utils::{
    consts::{NO_ERROR_CODE, NO_ERROR_MESSAGE},
    crypto::jose::JoseConfig,
    request::Method,
    types::MinorUnit,
};
use domain_types::{
    connector_flow::{
        Authenticate, Authorize, Capture, PSync, PostAuthenticate, PreAuthenticate, RSync, Refund,
        Void,
    },
    connector_types::{
        PaymentFlowData, PaymentVoidData, PaymentsAuthenticateData, PaymentsAuthorizeData,
        PaymentsCaptureData, PaymentsPostAuthenticateData, PaymentsPreAuthenticateData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData,
        RefundsResponseData, ResponseId,
    },
    errors,
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes, WalletData},
    router_data::{ConnectorSpecificConfig, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_request_types::AuthenticationData,
    router_response_types::RedirectForm,
};
use hyperswitch_masking::{PeekInterface, Secret};
use serde::{Deserialize, Serialize};

use crate::types::ResponseRouterData;

const PACO_LANGUAGE: &str = "en-US";
const PACO_PAYMENT_TYPE_CC: &str = "CC";
const PACO_CARD_TYPE_CREDIT: &str = "credit";
const PACO_CARD_TYPE_DEBIT: &str = "debit";
const PACO_PAYMENT_CATEGORY_ECOM: &str = "ECOM";
const PACO_PREFERRED_PAYMENT_TYPE_GCASH: &str = "WALLET-GCASH";
const PACO_REFUND_MAKER_ID: &str = "merchant";
const PACO_KID_HEX_LEN: usize = 32;
const PACO_OFFICE_ID_MAX_LEN: usize = 20;

/// PACO finalised-status response code prefix used by every successful response.
pub const PACO_RESPONSE_CODE_SUCCESS: &str = "PC-B050000";

/// Strongly-typed PACO authentication bundle. Built by validating the
/// `ConnectorSpecificConfig::TwoctwopPaco` variant once per request.
#[derive(Debug, Clone)]
pub struct TwoctwopPacoAuthType {
    pub access_token: Secret<String>,
    pub office_id: Secret<String>,
    pub merchant_id: Secret<String>,
    pub jose_cfg: JoseConfig,
}

impl TryFrom<&ConnectorSpecificConfig> for TwoctwopPacoAuthType {
    type Error = error_stack::Report<errors::IntegrationError>;

    fn try_from(value: &ConnectorSpecificConfig) -> Result<Self, Self::Error> {
        match value {
            ConnectorSpecificConfig::TwoctwopPaco {
                access_token,
                office_id,
                merchant_id,
                paco_kid,
                merchant_signing_private_key,
                merchant_encryption_private_key,
                paco_signing_public_key,
                paco_encryption_public_key,
                base_url: _,
            } => {
                let kid = paco_kid.peek().clone();
                if kid.len() != PACO_KID_HEX_LEN || !kid.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err(errors::IntegrationError::InvalidDataFormat {
                        field_name: "paco_kid",
                        context: errors::IntegrationErrorContext {
                            suggested_action: Some(
                                "Provide a 32-character lowercase hex string for paco_kid."
                                    .to_string(),
                            ),
                            doc_url: None,
                            additional_context: Some(
                                "paco_kid must be exactly 32 hexadecimal characters.".to_string(),
                            ),
                        },
                    }
                    .into());
                }

                let office = office_id.peek();
                if office.is_empty() || office.len() > PACO_OFFICE_ID_MAX_LEN {
                    return Err(errors::IntegrationError::InvalidDataFormat {
                        field_name: "office_id",
                        context: errors::IntegrationErrorContext {
                            suggested_action: Some(
                                "office_id must be 1..=20 characters.".to_string(),
                            ),
                            doc_url: None,
                            additional_context: None,
                        },
                    }
                    .into());
                }

                let jose_cfg = JoseConfig::new(
                    kid,
                    merchant_signing_private_key.clone(),
                    merchant_encryption_private_key.clone(),
                    paco_signing_public_key.clone(),
                    paco_encryption_public_key.clone(),
                )
                .map_err(|err| {
                    errors::IntegrationError::FailedToObtainAuthType {
                        context: errors::IntegrationErrorContext {
                            suggested_action: Some(
                                "Verify the four PEMs supplied for the PACO connector parse with OpenSSL."
                                    .to_string(),
                            ),
                            doc_url: None,
                            additional_context: Some(format!("JoseConfig validation failed: {err}")),
                        },
                    }
                })?;

                Ok(Self {
                    access_token: access_token.clone(),
                    office_id: office_id.clone(),
                    merchant_id: merchant_id.clone(),
                    jose_cfg,
                })
            }
            _ => Err(errors::IntegrationError::FailedToObtainAuthType {
                context: errors::IntegrationErrorContext {
                    suggested_action: Some(
                        "Configure the connector with the TwoctwopPaco auth variant.".to_string(),
                    ),
                    doc_url: None,
                    additional_context: Some(
                        "Expected ConnectorSpecificConfig::TwoctwopPaco.".to_string(),
                    ),
                },
            }
            .into()),
        }
    }
}

// ---------- Common envelope shared by every JOSE request body ----------

#[derive(Debug, Clone, Serialize)]
pub struct ApiRequestEnvelope {
    /// PACO accepts only `requestMessageID` (capital ID) — serde's camelCase
    /// would emit `requestMessageId`, which fails server-side validation.
    #[serde(rename = "requestMessageID")]
    pub request_message_id: String,
    #[serde(rename = "requestDateTime")]
    pub request_date_time: String,
    pub language: &'static str,
}

impl ApiRequestEnvelope {
    fn new() -> Self {
        let now = time::OffsetDateTime::now_utc();
        let formatted = now
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| String::from("1970-01-01T00:00:00Z"));
        Self {
            request_message_id: uuid::Uuid::new_v4().to_string(),
            request_date_time: formatted,
            language: PACO_LANGUAGE,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PacoTransactionAmount {
    /// 12-digit zero-padded minor-unit string PACO uses for cross-checking.
    pub amount_text: String,
    pub currency_code: Currency,
    pub decimal_places: u8,
    /// Decimal-form amount (e.g. 100.00).
    pub amount: f64,
}

impl PacoTransactionAmount {
    fn new(minor_amount: MinorUnit, currency: Currency) -> Result<Self, errors::IntegrationError> {
        let decimals = currency
            .number_of_digits_after_decimal_point()
            .map_err(|_| errors::IntegrationError::InvalidDataFormat {
                field_name: "currency",
                context: errors::IntegrationErrorContext {
                    suggested_action: None,
                    doc_url: None,
                    additional_context: Some(format!(
                        "Currency {currency:?} not supported for amount conversion"
                    )),
                },
            })?;
        let raw = minor_amount.get_amount_as_i64();
        let amount_text = format!("{raw:0>12}");
        let amount_decimal = currency
            .to_currency_base_unit_asf64(raw)
            .map_err(|_| errors::IntegrationError::InvalidDataFormat {
                field_name: "amount",
                context: errors::IntegrationErrorContext {
                    suggested_action: None,
                    doc_url: None,
                    additional_context: Some(
                        "Failed to convert minor amount to base currency unit".to_string(),
                    ),
                },
            })?;
        Ok(Self {
            amount_text,
            currency_code: currency,
            decimal_places: decimals,
            amount: amount_decimal,
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PacoNotificationUrls {
    /// PACO field names suffix `URL` (capitalised) — serde's camelCase
    /// would emit `confirmationUrl`, which fails server-side validation.
    #[serde(rename = "confirmationURL", skip_serializing_if = "Option::is_none")]
    pub confirmation_url: Option<String>,
    #[serde(rename = "failedURL", skip_serializing_if = "Option::is_none")]
    pub failed_url: Option<String>,
    #[serde(rename = "cancellationURL", skip_serializing_if = "Option::is_none")]
    pub cancellation_url: Option<String>,
    #[serde(rename = "backendURL", skip_serializing_if = "Option::is_none")]
    pub backend_url: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PacoCreditCardDetails {
    pub card_number: Secret<String>,
    /// PACO expects `cardExpiryMMYY` — serde camelCase would emit
    /// `cardExpiryMmyy`, which fails server-side validation.
    #[serde(rename = "cardExpiryMMYY")]
    pub card_expiry_mmyy: Secret<String>,
    pub cvv_code: Secret<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card_holder_name: Option<Secret<String>>,
    pub card_type: &'static str,
}

// ---------- /Payment/nonUi (Card S2S) ----------

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TwoctwopPacoCardAuthorizeRequest {
    pub api_request: ApiRequestEnvelope,
    pub office_id: Secret<String>,
    pub order_no: String,
    pub product_description: String,
    pub payment_type: &'static str,
    pub transaction_amount: PacoTransactionAmount,
    /// PACO expects the plural-with-capitals form `notificationURLs`.
    #[serde(rename = "notificationURLs")]
    pub notification_urls: PacoNotificationUrls,
    pub credit_card_details: PacoCreditCardDetails,
    /// "Y" / "N" — card-level 3DS toggle.
    #[serde(rename = "request3dsFlag")]
    pub request3ds_flag: &'static str,
}

// ---------- /Payment/prepaymentUi (GCash hosted) ----------

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TwoctwopPacoWalletAuthorizeRequest {
    pub api_request: ApiRequestEnvelope,
    pub office_id: Secret<String>,
    pub order_no: String,
    pub product_description: String,
    pub payment_category: &'static str,
    pub transaction_amount: PacoTransactionAmount,
    #[serde(rename = "notificationURLs")]
    pub notification_urls: PacoNotificationUrls,
    pub preferred_payment_types: Vec<&'static str>,
}

/// Discriminator returned by the request builder so the connector module knows
/// which PACO endpoint to POST to without re-inspecting the payment-method-data.
#[derive(Debug, Clone)]
pub enum AuthorizeRoute {
    CardNonUi,
    WalletPrepaymentUi,
}

#[derive(Debug, Clone)]
pub struct AuthorizeRequest {
    pub route: AuthorizeRoute,
    pub body: serde_json::Value,
}

pub fn build_authorize_request<T>(
    item: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    auth: &TwoctwopPacoAuthType,
) -> Result<AuthorizeRequest, error_stack::Report<errors::IntegrationError>>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize,
{
    let order_no = item.resource_common_data.connector_request_reference_id.clone();
    let description = item
        .resource_common_data
        .description
        .clone()
        .unwrap_or_else(|| order_no.clone());
    let amount = PacoTransactionAmount::new(item.request.minor_amount, item.request.currency)?;
    let notification_urls = PacoNotificationUrls {
        confirmation_url: item.request.router_return_url.clone(),
        failed_url: item.request.router_return_url.clone(),
        cancellation_url: item.request.router_return_url.clone(),
        backend_url: item.request.webhook_url.clone(),
    };

    match &item.request.payment_method_data {
        PaymentMethodData::Card(card) => {
            let card_type = match card.card_type.as_deref() {
                Some(t) if t.eq_ignore_ascii_case("debit") => PACO_CARD_TYPE_DEBIT,
                _ => PACO_CARD_TYPE_CREDIT,
            };
            let mmyy = card.get_card_expiry_month_year_2_digit_with_delimiter(String::new())?;
            let request3ds_flag = if item.request.enrolled_for_3ds.unwrap_or(false) {
                "Y"
            } else {
                "N"
            };
            let body = TwoctwopPacoCardAuthorizeRequest {
                api_request: ApiRequestEnvelope::new(),
                office_id: auth.office_id.clone(),
                order_no,
                product_description: description,
                payment_type: PACO_PAYMENT_TYPE_CC,
                transaction_amount: amount,
                notification_urls,
                credit_card_details: PacoCreditCardDetails {
                    card_number: Secret::new(card.card_number.peek().to_string()),
                    card_expiry_mmyy: mmyy,
                    cvv_code: card.card_cvc.clone(),
                    card_holder_name: card.get_optional_cardholder_name(),
                    card_type,
                },
                request3ds_flag,
            };
            Ok(AuthorizeRequest {
                route: AuthorizeRoute::CardNonUi,
                body: serde_json::to_value(&body).map_err(|_| {
                    errors::IntegrationError::InvalidDataFormat {
                        field_name: "twoctwop_paco card body",
                        context: errors::IntegrationErrorContext::default(),
                    }
                })?,
            })
        }
        PaymentMethodData::Wallet(WalletData::GcashRedirect(_)) => {
            let body = TwoctwopPacoWalletAuthorizeRequest {
                api_request: ApiRequestEnvelope::new(),
                office_id: auth.office_id.clone(),
                order_no,
                product_description: description,
                payment_category: PACO_PAYMENT_CATEGORY_ECOM,
                transaction_amount: amount,
                notification_urls,
                preferred_payment_types: vec![PACO_PREFERRED_PAYMENT_TYPE_GCASH],
            };
            Ok(AuthorizeRequest {
                route: AuthorizeRoute::WalletPrepaymentUi,
                body: serde_json::to_value(&body).map_err(|_| {
                    errors::IntegrationError::InvalidDataFormat {
                        field_name: "twoctwop_paco wallet body",
                        context: errors::IntegrationErrorContext::default(),
                    }
                })?,
            })
        }
        _ => Err(errors::IntegrationError::NotImplemented(
            "Selected payment method through TwoctwopPaco".to_string(),
            errors::IntegrationErrorContext::default(),
        )
        .into()),
    }
}

// ---------- /Payment/nonUi (Authenticate — same body as Authorize, request3dsFlag forced "Y") ----------

pub fn build_authenticate_request<T>(
    item: &RouterDataV2<
        Authenticate,
        PaymentFlowData,
        PaymentsAuthenticateData<T>,
        PaymentsResponseData,
    >,
    auth: &TwoctwopPacoAuthType,
) -> Result<TwoctwopPacoCardAuthorizeRequest, error_stack::Report<errors::IntegrationError>>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize,
{
    let order_no = item
        .resource_common_data
        .connector_request_reference_id
        .clone();
    let description = item
        .resource_common_data
        .description
        .clone()
        .unwrap_or_else(|| order_no.clone());
    let currency = item
        .request
        .currency
        .ok_or(errors::IntegrationError::MissingRequiredField {
            field_name: "currency",
            context: errors::IntegrationErrorContext::default(),
        })?;
    let amount = PacoTransactionAmount::new(item.request.amount, currency)?;
    let notification_urls = PacoNotificationUrls {
        confirmation_url: item.request.router_return_url.as_ref().map(|u| u.to_string()),
        failed_url: item.request.router_return_url.as_ref().map(|u| u.to_string()),
        cancellation_url: item.request.router_return_url.as_ref().map(|u| u.to_string()),
        backend_url: item
            .request
            .continue_redirection_url
            .as_ref()
            .map(|u| u.to_string()),
    };

    match item.request.payment_method_data.as_ref() {
        Some(PaymentMethodData::Card(card)) => {
            let card_type = match card.card_type.as_deref() {
                Some(t) if t.eq_ignore_ascii_case("debit") => PACO_CARD_TYPE_DEBIT,
                _ => PACO_CARD_TYPE_CREDIT,
            };
            let mmyy = card.get_card_expiry_month_year_2_digit_with_delimiter(String::new())?;
            Ok(TwoctwopPacoCardAuthorizeRequest {
                api_request: ApiRequestEnvelope::new(),
                office_id: auth.office_id.clone(),
                order_no,
                product_description: description,
                payment_type: PACO_PAYMENT_TYPE_CC,
                transaction_amount: amount,
                notification_urls,
                credit_card_details: PacoCreditCardDetails {
                    card_number: Secret::new(card.card_number.peek().to_string()),
                    card_expiry_mmyy: mmyy,
                    cvv_code: card.card_cvc.clone(),
                    card_holder_name: card.get_optional_cardholder_name(),
                    card_type,
                },
                // Authenticate is the explicit 3DS-enrolment leg, so always
                // request a 3DS challenge regardless of the upstream flag.
                request3ds_flag: "Y",
            })
        }
        _ => Err(errors::IntegrationError::NotImplemented(
            "Selected payment method through TwoctwopPaco Authenticate".to_string(),
            errors::IntegrationErrorContext::default(),
        )
        .into()),
    }
}

// ---------- Capture / Settle ----------

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PacoSettlementAmount {
    pub amount_text: String,
    pub currency_code: Currency,
    pub decimal_places: u8,
    pub amount: f64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TwoctwopPacoCaptureRequest {
    pub api_request: ApiRequestEnvelope,
    pub office_id: Secret<String>,
    pub order_no: String,
    /// PACO field is `invoiceNo2C2P` — serde camelCase would emit
    /// `invoiceNo2c2p`, which fails server-side validation.
    #[serde(rename = "invoiceNo2C2P")]
    pub invoice_no2c2p: String,
    pub settlement_amount: PacoSettlementAmount,
}

pub fn build_capture_request(
    item: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
    auth: &TwoctwopPacoAuthType,
) -> Result<TwoctwopPacoCaptureRequest, error_stack::Report<errors::IntegrationError>> {
    let invoice_no = item.request.get_connector_transaction_id()?;
    let amount =
        PacoTransactionAmount::new(item.request.minor_amount_to_capture, item.request.currency)?;
    Ok(TwoctwopPacoCaptureRequest {
        api_request: ApiRequestEnvelope::new(),
        office_id: auth.office_id.clone(),
        order_no: item
            .resource_common_data
            .connector_request_reference_id
            .clone(),
        invoice_no2c2p: invoice_no,
        settlement_amount: PacoSettlementAmount {
            amount_text: amount.amount_text,
            currency_code: amount.currency_code,
            decimal_places: amount.decimal_places,
            amount: amount.amount,
        },
    })
}

// ---------- Void ----------

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TwoctwopPacoVoidRequest {
    pub api_request: ApiRequestEnvelope,
    pub office_id: Secret<String>,
    pub order_no: String,
    /// PACO field is `invoiceNo2C2P` — serde camelCase would emit
    /// `invoiceNo2c2p`, which fails server-side validation.
    #[serde(rename = "invoiceNo2C2P")]
    pub invoice_no2c2p: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cancellation_reason: Option<String>,
}

pub fn build_void_request(
    item: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
    auth: &TwoctwopPacoAuthType,
) -> Result<TwoctwopPacoVoidRequest, error_stack::Report<errors::IntegrationError>> {
    Ok(TwoctwopPacoVoidRequest {
        api_request: ApiRequestEnvelope::new(),
        office_id: auth.office_id.clone(),
        order_no: item
            .resource_common_data
            .connector_request_reference_id
            .clone(),
        invoice_no2c2p: item.request.connector_transaction_id.clone(),
        cancellation_reason: item.request.cancellation_reason.clone(),
    })
}

// ---------- Refund ----------

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PacoRefundDetails {
    pub maker_id: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub refund_amount: PacoTransactionAmount,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TwoctwopPacoRefundRequest {
    pub api_request: ApiRequestEnvelope,
    pub office_id: Secret<String>,
    pub order_no: String,
    /// PACO field is `invoiceNo2C2P` — serde camelCase would emit
    /// `invoiceNo2c2p`, which fails server-side validation.
    #[serde(rename = "invoiceNo2C2P")]
    pub invoice_no2c2p: String,
    pub product_description: String,
    pub refund_details: PacoRefundDetails,
}

pub fn build_refund_request(
    item: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    auth: &TwoctwopPacoAuthType,
) -> Result<TwoctwopPacoRefundRequest, error_stack::Report<errors::IntegrationError>> {
    let amount =
        PacoTransactionAmount::new(item.request.minor_refund_amount, item.request.currency)?;
    Ok(TwoctwopPacoRefundRequest {
        api_request: ApiRequestEnvelope::new(),
        office_id: auth.office_id.clone(),
        order_no: item.request.refund_id.clone(),
        invoice_no2c2p: item.request.connector_transaction_id.clone(),
        product_description: item
            .request
            .reason
            .clone()
            .unwrap_or_else(|| item.request.refund_id.clone()),
        refund_details: PacoRefundDetails {
            maker_id: PACO_REFUND_MAKER_ID,
            reason: item.request.reason.clone(),
            refund_amount: amount,
        },
    })
}

// ---------- Status enums ----------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PacoPaymentStatus {
    /// Authorized.
    A,
    /// Settled / Charged.
    S,
    /// Voided.
    V,
    /// Refunded.
    R,
    /// Incomplete (3DS challenge in flight or pending).
    I,
    /// Pending.
    P,
    /// Payment Created, Page Generated (hosted-page wallet/redirect).
    #[serde(rename = "PCPS")]
    Pcps,
    /// Failure.
    F,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PacoPaymentStep {
    /// Pre-authorisation.
    PA,
    /// Settlement.
    ST,
    /// Voided.
    VD,
    /// Refunded.
    RF,
    /// Awaiting Challenge.
    AC,
    /// Initiated / Pending.
    IN,
    /// Pending refund.
    RP,
    /// Hosted page generated.
    GP,
    /// Pending Response from acquirer.
    PR,
    #[serde(other)]
    Unknown,
}

fn map_attempt_status(status: &PacoPaymentStatus, step: &PacoPaymentStep) -> AttemptStatus {
    match (status, step) {
        (PacoPaymentStatus::A, PacoPaymentStep::PA) => AttemptStatus::Authorized,
        (PacoPaymentStatus::S, PacoPaymentStep::ST) => AttemptStatus::Charged,
        (PacoPaymentStatus::V, PacoPaymentStep::VD) => AttemptStatus::Voided,
        (PacoPaymentStatus::R, PacoPaymentStep::RF) => AttemptStatus::Charged,
        (PacoPaymentStatus::I, PacoPaymentStep::AC) => AttemptStatus::AuthenticationPending,
        (PacoPaymentStatus::Pcps, PacoPaymentStep::GP) => AttemptStatus::AuthenticationPending,
        (PacoPaymentStatus::P, PacoPaymentStep::IN) => AttemptStatus::Authorizing,
        (PacoPaymentStatus::P, PacoPaymentStep::RP) => AttemptStatus::Pending,
        (PacoPaymentStatus::F, _) => AttemptStatus::Failure,
        _ => AttemptStatus::Pending,
    }
}

fn map_refund_status(status: &PacoPaymentStatus, step: &PacoPaymentStep) -> RefundStatus {
    match (status, step) {
        (PacoPaymentStatus::R, PacoPaymentStep::RF) => RefundStatus::Success,
        (PacoPaymentStatus::P, PacoPaymentStep::RP) => RefundStatus::Pending,
        (PacoPaymentStatus::F, _) => RefundStatus::Failure,
        _ => RefundStatus::Pending,
    }
}

// ---------- Generic JOSE response shape ----------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PacoApiResponse {
    pub response_code: Option<String>,
    pub response_description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PacoPaymentStatusInfo {
    pub payment_status: PacoPaymentStatus,
    pub payment_step: PacoPaymentStep,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PacoPriorPaymentResponseDetails {
    #[serde(default)]
    pub response_code: Option<String>,
    #[serde(default)]
    pub response_description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PacoPaymentPage {
    pub payment_page_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PacoPaymentResultBlock {
    #[serde(default, rename = "invoiceNo2C2P")]
    pub invoice_no2c2p: Option<String>,
    #[serde(default)]
    pub order_no: Option<String>,
    #[serde(default)]
    pub controller_internal_id: Option<String>,
    #[serde(default)]
    pub payment_status_info: Option<PacoPaymentStatusInfo>,
    #[serde(default)]
    pub prior_payment_response_details: Option<PacoPriorPaymentResponseDetails>,
    #[serde(default)]
    pub payment_page: Option<PacoPaymentPage>,
    #[serde(default)]
    pub payment_page_url: Option<String>,
    /// Present on /Payment/nonUi 3DS challenge responses
    /// (paymentStatus=I, paymentStep=AC).
    #[serde(default, rename = "aresACSChallenge")]
    pub ares_acs_challenge: Option<AresAcsChallenge>,
    /// Present on frictionless or post-challenge success responses with
    /// CAVV/ECI/3DS-version/etc.
    #[serde(default)]
    pub credit_card_authenticated_details: Option<PacoCreditCardAuthenticatedDetails>,
}

/// 3DS ACS challenge details returned by `/Payment/nonUi` when PACO needs the
/// cardholder to complete a CReq POST against the issuer's ACS.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AresAcsChallenge {
    #[serde(rename = "acsURL")]
    pub acs_url: String,
    pub creq: String,
    #[serde(rename = "threeDSSessionData")]
    pub three_ds_session_data: Option<String>,
    #[serde(rename = "authentication3DSVersion")]
    pub authentication_3ds_version: Option<String>,
    #[serde(rename = "challengeHTML")]
    pub challenge_html: Option<String>,
}

/// 3DS authentication artefacts returned by PACO once enrolment + challenge
/// have produced a CAVV / ECI / threeDS transaction id.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PacoCreditCardAuthenticatedDetails {
    pub cavv: Option<String>,
    #[serde(rename = "eciValue")]
    pub eci_value: Option<String>,
    #[serde(rename = "threeDsTransactionId")]
    pub three_ds_transaction_id: Option<String>,
    #[serde(rename = "authentication3DSVersion")]
    pub authentication_3ds_version: Option<String>,
    pub authentication_status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PacoData {
    #[serde(default)]
    pub payment_result: Option<PacoPaymentResultBlock>,
    #[serde(default)]
    pub payment_incomplete_result: Option<PacoPaymentResultBlock>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TwoctwopPacoNonUiResponse {
    #[serde(default)]
    pub data: Option<PacoData>,
    #[serde(default)]
    pub api_response: Option<PacoApiResponse>,
    #[serde(default)]
    pub version: Option<String>,
}

impl TwoctwopPacoNonUiResponse {
    /// PACO returns `paymentResult` once the transaction reaches a terminal
    /// step and `paymentIncompleteResult` while it is still in flight. Both
    /// blocks share the same shape; merge them into a single accessor so the
    /// caller does not have to repeat the fallback logic.
    pub fn merged_result(&self) -> Option<&PacoPaymentResultBlock> {
        self.data
            .as_ref()
            .and_then(|d| d.payment_result.as_ref().or(d.payment_incomplete_result.as_ref()))
    }
}

// ---------- Authorize response → RouterDataV2 ----------

impl<F, T>
    TryFrom<
        ResponseRouterData<
            TwoctwopPacoNonUiResponse,
            Self,
        >,
    > for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize,
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            TwoctwopPacoNonUiResponse,
            Self,
        >,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;
        let result = response.merged_result();
        let api_response = response.api_response.clone();

        let (status, redirection_data, connector_txn_id, connector_response_reference_id, prior) =
            match result {
                Some(block) => {
                    let info = block
                        .payment_status_info
                        .as_ref()
                        .ok_or_else(|| {
                            error_stack::report!(
                                errors::ConnectorError::response_deserialization_failed_with_context(
                                    http_code,
                                    Some(
                                        "twoctwop_paco: paymentStatusInfo missing on Authorize response"
                                            .to_string(),
                                    ),
                                )
                            )
                        })?;
                    let status = map_attempt_status(&info.payment_status, &info.payment_step);
                    let url = block
                        .payment_page
                        .as_ref()
                        .and_then(|p| p.payment_page_url.clone())
                        .or_else(|| block.payment_page_url.clone());
                    let redirection_data = url.map(|endpoint| {
                        Box::new(RedirectForm::Form {
                            endpoint,
                            method: Method::Get,
                            form_fields: HashMap::new(),
                        })
                    });
                    (
                        status,
                        redirection_data,
                        block.invoice_no2c2p.clone(),
                        block.order_no.clone(),
                        block.prior_payment_response_details.clone(),
                    )
                }
                None => (AttemptStatus::Pending, None, None, None, None),
            };

        if matches!(status, AttemptStatus::Failure) {
            let (code, message) = error_code_message(&api_response, &prior);
            let error = ErrorResponse {
                code,
                message: message.clone(),
                reason: Some(message),
                status_code: http_code,
                attempt_status: Some(status),
                connector_transaction_id: connector_txn_id,
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
            };
            return Ok(Self {
                resource_common_data: PaymentFlowData {
                    status,
                    ..router_data.resource_common_data
                },
                response: Err(error),
                ..router_data
            });
        }

        let resource_id = connector_txn_id
            .clone()
            .map(ResponseId::ConnectorTransactionId)
            .unwrap_or(ResponseId::NoResponseId);

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id,
                redirection_data,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id,
                incremental_authorization_allowed: None,
                status_code: http_code,
            }),
            ..router_data
        })
    }
}

impl
    TryFrom<
        ResponseRouterData<
            TwoctwopPacoNonUiResponse,
            Self,
        >,
    > for RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            TwoctwopPacoNonUiResponse,
            Self,
        >,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;
        let result = response.merged_result();
        let api_response = response.api_response.clone();
        let (status, txn_id, ref_id, prior) = extract_status(result, AttemptStatus::CaptureInitiated);

        if matches!(status, AttemptStatus::Failure) {
            let (code, message) = error_code_message(&api_response, &prior);
            let error = ErrorResponse {
                code,
                message: message.clone(),
                reason: Some(message),
                status_code: http_code,
                attempt_status: Some(status),
                connector_transaction_id: txn_id,
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
            };
            return Ok(Self {
                resource_common_data: PaymentFlowData {
                    status,
                    ..router_data.resource_common_data
                },
                response: Err(error),
                ..router_data
            });
        }

        let resource_id = txn_id
            .map(ResponseId::ConnectorTransactionId)
            .unwrap_or(ResponseId::NoResponseId);

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id,
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: ref_id,
                incremental_authorization_allowed: None,
                status_code: http_code,
            }),
            ..router_data
        })
    }
}

impl
    TryFrom<
        ResponseRouterData<
            TwoctwopPacoNonUiResponse,
            Self,
        >,
    > for RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            TwoctwopPacoNonUiResponse,
            Self,
        >,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;
        let result = response.merged_result();
        let api_response = response.api_response.clone();
        let (status, txn_id, ref_id, prior) = extract_status(result, AttemptStatus::VoidInitiated);

        if matches!(status, AttemptStatus::Failure) {
            let (code, message) = error_code_message(&api_response, &prior);
            let error = ErrorResponse {
                code,
                message: message.clone(),
                reason: Some(message),
                status_code: http_code,
                attempt_status: Some(status),
                connector_transaction_id: txn_id,
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
            };
            return Ok(Self {
                resource_common_data: PaymentFlowData {
                    status,
                    ..router_data.resource_common_data
                },
                response: Err(error),
                ..router_data
            });
        }

        let resource_id = txn_id
            .map(ResponseId::ConnectorTransactionId)
            .unwrap_or(ResponseId::NoResponseId);

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id,
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: ref_id,
                incremental_authorization_allowed: None,
                status_code: http_code,
            }),
            ..router_data
        })
    }
}

impl
    TryFrom<
        ResponseRouterData<
            TwoctwopPacoNonUiResponse,
            Self,
        >,
    > for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            TwoctwopPacoNonUiResponse,
            Self,
        >,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;
        let result = response.merged_result();

        let refund_status = match result.and_then(|b| b.payment_status_info.as_ref()) {
            Some(info) => map_refund_status(&info.payment_status, &info.payment_step),
            None => RefundStatus::Pending,
        };

        let connector_refund_id = result
            .and_then(|b| b.invoice_no2c2p.clone())
            .unwrap_or_else(|| router_data.request.refund_id.clone());

        if refund_status == RefundStatus::Failure {
            let (code, message) = error_code_message(
                &response.api_response,
                &result.and_then(|b| b.prior_payment_response_details.clone()),
            );
            let error = ErrorResponse {
                code,
                message: message.clone(),
                reason: Some(message),
                status_code: http_code,
                attempt_status: None,
                connector_transaction_id: Some(connector_refund_id),
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
            };
            return Ok(Self {
                response: Err(error),
                ..router_data
            });
        }

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id,
                refund_status,
                status_code: http_code,
            }),
            ..router_data
        })
    }
}

// ---------- Inquiry (PSync / RSync) — plain JSON ----------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TwoctwopPacoInquiryResponse {
    #[serde(default)]
    pub api_response: Option<PacoApiResponse>,
    /// PACO returns `data` as a JSON array on `/Inquiry/transactionStatus`,
    /// even when only one transaction matches. The accessor picks the
    /// first entry.
    #[serde(default, deserialize_with = "deserialize_inquiry_data")]
    pub data: Option<PacoInquiryData>,
}

fn deserialize_inquiry_data<'de, D>(
    deserializer: D,
) -> Result<Option<PacoInquiryData>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize as _;
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Repr {
        List(Vec<PacoInquiryData>),
        Single(PacoInquiryData),
        Null,
    }
    match Option::<Repr>::deserialize(deserializer)? {
        Some(Repr::List(mut v)) => Ok(v.drain(..).next()),
        Some(Repr::Single(d)) => Ok(Some(d)),
        Some(Repr::Null) | None => Ok(None),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PacoInquiryData {
    #[serde(default)]
    pub payment_status_info: Option<PacoPaymentStatusInfo>,
    #[serde(default, rename = "invoiceNo2C2P")]
    pub invoice_no2c2p: Option<String>,
    #[serde(default)]
    pub order_no: Option<String>,
    #[serde(default)]
    pub credit_card_authenticated_details: Option<PacoCreditCardAuthenticatedDetails>,
}

impl TryFrom<ResponseRouterData<TwoctwopPacoInquiryResponse, Self>>
    for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<TwoctwopPacoInquiryResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let info = response
            .data
            .as_ref()
            .and_then(|d| d.payment_status_info.as_ref());
        let status = match info {
            Some(info) => map_attempt_status(&info.payment_status, &info.payment_step),
            None => AttemptStatus::Pending,
        };
        let invoice = response
            .data
            .as_ref()
            .and_then(|d| d.invoice_no2c2p.clone());
        let order = response.data.as_ref().and_then(|d| d.order_no.clone());

        if matches!(status, AttemptStatus::Failure) {
            let (code, message) = error_code_message(&response.api_response, &None);
            let error = ErrorResponse {
                code,
                message: message.clone(),
                reason: Some(message),
                status_code: http_code,
                attempt_status: Some(status),
                connector_transaction_id: invoice.clone(),
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
            };
            return Ok(Self {
                resource_common_data: PaymentFlowData {
                    status,
                    ..router_data.resource_common_data
                },
                response: Err(error),
                ..router_data
            });
        }

        let resource_id = invoice
            .clone()
            .map(ResponseId::ConnectorTransactionId)
            .unwrap_or(ResponseId::NoResponseId);

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id,
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: order,
                incremental_authorization_allowed: None,
                status_code: http_code,
            }),
            ..router_data
        })
    }
}

impl TryFrom<ResponseRouterData<TwoctwopPacoInquiryResponse, Self>>
    for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<TwoctwopPacoInquiryResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let info = response
            .data
            .as_ref()
            .and_then(|d| d.payment_status_info.as_ref());
        let refund_status = match info {
            Some(info) => map_refund_status(&info.payment_status, &info.payment_step),
            None => RefundStatus::Pending,
        };
        let connector_refund_id = router_data.request.connector_refund_id.clone();

        if refund_status == RefundStatus::Failure {
            let (code, message) = error_code_message(&response.api_response, &None);
            let error = ErrorResponse {
                code,
                message: message.clone(),
                reason: Some(message),
                status_code: http_code,
                attempt_status: None,
                connector_transaction_id: Some(connector_refund_id),
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
            };
            return Ok(Self {
                response: Err(error),
                ..router_data
            });
        }

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id,
                refund_status,
                status_code: http_code,
            }),
            ..router_data
        })
    }
}

// ---------- Helpers ----------

fn extract_status(
    block: Option<&PacoPaymentResultBlock>,
    fallback: AttemptStatus,
) -> (
    AttemptStatus,
    Option<String>,
    Option<String>,
    Option<PacoPriorPaymentResponseDetails>,
) {
    match block {
        Some(b) => {
            let status = b
                .payment_status_info
                .as_ref()
                .map(|i| map_attempt_status(&i.payment_status, &i.payment_step))
                .unwrap_or(fallback);
            (
                status,
                b.invoice_no2c2p.clone(),
                b.order_no.clone(),
                b.prior_payment_response_details.clone(),
            )
        }
        None => (fallback, None, None, None),
    }
}

pub fn error_code_message(
    api_response: &Option<PacoApiResponse>,
    prior: &Option<PacoPriorPaymentResponseDetails>,
) -> (String, String) {
    let prior_code = prior.as_ref().and_then(|p| p.response_code.clone());
    let prior_msg = prior.as_ref().and_then(|p| p.response_description.clone());
    let api_code = api_response.as_ref().and_then(|a| a.response_code.clone());
    let api_msg = api_response.as_ref().and_then(|a| a.response_description.clone());
    let code = prior_code
        .or(api_code)
        .unwrap_or_else(|| NO_ERROR_CODE.to_string());
    let message = prior_msg
        .or(api_msg)
        .unwrap_or_else(|| NO_ERROR_MESSAGE.to_string());
    (code, message)
}

/// Inquiry-endpoint plain-JSON error body.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TwoctwopPacoErrorResponse {
    #[serde(default)]
    pub api_response: Option<PacoApiResponse>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
}

impl TwoctwopPacoErrorResponse {
    pub fn flatten(self) -> (String, String) {
        let api_code = self
            .api_response
            .as_ref()
            .and_then(|a| a.response_code.clone());
        let api_msg = self
            .api_response
            .as_ref()
            .and_then(|a| a.response_description.clone());
        let code = api_code
            .or(self.error)
            .unwrap_or_else(|| NO_ERROR_CODE.to_string());
        let message = api_msg
            .or(self.message)
            .unwrap_or_else(|| NO_ERROR_MESSAGE.to_string());
        (code, message)
    }
}

/// Build the JOSE claim envelope expected by PACO. The `iss` and
/// `CompanyApiKey` claims both carry the access token; `aud` is fixed.
#[derive(Debug, Serialize)]
pub struct PacoJoseClaims<'a> {
    pub iss: &'a str,
    pub aud: &'static str,
    #[serde(rename = "CompanyApiKey")]
    pub company_api_key: &'a str,
    pub iat: i64,
    pub nbf: i64,
    pub exp: i64,
    pub request: serde_json::Value,
}

impl<'a> PacoJoseClaims<'a> {
    pub fn new(access_token: &'a str, request: serde_json::Value) -> Self {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        Self {
            iss: access_token,
            aud: "PacoAudience",
            company_api_key: access_token,
            iat: now,
            nbf: now,
            exp: now + 5 * 60,
            request,
        }
    }
}

/// Wrap a serialisable PACO request body in the JOSE claim envelope and
/// return the compact JWE that PACO expects on the wire.
pub fn build_jose_envelope<T: Serialize>(
    body: T,
    auth: &TwoctwopPacoAuthType,
) -> Result<Vec<u8>, error_stack::Report<errors::IntegrationError>> {
    let request_value = serde_json::to_value(&body).map_err(|err| {
        error_stack::report!(errors::IntegrationError::InvalidDataFormat {
            field_name: "twoctwop_paco request body",
            context: errors::IntegrationErrorContext {
                suggested_action: None,
                doc_url: None,
                additional_context: Some(format!("Failed to serialise PACO body: {err}")),
            },
        })
    })?;
    let claims = PacoJoseClaims::new(auth.access_token.peek(), request_value);
    let jwe = common_utils::crypto::jose::sign_then_encrypt(&claims, &auth.jose_cfg).map_err(
        |err| {
            error_stack::report!(errors::IntegrationError::FailedToObtainAuthType {
                context: errors::IntegrationErrorContext {
                    suggested_action: Some(
                        "Confirm the PACO PEMs and `kid` resolve a valid JOSE pair.".to_string(),
                    ),
                    doc_url: None,
                    additional_context: Some(format!("JOSE sign+encrypt failed: {err}")),
                },
            })
        },
    )?;
    Ok(jwe.into_bytes())
}

/// Decrypt a compact JWE response from PACO and parse it as the requested type.
pub fn decode_jose_response<R: for<'de> Deserialize<'de>>(
    body: &[u8],
    status_code: u16,
    auth: &TwoctwopPacoAuthType,
) -> Result<R, error_stack::Report<errors::ConnectorError>> {
    let compact = std::str::from_utf8(body).map_err(|_| {
        error_stack::report!(
            errors::ConnectorError::response_deserialization_failed_with_context(
                status_code,
                Some("twoctwop_paco: response was not valid UTF-8".to_string()),
            )
        )
    })?;
    let trimmed = compact.trim().trim_matches('"');
    let claims = common_utils::crypto::jose::decrypt_then_verify(trimmed, &auth.jose_cfg)
        .map_err(|err| {
            error_stack::report!(
                errors::ConnectorError::response_deserialization_failed_with_context(
                    status_code,
                    Some(format!("JOSE decrypt+verify failed: {err}")),
                )
            )
        })?;
    let inner = match claims.get("response") {
        Some(value) => value.clone(),
        None => claims,
    };
    serde_json::from_value::<R>(inner).map_err(|err| {
        error_stack::report!(
            errors::ConnectorError::response_deserialization_failed_with_context(
                status_code,
                Some(format!("twoctwop_paco: response shape mismatch: {err}")),
            )
        )
    })
}

// ---------- 3DS trio: shared helpers ----------

/// Translate PACO's `creditCardAuthenticatedDetails` block into the prism
/// `AuthenticationData` shape consumed by downstream Authorize.
fn build_authentication_data_from_paco(
    details: &PacoCreditCardAuthenticatedDetails,
) -> AuthenticationData {
    AuthenticationData {
        trans_status: details
            .authentication_status
            .as_ref()
            .and_then(|s| s.parse::<common_enums::TransactionStatus>().ok()),
        eci: details.eci_value.clone(),
        cavv: details.cavv.clone().map(Secret::new),
        ucaf_collection_indicator: None,
        threeds_server_transaction_id: details.three_ds_transaction_id.clone(),
        message_version: details
            .authentication_3ds_version
            .as_ref()
            .and_then(|v| v.parse::<common_utils::types::SemanticVersion>().ok()),
        ds_trans_id: details.three_ds_transaction_id.clone(),
        acs_transaction_id: None,
        transaction_id: details.three_ds_transaction_id.clone(),
        network_params: None,
        exemption_indicator: None,
    }
}

/// PACO has no DDC step — `/Payment/nonUi` performs both enrolment lookup and
/// challenge issuance in a single call, so PreAuthenticate is a non-network
/// no-op. This helper shapes the synthetic router-data response.
pub fn build_preauthenticate_passthrough<T: PaymentMethodDataTypes>(
    data: &RouterDataV2<
        PreAuthenticate,
        PaymentFlowData,
        PaymentsPreAuthenticateData<T>,
        PaymentsResponseData,
    >,
) -> RouterDataV2<
    PreAuthenticate,
    PaymentFlowData,
    PaymentsPreAuthenticateData<T>,
    PaymentsResponseData,
> {
    let mut clone = data.clone();
    let connector_response_reference_id = Some(
        data.resource_common_data
            .connector_request_reference_id
            .clone(),
    );
    clone.resource_common_data.status = AttemptStatus::AuthenticationPending;
    clone.response = Ok(PaymentsResponseData::PreAuthenticateResponse {
        authentication_data: None,
        redirection_data: None,
        connector_response_reference_id,
        status_code: 200,
    });
    clone
}

// ---------- Authenticate response → RouterDataV2 ----------

impl<T: PaymentMethodDataTypes>
    TryFrom<
        ResponseRouterData<
            TwoctwopPacoNonUiResponse,
            Self,
        >,
    >
    for RouterDataV2<
        Authenticate,
        PaymentFlowData,
        PaymentsAuthenticateData<T>,
        PaymentsResponseData,
    >
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            TwoctwopPacoNonUiResponse,
            Self,
        >,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let result = response.merged_result();
        let api_response = response.api_response.clone();
        let info = result.and_then(|b| b.payment_status_info.as_ref());
        let prior = result.and_then(|b| b.prior_payment_response_details.clone());
        let connector_txn_id = result.and_then(|b| b.invoice_no2c2p.clone());
        let connector_response_reference_id = result.and_then(|b| b.order_no.clone());

        // Failure → emit ErrorResponse and stop.
        let mapped_status = info
            .map(|i| map_attempt_status(&i.payment_status, &i.payment_step))
            .unwrap_or(AttemptStatus::AuthenticationPending);

        if matches!(mapped_status, AttemptStatus::Failure) {
            let (code, message) = error_code_message(&api_response, &prior);
            tracing::warn!(
                code = %code,
                message = %message,
                "twoctwop_paco: Authenticate returned failure"
            );
            let error = ErrorResponse {
                code,
                message: message.clone(),
                reason: Some(message),
                status_code: http_code,
                attempt_status: Some(AttemptStatus::AuthenticationFailed),
                connector_transaction_id: connector_txn_id,
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
            };
            return Ok(Self {
                resource_common_data: PaymentFlowData {
                    status: AttemptStatus::AuthenticationFailed,
                    ..router_data.resource_common_data
                },
                response: Err(error),
                ..router_data
            });
        }

        // Challenge required → build CReq POST form.
        let challenge = result.and_then(|b| b.ares_acs_challenge.as_ref());
        if let Some(challenge) = challenge {
            tracing::debug!(
                acs_url = %challenge.acs_url,
                "twoctwop_paco: Authenticate requires ACS challenge"
            );
            let mut form_fields: HashMap<String, String> = HashMap::new();
            form_fields.insert("creq".to_string(), challenge.creq.clone());
            if let Some(session_data) = &challenge.three_ds_session_data {
                form_fields.insert("threeDSSessionData".to_string(), session_data.clone());
            }
            let redirect = Box::new(RedirectForm::Form {
                endpoint: challenge.acs_url.clone(),
                method: Method::Post,
                form_fields,
            });

            return Ok(Self {
                resource_common_data: PaymentFlowData {
                    status: AttemptStatus::AuthenticationPending,
                    ..router_data.resource_common_data
                },
                response: Ok(PaymentsResponseData::AuthenticateResponse {
                    resource_id: connector_txn_id.map(ResponseId::ConnectorTransactionId),
                    redirection_data: Some(redirect),
                    authentication_data: None,
                    connector_response_reference_id,
                    status_code: http_code,
                }),
                ..router_data
            });
        }

        // Frictionless → CAVV / ECI returned directly on the nonUi response.
        let authentication_data = result
            .and_then(|b| b.credit_card_authenticated_details.as_ref())
            .map(build_authentication_data_from_paco);

        let status = if authentication_data.is_some() {
            AttemptStatus::AuthenticationSuccessful
        } else {
            // No challenge AND no CAVV — keep the prism state machine on
            // AuthenticationPending so the orchestrator can fall through to
            // PostAuthenticate (which polls the inquiry endpoint).
            AttemptStatus::AuthenticationPending
        };

        tracing::debug!(
            frictionless = authentication_data.is_some(),
            "twoctwop_paco: Authenticate response decoded"
        );

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            response: Ok(PaymentsResponseData::AuthenticateResponse {
                resource_id: connector_txn_id.map(ResponseId::ConnectorTransactionId),
                redirection_data: None,
                authentication_data,
                connector_response_reference_id,
                status_code: http_code,
            }),
            ..router_data
        })
    }
}

// ---------- PostAuthenticate response → RouterDataV2 ----------

impl<T: PaymentMethodDataTypes>
    TryFrom<
        ResponseRouterData<
            TwoctwopPacoInquiryResponse,
            Self,
        >,
    >
    for RouterDataV2<
        PostAuthenticate,
        PaymentFlowData,
        PaymentsPostAuthenticateData<T>,
        PaymentsResponseData,
    >
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            TwoctwopPacoInquiryResponse,
            Self,
        >,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let info = response
            .data
            .as_ref()
            .and_then(|d| d.payment_status_info.as_ref());
        let mapped_status = info
            .map(|i| map_attempt_status(&i.payment_status, &i.payment_step))
            .unwrap_or(AttemptStatus::Pending);

        let order = response.data.as_ref().and_then(|d| d.order_no.clone());
        let invoice = response
            .data
            .as_ref()
            .and_then(|d| d.invoice_no2c2p.clone());

        if matches!(mapped_status, AttemptStatus::Failure) {
            let (code, message) = error_code_message(&response.api_response, &None);
            tracing::warn!(
                code = %code,
                message = %message,
                "twoctwop_paco: PostAuthenticate inquiry returned failure"
            );
            let error = ErrorResponse {
                code,
                message: message.clone(),
                reason: Some(message),
                status_code: http_code,
                attempt_status: Some(AttemptStatus::AuthenticationFailed),
                connector_transaction_id: invoice,
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
            };
            return Ok(Self {
                resource_common_data: PaymentFlowData {
                    status: AttemptStatus::AuthenticationFailed,
                    ..router_data.resource_common_data
                },
                response: Err(error),
                ..router_data
            });
        }

        let authentication_data = response
            .data
            .as_ref()
            .and_then(|d| d.credit_card_authenticated_details.as_ref())
            .map(build_authentication_data_from_paco);

        // The PACO transaction is considered "authenticated" once the inquiry
        // shows the post-challenge step (PA/Authorized) or any non-failure
        // terminal state. Any other state keeps the orchestrator in
        // AuthenticationPending.
        let status = match info.map(|i| (&i.payment_status, &i.payment_step)) {
            Some((PacoPaymentStatus::A, PacoPaymentStep::PA))
            | Some((PacoPaymentStatus::S, PacoPaymentStep::ST)) => {
                AttemptStatus::AuthenticationSuccessful
            }
            _ => AttemptStatus::AuthenticationPending,
        };

        tracing::debug!(
            cavv_present = authentication_data
                .as_ref()
                .map(|a| a.cavv.is_some())
                .unwrap_or(false),
            "twoctwop_paco: PostAuthenticate inquiry decoded"
        );

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            response: Ok(PaymentsResponseData::PostAuthenticateResponse {
                authentication_data,
                connector_response_reference_id: order,
                status_code: http_code,
            }),
            ..router_data
        })
    }
}

