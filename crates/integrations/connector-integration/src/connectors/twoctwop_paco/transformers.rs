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
        Authenticate, Authorize, Capture, PSync, RSync, Refund, Void, VoidPC,
    },
    connector_types::{
        PaymentFlowData, PaymentVoidData, PaymentsAuthenticateData, PaymentsAuthorizeData,
        PaymentsCancelPostCaptureData, PaymentsCaptureData, PaymentsResponseData, PaymentsSyncData,
        RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData, ResponseId,
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

use crate::{connectors::twoctwop_paco::TwoctwopPacoRouterData, types::ResponseRouterData};

const PACO_LANGUAGE: &str = "en-US";
const PACO_PAYMENT_TYPE_CC: &str = "CC";
const PACO_CARD_TYPE_CREDIT: &str = "credit";
const PACO_CARD_TYPE_DEBIT: &str = "debit";
const PACO_PAYMENT_CATEGORY_ECOM: &str = "ECOM";
const PACO_PREFERRED_PAYMENT_TYPE_GCASH: &str = "WALLET-GCASH";
const PACO_REFUND_MAKER_ID: &str = "merchant";
const PACO_KID_HEX_LEN: usize = 32;
const PACO_OFFICE_ID_MAX_LEN: usize = 20;
/// Audience claim PACO requires on every JWT envelope.
pub const PACO_AUDIENCE: &str = "PacoAudience";
/// TTL applied to outgoing JWT envelopes. PACO's published sample script
/// uses 5 minutes; anything past that returns a "JWT expired" error.
const PACO_JWT_TTL_SECONDS: i64 = 300;

/// PACO finalised-status response code prefix used by every successful response.
pub const PACO_RESPONSE_CODE_SUCCESS: &str = "PC-B050000";

/// Strongly-typed PACO authentication bundle. Built by validating the
/// `ConnectorSpecificConfig::TwoctwopPaco` variant once per request.
#[derive(Debug, Clone)]
pub struct TwoctwopPacoAuthType {
    pub access_token: Secret<String>,
    pub office_id: Secret<String>,
    pub merchant_id: Secret<String>,
    /// Audit-log human-actor id PACO records under
    /// `localMakerChecker.maker.username` on Refund. Defaults to "merchant"
    /// when the per-merchant config doesn't supply one.
    pub refund_maker_id: String,
    /// Expected `aud` claim on PACO response JWTs. Defaults to the merchant's
    /// access_token (current PACO behaviour) when the config doesn't override.
    pub response_audience: Secret<String>,
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
                refund_maker_id,
                response_audience,
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
                    refund_maker_id: refund_maker_id
                        .clone()
                        .unwrap_or_else(|| PACO_REFUND_MAKER_ID.to_string()),
                    response_audience: response_audience
                        .clone()
                        .unwrap_or_else(|| access_token.clone()),
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
        let amount_decimal = currency.to_currency_base_unit_asf64(raw).map_err(|_| {
            errors::IntegrationError::InvalidDataFormat {
                field_name: "amount",
                context: errors::IntegrationErrorContext {
                    suggested_action: None,
                    doc_url: None,
                    additional_context: Some(
                        "Failed to convert minor amount to base currency unit".to_string(),
                    ),
                },
            }
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

/// EMV 3DS 2.0 device-fingerprint payload PACO threads through to the
/// issuer's ACS. Populated from prism's `BrowserInformation` for the
/// browser channel; the issuer uses it to make the frictionless-vs-
/// challenge decision via Risk-Based Authentication. Omitting it
/// effectively forces a step-up challenge every time, because the ACS
/// has nothing to evaluate.
///
/// All fields here are optional in PACO's schema, but populating the
/// EMV 3DS 2.0 minimum set (acceptHeader, javaEnabled, javascriptEnabled,
/// language, colorDepth, screenH/W, timeZone, userAgent, ip) gives the
/// best chance of frictionless on a recognised cardholder device.
#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct PacoBrowserInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accept_header: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub javascript_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub java_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    /// PACO accepts numeric values as strings here (the EMV 3DS 2.0 wire
    /// format encodes everything as strings). Match that convention.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub color_depth: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub screen_height: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub screen_width: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_zone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
}

impl PacoBrowserInfo {
    /// Lift a prism `BrowserInformation` into PACO's expected shape. Any
    /// missing fields stay None and are skipped at serialisation — the
    /// issuer ACS then evaluates whatever's present.
    pub fn from_browser_info(bi: &domain_types::router_request_types::BrowserInformation) -> Self {
        Self {
            accept_header: bi.accept_header.clone(),
            ip: bi.ip_address.map(|ip| ip.to_string()),
            javascript_enabled: bi.java_script_enabled,
            java_enabled: bi.java_enabled,
            language: bi.language.clone(),
            color_depth: bi.color_depth.map(|d| d.to_string()),
            screen_height: bi.screen_height.map(|h| h.to_string()),
            screen_width: bi.screen_width.map(|w| w.to_string()),
            time_zone: bi.time_zone.map(|tz| tz.to_string()),
            user_agent: bi.user_agent.clone(),
        }
    }
}

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
    /// EMV 3DS 2.0 device fingerprint. Required for the issuer ACS to
    /// have any chance of evaluating frictionless. PACO accepts the body
    /// without it but then always escalates to challenge.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browser_info: Option<PacoBrowserInfo>,
    /// Maps to PACO's `deviceDetails` — distinct from `browserInfo`, used
    /// by PACO's own routing (mobile vs PC); also influences hosted-page
    /// rendering for the wallet flow.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_details: Option<PacoDeviceDetails>,
}

// ---------- /Payment/prepaymentUi (GCash hosted) ----------

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PacoDeviceDetails {
    /// `M` (mobile) / `P` (PC). Drives whether the GCash deep-link or the
    /// web-first hosted page is generated; PACO returns a null
    /// `paymentPageURL` when this field is missing.
    pub device_category: &'static str,
    pub user_agent: String,
}

impl PacoDeviceDetails {
    fn default_browser() -> Self {
        Self {
            device_category: "P",
            user_agent: "Mozilla/5.0 hyperswitch-prism".to_string(),
        }
    }

    /// Derive deviceCategory from the user-agent string. Mobile UAs that
    /// contain "Mobile" / "Android" / "iPhone" / "iPad" map to "M", everything
    /// else to "P". Used by PACO to decide whether to generate a mobile
    /// deep-link or a desktop payment page for hosted-redirect flows.
    pub fn from_user_agent(user_agent: String) -> Self {
        let lower = user_agent.to_ascii_lowercase();
        let is_mobile = lower.contains("mobile")
            || lower.contains("android")
            || lower.contains("iphone")
            || lower.contains("ipad");
        Self {
            device_category: if is_mobile { "M" } else { "P" },
            user_agent,
        }
    }
}

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
    pub device_details: PacoDeviceDetails,
    pub preferred_payment_types: Vec<&'static str>,
}

/// Discriminator used to pick the PACO endpoint for Authorize without
/// re-inspecting the payment-method-data inside both `get_url` and the
/// request-body TryFrom impl.
#[derive(Debug, Clone, Copy)]
pub enum AuthorizeRoute {
    CardNonUi,
    WalletPrepaymentUi,
}

/// Inspect the Authorize input and return the PACO endpoint to hit. Pure —
/// no auth or amount conversion. Used by both `get_url` (URL selection) and
/// the `TryFrom` impl (body selection) so the two stay in lock-step.
pub fn authorize_route<T>(
    item: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
) -> Result<AuthorizeRoute, error_stack::Report<errors::IntegrationError>>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize,
{
    match &item.request.payment_method_data {
        PaymentMethodData::Card(_) => Ok(AuthorizeRoute::CardNonUi),
        PaymentMethodData::Wallet(WalletData::GcashRedirect(_)) => {
            Ok(AuthorizeRoute::WalletPrepaymentUi)
        }
        _ => Err(errors::IntegrationError::NotImplemented(
            "Selected payment method through TwoctwopPaco".to_string(),
            errors::IntegrationErrorContext::default(),
        )
        .into()),
    }
}

/// Wire body for Authorize. Two-shape because PACO has two endpoints with
/// distinct schemas. `#[serde(untagged)]` keeps the on-wire JSON identical
/// to what the per-variant builder used to emit.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
// Card variant is ~656 B (card details + browser info); Wallet is far smaller.
// Boxing would double-allocate every Authorize. The enum is short-lived
// (built, serialised, then dropped), so the larger size is acceptable here.
#[allow(clippy::large_enum_variant)]
pub enum TwoctwopPacoAuthorizeRequest {
    Card(TwoctwopPacoCardAuthorizeRequest),
    Wallet(TwoctwopPacoWalletAuthorizeRequest),
}

/// Wire body for VoidPC (post-capture reverse). Same shape as Void — the
/// newtype only exists so the `Bridge<RequestTemplating, ...>` for VoidPC
/// is distinct from Void's at the type system level.
#[derive(Debug, Clone, Serialize)]
#[serde(transparent)]
pub struct TwoctwopPacoVoidPcRequest(pub TwoctwopPacoVoidRequest);

/// Wire body for Authenticate. Same shape as the card Authorize body with
/// `request3dsFlag` forced to "Y"; newtype gives Authenticate its own
/// `Bridge` templating slot.
#[derive(Debug, Clone, Serialize)]
#[serde(transparent)]
pub struct TwoctwopPacoAuthenticateRequest(pub TwoctwopPacoCardAuthorizeRequest);

// Response newtypes. Each JOSE flow shares the underlying
// `TwoctwopPacoNonUiResponse` wire shape, but the `Bridge<_, ResponseTemplating, T>`
// definition expanded by `impl_templating!` would collide if the same response
// type were registered against multiple flows. Per-flow newtypes give each
// bridge a distinct templating slot; `#[serde(transparent)]` keeps the on-wire
// deserialisation identical.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TwoctwopPacoAuthorizeResponse(pub TwoctwopPacoNonUiResponse);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TwoctwopPacoCaptureResponse(pub TwoctwopPacoNonUiResponse);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TwoctwopPacoVoidResponse(pub TwoctwopPacoNonUiResponse);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TwoctwopPacoVoidPcResponse(pub TwoctwopPacoNonUiResponse);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TwoctwopPacoRefundResponse(pub TwoctwopPacoNonUiResponse);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TwoctwopPacoAuthenticateResponse(pub TwoctwopPacoNonUiResponse);


pub fn build_authorize_request<T>(
    item: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    auth: &TwoctwopPacoAuthType,
) -> Result<TwoctwopPacoAuthorizeRequest, error_stack::Report<errors::IntegrationError>>
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
            let browser_info = item
                .request
                .browser_info
                .as_ref()
                .map(PacoBrowserInfo::from_browser_info);
            let device_details = item
                .request
                .browser_info
                .as_ref()
                .and_then(|bi| bi.user_agent.clone())
                .map(PacoDeviceDetails::from_user_agent);
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
                browser_info,
                device_details,
            };
            Ok(TwoctwopPacoAuthorizeRequest::Card(body))
        }
        PaymentMethodData::Wallet(WalletData::GcashRedirect(_)) => {
            let device_details = item
                .request
                .browser_info
                .as_ref()
                .and_then(|bi| bi.user_agent.clone())
                .map(|ua| PacoDeviceDetails {
                    device_category: "P",
                    user_agent: ua,
                })
                .unwrap_or_else(PacoDeviceDetails::default_browser);
            let body = TwoctwopPacoWalletAuthorizeRequest {
                api_request: ApiRequestEnvelope::new(),
                office_id: auth.office_id.clone(),
                order_no,
                product_description: description,
                payment_category: PACO_PAYMENT_CATEGORY_ECOM,
                transaction_amount: amount,
                notification_urls,
                device_details,
                preferred_payment_types: vec![PACO_PREFERRED_PAYMENT_TYPE_GCASH],
            };
            Ok(TwoctwopPacoAuthorizeRequest::Wallet(body))
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
        confirmation_url: item
            .request
            .router_return_url
            .as_ref()
            .map(|u| u.to_string()),
        failed_url: item
            .request
            .router_return_url
            .as_ref()
            .map(|u| u.to_string()),
        cancellation_url: item
            .request
            .router_return_url
            .as_ref()
            .map(|u| u.to_string()),
        backend_url: item
            .request
            .continue_redirection_url
            .as_ref()
            .map(|u| u.to_string()),
    };

    let browser_info = item
        .request
        .browser_info
        .as_ref()
        .map(PacoBrowserInfo::from_browser_info);
    let device_details = item
        .request
        .browser_info
        .as_ref()
        .and_then(|bi| bi.user_agent.clone())
        .map(PacoDeviceDetails::from_user_agent);

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
                browser_info,
                device_details,
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

/// PACO's `/api/2.0/Void` accepts both pre- and post-capture reversals.
/// VoidPC carries the same identifiers as Void, so the wire body is the
/// same — only the upstream Prism flow marker differs.
pub fn build_void_pc_request(
    item: &RouterDataV2<
        VoidPC,
        PaymentFlowData,
        PaymentsCancelPostCaptureData,
        PaymentsResponseData,
    >,
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
//
// Body shape per PACO's official OpenAPI spec at
// https://devzone.2c2p.com/reference/refund:
//
//   { officeId, orderNo, productDescription?,
//     refundAmount: AmountCompound,
//     localMakerChecker: { maker: { username }, checker? } }
//
// `orderNo` is the ORIGINAL transaction's order number (a.k.a. invoice no),
// NOT a new refund identifier. There is no `refundDetails` wrapper and no
// `invoiceNo2C2P` body field. `localMakerChecker.maker.username` is what
// PACO records in its audit log; the office config decides whether a
// checker (approver) is also required.

/// PACO HumanActor — used for both maker (requestor) and checker (approver)
/// inside the localMakerChecker / pspMakerChecker workflow objects. The
/// `username` is what PACO records in its audit log; merchants override the
/// default `"merchant"` via `ConnectorSpecificConfig::TwoctwopPaco.refund_maker_id`
/// for a traceable operator/ticket id.
#[derive(Debug, Clone, Serialize)]
pub struct PacoHumanActor {
    pub username: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PacoMakerChecker {
    pub maker: PacoHumanActor,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TwoctwopPacoRefundRequest {
    pub api_request: ApiRequestEnvelope,
    pub office_id: Secret<String>,
    /// PACO requires the ORIGINAL transaction's orderNo here. Callers must
    /// set `x-connector-request-reference-id` to the original auth's order
    /// reference when invoking Refund.
    pub order_no: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product_description: Option<String>,
    pub refund_amount: PacoTransactionAmount,
    pub local_maker_checker: PacoMakerChecker,
}

pub fn build_refund_request(
    item: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    auth: &TwoctwopPacoAuthType,
) -> Result<TwoctwopPacoRefundRequest, error_stack::Report<errors::IntegrationError>> {
    let amount =
        PacoTransactionAmount::new(item.request.minor_refund_amount, item.request.currency)?;
    // PACO's /Refund/refund matches the original payment by the merchant's
    // original orderNo (the value the merchant supplied to Authorize as
    // `merchant_transaction_id` / `x-connector-request-reference-id`). The
    // refund's own `merchant_refund_id` is recorded by PACO as a new
    // `refundNo`, not as the lookup key.
    //
    // RefundFlowData.connector_request_reference_id is forcibly overridden
    // by the orchestrator to carry the refund_id, so we cannot recover the
    // original orderNo from there. The caller must pass it through one of
    // the SecretString metadata fields on the proto PaymentServiceRefundRequest.
    // We check both in priority order:
    //   1. `refund_metadata` (proto field 10) → routed to
    //      RefundsData.refund_connector_metadata. Preferred.
    //   2. `connector_feature_data` (proto field 11) → routed to
    //      RefundsData.connector_feature_data. Fallback for merchants that
    //      stash the orderNo there during the Authorize lifecycle.
    // In both cases the value can be a plain JSON string (treated as the
    // orderNo) or an object `{"original_order_no":"<orderNo>"}`. See the
    // connector module docstring for the merchant-facing contract.
    let original_order_no = item
        .request
        .refund_connector_metadata
        .as_ref()
        .and_then(extract_paco_original_order_no)
        .or_else(|| {
            item.request
                .connector_feature_data
                .as_ref()
                .and_then(extract_paco_original_order_no)
        })
        .ok_or_else(|| errors::IntegrationError::MissingRequiredField {
            field_name: "refund_metadata.original_order_no",
            context: errors::IntegrationErrorContext {
                suggested_action: Some(
                    "Pass the original Authorize orderNo via either `refund_metadata` \
                         (preferred) or `connector_feature_data` on the Refund request, \
                         e.g. {\"original_order_no\":\"<auth orderNo>\"}."
                        .to_string(),
                ),
                doc_url: Some("https://devzone.2c2p.com/reference/refund".to_string()),
                additional_context: Some(
                    "PACO matches refunds against the original transaction's \
                         orderNo, which is not derivable from connector_transaction_id."
                        .to_string(),
                ),
            },
        })?;
    Ok(TwoctwopPacoRefundRequest {
        api_request: ApiRequestEnvelope::new(),
        office_id: auth.office_id.clone(),
        order_no: original_order_no,
        product_description: item.request.reason.clone(),
        refund_amount: amount,
        local_maker_checker: PacoMakerChecker {
            maker: PacoHumanActor {
                username: auth.refund_maker_id.clone(),
            },
        },
    })
}

/// Pull the original orderNo from a metadata SecretSerdeValue. Accepts either
/// a bare JSON string ("auth_xxx") or an object ({"original_order_no":"..."}).
fn extract_paco_original_order_no(meta: &common_utils::SecretSerdeValue) -> Option<String> {
    let value = meta.peek();
    if let Some(s) = value.as_str() {
        if !s.is_empty() {
            return Some(s.to_string());
        }
    }
    if let Some(obj) = value.as_object() {
        if let Some(s) = obj.get("original_order_no").and_then(|v| v.as_str()) {
            if !s.is_empty() {
                return Some(s.to_string());
            }
        }
    }
    None
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
    /// Refunded (final).
    RF,
    /// Refund Requested (in flight).
    RR,
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
        (PacoPaymentStatus::R, PacoPaymentStep::RR) => AttemptStatus::Charged,
        // PACO `I` ("Incomplete") means the payment is in-flight from PACO's
        // perspective — the customer hasn't yet finished the hosted-page or
        // ACS challenge. Map every (I, *) pair to AuthenticationPending; the
        // step variant only narrows which sub-stage is pending (AC = ACS
        // challenge, Unknown = post-hosted-page wallet authorisation, etc.).
        // Live verified 2026-05-11: PSync on an in-flight GCash returns
        // I/Unknown — without this fall-through it misclassified as Failure.
        (PacoPaymentStatus::I, _) => AttemptStatus::AuthenticationPending,
        (PacoPaymentStatus::Pcps, PacoPaymentStep::GP) => AttemptStatus::AuthenticationPending,
        (PacoPaymentStatus::P, PacoPaymentStep::IN) => AttemptStatus::Authorizing,
        // Per the PACO Solution Doc, P/RP (Pending Refund) is treated as
        // AUTHORIZING — the in-flight refund hasn't yet detached funds, so
        // the original auth is still effectively the canonical state.
        (PacoPaymentStatus::P, PacoPaymentStep::RP) => AttemptStatus::Authorizing,
        (PacoPaymentStatus::F, _) => AttemptStatus::Failure,
        // Unknown PACO (status, step) pairs MUST map to Failure, not Pending:
        // an indefinite "Pending" leaves the merchant unable to retry safely
        // and risks a double-debit when PACO has actually finalised the
        // payment in a state we don't yet model. New PACO state codes should
        // be added explicitly above.
        (s, st) => {
            tracing::warn!(
                target: "twoctwop_paco",
                paymentStatus = ?s,
                paymentStep = ?st,
                "twoctwop_paco: unknown (paymentStatus, paymentStep) pair — defaulting to Failure"
            );
            AttemptStatus::Failure
        }
    }
}

fn map_refund_status(status: &PacoPaymentStatus, step: &PacoPaymentStep) -> RefundStatus {
    match (status, step) {
        (PacoPaymentStatus::R, PacoPaymentStep::RF) => RefundStatus::Success,
        (PacoPaymentStatus::R, PacoPaymentStep::RR) => RefundStatus::Pending,
        (PacoPaymentStatus::P, PacoPaymentStep::RP) => RefundStatus::Pending,
        (PacoPaymentStatus::F, _) => RefundStatus::Failure,
        (s, st) => {
            tracing::warn!(
                target: "twoctwop_paco",
                paymentStatus = ?s,
                paymentStep = ?st,
                "twoctwop_paco: unknown (paymentStatus, paymentStep) pair — defaulting refund to Failure"
            );
            RefundStatus::Failure
        }
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
    /// PACO returns this field as `paymentPageUrl` on /Payment/nonUi
    /// responses but as `paymentPageURL` on /Payment/prepaymentUi. Accept
    /// both casings.
    #[serde(default, alias = "paymentPageURL")]
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
    /// Top-level page URL fallback. PACO emits this as `paymentPageUrl`
    /// on /Payment/nonUi and as `paymentPageURL` on /Payment/prepaymentUi.
    #[serde(default, alias = "paymentPageURL")]
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
    /// PACO field is `acsURL` (capital URL).
    #[serde(default, rename = "acsURL", alias = "acsUrl")]
    pub acs_url: Option<String>,
    /// PACO can name the CReq blob `creq`, `cReq`, or `creqB64`. Accept any.
    #[serde(default, alias = "cReq", alias = "creqB64")]
    pub creq: Option<String>,
    /// `threeDSSessionData` (capital DS).
    #[serde(default, rename = "threeDSSessionData")]
    pub three_ds_session_data: Option<String>,
    /// `authentication3DSVersion` (capital DS).
    #[serde(default, rename = "authentication3DSVersion")]
    pub authentication_3ds_version: Option<String>,
    /// `challengeHTML` (capital HTML).
    #[serde(default, rename = "challengeHTML")]
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
    /// On `/Payment/prepaymentUi` responses (GCash hosted-page) PACO returns
    /// `paymentPage` as a sibling of `paymentIncompleteResult` inside `data`,
    /// not nested under it. The `merged_payment_page_url` accessor below
    /// checks both locations.
    #[serde(default)]
    pub payment_page: Option<PacoPaymentPage>,
    /// `/Refund/refund` flattens the result fields onto `data` directly —
    /// there is no `paymentResult`/`paymentIncompleteResult` wrapper. Catch
    /// the flat shape with the same field set so `merged_result()` can fall
    /// back to it.
    #[serde(default)]
    pub payment_status_info: Option<PacoPaymentStatusInfo>,
    #[serde(default, rename = "invoiceNo2C2P")]
    pub invoice_no2c2p: Option<String>,
    #[serde(default)]
    pub order_no: Option<String>,
    #[serde(default)]
    pub refund_no: Option<String>,
    #[serde(default)]
    pub psp_response: Option<PacoPriorPaymentResponseDetails>,
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
        self.data.as_ref().and_then(|d| {
            d.payment_result
                .as_ref()
                .or(d.payment_incomplete_result.as_ref())
        })
    }

    /// Refund / Settlement / Void responses flatten the result fields onto
    /// `data` directly instead of nesting them under `paymentResult` /
    /// `paymentIncompleteResult`. Use this when the flat shape is expected.
    pub fn flat_data_block(&self) -> Option<PacoPaymentResultBlock> {
        let data = self.data.as_ref()?;
        // Prefer the wrapper shapes if present.
        if let Some(b) = data
            .payment_result
            .as_ref()
            .or(data.payment_incomplete_result.as_ref())
        {
            return Some(b.clone());
        }
        if data.payment_status_info.is_some() {
            return Some(PacoPaymentResultBlock {
                invoice_no2c2p: data.invoice_no2c2p.clone(),
                order_no: data.order_no.clone(),
                controller_internal_id: None,
                payment_status_info: data.payment_status_info.clone(),
                prior_payment_response_details: data.psp_response.clone(),
                payment_page: None,
                payment_page_url: None,
                ares_acs_challenge: None,
                credit_card_authenticated_details: None,
            });
        }
        None
    }
}

// ---------- Authorize response → RouterDataV2 ----------

impl<F, T> TryFrom<ResponseRouterData<TwoctwopPacoNonUiResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize,
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<TwoctwopPacoNonUiResponse, Self>,
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
                    // PACO publishes the hosted-page URL in three possible
                    // shapes across nonUi/prepaymentUi: `data.paymentPage`
                    // (sibling of paymentIncompleteResult, GCash flow),
                    // `data.<result>.paymentPage` (nested), or
                    // `data.<result>.paymentPageUrl` (top-level fallback).
                    // Check all three.
                    let url = response
                        .data
                        .as_ref()
                        .and_then(|d| d.payment_page.as_ref())
                        .and_then(|p| p.payment_page_url.clone())
                        .or_else(|| {
                            block
                                .payment_page
                                .as_ref()
                                .and_then(|p| p.payment_page_url.clone())
                        })
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

impl TryFrom<ResponseRouterData<TwoctwopPacoNonUiResponse, Self>>
    for RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<TwoctwopPacoNonUiResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;
        let result = response.merged_result();
        let api_response = response.api_response.clone();
        let (status, txn_id, ref_id, prior) =
            extract_status(result, AttemptStatus::CaptureInitiated);

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

impl TryFrom<ResponseRouterData<TwoctwopPacoNonUiResponse, Self>>
    for RouterDataV2<VoidPC, PaymentFlowData, PaymentsCancelPostCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<TwoctwopPacoNonUiResponse, Self>,
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

impl TryFrom<ResponseRouterData<TwoctwopPacoNonUiResponse, Self>>
    for RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<TwoctwopPacoNonUiResponse, Self>,
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

impl TryFrom<ResponseRouterData<TwoctwopPacoNonUiResponse, Self>>
    for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<TwoctwopPacoNonUiResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;
        // PACO's `/Refund/refund` returns the result fields flat on `data`,
        // not nested under `paymentResult`. Use `flat_data_block()` so the
        // shared status-mapping helpers still work on that shape.
        let result = response.flat_data_block();

        let refund_status = match result.as_ref().and_then(|b| b.payment_status_info.as_ref()) {
            Some(info) => map_refund_status(&info.payment_status, &info.payment_step),
            None => RefundStatus::Pending,
        };

        let connector_refund_id = result
            .as_ref()
            .and_then(|b| b.invoice_no2c2p.clone())
            .unwrap_or_else(|| router_data.request.refund_id.clone());

        if refund_status == RefundStatus::Failure {
            let (code, message) = error_code_message(
                &response.api_response,
                &result.and_then(|b| b.prior_payment_response_details),
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

fn deserialize_inquiry_data<'de, D>(deserializer: D) -> Result<Option<PacoInquiryData>, D::Error>
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TwoctwopPacoPSyncInquiryResponse(pub TwoctwopPacoInquiryResponse);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TwoctwopPacoRSyncInquiryResponse(pub TwoctwopPacoInquiryResponse);

impl TryFrom<ResponseRouterData<TwoctwopPacoPSyncInquiryResponse, Self>>
    for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<TwoctwopPacoPSyncInquiryResponse, Self>,
    ) -> Result<Self, Self::Error> {
        Self::try_from(ResponseRouterData {
            response: item.response.0,
            router_data: item.router_data,
            http_code: item.http_code,
        })
    }
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

impl TryFrom<ResponseRouterData<TwoctwopPacoRSyncInquiryResponse, Self>>
    for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<TwoctwopPacoRSyncInquiryResponse, Self>,
    ) -> Result<Self, Self::Error> {
        Self::try_from(ResponseRouterData {
            response: item.response.0,
            router_data: item.router_data,
            http_code: item.http_code,
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
    let api_msg = api_response
        .as_ref()
        .and_then(|a| a.response_description.clone());
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
            aud: PACO_AUDIENCE,
            company_api_key: access_token,
            iat: now,
            nbf: now,
            exp: now + PACO_JWT_TTL_SECONDS,
            request,
        }
    }
}

// Wire-envelope encode/decode lives on the connector struct itself, in
// `preprocess_request_bytes` / `preprocess_response_bytes` (see
// `twoctwop_paco.rs::create_all_prerequisites!`). The standalone helpers
// previously exposed here (`build_jose_envelope` / `decode_jose_response`)
// are no longer needed now that every flow runs through the framework's
// `preprocess_request: true, preprocess_response: true` macro path.

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


// ---------- Authenticate response → RouterDataV2 ----------

impl<T: PaymentMethodDataTypes> TryFrom<ResponseRouterData<TwoctwopPacoNonUiResponse, Self>>
    for RouterDataV2<
        Authenticate,
        PaymentFlowData,
        PaymentsAuthenticateData<T>,
        PaymentsResponseData,
    >
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<TwoctwopPacoNonUiResponse, Self>,
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
            // PACO returns aresACSChallenge with at least the acsURL when a
            // challenge is required; creq may be absent on some 3DS-method-data
            // responses. Use empty string defaults so we still surface the
            // form to the orchestrator.
            let acs_url = challenge.acs_url.clone().unwrap_or_default();
            let creq = challenge.creq.clone().unwrap_or_default();
            tracing::debug!(
                acs_url = %acs_url,
                "twoctwop_paco: Authenticate requires ACS challenge"
            );
            let mut form_fields: HashMap<String, String> = HashMap::new();
            form_fields.insert("creq".to_string(), creq);
            if let Some(session_data) = &challenge.three_ds_session_data {
                form_fields.insert("threeDSSessionData".to_string(), session_data.clone());
            }
            let redirect = Box::new(RedirectForm::Form {
                endpoint: acs_url,
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
            // AuthenticationPending so the orchestrator can fall through
            // to PSync (which polls the Inquiry endpoint) to retrieve the
            // final post-3DS state.
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

// ============================================================================
// TryFrom impls — used by the macro-driven bridge to construct each flow's
// typed request body. Each impl extracts auth from `connector_config` then
// delegates to the existing `build_*_request` helper, wrapping in the
// per-flow newtype where the wire body is shared (VoidPC reuses Void's body,
// Authenticate reuses the card-Authorize body).
// ============================================================================

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        TwoctwopPacoRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for TwoctwopPacoAuthorizeRequest
{
    type Error = error_stack::Report<errors::IntegrationError>;

    fn try_from(
        item: TwoctwopPacoRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = TwoctwopPacoAuthType::try_from(&item.router_data.connector_config)?;
        build_authorize_request(&item.router_data, &auth)
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        TwoctwopPacoRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    > for TwoctwopPacoCaptureRequest
{
    type Error = error_stack::Report<errors::IntegrationError>;

    fn try_from(
        item: TwoctwopPacoRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = TwoctwopPacoAuthType::try_from(&item.router_data.connector_config)?;
        build_capture_request(&item.router_data, &auth)
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        TwoctwopPacoRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    > for TwoctwopPacoVoidRequest
{
    type Error = error_stack::Report<errors::IntegrationError>;

    fn try_from(
        item: TwoctwopPacoRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = TwoctwopPacoAuthType::try_from(&item.router_data.connector_config)?;
        build_void_request(&item.router_data, &auth)
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        TwoctwopPacoRouterData<
            RouterDataV2<
                VoidPC,
                PaymentFlowData,
                PaymentsCancelPostCaptureData,
                PaymentsResponseData,
            >,
            T,
        >,
    > for TwoctwopPacoVoidPcRequest
{
    type Error = error_stack::Report<errors::IntegrationError>;

    fn try_from(
        item: TwoctwopPacoRouterData<
            RouterDataV2<
                VoidPC,
                PaymentFlowData,
                PaymentsCancelPostCaptureData,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = TwoctwopPacoAuthType::try_from(&item.router_data.connector_config)?;
        Ok(Self(build_void_pc_request(&item.router_data, &auth)?))
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        TwoctwopPacoRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    > for TwoctwopPacoRefundRequest
{
    type Error = error_stack::Report<errors::IntegrationError>;

    fn try_from(
        item: TwoctwopPacoRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = TwoctwopPacoAuthType::try_from(&item.router_data.connector_config)?;
        build_refund_request(&item.router_data, &auth)
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        TwoctwopPacoRouterData<
            RouterDataV2<
                Authenticate,
                PaymentFlowData,
                PaymentsAuthenticateData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for TwoctwopPacoAuthenticateRequest
{
    type Error = error_stack::Report<errors::IntegrationError>;

    fn try_from(
        item: TwoctwopPacoRouterData<
            RouterDataV2<
                Authenticate,
                PaymentFlowData,
                PaymentsAuthenticateData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = TwoctwopPacoAuthType::try_from(&item.router_data.connector_config)?;
        Ok(Self(build_authenticate_request(&item.router_data, &auth)?))
    }
}

// ============================================================================
// Response newtype → RouterDataV2 shim TryFrom impls. Each unwraps the
// flow-distinct newtype and delegates to the existing
// `TryFrom<ResponseRouterData<TwoctwopPacoNonUiResponse, _>>` impl that holds
// the actual decoding logic. Keeping the logic in the inner-type impl avoids
// duplicating ~30 lines of status/auth/error mapping per flow.
// ============================================================================

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<ResponseRouterData<TwoctwopPacoAuthorizeResponse, Self>>
    for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<TwoctwopPacoAuthorizeResponse, Self>,
    ) -> Result<Self, Self::Error> {
        Self::try_from(ResponseRouterData {
            response: item.response.0,
            router_data: item.router_data,
            http_code: item.http_code,
        })
    }
}

impl TryFrom<ResponseRouterData<TwoctwopPacoCaptureResponse, Self>>
    for RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<TwoctwopPacoCaptureResponse, Self>,
    ) -> Result<Self, Self::Error> {
        Self::try_from(ResponseRouterData {
            response: item.response.0,
            router_data: item.router_data,
            http_code: item.http_code,
        })
    }
}

impl TryFrom<ResponseRouterData<TwoctwopPacoVoidResponse, Self>>
    for RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<TwoctwopPacoVoidResponse, Self>,
    ) -> Result<Self, Self::Error> {
        Self::try_from(ResponseRouterData {
            response: item.response.0,
            router_data: item.router_data,
            http_code: item.http_code,
        })
    }
}

impl TryFrom<ResponseRouterData<TwoctwopPacoVoidPcResponse, Self>>
    for RouterDataV2<VoidPC, PaymentFlowData, PaymentsCancelPostCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<TwoctwopPacoVoidPcResponse, Self>,
    ) -> Result<Self, Self::Error> {
        Self::try_from(ResponseRouterData {
            response: item.response.0,
            router_data: item.router_data,
            http_code: item.http_code,
        })
    }
}

impl TryFrom<ResponseRouterData<TwoctwopPacoRefundResponse, Self>>
    for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<TwoctwopPacoRefundResponse, Self>,
    ) -> Result<Self, Self::Error> {
        Self::try_from(ResponseRouterData {
            response: item.response.0,
            router_data: item.router_data,
            http_code: item.http_code,
        })
    }
}

impl<T: PaymentMethodDataTypes>
    TryFrom<ResponseRouterData<TwoctwopPacoAuthenticateResponse, Self>>
    for RouterDataV2<
        Authenticate,
        PaymentFlowData,
        PaymentsAuthenticateData<T>,
        PaymentsResponseData,
    >
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<TwoctwopPacoAuthenticateResponse, Self>,
    ) -> Result<Self, Self::Error> {
        Self::try_from(ResponseRouterData {
            response: item.response.0,
            router_data: item.router_data,
            http_code: item.http_code,
        })
    }
}
