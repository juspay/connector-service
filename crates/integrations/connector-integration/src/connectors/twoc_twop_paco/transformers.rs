use std::collections::HashMap;

use common_enums::{AttemptStatus, Currency, RefundStatus};
use common_utils::{
    consts::{NO_ERROR_CODE, NO_ERROR_MESSAGE},
    crypto::jose::JoseConfig,
    request::Method,
    types::{FloatMajorUnit, FloatMajorUnitForConnector, MinorUnit},
};
use domain_types::{
    connector_flow::{Authenticate, Authorize, Capture, PSync, RSync, Refund, Void, VoidPC},
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

use crate::{connectors::twoc_twop_paco::TwocTwopPacoRouterData, types::ResponseRouterData};

const PACO_LANGUAGE: &str = "en-US";
const PACO_CARD_TYPE_CREDIT: &str = "credit";
const PACO_CARD_TYPE_DEBIT: &str = "debit";
const PACO_REFUND_MAKER_ID: &str = "merchant";
const PACO_KID_HEX_LEN: usize = 32;
const PACO_OFFICE_ID_MAX_LEN: usize = 20;
/// Audience claim PACO requires on every JWT envelope.
pub const PACO_AUDIENCE: &str = "PacoAudience";
/// TTL applied to outgoing JWT envelopes. PACO's published sample script
/// uses 5 minutes; anything past that returns a "JWT expired" error.
const PACO_JWT_TTL_SECONDS: i64 = 300;
/// 2C2P JOSE / config reference for error doc_url surfaces.
const PACO_INTEGRATION_DOC_URL: &str =
    "https://developer.2c2p.com/docs/getting-started-with-payment-air-controller-paco";

/// PACO finalised-status response code prefix used by every successful response.
pub const PACO_RESPONSE_CODE_SUCCESS: &str = "PC-B050000";

#[derive(Debug, Clone, Copy, Serialize)]
pub enum PacoPaymentType {
    CC,
    #[serde(rename = "WALLET-GCASH")]
    WalletGcash,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub enum PacoRequest3dsFlag {
    Y,
    N,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub enum PacoDeviceCategory {
    M,
    P,
}

#[derive(Debug, Clone)]
pub struct TwocTwopPacoAuthType {
    pub access_token: Secret<String>,
    /// Expected `aud` on PACO response JWTs. Defaults to `access_token`.
    pub response_audience: Secret<String>,
    pub jose_cfg: JoseConfig,
}

impl TryFrom<&ConnectorSpecificConfig> for TwocTwopPacoAuthType {
    type Error = error_stack::Report<errors::IntegrationError>;

    fn try_from(value: &ConnectorSpecificConfig) -> Result<Self, Self::Error> {
        match value {
            ConnectorSpecificConfig::TwocTwopPaco {
                access_token,
                paco_kid,
                merchant_signing_private_key,
                merchant_encryption_private_key,
                paco_signing_public_key,
                paco_encryption_public_key,
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
                            doc_url: Some(PACO_INTEGRATION_DOC_URL.to_string()),
                            additional_context: Some(format!("JoseConfig validation failed: {err}")),
                        },
                    }
                })?;

                Ok(Self {
                    access_token: access_token.clone(),
                    response_audience: response_audience
                        .clone()
                        .unwrap_or_else(|| access_token.clone()),
                    jose_cfg,
                })
            }
            _ => Err(errors::IntegrationError::FailedToObtainAuthType {
                context: errors::IntegrationErrorContext {
                    suggested_action: Some(
                        "Configure the connector with the TwocTwopPaco auth variant.".to_string(),
                    ),
                    doc_url: None,
                    additional_context: Some(
                        "Expected ConnectorSpecificConfig::TwocTwopPaco.".to_string(),
                    ),
                },
            }
            .into()),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiRequestEnvelope {
    /// PACO requires a unique id per request; it echoes back in
    /// `apiResponse.responseToRequestMessageId` for correlation. UUID v4
    /// matches 2C2P's sample-code convention.
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
    pub amount: FloatMajorUnit,
}

impl PacoTransactionAmount {
    fn new(minor_amount: MinorUnit, currency: Currency) -> Result<Self, errors::IntegrationError> {
        let decimals = currency
            .number_of_digits_after_decimal_point()
            .map_err(|_| errors::IntegrationError::InvalidDataFormat {
                field_name: "currency",
                context: errors::IntegrationErrorContext {
                    suggested_action: Some(
                        "Use an ISO 4217 currency PACO accepts (e.g. PHP, USD).".to_string(),
                    ),
                    doc_url: Some(PACO_INTEGRATION_DOC_URL.to_string()),
                    additional_context: Some(format!(
                        "Currency {currency:?} not supported for amount conversion"
                    )),
                },
            })?;
        let raw = minor_amount.get_amount_as_i64();
        let amount_text = format!("{raw:0>12}");
        let amount = <FloatMajorUnitForConnector as common_utils::types::AmountConvertor>::convert(
            &FloatMajorUnitForConnector,
            minor_amount,
            currency,
        )
        .map_err(|err| errors::IntegrationError::InvalidDataFormat {
            field_name: "amount",
            context: errors::IntegrationErrorContext {
                suggested_action: Some(
                    "Verify the request `amount` is a positive integer minor-unit value."
                        .to_string(),
                ),
                doc_url: Some(PACO_INTEGRATION_DOC_URL.to_string()),
                additional_context: Some(format!(
                    "Failed to convert minor amount to FloatMajorUnit: {err}"
                )),
            },
        })?;
        Ok(Self {
            amount_text,
            currency_code: currency,
            decimal_places: decimals,
            amount,
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

/// EMV 3DS 2.0 device fingerprint sent to the issuer ACS. Omitting it forces
/// a step-up challenge since the ACS has nothing to risk-evaluate.
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
pub struct TwocTwopPacoCardAuthorizeRequest {
    pub api_request: ApiRequestEnvelope,
    pub office_id: Secret<String>,
    pub order_no: String,
    pub product_description: String,
    pub payment_type: PacoPaymentType,
    pub transaction_amount: PacoTransactionAmount,
    /// PACO expects the plural-with-capitals form `notificationURLs`.
    #[serde(rename = "notificationURLs")]
    pub notification_urls: PacoNotificationUrls,
    pub credit_card_details: PacoCreditCardDetails,
    #[serde(rename = "request3dsFlag")]
    pub request3ds_flag: PacoRequest3dsFlag,
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

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PacoDeviceDetails {
    pub device_category: PacoDeviceCategory,
    pub user_agent: String,
}

impl PacoDeviceDetails {
    fn default_browser() -> Self {
        Self {
            device_category: PacoDeviceCategory::P,
            user_agent: "Mozilla/5.0 hyperswitch-prism".to_string(),
        }
    }

    /// Derive deviceCategory from the user-agent string. Mobile UAs that
    /// contain "Mobile" / "Android" / "iPhone" / "iPad" map to `M`; everything
    /// else to `P`.
    pub fn from_user_agent(user_agent: String) -> Self {
        let lower = user_agent.to_ascii_lowercase();
        let is_mobile = lower.contains("mobile")
            || lower.contains("android")
            || lower.contains("iphone")
            || lower.contains("ipad");
        Self {
            device_category: if is_mobile {
                PacoDeviceCategory::M
            } else {
                PacoDeviceCategory::P
            },
            user_agent,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TwocTwopPacoWalletAuthorizeRequest {
    pub api_request: ApiRequestEnvelope,
    pub office_id: Secret<String>,
    pub order_no: String,
    pub product_description: String,
    /// `WALLET-GCASH` returns the GCash app URL directly (no PACO hosted page).
    pub payment_type: PacoPaymentType,
    pub transaction_amount: PacoTransactionAmount,
    #[serde(rename = "notificationURLs")]
    pub notification_urls: PacoNotificationUrls,
    pub device_details: PacoDeviceDetails,
}

// PACO has two Authorize endpoints with distinct schemas; the untagged enum
// keeps the on-wire JSON identical to what each per-variant builder emits.
// Card variant is ~656 B (card + browser info); boxing would double-allocate
// every request, so the larger short-lived enum is acceptable.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum TwocTwopPacoAuthorizeRequest {
    Card(TwocTwopPacoCardAuthorizeRequest),
    Wallet(TwocTwopPacoWalletAuthorizeRequest),
}

#[derive(Debug, Clone, Serialize)]
#[serde(transparent)]
pub struct TwocTwopPacoVoidPcRequest(pub TwocTwopPacoVoidRequest);

#[derive(Debug, Clone, Serialize)]
#[serde(transparent)]
pub struct TwocTwopPacoAuthenticateRequest(pub TwocTwopPacoCardAuthorizeRequest);

// Per-flow newtypes around the shared wire shape so each `Bridge` gets a
// distinct templating slot. `#[serde(transparent)]` keeps the wire identical.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TwocTwopPacoAuthorizeResponse(pub TwocTwopPacoNonUiResponse);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TwocTwopPacoCaptureResponse(pub TwocTwopPacoNonUiResponse);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TwocTwopPacoVoidResponse(pub TwocTwopPacoNonUiResponse);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TwocTwopPacoVoidPcResponse(pub TwocTwopPacoNonUiResponse);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TwocTwopPacoRefundResponse(pub TwocTwopPacoNonUiResponse);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TwocTwopPacoAuthenticateResponse(pub TwocTwopPacoNonUiResponse);

pub fn build_authorize_request<T>(
    item: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    _auth: &TwocTwopPacoAuthType,
) -> Result<TwocTwopPacoAuthorizeRequest, error_stack::Report<errors::IntegrationError>>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize,
{
    let (office_id, _merchant_id) =
        extract_paco_merchant_identifiers(&item.resource_common_data.connector_feature_data)?;
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
                PacoRequest3dsFlag::Y
            } else {
                PacoRequest3dsFlag::N
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
            let body = TwocTwopPacoCardAuthorizeRequest {
                api_request: ApiRequestEnvelope::new(),
                office_id,
                order_no,
                product_description: description,
                payment_type: PacoPaymentType::CC,
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
            Ok(TwocTwopPacoAuthorizeRequest::Card(body))
        }
        PaymentMethodData::Wallet(WalletData::GcashRedirect(_)) => {
            let device_details = item
                .request
                .browser_info
                .as_ref()
                .and_then(|bi| bi.user_agent.clone())
                .map(|ua| PacoDeviceDetails {
                    device_category: PacoDeviceCategory::P,
                    user_agent: ua,
                })
                .unwrap_or_else(PacoDeviceDetails::default_browser);
            let body = TwocTwopPacoWalletAuthorizeRequest {
                api_request: ApiRequestEnvelope::new(),
                office_id,
                order_no,
                product_description: description,
                payment_type: PacoPaymentType::WalletGcash,
                transaction_amount: amount,
                notification_urls,
                device_details,
            };
            Ok(TwocTwopPacoAuthorizeRequest::Wallet(body))
        }
        _ => Err(errors::IntegrationError::NotImplemented(
            "Selected payment method through TwocTwopPaco".to_string(),
            errors::IntegrationErrorContext::default(),
        )
        .into()),
    }
}

pub fn build_authenticate_request<T>(
    item: &RouterDataV2<
        Authenticate,
        PaymentFlowData,
        PaymentsAuthenticateData<T>,
        PaymentsResponseData,
    >,
    _auth: &TwocTwopPacoAuthType,
) -> Result<TwocTwopPacoCardAuthorizeRequest, error_stack::Report<errors::IntegrationError>>
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

    let (office_id, _merchant_id) =
        extract_paco_merchant_identifiers(&item.resource_common_data.connector_feature_data)?;
    match item.request.payment_method_data.as_ref() {
        Some(PaymentMethodData::Card(card)) => {
            let card_type = match card.card_type.as_deref() {
                Some(t) if t.eq_ignore_ascii_case("debit") => PACO_CARD_TYPE_DEBIT,
                _ => PACO_CARD_TYPE_CREDIT,
            };
            let mmyy = card.get_card_expiry_month_year_2_digit_with_delimiter(String::new())?;
            Ok(TwocTwopPacoCardAuthorizeRequest {
                api_request: ApiRequestEnvelope::new(),
                office_id,
                order_no,
                product_description: description,
                payment_type: PacoPaymentType::CC,
                transaction_amount: amount,
                notification_urls,
                credit_card_details: PacoCreditCardDetails {
                    card_number: Secret::new(card.card_number.peek().to_string()),
                    card_expiry_mmyy: mmyy,
                    cvv_code: card.card_cvc.clone(),
                    card_holder_name: card.get_optional_cardholder_name(),
                    card_type,
                },
                // Authenticate forces 3DS regardless of the upstream flag.
                request3ds_flag: PacoRequest3dsFlag::Y,
                browser_info,
                device_details,
            })
        }
        _ => Err(errors::IntegrationError::NotImplemented(
            "Selected payment method through TwocTwopPaco Authenticate".to_string(),
            errors::IntegrationErrorContext::default(),
        )
        .into()),
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PacoSettlementAmount {
    pub amount_text: String,
    pub currency_code: Currency,
    pub decimal_places: u8,
    pub amount: FloatMajorUnit,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TwocTwopPacoCaptureRequest {
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
    _auth: &TwocTwopPacoAuthType,
) -> Result<TwocTwopPacoCaptureRequest, error_stack::Report<errors::IntegrationError>> {
    let (office_id, _merchant_id) =
        extract_paco_merchant_identifiers(&item.resource_common_data.connector_feature_data)?;
    let invoice_no = item.request.get_connector_transaction_id()?;
    let amount =
        PacoTransactionAmount::new(item.request.minor_amount_to_capture, item.request.currency)?;
    Ok(TwocTwopPacoCaptureRequest {
        api_request: ApiRequestEnvelope::new(),
        office_id,
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

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TwocTwopPacoVoidRequest {
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
    _auth: &TwocTwopPacoAuthType,
) -> Result<TwocTwopPacoVoidRequest, error_stack::Report<errors::IntegrationError>> {
    let (office_id, _merchant_id) =
        extract_paco_merchant_identifiers(&item.resource_common_data.connector_feature_data)?;
    Ok(TwocTwopPacoVoidRequest {
        api_request: ApiRequestEnvelope::new(),
        office_id,
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
    _auth: &TwocTwopPacoAuthType,
) -> Result<TwocTwopPacoVoidRequest, error_stack::Report<errors::IntegrationError>> {
    let (office_id, _merchant_id) =
        extract_paco_merchant_identifiers(&item.resource_common_data.connector_feature_data)?;
    Ok(TwocTwopPacoVoidRequest {
        api_request: ApiRequestEnvelope::new(),
        office_id,
        order_no: item
            .resource_common_data
            .connector_request_reference_id
            .clone(),
        invoice_no2c2p: item.request.connector_transaction_id.clone(),
        cancellation_reason: item.request.cancellation_reason.clone(),
    })
}

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

/// `username` is recorded in PACO's audit log. Defaults to `"merchant"`; pass
/// `{"maker_id":"<operator>"}` in `refund_metadata` for a traceable id.
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
pub struct TwocTwopPacoRefundRequest {
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
    _auth: &TwocTwopPacoAuthType,
) -> Result<TwocTwopPacoRefundRequest, error_stack::Report<errors::IntegrationError>> {
    let (office_id, _merchant_id) =
        extract_paco_merchant_identifiers(&item.resource_common_data.connector_feature_data)?;
    let amount =
        PacoTransactionAmount::new(item.request.minor_refund_amount, item.request.currency)?;
    // PACO matches refunds by the original Authorize orderNo, but the
    // orchestrator overwrites `connector_request_reference_id` with the
    // refund id — so the caller must pass it through `refund_metadata`
    // (preferred) or `connector_feature_data` (fallback).
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
                         e.g. {\"original_order_no\":\"<auth orderNo>\",\"maker_id\":\"<operator id>\"}."
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
    let maker_id = item
        .request
        .refund_connector_metadata
        .as_ref()
        .and_then(extract_paco_maker_id)
        .or_else(|| {
            item.request
                .connector_feature_data
                .as_ref()
                .and_then(extract_paco_maker_id)
        })
        .unwrap_or_else(|| PACO_REFUND_MAKER_ID.to_string());
    Ok(TwocTwopPacoRefundRequest {
        api_request: ApiRequestEnvelope::new(),
        office_id,
        order_no: original_order_no,
        product_description: item.request.reason.clone(),
        refund_amount: amount,
        local_maker_checker: PacoMakerChecker {
            maker: PacoHumanActor { username: maker_id },
        },
    })
}

/// Pull `(office_id, merchant_id)` from per-request `connector_feature_data`.
/// Both are required — PACO has no implicit defaults and signing fails fast
/// rather than silently routing to the wrong office. Mirrors the Axisbank
/// `extract_merchant_identifiers_from_metadata` pattern.
pub fn extract_paco_merchant_identifiers(
    feature_data: &Option<common_utils::SecretSerdeValue>,
) -> Result<(Secret<String>, Secret<String>), error_stack::Report<errors::IntegrationError>> {
    let meta =
        feature_data
            .as_ref()
            .ok_or_else(|| errors::IntegrationError::MissingRequiredField {
                field_name: "connector_feature_data",
                context: errors::IntegrationErrorContext {
                    suggested_action: Some(
                        "Set `connector_feature_data` to a JSON object containing \
                     `office_id` and `merchant_id`."
                            .to_string(),
                    ),
                    doc_url: None,
                    additional_context: None,
                },
            })?;
    let value = meta.peek();
    let obj = value
        .as_object()
        .ok_or_else(|| errors::IntegrationError::InvalidDataFormat {
            field_name: "connector_feature_data",
            context: errors::IntegrationErrorContext {
                suggested_action: Some("connector_feature_data must be a JSON object.".to_string()),
                doc_url: None,
                additional_context: None,
            },
        })?;
    let office_id = obj
        .get("office_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| errors::IntegrationError::MissingRequiredField {
            field_name: "connector_feature_data.office_id",
            context: errors::IntegrationErrorContext {
                suggested_action: Some(
                    "Provide office_id (1..=20 chars) in connector_feature_data.".to_string(),
                ),
                doc_url: None,
                additional_context: None,
            },
        })?;
    if office_id.len() > PACO_OFFICE_ID_MAX_LEN {
        return Err(errors::IntegrationError::InvalidDataFormat {
            field_name: "connector_feature_data.office_id",
            context: errors::IntegrationErrorContext {
                suggested_action: Some("office_id must be 1..=20 characters.".to_string()),
                doc_url: None,
                additional_context: None,
            },
        }
        .into());
    }
    let merchant_id = obj
        .get("merchant_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| errors::IntegrationError::MissingRequiredField {
            field_name: "connector_feature_data.merchant_id",
            context: errors::IntegrationErrorContext {
                suggested_action: Some(
                    "Provide merchant_id in connector_feature_data.".to_string(),
                ),
                doc_url: None,
                additional_context: None,
            },
        })?;
    Ok((
        Secret::new(office_id.to_string()),
        Secret::new(merchant_id.to_string()),
    ))
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

/// Pull the optional `maker_id` (audit-log operator username) from a refund
/// metadata SecretSerdeValue. Only valid when metadata is an object.
fn extract_paco_maker_id(meta: &common_utils::SecretSerdeValue) -> Option<String> {
    let value = meta.peek();
    let obj = value.as_object()?;
    let s = obj.get("maker_id").and_then(|v| v.as_str())?;
    (!s.is_empty()).then(|| s.to_string())
}

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
        // (I, *) = payment in-flight (hosted-page / ACS challenge pending).
        (PacoPaymentStatus::I, _) => AttemptStatus::AuthenticationPending,
        (PacoPaymentStatus::Pcps, PacoPaymentStep::GP) => AttemptStatus::AuthenticationPending,
        (PacoPaymentStatus::P, PacoPaymentStep::IN) => AttemptStatus::Authorizing,
        // P/RP (Pending Refund): the original auth is still the canonical state.
        (PacoPaymentStatus::P, PacoPaymentStep::RP) => AttemptStatus::Authorizing,
        (PacoPaymentStatus::F, _) => AttemptStatus::Failure,
        (s, st) => {
            tracing::warn!(
                target: "twoc_twop_paco",
                paymentStatus = ?s,
                paymentStep = ?st,
                "twoc_twop_paco: unknown (paymentStatus, paymentStep) pair — mapped to AttemptStatus::Unknown"
            );
            AttemptStatus::Unknown
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
                target: "twoc_twop_paco",
                paymentStatus = ?s,
                paymentStep = ?st,
                "twoc_twop_paco: unknown (paymentStatus, paymentStep) pair — defaulting refund to Failure"
            );
            RefundStatus::Failure
        }
    }
}

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
    /// `/nonUi` wallet flows (e.g. WALLET-GCASH) return the PSP-direct URL
    /// here under `data.webPaymentResult.webPaymentUrl`.
    #[serde(default)]
    pub web_payment_url: Option<String>,
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
    /// `/Payment/nonUi` wallet flows (e.g. `paymentType: WALLET-GCASH`)
    /// return their pending payment block here. Same field set as
    /// `paymentResult` but carries `webPaymentUrl` instead of `paymentPage`.
    #[serde(default)]
    pub web_payment_result: Option<PacoPaymentResultBlock>,
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
pub struct TwocTwopPacoNonUiResponse {
    #[serde(default)]
    pub data: Option<PacoData>,
    #[serde(default)]
    pub api_response: Option<PacoApiResponse>,
    #[serde(default)]
    pub version: Option<String>,
}

impl TwocTwopPacoNonUiResponse {
    /// PACO emits the per-flow status block under one of three keys depending
    /// on flow / endpoint:
    /// - `paymentResult` (terminal — card auth, capture, void)
    /// - `paymentIncompleteResult` (in-flight — pending CC auth)
    /// - `webPaymentResult` (`/nonUi` wallet flow, e.g. WALLET-GCASH)
    ///
    /// All three share the same shape, so we merge into one accessor.
    pub fn merged_result(&self) -> Option<&PacoPaymentResultBlock> {
        self.data.as_ref().and_then(|d| {
            d.payment_result
                .as_ref()
                .or(d.payment_incomplete_result.as_ref())
                .or(d.web_payment_result.as_ref())
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
                web_payment_url: None,
                ares_acs_challenge: None,
                credit_card_authenticated_details: None,
            });
        }
        None
    }
}

impl<F, T> TryFrom<ResponseRouterData<TwocTwopPacoNonUiResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize,
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<TwocTwopPacoNonUiResponse, Self>,
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
                                        "twoc_twop_paco: paymentStatusInfo missing on Authorize response"
                                            .to_string(),
                                    ),
                                )
                            )
                        })?;
                    let status = map_attempt_status(&info.payment_status, &info.payment_step);
                    // PACO publishes the redirect URL in four possible spots
                    // depending on flow:
                    //   - `data.webPaymentResult.webPaymentUrl`
                    //     (/nonUi wallet, direct PSP URL — current GCash path)
                    //   - `data.paymentPage.paymentPageUrl`
                    //     (legacy /prepaymentUi hosted-page sibling)
                    //   - `data.<result>.paymentPage.paymentPageUrl` (nested)
                    //   - `data.<result>.paymentPageUrl` (flat fallback)
                    let url = block
                        .web_payment_url
                        .clone()
                        .or_else(|| {
                            response
                                .data
                                .as_ref()
                                .and_then(|d| d.payment_page.as_ref())
                                .and_then(|p| p.payment_page_url.clone())
                        })
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

impl TryFrom<ResponseRouterData<TwocTwopPacoNonUiResponse, Self>>
    for RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<TwocTwopPacoNonUiResponse, Self>,
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

impl TryFrom<ResponseRouterData<TwocTwopPacoNonUiResponse, Self>>
    for RouterDataV2<VoidPC, PaymentFlowData, PaymentsCancelPostCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<TwocTwopPacoNonUiResponse, Self>,
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

impl TryFrom<ResponseRouterData<TwocTwopPacoNonUiResponse, Self>>
    for RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<TwocTwopPacoNonUiResponse, Self>,
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

impl TryFrom<ResponseRouterData<TwocTwopPacoNonUiResponse, Self>>
    for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<TwocTwopPacoNonUiResponse, Self>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TwocTwopPacoInquiryResponse {
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
pub struct TwocTwopPacoPSyncInquiryResponse(pub TwocTwopPacoInquiryResponse);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TwocTwopPacoRSyncInquiryResponse(pub TwocTwopPacoInquiryResponse);

impl TryFrom<ResponseRouterData<TwocTwopPacoPSyncInquiryResponse, Self>>
    for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<TwocTwopPacoPSyncInquiryResponse, Self>,
    ) -> Result<Self, Self::Error> {
        Self::try_from(ResponseRouterData {
            response: item.response.0,
            router_data: item.router_data,
            http_code: item.http_code,
        })
    }
}

impl TryFrom<ResponseRouterData<TwocTwopPacoInquiryResponse, Self>>
    for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<TwocTwopPacoInquiryResponse, Self>,
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

impl TryFrom<ResponseRouterData<TwocTwopPacoRSyncInquiryResponse, Self>>
    for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<TwocTwopPacoRSyncInquiryResponse, Self>,
    ) -> Result<Self, Self::Error> {
        Self::try_from(ResponseRouterData {
            response: item.response.0,
            router_data: item.router_data,
            http_code: item.http_code,
        })
    }
}

impl TryFrom<ResponseRouterData<TwocTwopPacoInquiryResponse, Self>>
    for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<TwocTwopPacoInquiryResponse, Self>,
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
pub struct TwocTwopPacoErrorResponse {
    #[serde(default)]
    pub api_response: Option<PacoApiResponse>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
}

impl TwocTwopPacoErrorResponse {
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
// `twoc_twop_paco.rs::create_all_prerequisites!`). The standalone helpers
// previously exposed here (`build_jose_envelope` / `decode_jose_response`)
// are no longer needed now that every flow runs through the framework's
// `preprocess_request: true, preprocess_response: true` macro path.

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

impl<T: PaymentMethodDataTypes> TryFrom<ResponseRouterData<TwocTwopPacoNonUiResponse, Self>>
    for RouterDataV2<
        Authenticate,
        PaymentFlowData,
        PaymentsAuthenticateData<T>,
        PaymentsResponseData,
    >
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<TwocTwopPacoNonUiResponse, Self>,
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
                "twoc_twop_paco: Authenticate returned failure"
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
                "twoc_twop_paco: Authenticate requires ACS challenge"
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
            "twoc_twop_paco: Authenticate response decoded"
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

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        TwocTwopPacoRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for TwocTwopPacoAuthorizeRequest
{
    type Error = error_stack::Report<errors::IntegrationError>;

    fn try_from(
        item: TwocTwopPacoRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = TwocTwopPacoAuthType::try_from(&item.router_data.connector_config)?;
        build_authorize_request(&item.router_data, &auth)
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        TwocTwopPacoRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    > for TwocTwopPacoCaptureRequest
{
    type Error = error_stack::Report<errors::IntegrationError>;

    fn try_from(
        item: TwocTwopPacoRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = TwocTwopPacoAuthType::try_from(&item.router_data.connector_config)?;
        build_capture_request(&item.router_data, &auth)
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        TwocTwopPacoRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    > for TwocTwopPacoVoidRequest
{
    type Error = error_stack::Report<errors::IntegrationError>;

    fn try_from(
        item: TwocTwopPacoRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = TwocTwopPacoAuthType::try_from(&item.router_data.connector_config)?;
        build_void_request(&item.router_data, &auth)
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        TwocTwopPacoRouterData<
            RouterDataV2<
                VoidPC,
                PaymentFlowData,
                PaymentsCancelPostCaptureData,
                PaymentsResponseData,
            >,
            T,
        >,
    > for TwocTwopPacoVoidPcRequest
{
    type Error = error_stack::Report<errors::IntegrationError>;

    fn try_from(
        item: TwocTwopPacoRouterData<
            RouterDataV2<
                VoidPC,
                PaymentFlowData,
                PaymentsCancelPostCaptureData,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = TwocTwopPacoAuthType::try_from(&item.router_data.connector_config)?;
        Ok(Self(build_void_pc_request(&item.router_data, &auth)?))
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        TwocTwopPacoRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    > for TwocTwopPacoRefundRequest
{
    type Error = error_stack::Report<errors::IntegrationError>;

    fn try_from(
        item: TwocTwopPacoRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = TwocTwopPacoAuthType::try_from(&item.router_data.connector_config)?;
        build_refund_request(&item.router_data, &auth)
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        TwocTwopPacoRouterData<
            RouterDataV2<
                Authenticate,
                PaymentFlowData,
                PaymentsAuthenticateData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for TwocTwopPacoAuthenticateRequest
{
    type Error = error_stack::Report<errors::IntegrationError>;

    fn try_from(
        item: TwocTwopPacoRouterData<
            RouterDataV2<
                Authenticate,
                PaymentFlowData,
                PaymentsAuthenticateData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = TwocTwopPacoAuthType::try_from(&item.router_data.connector_config)?;
        Ok(Self(build_authenticate_request(&item.router_data, &auth)?))
    }
}

// Shim TryFroms unwrap the newtype response and delegate to the inner-type
// decoder, avoiding ~30 lines of duplicated status/error mapping per flow.

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<ResponseRouterData<TwocTwopPacoAuthorizeResponse, Self>>
    for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<TwocTwopPacoAuthorizeResponse, Self>,
    ) -> Result<Self, Self::Error> {
        Self::try_from(ResponseRouterData {
            response: item.response.0,
            router_data: item.router_data,
            http_code: item.http_code,
        })
    }
}

impl TryFrom<ResponseRouterData<TwocTwopPacoCaptureResponse, Self>>
    for RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<TwocTwopPacoCaptureResponse, Self>,
    ) -> Result<Self, Self::Error> {
        Self::try_from(ResponseRouterData {
            response: item.response.0,
            router_data: item.router_data,
            http_code: item.http_code,
        })
    }
}

impl TryFrom<ResponseRouterData<TwocTwopPacoVoidResponse, Self>>
    for RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<TwocTwopPacoVoidResponse, Self>,
    ) -> Result<Self, Self::Error> {
        Self::try_from(ResponseRouterData {
            response: item.response.0,
            router_data: item.router_data,
            http_code: item.http_code,
        })
    }
}

impl TryFrom<ResponseRouterData<TwocTwopPacoVoidPcResponse, Self>>
    for RouterDataV2<VoidPC, PaymentFlowData, PaymentsCancelPostCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<TwocTwopPacoVoidPcResponse, Self>,
    ) -> Result<Self, Self::Error> {
        Self::try_from(ResponseRouterData {
            response: item.response.0,
            router_data: item.router_data,
            http_code: item.http_code,
        })
    }
}

impl TryFrom<ResponseRouterData<TwocTwopPacoRefundResponse, Self>>
    for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<TwocTwopPacoRefundResponse, Self>,
    ) -> Result<Self, Self::Error> {
        Self::try_from(ResponseRouterData {
            response: item.response.0,
            router_data: item.router_data,
            http_code: item.http_code,
        })
    }
}

impl<T: PaymentMethodDataTypes> TryFrom<ResponseRouterData<TwocTwopPacoAuthenticateResponse, Self>>
    for RouterDataV2<
        Authenticate,
        PaymentFlowData,
        PaymentsAuthenticateData<T>,
        PaymentsResponseData,
    >
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<TwocTwopPacoAuthenticateResponse, Self>,
    ) -> Result<Self, Self::Error> {
        Self::try_from(ResponseRouterData {
            response: item.response.0,
            router_data: item.router_data,
            http_code: item.http_code,
        })
    }
}
