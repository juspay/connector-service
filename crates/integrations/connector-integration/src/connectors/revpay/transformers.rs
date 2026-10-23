use std::str::FromStr;

use crate::types::ResponseRouterData;
use common_enums::{AttemptStatus, CardNetwork, CountryAlpha2, Currency, RefundStatus};
use common_utils::{
    consts::{NO_ERROR_CODE, NO_ERROR_MESSAGE},
    errors::ParsingError,
    pii::Email,
    types::MinorUnit,
};
use domain_types::{
    connector_flow::{Authorize, PSync, RSync, Refund},
    connector_types::{
        EventType, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData,
        RawConnectorStatus, RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData,
        ResponseId,
    },
    errors::{ConnectorError, IntegrationError, IntegrationErrorContext},
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes, RawCardNumber, WalletData},
    router_data::{ConnectorSpecificConfig, ErrorResponse, FlowStatus},
    router_data_v2::RouterDataV2,
    router_request_types::{
        AuthoriseIntegrityObject, PaymentSynIntegrityObject, RefundIntegrityObject,
        RefundSyncIntegrityObject,
    },
    router_response_types::RedirectForm,
};
use error_stack::{report, ResultExt};
use hyperswitch_masking::{ExposeInterface, PeekInterface, Secret};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

use crate::connectors::revpay::RevpayRouterData;

// =============================================================================
// AUTHENTICATION
// =============================================================================

/// Credentials from `ConnectorSpecificConfig::Revpay` (populated from a
/// `ConnectorAuthType::SignatureKey`).
#[derive(Debug, Clone)]
pub struct RevpayAuthType {
    /// revPAY Merchant ID (`Revpay_Merchant_ID`) — sent in the body. Config `merchant_id`.
    pub merchant_id: Secret<String>,
    /// Merchant Key — signature secret only, never transmitted. Config `merchant_key`.
    pub merchant_key: Secret<String>,
    /// `Key_Index` decimal string, sent in the body. Config `key_index`.
    pub key_index: Secret<String>,
}

impl TryFrom<&ConnectorSpecificConfig> for RevpayAuthType {
    type Error = error_stack::Report<IntegrationError>;

    fn try_from(auth_type: &ConnectorSpecificConfig) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorSpecificConfig::Revpay {
                merchant_id,
                merchant_key,
                key_index,
                ..
            } => Ok(Self {
                merchant_id: merchant_id.to_owned(),
                merchant_key: merchant_key.to_owned(),
                key_index: key_index.to_owned(),
            }),
            _ => Err(error_stack::report!(IntegrationError::FailedToObtainAuthType {
                context: IntegrationErrorContext {
                    suggested_action: Some(
                        "Configure the connector account with Revpay credentials".to_string(),
                    ),
                    doc_url: None,
                    additional_context: Some(
                        "ConnectorSpecificConfig variant mismatch: expected Revpay credentials but received credentials for a different connector; the request may have been routed to the wrong connector"
                            .to_string(),
                    ),
                }
            })),
        }
    }
}

// =============================================================================
// SIGNATURE
// =============================================================================

/// revPAY electronic signature: plain SHA-512 (NOT HMAC) over the Merchant Key
/// prepended to the raw concatenation of the message fields — no separators,
/// no field names, no URL-encoding. Output is the lowercase hex digest
/// (128 chars). Verified against the doc's known-answer vectors in tests below.
fn generate_revpay_signature(merchant_key: &str, fields: &[&str]) -> String {
    let preimage = std::iter::once(merchant_key)
        .chain(fields.iter().copied())
        .collect::<String>();
    hex::encode(Sha512::digest(preimage.as_bytes()))
}

// =============================================================================
// AMOUNT ENCODING
// =============================================================================

/// revPAY's `Amount` is a plain string: major units with exactly two decimal
/// places ("52.40"), whatever the currency's own ISO exponent, and the very
/// same bytes must appear in the JSON body and in the signature preimage.
/// `common_utils::types::StringTwoDecimalUnit` renders the implied-decimal
/// form instead ("5240"), so the conversion is done here in integer space —
/// no float hop.
pub fn format_revpay_amount(
    amount: MinorUnit,
    currency: Currency,
) -> Result<String, error_stack::Report<ParsingError>> {
    let exponent = currency
        .number_of_digits_after_decimal_point()
        .change_context(ParsingError::StructParseFailure(
            "currency decimal configuration",
        ))?;
    let scale = 10_i128.pow(u32::from(exponent));
    let minor = i128::from(amount.get_amount_as_i64());
    if minor < 0 {
        return Err(report!(ParsingError::StructParseFailure("Amount"))
            .attach_printable(format!("Amount `{minor}` is negative")));
    }
    let scaled = minor * 100;
    if scaled % scale != 0 {
        return Err(report!(ParsingError::StructParseFailure(
            "two-decimal amount"
        ))
        .attach_printable(format!(
            "{currency:?} minor amount {minor} has non-zero digits below the two decimals revPAY requires"
        )));
    }
    let units = scaled / scale;
    Ok(format!("{}.{:02}", units / 100, units % 100))
}

/// Inverse of [`format_revpay_amount`] — parses a connector-echoed `Amount`
/// back into framework minor units for the integrity object.
pub fn parse_revpay_amount(
    amount: &str,
    currency: Currency,
) -> Result<MinorUnit, error_stack::Report<ParsingError>> {
    let malformed = || {
        report!(ParsingError::StructParseFailure("two-decimal amount")).attach_printable(format!(
            "`{amount}` is not in revPAY's major-with-2-decimals form"
        ))
    };
    let exponent = currency
        .number_of_digits_after_decimal_point()
        .change_context(ParsingError::StructParseFailure(
            "currency decimal configuration",
        ))?;
    let scale = 10_i128.pow(u32::from(exponent));
    let (whole, fraction) = amount.split_once('.').ok_or_else(malformed)?;
    if whole.is_empty()
        || fraction.len() != 2
        || !whole.chars().all(|c| c.is_ascii_digit())
        || !fraction.chars().all(|c| c.is_ascii_digit())
    {
        return Err(malformed());
    }
    let whole_units: i128 = whole.parse::<i128>().map_err(|_| malformed())?;
    let fraction_units: i128 = fraction.parse::<i128>().map_err(|_| malformed())?;
    let wire: i128 = whole_units
        .checked_mul(100)
        .and_then(|value| value.checked_add(fraction_units))
        .ok_or_else(malformed)?;
    let minor = wire * scale;
    if minor % 100 != 0 {
        return Err(malformed());
    }
    i64::try_from(minor / 100)
        .map(MinorUnit::new)
        .map_err(|_| report!(ParsingError::DecimalToI64ConversionFailure))
}

// =============================================================================
// RESPONSE CODE
// =============================================================================

/// revPAY `Response_Code` wire enum ("00" success, "09" redirect, everything
/// else a declined/failed attempt).
///
/// A literal `#[serde(other)]` catch-all would drop the raw code, and the raw
/// code is exactly what belongs in `ErrorResponse.code` — so deserialization
/// is hand-rolled and the catch-all variant CARRIES the wire value. The
/// status mapping below stays exhaustive over named variants (no `_ =>`), so
/// adding a newly classified code forces a human decision here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevpayResponseCode {
    /// "00" — success; the sale is authorised and settled in one shot.
    Success,
    /// "09" — in progress; shopper must follow `Bank_Redirect_URL`.
    RedirectRequired,
    /// "99" — pending authorization (FPX B2B); the acquirer settles the
    /// authorisation asynchronously, so the attempt is still resolvable.
    PendingAuthorization,
    /// "76" — transaction not found. Classified apart from `Unknown` because
    /// its weight is flow-dependent: provably not chargeable on payment
    /// inquiry (§2.2), but NOT proof of a failed refund on RSync — revPAY
    /// 3.1.10 documents no refund-status inquiry, so a not-found refund
    /// reference may just mean the inquiry cannot see refunds at all (Flow 4
    /// of `grace/rulesbook/codegen/references/revpay/technical_specification.md`).
    TransactionNotFound,
    /// Any other documented or future code ("01", "30" signature mismatch,
    /// buyer-cancelled "17"/"1A"–"1L" variants, …): a failed attempt.
    Unknown(String),
}

impl RevpayResponseCode {
    fn as_str(&self) -> &str {
        match self {
            Self::Success => "00",
            Self::RedirectRequired => "09",
            Self::PendingAuthorization => "99",
            Self::TransactionNotFound => "76",
            Self::Unknown(raw) => raw.as_str(),
        }
    }

    /// Inquiry-side status mapping (§2.2). The redirect already happened on
    /// the Payment call, so on inquiry "09" is a shopper still in flight at
    /// the bank — Pending, not a fresh `AuthenticationPending`. "99" is
    /// pending authorization. Everything else is a failed attempt —
    /// "76" Transaction not found included: a payment revPAY cannot find is
    /// provably not chargeable (§2.2).
    fn psync_status(&self) -> AttemptStatus {
        match self {
            Self::Success => AttemptStatus::Charged,
            Self::RedirectRequired | Self::PendingAuthorization => AttemptStatus::Pending,
            Self::TransactionNotFound | Self::Unknown(_) => AttemptStatus::Failure,
        }
    }

    /// Refund-side status mapping (§2.5). The Refund API answers
    /// synchronously (immediate accept/reject), so only "00" proves the
    /// refund was accepted; every other code is a declined refund and the
    /// response transformer routes it into `Err(ErrorResponse)`.
    fn refund_status(&self) -> RefundStatus {
        match self {
            Self::Success => RefundStatus::Success,
            // A "76" on the Refund CALL itself is a synchronous not-found of
            // the original payment (§2.5) — a declined refund, correctly
            // terminal here. (RSync treats it differently; see below.)
            Self::RedirectRequired
            | Self::PendingAuthorization
            | Self::TransactionNotFound
            | Self::Unknown(_) => RefundStatus::Failure,
        }
    }

    /// Refund-sync status mapping (Flow 4). Unlike the synchronous Refund
    /// call, RSync is a status QUERY over the shared inquiry endpoint, so the
    /// in-flight codes "09"/"99" are resolvable intermediate states →
    /// Pending, exactly like `psync_status`. Only "00" proves the refund
    /// completed and only a failure code on a FOUND reference proves it
    /// failed. "76" is deliberately Pending, never Failure: the Refund call
    /// (§2.5) already answered accept/reject synchronously, and whether
    /// `/v1/inquiry` resolves REFUND references at all is UNVERIFIED from the
    /// vendor doc (Flow 4 of the technical spec) — so "76" may just mean the
    /// inquiry cannot see refunds. A terminal Failure here would report a
    /// completed refund as failed and invite duplicate refunds. Reported
    /// through the status, never `Err`.
    fn refund_sync_status(&self) -> RefundStatus {
        match self {
            Self::Success => RefundStatus::Success,
            Self::RedirectRequired | Self::PendingAuthorization => RefundStatus::Pending,
            Self::TransactionNotFound => RefundStatus::Pending,
            Self::Unknown(_) => RefundStatus::Failure,
        }
    }
}

impl Serialize for RevpayResponseCode {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for RevpayResponseCode {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Ok(match raw.as_str() {
            "00" => Self::Success,
            "09" => Self::RedirectRequired,
            "99" => Self::PendingAuthorization,
            "76" => Self::TransactionNotFound,
            _ => Self::Unknown(raw),
        })
    }
}

// ===== STATUS-MAPPING LAYER =====
// Deliberately exhaustive: NO `_ =>` catch-all. If revPAY adds a classifiable
// code and the enum above gains a named variant, this match stops compiling
// until a human picks the right AttemptStatus.
impl From<&RevpayResponseCode> for AttemptStatus {
    fn from(code: &RevpayResponseCode) -> Self {
        match code {
            // The Payment API authorises and captures (sale) in one call.
            RevpayResponseCode::Success => Self::Charged,
            RevpayResponseCode::RedirectRequired => Self::AuthenticationPending,
            // FPX B2B: the acquirer confirms the authorisation asynchronously.
            RevpayResponseCode::PendingAuthorization => Self::Pending,
            // "76": a payment revPAY cannot find is provably not chargeable.
            RevpayResponseCode::TransactionNotFound => Self::Failure,
            RevpayResponseCode::Unknown(_) => Self::Failure,
        }
    }
}

// =============================================================================
// PAYMENT METHOD MAPPING
// =============================================================================

/// Payment_ID = 2 (VISA/MASTERCARD). `Customer_Email`/`Customer_Contact` are
/// mandatory on this rail, per revPAY's field table.
const CARD_PAYMENT_ID: u16 = 2;
/// Payment_ID = 4 (AMEX).
const AMEX_PAYMENT_ID: u16 = 4;
/// Payment_ID = 29 (Diners Club).
const DINERS_PAYMENT_ID: u16 = 29;

/// revPAY `Card_Type` (Appendix H): `02`=VISA, `03`=MASTERCARD, `04`=AMEX,
/// `05`=MYDEBIT, `06`=UPI. The table has no Diners Club code, so `None` omits
/// the field. A card payment without `Card_Type` is rejected by the UAT
/// gateway with `Response_Code 14` "Invalid buyer account or card information"
/// (confirmed by revPAY support, 22 Oct 2026).
#[derive(Debug, Clone, Copy, Serialize)]
pub enum RevpayCardType {
    #[serde(rename = "02")]
    Visa,
    #[serde(rename = "03")]
    Mastercard,
    #[serde(rename = "04")]
    Amex,
    /// Appendix H `05`=MYDEBIT. Also used for UnionPay cards: Appendix H has
    /// no UnionPay code and the gateway only validates `Card_Type` *presence*
    /// (their own UAT sample pairs `02` with a MasterCard PAN), so `05` is the
    /// closest scheme label for UnionPay / MyDebit co-badged cards.
    #[serde(rename = "05")]
    MyDebit,
}

fn unsupported(what: &str, context_detail: &str) -> error_stack::Report<IntegrationError> {
    error_stack::report!(IntegrationError::NotSupported {
        message: format!("Selected payment method ({what})"),
        connector: "revpay",
        context: IntegrationErrorContext {
            suggested_action: Some(
                "Use a card or a revPAY-supported wallet (Alipay, WeChat Pay, Touch 'n Go, GrabPay)"
                    .to_string(),
            ),
            doc_url: None,
            additional_context: Some(context_detail.to_string()),
        },
    })
}

/// revPAY's direct-method rails: Payment_ID = 2 for VISA/MASTERCARD,
/// 4 for AMEX, 29 for Diners Club. Where the card network is not determinable
/// (absent, or a network revPAY has no rail for) the default Visa/Mastercard
/// rail is used — revPAY routes it by BIN.
fn card_payment_details(
    network: Option<&CardNetwork>,
    pan: &str,
) -> (u16, Option<RevpayCardType>) {
    match network {
        Some(CardNetwork::AmericanExpress) => (AMEX_PAYMENT_ID, Some(RevpayCardType::Amex)),
        Some(CardNetwork::DinersClub) => (DINERS_PAYMENT_ID, None),
        Some(CardNetwork::Visa) => (CARD_PAYMENT_ID, Some(RevpayCardType::Visa)),
        Some(CardNetwork::Mastercard) => (CARD_PAYMENT_ID, Some(RevpayCardType::Mastercard)),
        // Appendix H has no UnionPay code; `05` MYDEBIT is the closest label
        // and revPAY validates presence only (see RevpayCardType).
        Some(CardNetwork::UnionPay) => (CARD_PAYMENT_ID, Some(RevpayCardType::MyDebit)),
        _ => (CARD_PAYMENT_ID, card_type_from_pan(pan)),
    }
}

/// Infer revPAY `Card_Type` (Appendix H) from the PAN when UCS carries no
/// `card_network` — the euler `/txns` path never populates it, and revPAY
/// rejects a card payment missing `Card_Type` with `Response_Code 14`.
/// MyDebit (`05`) is deliberately not sniffed from its own BIN ranges: they
/// overlap Maestro and cannot be read reliably. BIN `62` is UnionPay
/// (including MyDebit co-badged cards) — Appendix H has no UnionPay code, so
/// it maps to `05` to satisfy the gateway's presence check (see
/// `RevpayCardType`).
fn card_type_from_pan(pan: &str) -> Option<RevpayCardType> {
    let digits: String = pan.chars().filter(char::is_ascii_digit).collect();
    let bin2: u32 = digits.get(..2)?.parse().ok()?;
    let bin4: u32 = digits.get(..4)?.parse().ok()?;
    match (bin2, bin4) {
        (34 | 37, _) => Some(RevpayCardType::Amex),
        (51..=55, _) => Some(RevpayCardType::Mastercard),
        (40..=49, _) => Some(RevpayCardType::Visa),
        (62, _) => Some(RevpayCardType::MyDebit),
        (_, 2221..=2720) => Some(RevpayCardType::Mastercard),
        _ => None,
    }
}

/// Format the card expiry as revPAY's `Funding_Exp_Date`: strictly `YYYYMM`,
/// six digits, year first (doc §2.1 field 24; format confirmed by the UAT
/// gateway, e.g. `"203901"` = Jan 2039). Accepts `M`/`MM` month and
/// `YY`/`YYYY` year and rejects everything else rather than forwarding it —
/// a malformed value reaches revPAY as `Response_Code 14`.
fn format_revpay_exp_date(
    month: &str,
    year: &str,
) -> Result<Secret<String>, error_stack::Report<IntegrationError>> {
    let invalid = |context: &str| {
        error_stack::report!(IntegrationError::InvalidDataFormat {
            field_name: "payment_method_data.card.card_exp_month/card_exp_year",
            context: IntegrationErrorContext {
                additional_context: Some(context.to_string()),
                ..Default::default()
            },
        })
    };

    let month_digits = month.trim();
    let month = month_digits
        .parse::<u8>()
        .map_err(|_| invalid("Expected month format: M or MM"))
        .and_then(|month| {
            if (1..=12).contains(&month) {
                Ok(month)
            } else {
                Err(invalid("Card expiry month must be in 1-12"))
            }
        })?;

    let year_digits = year.trim();
    if year_digits.is_empty() || !year_digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid("Expected year format: YY or YYYY"));
    }
    let year = match year_digits.len() {
        2 => format!("{}{}", common_utils::date_time::now().year() / 100, year_digits),
        4 => year_digits.to_string(),
        _ => return Err(invalid("Expected year format: YY or YYYY")),
    };

    Ok(Secret::new(format!("{year}{month:02}")))
}

/// `Card_Issuer_Bank_Country_Code` (doc §2.1 field 26): ISO 3166-1 alpha-3,
/// e.g. `MYS`. Prefers the explicit card issuing country and falls back to
/// the billing country.
fn issuer_country_alpha3(
    card_issuing_country: Option<&str>,
    billing_country: Option<CountryAlpha2>,
) -> Option<String> {
    card_issuing_country
        .map(str::trim)
        .filter(|country| country.len() == 3)
        .map(str::to_uppercase)
        .or_else(|| {
            billing_country.map(|country| CountryAlpha2::from_alpha2_to_alpha3(country).to_string())
        })
}

/// Payment_ID = 15 (Alipay Online, Web) — spec §2.1 / Appendix A.
const ALIPAY_PAYMENT_ID: u16 = 15;
/// Payment_ID = 14 (WeChat Pay) — spec §2.1 / Appendix A.
const WECHAT_PAYMENT_ID: u16 = 14;
/// Payment_ID = 28 (Touch 'n Go eWallet) — spec §2.1 / Appendix A.
const TOUCHNGO_PAYMENT_ID: u16 = 28;
/// Payment_ID = 17 (GrabPay) — spec §2.1 / Appendix A.
const GRABPAY_PAYMENT_ID: u16 = 17;

/// revPAY `Source_Of_Funds` value for raw-PAN card payments (spec §2.1,
/// Appendix O; gateway-token payments would use `TOKEN`, unsupported here).
const SOURCE_OF_FUNDS_CARD: &str = "CARD";

/// Wallet rails — Payment_ID only; revPAY needs no wallet credential fields
/// on the request (the shopper completes payment on the wallet's page).
fn wallet_payment_id(wallet: &WalletData) -> Result<u16, error_stack::Report<IntegrationError>> {
    Ok(match wallet {
        // Alipay Online (Web)
        WalletData::AliPayRedirect(_) => ALIPAY_PAYMENT_ID,
        WalletData::WeChatPayRedirect(_) => WECHAT_PAYMENT_ID,
        WalletData::TouchNGoRedirect(_) => TOUCHNGO_PAYMENT_ID,
        WalletData::GrabpayRedirect {} => GRABPAY_PAYMENT_ID,
        _ => {
            return Err(unsupported(
                "wallet",
                "UCS exposes no revPAY rail for this wallet; revPAY supports Alipay (15), \
                 WeChat Pay (14), GrabPay (17), Touch 'n Go (28) plus Malaysian wallets that \
                 have no UCS WalletData variant today (Merchantrade 10, Boost 11, Mae 12, \
                 Vcash 13, AirAsia Big 16, ShopeePay 33)",
            ));
        }
    })
}

/// Resource id for an authorize outcome: revPAY assigns `Transaction_ID` only
/// once a redirect completes — the "09 Request in progress" response carries
/// `Transaction_ID: null` (captured from the UAT sandbox, 22 Oct 2026) — so
/// fall back to our `Reference_Number`, which is also what the `/v1/inquiry`
/// sync correlates on (PSync later overwrites the resource id with the real
/// `Transaction_ID`), and fail only when the response carries neither
/// identifier.
fn authorize_resource_id(
    response: &RevpayPaymentsResponse,
    http_code: u16,
) -> Result<ResponseId, error_stack::Report<ConnectorError>> {
    let transaction_id = response
        .transaction_id
        .clone()
        .or_else(|| response.reference_number.clone())
        .ok_or_else(|| {
            crate::utils::response_deserialization_fail(
                http_code,
                "revpay: success/redirect response missing Transaction_ID \
                 and Reference_Number; confirm API contract.",
            )
        })?;
    Ok(ResponseId::ConnectorTransactionId(transaction_id))
}

// =============================================================================
// REQUEST TYPES
// =============================================================================

#[derive(Debug, Serialize)]
pub struct RevpayCardDetails<T: PaymentMethodDataTypes> {
    /// `CARD` — raw PAN, per revPAY's `Source_Of_Funds` contract.
    #[serde(rename = "Source_Of_Funds")]
    pub source_of_funds: &'static str,
    #[serde(rename = "Card_Type", skip_serializing_if = "Option::is_none")]
    pub card_type: Option<RevpayCardType>,
    #[serde(rename = "Card_Holder_Name", skip_serializing_if = "Option::is_none")]
    pub card_holder_name: Option<Secret<String>>,
    #[serde(rename = "Funding_Pan")]
    pub funding_pan: RawCardNumber<T>,
    /// `YYYYMM` — year first, zero-padded two-digit month.
    #[serde(rename = "Funding_Exp_Date")]
    pub funding_exp_date: Secret<String>,
    #[serde(rename = "Funding_CVV")]
    pub funding_cvv: Secret<String>,
    /// ISO 3166-1 alpha-3 issuer country (doc §2.1 field 26), e.g. `MYS`.
    #[serde(
        rename = "Card_Issuer_Bank_Country_Code",
        skip_serializing_if = "Option::is_none"
    )]
    pub card_issuer_bank_country_code: Option<String>,
    /// Mandatory when Payment_ID = 2 (revPAY field table).
    #[serde(rename = "Customer_Email", skip_serializing_if = "Option::is_none")]
    pub customer_email: Option<Email>,
    /// Mandatory when Payment_ID = 2 (revPAY field table), format `+6012…`.
    #[serde(rename = "Customer_Contact", skip_serializing_if = "Option::is_none")]
    pub customer_contact: Option<Secret<String>>,
}

#[derive(Debug, Serialize)]
pub struct RevpayPaymentsRequest<T: PaymentMethodDataTypes> {
    #[serde(rename = "Revpay_Merchant_ID")]
    pub revpay_merchant_id: String,
    #[serde(rename = "Payment_ID")]
    pub payment_id: u16,
    #[serde(rename = "Reference_Number")]
    pub reference_number: String,
    /// The exact 2-decimal string that is also signed — see `format_revpay_amount`.
    #[serde(rename = "Amount")]
    pub amount: String,
    #[serde(rename = "Currency")]
    pub currency: String,
    #[serde(rename = "Transaction_Description")]
    pub transaction_description: String,
    #[serde(rename = "Customer_ID", skip_serializing_if = "Option::is_none")]
    pub customer_id: Option<String>,
    #[serde(rename = "Customer_Name", skip_serializing_if = "Option::is_none")]
    pub customer_name: Option<String>,
    #[serde(rename = "Customer_IP")]
    pub customer_ip: String,
    #[serde(rename = "Return_URL")]
    pub return_url: String,
    #[serde(rename = "Backend_URL", skip_serializing_if = "Option::is_none")]
    pub backend_url: Option<String>,
    #[serde(rename = "Key_Index")]
    pub key_index: u32,
    #[serde(rename = "Signature")]
    pub signature: String,
    /// Card-side fields are flattened in; omitted entirely for wallet calls.
    #[serde(flatten)]
    pub payment_method_fields: Option<RevpayCardDetails<T>>,
}

impl<T: PaymentMethodDataTypes>
    TryFrom<
        &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    > for RevpayPaymentsRequest<T>
{
    type Error = error_stack::Report<IntegrationError>;

    fn try_from(
        item: &RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData<T>,
            PaymentsResponseData,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = RevpayAuthType::try_from(&item.connector_config)?;

        // Key_Index is Int(3) on the wire; it is configured as a string.
        let key_index = auth.key_index.peek().trim().parse::<u32>().map_err(|_| {
            error_stack::report!(IntegrationError::InvalidDataFormat {
                field_name: "connector_config.api_secret (revPAY Key_Index)",
                context: IntegrationErrorContext {
                    additional_context: Some("expected a decimal integer, e.g. \"1\"".to_string()),
                    ..Default::default()
                },
            })
        })?;

        let currency = item.request.currency.to_string();
        let amount = format_revpay_amount(item.request.amount.amount, item.request.currency)
            .change_context(IntegrationError::InvalidDataFormat {
                field_name: "request.amount",
                context: IntegrationErrorContext::default(),
            })?;

        let reference_number = item
            .resource_common_data
            .connector_request_reference_id
            .clone();

        // Signature = sha512(MerchantKey + Revpay_Merchant_ID + Reference_Number
        // + Amount + Currency) — the SAME Amount string that goes in the body.
        let signature = generate_revpay_signature(
            auth.merchant_key.peek(),
            &[
                auth.merchant_id.peek(),
                &reference_number,
                &amount,
                &currency,
            ],
        );

        // Return_URL is mandatory in revPAY's Payment field table.
        let return_url = item.request.router_return_url.clone().ok_or_else(|| {
            error_stack::report!(IntegrationError::MissingRequiredField {
                field_name: "router_return_url",
                context: IntegrationErrorContext::default(),
            })
        })?;

        // spec §2.1 field #18: Customer_IP is Mandatory on every payment request.
        // When the shopper's browser info is absent (e.g. server-side flows),
        // substitute the loopback placeholder rather than failing the payment
        // (same exemption UCS applies to other IP-mandating connectors).
        let customer_ip = item
            .request
            .browser_info
            .as_ref()
            .and_then(|info| info.ip_address)
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "127.0.0.1".to_string());

        // spec §2.1 field #7: Transaction_Description is Mandatory; when the
        // merchant supplies none — or a blank string (euler sends
        // `description: ""`) — fall back to the unique order reference so
        // the merchant-portal report row stays meaningful. revPAY rejects an
        // empty value with HTTP 422 "Unprocessable Entity" (verified against
        // the UAT sandbox), which is not documented in the 3.1.10 spec.
        let transaction_description = item
            .resource_common_data
            .description
            .clone()
            .filter(|description| !description.trim().is_empty())
            .unwrap_or_else(|| format!("Payment {reference_number}"));

        let (payment_id, payment_method_fields) = match &item.request.payment_method_data {
            PaymentMethodData::Card(card_data) => {
                let (payment_id, card_type) = card_payment_details(
                    card_data.card_network.as_ref(),
                    card_data.card_number.peek(),
                );

                let customer_email = item
                    .request
                    .email
                    .clone()
                    .or_else(|| item.resource_common_data.get_optional_billing_email());
                // revPAY wants "+<cc><number>". Euler forwards the phone number
                // without a country code (UCSTransforms.hs maps
                // phoneCountryCode = Nothing), and get_number_with_country_code
                // errors without one — so fall back to the raw number rather
                // than reporting the phone as missing.
                let customer_contact = item
                    .resource_common_data
                    .get_billing_phone_number()
                    .ok()
                    .or_else(|| {
                        item.resource_common_data
                            .get_optional_billing_phone_number()
                    });

                if payment_id == CARD_PAYMENT_ID {
                    if customer_email.is_none() {
                        return Err(error_stack::report!(IntegrationError::MissingRequiredField {
                            field_name: "email",
                            context: IntegrationErrorContext {
                                additional_context: Some(
                                    "revPAY marks Customer_Email mandatory for Payment_ID = 2 (Visa/Mastercard rail)"
                                        .to_string(),
                                ),
                                ..Default::default()
                            },
                        }));
                    }
                    if customer_contact.is_none() {
                        return Err(error_stack::report!(IntegrationError::MissingRequiredField {
                            field_name: "billing.phone",
                            context: IntegrationErrorContext {
                                additional_context: Some(
                                    "revPAY marks Customer_Contact mandatory for Payment_ID = 2 (Visa/Mastercard rail)"
                                        .to_string(),
                                ),
                                ..Default::default()
                            },
                        }));
                    }
                }

                (
                    payment_id,
                    Some(RevpayCardDetails {
                        source_of_funds: SOURCE_OF_FUNDS_CARD,
                        card_type,
                        card_holder_name: card_data.card_holder_name.clone(),
                        funding_pan: card_data.card_number.clone(),
                        funding_exp_date: format_revpay_exp_date(
                            card_data.card_exp_month.peek(),
                            card_data.card_exp_year.peek(),
                        )?,
                        funding_cvv: card_data.card_cvc.clone(),
                        card_issuer_bank_country_code: issuer_country_alpha3(
                            card_data.card_issuing_country.as_deref(),
                            item.resource_common_data.get_optional_billing_country(),
                        ),
                        customer_email,
                        customer_contact,
                    }),
                )
            }
            PaymentMethodData::Wallet(wallet_data) => (wallet_payment_id(wallet_data)?, None),
            _ => {
                return Err(unsupported(
                    "other",
                    "revPAY Authorize supports cards and the mapped redirect wallets; \
                     FPX online banking / QR payment methods are out of scope",
                ));
            }
        };

        Ok(Self {
            revpay_merchant_id: auth.merchant_id.peek().to_string(),
            payment_id,
            reference_number,
            amount,
            currency,
            transaction_description,
            customer_id: item
                .request
                .customer_id
                .as_ref()
                .map(|customer| customer.get_string_repr().to_string()),
            customer_name: item.request.customer_name.clone().or_else(|| {
                // revPAY's gateway sample sends `Customer_Name`; fall back to
                // the billing name when the request carries none.
                let name = [
                    item.resource_common_data.get_optional_billing_first_name(),
                    item.resource_common_data.get_optional_billing_last_name(),
                ]
                .into_iter()
                .flatten()
                .map(|part| part.peek().trim().to_string())
                .filter(|part| !part.is_empty())
                .collect::<Vec<_>>()
                .join(" ");
                (!name.is_empty()).then_some(name)
            }),
            customer_ip,
            return_url,
            backend_url: item.request.webhook_url.clone(),
            key_index,
            signature,
            payment_method_fields,
        })
    }
}

// Bridge between the macro-generated `RevpayRouterData` wrapper and the
// `TryFrom<&RouterDataV2<..>>` transform above (same idiom as travelhub).
impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        RevpayRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for RevpayPaymentsRequest<T>
{
    type Error = error_stack::Report<IntegrationError>;

    fn try_from(
        wrapper: RevpayRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Self::try_from(&wrapper.router_data)
    }
}

// =============================================================================
// RESPONSE TYPES
// =============================================================================

/// revPAY may echo `Amount`/`Currency`/dates either as JSON strings (matching
/// what we sent) or as bare JSON numbers (as in the doc samples).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RevpayAmount {
    Text(String),
    Number(f64),
}

impl RevpayAmount {
    /// Normalised two-decimal-major rendering, ready for `parse_revpay_amount`.
    fn as_two_decimal_string(&self) -> String {
        match self {
            Self::Text(text) => text.clone(),
            Self::Number(number) => format!("{number:.2}"),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RevpayPaymentsResponse {
    #[serde(rename = "Revpay_Merchant_ID", skip_serializing_if = "Option::is_none")]
    pub revpay_merchant_id: Option<String>,
    #[serde(rename = "Payment_ID", skip_serializing_if = "Option::is_none")]
    pub payment_id: Option<u16>,
    #[serde(rename = "Transaction_ID", skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,
    #[serde(rename = "Reference_Number", skip_serializing_if = "Option::is_none")]
    pub reference_number: Option<String>,
    #[serde(rename = "Amount", skip_serializing_if = "Option::is_none")]
    pub amount: Option<RevpayAmount>,
    #[serde(rename = "Currency", skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
    #[serde(rename = "Response_Code")]
    pub response_code: RevpayResponseCode,
    #[serde(rename = "Error_Description", skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
    #[serde(rename = "Bank_Redirect_URL", skip_serializing_if = "Option::is_none")]
    pub bank_redirect_url: Option<String>,
    #[serde(rename = "Key_Index", skip_serializing_if = "Option::is_none")]
    pub key_index: Option<i64>,
    // TODO(webhook task): revPAY echoes `Key_Index` + `Signature` on every
    // response; the webhook/source-verification path recomputes and verifies
    // them (sha512(key + mid + Transaction_ID + Response_Code +
    // Reference_Number + Amount + Currency)). Authorize response-signature
    // verification is intentionally not done here — this transformer stays pure.
    #[serde(rename = "Signature", skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(
        rename = "Bank_Reference_Number",
        skip_serializing_if = "Option::is_none"
    )]
    pub bank_reference_number: Option<String>,
}

impl<T: PaymentMethodDataTypes> TryFrom<ResponseRouterData<RevpayPaymentsResponse, Self>>
    for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<RevpayPaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let router_data = &item.router_data;
        let status = AttemptStatus::from(&response.response_code);

        // IN-BAND 2xx FAILURE.
        // revPAY answers EVERYTHING (declines included) with HTTP 200; success
        // vs declination lives in the body `Response_Code`. Only `00` (sale
        // charged) and `09` (redirect, needs `Bank_Redirect_URL`) are
        // non-error outcomes — every other code is a failed attempt and must
        // land in `Err(ErrorResponse)` here, because `build_error_response`
        // never sees a 200 on this connector. Both halves of the enum are
        // matched as named arms (no `_ =>` at the code level).
        let in_band_failure_code: Option<&str> = match (
            &response.response_code,
            response.bank_redirect_url.as_deref(),
        ) {
            (RevpayResponseCode::Success, _) => None,
            (RevpayResponseCode::RedirectRequired, Some(_)) => None,
            // FPX B2B settles asynchronously — pending, not an error.
            (RevpayResponseCode::PendingAuthorization, _) => None,
            // A 09 without its redirect URL cannot complete the payment.
            (code @ RevpayResponseCode::RedirectRequired, None) => Some(code.as_str()),
            // "76" here: the gateway cannot find the payment being authorized.
            (code @ RevpayResponseCode::TransactionNotFound, _) => Some(code.as_str()),
            (code @ RevpayResponseCode::Unknown(_), _) => Some(code.as_str()),
        };

        if let Some(raw_code) = in_band_failure_code {
            // Flow-specific: the Payment API authorises (and captures) in one
            // call, so a decline maps to AuthorizationFailed, not generic
            // Failure.
            let status = AttemptStatus::AuthorizationFailed;
            let message = response.error_description.clone().unwrap_or_else(|| {
                if matches!(response.response_code, RevpayResponseCode::RedirectRequired) {
                    "revPAY returned Response_Code 09 without Bank_Redirect_URL".to_string()
                } else {
                    NO_ERROR_MESSAGE.to_string()
                }
            });
            return Ok(Self {
                resource_common_data: PaymentFlowData {
                    status,
                    ..router_data.resource_common_data.clone()
                },
                response: Err(ErrorResponse {
                    status_code: item.http_code,
                    code: raw_code.to_string(),
                    message,
                    reason: response.error_description.clone(),
                    // Terminal here is correct: the decline state came from the
                    // connector's own body and revPAY does not re-drive a
                    // failed Payment API attempt. Do NOT copy this into
                    // `build_error_response`, which is shared by every flow.
                    attempt_status: Some(FlowStatus::Payment(status)),
                    connector_transaction_id: response.transaction_id.clone(),
                    ..Default::default()
                }),
                ..router_data.clone()
            });
        }

        // revPAY's "09 Request in progress" (redirect) response carries
        // `Transaction_ID: null` — the id is only assigned once the shopper
        // completes the payment (captured from the UAT sandbox, 22 Oct 2026).
        // See `authorize_resource_id` for the interim-identifier contract.
        let resource_id = authorize_resource_id(response, item.http_code)?;

        // revPAY echoes Amount/Currency on the payment response — populate the
        // integrity object from the echoed values so the framework detects
        // tampering between request build and response handling. Amount is
        // mandatory in the doc; fall back to the request value only when the
        // connector genuinely omits it.
        let integrity_amount = match &response.amount {
            Some(amount) => parse_revpay_amount(
                &amount.as_two_decimal_string(),
                router_data.request.currency,
            )
            .change_context(crate::utils::response_handling_fail_for_connector(
                item.http_code,
                "revpay",
            ))
            .attach_printable("revpay: echoed Amount is not in revPAY's 2-decimal form")?,
            None => router_data.request.amount.amount,
        };
        let integrity_currency = response
            .currency
            .as_deref()
            .and_then(|echoed| Currency::from_str(echoed).ok())
            .unwrap_or(router_data.request.currency);

        // 09 → shopper must open Bank_Redirect_URL with a plain HTTP GET;
        // RedirectForm::Uri navigates callers directly to the URL as-is.
        let redirection_data = response
            .bank_redirect_url
            .clone()
            .map(|url| Box::new(RedirectForm::Uri { uri: url }));

        let payments_response_data = PaymentsResponseData::TransactionResponse {
            resource_id,
            redirection_data,
            connector_metadata: None,
            mandate_reference: None,
            network_txn_id: None,
            network_txn_link_id: None,
            connector_response_reference_id: response.reference_number.clone(),
            incremental_authorization_allowed: None,
            splits: None,
            status_code: item.http_code,
            payment_account_reference: None,
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data.clone()
            },
            response: Ok(payments_response_data),
            request: PaymentsAuthorizeData {
                integrity_object: Some(AuthoriseIntegrityObject {
                    amount: integrity_amount,
                    currency: integrity_currency,
                }),
                ..router_data.request.clone()
            },
            ..router_data.clone()
        })
    }
}

// =============================================================================
// PSYNC TYPES — POST {base}/v1/inquiry (§2.2)
// =============================================================================

/// The inquiry response is the very same wire shape as the Payment response
/// (§2.2: "`Transaction_ID`, `Response_Code`, `Error_Description`,
/// `Key_Index`, `Signature`, … — see Flow 1 table"); only the status mapping
/// and in-band handling differ, so it reuses `RevpayPaymentsResponse`. The
/// alias exists so the two flows get distinct idents in the macro-generated
/// templating layer.
pub type RevpayPSyncResponse = RevpayPaymentsResponse;

/// Payment Status Inquiry request. revPAY's inquiry has NO
/// query-by-transaction-id input: it resolves only the merchant reference the
/// Payment call was signed with, so `Reference_Number` must be byte-identical
/// to the value sent on Payment.
#[derive(Debug, Serialize)]
pub struct RevpayPSyncRequest {
    #[serde(rename = "Revpay_Merchant_ID")]
    pub revpay_merchant_id: String,
    #[serde(rename = "Reference_Number")]
    pub reference_number: String,
    /// The ORIGINAL payment amount in the same 2-decimal form signed at
    /// Payment time — the doc requires the inquiry to re-sign it.
    #[serde(rename = "Amount")]
    pub amount: String,
    #[serde(rename = "Currency")]
    pub currency: String,
    #[serde(rename = "Key_Index")]
    pub key_index: u32,
    #[serde(rename = "Signature")]
    pub signature: String,
}

impl TryFrom<&RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>
    for RevpayPSyncRequest
{
    type Error = error_stack::Report<IntegrationError>;

    fn try_from(
        item: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let auth = RevpayAuthType::try_from(&item.connector_config)?;

        // Key_Index is Int(3) on the wire; it is configured as a string.
        let key_index = auth.key_index.peek().trim().parse::<u32>().map_err(|_| {
            error_stack::report!(IntegrationError::InvalidDataFormat {
                field_name: "connector_config.api_secret (revPAY Key_Index)",
                context: IntegrationErrorContext {
                    additional_context: Some("expected a decimal integer, e.g. \"1\"".to_string()),
                    ..Default::default()
                },
            })
        })?;

        // PRE-FLIGHT GATE: the inquiry Reference_Number must be the exact
        // merchant reference the Authorize flow sent, carried into PSync by
        // `connector_request_reference_id`. NEVER re-derive it from
        // `connector_transaction_id` (revPAY only mints Transaction_ID in its
        // Payment response, and the inquiry cannot be keyed by it) and NEVER
        // fall back to a default — an empty reference resolves nothing and
        // the payment would be mis-reported as not found.
        let reference_number = item
            .resource_common_data
            .connector_request_reference_id
            .clone();
        if reference_number.trim().is_empty() {
            return Err(error_stack::report!(
                IntegrationError::MissingRequiredField {
                    field_name: "connector_request_reference_id",
                    context: IntegrationErrorContext {
                        additional_context: Some(
                            "revPAY Inquiry (PSync) requires the Reference_Number signed on the \
                         original Payment call; the connector_request_reference_id carrier is \
                         empty for this request"
                                .to_string(),
                        ),
                        suggested_action: Some(
                            "Ensure the original payment carried connector_request_reference_id \
                         before requesting a payment sync"
                                .to_string(),
                        ),
                        doc_url: None,
                    },
                }
            ));
        }

        // The inquiry must re-send the ORIGINAL payment amount with the same
        // 2-decimal encoding that was signed at Payment time.
        // `PaymentsSyncData.amount` is mandatory in the framework's
        // PaymentServiceGet → PaymentsSyncData conversion, so the exact
        // authorize-time figure (and currency) is available here without any
        // reconstruction.
        let currency = item.request.currency.to_string();
        let amount = format_revpay_amount(item.request.amount.amount, item.request.currency)
            .change_context(IntegrationError::InvalidDataFormat {
                field_name: "request.amount",
                context: IntegrationErrorContext::default(),
            })?;

        // Signature = sha512(MerchantKey + Revpay_Merchant_ID +
        // Reference_Number + Amount + Currency) — the same formula as the
        // Payment call (§3.4), over the same byte values.
        let signature = generate_revpay_signature(
            auth.merchant_key.peek(),
            &[
                auth.merchant_id.peek(),
                &reference_number,
                &amount,
                &currency,
            ],
        );

        Ok(Self {
            revpay_merchant_id: auth.merchant_id.peek().to_string(),
            reference_number,
            amount,
            currency,
            key_index,
            signature,
        })
    }
}

// Bridge between the macro-generated `RevpayRouterData` wrapper and the
// `TryFrom<&RouterDataV2<..>>` transform above (same idiom as Authorize).
impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        RevpayRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    > for RevpayPSyncRequest
{
    type Error = error_stack::Report<IntegrationError>;

    fn try_from(
        wrapper: RevpayRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Self::try_from(&wrapper.router_data)
    }
}

impl TryFrom<ResponseRouterData<RevpayPSyncResponse, Self>>
    for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(item: ResponseRouterData<RevpayPSyncResponse, Self>) -> Result<Self, Self::Error> {
        let response = &item.response;
        let router_data = &item.router_data;

        // INQUIRY SEMANTICS: PSync is a status query and revPAY answers every
        // inquiry with HTTP 200, so the outcome is REPORTED through the
        // attempt status — never returned as `Err(ErrorResponse)`. "00" →
        // Charged, "09"/"99" → Pending, every other code (including "76"
        // Transaction not found) → Failure; the raw code and description ride
        // along on `raw_connector_status`, and non-2xx transport faults are
        // still handled by the shared `build_error_response`.
        let status = response.response_code.psync_status();

        let resource_id = match response.transaction_id.clone() {
            Some(transaction_id) => ResponseId::ConnectorTransactionId(transaction_id),
            // revPAY omits Transaction_ID when the reference resolves to
            // nothing (e.g. "76"); mirror the request-side id the sync was
            // keyed by instead of manufacturing a new identifier.
            None => router_data.request.connector_transaction_id.clone(),
        };

        // Identifier round-trip: prefer the Reference_Number revPAY echoes;
        // the fallback is the very reference the inquiry was keyed by, so the
        // caller can always correlate the sync with the original attempt.
        let connector_response_reference_id = response.reference_number.clone().or_else(|| {
            Some(
                router_data
                    .resource_common_data
                    .connector_request_reference_id
                    .clone(),
            )
        });

        // Identifier carrier chain: re-publish whatever metadata arrived on
        // the sync request so later flows keep access to it.
        let connector_metadata = router_data
            .request
            .connector_feature_data
            .clone()
            .map(|meta| meta.expose());

        // Integrity object: the inquiry echoes the AUTHORIZE-side Amount /
        // Currency, so prefer the echoed values (parsed back through the same
        // 2-decimal contract). The request-side figures are the fallback for
        // the one case revPAY genuinely omits the echo — an unresolved
        // reference ("76"), whose body carries no Amount/Currency.
        let integrity_currency = response
            .currency
            .as_deref()
            .and_then(|echoed| Currency::from_str(echoed).ok())
            .unwrap_or(router_data.request.currency);
        let integrity_amount = match &response.amount {
            Some(amount) => {
                parse_revpay_amount(&amount.as_two_decimal_string(), integrity_currency)
                    .change_context(crate::utils::response_handling_fail_for_connector(
                        item.http_code,
                        "revpay",
                    ))
                    .attach_printable(
                        "revpay: inquiry echoed Amount is not in revPAY's 2-decimal form",
                    )?
            }
            None => router_data.request.amount.amount,
        };

        let payments_response_data = PaymentsResponseData::TransactionResponse {
            resource_id,
            redirection_data: None,
            connector_metadata,
            mandate_reference: None,
            network_txn_id: None,
            network_txn_link_id: None,
            connector_response_reference_id,
            incremental_authorization_allowed: None,
            splits: None,
            status_code: item.http_code,
            payment_account_reference: None,
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                raw_connector_status: Some(RawConnectorStatus {
                    code: Some(response.response_code.as_str().to_string()),
                    message: Some(
                        response
                            .error_description
                            .clone()
                            .unwrap_or_else(|| NO_ERROR_MESSAGE.to_string()),
                    ),
                    reason: response.error_description.clone(),
                }),
                ..router_data.resource_common_data.clone()
            },
            response: Ok(payments_response_data),
            request: PaymentsSyncData {
                integrity_object: Some(PaymentSynIntegrityObject {
                    amount: integrity_amount,
                    currency: integrity_currency,
                }),
                ..router_data.request.clone()
            },
            ..router_data.clone()
        })
    }
}

// =============================================================================
// REFUND TYPES — POST {base}/v1/refund (§2.5), synchronous accept/reject
// =============================================================================

/// revPAY refunds the ORIGINAL payment by `Original_Reference_Number` — the
/// Reference_Number signed on the Payment call — and identifies THIS refund
/// with a NEW `Reference_Number` (UCS `refund_id`).
///
/// `RefundFlowData::connector_request_reference_id` cannot serve as the
/// original reference: the framework derives it from `merchant_refund_id`, so
/// it identifies the refund, not the payment. The original payment's Reference
/// is taken from `RefundsData::connector_order_id` ("connector-side identifier
/// for the original payment that this refund targets" — same idiom as
/// travelhub). Absent => refuse locally rather than sending revPAY a reference
/// that can never match a payment.
fn resolve_original_reference_number(
    connector_order_id: Option<&str>,
) -> Result<String, error_stack::Report<IntegrationError>> {
    connector_order_id
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            error_stack::report!(IntegrationError::MissingRequiredField {
                field_name: "connector_order_id",
                context: IntegrationErrorContext {
                    suggested_action: Some(
                        "Pass the original Authorize call's merchant reference (the \
                         connector_request_reference_id that revPAY signed as \
                         `Reference_Number`) as `connector_order_id` on the refund request."
                            .to_string(),
                    ),
                    doc_url: None,
                    additional_context: Some(
                        "revPAY refunds a payment by `Original_Reference_Number` alone, the \
                         only original-payment identifier the refund body carries. \
                         `refund_id` identifies this refund call and cannot locate the \
                         original payment."
                            .to_string(),
                    ),
                },
            })
        })
}

#[derive(Debug, Serialize)]
pub struct RevpayRefundRequest {
    #[serde(rename = "Revpay_Merchant_ID")]
    pub revpay_merchant_id: String,
    /// NEW unique reference for this refund — UCS `refund_id`.
    #[serde(rename = "Reference_Number")]
    pub reference_number: String,
    #[serde(rename = "Original_Reference_Number")]
    pub original_reference_number: String,
    /// The exact 2-decimal string that is also signed — see `format_revpay_amount`.
    #[serde(rename = "Refund_Amount")]
    pub refund_amount: String,
    #[serde(rename = "Key_Index")]
    pub key_index: u32,
    #[serde(rename = "Signature")]
    pub signature: String,
}

impl TryFrom<&RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>>
    for RevpayRefundRequest
{
    type Error = error_stack::Report<IntegrationError>;

    fn try_from(
        item: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> Result<Self, Self::Error> {
        let auth = RevpayAuthType::try_from(&item.connector_config)?;

        // Key_Index is Int(3) on the wire; it is configured as a string.
        let key_index = auth.key_index.peek().trim().parse::<u32>().map_err(|_| {
            error_stack::report!(IntegrationError::InvalidDataFormat {
                field_name: "connector_config.api_secret (revPAY Key_Index)",
                context: IntegrationErrorContext {
                    additional_context: Some("expected a decimal integer, e.g. \"1\"".to_string()),
                    ..Default::default()
                },
            })
        })?;

        // Reference_Number is a NEW reference identifying this refund —
        // revPAY rejects a refund that duplicates a previous reference.
        let reference_number = item.request.refund_id.clone();
        if reference_number.trim().is_empty() {
            return Err(error_stack::report!(
                IntegrationError::MissingRequiredField {
                    field_name: "refund_id",
                    context: IntegrationErrorContext {
                        additional_context: Some(
                            "revPAY Refund requires a unique Reference_Number per refund; the \
                         framework's refund_id carrier is empty for this request"
                                .to_string(),
                        ),
                        ..Default::default()
                    },
                }
            ));
        }

        let original_reference_number =
            resolve_original_reference_number(item.request.connector_order_id.as_deref())?;

        // Refund_Amount in the exact 2-decimal form that is also signed;
        // partial refunds are supported by the API (§2.5).
        let refund_amount =
            format_revpay_amount(item.request.refund_amount.amount, item.request.currency)
                .change_context(IntegrationError::InvalidDataFormat {
                    field_name: "request.refund_amount",
                    context: IntegrationErrorContext::default(),
                })?;

        // Signature = sha512(MerchantKey + Revpay_Merchant_ID + Reference_Number
        // + Refund_Amount + Original_Reference_Number) (§3.10) — DIFFERENT field
        // order from the Payment formula (no Currency; Original_Reference_Number
        // appended). Verified against a self-computed vector in tests below.
        let signature = generate_revpay_signature(
            auth.merchant_key.peek(),
            &[
                auth.merchant_id.peek(),
                &reference_number,
                &refund_amount,
                &original_reference_number,
            ],
        );

        Ok(Self {
            revpay_merchant_id: auth.merchant_id.peek().to_string(),
            reference_number,
            original_reference_number,
            refund_amount,
            key_index,
            signature,
        })
    }
}

// Bridge between the macro-generated `RevpayRouterData` wrapper and the
// `TryFrom<&RouterDataV2<..>>` transform above (same idiom as Authorize).
impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        RevpayRouterData<RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>, T>,
    > for RevpayRefundRequest
{
    type Error = error_stack::Report<IntegrationError>;

    fn try_from(
        wrapper: RevpayRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Self::try_from(&wrapper.router_data)
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RevpayRefundResponse {
    #[serde(rename = "Revpay_Merchant_ID", skip_serializing_if = "Option::is_none")]
    pub revpay_merchant_id: Option<String>,
    /// No separate refund id exists in the doc — this becomes `connector_refund_id`.
    #[serde(rename = "Transaction_ID", skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,
    /// Echoed refund-side Reference_Number.
    #[serde(rename = "Reference_Number", skip_serializing_if = "Option::is_none")]
    pub reference_number: Option<String>,
    #[serde(
        rename = "Original_Reference_Number",
        skip_serializing_if = "Option::is_none"
    )]
    pub original_reference_number: Option<String>,
    #[serde(rename = "Refund_Amount", skip_serializing_if = "Option::is_none")]
    pub refund_amount: Option<RevpayAmount>,
    /// Remaining refundable balance — informational only, not mapped onward.
    #[serde(rename = "Amount_Balance", skip_serializing_if = "Option::is_none")]
    pub amount_balance: Option<RevpayAmount>,
    #[serde(rename = "Response_Code")]
    pub response_code: RevpayResponseCode,
    #[serde(rename = "Error_Description", skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
    #[serde(rename = "Key_Index", skip_serializing_if = "Option::is_none")]
    pub key_index: Option<i64>,
    // TODO(webhook task): §3.11 signs refund responses as sha512(key + mid +
    // Transaction_ID + Response_Code + Reference_Number + Refund_Amount);
    // response-signature verification stays out of this transformer.
    #[serde(rename = "Signature", skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl TryFrom<ResponseRouterData<RevpayRefundResponse, Self>>
    for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(item: ResponseRouterData<RevpayRefundResponse, Self>) -> Result<Self, Self::Error> {
        let response = &item.response;
        let router_data = &item.router_data;

        // IN-BAND 2xx FAILURE. revPAY answers EVERY refund (declines included)
        // with HTTP 200; only "00" is acceptance. Every other code must land in
        // `Err(ErrorResponse)` here, because `build_error_response` never sees a
        // 200 on this connector. Terminal FlowStatus::Refund(Failure) is correct:
        // the decline state came from the connector's own body and the Refund
        // API is synchronous — it never re-drives a declined refund.
        if !matches!(response.response_code, RevpayResponseCode::Success) {
            let raw_code = response.response_code.as_str();
            return Ok(Self {
                response: Err(ErrorResponse {
                    status_code: item.http_code,
                    code: if raw_code.trim().is_empty() {
                        NO_ERROR_CODE.to_string()
                    } else {
                        raw_code.to_string()
                    },
                    message: response
                        .error_description
                        .clone()
                        .unwrap_or_else(|| NO_ERROR_MESSAGE.to_string()),
                    reason: response.error_description.clone(),
                    attempt_status: Some(FlowStatus::Refund(
                        response.response_code.refund_status(),
                    )),
                    connector_transaction_id: response.transaction_id.clone(),
                    ..Default::default()
                }),
                ..router_data.clone()
            });
        }

        let refund_status = response.response_code.refund_status();

        let connector_refund_id = response.transaction_id.clone().ok_or_else(|| {
            crate::utils::response_deserialization_fail(
                item.http_code,
                "revpay: successful refund response missing Transaction_ID; confirm API contract.",
            )
        })?;

        // Integrity object (refund_amount, currency). revPAY's refund response
        // carries NO Currency field and echoes Refund_Amount, so the amount is
        // parsed from the echo whenever present; currency can only come from
        // the request side (§2.5 refund table has no currency echo).
        let integrity_currency = router_data.request.currency;
        let integrity_amount = match &response.refund_amount {
            Some(amount) => {
                parse_revpay_amount(&amount.as_two_decimal_string(), integrity_currency)
                    .change_context(crate::utils::response_handling_fail_for_connector(
                        item.http_code,
                        "revpay",
                    ))
                    .attach_printable(
                        "revpay: echoed Refund_Amount is not in revPAY's 2-decimal form",
                    )?
            }
            None => router_data.request.refund_amount.amount,
        };

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id,
                refund_status,
                status_code: item.http_code,
                acquirer_reference_number: None,
            }),
            request: RefundsData {
                integrity_object: Some(RefundIntegrityObject {
                    refund_amount: integrity_amount,
                    currency: integrity_currency,
                }),
                ..router_data.request.clone()
            },
            ..router_data.clone()
        })
    }
}

// =============================================================================
// RSYNC TYPES — POST {base}/v1/inquiry (Flow 4, re-uses the payment inquiry)
// =============================================================================

/// FLOW 4 / PRODUCT DECISION: revPAY 3.1.10 has NO dedicated refund-inquiry
/// endpoint — refund outcomes on the Refund call are synchronous. RSync
/// reuses the PAYMENT inquiry endpoint (`POST /v1/inquiry`, §2.2), keyed on
/// the REFUND's own `Reference_Number` (the `refund_id` the Refund call
/// signed) with `Amount` = the refund amount, signed with the
/// payment/inquiry formula sha512(key + mid + Reference_Number + Amount +
/// Currency). Whether revPAY's inquiry resolves refund references is
/// UNVERIFIED from the vendor doc, so the wire shape and parsing deliberately
/// stay identical to PSync.
///
/// The inquiry response is the same wire shape as the Payment/Inquiry
/// response (§2.2), so the alias trick from PSync is applied once more: a
/// distinct ident for the macro-generated templating layer, one wire struct.
pub type RevpayRSyncResponse = RevpayPaymentsResponse;

/// Refund-status inquiry request — field-for-field the PSync inquiry shape,
/// but each value is sourced from the REFUND side (reference and amount
/// identify the refund, not the original payment). A distinct struct (not
/// another alias) because the TryFrom input differs (`RefundSyncData`).
#[derive(Debug, Serialize)]
pub struct RevpayRSyncRequest {
    #[serde(rename = "Revpay_Merchant_ID")]
    pub revpay_merchant_id: String,
    /// The REFUND's own Reference_Number — the `refund_id` sent as
    /// `Reference_Number` on the Refund call. NOT the original payment's
    /// reference and NOT the connector's Transaction_ID.
    #[serde(rename = "Reference_Number")]
    pub reference_number: String,
    /// The refund amount in the exact 2-decimal form that is also signed.
    #[serde(rename = "Amount")]
    pub amount: String,
    #[serde(rename = "Currency")]
    pub currency: String,
    #[serde(rename = "Key_Index")]
    pub key_index: u32,
    #[serde(rename = "Signature")]
    pub signature: String,
}

impl TryFrom<&RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>>
    for RevpayRSyncRequest
{
    type Error = error_stack::Report<IntegrationError>;

    fn try_from(
        item: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
    ) -> Result<Self, Self::Error> {
        let auth = RevpayAuthType::try_from(&item.connector_config)?;

        // Key_Index is Int(3) on the wire; it is configured as a string.
        let key_index = auth.key_index.peek().trim().parse::<u32>().map_err(|_| {
            error_stack::report!(IntegrationError::InvalidDataFormat {
                field_name: "connector_config.api_secret (revPAY Key_Index)",
                context: IntegrationErrorContext {
                    additional_context: Some("expected a decimal integer, e.g. \"1\"".to_string()),
                    ..Default::default()
                },
            })
        })?;

        // PRE-FLIGHT GATE: Reference_Number must be the refund's own merchant
        // reference, byte-identical to the one the Refund call signed —
        // revPAY's inquiry resolves only merchant references, not
        // Transaction_IDs. The RSync carrier is
        // `RefundFlowData::connector_request_reference_id` (derived from
        // `merchant_refund_id`, same bytes as `RefundsData::refund_id` at
        // Refund time). NEVER re-derive it from
        // `RefundSyncData::connector_refund_id` — that is revPAY's
        // Transaction_ID, which the inquiry cannot be keyed by — and never
        // default it: an empty reference resolves nothing.
        let reference_number = item
            .resource_common_data
            .connector_request_reference_id
            .clone();
        if reference_number.trim().is_empty() {
            return Err(
                error_stack::report!(IntegrationError::MissingRequiredField {
                field_name: "connector_request_reference_id",
                context: IntegrationErrorContext {
                    additional_context: Some(
                        "revPAY RSync (inquiry re-use) requires the Reference_Number signed on \
                         the original Refund call; the connector_request_reference_id carrier \
                         is empty for this refund-sync request"
                            .to_string(),
                    ),
                    suggested_action: Some(
                        "Ensure the original refund carried merchant_refund_id before requesting \
                         a refund status sync"
                            .to_string(),
                    ),
                    doc_url: None,
                },
            }),
            );
        }

        // Amount = the refund amount, signed with the payment/inquiry
        // formula. `RefundSyncData` carries it only as the optional
        // `refund_money`; there is no legal reconstruction available (the
        // original payment amount would sign the wrong figure), so absence is
        // a hard MissingRequiredField rather than a fabrication.
        let refund_money = item.request.refund_money.as_ref().ok_or_else(|| {
            error_stack::report!(IntegrationError::MissingRequiredField {
                field_name: "refund_money",
                context: IntegrationErrorContext {
                    additional_context: Some(
                        "revPAY RSync (inquiry re-use) signs the REFUND amount; the framework \
                         did not carry refund amount/currency into the refund-sync request"
                            .to_string(),
                    ),
                    suggested_action: Some(
                        "Pass the refund amount on the refund-get (RSync) request".to_string(),
                    ),
                    doc_url: None,
                },
            })
        })?;
        let currency = refund_money.currency.to_string();
        let amount = format_revpay_amount(refund_money.amount, refund_money.currency)
            .change_context(IntegrationError::InvalidDataFormat {
                field_name: "request.refund_money.amount",
                context: IntegrationErrorContext::default(),
            })?;

        // Signature = sha512(MerchantKey + Revpay_Merchant_ID +
        // Reference_Number + Amount + Currency) — the payment/inquiry formula
        // (§3.4), applied to the refund-side values per the Flow 4 decision.
        let signature = generate_revpay_signature(
            auth.merchant_key.peek(),
            &[
                auth.merchant_id.peek(),
                &reference_number,
                &amount,
                &currency,
            ],
        );

        Ok(Self {
            revpay_merchant_id: auth.merchant_id.peek().to_string(),
            reference_number,
            amount,
            currency,
            key_index,
            signature,
        })
    }
}

// Bridge between the macro-generated `RevpayRouterData` wrapper and the
// `TryFrom<&RouterDataV2<..>>` transform above (same idiom as PSync).
impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        RevpayRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    > for RevpayRSyncRequest
{
    type Error = error_stack::Report<IntegrationError>;

    fn try_from(
        wrapper: RevpayRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Self::try_from(&wrapper.router_data)
    }
}

impl TryFrom<ResponseRouterData<RevpayRSyncResponse, Self>>
    for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(item: ResponseRouterData<RevpayRSyncResponse, Self>) -> Result<Self, Self::Error> {
        let response = &item.response;
        let router_data = &item.router_data;

        // INQUIRY SEMANTICS (same posture as PSync): RSync is a status query
        // and revPAY answers every inquiry with HTTP 200, so the refund
        // outcome is REPORTED through the refund status — never returned as
        // `Err(ErrorResponse)`. "00" → Success, "09"/"99" → Pending, every
        // other code (including "76" reference not found) → Failure. The raw
        // code/description ride along on `raw_connector_status`; non-2xx
        // transport faults still go through the shared
        // `build_error_response`.
        let refund_status = response.response_code.refund_sync_status();

        // revPAY echoes Transaction_ID when the reference resolves; when the
        // refund reference resolves to nothing the echo is absent — mirror
        // the request-side id instead of manufacturing a new identifier.
        let connector_refund_id = response
            .transaction_id
            .clone()
            .unwrap_or_else(|| router_data.request.connector_refund_id.clone());

        // Integrity object: RSync compares the lookup ids (not amounts), and
        // this inquiry is keyed by a DIFFERENT id shape (the merchant refund
        // reference) than the connector's own Transaction_ID, so the echoed
        // id would be a false-mismatch target — mirror the request-side ids
        // exactly, per the integrity pattern for sync flows.
        let integrity_object = RefundSyncIntegrityObject {
            connector_transaction_id: router_data.request.connector_transaction_id.clone(),
            connector_refund_id: router_data.request.connector_refund_id.clone(),
        };

        Ok(Self {
            resource_common_data: RefundFlowData {
                status: refund_status,
                raw_connector_status: Some(RawConnectorStatus {
                    code: Some(response.response_code.as_str().to_string()),
                    message: Some(
                        response
                            .error_description
                            .clone()
                            .unwrap_or_else(|| NO_ERROR_MESSAGE.to_string()),
                    ),
                    reason: response.error_description.clone(),
                }),
                ..router_data.resource_common_data.clone()
            },
            response: Ok(RefundsResponseData {
                connector_refund_id,
                refund_status,
                status_code: item.http_code,
                acquirer_reference_number: None,
            }),
            request: RefundSyncData {
                integrity_object: Some(integrity_object),
                ..router_data.request.clone()
            },
            ..router_data.clone()
        })
    }
}

// =============================================================================
// WEBHOOK TYPES — Backend_URL payment notification (Flow 5, §2.1.3)
// =============================================================================

/// revPAY POSTs the payment result server-to-server to the merchant
/// Backend_URL as `application/x-www-form-urlencoded` (NOT JSON). The form
/// body carries the same field set as the Payment backend response. This is
/// the FINAL status source for redirect/wallet payments that left Authorize
/// in `AuthenticationPending`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevpayWebhookBody {
    #[serde(rename = "Revpay_Merchant_ID")]
    pub revpay_merchant_id: String,
    #[serde(rename = "Payment_ID", skip_serializing_if = "Option::is_none")]
    pub payment_id: Option<u16>,
    #[serde(rename = "Bank_Code", skip_serializing_if = "Option::is_none")]
    pub bank_code: Option<String>,
    #[serde(rename = "Transaction_ID")]
    pub transaction_id: String,
    #[serde(rename = "Reference_Number")]
    pub reference_number: String,
    #[serde(
        rename = "Bank_Reference_Number",
        skip_serializing_if = "Option::is_none"
    )]
    pub bank_reference_number: Option<String>,
    /// The exact 2-decimal wire string — signed verbatim, never reformatted.
    #[serde(rename = "Amount")]
    pub amount: String,
    #[serde(rename = "Currency")]
    pub currency: String,
    #[serde(
        rename = "Transaction_Description",
        skip_serializing_if = "Option::is_none"
    )]
    pub transaction_description: Option<String>,
    #[serde(rename = "Fraud_Score", skip_serializing_if = "Option::is_none")]
    pub fraud_score: Option<String>,
    #[serde(rename = "Response_Code")]
    pub response_code: RevpayResponseCode,
    #[serde(rename = "Error_Description", skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
    /// Kept as a string (form bodies are all strings; leading zeros, if any,
    /// must survive) and compared trimmed against the configured index.
    #[serde(rename = "Key_Index")]
    pub key_index: String,
    #[serde(rename = "Signature")]
    pub signature: String,
    #[serde(rename = "Request_Datetime", skip_serializing_if = "Option::is_none")]
    pub request_datetime: Option<String>,
    #[serde(rename = "Response_Datetime", skip_serializing_if = "Option::is_none")]
    pub response_datetime: Option<String>,
}

impl RevpayWebhookBody {
    /// SOURCE VERIFICATION (§3.3, Flow 5): recompute
    /// `lowercase_hex(sha512(MerchantKey + Revpay_Merchant_ID +
    /// Transaction_ID + Response_Code + Reference_Number + Amount +
    /// Currency))` with the configured merchant key over the RECEIVED field
    /// bytes and compare full-string against the received `Signature`
    /// (lower-cased first). The received `Key_Index` must also equal the
    /// configured key index — we hold exactly one merchant key, so an
    /// unknown index can never verify. Returns `false` on ANY mismatch;
    /// never panics.
    pub fn verifies_against(&self, auth: &RevpayAuthType) -> bool {
        if self.key_index.trim() != auth.key_index.peek().trim() {
            return false;
        }
        let expected = generate_revpay_signature(
            auth.merchant_key.peek(),
            &[
                &self.revpay_merchant_id,
                &self.transaction_id,
                self.response_code.as_str(),
                &self.reference_number,
                &self.amount,
                &self.currency,
            ],
        );
        expected == self.signature.trim().to_lowercase()
    }

    /// Event interpretation: "00" — the sale settled → success;
    /// "09"/"99" — still in flight at the bank / pending authorization →
    /// processing; every other code → failure.
    pub fn event_type(&self) -> EventType {
        match &self.response_code {
            RevpayResponseCode::Success => EventType::PaymentIntentSuccess,
            RevpayResponseCode::RedirectRequired | RevpayResponseCode::PendingAuthorization => {
                EventType::PaymentIntentProcessing
            }
            RevpayResponseCode::TransactionNotFound | RevpayResponseCode::Unknown(_) => {
                EventType::PaymentIntentFailure
            }
        }
    }

    /// Attempt-status interpretation, via the SAME payment status mapping
    /// helper the Authorize flow uses (`From<&RevpayResponseCode> for
    /// AttemptStatus`): "00" → Charged, "09" → AuthenticationPending,
    /// "99" → Pending, everything else → Failure.
    pub fn attempt_status(&self) -> AttemptStatus {
        AttemptStatus::from(&self.response_code)
    }

    /// `(code, message)` for a terminal failure webhook, or `None` for the
    /// non-failure codes ("00"/"09"/"99"). The raw `Response_Code` is the
    /// code; `Error_Description` falls back to NO_ERROR_MESSAGE.
    pub fn failure_details(&self) -> Option<(String, String)> {
        match &self.response_code {
            RevpayResponseCode::Success
            | RevpayResponseCode::RedirectRequired
            | RevpayResponseCode::PendingAuthorization => None,
            RevpayResponseCode::TransactionNotFound | RevpayResponseCode::Unknown(_) => Some((
                self.response_code.as_str().to_string(),
                self.error_description
                    .clone()
                    .unwrap_or_else(|| NO_ERROR_MESSAGE.to_string()),
            )),
        }
    }
}

// =============================================================================
// ERROR RESPONSE TYPES
// =============================================================================

// Every field is `Option` on purpose: a vendor error body that omits the wire
// fields must still deserialize. The NO_ERROR_CODE / NO_ERROR_MESSAGE
// sentinels are applied at the call site in the connector's
// `build_error_response` - never `.unwrap_or_default()`, which turns a missing
// code into an empty string indistinguishable from a real empty code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevpayErrorResponse {
    /// Generic REST wrapper fields, when revPAY reports one (e.g. its
    /// undocumented HTTP 422 `{"code":422,"Description":"Unprocessable
    /// Entity"}`). revPAY emits `code` as a bare integer in these bodies but
    /// as a string in others, so accept both.
    #[serde(default, deserialize_with = "revpay_string_or_int")]
    pub code: Option<String>,
    #[serde(alias = "Description", alias = "description", default)]
    pub message: Option<String>,
    /// revPAY's own outcome fields (a non-2xx JSON body still carries them).
    #[serde(rename = "Response_Code", default)]
    pub response_code: Option<String>,
    #[serde(rename = "Error_Description", default)]
    pub error_description: Option<String>,
}

/// Deserializes a JSON string OR number into `Option<String>`, so revPAY's
/// `{"code": 422}` and `{"code": "422"}` error bodies both parse.
fn revpay_string_or_int<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum StringOrNumber {
        String(String),
        Int(i64),
        Float(f64),
    }

    Ok(match Option::<StringOrNumber>::deserialize(deserializer)? {
        Some(StringOrNumber::String(value)) => Some(value),
        Some(StringOrNumber::Int(value)) => Some(value.to_string()),
        Some(StringOrNumber::Float(value)) => Some(value.to_string()),
        None => None,
    })
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // Known-answer vectors from the revPAY Merchant API doc (§3.28 / §3.29)
    // with sample key material Merchant Key "1OoL87PmJQ", Merchant ID
    // "MER00000000001".

    #[test]
    fn error_response_parses_revpay_undocumented_422_body() {
        // Exact body captured from the UAT sandbox (HTTP 422) when
        // Transaction_Description is empty: integer `code`, capitalised
        // `Description`. Must parse into the error shape, not blow up.
        let body = r#"{"code":422,"Description":"Unprocessable Entity"}"#;
        let parsed: RevpayErrorResponse =
            serde_json::from_str(body).expect("422 error body must deserialize");
        assert_eq!(parsed.code.as_deref(), Some("422"));
        assert_eq!(parsed.message.as_deref(), Some("Unprocessable Entity"));
    }

    #[test]
    fn error_response_parses_string_code_variant() {
        let body = r#"{"code":"422","Description":"Unprocessable Entity"}"#;
        let parsed: RevpayErrorResponse =
            serde_json::from_str(body).expect("string-code error body must deserialize");
        assert_eq!(parsed.code.as_deref(), Some("422"));
    }

    #[test]
    fn payment_request_signature_matches_doc_vector() {
        let signature = generate_revpay_signature(
            "1OoL87PmJQ",
            &["MER00000000001", "RF201774111", "52.40", "MYR"],
        );
        assert_eq!(
            signature,
            "0716dc1863519f53d47a11ec603d402782222083b2178f596d210fcb93287e81412dd529fa2adddd8e0cdfa2ddf0bb5e8421f55a105196d4ee58961b253b98a1"
        );
    }

    #[test]
    fn payment_response_signature_matches_doc_vector() {
        // Same formula shape the webhook path (separate task) will verify.
        let signature = generate_revpay_signature(
            "1OoL87PmJQ",
            &[
                "MER00000000001",
                "RT000000007222",
                "00",
                "RF201774111",
                "52.40",
                "MYR",
            ],
        );
        assert_eq!(
            signature,
            "fc8d556ae2e4fa12836e1192a4f0a793a9672af1d2348da502ef299a6b5169f4402fb6bb282a9e097fe1253b4bfd4f2fa365b7d593b564c585fc79b6c302ecad"
        );
    }

    #[test]
    fn refund_request_signature_matches_offline_vector() {
        // Refund formula (§3.10): sha512(key + mid + Reference_Number +
        // Refund_Amount + Original_Reference_Number) — no Currency, original
        // reference appended. Self-computed offline:
        //   python3 -c 'import hashlib; print(hashlib.sha512(
        //       b"1OoL87PmJQMER00000000001RF20177411210.00RF201774111").hexdigest())'
        let signature = generate_revpay_signature(
            "1OoL87PmJQ",
            &["MER00000000001", "RF201774112", "10.00", "RF201774111"],
        );
        assert_eq!(
            signature,
            "981aa4c5b4109e97969e75916eb3c69476eea1180af60d87997916ae5f21f7aa13e384f4dcd7e3aebdd8ccd4571ba1c16e1dbf6f36c5a74b936a943d0fa820bf"
        );
    }

    #[test]
    fn response_code_maps_to_refund_status() {
        // §2.5: only "00" is a synchronous acceptance; all else is declined.
        assert_eq!(
            RevpayResponseCode::Success.refund_status(),
            RefundStatus::Success
        );
        assert_eq!(
            RevpayResponseCode::RedirectRequired.refund_status(),
            RefundStatus::Failure
        );
        assert_eq!(
            RevpayResponseCode::PendingAuthorization.refund_status(),
            RefundStatus::Failure
        );
        assert_eq!(
            RevpayResponseCode::TransactionNotFound.refund_status(),
            RefundStatus::Failure
        );
        assert_eq!(
            RevpayResponseCode::Unknown("30".to_string()).refund_status(),
            RefundStatus::Failure
        );
    }

    #[test]
    fn response_code_maps_to_refund_sync_status() {
        // Flow 4: "00" → Success, "09"/"99" → Pending (in flight — a status
        // query must stay resolvable). "76" is Pending, NOT Failure: whether
        // the inquiry resolves refund references is unverified, so not-found
        // must never terminally fail a refund the Refund call accepted.
        assert_eq!(
            RevpayResponseCode::Success.refund_sync_status(),
            RefundStatus::Success
        );
        assert_eq!(
            RevpayResponseCode::RedirectRequired.refund_sync_status(),
            RefundStatus::Pending
        );
        assert_eq!(
            RevpayResponseCode::PendingAuthorization.refund_sync_status(),
            RefundStatus::Pending
        );
        assert_eq!(
            RevpayResponseCode::TransactionNotFound.refund_sync_status(),
            RefundStatus::Pending
        );
        assert_eq!(
            RevpayResponseCode::Unknown("30".to_string()).refund_sync_status(),
            RefundStatus::Failure
        );
    }

    #[test]
    fn amount_formats_major_with_two_decimals() {
        // RM 52.40 — the bytes revPAY signs must carry the literal dot.
        let amount = format_revpay_amount(MinorUnit::new(5240), Currency::MYR)
            .expect("amount conversion should succeed for MYR");
        assert_eq!(amount, "52.40");
    }

    #[test]
    fn payment_response_parses_uat_redirect_body_with_null_transaction_id() {
        // Captured verbatim from the UAT sandbox (22 Oct 2026) against the
        // gateway's test card: the "09 Request in progress" redirect response
        // has `Transaction_ID: null` plus many optional null fields. Must
        // parse and surface the redirect URL.
        let body = r#"{"Revpay_Merchant_ID":"MER00000006606","Payment_ID":2,"Bank_Code":null,"Transaction_ID":null,"Reference_Number":"azharamin-REVPAY1792669250-R1","Amount":"10.00","Currency":"MYR","Transaction_Description":"Payment azharamin-REVPAY1792669250-R1","Response_Code":"09","Error_Description":"Request in progress.","Key_Index":1,"Signature":"e4b159","Settlement_Amount":null,"Settlement_Currency":null,"Settlement_FX_Rate":null,"Request_Datetime":null,"Response_Datetime":null,"Ecomm_Marketplace":null,"Promo_Code":null,"Funding_Pan_Mask":null,"Funding_Bin":null,"Funding_Exp_Date":null,"Token_Pan":null,"Token_Exp_Date":null,"Fraud_Score":null,"Bank_Reference_Number":null,"Bank_Redirect_URL":"https://stg-mpg.revpay-sandbox.com.my/v1/payment/intents/3936cb80-bf75-4943-92c4-ff7620f70f36/abc"}"#;
        let parsed: RevpayPaymentsResponse =
            serde_json::from_str(body).expect("UAT redirect body must deserialize");
        assert_eq!(parsed.transaction_id, None);
        assert!(matches!(
            parsed.response_code,
            RevpayResponseCode::RedirectRequired
        ));
        assert_eq!(
            parsed.bank_redirect_url.as_deref(),
            Some("https://stg-mpg.revpay-sandbox.com.my/v1/payment/intents/3936cb80-bf75-4943-92c4-ff7620f70f36/abc")
        );
    }

    #[test]
    fn redirect_without_transaction_id_falls_back_to_reference_number() {
        let response = RevpayPaymentsResponse {
            revpay_merchant_id: None,
            payment_id: Some(2),
            transaction_id: None,
            reference_number: Some("reference".to_string()),
            amount: Some(RevpayAmount::Text("10.00".to_string())),
            currency: Some("MYR".to_string()),
            response_code: RevpayResponseCode::RedirectRequired,
            error_description: Some("Request in progress.".to_string()),
            bank_redirect_url: Some("https://example.com/redirect".to_string()),
            key_index: Some(1),
            signature: Some("signature".to_string()),
            bank_reference_number: None,
        };

        // "09" carries `Transaction_ID: null`; the interim resource id is the
        // `Reference_Number` we sent (PSync later overwrites it with the real
        // Transaction_ID).
        assert!(matches!(
            authorize_resource_id(&response, 200).expect("reference number is a valid interim id"),
            ResponseId::ConnectorTransactionId(id) if id == "reference"
        ));
    }

    #[test]
    fn response_without_any_identifier_is_rejected() {
        let response = RevpayPaymentsResponse {
            revpay_merchant_id: None,
            payment_id: Some(2),
            transaction_id: None,
            reference_number: None,
            amount: Some(RevpayAmount::Text("10.00".to_string())),
            currency: Some("MYR".to_string()),
            response_code: RevpayResponseCode::RedirectRequired,
            error_description: Some("Request in progress.".to_string()),
            bank_redirect_url: Some("https://example.com/redirect".to_string()),
            key_index: Some(1),
            signature: Some("signature".to_string()),
            bank_reference_number: None,
        };

        assert!(authorize_resource_id(&response, 200).is_err());
    }

    #[test]
    fn exp_date_formats_strict_yyyymm() {
        // revPAY `Funding_Exp_Date` is YYYYMM — the UAT gateway's own sample
        // is "203901" = January 2039.
        let exp = format_revpay_exp_date("01", "2039").expect("valid expiry must format");
        assert_eq!(exp.peek(), "203901");
        let exp = format_revpay_exp_date("1", "39").expect("valid expiry must format");
        assert_eq!(exp.peek(), "203901");
    }

    #[test]
    fn exp_date_rejects_malformed_values() {
        // Anything but M/MM + YY/YYYY must fail locally instead of surfacing
        // as revPAY Response_Code 14 "Invalid buyer account or card
        // information" (the gateway rejects a malformed Funding_Exp_Date).
        assert!(format_revpay_exp_date("13", "2039").is_err());
        assert!(format_revpay_exp_date("0", "2039").is_err());
        assert!(format_revpay_exp_date("01", "01/2039").is_err());
        assert!(format_revpay_exp_date("01", "").is_err());
        assert!(format_revpay_exp_date("Jan", "2039").is_err());
    }

    #[test]
    fn card_type_infers_from_pan_bin() {
        // UCS `card_network` is absent on the euler /txns path, so `Card_Type`
        // (Appendix H) is inferred from the PAN; a missing Card_Type is a
        // gateway-confirmed cause of Response_Code 14.
        assert!(matches!(
            card_type_from_pan("4111111111111111"),
            Some(RevpayCardType::Visa)
        ));
        // The gateway's own UAT test card is a MasterCard BIN.
        assert!(matches!(
            card_type_from_pan("5123450000000008"),
            Some(RevpayCardType::Mastercard)
        ));
        assert!(matches!(
            card_type_from_pan("5123-4500 0000-0008"),
            Some(RevpayCardType::Mastercard)
        ));
        assert!(matches!(
            card_type_from_pan("2221000000000009"),
            Some(RevpayCardType::Mastercard)
        ));
        assert!(matches!(
            card_type_from_pan("378282246310005"),
            Some(RevpayCardType::Amex)
        ));
        // BIN 62 = UnionPay (incl. MyDebit co-badged, e.g. 625094…): Appendix H
        // has no UnionPay code, so it maps to `05` rather than being omitted —
        // omission is a gateway-confirmed cause of Response_Code 14.
        assert!(matches!(
            card_type_from_pan("6250941234567890"),
            Some(RevpayCardType::MyDebit)
        ));
        assert!(card_type_from_pan("9999").is_none());
    }

    #[test]
    fn unionpay_explicit_network_maps_to_mydebit_card_type() {
        let (payment_id, card_type) =
            card_payment_details(Some(&CardNetwork::UnionPay), "6250941234567890");
        assert_eq!(payment_id, CARD_PAYMENT_ID);
        assert!(matches!(card_type, Some(RevpayCardType::MyDebit)));
    }

    #[test]
    fn card_type_serializes_to_appendix_h_codes() {
        assert_eq!(
            serde_json::to_string(&RevpayCardType::Visa).expect("serialize"),
            "\"02\""
        );
        assert_eq!(
            serde_json::to_string(&RevpayCardType::Mastercard).expect("serialize"),
            "\"03\""
        );
        assert_eq!(
            serde_json::to_string(&RevpayCardType::Amex).expect("serialize"),
            "\"04\""
        );
        assert_eq!(
            serde_json::to_string(&RevpayCardType::MyDebit).expect("serialize"),
            "\"05\""
        );
    }

    #[test]
    fn issuer_country_maps_to_alpha3() {
        // Gateway sample sends "MYS" (ISO 3166-1 alpha-3).
        assert_eq!(issuer_country_alpha3(Some("mys"), None).as_deref(), Some("MYS"));
        assert_eq!(
            issuer_country_alpha3(None, Some(CountryAlpha2::MY)).as_deref(),
            Some("MYS")
        );
        assert_eq!(
            issuer_country_alpha3(Some("IN"), Some(CountryAlpha2::MY)).as_deref(),
            Some("MYS"),
            "a two-letter card country must fall back to billing"
        );
        assert_eq!(issuer_country_alpha3(None, None), None);
    }

    #[test]
    fn amount_round_trips_through_wire_form() {
        let amount = format_revpay_amount(MinorUnit::new(1000), Currency::MYR)
            .expect("amount conversion should succeed");
        assert_eq!(amount, "10.00");
        let back = parse_revpay_amount(&amount, Currency::MYR).expect("parse should succeed");
        assert_eq!(back, MinorUnit::new(1000));

        // Zero-exponent currency: no minor units, still rendered with two decimals.
        let jpy = format_revpay_amount(MinorUnit::new(1000), Currency::JPY)
            .expect("JPY conversion should succeed");
        assert_eq!(jpy, "1000.00");
        let back = parse_revpay_amount(&jpy, Currency::JPY).expect("parse should succeed");
        assert_eq!(back, MinorUnit::new(1000));
    }

    // ========================================================================
    // WEBHOOK TESTS (Flow 5) — doc-vector-based, key "1OoL87PmJQ"
    // ========================================================================
    //
    // Positive vector recomputed offline (matches the doc's §3.29 response
    // signature KA-vector):
    //   python3 -c 'import hashlib; print(hashlib.sha512(
    //       b"1OoL87PmJQMER00000000001RT00000000722200RF20177411152.40MYR"
    //   ).hexdigest())'
    const WEBHOOK_DOC_SIGNATURE: &str = "fc8d556ae2e4fa12836e1192a4f0a793a9672af1d2348da502ef299a6b5169f4402fb6bb282a9e097fe1253b4bfd4f2fa365b7d593b564c585fc79b6c302ecad";

    fn webhook_auth() -> RevpayAuthType {
        RevpayAuthType {
            merchant_id: Secret::new("MER00000000001".to_string()),
            merchant_key: Secret::new("1OoL87PmJQ".to_string()),
            key_index: Secret::new("1".to_string()),
        }
    }

    fn webhook_form_body(amount: &str, key_index: &str, signature: &str) -> String {
        format!(
            "Revpay_Merchant_ID=MER00000000001&Payment_ID=2&Bank_Code=MB2U&\
             Transaction_ID=RT000000007222&Reference_Number=RF201774111&\
             Bank_Reference_Number=BR000001&Amount={amount}&Currency=MYR&\
             Transaction_Description=Order+RF201774111&Fraud_Score=0&\
             Response_Code=00&Error_Description=&Key_Index={key_index}&\
             Signature={signature}&Request_Datetime=2020-01-01+12%3A00%3A00&\
             Response_Datetime=2020-01-01+12%3A00%3A05"
        )
    }

    #[test]
    fn webhook_body_parses_form_encoded() {
        let body: RevpayWebhookBody =
            serde_urlencoded::from_str(&webhook_form_body("52.40", "1", WEBHOOK_DOC_SIGNATURE))
                .expect("form-encoded webhook body parses");
        assert_eq!(body.revpay_merchant_id, "MER00000000001");
        assert_eq!(body.payment_id, Some(2));
        assert_eq!(body.transaction_id, "RT000000007222");
        assert_eq!(body.reference_number, "RF201774111");
        assert_eq!(body.amount, "52.40");
        assert_eq!(body.currency, "MYR");
        assert_eq!(body.response_code, RevpayResponseCode::Success);
        assert_eq!(body.error_description, Some(String::new()));
        assert_eq!(body.key_index, "1");
        assert_eq!(body.signature, WEBHOOK_DOC_SIGNATURE);
    }

    #[test]
    fn webhook_signature_verify_accepts_doc_vector() {
        let body: RevpayWebhookBody =
            serde_urlencoded::from_str(&webhook_form_body("52.40", "1", WEBHOOK_DOC_SIGNATURE))
                .expect("form-encoded webhook body parses");
        assert!(body.verifies_against(&webhook_auth()));
    }

    #[test]
    fn webhook_signature_verify_rejects_tampered_amount() {
        // Same body, same signature, but Amount flipped 52.40 -> 52.41: the
        // recomputed sha512 preimage differs, so verification MUST fail.
        let body: RevpayWebhookBody =
            serde_urlencoded::from_str(&webhook_form_body("52.41", "1", WEBHOOK_DOC_SIGNATURE))
                .expect("form-encoded webhook body parses");
        assert!(!body.verifies_against(&webhook_auth()));
    }

    #[test]
    fn webhook_signature_verify_rejects_unknown_key_index() {
        // A Key_Index we do not hold cannot verify — we keep exactly one key.
        let body: RevpayWebhookBody =
            serde_urlencoded::from_str(&webhook_form_body("52.40", "2", WEBHOOK_DOC_SIGNATURE))
                .expect("form-encoded webhook body parses");
        assert!(!body.verifies_against(&webhook_auth()));
    }

    #[test]
    fn webhook_event_and_status_mapping_follows_response_code() {
        let parse = |code: &str| RevpayWebhookBody {
            revpay_merchant_id: "MER00000000001".to_string(),
            payment_id: None,
            bank_code: None,
            transaction_id: "RT000000007222".to_string(),
            reference_number: "RF201774111".to_string(),
            bank_reference_number: None,
            amount: "52.40".to_string(),
            currency: "MYR".to_string(),
            transaction_description: None,
            fraud_score: None,
            response_code: serde_json::from_str::<RevpayResponseCode>(&format!("\"{code}\""))
                .expect("response code parses"),
            error_description: (code != "00" && code != "09" && code != "99")
                .then(|| "Declined".to_string()),
            key_index: "1".to_string(),
            signature: WEBHOOK_DOC_SIGNATURE.to_string(),
            request_datetime: None,
            response_datetime: None,
        };

        // "00" — final success for a payment that left Authorize pending.
        let body = parse("00");
        assert_eq!(body.event_type(), EventType::PaymentIntentSuccess);
        assert_eq!(body.attempt_status(), AttemptStatus::Charged);
        assert_eq!(body.failure_details(), None);

        // "09"/"99" — still resolvable; NOT a failure and NOT terminal.
        let body = parse("99");
        assert_eq!(body.event_type(), EventType::PaymentIntentProcessing);
        assert_eq!(body.attempt_status(), AttemptStatus::Pending);
        assert_eq!(body.failure_details(), None);

        // Terminal failure carries the raw code + description.
        let body = parse("1A");
        assert_eq!(body.event_type(), EventType::PaymentIntentFailure);
        assert_eq!(body.attempt_status(), AttemptStatus::Failure);
        assert_eq!(
            body.failure_details(),
            Some(("1A".to_string(), "Declined".to_string()))
        );
    }

    #[test]
    fn response_code_deserializes_known_and_unknown_codes() {
        assert_eq!(
            serde_json::from_str::<RevpayResponseCode>("\"00\"").expect("00 parses"),
            RevpayResponseCode::Success
        );
        assert_eq!(
            serde_json::from_str::<RevpayResponseCode>("\"09\"").expect("09 parses"),
            RevpayResponseCode::RedirectRequired
        );
        assert_eq!(
            serde_json::from_str::<RevpayResponseCode>("\"99\"").expect("99 parses"),
            RevpayResponseCode::PendingAuthorization
        );
        // Inquiry-side mapping round-trip for the documented pending codes.
        assert_eq!(
            RevpayResponseCode::Success.psync_status(),
            AttemptStatus::Charged
        );
        assert_eq!(
            RevpayResponseCode::RedirectRequired.psync_status(),
            AttemptStatus::Pending
        );
        assert_eq!(
            RevpayResponseCode::PendingAuthorization.psync_status(),
            AttemptStatus::Pending
        );
        assert_eq!(
            RevpayResponseCode::Unknown("76".to_string()).psync_status(),
            AttemptStatus::Failure
        );
        assert_eq!(
            serde_json::from_str::<RevpayResponseCode>("\"1A\"").expect("1A parses"),
            RevpayResponseCode::Unknown("1A".to_string())
        );
    }
}
