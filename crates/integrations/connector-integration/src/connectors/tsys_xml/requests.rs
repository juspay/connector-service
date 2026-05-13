use std::fmt::Debug;

use common_utils::types::StringMajorUnit;
use domain_types::{errors::IntegrationError, payment_method_data::PaymentMethodDataTypes};
use error_stack::ResultExt;
use hyperswitch_masking::Secret;
use serde::Serialize;

use super::super::macros::GetSoapXml;

/// Origin of card data — drives how TransIT scores risk / which fields are required.
///
/// PHONE = MOTO, INTERNET = eCommerce, MANUAL = keyed (incremental auth / void),
/// RECURRING = scheduled MIT. Tech spec § Sale/Auth Field Reference.
#[derive(Debug, Serialize, Clone, Copy)]
#[serde(rename_all = "UPPERCASE")]
pub enum TsysXmlCardDataSource {
    Phone,
    Internet,
    Manual,
    Recurring,
}

fn generate_xml<T: Serialize>(
    request: &T,
) -> Result<String, error_stack::Report<IntegrationError>> {
    let body = quick_xml::se::to_string(request).change_context(
        IntegrationError::RequestEncodingFailed {
            context: Default::default(),
        },
    )?;

    Ok(format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}", body))
}

/// TransIT Sale / Auth request.
///
/// Both `<Sale>` and `<Auth>` share the same field schema (tech spec § 1, § 2). We
/// flip the root element via a tagged enum so callers can pick at runtime based on
/// `auto_capture`.
#[derive(Debug, Serialize)]
pub enum TsysXmlAuthorizeRequest<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
{
    #[serde(rename = "Sale")]
    Sale(TsysXmlAuthorizeBody<T>),
    #[serde(rename = "Auth")]
    Auth(TsysXmlAuthorizeBody<T>),
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> GetSoapXml
    for TsysXmlAuthorizeRequest<T>
{
    fn to_soap_xml(&self) -> String {
        generate_xml(self).unwrap_or_else(|_| {
            // Empty-body fallback; the macro layer also validates and surfaces
            // structural failures, so this branch is essentially unreachable
            // for valid inputs.
            String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Sale/>")
        })
    }
}

#[derive(Debug, Serialize)]
pub struct TsysXmlAuthorizeBody<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
{
    #[serde(rename = "deviceID")]
    pub device_id: Secret<String>,
    #[serde(rename = "transactionKey")]
    pub transaction_key: Secret<String>,
    #[serde(rename = "developerID")]
    pub developer_id: Secret<String>,
    #[serde(rename = "cardDataSource")]
    pub card_data_source: TsysXmlCardDataSource,
    #[serde(rename = "transactionAmount")]
    pub transaction_amount: StringMajorUnit,
    #[serde(rename = "cardNumber")]
    pub card_number: Secret<String>,
    /// MM/YY — TransIT explicitly documents this format (tech spec § Field Reference).
    #[serde(rename = "expirationDate")]
    pub expiration_date: Secret<String>,
    #[serde(rename = "cvv2", skip_serializing_if = "Option::is_none")]
    pub cvv2: Option<Secret<String>>,
    #[serde(rename = "addressLine1", skip_serializing_if = "Option::is_none")]
    pub address_line1: Option<Secret<String>>,
    #[serde(rename = "zip", skip_serializing_if = "Option::is_none")]
    pub zip: Option<Secret<String>>,
    #[serde(rename = "externalReferenceID", skip_serializing_if = "Option::is_none")]
    pub external_reference_id: Option<String>,
    /// Phantom marker so the generic `T` is preserved on the struct without leaking
    /// into the serialized payload.
    #[serde(skip)]
    pub _marker: std::marker::PhantomData<T>,
}

/// TransIT Transaction Inquiry (PSync) request.
///
/// TODO(tsys_xml): UNDECIDED - confirm element name with TSYS.
/// The spec lists `<TransactionInquiry>` as the most likely candidate with
/// `<GetDetails>` as alternative.
#[derive(Debug, Serialize)]
#[serde(rename = "TransactionInquiry")]
pub struct TsysXmlTransactionInquiryRequest {
    #[serde(rename = "deviceID")]
    pub device_id: Secret<String>,
    #[serde(rename = "transactionKey")]
    pub transaction_key: Secret<String>,
    #[serde(rename = "developerID")]
    pub developer_id: Secret<String>,
    #[serde(rename = "transactionID")]
    pub transaction_id: String,
}

impl GetSoapXml for TsysXmlTransactionInquiryRequest {
    fn to_soap_xml(&self) -> String {
        generate_xml(self).unwrap_or_else(|_| {
            // Empty-body fallback; the macro layer also validates and surfaces
            // structural failures, so this branch is essentially unreachable
            // for valid inputs.
            String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<TransactionInquiry/>")
        })
    }
}

/// RSync request — reuses the PSync `<TransactionInquiry>` shape via a type
/// alias. TransIT exposes a single inquiry endpoint for both payment and
/// refund status lookups; the type alias keeps the macro layer's Templating
/// types distinct without duplicating wire-level schema.
pub type TsysXmlRSyncRequest = TsysXmlTransactionInquiryRequest;

/// TransIT Capture request (tech spec § Capture / Field Reference for Capture).
///
/// Roots at `<Capture>`. The auth triple (`deviceID` / `transactionKey` /
/// `developerID`) is flattened into the body just like the other flows.
/// `transactionID` references the prior Auth's `<transactionID>`.
///
/// `seqNumber` / `paymentCount` are reserved for multi-clearing
/// (split-shipment / partial captures against a single auth). PR-1 leaves them
/// as `None`; a follow-up via `add-connector-flow` will wire them up.
#[derive(Debug, Serialize)]
#[serde(rename = "Capture")]
pub struct TsysXmlCaptureRequest {
    #[serde(rename = "deviceID")]
    pub device_id: Secret<String>,
    #[serde(rename = "transactionKey")]
    pub transaction_key: Secret<String>,
    #[serde(rename = "developerID")]
    pub developer_id: Secret<String>,
    #[serde(rename = "transactionID")]
    pub transaction_id: String,
    #[serde(rename = "transactionAmount")]
    pub transaction_amount: StringMajorUnit,
    /// Multi-clearing sequence number (1-based). Stubbed `None` for PR-1.
    #[serde(rename = "seqNumber", skip_serializing_if = "Option::is_none")]
    pub seq_number: Option<u32>,
    /// Total expected capture count for this auth. Stubbed `None` for PR-1.
    #[serde(rename = "paymentCount", skip_serializing_if = "Option::is_none")]
    pub payment_count: Option<u32>,
}

impl GetSoapXml for TsysXmlCaptureRequest {
    fn to_soap_xml(&self) -> String {
        generate_xml(self).unwrap_or_else(|_| {
            // Empty-body fallback; the macro layer also validates and surfaces
            // structural failures, so this branch is essentially unreachable
            // for valid inputs.
            String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Capture/>")
        })
    }
}

/// TransIT Return (Refund) request (tech spec § Return / Field Reference for Return).
///
/// Roots at `<Return>`. TransIT supports three modes from the same element shape:
///
/// 1. **Referenced full**: `transactionID` populated, no `transactionAmount` →
///    refunds the full captured amount. (PR-1 still emits `transactionAmount`
///    for explicitness; "omit for full" is a follow-up TODO.)
/// 2. **Referenced partial**: `transactionID` + `transactionAmount` (less than
///    the original).
/// 3. **Unreferenced** ("Return WITHOUT Reference"): NO `transactionID`; raw
///    card data (`cardNumber`, `expirationDate`, `cardDataSource`) +
///    `transactionAmount` instead.
///
/// All discriminator fields are `Option<>` and `skip_serializing_if`-gated so a
/// single struct can serialize any of the three layouts.
#[derive(Debug, Serialize)]
#[serde(rename = "Return")]
pub struct TsysXmlReturnRequest {
    #[serde(rename = "deviceID")]
    pub device_id: Secret<String>,
    #[serde(rename = "transactionKey")]
    pub transaction_key: Secret<String>,
    #[serde(rename = "developerID")]
    pub developer_id: Secret<String>,
    /// Reference to the original capture's `<transactionID>`. Present for
    /// referenced refunds; absent for unreferenced refunds.
    #[serde(rename = "transactionID", skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,
    /// Origin of card data — only sent for unreferenced refunds.
    #[serde(rename = "cardDataSource", skip_serializing_if = "Option::is_none")]
    pub card_data_source: Option<TsysXmlCardDataSource>,
    /// PAN — only present for unreferenced refunds.
    #[serde(rename = "cardNumber", skip_serializing_if = "Option::is_none")]
    pub card_number: Option<Secret<String>>,
    /// MM/YY — only present for unreferenced refunds.
    #[serde(rename = "expirationDate", skip_serializing_if = "Option::is_none")]
    pub expiration_date: Option<Secret<String>>,
    /// CVV — optional even within the unreferenced mode (not all card types
    /// require it).
    #[serde(rename = "cvv2", skip_serializing_if = "Option::is_none")]
    pub cvv2: Option<Secret<String>>,
    /// Refund amount in major units. Always emitted in PR-1; "omit for full
    /// referenced refunds" is a TODO follow-up.
    #[serde(rename = "transactionAmount", skip_serializing_if = "Option::is_none")]
    pub transaction_amount: Option<StringMajorUnit>,
}

impl GetSoapXml for TsysXmlReturnRequest {
    fn to_soap_xml(&self) -> String {
        generate_xml(self).unwrap_or_else(|_| {
            // Empty-body fallback; the macro layer also validates and surfaces
            // structural failures, so this branch is essentially unreachable
            // for valid inputs.
            String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Return/>")
        })
    }
}

/// TransIT Void request (tech spec § Void / Field Reference for Void).
///
/// Roots at `<Void>`. The auth triple (`deviceID` / `transactionKey` /
/// `developerID`) is flattened into the body just like the other flows.
/// `transactionID` references the prior Auth/Capture's `<transactionID>`.
///
/// `transactionAmount` is OPTIONAL — omit for a full void; include for a
/// partial void (cert script Step 7).
#[derive(Debug, Serialize)]
#[serde(rename = "Void")]
pub struct TsysXmlVoidRequest {
    #[serde(rename = "deviceID")]
    pub device_id: Secret<String>,
    #[serde(rename = "transactionKey")]
    pub transaction_key: Secret<String>,
    #[serde(rename = "developerID")]
    pub developer_id: Secret<String>,
    #[serde(rename = "transactionID")]
    pub transaction_id: String,
    /// Optional — present for a partial void, omitted for a full void.
    #[serde(rename = "transactionAmount", skip_serializing_if = "Option::is_none")]
    pub transaction_amount: Option<StringMajorUnit>,
}

impl GetSoapXml for TsysXmlVoidRequest {
    fn to_soap_xml(&self) -> String {
        generate_xml(self).unwrap_or_else(|_| {
            // Empty-body fallback; the macro layer also validates and surfaces
            // structural failures, so this branch is essentially unreachable
            // for valid inputs.
            String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Void/>")
        })
    }
}
