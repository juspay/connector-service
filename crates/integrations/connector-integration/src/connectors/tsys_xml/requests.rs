use std::fmt::Debug;

use common_utils::types::StringMajorUnit;
use domain_types::{errors::IntegrationError, payment_method_data::PaymentMethodDataTypes};
use error_stack::ResultExt;
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};

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
    Mail,
}

// =============================================================================
// TerminalData group — XSD-driven enums for the e-commerce cert script.
//
// Every variant carries its exact XSD wire string via `#[serde(rename = "...")]`.
// We avoid `rename_all` to keep the wire contract explicit.
//
// `Deserialize` is derived on each enum so the connector metadata override
// (`connector_metadata.tsys_xml.terminal_data.*`) — which arrives as a
// `serde_json::Value` — can parse straight into these types.
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TsysXmlTerminalCapability {
    #[serde(rename = "UNKNOWN")]
    Unknown,
    #[serde(rename = "NO_TERMINAL_MANUAL")]
    NoTerminalManual,
    #[serde(rename = "MAGSTRIPE_READ_ONLY")]
    MagstripeReadOnly,
    #[serde(rename = "OCR")]
    Ocr,
    #[serde(rename = "ICC_CHIP_READ_ONLY")]
    IccChipReadOnly,
    #[serde(rename = "KEYED_ENTRY_ONLY")]
    KeyedEntryOnly,
    #[serde(rename = "MAGSTRIPE_CONTACTLESS_ONLY")]
    MagstripeContactlessOnly,
    #[serde(rename = "MAGSTRIPE_KEYED_ENTRY_ONLY")]
    MagstripeKeyedEntryOnly,
    #[serde(rename = "MAGSTRIPE_ICC_KEYED_ENTRY_ONLY")]
    MagstripeIccKeyedEntryOnly,
    #[serde(rename = "MAGSTRIPE_ICC_ONLY")]
    MagstripeIccOnly,
    #[serde(rename = "ICC_KEYED_ENTRY_ONLY")]
    IccKeyedEntryOnly,
    #[serde(rename = "ICC_CHIP_CONTACT_CONTACTLESS")]
    IccChipContactContactless,
    #[serde(rename = "ICC_CONTACTLESS_ONLY")]
    IccContactlessOnly,
    #[serde(rename = "OTHER_CAPABILITY_FOR_MASTERCARD")]
    OtherCapabilityForMastercard,
    #[serde(rename = "MAGSTRIPE_SIGNATURE_FOR_AMEX_ONLY")]
    MagstripeSignatureForAmexOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TsysXmlTerminalOperatingEnvironment {
    #[serde(rename = "NO_TERMINAL")]
    NoTerminal,
    #[serde(rename = "ON_MERCHANT_PREMISES_ATTENDED")]
    OnMerchantPremisesAttended,
    #[serde(rename = "ON_MERCHANT_PREMISES_UNATTENDED")]
    OnMerchantPremisesUnattended,
    #[serde(rename = "OFF_MERCHANT_PREMISES_ATTENDED")]
    OffMerchantPremisesAttended,
    #[serde(rename = "OFF_MERCHANT_PREMISES_UNATTENDED")]
    OffMerchantPremisesUnattended,
    #[serde(rename = "ON_CUSTOMER_PREMISES_UNATTENDED")]
    OnCustomerPremisesUnattended,
    #[serde(rename = "UNKNOWN")]
    Unknown,
    #[serde(rename = "ELECTRONIC_DELIVERY_AMEX")]
    ElectronicDeliveryAmex,
    #[serde(rename = "PHYSICAL_DELIVERY_AMEX")]
    PhysicalDeliveryAmex,
    #[serde(rename = "OFF_MERCHANT_PREMISES_MPOS")]
    OffMerchantPremisesMpos,
    #[serde(rename = "ON_MERCHANT_PREMISES_MPOS")]
    OnMerchantPremisesMpos,
    #[serde(rename = "OFF_MERCHANT_PREMISES_CUSTOMER_POS")]
    OffMerchantPremisesCustomerPos,
    #[serde(rename = "ON_MERCHANT_PREMISES_CUSTOMER_POS")]
    OnMerchantPremisesCustomerPos,
    #[serde(rename = "OFF_CUSTOMER_PREMISES_UNATTENDED")]
    OffCustomerPremisesUnattended,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TsysXmlCardholderAuthenticationMethod {
    #[serde(rename = "NOT_AUTHENTICATED")]
    NotAuthenticated,
    #[serde(rename = "PIN")]
    Pin,
    #[serde(rename = "ELECTRONIC_SIGNATURE_ANALYSIS")]
    ElectronicSignatureAnalysis,
    #[serde(rename = "MANUAL_SIGNATURE")]
    ManualSignature,
    #[serde(rename = "MANUAL_OTHER")]
    ManualOther,
    #[serde(rename = "UNKNOWN")]
    Unknown,
    #[serde(rename = "SYSTEMATIC_OTHER")]
    SystematicOther,
    #[serde(rename = "E_TICKET_ENV_AMEX")]
    ETicketEnvAmex,
    #[serde(rename = "OFFLINE_PIN")]
    OfflinePin,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TsysXmlTerminalAuthenticationCapability {
    #[serde(rename = "NO_CAPABILITY")]
    NoCapability,
    #[serde(rename = "PIN_ENTRY")]
    PinEntry,
    #[serde(rename = "SIGNATURE_ANALYSIS")]
    SignatureAnalysis,
    #[serde(rename = "MPOS_SOFTWARE_BASED_PIN_ENTRY_CAPABILITY")]
    MposSoftwareBasedPinEntryCapability,
    #[serde(rename = "SIGNATURE_ANALYSIS_INOPERATIVE")]
    SignatureAnalysisInoperative,
    #[serde(rename = "OTHER")]
    Other,
    #[serde(rename = "UNKNOWN")]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TsysXmlTerminalOutputCapability {
    #[serde(rename = "NONE")]
    None,
    #[serde(rename = "PRINT_ONLY")]
    PrintOnly,
    #[serde(rename = "DISPLAY_ONLY")]
    DisplayOnly,
    #[serde(rename = "PRINT_AND_DISPLAY")]
    PrintAndDisplay,
    #[serde(rename = "UNKNOWN")]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TsysXmlMaxPinLength {
    #[serde(rename = "UNKNOWN")]
    Unknown,
    #[serde(rename = "NOT_SUPPORTED")]
    NotSupported,
    #[serde(rename = "4")]
    Four,
    #[serde(rename = "5")]
    Five,
    #[serde(rename = "6")]
    Six,
    #[serde(rename = "7")]
    Seven,
    #[serde(rename = "8")]
    Eight,
    #[serde(rename = "9")]
    Nine,
    #[serde(rename = "10")]
    Ten,
    #[serde(rename = "11")]
    Eleven,
    #[serde(rename = "12")]
    Twelve,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TsysXmlTerminalCardCaptureCapability {
    #[serde(rename = "NO_CAPABILITY")]
    NoCapability,
    #[serde(rename = "CARD_CAPTURE_CAPABILITY")]
    CardCaptureCapability,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TsysXmlCardholderPresentDetail {
    #[serde(rename = "CLICK_TO_PAY_DISCOVER")]
    ClickToPayDiscover,
    #[serde(rename = "CARDHOLDER_PRESENT")]
    CardholderPresent,
    #[serde(rename = "CARDHOLDER_NOT_PRESENT_UNSPECIFIED_REASON")]
    CardholderNotPresentUnspecifiedReason,
    #[serde(rename = "CARDHOLDER_NOT_PRESENT_MAIL_TRANSACTION")]
    CardholderNotPresentMailTransaction,
    #[serde(rename = "CARDHOLDER_NOT_PRESENT_PHONE_TRANSACTION")]
    CardholderNotPresentPhoneTransaction,
    #[serde(rename = "CARDHOLDER_NOT_PRESENT_RECURRING_TRANSACTION")]
    CardholderNotPresentRecurringTransaction,
    #[serde(rename = "CARDHOLDER_NOT_PRESENT_ELECTRONIC_COMMERCE")]
    CardholderNotPresentElectronicCommerce,
    #[serde(rename = "CARDHOLDER_NOT_PRESENT_INSTALLMENT_TRANSACTION")]
    CardholderNotPresentInstallmentTransaction,
    #[serde(rename = "PARTIAL_SHIPMENT_TRANSACTION_ON_TOKEN_CRYPTOGRAM_TXN")]
    PartialShipmentTransactionOnTokenCryptogramTxn,
    #[serde(rename = "RECURRING_TRANSACTION_ON_TOKEN_CRYPTOGRAM_TXN")]
    RecurringTransactionOnTokenCryptogramTxn,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TsysXmlCardPresentDetail {
    #[serde(rename = "CARD_NOT_PRESENT")]
    CardNotPresent,
    #[serde(rename = "CARD_PRESENT")]
    CardPresent,
    #[serde(rename = "TRANSPONDER_AMEX")]
    TransponderAmex,
    #[serde(rename = "CONTACTLESS_CHIP_TRANSACTIONS")]
    ContactlessChipTransactions,
    #[serde(rename = "DIGITAL_WALLET_AMEX")]
    DigitalWalletAmex,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TsysXmlCardDataInputMode {
    #[serde(rename = "VOICE_AUTH_ARU_ONLY")]
    VoiceAuthAruOnly,
    #[serde(rename = "MAGNETIC_STRIPE_READER_INPUT")]
    MagneticStripeReaderInput,
    #[serde(rename = "BAR_CODE_PAYMENT_CODE")]
    BarCodePaymentCode,
    #[serde(rename = "KEY_ENTERED_INPUT")]
    KeyEnteredInput,
    #[serde(rename = "MERCHANT_INITIATED_TRANSACTION_CARD_CREDENTIAL_STORED_ON_FILE")]
    MerchantInitiatedTransactionCardCredentialStoredOnFile,
    #[serde(rename = "PAN_AUTO_ENTRY_CONTACTLESS_MAGNETIC_STRIPE")]
    PanAutoEntryContactlessMagneticStripe,
    #[serde(rename = "MAGNETIC_STRIPE_READER_INPUT_TRACK_DATA_CAPTURED_PASSED_UNALTERED")]
    MagneticStripeReaderInputTrackDataCapturedPassedUnaltered,
    #[serde(rename = "ONLINE_CHIP")]
    OnlineChip,
    #[serde(rename = "OFFLINE_CHIP")]
    OfflineChip,
    #[serde(rename = "PAN_AUTO_ENTRY_CONTACTLESS_CHIP_CARD")]
    PanAutoEntryContactlessChipCard,
    #[serde(rename = "TRACK_DATA_READ_UNALTERED_CHIP_CAPABLE_TERMINAL_CHIP_DATA_NOT_READ")]
    TrackDataReadUnalteredChipCapableTerminalChipDataNotRead,
    #[serde(rename = "EMPTY_CANDIDATE_LIST_FALLBACK")]
    EmptyCandidateListFallback,
    #[serde(rename = "PAN_ENTRY_ELECTRONIC_COMMERCE_INCLUDING_REMOTE_CHIP")]
    PanEntryElectronicCommerceIncludingRemoteChip,
    #[serde(rename = "ELECTRONIC_COMMERCE_NO_SECURITY_CHANNEL_ENCRYPTED_SET_WITHOUT_CARDHOLDER_CERTIFICATE")]
    ElectronicCommerceNoSecurityChannelEncryptedSetWithoutCardholderCertificate,
    #[serde(rename = "MANUALLY_ENTERED_WITH_KEYED_CID_AMEX_JCB")]
    ManuallyEnteredWithKeyedCidAmexJcb,
    #[serde(rename = "SWIPED_TRANSACTION_WITH_KEYED_CID_AMEX_JCB")]
    SwipedTransactionWithKeyedCidAmexJcb,
    #[serde(rename = "CONTACTLESS_TO_CONTACT_CHIP_CARD_SWITCH_TRANSACTION_DISCOVER_ONLY")]
    ContactlessToContactChipCardSwitchTransactionDiscoverOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TsysXmlCardholderAuthenticationEntity {
    #[serde(rename = "NOT_AUTHENTICATED")]
    NotAuthenticated,
    #[serde(rename = "ICC_OFFLINE_PIN")]
    IccOfflinePin,
    #[serde(rename = "CARD_ACCEPTANCE_DEVICE")]
    CardAcceptanceDevice,
    #[serde(rename = "AUTHORIZING_AGENT_ONLINE_PIN")]
    AuthorizingAgentOnlinePin,
    #[serde(rename = "MERCHANT_CARD_ACCEPTOR_SIGNATURE")]
    MerchantCardAcceptorSignature,
    #[serde(rename = "OTHER")]
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TsysXmlCardDataOutputCapability {
    #[serde(rename = "NONE")]
    None,
    #[serde(rename = "MAGNETIC_STRIPE_WRITE")]
    MagneticStripeWrite,
    #[serde(rename = "ICC")]
    Icc,
    #[serde(rename = "OTHER")]
    Other,
}

/// MC/AMEX-only field. PREAUTH for manual capture (delayed funds), FINAL for
/// auto-capture (Sale).
#[derive(Debug, Clone, Serialize)]
pub enum TsysXmlAuthorizationIndicator {
    #[serde(rename = "PREAUTH")]
    Preauth,
    #[serde(rename = "FINAL")]
    Final,
}

/// `<cardOnFile>` flag — `Y` when a credential is being used / stored on file
/// (CIT / MIT / vault), `N` otherwise. Two-variant enum keeps the wire contract
/// explicit per tech spec § CIT/MIT.
#[derive(Debug, Clone, Copy, Serialize)]
pub enum TsysXmlCardOnFile {
    #[serde(rename = "Y")]
    Y,
    #[serde(rename = "N")]
    N,
}

/// Merchant-initiated-transaction indicator — TransIT XSD enum per § CIT/MIT.
/// Values:
/// - `R` — recurring
/// - `M101` — resubmission
/// - `M102` — reauthorization
/// - `M103` — delayed charge
/// - `M104` — no-show
/// - `S` — installment
#[derive(Debug, Clone, Copy, Serialize)]
pub enum TsysXmlMitIndicator {
    R,
    M101,
    M102,
    M103,
    M104,
    S,
}

/// `<mit>` wrapper carrying the MIT indicator value.
#[derive(Debug, Clone, Serialize)]
#[serde(rename = "mit")]
pub struct TsysXmlMit {
    #[serde(rename = "mitIndicator")]
    pub mit_indicator: TsysXmlMitIndicator,
}

/// Vault wallet details — emitted on Path B MIT (and CreateConnectorCustomer
/// response shape). The `<walletDetails><walletID>...</walletID></walletDetails>`
/// structure replaces PAN/expiry/cvv2 on Path B Authorize calls.
#[derive(Debug, Clone, Serialize)]
#[serde(rename = "walletDetails")]
pub struct TsysXmlWalletDetailsRef {
    #[serde(rename = "walletID")]
    pub wallet_id: Secret<String>,
}

/// Discover/JCB/Diners/CUP-only signal indicating whether the cardholder is a
/// registered user in the merchant's system.
#[derive(Debug, Clone, Serialize)]
pub enum TsysXmlRegisteredUserIndicator {
    #[serde(rename = "YES")]
    Yes,
    #[serde(rename = "NO")]
    No,
}

/// XSD `terminalData` group — required by the TransIT e-commerce certification
/// script for every authorization. The 12 inner fields are all required.
#[derive(Debug, Serialize)]
#[serde(rename = "terminalData")]
pub struct TsysXmlTerminalData {
    #[serde(rename = "terminalCapability")]
    pub terminal_capability: TsysXmlTerminalCapability,
    #[serde(rename = "terminalOperatingEnvironment")]
    pub terminal_operating_environment: TsysXmlTerminalOperatingEnvironment,
    #[serde(rename = "cardholderAuthenticationMethod")]
    pub cardholder_authentication_method: TsysXmlCardholderAuthenticationMethod,
    #[serde(rename = "terminalAuthenticationCapability")]
    pub terminal_authentication_capability: TsysXmlTerminalAuthenticationCapability,
    #[serde(rename = "terminalOutputCapability")]
    pub terminal_output_capability: TsysXmlTerminalOutputCapability,
    #[serde(rename = "maxPinLength")]
    pub max_pin_length: TsysXmlMaxPinLength,
    #[serde(rename = "terminalCardCaptureCapability")]
    pub terminal_card_capture_capability: TsysXmlTerminalCardCaptureCapability,
    #[serde(rename = "cardholderPresentDetail")]
    pub cardholder_present_detail: TsysXmlCardholderPresentDetail,
    #[serde(rename = "cardPresentDetail")]
    pub card_present_detail: TsysXmlCardPresentDetail,
    #[serde(rename = "cardDataInputMode")]
    pub card_data_input_mode: TsysXmlCardDataInputMode,
    #[serde(rename = "cardholderAuthenticationEntity")]
    pub cardholder_authentication_entity: TsysXmlCardholderAuthenticationEntity,
    #[serde(rename = "cardDataOutputCapability")]
    pub card_data_output_capability: TsysXmlCardDataOutputCapability,
}

/// XSD `developerInfo` wrapper. Cert script asks for the developerID to be
/// nested under a `<developerInfo>` element on the Authorize flow.
#[derive(Debug, Serialize)]
#[serde(rename = "developerInfo")]
pub struct TsysXmlDeveloperInfo {
    #[serde(rename = "developerID")]
    pub developer_id: Secret<String>,
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

// Field order MATTERS: TransIT XSD is sequence-validated. Order verified against
// the dev portal MOTO sample and live `<SaleResponse><responseCode>F9901`
// rejections that leaked the allowed-next sets.
//
// CRITICAL DEV-PORTAL DOC MISMATCH:
// The dev portal labels `terminalData` and `developerInfo` as XSD groups with
// child nodes. The live XSD does NOT have those groups — every child element
// (`terminalCapability`, `developerID`, `acceptorStreetAddress`, etc.) is a
// FLAT sibling. Verified against the F9901 error pasted into the design doc.
// `partialApprovalCapable` is similarly bogus — the real element is
// `partialAuthSupport`.
#[derive(Debug, Serialize)]
pub struct TsysXmlAuthorizeBody<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
{
    #[serde(rename = "deviceID")]
    pub device_id: Secret<String>,
    #[serde(rename = "transactionKey")]
    pub transaction_key: Secret<String>,
    #[serde(rename = "cardDataSource")]
    pub card_data_source: TsysXmlCardDataSource,
    #[serde(rename = "transactionAmount")]
    pub transaction_amount: StringMajorUnit,
    /// Path A (PAN / network-token MIT / CIT) — emit `<cardNumber>` /
    /// `<expirationDate>` / `<cvv2>`. Mutually exclusive with the
    /// Path B (`customerCode` + `walletDetails`) block below.
    #[serde(rename = "cardNumber", skip_serializing_if = "Option::is_none")]
    pub card_number: Option<Secret<String>>,
    /// MM/YY — TransIT explicitly documents this format (tech spec § Field Reference).
    /// Skipped on Path B (vault token MIT).
    #[serde(rename = "expirationDate", skip_serializing_if = "Option::is_none")]
    pub expiration_date: Option<Secret<String>>,
    #[serde(rename = "cvv2", skip_serializing_if = "Option::is_none")]
    pub cvv2: Option<Secret<String>>,
    /// Path B vault dispatch (`customerCode` + `walletDetails`). When present,
    /// `card_number` / `expiration_date` / `cvv2` MUST be `None`.
    /// Sequence-positioned near the other card-source fields per tech spec §
    /// CIT/MIT; final wire order is the same as TSYS doc examples (we iterate
    /// against F9901 if needed).
    #[serde(rename = "customerCode", skip_serializing_if = "Option::is_none")]
    pub customer_code: Option<Secret<String>>,
    #[serde(rename = "walletDetails", skip_serializing_if = "Option::is_none")]
    pub wallet_details: Option<TsysXmlWalletDetailsRef>,
    /// Required by the cert script (AVS).
    #[serde(rename = "addressLine1")]
    pub address_line1: Secret<String>,
    /// Required by the cert script (AVS).
    #[serde(rename = "zip")]
    pub zip: Secret<String>,
    /// Required by the cert script (merchant's reference id, echoed in the response).
    #[serde(rename = "externalReferenceID")]
    pub external_reference_id: String,
    /// Always "YES" — declares partial-auth support to TSYS. XSD name is
    /// `partialAuthSupport` (not `partialApprovalCapable`).
    #[serde(rename = "partialAuthSupport")]
    pub partial_auth_support: String,
    // --- terminalData fields (flat per the XSD; dev portal groups them, XSD doesn't) ---
    #[serde(rename = "terminalCapability")]
    pub terminal_capability: TsysXmlTerminalCapability,
    #[serde(rename = "terminalOperatingEnvironment")]
    pub terminal_operating_environment: TsysXmlTerminalOperatingEnvironment,
    #[serde(rename = "cardholderAuthenticationMethod")]
    pub cardholder_authentication_method: TsysXmlCardholderAuthenticationMethod,
    #[serde(rename = "terminalAuthenticationCapability")]
    pub terminal_authentication_capability: TsysXmlTerminalAuthenticationCapability,
    #[serde(rename = "terminalOutputCapability")]
    pub terminal_output_capability: TsysXmlTerminalOutputCapability,
    #[serde(rename = "maxPinLength")]
    pub max_pin_length: TsysXmlMaxPinLength,
    #[serde(rename = "terminalCardCaptureCapability")]
    pub terminal_card_capture_capability: TsysXmlTerminalCardCaptureCapability,
    #[serde(rename = "cardholderPresentDetail")]
    pub cardholder_present_detail: TsysXmlCardholderPresentDetail,
    #[serde(rename = "cardPresentDetail")]
    pub card_present_detail: TsysXmlCardPresentDetail,
    #[serde(rename = "cardDataInputMode")]
    pub card_data_input_mode: TsysXmlCardDataInputMode,
    #[serde(rename = "cardholderAuthenticationEntity")]
    pub cardholder_authentication_entity: TsysXmlCardholderAuthenticationEntity,
    #[serde(rename = "cardDataOutputCapability")]
    pub card_data_output_capability: TsysXmlCardDataOutputCapability,
    /// developerID is a FLAT element, NOT inside a `<developerInfo>` wrapper.
    #[serde(rename = "developerID")]
    pub developer_id: Secret<String>,
    /// Discover/JCB/Diners/CUP only.
    #[serde(rename = "registeredUserIndicator", skip_serializing_if = "Option::is_none")]
    pub registered_user_indicator: Option<TsysXmlRegisteredUserIndicator>,
    /// Discover/JCB/Diners/CUP only.
    #[serde(rename = "lastRegisteredChangeDate", skip_serializing_if = "Option::is_none")]
    pub last_registered_change_date: Option<String>,
    /// MC/AMEX only: PREAUTH for manual capture, FINAL otherwise.
    #[serde(rename = "authorizationIndicator", skip_serializing_if = "Option::is_none")]
    pub authorization_indicator: Option<TsysXmlAuthorizationIndicator>,
    /// MC-only acceptor info — all four sub-fields must be present together.
    #[serde(rename = "acceptorStreetAddress", skip_serializing_if = "Option::is_none")]
    pub acceptor_street_address: Option<String>,
    #[serde(rename = "acceptorCustomerServicePhoneNumber", skip_serializing_if = "Option::is_none")]
    pub acceptor_customer_service_phone_number: Option<String>,
    #[serde(rename = "acceptorPhoneNumber", skip_serializing_if = "Option::is_none")]
    pub acceptor_phone_number: Option<String>,
    #[serde(rename = "acceptorURLAddress", skip_serializing_if = "Option::is_none")]
    pub acceptor_url_address: Option<String>,
    /// `<cardOnFile>` — emitted as `Y` on CIT (stored credential consent) and
    /// MIT (subsequent use) per tech spec § CIT/MIT. Sequence position mirrors
    /// TSYS doc examples; we iterate on F9901 if XSD ordering disagrees.
    #[serde(rename = "cardOnFile", skip_serializing_if = "Option::is_none")]
    pub card_on_file: Option<TsysXmlCardOnFile>,
    /// `<previousNetworkTransactionID>` — Path A (network-token MIT) only.
    /// Holds the originating CIT's `cardTransactionIdentifier` (NTID).
    #[serde(
        rename = "previousNetworkTransactionID",
        skip_serializing_if = "Option::is_none"
    )]
    pub previous_network_transaction_id: Option<String>,
    /// `<mit>` block — MIT indicator. Path A & Path B both emit on MIT calls.
    #[serde(rename = "mit", skip_serializing_if = "Option::is_none")]
    pub mit: Option<TsysXmlMit>,
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
    #[serde(rename = "transactionID")]
    pub transaction_id: String,
    #[serde(rename = "developerID")]
    pub developer_id: Secret<String>,
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
    // TransIT XSD: transactionAmount before transactionID for Capture/Void/Return.
    // Verified live against responseCode F9901.
    #[serde(rename = "transactionAmount")]
    pub transaction_amount: StringMajorUnit,
    #[serde(rename = "transactionID")]
    pub transaction_id: String,
    /// Multi-clearing sequence number (1-based). Stubbed `None` for PR-1.
    #[serde(rename = "seqNumber", skip_serializing_if = "Option::is_none")]
    pub seq_number: Option<u32>,
    /// Total expected capture count for this auth. Stubbed `None` for PR-1.
    #[serde(rename = "paymentCount", skip_serializing_if = "Option::is_none")]
    pub payment_count: Option<u32>,
    #[serde(rename = "developerID")]
    pub developer_id: Secret<String>,
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
    /// Origin of card data — only sent for unreferenced refunds.
    #[serde(rename = "cardDataSource", skip_serializing_if = "Option::is_none")]
    pub card_data_source: Option<TsysXmlCardDataSource>,
    /// Refund amount in major units. Always emitted in PR-1; "omit for full
    /// referenced refunds" is a TODO follow-up.
    /// TransIT XSD requires transactionAmount BEFORE transactionID.
    #[serde(rename = "transactionAmount", skip_serializing_if = "Option::is_none")]
    pub transaction_amount: Option<StringMajorUnit>,
    /// Reference to the original capture's `<transactionID>`. Present for
    /// referenced refunds; absent for unreferenced refunds.
    #[serde(rename = "transactionID", skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,
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
    #[serde(rename = "developerID")]
    pub developer_id: Secret<String>,
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
    /// Optional — present for a partial void, omitted for a full void.
    /// TransIT XSD requires transactionAmount BEFORE transactionID.
    #[serde(rename = "transactionAmount", skip_serializing_if = "Option::is_none")]
    pub transaction_amount: Option<StringMajorUnit>,
    #[serde(rename = "transactionID")]
    pub transaction_id: String,
    #[serde(rename = "developerID")]
    pub developer_id: Secret<String>,
    /// MUST come AFTER developerID (TransIT XSD verified live — voidReason is the
    /// last element in the Void sequence). Derived from `cancellation_reason`,
    /// capped at 80 chars. Defaults to `POST_AUTH_USER_DECLINE` — the only enum
    /// value we've found accepted by TSYS' XSD validator.
    #[serde(rename = "voidReason")]
    pub void_reason: String,
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

// =============================================================================
// AddCustomer — CreateConnectorCustomer flow
// =============================================================================

/// `<personalDetails>` block for `<AddCustomer>`. TransIT requires firstName +
/// lastName (we split on first whitespace; if no whitespace, lastName is `"-"`).
#[derive(Debug, Serialize)]
#[serde(rename = "personalDetails")]
pub struct TsysXmlPersonalDetails {
    #[serde(rename = "firstName")]
    pub first_name: Secret<String>,
    #[serde(rename = "lastName")]
    pub last_name: Secret<String>,
    #[serde(rename = "addressLine1")]
    pub address_line1: Secret<String>,
    #[serde(rename = "zip")]
    pub zip: Secret<String>,
}

/// Card data inside `<walletDetails>` of `<AddCustomer>`. Note the
/// `expirationDate` format here is `MMYYYY` (6 digits) — different from
/// Sale/Auth which uses `MMYY`.
#[derive(Debug, Serialize)]
#[serde(rename = "cardDetails")]
pub struct TsysXmlAddCustomerCardDetails {
    #[serde(rename = "cardNumber")]
    pub card_number: Secret<String>,
    /// `MMYYYY` (6 digits) — see tech spec note.
    #[serde(rename = "expirationDate")]
    pub expiration_date: Secret<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename = "walletDetails")]
pub struct TsysXmlAddCustomerWalletDetails {
    #[serde(rename = "cardDetails")]
    pub card_details: TsysXmlAddCustomerCardDetails,
    #[serde(rename = "addressLine1")]
    pub address_line1: Secret<String>,
    #[serde(rename = "zip")]
    pub zip: Secret<String>,
    /// `1` for the primary card on the new customer wallet.
    #[serde(rename = "paymentSequence")]
    pub payment_sequence: String,
}

/// TransIT `<AddCustomer>` request (CreateConnectorCustomer flow). The wallet
/// block holds the first card we want to associate with the new customer.
#[derive(Debug, Serialize)]
#[serde(rename = "AddCustomer")]
pub struct TsysXmlAddCustomerRequest {
    #[serde(rename = "deviceID")]
    pub device_id: Secret<String>,
    #[serde(rename = "transactionKey")]
    pub transaction_key: Secret<String>,
    #[serde(rename = "personalDetails")]
    pub personal_details: TsysXmlPersonalDetails,
    #[serde(rename = "walletDetails")]
    pub wallet_details: TsysXmlAddCustomerWalletDetails,
    #[serde(rename = "developerID")]
    pub developer_id: Secret<String>,
}

impl GetSoapXml for TsysXmlAddCustomerRequest {
    fn to_soap_xml(&self) -> String {
        generate_xml(self).unwrap_or_else(|_| {
            String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<AddCustomer/>")
        })
    }
}

// =============================================================================
// CardAuthentication — SetupMandate flow (zero-dollar CIT verify)
// =============================================================================

/// TransIT `<CardAuthentication>` request — zero-dollar CIT card verification
/// used by the SetupMandate flow. Mirrors the Sale/Auth terminalData fields
/// plus `<cardOnFile>Y</cardOnFile>` to flag CIT consent.
#[derive(Debug, Serialize)]
#[serde(rename = "CardAuthentication")]
pub struct TsysXmlCardAuthenticationRequest {
    #[serde(rename = "deviceID")]
    pub device_id: Secret<String>,
    #[serde(rename = "transactionKey")]
    pub transaction_key: Secret<String>,
    #[serde(rename = "cardDataSource")]
    pub card_data_source: TsysXmlCardDataSource,
    #[serde(rename = "cardNumber")]
    pub card_number: Secret<String>,
    /// MM/YY (matches Sale/Auth format) — TransIT XSD-aligned per tech spec.
    #[serde(rename = "expirationDate")]
    pub expiration_date: Secret<String>,
    #[serde(rename = "addressLine1")]
    pub address_line1: Secret<String>,
    #[serde(rename = "zip")]
    pub zip: Secret<String>,
    #[serde(rename = "externalReferenceID")]
    pub external_reference_id: String,
    #[serde(rename = "cardOnFile")]
    pub card_on_file: TsysXmlCardOnFile,
    #[serde(rename = "developerID")]
    pub developer_id: Secret<String>,
    // terminalData (flat per XSD; same flattening as Sale/Auth)
    #[serde(rename = "terminalCapability")]
    pub terminal_capability: TsysXmlTerminalCapability,
    #[serde(rename = "terminalOperatingEnvironment")]
    pub terminal_operating_environment: TsysXmlTerminalOperatingEnvironment,
    #[serde(rename = "cardholderAuthenticationMethod")]
    pub cardholder_authentication_method: TsysXmlCardholderAuthenticationMethod,
    #[serde(rename = "terminalAuthenticationCapability")]
    pub terminal_authentication_capability: TsysXmlTerminalAuthenticationCapability,
    #[serde(rename = "terminalOutputCapability")]
    pub terminal_output_capability: TsysXmlTerminalOutputCapability,
    #[serde(rename = "maxPinLength")]
    pub max_pin_length: TsysXmlMaxPinLength,
    #[serde(rename = "terminalCardCaptureCapability")]
    pub terminal_card_capture_capability: TsysXmlTerminalCardCaptureCapability,
    #[serde(rename = "cardholderPresentDetail")]
    pub cardholder_present_detail: TsysXmlCardholderPresentDetail,
    #[serde(rename = "cardPresentDetail")]
    pub card_present_detail: TsysXmlCardPresentDetail,
    #[serde(rename = "cardDataInputMode")]
    pub card_data_input_mode: TsysXmlCardDataInputMode,
    #[serde(rename = "cardholderAuthenticationEntity")]
    pub cardholder_authentication_entity: TsysXmlCardholderAuthenticationEntity,
    #[serde(rename = "cardDataOutputCapability")]
    pub card_data_output_capability: TsysXmlCardDataOutputCapability,
}

impl GetSoapXml for TsysXmlCardAuthenticationRequest {
    fn to_soap_xml(&self) -> String {
        generate_xml(self).unwrap_or_else(|_| {
            String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<CardAuthentication/>")
        })
    }
}
