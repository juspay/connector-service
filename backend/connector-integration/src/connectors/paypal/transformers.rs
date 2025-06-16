// Transformers for Paypal connector
use hyperswitch_common_utils::types::StringMajorUnit; // As per Hyperswitch paypal/transformers.rs
use hyperswitch_masking::{Secret,ExposeInterface};
use serde::{Deserialize, Serialize};

use hyperswitch_interfaces::errors;

use base64::Engine;
pub const BASE64_ENGINE: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

use domain_types::{
    connector_flow::{Authorize, Capture, Refund, Void},
    connector_types::{
        EventType, PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData,
        PaymentsResponseData, RefundFlowData, RefundsData, RefundsResponseData,
    },
};

use hyperswitch_common_enums::enums as storage_enums;

use std::convert::TryFrom;
use error_stack::{ResultExt, report};
use hyperswitch_masking::PeekInterface;
use hyperswitch_domain_models::{
    payment_method_data::{Card, PaymentMethodData},
    router_data::{ConnectorAuthType, ErrorResponse, RouterData},
    router_data_v2::RouterDataV2,
    router_request_types::ResponseId,
    router_response_types::{MandateReference, RedirectForm},
};
use hyperswitch_common_utils::{request::Method,errors::CustomResult};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaypalErrorResponse {
    // Based on general error structure, specific fields from Paypal docs if available
    // The provided snippets show error mapping from string codes, not a full error response struct.
    // For now, a generic structure. Hyperswitch paypal.rs has detailed error mapping.
    pub name: String,
    pub message: String,
    pub debug_id: Option<String>,
    // issue: String, // from one of the snippets - likely 'name' or a similar top-level field
    // description: Option<String>, // from one of the snippets - likely 'message'
}

#[derive(Debug)]
pub struct StandardFlowCredentials {
    pub(super) client_id: Secret<String>,
    pub(super) client_secret: Secret<String>,
}

#[derive(Debug)]
pub struct PartnerFlowCredentials {
    pub(super) client_id: Secret<String>,
    pub(super) client_secret: Secret<String>,
    pub(super) payer_id: Secret<String>,
}

#[derive(Debug)]
pub enum PaypalConnectorCredentials {
    StandardIntegration(StandardFlowCredentials),
    PartnerIntegration(PartnerFlowCredentials),
}

impl PaypalConnectorCredentials {
    pub fn get_client_id(&self) -> Secret<String> {
        match self {
            Self::StandardIntegration(item) => item.client_id.clone(),
            Self::PartnerIntegration(item) => item.client_id.clone(),
        }
    }

    pub fn get_client_secret(&self) -> Secret<String> {
        match self {
            Self::StandardIntegration(item) => item.client_secret.clone(),
            Self::PartnerIntegration(item) => item.client_secret.clone(),
        }
    }

    pub fn get_payer_id(&self) -> Option<Secret<String>> {
        match self {
            Self::StandardIntegration(_) => None,
            Self::PartnerIntegration(item) => Some(item.payer_id.clone()),
        }
    }

    pub fn generate_authorization_value(&self) -> String {
        let auth_id = format!(
            "{}:{}",
            self.get_client_id().expose(),
            self.get_client_secret().expose(),
        );
        format!("Basic {}", BASE64_ENGINE.encode(auth_id))
    }
}

#[derive(Debug)]
pub enum PaypalAuthType {
    TemporaryAuth,
    AuthWithDetails(PaypalConnectorCredentials),
}

impl PaypalAuthType {
    pub fn get_credentials(
        &self,
    ) -> CustomResult<&PaypalConnectorCredentials, errors::ConnectorError> {
        match self {
            Self::TemporaryAuth => Err(errors::ConnectorError::InvalidConnectorConfig {
                config: "TemporaryAuth found in connector_account_details",
            }
            .into()),
            Self::AuthWithDetails(credentials) => Ok(credentials),
        }
    }
}

impl TryFrom<&ConnectorAuthType> for PaypalAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self::AuthWithDetails(
                PaypalConnectorCredentials::StandardIntegration(StandardFlowCredentials {
                    client_id: key1.to_owned(),
                    client_secret: api_key.to_owned(),
                }),
            )),
            ConnectorAuthType::SignatureKey {
                api_key,
                key1,
                api_secret,
            } => Ok(Self::AuthWithDetails(
                PaypalConnectorCredentials::PartnerIntegration(PartnerFlowCredentials {
                    client_id: key1.to_owned(),
                    client_secret: api_key.to_owned(),
                    payer_id: api_secret.to_owned(),
                }),
            )),
            ConnectorAuthType::TemporaryAuth => Ok(Self::TemporaryAuth),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType)?,
        }
    }
}


// Based on PaypalRouterData<T> in Hyperswitch
#[derive(Debug, Serialize)]
pub struct PaypalRouterData<T> {
    pub amount: StringMajorUnit, // Paypal generally uses string amounts
    pub router_data: T,
    // Added optional fields from Hyperswitch PaypalRouterData
    pub shipping_cost: Option<StringMajorUnit>,
    pub order_tax_amount: Option<StringMajorUnit>,
    pub order_amount: Option<StringMajorUnit>,
}

// Corresponds to TryFrom in Hyperswitch for PaypalRouterData
impl<T>
    TryFrom<(
        StringMajorUnit,
        Option<StringMajorUnit>,
        Option<StringMajorUnit>,
        Option<StringMajorUnit>,
        T,
    )> for PaypalRouterData<T>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        (amount, shipping_cost, order_tax_amount, order_amount, item): (
            StringMajorUnit,
            Option<StringMajorUnit>,
            Option<StringMajorUnit>,
            Option<StringMajorUnit>,
            T,
        ),
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            amount,
            shipping_cost,
            order_tax_amount,
            order_amount,
            router_data: item,
        })
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")] // Paypal uses SCREAMING_SNAKE_CASE for enums like this
pub enum PaypalIntent {
    Capture, // For immediate capture
    Authorize, // For authorizing payment for later capture
}

#[derive(Debug, Clone, Serialize)]
pub struct PaypalAmountBreakdown {
    // Simplified, Hyperswitch has more detail (item_total, shipping, tax_total, discount etc.)
    // Each of those is an Amount object (currency_code, value)
    // For now, keeping it simple or assuming these are part of the main amount calculation passed to Paypal.
    // We will need StringMajorUnit for these if used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub item_total: Option<PaypalMoney>, // Example
}

#[derive(Debug, Clone, Serialize)]
pub struct PaypalMoney { // Corresponds to Money in Hyperswitch
    pub currency_code: storage_enums::Currency, // storage_enums = hyperswitch_common_enums::enums
    pub value: StringMajorUnit, // Paypal uses string amounts
}

#[derive(Debug, Clone, Serialize)]
pub struct PaypalPurchaseUnitRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference_id: Option<Secret<String>>, // Merchant-provided ID for the purchase unit
    pub amount: PaypalMoney, // Amount for this purchase unit
    // description: Option<String>,
    // custom_id: Option<String>,
    // soft_descriptor: Option<String>,
    // items: Option<Vec<PaypalItem>>, // If item-level details are needed
    // shipping: Option<PaypalShippingDetails>, // If shipping details are per purchase unit
    // breakdown: Option<PaypalAmountBreakdown>, // If amount breakdown is needed at PU level
}

#[derive(Debug, Clone, Serialize)]
pub struct PaypalCardDetails {
    pub number: Secret<String>, // Card number
    pub expiry: Secret<String>, // Expiry in YYYY-MM format
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_code: Option<Secret<String>>, // CVV
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<Secret<String>>, // Cardholder name
    // billing_address: Option<PaypalAddressPortable>
}

#[derive(Debug, Clone, Serialize)]
pub struct PaypalPaymentSourceCard {
    pub card: PaypalCardDetails,
    // stored_credential: Option<PaypalStoredCredential>,
    // network_token_options: Option<PaypalNetworkTokenOptions>
}

#[derive(Debug, Clone, Serialize)]
pub struct PaypalPaymentSource {
    // Based on Hyperswitch, Paypal supports various sources like card, paypal wallet, tokens etc.
    // For card authorize, we focus on card.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card: Option<PaypalPaymentSourceCard>, 
    // token: Option<PaypalTokenSource> // For vaulted tokens
    // paypal: Option<PaypalWalletSource> // For paypal wallet payments
}

#[derive(Debug, Clone, Serialize, Default)] // Added Default
pub struct PaypalApplicationContext {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cancel_url: Option<String>,
    // brand_name: Option<String>,
    // locale: Option<String>,
    // shipping_preference: Option<PaypalShippingPreference> (e.g. GET_FROM_FILE, NO_SHIPPING, SET_PROVIDED_ADDRESS)
    // user_action: Option<String> (e.g. CONTINUE, PAY_NOW)
}

#[derive(Debug, Clone, Serialize)]
pub struct PaypalPaymentRequest {
    pub intent: PaypalIntent,
    pub purchase_units: Vec<PaypalPurchaseUnitRequest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_source: Option<PaypalPaymentSource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_context: Option<PaypalApplicationContext>,
}

// --- PAYPAL AUTHORIZE RESPONSE --- Based on Hyperswitch paypal/transformers.rs

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PaypalOrderStatus {
    Pending,
    Completed,
    Voided,
    Created,
    Saved,
    PayerActionRequired,
    Approved,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PaypalLinkDescription {
    pub href: String, // The complete target URL.
    pub rel: String,  // The link relationship type. For example: approve, capture, self.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>, // The HTTP method required to make the related call.
}

// Minimal response structure for now focusing on what's needed for RouterData
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PaypalPaymentResponse {
    pub id: String, // The ID of the order.
    pub status: PaypalOrderStatus, // The status of the order.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<Vec<PaypalLinkDescription>>, // HATEOAS links including approval link if status is CREATED/PAYER_ACTION_REQUIRED.
    // purchase_units: Vec<PaypalPurchaseUnitResponse>, // Detailed purchase units if needed
    // payment_source: Option<HashMap<String, Value>>, // From Hyperswitch, complex payment source details
    // create_time, update_time etc.
    // intent: PaypalIntent (present in capture response)
    // payer: Option<PaypalPayer> (payer info)
}

impl TryFrom<&PaypalPaymentResponse> for domain_types::connector_types::PaymentsResponseData {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(res: &PaypalPaymentResponse) -> Result<Self, Self::Error> {
        let status = match res.status {
            PaypalOrderStatus::Created => storage_enums::AttemptStatus::AuthenticationPending,
            PaypalOrderStatus::Approved => storage_enums::AttemptStatus::Charged,
            PaypalOrderStatus::Completed => storage_enums::AttemptStatus::Charged,
            PaypalOrderStatus::Voided => storage_enums::AttemptStatus::Voided,
            PaypalOrderStatus::PayerActionRequired => storage_enums::AttemptStatus::AuthenticationPending,
            _ => storage_enums::AttemptStatus::Pending,
        };
        let redirection_data = res.links.as_ref().and_then(|links| {
            links.iter().find(|l| l.rel == "approve").map(|l| {
                RedirectForm::Form {
                    endpoint: l.href.clone(),
                    method: Method::Get,
                    form_fields: HashMap::new(),
                }
            })
        });
        Ok(PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(res.id.clone()),
            redirection_data: Box::new(redirection_data),
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: None,
            incremental_authorization_allowed: None,
        })
    }
} 


#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErrorCodeAndMessage {
    pub error_code: String,
    pub error_message: String,
}

impl From<OrderErrorDetails> for ErrorCodeAndMessage {
    fn from(error: OrderErrorDetails) -> Self {
        Self {
            error_code: error.issue.to_string(),
            error_message: error.issue.to_string(),
        }
    }
}

//
#[derive(Default, Debug, Serialize, Deserialize, PartialEq)]
pub struct PaypalPaymentErrorResponse {
    pub name: Option<String>,
    pub message: String,
    pub debug_id: Option<String>,
    pub details: Option<Vec<ErrorDetails>>,
}

pub mod auth_headers {
    pub const PAYPAL_PARTNER_ATTRIBUTION_ID: &str = "PayPal-Partner-Attribution-Id";
    pub const PREFER: &str = "Prefer";
    pub const PAYPAL_REQUEST_ID: &str = "PayPal-Request-Id";
    pub const PAYPAL_AUTH_ASSERTION: &str = "PayPal-Auth-Assertion";
}

#[derive(Debug, Serialize)]
pub struct PaypalPaymentsRequest {
    intent: PaypalPaymentIntent,
    purchase_units: Vec<PurchaseUnitRequest>,
    payment_source: Option<PaymentSourceItem>,
}

pub trait ForeignTryFrom<F>: Sized {
    type Error;

    fn foreign_try_from(from: F) -> Result<Self, Self::Error>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaypalRedirectResponse {
    id: String,
    intent: PaypalPaymentIntent,
    status: PaypalOrderStatus,
    purchase_units: Vec<RedirectPurchaseUnitItem>,
    links: Vec<PaypalLinks>,
    payment_source: Option<PaymentSourceItemResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaypalOrdersResponse {
    id: String,
    intent: PaypalPaymentIntent,
    status: PaypalOrderStatus,
    purchase_units: Vec<PurchaseUnitItem>,
    payment_source: Option<PaymentSourceItemResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaypalThreeDsResponse {
    id: String,
    status: PaypalOrderStatus,
    links: Vec<PaypalLinks>,
}

#[derive(Default, Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ErrorDetails {
    pub issue: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaypalLinks {
    href: Option<Url>,
    rel: String,
}

use url::Url;

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum PaymentSourceItemResponse {
    Card(CardVaultResponse),
    Paypal(PaypalRedirectionResponse),
    Eps(EpsRedirectionResponse),
    Ideal(IdealRedirectionResponse),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EpsRedirectionResponse {
    name: Option<Secret<String>>,
    country_code: Option<hyperswitch_common_enums::CountryAlpha2>,
    bic: Option<Secret<String>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IdealRedirectionResponse {
    name: Option<Secret<String>>,
    country_code: Option<hyperswitch_common_enums::CountryAlpha2>,
    bic: Option<Secret<String>>,
    iban_last_chars: Option<Secret<String>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PaypalRedirectionResponse {
    attributes: Option<AttributeResponse>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CardVaultResponse {
    attributes: Option<AttributeResponse>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AttributeResponse {
    vault: PaypalVaultResponse,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PaypalVaultResponse {
    id: String,
    status: String,
    customer: CustomerId,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CustomerId {
    id: String,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct PurchaseUnitItem {
    pub reference_id: Option<String>,
    pub invoice_id: Option<String>,
    pub payments: PaymentsCollection,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct PaymentsCollection {
    authorizations: Option<Vec<PaymentsCollectionItem>>,
    captures: Option<Vec<PaymentsCollectionItem>>,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentsCollectionItem {
    amount: OrderAmount,
    expiration_time: Option<String>,
    id: String,
    final_capture: Option<bool>,
    status: PaypalPaymentStatus,
}

#[derive(Default, Debug, Clone, Serialize, Eq, PartialEq, Deserialize)]
pub struct OrderAmount {
    pub currency_code: storage_enums::Currency,
    pub value: StringMajorUnit,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PaypalPaymentStatus {
    Created,
    Captured,
    Completed,
    Declined,
    Voided,
    Failed,
    Pending,
    Denied,
    Expired,
    PartiallyCaptured,
    Refunded,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum PaypalPaymentIntent {
    Capture,
    Authorize,
    Authenticate,
}

#[derive(Default, Debug, Serialize, Eq, PartialEq)]
pub struct PurchaseUnitRequest {
    reference_id: Option<String>, //reference for an item in purchase_units
    invoice_id: Option<String>, //The API caller-provided external invoice number for this order. Appears in both the payer's transaction history and the emails that the payer receives.
    custom_id: Option<String>,  //Used to reconcile client transactions with PayPal transactions.
    amount: OrderRequestAmount,
    #[serde(skip_serializing_if = "Option::is_none")]
    payee: Option<Payee>,
    shipping: Option<ShippingAddress>,
    items: Vec<ItemDetails>,
}

#[derive(Default, Debug, Serialize, Eq, PartialEq)]
pub struct ItemDetails {
    name: String,
    quantity: u16,
    unit_amount: OrderAmount,
    tax: Option<OrderAmount>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PaymentSourceItem {
    Card(CardRequest),
    Paypal(PaypalRedirectionRequest),
    IDeal(RedirectRequest),
    Eps(RedirectRequest),
    Giropay(RedirectRequest),
    Sofort(RedirectRequest),
}

#[derive(Debug, Serialize)]
pub struct RedirectRequest {
    name: Secret<String>,
    country_code: hyperswitch_common_enums::CountryAlpha2,
    experience_context: ContextStruct,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum PaypalRedirectionRequest {
    PaypalRedirectionStruct(PaypalRedirectionStruct),
    PaypalVaultStruct(VaultStruct),
}

#[derive(Debug, Serialize)]
pub struct PaypalRedirectionStruct {
    experience_context: ContextStruct,
    attributes: Option<Attributes>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Attributes {
    vault: PaypalVault,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ContextStruct {
    return_url: Option<String>,
    cancel_url: Option<String>,
    user_action: Option<UserAction>,
    shipping_preference: ShippingPreference,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum UserAction {
    #[serde(rename = "PAY_NOW")]
    PayNow,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ShippingPreference {
    #[serde(rename = "SET_PROVIDED_ADDRESS")]
    SetProvidedAddress,
    #[serde(rename = "GET_FROM_FILE")]
    GetFromFile,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum CardRequest {
    CardRequestStruct(CardRequestStruct),
    CardVaultStruct(VaultStruct),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VaultStruct {
    vault_id: Secret<String>,
}

#[derive(Debug, Serialize)]
pub struct CardRequestStruct {
    billing_address: Option<Address>,
    expiry: Option<Secret<String>>,
    name: Option<Secret<String>>,
    number: Option<hyperswitch_cards::CardNumber>,
    security_code: Option<Secret<String>>,
    attributes: Option<CardRequestAttributes>,
}

#[derive(Debug, Serialize)]
pub struct CardRequestAttributes {
    vault: Option<PaypalVault>,
    verification: Option<ThreeDsMethod>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PaypalVault {
    store_in_vault: StoreInVault,
    usage_type: UsageType,
}

#[derive(Debug, Serialize)]
pub struct ThreeDsMethod {
    method: ThreeDsType,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StoreInVault {
    OnSuccess,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UsageType {
    Merchant,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ThreeDsType {
    ScaAlways,
}

#[derive(Default, Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct OrderErrorDetails {
    pub issue: String,
    pub description: String,
    pub value: Option<String>,
    pub field: Option<String>,
}

fn is_auto_capture(data:&PaymentsAuthorizeData) -> Result<bool, errors::ConnectorError> {
    match data.capture_method {
        Some(hyperswitch_common_enums::CaptureMethod::Automatic)
        |None => Ok(true),
        Some(hyperswitch_common_enums::CaptureMethod::Manual) => Ok(false),
        Some(_) => Err(errors::ConnectorError::CaptureMethodNotSupported),
    }
}

#[derive(Default, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct OrderRequestAmount {
    pub currency_code: storage_enums::Currency,
    pub value: StringMajorUnit,
    pub breakdown: AmountBreakdown,
}

fn get_payee(auth_type: &PaypalAuthType) -> Option<Payee> {
    auth_type
        .get_credentials()
        .ok()
        .and_then(|credentials| credentials.get_payer_id())
        .map(|payer_id| Payee {
            merchant_id: payer_id,
        })
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct RedirectPurchaseUnitItem {
    pub invoice_id: String,
}

#[derive(Default, Debug, Serialize, Eq, PartialEq)]
pub struct Payee {
    merchant_id: Secret<String>,
}

#[derive(Default, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct AmountBreakdown {
    item_total: OrderAmount,
    tax_total: Option<OrderAmount>,
    shipping: Option<OrderAmount>,
}

fn paypal_threeds_link(
    (redirect_url, complete_auth_url): (Option<Url>, Option<String>),
) -> CustomResult<RedirectForm, errors::ConnectorError> {
    let mut redirect_url =
        redirect_url.ok_or(errors::ConnectorError::ResponseDeserializationFailed)?;
    let complete_auth_url =
        complete_auth_url.ok_or(errors::ConnectorError::MissingRequiredField {
            field_name: "complete_authorize_url",
        })?;
    let mut form_fields = std::collections::HashMap::from_iter(
        redirect_url
            .query_pairs()
            .map(|(key, value)| (key.to_string(), value.to_string())),
    );

    // paypal requires return url to be passed as a field along with payer_action_url
    form_fields.insert(String::from("redirect_uri"), complete_auth_url);

    // Do not include query params in the endpoint
    redirect_url.set_query(None);

    Ok(RedirectForm::Form {
        endpoint: redirect_url.to_string(),
        method: Method::Get,
        form_fields,
    })
}


pub(crate) fn get_order_status(
    item: PaypalOrderStatus,
    intent: PaypalPaymentIntent,
) -> storage_enums::AttemptStatus {
    match item {
        PaypalOrderStatus::Completed => {
            if intent == PaypalPaymentIntent::Authorize {
                storage_enums::AttemptStatus::Authorized
            } else {
                storage_enums::AttemptStatus::Charged
            }
        }
        PaypalOrderStatus::Voided => storage_enums::AttemptStatus::Voided,
        PaypalOrderStatus::Created | PaypalOrderStatus::Saved | PaypalOrderStatus::Pending => {
            storage_enums::AttemptStatus::Pending
        }
        PaypalOrderStatus::Approved => storage_enums::AttemptStatus::AuthenticationSuccessful,
        PaypalOrderStatus::PayerActionRequired => {
            storage_enums::AttemptStatus::AuthenticationPending
        }
    }
}

fn get_redirect_url(
    link_vec: Vec<PaypalLinks>,
) -> CustomResult<Option<Url>, errors::ConnectorError> {
    let mut link: Option<Url> = None;
    for item2 in link_vec.iter() {
        if item2.rel == "payer-action" {
            link.clone_from(&item2.href)
        }
    }
    Ok(link)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PaypalMeta {
    pub authorize_id: Option<String>,
    pub capture_id: Option<String>,
    pub psync_flow: PaypalPaymentIntent,
    pub next_action: Option<hyperswitch_api_models::payments::NextActionCall>,
    pub order_id: Option<String>,
}

#[derive(Default, Debug, Serialize, Eq, PartialEq)]
pub struct ShippingAddress {
    address: Option<Address>,
    name: Option<ShippingName>,
}

#[derive(Default, Debug, Serialize, Eq, PartialEq, Deserialize)]
pub struct Address {
    address_line_1: Option<Secret<String>>,
    postal_code: Option<Secret<String>>,
    country_code: hyperswitch_common_enums::CountryAlpha2,
    admin_area_2: Option<String>,
}

#[derive(Default, Debug, Serialize, Eq, PartialEq)]
pub struct ShippingName {
    full_name: Option<Secret<String>>,
}

impl From<ErrorDetails> for ErrorCodeAndMessage {
    fn from(error: ErrorDetails) -> Self {
        Self {
            error_code: error.issue.to_string(),
            error_message: error.issue.to_string(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum PaypalAuthResponse {
    PaypalOrdersResponse(PaypalOrdersResponse),
    PaypalRedirectResponse(PaypalRedirectResponse),
    PaypalThreeDsResponse(PaypalThreeDsResponse),
}

#[derive(Default, Debug, Serialize, Deserialize, PartialEq)]
pub struct PaypalOrderErrorResponse {
    pub name: Option<String>,
    pub message: String,
    pub debug_id: Option<String>,
    pub details: Option<Vec<OrderErrorDetails>>,
}


impl From<&PaypalRouterData<&RouterDataV2<
                    Authorize,
                    PaymentFlowData,
                    PaymentsAuthorizeData,
                    PaymentsResponseData,
                >,>> for OrderRequestAmount {
    fn from(item: &PaypalRouterData<&RouterDataV2<
                    Authorize,
                    PaymentFlowData,
                    PaymentsAuthorizeData,
                    PaymentsResponseData,
                >,>) -> Self {
        Self {
            currency_code: item.router_data.request.currency,
            value: item.amount.clone(),
            breakdown: AmountBreakdown {
                item_total: OrderAmount {
                    currency_code: item.router_data.request.currency,
                    value: item.amount.clone(),
                },
                tax_total: None,
                shipping: None,
            },
        }
    }
}


impl From<&PaypalRouterData<
            &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        >,> for ShippingAddress {
    fn from(item: &PaypalRouterData<
            &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        >) -> Self {
        Self {
            address: None,
            name: None,
        }
    }
}

impl From<&PaypalRouterData<
            &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        >,> for ItemDetails {
    fn from(item: &PaypalRouterData<
            &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        >) -> Self {
        Self {
            name: format!(
                "Payment for invoice {}",
                item.router_data.connector_request_reference_id
            ),
            quantity: ORDER_QUANTITY,
            unit_amount: OrderAmount {
                currency_code: item.router_data.request.currency,
                value: item.amount.clone(),
            },
            tax: None,
        }
    }
}

fn get_expiry_year_4_digit(card:&Card) -> Secret<String> {
        let mut year = card.card_exp_year.peek().clone();
        if year.len() == 2 {
            year = format!("20{}", year);
        }
        Secret::new(year)
    }

fn get_expiry_date_as_yyyymm(card:&Card, delimiter: &str) -> Secret<String> {
        let year = get_expiry_year_4_digit(&card);
        Secret::new(format!(
            "{}{}{}",
            year.peek(),
            delimiter,
            card.card_exp_month.peek()
        ))
    }

const ORDER_QUANTITY: u16 = 1;

impl
    TryFrom<
        &PaypalRouterData<
            &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        >,
    > for PaypalPaymentsRequest
{
    type Error = error_stack::Report<hyperswitch_interfaces::errors::ConnectorError>;
    fn try_from(
        item: 
             &PaypalRouterData<
                &RouterDataV2<
                    Authorize,
                    PaymentFlowData,
                    PaymentsAuthorizeData,
                    PaymentsResponseData,
                >,
            >,
        
    ) -> Result<Self, Self::Error> {
        let paypal_auth: PaypalAuthType =
            PaypalAuthType::try_from(&item.router_data.connector_auth_type)?;
        let payee = get_payee(&paypal_auth);

        let amount = OrderRequestAmount::from(item);

        let intent = if is_auto_capture(&item.router_data.request)? {
            PaypalPaymentIntent::Capture
        } else {
            PaypalPaymentIntent::Authorize
        };

        let connector_request_reference_id =
            item.router_data.connector_request_reference_id.clone();

        let shipping_address = ShippingAddress::from(item);
        let item_details = vec![ItemDetails::from(item)];

        let purchase_units = vec![PurchaseUnitRequest {
            reference_id: Some(connector_request_reference_id.clone()),
            custom_id: item.router_data.request.merchant_order_reference_id.clone(),
            invoice_id: Some(connector_request_reference_id),
            amount,
            payee,
            shipping: Some(shipping_address),
            items: item_details,
        }];

       
        let card =match item.router_data.request.payment_method_data.clone() {
            PaymentMethodData::Card(card) => Ok(card),
            _ => Err(errors::ConnectorError::MismatchedPaymentData),
        }?;
        let expiry = Some(get_expiry_date_as_yyyymm(&card,"-"));

        let verification = match item.router_data.resource_common_data.auth_type {
            hyperswitch_common_enums::AuthenticationType::ThreeDs => Some(ThreeDsMethod {
                method: ThreeDsType::ScaAlways,
            }),
            hyperswitch_common_enums::AuthenticationType::NoThreeDs => None,
        };

        let payment_source = Some(PaymentSourceItem::Card(CardRequest::CardRequestStruct(
            CardRequestStruct {
                billing_address: None,
                expiry,
                name: None,
                number: Some(card.card_number.clone()),
                security_code: Some(card.card_cvc.clone()),
                attributes: Some(CardRequestAttributes {
                    vault: match item.router_data.request.setup_future_usage {
                        Some(setup_future_usage) => match setup_future_usage {
                            hyperswitch_common_enums::FutureUsage::OffSession => Some(PaypalVault {
                                store_in_vault: StoreInVault::OnSuccess,
                                usage_type: UsageType::Merchant,
                            }),

                            hyperswitch_common_enums::FutureUsage::OnSession => None,
                        },
                        None => None,
                    },
                    verification,
                }),
            },
        )));
     
        Ok(Self {
            intent,
            purchase_units,
            payment_source,
        })   
    }
}


fn get_id_based_on_intent(
    intent: &PaypalPaymentIntent,
    purchase_unit: &PurchaseUnitItem,
) -> CustomResult<String, errors::ConnectorError> {
    || -> _ {
        match intent {
            PaypalPaymentIntent::Capture => Some(
                purchase_unit
                    .payments
                    .captures
                    .clone()?
                    .into_iter()
                    .next()?
                    .id,
            ),
            PaypalPaymentIntent::Authorize => Some(
                purchase_unit
                    .payments
                    .authorizations
                    .clone()?
                    .into_iter()
                    .next()?
                    .id,
            ),
            PaypalPaymentIntent::Authenticate => None,
        }
    }()
    .ok_or_else(|| errors::ConnectorError::MissingConnectorTransactionID.into())
}



impl<F, Req>
    ForeignTryFrom<(
        PaypalRedirectResponse,
        RouterDataV2<F, PaymentFlowData, Req, PaymentsResponseData>,
        u16,
    )> for RouterDataV2<F, PaymentFlowData, Req, PaymentsResponseData>
{
    type Error = error_stack::Report<hyperswitch_interfaces::errors::ConnectorError>;
    fn foreign_try_from(
        (response, data, _http_code): (
            PaypalRedirectResponse,
            RouterDataV2<F, PaymentFlowData, Req, PaymentsResponseData>,
            u16,
        ),
    ) -> Result<Self, Self::Error> {
        let status = get_order_status(response.clone().status, response.intent.clone());
        let link = get_redirect_url(response.links.clone())?;

        let connector_meta = serde_json::json!(PaypalMeta {
            authorize_id: None,
            capture_id: None,
            psync_flow: response.intent,
            next_action: None,
            order_id: None,
        });
        let purchase_units = response.purchase_units.first();
        Ok(Self {        
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(response.id.clone()),
                redirection_data: Box::new(Some(RedirectForm::from((
                    link.ok_or(errors::ConnectorError::ResponseDeserializationFailed)?,
                    Method::Get,
                )))),
                
                connector_metadata: Some(connector_meta),
                network_txn_id: None,
                connector_response_reference_id: Some(
                    purchase_units.map_or(response.id, |item| item.invoice_id.clone()),
                ),
                incremental_authorization_allowed: None,
                
            }),
            resource_common_data: PaymentFlowData {
                status,
                ..data.resource_common_data
            },
            ..data
        })
    }
}

impl From<PaypalPaymentStatus> for storage_enums::AttemptStatus {
    fn from(item: PaypalPaymentStatus) -> Self {
        match item {
            PaypalPaymentStatus::Created => Self::Authorized,
            PaypalPaymentStatus::Completed
            | PaypalPaymentStatus::Captured
            | PaypalPaymentStatus::Refunded => Self::Charged,
            PaypalPaymentStatus::Declined => Self::Failure,
            PaypalPaymentStatus::Failed => Self::CaptureFailed,
            PaypalPaymentStatus::Pending => Self::Pending,
            PaypalPaymentStatus::Denied | PaypalPaymentStatus::Expired => Self::Failure,
            PaypalPaymentStatus::PartiallyCaptured => Self::PartialCharged,
            PaypalPaymentStatus::Voided => Self::Voided,
        }
    }
}

impl<F, Req>
    ForeignTryFrom<(
        PaypalOrdersResponse,
        RouterDataV2<F, PaymentFlowData, Req, PaymentsResponseData>,
        u16,
    )> for RouterDataV2<F, PaymentFlowData, Req, PaymentsResponseData>
{
    type Error = error_stack::Report<hyperswitch_interfaces::errors::ConnectorError>;
    fn foreign_try_from(
        (response, data, _http_code): (
            PaypalOrdersResponse,
            RouterDataV2<F, PaymentFlowData, Req, PaymentsResponseData>,
            u16,
        ),
    ) -> Result<Self, Self::Error> {
        let purchase_units = 
            response
            .purchase_units
            .first()
            .ok_or(errors::ConnectorError::MissingConnectorTransactionID)?;

        let id = get_id_based_on_intent(&response.intent, purchase_units)?;
        let (connector_meta, order_id) = match response.intent.clone() {
            PaypalPaymentIntent::Capture => (
                serde_json::json!(PaypalMeta {
                    authorize_id: None,
                    capture_id: Some(id),
                    psync_flow: response.intent.clone(),
                    next_action: None,
                    order_id: None,
                }),
                ResponseId::ConnectorTransactionId(response.id.clone()),
            ),

            PaypalPaymentIntent::Authorize => (
                serde_json::json!(PaypalMeta {
                    authorize_id: Some(id),
                    capture_id: None,
                    psync_flow: response.intent.clone(),
                    next_action: None,
                    order_id: None,
                }),
                ResponseId::ConnectorTransactionId(response.id.clone()),
            ),

            PaypalPaymentIntent::Authenticate => {
                Err(errors::ConnectorError::ResponseDeserializationFailed)?
            }
        };
        //payment collection will always have only one element as we only make one transaction per order.
        let payment_collection = 
            &response
            .purchase_units
            .first()
            .ok_or(errors::ConnectorError::ResponseDeserializationFailed)?
            .payments;
        //payment collection item will either have "authorizations" field or "capture" field, not both at a time.
        let payment_collection_item = match (
            &payment_collection.authorizations,
            &payment_collection.captures,
        ) {
            (Some(authorizations), None) => authorizations.first(),
            (None, Some(captures)) => captures.first(),
            (Some(_), Some(captures)) => captures.first(),
            _ => None,
        }
        .ok_or(errors::ConnectorError::ResponseDeserializationFailed)?;
        let status = payment_collection_item.status.clone();
        let status = storage_enums::AttemptStatus::from(status);
        Ok(Self {
            response:  Ok(PaymentsResponseData::TransactionResponse {
                resource_id: order_id,
                redirection_data: Box::new(None),
                // mandate_reference:
                connector_metadata: Some(connector_meta),
                network_txn_id: None,
                connector_response_reference_id: purchase_units
                    .invoice_id
                    .clone()
                    .or(Some(response.id)),
                incremental_authorization_allowed: None,
            }),
            resource_common_data: PaymentFlowData {
                status,
                ..data.resource_common_data
            },
            ..data
        })
    }
}


impl<F>
    ForeignTryFrom<(
        PaypalThreeDsResponse,
        RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        u16,
    )> for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>
{
    type Error = error_stack::Report<hyperswitch_interfaces::errors::ConnectorError>;
    fn foreign_try_from(
        (response, data, _http_code): (
            PaypalThreeDsResponse,
            RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
            u16,
        ),
    ) -> Result<Self, Self::Error> {
         let connector_meta = serde_json::json!(PaypalMeta {
            authorize_id: None,
            capture_id: None,
            psync_flow: PaypalPaymentIntent::Authenticate, // when there is no capture or auth id present
            next_action: None,
            order_id: None,
        });

        let status = get_order_status(
            response.clone().status,
            PaypalPaymentIntent::Authenticate,
        );
        let link = get_redirect_url(response.links.clone())?;

        Ok(Self {
            
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(response.id),
                redirection_data: Box::new(Some(paypal_threeds_link((
                    link,
                    data.request.complete_authorize_url.clone(),
                ))?)),
               
                connector_metadata: Some(connector_meta),
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                
            }),
            resource_common_data: PaymentFlowData {
                status,
                ..data.resource_common_data
            },
            ..data
        })
    }
}
