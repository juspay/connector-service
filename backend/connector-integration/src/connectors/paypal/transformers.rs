// Transformers for Paypal connector
use hyperswitch_common_utils::types::StringMajorUnit; // As per Hyperswitch paypal/transformers.rs
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};
use hyperswitch_domain_models::router_data::ConnectorAuthType;
use hyperswitch_interfaces::errors;

// Using StringMajorUnit as per Hyperswitch Paypal transformer
// Hyperswitch uses api_models::enums for Currency, but domain_types also has Currency.
// For now, let's assume we'll use the one from api_models or map it as needed.
// Using common_enums directly as seen in Hyperswitch paypal/transformers.rs for some enums
use hyperswitch_common_enums::enums as storage_enums;

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

// As per Hyperswitch paypal/transformers.rs, Paypal uses client_id and client_secret
// This will be used by get_auth_header in paypal.rs
pub struct PaypalAuthType {
    pub(super) client_id: Secret<String>,
    pub(super) client_secret: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for PaypalAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey { api_key, key1, .. } => Ok(Self {
                client_id: api_key.clone(),
                client_secret: key1.clone(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
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
impl<T> TryFrom<(
    StringMajorUnit, // amount
    Option<StringMajorUnit>, // shipping_cost
    Option<StringMajorUnit>, // order_tax_amount
    Option<StringMajorUnit>, // order_amount
    T, // router_data (item)
)> for PaypalRouterData<T> {
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

// Placeholder for Payment Status, will be detailed from Hyperswitch paypal/transformers.rs
// enum PaymentStatus { ... }

// --- PAYPAL AUTHORIZE REQUEST --- Based on Hyperswitch paypal/transformers.rs

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

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PaypalOrderStatus {
    Created,
    Saved, // The order was saved and is pending approval.
    Approved, // The customer approved the payment through the PayPal wallet or other alternative payment method.
    Voided, // All purchase units in the order are voided.
    Completed, // The payment was authorized or captured for an order.
    PayerActionRequired, // The order requires an action from the payer (e.g. 3DS authentication).
    // From Hyperswitch PaymentStatus mapping:
    // Active, Denied, Expired, PartiallyCompleted, PendingApproval, Revoked, Suspended
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