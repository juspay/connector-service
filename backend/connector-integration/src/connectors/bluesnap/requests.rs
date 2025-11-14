use common_utils::types::StringMajorUnit;
use domain_types::payment_method_data::PaymentMethodDataTypes;
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};

// BlueSnap Transaction Type enum
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BluesnapTxnType {
    AuthOnly,
    AuthCapture,
    AuthReversal,
    Capture,
    Refund,
}

// Card holder information
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BluesnapCardHolderInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_name: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_name: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zip: Option<Secret<String>>,
}

// Credit card details for BlueSnap API
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BluesnapCreditCard {
    pub card_number: Secret<String>,
    pub security_code: Secret<String>,
    pub expiration_month: Secret<String>,
    pub expiration_year: Secret<String>,
}

// Apple Pay wallet structure
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BluesnapApplePayWallet {
    pub encoded_payment_token: Secret<String>,
}

// Google Pay wallet structure
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BluesnapGooglePayWallet {
    pub encoded_payment_token: Secret<String>,
}

// Wallet container for Apple Pay and Google Pay
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BluesnapWallet {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub apple_pay: Option<BluesnapApplePayWallet>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub google_pay: Option<BluesnapGooglePayWallet>,
    pub wallet_type: String,
}

// Payment method details - supports cards and wallets
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum BluesnapPaymentMethodDetails {
    Card {
        #[serde(rename = "creditCard")]
        credit_card: BluesnapCreditCard,
    },
    Wallet {
        wallet: BluesnapWallet,
    },
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionFraudInfo {
    fraud_session_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BluesnapMetadata {
    meta_data: Vec<RequestMetadata>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestMetadata {
    meta_key: Option<String>,
    meta_value: Option<String>,
    is_visible: Option<String>,
}

// Main authorize request structure based on tech spec
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BluesnapPaymentsRequest<T: PaymentMethodDataTypes> {
    pub amount: StringMajorUnit,
    pub currency: String,
    pub card_transaction_type: BluesnapTxnType,
    #[serde(flatten)]
    pub payment_method_details: BluesnapPaymentMethodDetails,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card_holder_info: Option<BluesnapCardHolderInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_fraud_info: Option<TransactionFraudInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merchant_transaction_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_meta_data: Option<BluesnapMetadata>,
    #[serde(skip)]
    pub _phantom: std::marker::PhantomData<T>,
}

// Capture request structure based on BlueSnap tech spec
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BluesnapCaptureRequest {
    pub card_transaction_type: BluesnapTxnType,
    pub transaction_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<StringMajorUnit>,
}

// Void request structure based on BlueSnap tech spec
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BluesnapVoidRequest {
    pub card_transaction_type: BluesnapTxnType,
    pub transaction_id: String,
}

// PSync request structure - empty for GET endpoint
#[derive(Debug, Serialize, Default)]
pub struct BluesnapSyncRequest {}

// Refund request structure - supports partial refunds via optional amount
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BluesnapRefundRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<StringMajorUnit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

// Refund sync request - empty for GET endpoint
#[derive(Debug, Serialize, Default)]
pub struct BluesnapRefundSyncRequest {}
