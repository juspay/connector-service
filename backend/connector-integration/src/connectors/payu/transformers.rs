use base64::Engine;
use common_enums::AttemptStatus;
use common_utils::{pii::EmailStrategy, request::Method};
use domain_types::{
    connector_flow::Authorize,
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, ResponseId},
};
use hex;
use hyperswitch_domain_models::router_data::ConnectorAuthType;
use hyperswitch_domain_models::{
    payment_method_data::{self, PaymentMethodData},
    router_data::ErrorResponse,
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
};
use hyperswitch_interfaces::errors;
use masking::{ExposeInterface, Secret};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::collections::HashMap;
use std::convert::TryFrom;

use crate::types::ResponseRouterData;

// Authentication type for PayU
#[derive(Debug, Clone)]
pub struct PayuAuthType {
    pub(crate) key: Secret<String>,  // Merchant key
    pub(crate) salt: Secret<String>, // Salt for hash generation
}

impl TryFrom<&ConnectorAuthType> for PayuAuthType {
    type Error = error_stack::Report<hyperswitch_interfaces::errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self {
                key: key1.to_owned(),
                salt: api_key.to_owned(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

// UPI App details for PayU
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UpiAppConfig {
    pub payu_code: String,    // PayU's internal code for the app
    pub display_name: String, // Display name for the app
    pub package_name: String, // Android package name (optional, for deep linking)
    pub priority: i32,        // Display priority
}

// PayU payment request structure
#[derive(Debug, Serialize)]
pub struct PayuPaymentRequest {
    pub amount: i64,              // Amount in smallest currency unit (paise for INR)
    pub pg: String,               // Payment gateway type
    pub currency: String,         // Currency code
    pub order_id: Option<String>, // Order ID
    pub email: masking::Secret<String, EmailStrategy>, // Customer email
    pub contact: Option<String>,  // Phone number
    pub key: String,              // Merchant key
    pub txnid: String,            // Unique transaction ID
    pub productinfo: String,      // Product description
    pub firstname: String,        // Customer first name
    pub lastname: Option<String>, // Customer last name
    pub phone: String,            // Customer phone
    pub surl: String,             // Success URL
    pub furl: Option<String>,     // Failure URL
    pub hash: String,             // Security hash
    #[serde(rename = "upiAppName")]
    pub upi_app_name: Option<String>, // UPI app name
    pub bankcode: String,         // Bank code
    pub txn_s2s_flow: i64,        // S2S flow type
    pub s2s_client_ip: String,    // Client IP
    pub s2s_device_info: String,  // Device info

    // Additional fields
    pub description: Option<String>,  // Description
    pub callback_url: Option<String>, // Callback URL
    pub cancel_url: Option<String>,   // Cancel URL

    // Recurring/Mandate related
    pub recurring: Option<bool>, // Recurring payment
    pub save: Option<bool>,      // Save payment method
    pub token: Option<String>,   // Token

    // 3DS and authentication
    pub auth_type: Option<String>, // Authentication type

    // Additional charges
    pub fee: Option<i64>, // Fee
    pub tax: Option<i64>, // Tax

    // Address fields
    pub address1: Option<String>, // Address line 1
    pub address2: Option<String>, // Address line 2
    pub city: Option<String>,     // City
    pub state: Option<String>,    // State
    pub country: Option<String>,  // Country
    pub zipcode: Option<String>,  // Zip code

    // UDF fields (User Defined Fields)
    pub udf1: Option<String>, // User defined field 1
    pub udf2: Option<String>, // User defined field 2
    pub udf3: Option<String>, // User defined field 3
    pub udf4: Option<String>, // User defined field 4
    pub udf5: Option<String>, // User defined field 5

    // Offer related
    pub offer_id: Option<String>, // Offer ID

    // Internal fields for processing
    pub vpa: Option<String>, // Virtual Payment Address (for UPI Collect)
    #[serde(skip)]
    pub enforce_pay_method: Option<String>, // Force payment method
    #[serde(skip)]
    pub connector_metadata: Option<HashMap<String, String>>, // Additional metadata
}

impl PayuPaymentRequest {
    // Validate UPI VPA format
    pub fn validate_vpa(vpa: &str) -> bool {
        // Basic validation: UPI VPAs typically have format username@provider
        if !vpa.contains('@') {
            return false;
        }

        let parts: Vec<&str> = vpa.split('@').collect();
        if parts.len() != 2 {
            return false;
        }

        let (username, provider) = (parts[0], parts[1]);

        // Username should not be empty and should contain only valid characters
        if username.is_empty()
            || !username
                .chars()
                .all(|c| c.is_alphanumeric() || c == '.' || c == '-' || c == '_')
        {
            return false;
        }

        // Provider should not be empty and should be a valid domain-like string
        if provider.is_empty() || !provider.chars().all(|c| c.is_alphanumeric() || c == '.') {
            return false;
        }

        true
    }
}

// PayU direct response structure (for UPI Collect)
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PayuDirectResponse {
    pub status: i32,
    pub token: String,
    #[serde(rename = "referenceId")]
    pub reference_id: String,
    #[serde(rename = "returnUrl")]
    pub return_url: String,
    #[serde(rename = "merchantName")]
    pub merchant_name: String,
    #[serde(rename = "merchantVpa")]
    pub merchant_vpa: String,
    pub amount: String,
    #[serde(rename = "intentSdkCombineVerifyAndPayButton")]
    pub intent_sdk_combine_verify_and_pay_button: Option<String>,
    #[serde(rename = "txnId")]
    pub txn_id: String,
    #[serde(rename = "disableIntentSeamlessFailure")]
    pub disable_intent_seamless_failure: String,
    #[serde(rename = "vpaRegex")]
    pub vpa_regex: String,
    pub apps: Vec<UpiApp>,
    #[serde(rename = "upiPushDisabled")]
    pub upi_push_disabled: String,
    #[serde(rename = "pushServiceUrl")]
    pub push_service_url: String,
    #[serde(rename = "pushServiceUrlV2")]
    pub push_service_url_v2: String,
    #[serde(rename = "upiServicePollInterval")]
    pub upi_service_poll_interval: String,
    #[serde(rename = "sdkUpiPushExpiry")]
    pub sdk_upi_push_expiry: String,
    #[serde(rename = "sdkUpiVerificationInterval")]
    pub sdk_upi_verification_interval: String,
    #[serde(rename = "encodedPayuId")]
    pub encoded_payu_id: String,
    #[serde(rename = "intentURIData")]
    pub intent_uri_data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpiApp {
    pub name: String,
    pub package: String,
}

// PayU redirect response structure (for UPI Intent)
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PayuRedirectResponse {
    pub status: String,
    pub txn_id: String,
    #[serde(rename = "surl")]
    pub success_url: String,
    #[serde(rename = "furl")]
    pub failure_url: String,
    pub redirect_url: String, // URL for browser redirection
    #[serde(default)]
    pub deep_link_url: Option<String>, // URL for mobile app deep linking
    #[serde(default)]
    pub intent_url: Option<String>, // Android intent URL
}

// PayU collect response structure (for UPI Collect status)
#[derive(Debug, Deserialize, Serialize)]
pub struct PayuCollectResponse {
    pub status: String,
    pub result: PayuCollectResult,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PayuCollectResult {
    pub mihpayid: String,
    pub mode: String,
    pub status: String,
    pub key: String,
    pub txnid: String,
    pub amount: String,
    pub addedon: String,
    pub productinfo: String,
    pub firstname: String,
    pub lastname: String,
    pub address1: String,
    pub address2: String,
    pub city: String,
    pub state: String,
    pub country: String,
    pub zipcode: String,
    pub email: String,
    pub phone: String,
    pub udf1: String,
    pub udf2: String,
    pub udf3: String,
    pub udf4: String,
    pub udf5: String,
    pub udf6: String,
    pub udf7: String,
    pub udf8: String,
    pub udf9: String,
    pub udf10: String,
    pub card_token: String,
    pub card_no: String,
    pub field0: String,
    pub field1: String,
    pub field2: String,
    pub field3: String,
    pub field4: String,
    pub field5: String,
    pub field6: String,
    pub field7: String,
    pub field8: String,
    pub field9: String,
    pub payment_source: String,
    #[serde(rename = "PG_TYPE")]
    pub pg_type: String,
    pub error: String,
    #[serde(rename = "error_Message")]
    pub error_message: String,
    pub net_amount_debit: String,
    pub discount: String,
    pub offer_key: String,
    pub offer_availed: String,
    pub unmappedstatus: String,
    pub hash: String,
    pub bank_ref_no: String,
    pub bank_ref_num: String,
    pub bankcode: String,
    pub surl: String,
    pub curl: String,
    pub furl: String,
}

// Combined PayU response type
#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum PayuPaymentResponse {
    DirectResponse(PayuDirectResponse),
    RedirectResponse(PayuRedirectResponse),
    CollectResponse(PayuCollectResponse),
    ErrorResponse(PayuErrorResponse),
}

// PayU error response structure
#[derive(Debug, Deserialize, Serialize)]
pub struct PayuErrorResponse {
    pub result: Option<serde_json::Value>,
    pub status: String,
    pub error: String,
    pub message: String,
}

// PayU error response
#[derive(Debug, Deserialize, Clone, strum::AsRefStr)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PayuErrorCode {
    // Common errors
    InvalidParams,
    InvalidHash,
    AuthenticationFailed,
    InvalidMerchant,

    // UPI specific errors
    InvalidVpa,
    UpiTimeout,
    UpiAppNotInstalled,
    UpiAppError,
    VpaNotRegistered,
    UpiInvalidAccount,
    UpiQuotaExceeded,
    UpiInsufficientFunds,
    UpiDeclinedByCustomer,

    // Other PayU errors
    PaymentFailed,
    TechnicalError,
    InvalidAmount,
    InvalidCurrency,
    DuplicateTransaction,
    TransactionRejected,

    // Fallback for unknown errors
    #[serde(other)]
    Unknown,
}

impl PayuErrorCode {
    pub fn to_connector_error(&self) -> errors::ConnectorError {
        match self {
            Self::InvalidParams => errors::ConnectorError::RequestEncodingFailed,
            Self::InvalidHash => errors::ConnectorError::InvalidDataFormat { field_name: "hash" },
            Self::AuthenticationFailed | Self::InvalidMerchant => {
                errors::ConnectorError::FailedToObtainAuthType
            }
            Self::InvalidVpa | Self::VpaNotRegistered | Self::UpiInvalidAccount => {
                errors::ConnectorError::InvalidDataFormat { field_name: "vpa" }
            }
            Self::UpiTimeout => errors::ConnectorError::RequestTimeoutReceived,
            Self::UpiAppNotInstalled | Self::UpiAppError => {
                errors::ConnectorError::ProcessingStepFailed(None)
            }
            Self::UpiQuotaExceeded => errors::ConnectorError::ProcessingStepFailed(None),
            Self::UpiInsufficientFunds => {
                errors::ConnectorError::InSufficientBalanceInPaymentMethod
            }
            Self::UpiDeclinedByCustomer => errors::ConnectorError::ProcessingStepFailed(None),
            Self::InvalidAmount | Self::InvalidCurrency => {
                errors::ConnectorError::AmountConversionFailed
            }
            Self::DuplicateTransaction => errors::ConnectorError::ProcessingStepFailed(None),
            Self::TransactionRejected | Self::PaymentFailed => {
                errors::ConnectorError::ProcessingStepFailed(None)
            }
            Self::TechnicalError | Self::Unknown => {
                errors::ConnectorError::ProcessingStepFailed(None)
            }
        }
    }
}

// Use the PayuRouterData type generated by the macro
use super::PayuRouterData;

impl
    TryFrom<
        PayuRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        >,
    > for PayuPaymentRequest
{
    type Error = error_stack::Report<hyperswitch_interfaces::errors::ConnectorError>;

    fn try_from(
        item: PayuRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;

        // Extract auth credentials
        let auth = PayuAuthType::try_from(&router_data.connector_auth_type)?;

        // Prepare common request fields
        let txn_id = router_data.connector_request_reference_id.clone();
        let amount = router_data.request.minor_amount.get_amount_as_i64();

        tracing::info!(
            "PayU: Amount details - minor_amount: {:?}, amount_as_i64: {}, currency: {:?}",
            router_data.request.minor_amount,
            amount,
            router_data.request.currency
        );

        // Validate amount for PayU requirements
        if amount <= 0 {
            tracing::error!(
                "PayU: Invalid amount - amount must be greater than 0, got: {}",
                amount
            );
            return Err(errors::ConnectorError::AmountConversionFailed.into());
        }

        // PayU typically requires minimum 1 rupee (100 paise) for Indian market
        if router_data.request.currency.to_string() == "INR" && amount < 100 {
            tracing::warn!(
                "PayU: Amount {} paise is less than minimum 100 paise (1 INR) for Indian market",
                amount
            );
        }

        // Extract customer info
        let first_name = router_data
            .request
            .customer_name
            .clone()
            .unwrap_or_else(|| "Customer".to_string());
        let email = match router_data.request.email.clone() {
            Some(e) => e.expose(),
            None => masking::Secret::new("customer@email.com".to_string()),
        };

        // Get phone number from payment address or use default
        let phone = router_data
            .resource_common_data
            .address
            .get_payment_billing()
            .and_then(|billing| billing.phone.as_ref())
            .and_then(|p| p.number.as_ref())
            .map(|n| n.clone().expose().to_string())
            .unwrap_or_else(|| "9999999999".to_string());

        // Get return URLs
        let return_url = router_data.request.router_return_url.clone().ok_or(
            errors::ConnectorError::MissingRequiredField {
                field_name: "return_url",
            },
        )?;

        // Get product info from metadata or use default
        let product_info = router_data
            .request
            .metadata
            .as_ref()
            .and_then(|meta| meta.get("product_info").map(|v| v.to_string()))
            .unwrap_or_else(|| "Payment".to_string());

        // Get billing address
        let billing_address = router_data
            .resource_common_data
            .address
            .get_payment_billing();

        let udf1 = router_data
            .request
            .metadata
            .as_ref()
            .and_then(|meta| meta.get("udf1").map(|v| v.to_string()))
            .unwrap_or_else(|| "ghh".to_string());
        let udf2 = router_data
            .request
            .metadata
            .as_ref()
            .and_then(|meta| meta.get("udf2").map(|v| v.to_string()))
            .unwrap_or_else(|| "gh".to_string());
        let udf3 = router_data
            .request
            .metadata
            .as_ref()
            .and_then(|meta| meta.get("udf3").map(|v| v.to_string()))
            .unwrap_or_else(|| "hg".to_string());
        let udf4 = router_data
            .request
            .metadata
            .as_ref()
            .and_then(|meta| meta.get("udf4").map(|v| v.to_string()))
            .unwrap_or_else(|| "gh".to_string());
        let udf5 = router_data
            .request
            .metadata
            .as_ref()
            .and_then(|meta| meta.get("udf5").map(|v| v.to_string()))
            .unwrap_or_else(|| "hg".to_string());

        // Generate security hash
        let email_for_hash = router_data
            .request
            .email
            .clone()
            .map(|e| e.expose().expose().to_string())
            .unwrap_or("customer@email.com".to_string());
        let hash_string = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}||||||{}",
            auth.key.clone().expose(),
            txn_id,
            amount,
            product_info.clone(),
            first_name.clone(),
            email_for_hash,
            udf1,
            udf2,
            udf3,
            udf4,
            udf5,
            auth.salt.clone().expose()
        );

        tracing::info!("PayU: Hash string components - key: {}, txnid: {}, amount: {}, productinfo: {}, firstname: {}, email: {}", 
            auth.key.clone().expose(), txn_id, amount, product_info, first_name, email_for_hash);

        // Generate SHA512 hash
        let mut hasher = Sha512::new();
        hasher.update(hash_string.as_bytes());
        let hash_result = hasher.finalize();

        // Convert to hex string
        let hash = hex::encode(hash_result);

        tracing::debug!("PayU: Generated hash: {}", hash);

        // Get client IP from metadata or use default
        let client_ip = router_data
            .request
            .browser_info
            .as_ref()
            .and_then(|meta| meta.ip_address.map(|v| v.to_string()))
            .unwrap_or_else(|| "127.0.0.1".to_string());

        // Get device info from metadata or use default
        let device_info = router_data
            .request
            .browser_info
            .as_ref()
            .and_then(|meta| meta.user_agent.as_ref().map(|v| v.to_string()))
            .unwrap_or_else(|| "web".to_string());

        // Prepare common request fields
        let mut request = PayuPaymentRequest {
            amount: amount,
            pg: "UPI".to_string(),
            currency: router_data.request.currency.to_string(),
            order_id: Some(
                router_data
                    .resource_common_data
                    .connector_request_reference_id
                    .clone(),
            ),
            email,
            contact: Some(phone.clone()),
            key: auth.key.clone().expose(),
            txnid: txn_id,
            productinfo: product_info.clone(),
            firstname: first_name,
            lastname: None,
            phone,
            surl: return_url.clone(),
            furl: Some(return_url),
            hash,
            upi_app_name: None,       // Will be set based on payment method
            bankcode: "".to_string(), // Will be set based on payment method
            txn_s2s_flow: 2,
            s2s_client_ip: client_ip,
            s2s_device_info: device_info,

            // Optional fields
            description: Some(product_info.clone()),
            callback_url: router_data.request.webhook_url.clone(),
            cancel_url: router_data.request.router_return_url.clone(),

            // Recurring/Mandate related
            recurring: None,
            save: Some(false),
            token: None,

            // 3DS and authentication
            auth_type: None,

            // Additional charges
            fee: None,
            tax: None,

            // Address fields
            address1: billing_address.and_then(|addr| {
                addr.address
                    .as_ref()
                    .and_then(|a| a.line1.clone().map(|s| s.expose()))
            }),
            address2: billing_address.and_then(|addr| {
                addr.address
                    .as_ref()
                    .and_then(|a| a.line2.clone().map(|s| s.expose()))
            }),
            city: billing_address
                .and_then(|addr| addr.address.as_ref().and_then(|a| a.city.clone())),
            state: billing_address.and_then(|addr| {
                addr.address
                    .as_ref()
                    .and_then(|a| a.state.clone().map(|s| s.expose()))
            }),
            country: billing_address.and_then(|addr| {
                addr.address
                    .as_ref()
                    .and_then(|a| a.country.clone().map(|c| c.to_string()))
            }),
            zipcode: billing_address.and_then(|addr| {
                addr.address
                    .as_ref()
                    .and_then(|a| a.zip.clone().map(|s| s.expose()))
            }),

            // UDF fields - use empty strings if not provided
            udf1: Some(udf1),
            udf2: Some(udf2),
            udf3: Some(udf3),
            udf4: Some(udf4),
            udf5: Some(udf5),

            // Offer related
            offer_id: router_data
                .request
                .metadata
                .as_ref()
                .and_then(|meta| meta.get("offer_id").map(|v| v.to_string())),

            // Internal processing fields
            vpa: None,
            enforce_pay_method: Some("upi".to_string()),
            connector_metadata: None,
        };

        // Payment method specific logic
        tracing::debug!("PayU: Processing payment method data");
        match &router_data.request.payment_method_data {
            PaymentMethodData::Upi(upi_data) => {
                tracing::info!("PayU: UPI payment method detected");
                match upi_data {
                    payment_method_data::UpiData::UpiIntent(_intent_data) => {
                        tracing::info!("PayU: UPI Intent flow");
                        // Extract UPI app from the gRPC request UpiIntentData
                        // Since the UpiIntentData in domain model is empty, we get the app info from metadata
                        let app_name = router_data
                            .request
                            .metadata
                            .as_ref()
                            .and_then(|meta| meta.get("upi_app").map(|v| v.to_string()))
                            .unwrap_or_else(|| "GPAY".to_string());

                        request.upi_app_name = Some(app_name);
                        request.bankcode = "INTENT".to_string();
                        request.txn_s2s_flow = 2;
                        // For UPI Intent, we don't set the VPA
                        request.vpa = None;
                    }
                    payment_method_data::UpiData::UpiCollect(collect_data) => {
                        tracing::info!("PayU: UPI Collect flow");
                        // Get the VPA ID from the collect_data
                        if let Some(vpa_secret) = &collect_data.vpa_id {
                            let vpa_id = vpa_secret.clone().expose();
                            tracing::info!("VPA ID ++ {:?}", vpa_id);
                            // Validate VPA format
                            if !Self::validate_vpa(&vpa_id) {
                                return Err(errors::ConnectorError::InvalidDataFormat {
                                    field_name: "vpa_id",
                                }
                                .into());
                            }

                            // UPI Collect requires VPA
                            request.vpa = Some(vpa_id.clone());
                            request.upi_app_name = None;
                            request.bankcode = "UPI".to_string();
                            request.pg = "UPI".to_string();
                            // For Collect flow, set specific UPI parameters
                            request.enforce_pay_method = Some("upi_collect".to_string());
                        } else {
                            return Err(errors::ConnectorError::MissingRequiredField {
                                field_name: "vpa_id",
                            }
                            .into());
                        }
                    }
                    payment_method_data::UpiData::UpiQr(_qr_data) => {
                        tracing::info!("PayU: UPI QR flow");
                        // For UPI QR, PayU generates a QR code that customers can scan
                        request.pg = "QR".to_string();
                        request.bankcode = "UPIQR".to_string(); // UPIQR for UPI QR, BQR for Bharath QR
                        request.txn_s2s_flow = 2;
                        request.upi_app_name = None;
                        request.vpa = None;
                        request.enforce_pay_method = Some("upi_qr".to_string());
                    }
                }
            }
            _ => {
                return Err(errors::ConnectorError::NotImplemented(
                    "Payment method not supported".into(),
                )
                .into());
            }
        }

        tracing::info!(
            "PayU: Successfully created payment request with txnid={}",
            request.txnid
        );
        Ok(request)
    }
}

impl
    TryFrom<
        ResponseRouterData<
            PayuPaymentResponse,
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        >,
    > for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>
{
    type Error = error_stack::Report<hyperswitch_interfaces::errors::ConnectorError>;

    fn try_from(value: ResponseRouterData<PayuPaymentResponse, Self>) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            mut router_data,
            http_code,
        } = value;

        // Store raw connector response for debugging and auditing
        let response_string = serde_json::to_string(&response)
            .map_err(|_| errors::ConnectorError::ResponseDeserializationFailed)?
            .to_string();
        router_data.resource_common_data.raw_connector_response = Some(response_string);

        match response {
            PayuPaymentResponse::DirectResponse(direct_response) => {
                // Map PayU status to AttemptStatus for direct responses (typically UPI Collect)
                let status = match direct_response.status {
                    1 => AttemptStatus::Authorized, // Success
                    0 => AttemptStatus::Failure,    // Failure
                    _ => AttemptStatus::Pending,    // Other statuses
                };

                // Update status in router data
                router_data.resource_common_data.status = status;

                // For direct response, create transaction response with intent URL
                let redirection_data = Some(RedirectForm::Uri {
                    uri: direct_response.intent_uri_data.clone(),
                });

                let payments_response_data = PaymentsResponseData::TransactionResponse {
                    resource_id: ResponseId::ConnectorTransactionId(
                        direct_response.reference_id.clone(),
                    ),
                    redirection_data: Box::new(redirection_data),
                    connector_metadata: {
                        let mut metadata = HashMap::new();
                        metadata.insert(
                            "apps".to_string(),
                            serde_json::to_string(&direct_response.apps).unwrap_or_default(),
                        );
                        Some(serde_json::to_value(metadata).unwrap_or_default())
                    },
                    network_txn_id: None,
                    connector_response_reference_id: Some(direct_response.txn_id.clone()),
                    incremental_authorization_allowed: None,
                    mandate_reference: Box::new(None),
                    raw_connector_response: serde_json::to_string(&direct_response).ok(),
                    transaction_token: Some(direct_response.token.clone()),
                    transaction_amount: Some(direct_response.amount.clone()),
                    merchant_name: Some(direct_response.merchant_name.clone()),
                    merchant_vpa: Some(direct_response.merchant_vpa.clone()),
                };
                router_data.response = Ok(payments_response_data);
            }
            PayuPaymentResponse::RedirectResponse(redirect_response) => {
                // For redirection response (typically UPI Intent)

                // Set status to AuthenticationPending since user needs to authenticate in UPI app
                router_data.resource_common_data.status = AttemptStatus::AuthenticationPending;

                // Determine if this is a mobile request
                let is_mobile = router_data
                    .request
                    .metadata
                    .as_ref()
                    .and_then(|meta| meta.get("is_mobile_device").map(|v| v == "true"))
                    .unwrap_or(false);

                // Choose the appropriate URL for redirection
                let redirect_url = if is_mobile {
                    // For mobile, prefer deep link or intent URL if available
                    redirect_response
                        .deep_link_url
                        .clone()
                        .or(redirect_response.intent_url.clone())
                        .unwrap_or_else(|| redirect_response.redirect_url.clone())
                } else {
                    // For web, use the standard redirect URL
                    redirect_response.redirect_url.clone()
                };

                // Create form fields for the redirection
                let mut form_fields = HashMap::new();

                // Add any needed query parameters
                if let Some(txn_id) = Some(
                    router_data
                        .resource_common_data
                        .connector_request_reference_id
                        .clone(),
                ) {
                    form_fields.insert("txnid".to_string(), txn_id);
                }

                // Create redirection data
                let redirection_data = Some(RedirectForm::Form {
                    endpoint: redirect_url,
                    method: Method::Get,
                    form_fields,
                });

                // Create response with redirection data
                let payments_response_data = PaymentsResponseData::TransactionResponse {
                    resource_id: ResponseId::ConnectorTransactionId(
                        redirect_response.txn_id.clone(),
                    ),
                    redirection_data: Box::new(redirection_data),
                    connector_metadata: None,
                    network_txn_id: None,
                    connector_response_reference_id: Some(redirect_response.txn_id.clone()),
                    incremental_authorization_allowed: None,
                    mandate_reference: Box::new(None),
                    raw_connector_response: serde_json::to_string(&redirect_response).ok(),
                    transaction_token: None,
                    transaction_amount: None,
                    merchant_name: None,
                    merchant_vpa: None,
                };
                router_data.response = Ok(payments_response_data);
            }
            PayuPaymentResponse::CollectResponse(collect_response) => {
                // Handle collect response from PayU (typically for UPI Collect status check)
                let status = match collect_response.result.status.to_lowercase().as_str() {
                    "success" => AttemptStatus::Charged,
                    "failure" | "failed" => AttemptStatus::Failure,
                    "pending" | "in progress" => AttemptStatus::Pending,
                    _ => AttemptStatus::Pending,
                };

                router_data.resource_common_data.status = status;

                let payments_response_data = PaymentsResponseData::TransactionResponse {
                    resource_id: ResponseId::ConnectorTransactionId(
                        collect_response.result.mihpayid.clone(),
                    ),
                    redirection_data: Box::new(None),
                    connector_metadata: {
                        let mut metadata = HashMap::new();
                        metadata.insert("mode".to_string(), collect_response.result.mode.clone());
                        metadata.insert(
                            "bankcode".to_string(),
                            collect_response.result.bankcode.clone(),
                        );
                        metadata.insert(
                            "pg_type".to_string(),
                            collect_response.result.pg_type.clone(),
                        );
                        metadata.insert(
                            "unmappedstatus".to_string(),
                            collect_response.result.unmappedstatus.clone(),
                        );
                        Some(serde_json::to_value(metadata).unwrap_or_default())
                    },
                    network_txn_id: if !collect_response.result.bank_ref_no.is_empty() {
                        Some(collect_response.result.bank_ref_no.clone())
                    } else {
                        None
                    },
                    connector_response_reference_id: Some(collect_response.result.txnid.clone()),
                    incremental_authorization_allowed: None,
                    mandate_reference: Box::new(None),
                    raw_connector_response: serde_json::to_string(&collect_response).ok(),
                    transaction_token: None,
                    transaction_amount: Some(collect_response.result.amount.clone()),
                    merchant_name: None,
                    merchant_vpa: None,
                };
                router_data.response = Ok(payments_response_data);
            }
            PayuPaymentResponse::ErrorResponse(error_response) => {
                // Handle error response from PayU
                router_data.resource_common_data.status = AttemptStatus::Failure;

                // Create error response with PayU error details
                let error_reason = format!("{}: {}", error_response.error, error_response.message);
                let connector_error = ErrorResponse {
                    code: error_response.error.clone(),
                    message: error_response.message.clone(),
                    reason: Some(error_reason),
                    status_code: http_code,
                    attempt_status: Some(AttemptStatus::Failure),
                    connector_transaction_id: None,
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                };

                router_data.response = Err(connector_error);
            }
        }

        Ok(router_data)
    }
}
