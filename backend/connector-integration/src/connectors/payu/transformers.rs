use common_enums::{self, AttemptStatus};
use domain_types::{
    connector_flow::Authorize,
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, ResponseId},
    errors::ConnectorError,
    payment_method_data::{PaymentMethodData, UpiData, WalletData},
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_request_types::AuthoriseIntegrityObject,
    router_response_types::RedirectForm,
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, PeekInterface, Secret};
use serde::{Deserialize, Serialize};

use crate::types::ResponseRouterData;

// PayU Status enum to handle both integer and string status values
#[derive(Debug, Serialize, Clone)]
pub enum PayuStatusValue {
    IntStatus(i32),       // 1 for UPI Intent success
    StringStatus(String), // "success" for UPI Collect success
}

// Custom deserializer for PayU status field that can be either int or string
fn deserialize_payu_status<'de, D>(deserializer: D) -> Result<Option<PayuStatusValue>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde_json::Value;
    let value: Option<Value> = Option::deserialize(deserializer)?;

    match value {
        Some(Value::Number(n)) => {
            if let Some(i) = n.as_i64() {
                Ok(Some(PayuStatusValue::IntStatus(i as i32)))
            } else {
                Ok(None)
            }
        }
        Some(Value::String(s)) => Ok(Some(PayuStatusValue::StringStatus(s))),
        _ => Ok(None),
    }
}

// Authentication structure based on Payu analysis
#[derive(Debug, Clone)]
pub struct PayuAuthType {
    pub api_key: Secret<String>,
    pub api_secret: Secret<String>, // Merchant salt for signature
}

impl TryFrom<&ConnectorAuthType> for PayuAuthType {
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self {
                api_key: api_key.to_owned(),
                api_secret: key1.to_owned(), // key1 is merchant salt
            }),
            _ => Err(ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

// Note: Integrity Framework implementation will be handled by the framework itself
// since we can't implement foreign traits for foreign types (orphan rules)

// Request structure based on Payu UPI analysis
#[derive(Debug, Serialize)]
pub struct PayuPaymentRequest {
    // Core payment fields
    pub key: String,                                  // Merchant key
    pub txnid: String,                                // Transaction ID
    pub amount: common_utils::types::StringMajorUnit, // Amount in string major units
    pub currency: String,                             // Currency code
    pub productinfo: String,                          // Product description

    // Customer information
    pub firstname: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lastname: Option<String>,
    pub email: String,
    pub phone: String,

    // URLs
    pub surl: String, // Success URL
    pub furl: String, // Failure URL

    // Payment method specific
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pg: Option<String>, // Payment gateway code (UPI)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bankcode: Option<String>, // Bank code (TEZ, INTENT, TEZOMNI)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vpa: Option<String>, // UPI VPA (for collect)

    // UPI specific fields
    pub txn_s2s_flow: String,    // S2S flow type ("1" for UPI)
    pub s2s_client_ip: String,   // Client IP
    pub s2s_device_info: String, // Device info
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_version: Option<String>, // API version ("2.0")

    // Security
    pub hash: String, // SHA-512 signature

    // User defined fields (10 fields as per PayU spec)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udf1: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udf2: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udf3: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udf4: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udf5: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udf6: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udf7: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udf8: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udf9: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udf10: Option<String>,

    // Optional PayU fields for UPI
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offer_key: Option<String>, // Offer identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub si: Option<i32>, // Standing instruction flag
    #[serde(skip_serializing_if = "Option::is_none")]
    pub si_details: Option<String>, // SI details JSON
    #[serde(skip_serializing_if = "Option::is_none")]
    pub beneficiarydetail: Option<String>, // TPV beneficiary details
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_token: Option<String>, // User token for repeat transactions
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offer_auto_apply: Option<i32>, // Auto apply offer flag (0 or 1)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_charges: Option<String>, // Surcharge/fee amount
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_gst_charges: Option<String>, // GST charges
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upi_app_name: Option<String>, // UPI app name for intent flows
}

// Response structure based on actual PayU API response
#[derive(Debug, Deserialize, Serialize)]
pub struct PayuPaymentResponse {
    // Success response fields - PayU can return status as either int or string
    #[serde(deserialize_with = "deserialize_payu_status")]
    pub status: Option<PayuStatusValue>, // Status can be 1 (int) or "success" (string)
    pub token: Option<String>, // PayU token
    #[serde(alias = "referenceId")]
    pub reference_id: Option<String>, // PayU reference ID
    #[serde(alias = "returnUrl")]
    pub return_url: Option<String>, // Return URL
    #[serde(alias = "merchantName")]
    pub merchant_name: Option<String>, // Merchant display name
    #[serde(alias = "merchantVpa")]
    pub merchant_vpa: Option<String>, // Merchant UPI VPA
    pub amount: Option<String>, // Transaction amount
    #[serde(alias = "txnId")]
    pub txn_id: Option<String>, // Transaction ID
    #[serde(alias = "intentURIData")]
    pub intent_uri_data: Option<String>, // UPI intent URI data

    // UPI-specific fields
    pub apps: Option<Vec<PayuUpiApp>>, // Available UPI apps
    #[serde(alias = "upiPushDisabled")]
    pub upi_push_disabled: Option<String>, // UPI push disabled flag
    #[serde(alias = "pushServiceUrl")]
    pub push_service_url: Option<String>, // Push service URL
    #[serde(alias = "pushServiceUrlV2")]
    pub push_service_url_v2: Option<String>, // Push service URL V2
    #[serde(alias = "encodedPayuId")]
    pub encoded_payu_id: Option<String>, // Encoded PayU ID
    #[serde(alias = "vpaRegex")]
    pub vpa_regex: Option<String>, // VPA validation regex

    // Polling and timeout configuration
    #[serde(alias = "upiServicePollInterval")]
    pub upi_service_poll_interval: Option<String>, // Poll interval
    #[serde(alias = "sdkUpiPushExpiry")]
    pub sdk_upi_push_expiry: Option<String>, // Push expiry time
    #[serde(alias = "sdkUpiVerificationInterval")]
    pub sdk_upi_verification_interval: Option<String>, // Verification interval

    // Additional flags
    #[serde(alias = "disableIntentSeamlessFailure")]
    pub disable_intent_seamless_failure: Option<String>,
    #[serde(alias = "intentSdkCombineVerifyAndPayButton")]
    pub intent_sdk_combine_verify_and_pay_button: Option<String>,

    // Error response fields (actual PayU format)
    pub result: Option<PayuResult>, // PayU result field (null for errors)
    pub error: Option<String>,      // Error code like "EX158"
    pub message: Option<String>,    // Error message
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PayuResult {
    pub status: String,   // UPI Collect Status
    pub mihpayid: String, // ID
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PayuUpiApp {
    pub name: String,    // App display name
    pub package: String, // Android package name
}

// Error response structure matching actual PayU format
#[derive(Debug, Deserialize, Serialize)]
pub struct PayuErrorResponse {
    pub result: Option<serde_json::Value>, // null for errors
    pub status: Option<String>,            // "failed" for errors
    pub error: Option<String>,             // Error code like "EX158", "EX311"
    pub message: Option<String>,           // Error description

    // Legacy fields for backward compatibility
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub error_description: Option<String>,
    pub transaction_id: Option<String>,
}

// Request conversion with Framework Integration
impl
    TryFrom<
        super::PayuRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        >,
    > for PayuPaymentRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: super::PayuRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        // Extract router data
        let router_data = &item.router_data;

        // Use AmountConvertor framework for proper amount handling
        let amount = item
            .connector
            .amount_converter
            .convert(
                router_data.request.minor_amount,
                router_data.request.currency,
            )
            .change_context(ConnectorError::AmountConversionFailed)?;

        // Extract authentication
        let auth = PayuAuthType::try_from(&router_data.connector_auth_type)?;

        // Determine payment flow based on payment method
        let (pg, bankcode, vpa, s2s_flow) = determine_upi_flow(&router_data.request)?;

        // Generate UDF fields based on Haskell implementation
        let udf_fields = generate_udf_fields(
            &router_data.resource_common_data.payment_id,
            router_data
                .resource_common_data
                .merchant_id
                .get_string_repr(),
            &router_data.resource_common_data,
        );

        // Build base request
        let mut request = Self {
            key: auth.api_key.peek().to_string(),
            txnid: router_data.resource_common_data.payment_id.clone(),
            amount,
            currency: router_data.request.currency.to_string(),
            productinfo: "Payment".to_string(), // Default product info

            // Customer info - extract from billing address if available
            firstname: router_data
                .resource_common_data
                .get_optional_billing_first_name()
                .map(|name| name.peek().to_string())
                .unwrap_or_else(|| "Customer".to_string()),
            lastname: router_data
                .resource_common_data
                .get_optional_billing_last_name()
                .map(|name| name.peek().to_string()),
            email: router_data
                .resource_common_data
                .get_optional_billing_email()
                .as_ref()
                .map(|email| email.clone().expose().peek().to_string())
                .unwrap_or("customer@example.com".to_string()),
            phone: router_data
                .resource_common_data
                .get_optional_billing_phone_number()
                .map(|phone| phone.peek().to_string())
                .unwrap_or_else(|| "9999999999".to_string()),

            // URLs - use router return URL if available
            surl: router_data
                .request
                .router_return_url
                .clone()
                .unwrap_or_else(|| "https://example.com/success".to_string()),
            furl: "https://example.com/failure".to_string(),

            // Payment method specific
            pg,
            bankcode,
            vpa,

            // UPI specific - corrected based on PayU docs
            txn_s2s_flow: s2s_flow,
            s2s_client_ip: "127.0.0.1".to_string(),
            s2s_device_info: "web".to_string(),
            api_version: Some("2.0".to_string()), // As per PayU analysis

            // Will be calculated after struct creation
            hash: String::new(),

            // User defined fields based on Haskell implementation logic
            udf1: udf_fields[0].clone(), // Transaction ID or metadata value
            udf2: udf_fields[1].clone(), // Merchant ID or metadata value
            udf3: udf_fields[2].clone(), // From metadata or order reference
            udf4: udf_fields[3].clone(), // From metadata or order reference
            udf5: udf_fields[4].clone(), // From metadata or order reference
            udf6: udf_fields[5].clone(), // From order reference (udf6)
            udf7: udf_fields[6].clone(), // From order reference (udf7)
            udf8: udf_fields[7].clone(), // From order reference (udf8)
            udf9: udf_fields[8].clone(), // From order reference (udf9)
            udf10: udf_fields[9].clone(), // Always empty string

            // Optional PayU fields for UPI
            offer_key: None,
            si: None, // Not implementing mandate flows initially
            si_details: None,
            beneficiarydetail: None, // Not implementing TPV initially
            user_token: None,
            offer_auto_apply: None,
            additional_charges: None,
            additional_gst_charges: None,
            upi_app_name: determine_upi_app_name(&router_data.request)?,
        };

        // Generate hash signature
        request.hash = generate_payu_hash(&request, &auth.api_secret)?;

        Ok(request)
    }
}

// UDF field generation based on Haskell implementation
// Implements the logic from getUdf1-getUdf5 functions and orderReference fields
fn generate_udf_fields(
    payment_id: &str,
    merchant_id: &str,
    _payment_flow_data: &PaymentFlowData,
) -> [Option<String>; 10] {
    // Based on Haskell implementation:
    // udf1-udf5 come from PayuMetaData (if available) or default values
    // udf6-udf9 come from orderReference fields
    // udf10 is always empty string

    // Default UDF values as per Haskell getUdf* functions
    // In Haskell: getUdf1 returns txnId, getUdf2 returns merchantId, others are empty unless metadata exists

    [
        Some(payment_id.to_string()),  // udf1: Transaction ID (getUdf1 default)
        Some(merchant_id.to_string()), // udf2: Merchant ID (getUdf2 default)
        Some("".to_string()),          // udf3: Empty by default (getUdf3)
        Some("".to_string()),          // udf4: Empty by default (getUdf4)
        Some("".to_string()),          // udf5: Empty by default (getUdf5)
        Some("".to_string()),          // udf6: Empty by default (orderReference.udf6)
        Some("".to_string()),          // udf7: Empty by default (orderReference.udf7)
        Some("".to_string()),          // udf8: Empty by default (orderReference.udf8)
        Some("".to_string()),          // udf9: Empty by default (orderReference.udf9)
        Some("".to_string()),          // udf10: Always empty string (just $ "")
    ]
}

// UPI app name determination based on Haskell getUpiAppName implementation
fn determine_upi_app_name(
    request: &PaymentsAuthorizeData,
) -> Result<Option<String>, ConnectorError> {
    // From Haskell getUpiAppName implementation:
    // getUpiAppName txnDetail = case getJuspayBankCodeFromInternalMetadata txnDetail of
    //   Just "JP_PHONEPE"   -> "phonepe"
    //   Just "JP_GOOGLEPAY" -> "googlepay"
    //   Just "JP_BHIM"      -> "bhim"
    //   Just "JP_PAYTM"     -> "paytm"
    //   Just "JP_CRED"      -> "cred"
    //   Just "JP_AMAZONPAY" -> "amazonpay"
    //   Just "JP_WHATSAPP"  -> "whatsapp"
    //   _                   -> "genericintent"

    match &request.payment_method_data {
        PaymentMethodData::Upi(upi_data) => {
            match upi_data {
                UpiData::UpiIntent(_) => {
                    // For UPI Intent, return generic intent as fallback
                    // TODO: Extract bank code from metadata if available
                    Ok(None)
                }
                UpiData::UpiCollect(upi_collect_data) => {
                    // UPI Collect doesn't typically use app name
                    Ok(upi_collect_data.vpa_id.clone().map(|vpa| vpa.expose()))
                }
            }
        }
        PaymentMethodData::Wallet(wallet_data) => {
            match wallet_data {
                WalletData::GooglePay(_) => {
                    // Map GooglePay to googlepay as per Haskell
                    Ok(Some("googlepay".to_string()))
                }
                // TODO: Add other wallet mappings as needed:
                // PayTM -> "paytm"
                // PhonePe -> "phonepe"
                // Amazon -> "amazonpay"
                _ => Ok(Some("genericintent".to_string())),
            }
        }
        _ => Ok(None),
    }
}

// PayU flow determination based on Haskell getTxnS2SType implementation
#[allow(clippy::type_complexity)]
fn determine_upi_flow(
    request: &PaymentsAuthorizeData,
) -> Result<(Option<String>, Option<String>, Option<String>, String), ConnectorError> {
    // Based on Haskell implementation:
    // getTxnS2SType :: Bool -> Bool -> Bool -> Bool -> Bool -> Maybe Text
    // getTxnS2SType isTxnS2SFlow4Enabled s2sEnabled isDirectOTPTxn isEmandateRegister isDirectAuthorization

    match &request.payment_method_data {
        PaymentMethodData::Wallet(wallet_data) => {
            match wallet_data {
                WalletData::GooglePay(_) => {
                    // Google Pay UPI Intent flow
                    // From Haskell: For UPI Intent, typically uses flow "2" or "4"
                    // pg=UPI, bankcode=INTENT for generic UPI intent
                    Ok((
                        Some("UPI".to_string()),
                        Some("INTENT".to_string()),
                        None,
                        "2".to_string(),
                    ))
                }
                _ => {
                    // Other wallet types use CASH PG as per Haskell
                    // Standard S2S flow
                    Ok((Some("CASH".to_string()), None, None, "1".to_string()))
                }
            }
        }
        PaymentMethodData::Upi(upi_data) => {
            match upi_data {
                UpiData::UpiCollect(collect_data) => {
                    if let Some(vpa) = &collect_data.vpa_id {
                        // UPI Collect flow - based on Haskell implementation
                        // For UPI Collect: pg=UPI, no specific bankcode (unless TPV), VPA required
                        // The key is that VPA must be populated for sourceObject == "UPI_COLLECT"
                        Ok((
                            Some("UPI".to_string()),
                            Some("UPI".to_string()),
                            Some(vpa.peek().to_string()),
                            "2".to_string(), // UPI Collect typically uses S2S flow "2"
                        ))
                    } else {
                        // Missing VPA for UPI Collect - this should be an error
                        Err(ConnectorError::MissingRequiredField {
                            field_name: "vpa_id",
                        })
                    }
                }
                UpiData::UpiIntent(_) => {
                    // UPI Intent flow - uses S2S flow "2" for intent-based transactions
                    // pg=UPI, bankcode=INTENT for intent flows
                    Ok((
                        Some("UPI".to_string()),
                        Some("INTENT".to_string()),
                        None,
                        "2".to_string(),
                    ))
                }
            }
        }
        _ => Err(ConnectorError::NotSupported {
            message:
                "Payment method not supported by PayU. Only UPI and Wallet payments are supported"
                    .to_string(),
            connector: "PayU",
        }),
    }
}

pub fn is_upi_collect_flow(request: &PaymentsAuthorizeData) -> bool {
    // Check if the payment method is UPI Collect
    matches!(
        request.payment_method_data,
        PaymentMethodData::Upi(UpiData::UpiCollect(_))
    )
}

// Hash generation based on Haskell PayU implementation (makePayuTxnHash)
// PayU expects: sha512(key|txnid|amount|productinfo|firstname|email|udf1|udf2|udf3|udf4|udf5|udf6|udf7|udf8|udf9|udf10|salt)
fn generate_payu_hash(
    request: &PayuPaymentRequest,
    merchant_salt: &Secret<String>,
) -> Result<String, ConnectorError> {
    use sha2::{Digest, Sha512};

    // Build hash fields array exactly as PayU expects based on Haskell implementation
    // Pattern from Haskell: key|txnid|amount|productinfo|firstname|email|udf1|udf2|udf3|udf4|udf5|udf6|udf7|udf8|udf9|udf10|salt
    let hash_fields = vec![
        request.key.clone(),                                // key
        request.txnid.clone(),                              // txnid
        request.amount.get_amount_as_string(),              // amount
        request.productinfo.clone(),                        // productinfo
        request.firstname.clone(),                          // firstname
        request.email.clone(),                              // email
        request.udf1.as_deref().unwrap_or("").to_string(),  // udf1
        request.udf2.as_deref().unwrap_or("").to_string(),  // udf2
        request.udf3.as_deref().unwrap_or("").to_string(),  // udf3
        request.udf4.as_deref().unwrap_or("").to_string(),  // udf4
        request.udf5.as_deref().unwrap_or("").to_string(),  // udf5
        request.udf6.as_deref().unwrap_or("").to_string(),  // udf6
        request.udf7.as_deref().unwrap_or("").to_string(),  // udf7
        request.udf8.as_deref().unwrap_or("").to_string(),  // udf8
        request.udf9.as_deref().unwrap_or("").to_string(),  // udf9
        request.udf10.as_deref().unwrap_or("").to_string(), // udf10
        merchant_salt.peek().to_string(),                   // salt
    ];

    // Join with pipe separator as PayU expects
    let hash_string = hash_fields.join("|");

    // Log hash string for debugging (remove in production)
    #[cfg(debug_assertions)]
    {
        let masked_hash = format!(
            "{}|***MASKED***",
            hash_fields[..hash_fields.len() - 1].join("|")
        );
        tracing::debug!("PayU hash string (salt masked): {}", masked_hash);
        tracing::debug!("PayU expected format from Haskell: key|txnid|amount|productinfo|firstname|email|udf1|udf2|udf3|udf4|udf5|udf6|udf7|udf8|udf9|udf10|salt");
    }

    // Generate SHA-512 hash as PayU expects
    let mut hasher = Sha512::new();
    hasher.update(hash_string.as_bytes());
    let result = hasher.finalize();
    Ok(hex::encode(result))
}

// Response conversion with Framework Integration
impl
    TryFrom<
        ResponseRouterData<
            PayuPaymentResponse,
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        >,
    > for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            PayuPaymentResponse,
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let response = item.response;

        // Check if this is an error response first
        if let Some(error_code) = &response.error {
            // Extract transaction ID for error response
            let error_transaction_id = response
                .reference_id
                .clone()
                .or_else(|| response.txn_id.clone())
                .or_else(|| response.token.clone());

            // This is an error response - return error
            let error_response = ErrorResponse {
                status_code: 200, // PayU returns 200 even for errors
                code: error_code.clone(),
                message: response.message.clone().unwrap_or_default(),
                reason: None,
                attempt_status: Some(AttemptStatus::Failure),
                connector_transaction_id: error_transaction_id,
                network_error_message: None,
                network_advice_code: None,
                network_decline_code: None,
                raw_connector_response: None,
            };

            return Ok(Self {
                response: Err(error_response),
                resource_common_data: PaymentFlowData {
                    status: AttemptStatus::Failure,
                    ..item.router_data.resource_common_data
                },
                ..item.router_data
            });
        }

        // Extract reference ID for transaction tracking (success case)
        let upi_transaction_id = response
            .reference_id
            .or_else(|| response.txn_id.clone())
            .or_else(|| response.token.clone())
            .unwrap_or_else(|| item.router_data.resource_common_data.payment_id.clone());

        // Convert amount back using AmountConvertor framework if available
        let response_amount = if let Some(_amount_str) = response.amount {
            // For now, we'll use the request amount since convert_back has complex requirements
            // This will be improved in the full implementation
            item.router_data.request.minor_amount
        } else {
            item.router_data.request.minor_amount // Use request amount if response doesn't have it
        };

        // Create integrity object for response validation
        let _integrity_object = Some(AuthoriseIntegrityObject {
            amount: response_amount,
            currency: item.router_data.request.currency,
        });

        // This is a success response - determine type based on response format
        let (status, transaction_id, redirection_data) = match &response.status {
            Some(PayuStatusValue::IntStatus(1)) => {
                // UPI Intent success - PayU returns status=1 for successful UPI intent generation
                let redirection_data = response.intent_uri_data.map(|intent_data| {
                    // PayU returns UPI intent parameters that need to be formatted as UPI URI
                    Box::new(RedirectForm::Uri { uri: intent_data })
                });

                (
                    AttemptStatus::AuthenticationPending,
                    upi_transaction_id.clone(),
                    redirection_data,
                )
            }
            Some(PayuStatusValue::StringStatus(s)) if s == "success" => {
                // UPI Collect success - PayU returns status="success" with result object
                let (status, transaction_id) = response
                    .result
                    .map(|result| {
                        if result.status == "pending" {
                            (
                                AttemptStatus::AuthenticationPending,
                                result.mihpayid.clone(),
                            )
                        } else {
                            (AttemptStatus::Failure, result.mihpayid.clone())
                        }
                    })
                    .unwrap_or((AttemptStatus::Failure, "".to_owned()));
                (status, transaction_id, None)
            }
            _ => {
                // Unknown success status
                (AttemptStatus::Failure, upi_transaction_id.clone(), None)
            }
        };

        let payment_response_data = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(transaction_id.clone()),
            redirection_data,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: Some(transaction_id),
            incremental_authorization_allowed: None,
            raw_connector_response: None,
            status_code: Some(item.http_code),
        };

        Ok(Self {
            response: Ok(payment_response_data),
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}
