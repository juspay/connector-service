use common_enums::{self, AttemptStatus, Currency};
use common_utils::{pii::IpAddress, Email, crypto::GenerateDigest};

use domain_types::{
    connector_flow::{Authorize, PSync},
    connector_types::{
        PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData,
    },
    errors::ConnectorError,
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes, UpiData},
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
};

use hyperswitch_masking::{ExposeInterface, PeekInterface, Secret};
use serde::{Deserialize, Serialize};

use crate::types::ResponseRouterData;

pub mod constants {
    // Payu API versions
    pub const API_VERSION: &str = "2.0";

    // Payu device info
    pub const DEVICE_INFO: &str = "web";

    // Payu UPI specific constants
    pub const PRODUCT_INFO: &str = "Payment"; // Default product info
    pub const UPI_PG: &str = "UPI"; // UPI payment gateway
    pub const UPI_COLLECT_BANKCODE: &str = "UPI"; // UPI Collect bank code
    pub const UPI_INTENT_BANKCODE: &str = "INTENT"; // UPI Intent bank code
    pub const UPI_S2S_FLOW: &str = "2"; // S2S flow type for UPI

    // Payu PSync specific constants
    pub const COMMAND: &str = "verify_payment";
}

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
    pub currency: Currency,                           // Currency code
    pub productinfo: String,                          // Product description
    // Customer information
    pub firstname: Secret<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lastname: Option<Secret<String>>,
    pub email: Email,
    pub phone: Secret<String>,

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
    pub txn_s2s_flow: String, // S2S flow type ("2" for UPI)
    pub s2s_client_ip: Secret<String>, // Client IP
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
    #[serde(alias = "upiServicePollInterval")]
    pub upi_service_poll_interval: Option<String>, // Poll interval
    #[serde(alias = "sdkUpiPushExpiry")]
    pub sdk_upi_push_expiry: Option<String>, // Push expiry
    #[serde(alias = "sdkUpiVerificationInterval")]
    pub sdk_upi_verification_interval: Option<String>, // Verification interval
    #[serde(alias = "vpaRegex")]
    pub vpa_regex: Option<String>, // VPA validation regex
    #[serde(alias = "cardSupported")]
    pub card_supported: Option<bool>, // Card support flag
    #[serde(alias = "allowedCardNetworks")]
    pub allowed_card_networks: Option<String>, // Allowed card networks

    // Error response fields
    pub error: Option<String>, // Error code
    pub message: Option<String>, // Error message
    pub msg: Option<String>, // Alternative message field
}

// UPI App structure for PayU response
#[derive(Debug, Deserialize, Serialize)]
pub struct PayuUpiApp {
    #[serde(alias = "name")]
    pub app_name: Option<String>,
    #[serde(alias = "package")]
    pub package_name: Option<String>,
}

// PSync Request structure
#[derive(Debug, Serialize)]
pub struct PayuSyncRequest {
    pub key: String,        // Merchant key
    pub command: String,    // "verify_payment"
    pub var1: String,       // Transaction ID
    pub hash: String,       // SHA-512 signature
}

// PSync Response structure
#[derive(Debug, Deserialize, Serialize)]
pub struct PayuSyncResponse {
    pub status: Option<i32>, // Status code (1 = success, 0 = error)
    pub msg: Option<String>, // Message
    pub transaction_details: Option<serde_json::Value>, // Transaction details
}

// Helper function to check if this is a UPI collect flow
pub fn is_upi_collect_flow<T: domain_types::payment_method_data::PaymentMethodDataTypes>(payment_data: &PaymentsAuthorizeData<T>) -> bool {
    match &payment_data.payment_method_data {
        PaymentMethodData::Upi(upi_data) => {
            match upi_data {
                UpiData::UpiCollect(collect_data) => {
                    collect_data.vpa_id.is_some()
                }
                UpiData::UpiIntent(_) => false,
                UpiData::UpiQr(_) => false,
            }
        }
        _ => false,
    }
}

// Helper function to generate PayU hash
fn generate_payu_hash(
    key: &str,
    txnid: &str,
    amount: &str,
    productinfo: &str,
    firstname: &str,
    email: &str,
    salt: &str,
    udf_fields: &[Option<&str>; 10],
) -> Result<String, ConnectorError> {
    // Build hash string according to PayU specification
    // Format: key|txnid|amount|productinfo|firstname|email|udf1|udf2|udf3|udf4|udf5|udf6|udf7|udf8|udf9|udf10|salt
    let mut hash_parts = vec![
        key,
        txnid,
        amount,
        productinfo,
        firstname,
        email,
    ];

    // Add UDF fields
    for udf in udf_fields {
        hash_parts.push(udf.unwrap_or(""));
    }

    hash_parts.push(salt);

    let hash_string = hash_parts.join("|");
    
    // Generate SHA-512 hash
    let sha512 = common_utils::crypto::Sha512;
    let hash = sha512.generate_digest(hash_string.as_bytes())
        .map_err(|_| ConnectorError::RequestEncodingFailed)?;
    
    Ok(hex::encode(hash))
}

// Transformer implementations

impl<T> TryFrom<&RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>
    for PayuPaymentRequest
where
    T: PaymentMethodDataTypes,
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let auth = PayuAuthType::try_from(&item.connector_auth_type)?;
        
        let transaction_id = item
            .resource_common_data
            .connector_request_reference_id
            .clone();

        // Use AmountConvertor to convert amount properly
        let converter = common_utils::types::StringMajorUnitForConnector;
        let amount = converter.convert(
            common_utils::types::MinorUnit(item.request.amount),
            item.request.currency
        ).map_err(|_| ConnectorError::RequestEncodingFailed)?;
        let currency = item.request.currency;

        // Extract customer information
        let email = item.request.email.clone().ok_or_else(|| {
            ConnectorError::MissingRequiredField {
                field_name: "email",
            }
        })?;

        // Phone is not directly available in PaymentsAuthorizeData, skip for now
        let phone = Secret::new("".to_string());

        let customer_name = item.request.customer_name.clone().unwrap_or_else(|| "Customer".to_string());

        // Get return URLs - use router_return_url instead
        let return_url = item.request.router_return_url.clone().unwrap_or_else(|| "https://default.com".to_string());

        // Get client IP
        let client_ip_address = item.request.browser_info.clone()
            .and_then(|info| info.ip_address)
            .unwrap_or_else(|| IpAddress::from("127.0.0.1"));
        let client_ip = Secret::new(client_ip_address.to_string());

        // Extract payment method data
        let (pg, bankcode, vpa, upi_app_name) = match &item.request.payment_method_data {
            PaymentMethodData::Upi(upi_data) => {
                let pg = Some(constants::UPI_PG.to_string());
                
                let (bankcode, vpa, upi_app_name) = match upi_data {
                    UpiData::UpiIntent(_) => {
                        // UPI Intent flow
                        (Some(constants::UPI_INTENT_BANKCODE.to_string()), None, None)
                    }
                    UpiData::UpiCollect(collect_data) => {
                        // UPI Collect flow
                        (Some(constants::UPI_COLLECT_BANKCODE.to_string()), collect_data.vpa_id.as_ref().map(|v| v.expose().clone()), None)
                    }
                    UpiData::UpiQr(_) => {
                        (None, None, None)
                    }
                };
                
                (pg, bankcode, vpa, upi_app_name)
            }
            _ => {
                return Err(ConnectorError::MissingRequiredField {
                    field_name: "upi_payment_method_data",
                }
                .into())
            }
        };

        // Prepare UDF fields (all empty for now)
        let udf_fields = [None; 10];

        // Generate hash
        let hash = generate_payu_hash(
            &auth.api_key.peek(),
            &transaction_id,
            &amount.to_string(),
            constants::PRODUCT_INFO,
            &customer_name,
            &email.peek().to_string(),
            &auth.api_secret.peek(),
            &udf_fields,
        )?;

        Ok(Self {
            key: auth.api_key.peek().clone(),
            txnid: transaction_id,
            amount: {
                // Use AmountConvertor to convert amount properly
                let converter = common_utils::types::StringMajorUnitForConnector;
                converter.convert(
                    common_utils::types::MinorUnit(item.request.amount),
                    item.request.currency
                ).map_err(|_| ConnectorError::RequestEncodingFailed)?
            },
            currency,
            productinfo: constants::PRODUCT_INFO.to_string(),
            firstname: Secret::new(customer_name.to_string()),
            lastname: None,
            email,
            phone,
            surl: return_url.clone(),
            furl: return_url,
            pg,
            bankcode,
            vpa,
            txn_s2s_flow: constants::UPI_S2S_FLOW.to_string(),
            s2s_client_ip: client_ip,
            s2s_device_info: constants::DEVICE_INFO.to_string(),
            api_version: Some(constants::API_VERSION.to_string()),
            hash,
            udf1: None,
            udf2: None,
            udf3: None,
            udf4: None,
            udf5: None,
            udf6: None,
            udf7: None,
            udf8: None,
            udf9: None,
            udf10: None,
            offer_key: None,
            si: None,
            si_details: None,
            beneficiarydetail: None,
            user_token: None,
            offer_auto_apply: None,
            additional_charges: None,
            additional_gst_charges: None,
            upi_app_name,
        })
    }
}

impl TryFrom<&RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>
    for PayuSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let auth = PayuAuthType::try_from(&item.connector_auth_type)?;
        
        let transaction_id = item
            .resource_common_data
            .connector_request_reference_id
            .clone();

        // Generate hash for PSync
        let hash_string = format!("{}|{}|{}|{}", 
            auth.api_key.peek(), 
            constants::COMMAND, 
            transaction_id, 
            auth.api_secret.peek()
        );
        
        let sha512 = common_utils::crypto::Sha512;
        let hash = sha512.generate_digest(hash_string.as_bytes())
            .map_err(|_| ConnectorError::RequestEncodingFailed)?;
        
        Ok(Self {
            key: auth.api_key.peek().clone(),
            command: constants::COMMAND.to_string(),
            var1: transaction_id,
            hash: hex::encode(hash),
        })
    }
}

// Response transformers

impl TryFrom<PayuPaymentResponse> for ResponseRouterData {
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(response: PayuPaymentResponse) -> Result<Self, Self::Error> {
        let _status = match response.status {
            Some(PayuStatusValue::IntStatus(1)) => {
                AttemptStatus::Charged
            }
            Some(PayuStatusValue::StringStatus(ref s)) if s == "success" => {
                AttemptStatus::Charged
            }
            Some(PayuStatusValue::IntStatus(0)) => {
                AttemptStatus::Pending
            }
            Some(PayuStatusValue::StringStatus(ref s)) if s == "pending" => {
                AttemptStatus::Pending
            }
            Some(PayuStatusValue::IntStatus(-1)) => {
                AttemptStatus::Failure
            }
            Some(PayuStatusValue::StringStatus(ref s)) if s == "failure" => {
                AttemptStatus::Failure
            }
            _ => AttemptStatus::Pending,
        };

        let _error_message = response.error.or(response.message).or(response.msg);

        Ok(ResponseRouterData {
            headers: None,
            status_code: 200,
            response: "success".into(),
        })
    }
}

impl TryFrom<PayuSyncResponse> for ResponseRouterData {
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(response: PayuSyncResponse) -> Result<Self, Self::Error> {
        let _status = match response.status {
            Some(1) => AttemptStatus::Charged,
            Some(0) => AttemptStatus::Failure,
            _ => AttemptStatus::Pending,
        };

        let _error_message = response.msg;

        Ok(ResponseRouterData {
            headers: None,
            status_code: 200,
            response: "success".into(),
        })
    }
}