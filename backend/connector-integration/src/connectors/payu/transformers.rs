use serde::{Deserialize, Serialize};
use error_stack::ResultExt;
use hyperswitch_masking::Secret;
use domain_types::errors::ConnectorError;
use domain_types::{
    connector_types::{
        PaymentsAuthorizeData, PaymentsResponseData,
        PaymentFlowData,
        ResponseId,
    },
    connector_flow::{
        Accept, Authorize, Capture, CreateOrder, DefendDispute, PSync, RSync, Refund, SetupMandate,
        SubmitEvidence, Void,
    },
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
    payment_method_data::PaymentMethodData,
};
use common_enums::{self, AttemptStatus, RefundStatus};

use crate::types::ResponseRouterData;
// use crate::traits::GetIntegrityObject;

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

// Implement Integrity Framework support
// impl GetIntegrityObject<AuthoriseIntegrityObject> for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData> {
//     fn get_response_integrity_object(&self) -> Option<AuthoriseIntegrityObject> {
//         match &self.response {
//             Ok(PaymentsResponseData::TransactionResponse { amount, currency, .. }) => {
//                 Some(AuthoriseIntegrityObject {
//                     amount: *amount,
//                     currency: *currency,
//                 })
//             }
//             _ => None,
//         }
//     }

//     fn get_request_integrity_object(&self) -> AuthoriseIntegrityObject {
//         self.request.integrity_object.clone().unwrap_or_else(|| {
//             AuthoriseIntegrityObject {
//                 amount: self.request.amount,
//                 currency: self.request.currency,
//             }
//         })
//     }
// }

// Request structure based on Payu UPI analysis
#[derive(Debug, Serialize)]
pub struct PayuPaymentRequest {
    // Core payment fields
    pub key: String,                    // Merchant key
    pub txnid: String,                  // Transaction ID
    pub amount: String,                 // Amount in string major units
    pub currency: String,               // Currency code
    pub productinfo: String,            // Product description

    // Customer information
    pub firstname: String,
    pub lastname: Option<String>,
    pub email: String,
    pub phone: String,

    // URLs
    pub surl: String,                   // Success URL
    pub furl: String,                   // Failure URL

    // Payment method specific
    pub pg: Option<String>,             // Payment gateway code
    pub bankcode: Option<String>,       // Bank code
    pub vpa: Option<String>,           // UPI VPA (for collect)

    // UPI specific fields
    pub txn_s2s_flow: String,          // S2S flow type ("2" or "4")
    pub s2s_client_ip: String,         // Client IP
    pub s2s_device_info: String,       // Device info
    pub api_version: Option<String>,   // API version

    // Security
    pub hash: String,                   // HMAC signature

    // Optional fields
    pub udf1: Option<String>,
    pub udf2: Option<String>,
    pub udf3: Option<String>,
    pub udf4: Option<String>,
    pub udf5: Option<String>,
}

// Response structure based on Payu analysis
#[derive(Debug, Deserialize)]
pub struct PayuPaymentResponse {
    pub transaction_id: String,
    pub status: String,
    pub amount: String,
    pub currency: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
}

// Error response structure
#[derive(Debug, Deserialize)]
pub struct PayuErrorResponse {
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub error_description: Option<String>,
    pub transaction_id: Option<String>,
}

// Request conversion with Framework Integration
impl TryFrom<&RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>>
    for PayuPaymentRequest {
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(item: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>) -> Result<Self, Self::Error> {
        // Extract connector instance to access amount_converter
        let connector = super::Payu::new();

        // Use AmountConvertor framework for proper amount handling
        let amount = connector
            .amount_converter
            .convert(item.request.amount, item.request.currency)
            .change_context(ConnectorError::AmountConversionFailed)?;

        // Extract authentication
        let auth = PayuAuthType::try_from(&item.connector_auth_type)?;

        // Determine payment flow based on payment method
        let (pg, bankcode, vpa, s2s_flow) = determine_upi_flow(&item.request)?;

        // Build base request
        let mut request = Self {
            key: auth.api_key.peek().to_string(),
            txnid: item.payment_id.clone(),
            amount: amount.clone(),
            currency: item.request.currency.to_string(),
            productinfo: "Payment".to_string(), // Default product info

            // Customer info (with defaults for testing)
            firstname: "Customer".to_string(),
            lastname: Some("Name".to_string()),
            email: "customer@example.com".to_string(),
            phone: "9999999999".to_string(),

            // URLs (will be provided by connector service)
            surl: "https://example.com/success".to_string(),
            furl: "https://example.com/failure".to_string(),

            // Payment method specific
            pg,
            bankcode,
            vpa,

            // UPI specific
            txn_s2s_flow: s2s_flow,
            s2s_client_ip: "127.0.0.1".to_string(),
            s2s_device_info: "connector-service".to_string(),
            api_version: Some("7".to_string()), // UPI mandate version

            // Will be calculated after struct creation
            hash: String::new(),

            // Optional fields
            udf1: None,
            udf2: None,
            udf3: None,
            udf4: None,
            udf5: None,
        };

        // Generate hash signature
        request.hash = generate_payu_hash(&request, &auth.api_secret)?;

        Ok(request)
    }
}

// UPI flow determination based on payment method analysis
fn determine_upi_flow(request: &PaymentsAuthorizeData) -> Result<(Option<String>, Option<String>, Option<String>, String), ConnectorError> {
    // Based on Payu analysis:
    // - UPI Intent: vpa = None, s2s_flow = "4" for mandates or "2" for standard
    // - UPI Collect: vpa = Some(customer_vpa), s2s_flow = "2"
    // - UPI QR: vpa = None, s2s_flow = "2"

    match &request.payment_method_data {
        PaymentMethodData::Upi(upi_data) => {
            if let Some(vpa) = &upi_data.vpa_id {
                // UPI Collect flow
                Ok((Some("UPI".to_string()), None, Some(vpa.clone()), "2".to_string()))
            } else {
                // UPI Intent/QR flow
                Ok((Some("UPI".to_string()), None, None, "2".to_string()))
            }
        }
        _ => Err(ConnectorError::NotSupported {
            message: "Only UPI payment method is supported".to_string(),
        }),
    }
}

// Hash generation based on Payu analysis
fn generate_payu_hash(request: &PayuPaymentRequest, merchant_salt: &Secret<String>) -> Result<String, ConnectorError> {
    use ring::hmac;
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    // Payu hash string format: key|txnid|amount|productinfo|firstname|email|udf1|udf2|udf3|udf4|udf5||||||SALT
    let hash_string = format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}||||||{}",
        request.key,
        request.txnid,
        request.amount,
        request.productinfo,
        request.firstname,
        request.email,
        request.udf1.as_deref().unwrap_or(""),
        request.udf2.as_deref().unwrap_or(""),
        request.udf3.as_deref().unwrap_or(""),
        request.udf4.as_deref().unwrap_or(""),
        request.udf5.as_deref().unwrap_or(""),
        merchant_salt.peek()
    );

    let mut mac = HmacSha256::new_from_slice(merchant_salt.peek().as_bytes())
        .map_err(|_| ConnectorError::InvalidConnectorConfig {
            config: "Invalid merchant salt for HMAC calculation".to_string(),
        })?;

    mac.update(hash_string.as_bytes());
    let result = mac.finalize();
    Ok(hex::encode(result.into_bytes()))
}

// Response conversion with Framework Integration
impl TryFrom<ResponseRouterData<PayuPaymentResponse, RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>>>
    for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData> {
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(item: ResponseRouterData<PayuPaymentResponse, RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>>) -> Result<Self, Self::Error> {
        let connector = super::Payu::new();
        let response = item.response;

        // Convert amount back using AmountConvertor framework
        let response_amount = connector
            .amount_converter
            .convert_back(response.amount, item.data.request.currency)
            .change_context(ConnectorError::ResponseDeserializationFailed)?;

        // Create integrity object for response validation
        let integrity_object = Some(AuthoriseIntegrityObject {
            amount: response_amount,
            currency: item.data.request.currency,
        });

        let status = match response.status.as_str() {
            "success" | "SUCCESS" => AttemptStatus::Charged,
            "pending" | "PENDING" => AttemptStatus::Pending,
            "failure" | "FAILURE" | "failed" | "FAILED" => AttemptStatus::Failure,
            _ => AttemptStatus::Pending,
        };

        Ok(Self {
            status,
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(response.transaction_id.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_transaction_id: None,
                connector_response_reference_id: Some(response.transaction_id),
                incremental_authorization_allowed: None,
                charge_id: None,
                integrity_object, // ✅ Include integrity data
            }),
            ..item.data
        })
    }
}