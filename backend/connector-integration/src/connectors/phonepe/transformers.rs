use serde::{Deserialize, Serialize};
use common_utils::{errors::CustomResult, crypto::{Sha256, GenerateDigest}};
use hyperswitch_masking::ExposeInterface;
use domain_types::{
    connector_types::ResponseId,
    errors,
    payment_method_data::{PaymentMethodData, UpiData},
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
    connector_flow::Authorize,
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData},
};
use error_stack::ResultExt;
use hyperswitch_masking::{Secret, PeekInterface};
use common_enums::AttemptStatus;
use base64::{Engine, engine::general_purpose::STANDARD};
use tracing::info;

// Authentication structure for PhonePe
#[derive(Debug, Clone)]
pub struct PhonepeAuthType {
    pub merchant_id: Secret<String>,
    pub api_key: Secret<String>,
    pub key_index: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for PhonepeAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey { api_key, key1, api_secret } => Ok(Self {
                merchant_id: api_key.clone(),
                api_key: key1.clone(),
                key_index: api_secret.clone(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

// PhonePe request structures based on the analysis document

#[derive(Debug, Serialize)]
pub struct PhonepePaymentRequest {
    #[serde(rename = "merchantId")]
    pub merchant_id: Secret<String>,
    #[serde(rename = "merchantTransactionId")]
    pub merchant_transaction_id: String,
    #[serde(rename = "merchantUserId")]
    pub merchant_user_id: String,
    pub amount: i64, // Amount in minor units (paise)
    #[serde(rename = "callbackUrl")]
    pub callback_url: String,
    #[serde(rename = "mobileNumber", skip_serializing_if = "Option::is_none")]
    pub mobile_number: Option<Secret<String>>,
    #[serde(rename = "paymentInstrument")]
    pub payment_instrument: PaymentInstrument,
    #[serde(rename = "deviceContext", skip_serializing_if = "Option::is_none")]
    pub device_context: Option<DeviceContext>,
}

#[derive(Debug, Serialize)]
pub struct PaymentInstrument {
    #[serde(rename = "type")]
    pub instrument_type: String,
    #[serde(rename = "targetApp", skip_serializing_if = "Option::is_none")]
    pub target_app: Option<String>,
    #[serde(rename = "vpa", skip_serializing_if = "Option::is_none")]
    pub vpa: Option<Secret<String>>,
}

#[derive(Debug, Serialize)]
pub struct DeviceContext {
    #[serde(rename = "deviceOS")]
    pub device_os: String,
}

// PhonePe response structures

#[derive(Debug, Serialize, Deserialize)]
pub struct PhonepePaymentResponse {
    pub success: bool,
    pub code: String,
    pub message: String,
    pub data: Option<PhonepePaymentData>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PhonepePaymentData {
    #[serde(rename = "merchantId")]
    pub merchant_id: String,
    #[serde(rename = "merchantTransactionId")]
    pub merchant_transaction_id: String,
    #[serde(rename = "transactionId")]
    pub transaction_id: String,
    #[serde(default)]
    pub amount: Option<i64>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(rename = "responseCode", default)]
    pub response_code: Option<String>,
    #[serde(rename = "paymentInstrument", default)]
    pub payment_instrument: Option<ResponsePaymentInstrument>,
    #[serde(rename = "instrumentResponse", default)]
    pub instrument_response: Option<InstrumentResponse>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ResponsePaymentInstrument {
    #[serde(rename = "_type")]
    pub instrument_type: String,
    pub utr: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InstrumentResponse {
    #[serde(rename = "type")]
    pub instrument_type: String,
}

// Error response structure
#[derive(Debug, Serialize, Deserialize)]
pub struct PhonepeErrorResponse {
    pub success: Option<bool>,
    pub code: Option<String>,
    pub message: Option<String>,
    pub data: Option<PhonepeErrorData>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PhonepeErrorData {
    #[serde(rename = "merchantId")]
    pub merchant_id: Option<String>,
    #[serde(rename = "merchantTransactionId")]
    pub merchant_transaction_id: Option<String>,
    #[serde(rename = "transactionId")]
    pub transaction_id: Option<String>,
    #[serde(rename = "errorCode")]
    pub error_code: Option<String>,
    #[serde(rename = "errorMessage")]
    pub error_message: Option<String>,
    #[serde(rename = "errorDescription")]
    pub error_description: Option<String>,
}

// Request conversion trait
pub trait ForeignTryFrom<T>: Sized {
    type Error;
    fn foreign_try_from(from: T) -> Result<Self, Self::Error>;
}

impl TryFrom<&RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>> 
    for PhonepePaymentRequest {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        // PhonePe transaction ID length validation (from analysis: isTxnlessThan38Char)
        if item.resource_common_data.payment_id.len() > 38 {
            return Err(errors::ConnectorError::RequestEncodingFailed.into());
        }
        
        let auth = PhonepeAuthType::try_from(&item.connector_auth_type)?;
        
        // Get connector instance to access amount_converter
        let _connector = crate::connectors::phonepe::Phonepe::new();
        
        // PhonePe expects amount in minor units (paise) - direct integer conversion
        // Based on analysis: amount = getMoney txn ord (returns integer paise)
        let amount = item.request.minor_amount.get_amount_as_i64();

        // Determine payment instrument based on UPI flow type
        // Based on PhonePe analysis: flow differentiation via sourceObject and UPI data type
        let payment_instrument = match &item.request.payment_method_data {
            PaymentMethodData::Upi(upi_data) => match upi_data {
                // UPI Intent Flow: sourceObject == "UPI_PAY" in PhonePe analysis
                UpiData::UpiIntent(intent_data) => {
                    // Extract target app from intent data if available, default to GPAY
                    let target_app = intent_data.app_name
                        .as_ref()
                        .map(|app| app.to_uppercase())
                        .unwrap_or_else(|| "GPAY".to_string());
                    
                    PaymentInstrument {
                        instrument_type: "UPI_INTENT".to_string(),
                        target_app: Some(target_app),
                        vpa: None,
                    }
                },
                // UPI QR Flow: sourceObject == "UPI_QR" in PhonePe analysis
                UpiData::UpiQr(_) => PaymentInstrument {
                    instrument_type: "UPI_QR".to_string(),
                    target_app: None,
                    vpa: None,
                },
                // UPI Collect Flow: VPA-based routing as per PhonePe analysis
                UpiData::UpiCollect(collect_data) => {
                    // Validate VPA presence for collect flow
                    let vpa = collect_data.vpa_id.as_ref()
                        .ok_or_else(|| {
                            errors::ConnectorError::MissingRequiredField {
                                field_name: "vpa_id",
                            }
                        })?;
                    
                    // Basic VPA format validation (user@psp format)
                    let vpa_string = vpa.peek();
                    if !vpa_string.contains('@') || vpa_string.split('@').count() != 2 {
                        return Err(errors::ConnectorError::RequestEncodingFailed.into());
                    }
                    
                    PaymentInstrument {
                        instrument_type: "UPI_COLLECT".to_string(),
                        target_app: None,
                        vpa: Some(Secret::new(vpa_string.to_string())),
                    }
                },
            },
            _ => return Err(errors::ConnectorError::NotSupported {
                message: "Payment method not supported for PhonePe".to_string(),
                connector: "phonepe",
            }.into()),
        };

        // Add device context only for UPI Intent flow as per PhonePe analysis
        // Analysis shows deviceContext required only for Intent flow, not QR or Collect
        let device_context = match &item.request.payment_method_data {
            PaymentMethodData::Upi(UpiData::UpiIntent(intent_data)) => {
                // Extract device OS from intent data if available, default to ANDROID
                let device_os = intent_data.device_os
                    .as_ref()
                    .map(|os| os.to_uppercase())
                    .unwrap_or_else(|| "ANDROID".to_string());
                
                Some(DeviceContext {
                    device_os,
                })
            },
            // QR and Collect flows don't require device context per PhonePe analysis
            _ => None,
        };

        // Build callback URL
        let callback_url = item.request.webhook_url
            .clone()
            .or_else(|| item.request.router_return_url.clone())
            .unwrap_or_else(|| format!("https://api.hyperswitch.io/phonepe/webhook/{}", item.resource_common_data.payment_id));

        let requestpp = Self {
            merchant_id: auth.merchant_id,
            merchant_transaction_id: item.resource_common_data.payment_id.clone(),
            merchant_user_id: item.request.customer_id
                .as_ref()
                .map(|id| id.get_string_repr().to_string())
                .unwrap_or_else(|| "guest".to_string()),
            amount,
            callback_url,
            mobile_number: None, // TODO: Extract from customer data if available
            payment_instrument,
            device_context,
        };

        info!("PhonePe payment request created: {:?}", requestpp);

        Ok(requestpp)
    }
}

// Security helper functions based on PhonePe analysis


impl PhonepePaymentRequest {
    // Generate X-VERIFY header based on PhonePe V2 API requirements
    pub fn generate_verify_header(
        &self,
        auth: &PhonepeAuthType,
        api_path: &str,
    ) -> CustomResult<String, errors::ConnectorError> {
        // Serialize request to JSON and encode to base64
        let json_payload = serde_json::to_string(self)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;
        
        let encoded_payload = STANDARD.encode(json_payload);

        let checksum_string = format!(
                "{}{}{}",
                encoded_payload,
                api_path,
                auth.api_key.peek()
            );

            tracing::info!(
                "PhonePe checksum string: {}{}{}",
                encoded_payload,
                api_path,
                auth.api_key.peek()
            );

            let hasher = Sha256;
            let hash_result = hasher.generate_digest(checksum_string.as_bytes())
                .change_context(errors::ConnectorError::RequestEncodingFailed)?;
            
            // Convert to hex string
            let hash = hash_result.iter().map(|b| format!("{:02x}", b)).collect::<String>();

            tracing::info!("PhonePe checksum hash: {}", hash);

            let checksum = format!("{}###{}", hash, auth.key_index.clone().expose());
            tracing::info!("PhonePe checksum: {}", checksum);
            Ok(checksum)
        


    }

    // Encode request as base64 JSON for PhonePe API
    pub fn encode_payload(&self) -> CustomResult<String, errors::ConnectorError> {
        let json_payload = serde_json::to_string(self)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;
        
        Ok(STANDARD.encode(json_payload))
    }
}

// Response conversion
impl TryFrom<PhonepePaymentResponse> for PaymentsResponseData {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: PhonepePaymentResponse) -> Result<Self, Self::Error> {
        let data = item.data.ok_or_else(|| {
            errors::ConnectorError::ResponseDeserializationFailed
        })?;

        let _status = match data.state.as_deref() {
            Some("COMPLETED") => AttemptStatus::Charged,
            Some("PENDING") => AttemptStatus::Pending,
            Some("FAILED") => AttemptStatus::Failure,
            _ => AttemptStatus::Pending,
        };

        Ok(Self::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(data.transaction_id.clone()),
            redirection_data: Box::new(None),
            mandate_reference: Box::new(None),
            connector_metadata: None,
            network_txn_id: data.payment_instrument
                .as_ref()
                .and_then(|pi| pi.utr.clone()),
            connector_response_reference_id: Some(data.transaction_id),
            incremental_authorization_allowed: None,
            raw_connector_response: None,
        })
    }
}

// Required ForeignTryFrom implementation for RouterDataV2 conversion
impl ForeignTryFrom<(
    PhonepePaymentResponse,
    RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
    u16,
    Option<common_enums::CaptureMethod>,
    bool,
    common_enums::PaymentMethodType,
)> for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData> {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn foreign_try_from(
        (response, mut item, _http_code, _capture_method, _is_auto_capture, _payment_method_type): (
            PhonepePaymentResponse,
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
            u16,
            Option<common_enums::CaptureMethod>,
            bool,
            common_enums::PaymentMethodType,
        ),
    ) -> Result<Self, Self::Error> {
        let status = if response.success {
            if let Some(data) = &response.data {
                match data.state.as_deref() {
                    Some("COMPLETED") => AttemptStatus::Charged,
                    Some("PENDING") => AttemptStatus::Pending,
                    Some("FAILED") => AttemptStatus::Failure,
                    _ => AttemptStatus::Pending,
                }
            } else {
                AttemptStatus::Pending
            }
        } else {
            AttemptStatus::Failure
        };

        let payments_response_data = PaymentsResponseData::try_from(response)?;
        
        item.resource_common_data.status = status;
        item.response = Ok(payments_response_data);
        
        Ok(item)
    }
}