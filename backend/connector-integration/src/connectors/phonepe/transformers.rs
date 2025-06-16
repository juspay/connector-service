use base64::Engine;
use common_enums::AttemptStatus;
use domain_types::{
    connector_flow::Authorize,
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, ResponseId},
};
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
use std::collections::HashMap;
use std::convert::TryFrom;

use crate::types::ResponseRouterData;

// Authentication type for PhonePe
#[derive(Debug, Clone)]
pub struct PhonePeAuthType {
    pub(crate) merchant_id: Secret<String>, // PhonePe merchant ID
    pub(crate) salt_key: Secret<String>,    // Salt key for checksum generation
    pub(crate) salt_index: Secret<String>,  // Salt index (usually "1")
}

impl TryFrom<&ConnectorAuthType> for PhonePeAuthType {
    type Error = error_stack::Report<hyperswitch_interfaces::errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey {
                api_key,
                key1,
                api_secret,
            } => Ok(Self {
                merchant_id: api_key.to_owned(),
                salt_key: key1.to_owned(),
                salt_index: api_secret.to_owned(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

// PhonePe device context for UPI Intent
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PhonePeDeviceContext {
    pub device_os: String, // "ANDROID", "IOS", or "WEB"
}

// PhonePe payment instrument for different UPI flows
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct PhonePePaymentInstrument {
    #[serde(rename = "type")]
    pub instrument_type: String, // "UPI_INTENT", "UPI_QR", or "UPI_COLLECT"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_app: Option<String>, // Specific UPI app for Intent
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vpa: Option<String>, // VPA for Collect flow
}

// Inner payload structure for PhonePe (before base64 encoding)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct PhonePeInnerPayload {
    pub merchant_id: String,
    pub merchant_transaction_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merchant_user_id: Option<String>,
    pub amount: i64, // Amount in paisa
    pub callback_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mobile_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_context: Option<PhonePeDeviceContext>, // Only for UPI Intent
    pub payment_instrument: PhonePePaymentInstrument,
}

// PhonePe payment request structure (final request body with base64 encoding)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhonePePaymentRequest {
    pub request: String, // Base64 encoded JSON payload
    #[serde(skip)]
    inner_payload: PhonePeInnerPayload, // Keep reference to inner payload for processing
}

impl PhonePePaymentRequest {
    pub fn new(inner_payload: PhonePeInnerPayload) -> Result<Self, serde_json::Error> {
        // Convert inner payload to JSON
        let json_payload = serde_json::to_string(&inner_payload)?;

        // Encode to base64
        let base64_payload = base64::engine::general_purpose::STANDARD.encode(json_payload);

        Ok(Self {
            request: base64_payload,
            inner_payload,
        })
    }

    pub fn get_inner_payload(&self) -> &PhonePeInnerPayload {
        &self.inner_payload
    }

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

// PhonePe instrument response structures
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PhonePeInstrumentResponse {
    #[serde(rename = "type")]
    pub instrument_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intent_url: Option<String>, // For UPI Intent
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qr_data: Option<String>, // For UPI QR
}

// PhonePe transaction details (optional in response)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PhonePeTransactionDetails {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pay_response_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pay_response_code_description: Option<String>,
}

// PhonePe success response data
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PhonePeSuccessData {
    pub merchant_id: String,
    pub merchant_transaction_id: String,
    pub instrument_response: PhonePeInstrumentResponse,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_code_description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pay_response_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pay_response_code_description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_details: Option<PhonePeTransactionDetails>,
}

// PhonePe success response structure
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PhonePeSuccessResponse {
    pub success: bool,
    pub code: String,
    pub message: String,
    pub data: PhonePeSuccessData,
}

// PhonePe error response structure
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PhonePeErrorResponse {
    pub success: bool,
    pub code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

// Combined PhonePe response type
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PhonePePaymentResponse {
    Success(PhonePeSuccessResponse),
    Error(PhonePeErrorResponse),
}

impl TryFrom<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>>
    for PhonePePaymentRequest
{
    type Error = error_stack::Report<hyperswitch_interfaces::errors::ConnectorError>;

    fn try_from(
        item: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let router_data = &item;

        // Extract auth credentials
        let auth = PhonePeAuthType::try_from(&router_data.connector_auth_type)?;

        // Prepare common request fields
        let merchant_transaction_id = router_data.connector_request_reference_id.clone();
        let amount = router_data.request.minor_amount.get_amount_as_i64();

        tracing::info!(
            "PhonePe: Amount details - minor_amount: {:?}, amount_as_i64: {}, currency: {:?}",
            router_data.request.minor_amount,
            amount,
            router_data.request.currency
        );

        // Validate amount for PhonePe requirements
        if amount <= 0 {
            tracing::error!(
                "PhonePe: Invalid amount - amount must be greater than 0, got: {}",
                amount
            );
            return Err(errors::ConnectorError::AmountConversionFailed.into());
        }

        // PhonePe typically requires minimum 1 rupee (100 paise) for Indian market
        if router_data.request.currency.to_string() == "INR" && amount < 100 {
            tracing::warn!(
                "PhonePe: Amount {} paise is less than minimum 100 paise (1 INR) for Indian market",
                amount
            );
        }

        // Get customer mobile number
        let mobile_number = router_data
            .resource_common_data
            .address
            .get_payment_billing()
            .and_then(|billing| billing.phone.as_ref())
            .and_then(|p| p.number.as_ref())
            .map(|n| n.clone().expose().to_string())
            .filter(|phone| !phone.is_empty() && phone != "9999999999"); // Filter default/invalid numbers

        // Get merchant user ID (customer ID)
        let merchant_user_id = router_data
            .resource_common_data
            .customer_id
            .as_ref()
            .map(|id| id.get_string_repr().to_string());

        // Get callback URL (webhook URL)
        let callback_url = router_data.request.webhook_url.clone().ok_or(
            errors::ConnectorError::MissingRequiredField {
                field_name: "webhook_url",
            },
        )?;

        // Determine device context for UPI Intent
        let device_context = match &router_data.request.payment_method_data {
            PaymentMethodData::Upi(payment_method_data::UpiData::UpiIntent(_)) => router_data
                .request
                .browser_info
                .as_ref()
                .and_then(|info| info.user_agent.as_ref())
                .and_then(|ua| {
                    let ua_lower = ua.to_lowercase();
                    if ua_lower.contains("android") {
                        Some(PhonePeDeviceContext {
                            device_os: "ANDROID".to_string(),
                        })
                    } else if ua_lower.contains("iphone")
                        || ua_lower.contains("ipad")
                        || ua_lower.contains("ios")
                    {
                        Some(PhonePeDeviceContext {
                            device_os: "IOS".to_string(),
                        })
                    } else {
                        Some(PhonePeDeviceContext {
                            device_os: "WEB".to_string(),
                        })
                    }
                }),
            _ => None,
        };

        // Create payment instrument based on UPI flow
        let payment_instrument = match &router_data.request.payment_method_data {
            PaymentMethodData::Upi(upi_data) => {
                match upi_data {
                    payment_method_data::UpiData::UpiIntent(_intent_data) => {
                        tracing::info!("PhonePe: UPI Intent flow");

                        // Extract target UPI app from metadata if specified
                        let target_app = router_data
                            .request
                            .metadata
                            .as_ref()
                            .and_then(|meta| meta.get("upi_app").map(|v| v.to_string()));

                        PhonePePaymentInstrument {
                            instrument_type: "UPI_INTENT".to_string(),
                            target_app,
                            vpa: None,
                        }
                    }
                    payment_method_data::UpiData::UpiQr(_qr_data) => {
                        tracing::info!("PhonePe: UPI QR flow");

                        PhonePePaymentInstrument {
                            instrument_type: "UPI_QR".to_string(),
                            target_app: None,
                            vpa: None,
                        }
                    }
                    payment_method_data::UpiData::UpiCollect(collect_data) => {
                        tracing::info!("PhonePe: UPI Collect flow");

                        // Get the VPA ID from the collect_data
                        if let Some(vpa_secret) = &collect_data.vpa_id {
                            let vpa_id = vpa_secret.clone().expose();
                            tracing::info!("PhonePe: VPA ID: {:?}", vpa_id);

                            // Validate VPA format
                            if !Self::validate_vpa(&vpa_id) {
                                return Err(errors::ConnectorError::InvalidDataFormat {
                                    field_name: "vpa_id",
                                }
                                .into());
                            }

                            PhonePePaymentInstrument {
                                instrument_type: "UPI_COLLECT".to_string(),
                                target_app: None,
                                vpa: Some(vpa_id),
                            }
                        } else {
                            return Err(errors::ConnectorError::MissingRequiredField {
                                field_name: "vpa_id",
                            }
                            .into());
                        }
                    }
                }
            }
            _ => {
                return Err(errors::ConnectorError::NotImplemented(
                    "Payment method not supported".into(),
                )
                .into());
            }
        };

        // Create inner payload
        let inner_payload = PhonePeInnerPayload {
            merchant_id: auth.merchant_id.clone().expose(),
            merchant_transaction_id,
            merchant_user_id,
            amount,
            callback_url,
            mobile_number,
            device_context,
            payment_instrument,
        };

        // Create final request with base64 encoding
        let request =
            Self::new(inner_payload).map_err(|_| errors::ConnectorError::RequestEncodingFailed)?;

        tracing::info!(
            "PhonePe: Successfully created payment request with merchant_transaction_id={}",
            request.inner_payload.merchant_transaction_id
        );

        Ok(request)
    }
}

// Use the PhonePeRouterData type generated by the macro
use super::PhonePeRouterData;

// Implementation for PhonePeRouterData (required by macro) - forwards to RouterDataV2 implementation
impl
    TryFrom<
        PhonePeRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        >,
    > for PhonePePaymentRequest
{
    type Error = error_stack::Report<hyperswitch_interfaces::errors::ConnectorError>;

    fn try_from(
        item: PhonePeRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        // Forward to the RouterDataV2 implementation
        Self::try_from(item.router_data)
    }
}

// Implementation for RouterDataV2 directly (your main implementation)
impl
    TryFrom<
        ResponseRouterData<
            PhonePePaymentResponse,
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        >,
    > for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>
{
    type Error = error_stack::Report<hyperswitch_interfaces::errors::ConnectorError>;

    fn try_from(
        value: ResponseRouterData<PhonePePaymentResponse, Self>,
    ) -> Result<Self, Self::Error> {
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
            PhonePePaymentResponse::Success(success_response) => {
                if success_response.success {
                    // Success response
                    if let Ok(success_json) = serde_json::to_string(&success_response) {
                        tracing::info!("PhonePe: Successful response received: {}", success_json);
                    } else {
                        tracing::info!(
                            "PhonePe: Successful response received (could not serialize to JSON)"
                        );
                    }

                    // Set appropriate status based on payment flow
                    let status = match success_response
                        .data
                        .instrument_response
                        .instrument_type
                        .as_str()
                    {
                        "UPI_INTENT" | "UPI_QR" => AttemptStatus::AuthenticationPending, // Needs user action
                        "UPI_COLLECT" => AttemptStatus::Pending, // Waiting for customer approval
                        _ => AttemptStatus::AuthenticationPending,
                    };

                    router_data.resource_common_data.status = status;

                    tracing::info!(
                        "PhonePe: Setting status to {:?} for instrument type: {}",
                        status,
                        success_response.data.instrument_response.instrument_type
                    );

                    // Create redirection data based on instrument type
                    let redirection_data = match success_response
                        .data
                        .instrument_response
                        .instrument_type
                        .as_str()
                    {
                        "UPI_INTENT" => {
                            // For UPI Intent, create redirect to intent URL
                            tracing::info!("PhonePe: UPI Intent flow detected, creating redirect to intent URL {:?}", success_response.data.instrument_response.intent_url);
                            if let Some(ref intent_url) =
                                success_response.data.instrument_response.intent_url
                            {
                                Some(RedirectForm::Uri {
                                    uri: intent_url.clone(),
                                })
                            } else {
                                None
                            }
                        }

                        "UPI_QR" => {
                            // For UPI QR, QR data is returned in metadata, no redirection needed
                            None
                        }
                        "UPI_COLLECT" => {
                            // For UPI Collect, no redirection needed
                            None
                        }
                        _ => None,
                    };

                    // Create connector metadata
                    let mut metadata = HashMap::new();
                    metadata.insert(
                        "instrument_type".to_string(),
                        success_response
                            .data
                            .instrument_response
                            .instrument_type
                            .clone(),
                    );

                    // Add QR data if available
                    if let Some(ref qr_data) = success_response.data.instrument_response.qr_data {
                        metadata.insert("qr_data".to_string(), qr_data.clone());
                    }

                    // Add response codes if available
                    if let Some(ref response_code) = success_response.data.response_code {
                        metadata.insert("response_code".to_string(), response_code.clone());
                    }
                    if let Some(ref pay_response_code) = success_response.data.pay_response_code {
                        metadata.insert("pay_response_code".to_string(), pay_response_code.clone());
                    }

                    let payments_response_data = PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(
                            success_response.data.merchant_transaction_id.clone(),
                        ),
                        redirection_data: Box::new(redirection_data),
                        connector_metadata: Some(
                            serde_json::to_value(metadata).unwrap_or_default(),
                        ),
                        network_txn_id: None,
                        connector_response_reference_id: Some(
                            success_response.data.merchant_transaction_id.clone(),
                        ),
                        incremental_authorization_allowed: None,
                        mandate_reference: Box::new(None),
                        raw_connector_response: serde_json::to_string(&success_response).ok(),
                        transaction_token: None,
                        transaction_amount: None,
                        merchant_name: None,
                        merchant_vpa: None,
                    };

                    tracing::info!(
                                            "PhonePe: Successfully processed payment response with transaction ID: {:?}",
                                            payments_response_data
                                        );
                    router_data.response = Ok(payments_response_data);
                } else {
                    // Success=false but still in success response structure
                    tracing::warn!(
                        "PhonePe: Response marked as unsuccessful: {}",
                        success_response.code
                    );
                    router_data.resource_common_data.status = AttemptStatus::Failure;

                    let error_response = ErrorResponse {
                        code: success_response.code.clone(),
                        message: success_response.message.clone(),
                        reason: Some(success_response.message.clone()),
                        status_code: http_code,
                        attempt_status: Some(AttemptStatus::Failure),
                        connector_transaction_id: Some(
                            success_response.data.merchant_transaction_id.clone(),
                        ),
                        network_decline_code: None,
                        network_advice_code: None,
                        network_error_message: None,
                    };

                    router_data.response = Err(error_response);
                }
            }
            PhonePePaymentResponse::Error(error_response) => {
                // Error response from PhonePe
                tracing::error!(
                    "PhonePe: Error response received: {} - {:?}",
                    error_response.code,
                    error_response.message
                );

                router_data.resource_common_data.status = AttemptStatus::Failure;

                let error_message = error_response
                    .message
                    .clone()
                    .unwrap_or_else(|| "Unknown error".to_string());
                let error_reason = format!("{}: {}", error_response.code, &error_message);

                let connector_error = ErrorResponse {
                    code: error_response.code.clone(),
                    message: error_message,
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
