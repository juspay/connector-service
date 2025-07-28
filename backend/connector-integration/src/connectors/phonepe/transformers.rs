use std::collections::HashMap;

use base64::Engine;
use common_enums;
use common_utils::{
    crypto::{self, GenerateDigest},
    ext_traits::Encode,
    types::{AmountConvertor, MinorUnit},
};
use domain_types::{
    connector_flow::Authorize,
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, ResponseId},
    errors,
    payment_method_data::{PaymentMethodData, UpiData},
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
};
use error_stack::ResultExt;
use hyperswitch_masking::{PeekInterface, Secret};
use serde::{Deserialize, Serialize};

use super::constants;
use crate::types::ResponseRouterData;

type Error = error_stack::Report<errors::ConnectorError>;

// ===== AMOUNT CONVERSION =====

pub struct PhonepeRouterData<T> {
    pub amount: MinorUnit,
    pub router_data: T,
    pub amount_converter: &'static (dyn AmountConvertor<Output = MinorUnit> + Sync),
}

impl<T> TryFrom<(MinorUnit, T)> for PhonepeRouterData<T> {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from((amount, item): (MinorUnit, T)) -> Result<Self, Self::Error> {
        Ok(Self {
            amount,
            router_data: item,
            amount_converter: &common_utils::types::MinorUnitForConnector,
        })
    }
}

// ===== REQUEST STRUCTURES =====

#[derive(Debug, Serialize)]
pub struct PhonepePaymentsRequest {
    request: Secret<String>,
    #[serde(skip)]
    pub checksum: String,
}

#[derive(Debug, Serialize)]
struct PhonepePaymentRequestPayload {
    #[serde(rename = "merchantId")]
    merchant_id: Secret<String>,
    #[serde(rename = "merchantTransactionId")]
    merchant_transaction_id: String,
    #[serde(rename = "merchantUserId", skip_serializing_if = "Option::is_none")]
    merchant_user_id: Option<String>,
    amount: MinorUnit,
    #[serde(rename = "callbackUrl")]
    callback_url: String,
    #[serde(rename = "mobileNumber", skip_serializing_if = "Option::is_none")]
    mobile_number: Option<Secret<String>>,
    #[serde(rename = "paymentInstrument")]
    payment_instrument: PhonepePaymentInstrument,
    #[serde(rename = "deviceContext", skip_serializing_if = "Option::is_none")]
    device_context: Option<PhonepeDeviceContext>,
}

#[derive(Debug, Serialize)]
struct PhonepeDeviceContext {
    #[serde(rename = "deviceOS", skip_serializing_if = "Option::is_none")]
    device_os: Option<String>,
}

#[derive(Debug, Serialize)]
struct PhonepePaymentInstrument {
    #[serde(rename = "type")]
    instrument_type: String,
    #[serde(rename = "targetApp", skip_serializing_if = "Option::is_none")]
    target_app: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    vpa: Option<Secret<String>>,
}

// ===== RESPONSE STRUCTURES =====

#[derive(Debug, Deserialize, Serialize)]
pub struct PhonepePaymentsResponse {
    pub success: bool,
    pub code: String,
    pub message: String,
    pub data: Option<PhonepeResponseData>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PhonepeResponseData {
    #[serde(rename = "merchantId")]
    merchant_id: String,
    #[serde(rename = "merchantTransactionId")]
    merchant_transaction_id: String,
    #[serde(rename = "instrumentResponse", skip_serializing_if = "Option::is_none")]
    instrument_response: Option<PhonepeInstrumentResponse>,
    #[serde(rename = "responseCode", skip_serializing_if = "Option::is_none")]
    response_code: Option<String>,
    #[serde(
        rename = "responseCodeDescription",
        skip_serializing_if = "Option::is_none"
    )]
    response_code_description: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PhonepeInstrumentResponse {
    #[serde(rename = "type")]
    instrument_type: String,
    #[serde(rename = "intentUrl", skip_serializing_if = "Option::is_none")]
    intent_url: Option<String>,
    #[serde(rename = "qrData", skip_serializing_if = "Option::is_none")]
    qr_data: Option<String>,
}

// ===== REQUEST BUILDING =====

// TryFrom implementation for macro-generated PhonepeRouterData wrapper
impl
    TryFrom<
        crate::connectors::phonepe::PhonepeRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        >,
    > for PhonepePaymentsRequest
{
    type Error = Error;

    fn try_from(
        wrapper: crate::connectors::phonepe::PhonepeRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        Self::try_from(&PhonepeRouterData {
            amount: wrapper.router_data.request.minor_amount,
            router_data: &wrapper.router_data,
            amount_converter: &common_utils::types::MinorUnitForConnector,
        })
    }
}

impl
    TryFrom<
        &PhonepeRouterData<
            &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        >,
    > for PhonepePaymentsRequest
{
    type Error = Error;

    fn try_from(
        item: &PhonepeRouterData<
            &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = item.router_data;
        let auth: PhonepeAuthType = (&router_data.connector_auth_type).try_into()?;

        // Use amount converter to get proper amount in minor units
        let amount_in_minor_units = item
            .amount_converter
            .convert(item.amount, router_data.request.currency)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;

        // Get customer mobile number from billing address
        let mobile_number = router_data
            .resource_common_data
            .get_optional_billing_phone_number()
            .map(|phone| Secret::new(phone.peek().to_string()));

        // Create payment instrument based on payment method data
        let payment_instrument = match &router_data.request.payment_method_data {
            PaymentMethodData::Upi(upi_data) => match upi_data {
                UpiData::UpiIntent(_) => PhonepePaymentInstrument {
                    instrument_type: constants::UPI_INTENT.to_string(),
                    target_app: None, // Could be extracted from payment method details if needed
                    vpa: None,
                },
                UpiData::UpiCollect(collect_data) => PhonepePaymentInstrument {
                    instrument_type: constants::UPI_COLLECT.to_string(),
                    target_app: None,
                    vpa: collect_data
                        .vpa_id
                        .as_ref()
                        .map(|vpa| Secret::new(vpa.peek().to_string())),
                },
            },
            _ => {
                return Err(errors::ConnectorError::NotSupported {
                    message: "Payment method not supported".to_string(),
                    connector: "Phonepe",
                }
                .into())
            }
        };

        // For UPI Intent, add device context with proper OS detection
        let device_context = match &router_data.request.payment_method_data {
            PaymentMethodData::Upi(UpiData::UpiIntent(_)) => {
                let device_os = router_data
                    .request
                    .browser_info
                    .as_ref()
                    .and_then(|info| info.os_type.clone())
                    .unwrap_or_else(|| constants::DEFAULT_DEVICE_OS.to_string());

                Some(PhonepeDeviceContext {
                    device_os: Some(device_os),
                })
            }
            _ => None,
        };

        // Build payload
        let payload = PhonepePaymentRequestPayload {
            merchant_id: auth.merchant_id.clone(),
            merchant_transaction_id: router_data
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            merchant_user_id: router_data
                .resource_common_data
                .customer_id
                .clone()
                .map(|id| id.get_string_repr().to_string()),
            amount: amount_in_minor_units,
            callback_url: router_data.request.get_webhook_url()?,
            mobile_number,
            payment_instrument,
            device_context,
        };

        // Convert to JSON and encode
        let json_payload = Encode::encode_to_string_of_json(&payload)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;

        // Base64 encode the payload
        let base64_payload = base64::engine::general_purpose::STANDARD.encode(&json_payload);

        // Generate checksum
        let api_path = format!("/{}", constants::API_PAY_ENDPOINT);
        let checksum =
            generate_phonepe_checksum(&base64_payload, &api_path, &auth.salt_key, &auth.key_index)?;

        Ok(Self {
            request: Secret::new(base64_payload),
            checksum,
        })
    }
}

// ===== RESPONSE HANDLING =====

impl
    TryFrom<
        ResponseRouterData<
            PhonepePaymentsResponse,
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        >,
    > for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>
{
    type Error = Error;

    fn try_from(
        item: ResponseRouterData<
            PhonepePaymentsResponse,
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;

        if response.success {
            if let Some(data) = &response.data {
                if let Some(instrument_response) = &data.instrument_response {
                    // Handle different UPI flow responses
                    let (redirect_form, connector_metadata) =
                        match instrument_response.instrument_type.as_str() {
                            instrument_type if instrument_type == constants::UPI_INTENT => {
                                if let Some(intent_url) = &instrument_response.intent_url {
                                    (
                                        Some(RedirectForm::Uri {
                                            uri: intent_url.clone(),
                                        }),
                                        None,
                                    )
                                } else {
                                    (None, None)
                                }
                            }
                            instrument_type if instrument_type == constants::UPI_QR => {
                                if let Some(qr_data) = &instrument_response.qr_data {
                                    // For QR, return the QR data in metadata
                                    let mut metadata = HashMap::new();
                                    metadata.insert(
                                        "qr_data".to_string(),
                                        serde_json::Value::String(qr_data.clone()),
                                    );
                                    (
                                        None,
                                        Some(serde_json::Value::Object(
                                            serde_json::Map::from_iter(metadata),
                                        )),
                                    )
                                } else {
                                    (None, None)
                                }
                            }
                            _ => (None, None),
                        };

                    Ok(Self {
                        response: Ok(PaymentsResponseData::TransactionResponse {
                            resource_id: ResponseId::ConnectorTransactionId(
                                data.merchant_transaction_id.clone(),
                            ),
                            redirection_data: redirect_form.map(Box::new),
                            mandate_reference: None,
                            connector_metadata,
                            network_txn_id: None,
                            connector_response_reference_id: Some(
                                data.merchant_transaction_id.clone(),
                            ),
                            incremental_authorization_allowed: None,
                            raw_connector_response: Some(
                                serde_json::to_string(&item.response).unwrap_or_default(),
                            ),
                            status_code: Some(item.http_code),
                        }),
                        ..item.router_data
                    })
                } else {
                    // Success but no instrument response
                    Ok(Self {
                        response: Ok(PaymentsResponseData::TransactionResponse {
                            resource_id: ResponseId::ConnectorTransactionId(
                                data.merchant_transaction_id.clone(),
                            ),
                            redirection_data: None,
                            mandate_reference: None,
                            connector_metadata: None,
                            network_txn_id: None,
                            connector_response_reference_id: Some(
                                data.merchant_transaction_id.clone(),
                            ),
                            incremental_authorization_allowed: None,
                            raw_connector_response: Some(
                                serde_json::to_string(&item.response).unwrap_or_default(),
                            ),
                            status_code: Some(item.http_code),
                        }),
                        ..item.router_data
                    })
                }
            } else {
                Err(errors::ConnectorError::ResponseDeserializationFailed.into())
            }
        } else {
            // Error response - PhonePe returned success: false
            let error_message = response.message.clone();
            let error_code = response.code.clone();

            // Get merchant transaction ID from data if available for better tracking
            let connector_transaction_id = response
                .data
                .as_ref()
                .map(|data| data.merchant_transaction_id.clone());

            // Map specific PhonePe error codes to attempt status if needed
            let attempt_status = match error_code.as_str() {
                "INVALID_TRANSACTION_ID" => Some(common_enums::AttemptStatus::Failure),
                "TRANSACTION_NOT_FOUND" => Some(common_enums::AttemptStatus::Failure),
                "INVALID_REQUEST" => Some(common_enums::AttemptStatus::Failure),
                "INTERNAL_SERVER_ERROR" => Some(common_enums::AttemptStatus::Failure),
                "PAYMENT_PENDING" => Some(common_enums::AttemptStatus::Pending),
                "PAYMENT_DECLINED" => Some(common_enums::AttemptStatus::Failure),
                _ => Some(common_enums::AttemptStatus::Pending),
            };

            tracing::warn!(
                "PhonePe payment failed - Code: {}, Message: {}, Status: {}",
                error_code,
                error_message,
                item.http_code
            );

            Ok(Self {
                response: Err(domain_types::router_data::ErrorResponse {
                    code: error_code,
                    message: error_message.clone(),
                    reason: Some(error_message),
                    status_code: item.http_code,
                    attempt_status,
                    connector_transaction_id,
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                    raw_connector_response: Some(
                        serde_json::to_string(&item.response).unwrap_or_default(),
                    ),
                }),
                ..item.router_data
            })
        }
    }
}

// ===== AUTHENTICATION =====

#[derive(Debug)]
pub struct PhonepeAuthType {
    pub merchant_id: Secret<String>,
    pub salt_key: Secret<String>,
    pub key_index: String,
}

impl TryFrom<&ConnectorAuthType> for PhonepeAuthType {
    type Error = Error;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey {
                api_key,
                key1,
                api_secret,
            } => Ok(Self {
                merchant_id: api_key.clone(),
                salt_key: key1.clone(),
                key_index: api_secret.peek().clone(), // Use api_secret for key index
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

// ===== HELPER FUNCTIONS =====

fn generate_phonepe_checksum(
    base64_payload: &str,
    api_path: &str,
    salt_key: &Secret<String>,
    key_index: &str,
) -> Result<String, Error> {
    // PhonePe checksum algorithm: SHA256(base64Payload + apiPath + saltKey) + "###" + keyIndex
    let checksum_input = format!("{}{}{}", base64_payload, api_path, salt_key.peek());

    let sha256 = crypto::Sha256;
    let hash_bytes = sha256
        .generate_digest(checksum_input.as_bytes())
        .change_context(errors::ConnectorError::RequestEncodingFailed)?;
    let hash = hash_bytes.iter().fold(String::new(), |mut acc, byte| {
        use std::fmt::Write;
        write!(&mut acc, "{byte:02x}").unwrap();
        acc
    });

    // Format: hash###keyIndex
    Ok(format!(
        "{}{}{}",
        hash,
        constants::CHECKSUM_SEPARATOR,
        key_index
    ))
}
