use base64::Engine;
use common_enums::{enums, AttemptStatus};
use common_utils::errors::CustomResult;
use des::cipher::{BlockEncrypt, KeyInit};
use domain_types::{
    connector_flow::{
        Authorize, Capture, PSync, PostAuthenticate, PreAuthenticate, RSync, Refund, Void,
    },
    connector_types::{
        PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData,
        PaymentsPostAuthenticateData, PaymentsPreAuthenticateData, PaymentsResponseData,
        PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData,
        ResponseId,
    },
    errors,
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes},
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, PeekInterface, Secret};
use ring::hmac;
use serde::Deserialize;

use super::{requests, responses};
use crate::types::ResponseRouterData;

pub use super::requests::{
    RedsysAuthorizeMerchantParams, RedsysOperationMerchantParams, RedsysPostAuthMerchantParams,
    RedsysPreAuthMerchantParams, RedsysTransaction, TransactionType,
};
pub use super::responses::{
    RedsysAuthorizeResponse, RedsysCaptureResponse, RedsysErrorResponse, RedsysPSyncResponse,
    RedsysPostAuthenticateResponse, RedsysPreAuthenticateResponse, RedsysRSyncResponse,
    RedsysRefundResponse, RedsysTransactionResponse, RedsysVoidResponse,
};

// ===== CONSTANTS =====
const SIGNATURE_VERSION: &str = "HMAC_SHA256_V1";
const BASE64_ENGINE: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

// ===== AUTH STRUCTURES =====

#[derive(Debug, Clone, Deserialize)]
pub struct RedsysAuthType {
    pub merchant_code: Secret<String>,
    pub terminal_id: Secret<String>,
    pub secret_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for RedsysAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey {
                api_key,
                key1,
                api_secret,
            } => Ok(Self {
                merchant_code: api_key.clone(),
                terminal_id: key1.clone(),
                secret_key: api_secret.clone(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

// ===== SIGNATURE GENERATION HELPERS =====

pub struct RedsysSignature;

impl RedsysSignature {
    /// Generate 3DES encrypted key from order and secret
    pub fn encrypt_order_with_3des(
        order: &str,
        secret_key: &Secret<String>,
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        // Decode the base64 secret key
        let key_bytes = BASE64_ENGINE
            .decode(secret_key.clone().expose())
            .change_context(errors::ConnectorError::InvalidConnectorConfig {
                config: "secret_key",
            })
            .attach_printable("Failed to decode base64 secret key")?;

        // Ensure key is 24 bytes for 3DES (pad with zeros if needed)
        let mut key_24 = [0u8; 24];
        let key_len = key_bytes.len().min(24);
        key_24[..key_len].copy_from_slice(&key_bytes[..key_len]);

        // Create 3DES cipher
        let cipher = des::TdesEde3::new(&key_24.into());

        // Pad order to 8 bytes (DES block size)
        let mut order_bytes = order.as_bytes().to_vec();
        while order_bytes.len() % 8 != 0 {
            order_bytes.push(0);
        }

        // Encrypt each 8-byte block
        let mut encrypted = Vec::new();
        for chunk in order_bytes.chunks(8) {
            let mut block = des::cipher::Block::<des::TdesEde3>::default();
            block.copy_from_slice(chunk);
            cipher.encrypt_block(&mut block);
            encrypted.extend_from_slice(&block);
        }

        Ok(encrypted)
    }

    /// Calculate HMAC-SHA256 signature
    pub fn calculate_signature(
        merchant_params: &str,
        operation_key: &[u8],
    ) -> CustomResult<String, errors::ConnectorError> {
        let key = hmac::Key::new(hmac::HMAC_SHA256, operation_key);
        let signature = hmac::sign(&key, merchant_params.as_bytes());
        Ok(BASE64_ENGINE.encode(signature.as_ref()))
    }

    /// Generate complete signature for request
    pub fn generate_request_signature(
        merchant_params_json: &str,
        order: &str,
        secret_key: &Secret<String>,
    ) -> CustomResult<String, errors::ConnectorError> {
        // Step 1: Encode merchant parameters to base64
        let merchant_params_b64 = BASE64_ENGINE.encode(merchant_params_json);

        // Step 2: Encrypt order with 3DES
        let operation_key = Self::encrypt_order_with_3des(order, secret_key)?;

        // Step 3: Calculate HMAC-SHA256
        let signature = Self::calculate_signature(&merchant_params_b64, &operation_key)?;

        Ok(signature)
    }

    /// Verify response signature
    pub fn verify_response_signature(
        merchant_params_b64: &str,
        received_signature: &str,
        order: &str,
        secret_key: &Secret<String>,
    ) -> CustomResult<bool, errors::ConnectorError> {
        let operation_key = Self::encrypt_order_with_3des(order, secret_key)?;
        let calculated_signature = Self::calculate_signature(merchant_params_b64, &operation_key)?;
        Ok(calculated_signature == received_signature)
    }
}

// ===== HELPER FUNCTIONS =====

/// Get currency code in ISO 4217 numeric format
fn get_currency_code(currency: enums::Currency) -> CustomResult<String, errors::ConnectorError> {
    let code = match currency {
        enums::Currency::EUR => "978",
        enums::Currency::USD => "840",
        enums::Currency::GBP => "826",
        enums::Currency::JPY => "392",
        enums::Currency::CHF => "756",
        enums::Currency::CAD => "124",
        _ => {
            return Err(errors::ConnectorError::NotSupported {
                message: format!("Currency: {}", currency),
                connector: "Redsys",
            }
            .into())
        }
    };
    Ok(code.to_string())
}

/// Truncate order ID to 12 characters max
fn truncate_order_id(order_id: &str) -> String {
    order_id.chars().take(12).collect()
}

/// Get card expiry in YYMM format
fn get_card_expiry_yymm<T: PaymentMethodDataTypes>(
    card: &domain_types::payment_method_data::Card<T>,
) -> CustomResult<Secret<String>, errors::ConnectorError> {
    let expiry = format!(
        "{}{}",
        card.card_exp_year.peek().get(2..).unwrap_or(""),
        card.card_exp_month.peek()
    );
    Ok(Secret::new(expiry))
}

/// Map Redsys response code to AttemptStatus
pub fn get_attempt_status_from_response_code(response_code: &str) -> AttemptStatus {
    match response_code {
        // Success codes (0000-0099 except 0002)
        code if code.starts_with("00") && code != "0002" => AttemptStatus::Charged,
        // Capture success
        "0900" => AttemptStatus::Charged,
        // Void/Cancel success
        "0400" | "0481" | "0940" | "9915" => AttemptStatus::Voided,
        // Authentication pending
        "0112" | "0195" | "8210" | "8220" | "9998" | "9999" => AttemptStatus::AuthenticationPending,
        // Pending/Processing
        "9997" => AttemptStatus::Pending,
        // All other codes are failures
        _ => AttemptStatus::Failure,
    }
}

/// Determine if response requires customer action (3DS challenge)
pub fn requires_customer_action(response_code: &str) -> bool {
    matches!(response_code, "9999")
}

// ===== TRYFROM IMPLEMENTATIONS FOR REQUESTS =====

// PreAuthenticate Request
impl<T: PaymentMethodDataTypes + serde::Serialize>
    TryFrom<
        &RouterDataV2<
            PreAuthenticate,
            PaymentFlowData,
            PaymentsPreAuthenticateData<T>,
            PaymentsResponseData,
        >,
    > for RedsysTransaction
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<
            PreAuthenticate,
            PaymentFlowData,
            PaymentsPreAuthenticateData<T>,
            PaymentsResponseData,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = RedsysAuthType::try_from(&item.connector_auth_type)?;

        // Extract card data
        let card = match &item.request.payment_method_data {
            Some(PaymentMethodData::Card(card_data)) => card_data,
            _ => {
                return Err(errors::ConnectorError::NotSupported {
                    message: "Payment method".to_string(),
                    connector: "Redsys",
                }
                .into())
            }
        };

        let order_id = truncate_order_id(&item.resource_common_data.connector_request_reference_id);
        let currency_code = get_currency_code(item.request.currency.ok_or(
            errors::ConnectorError::MissingRequiredField {
                field_name: "currency",
            },
        )?)?;
        let amount = item.request.amount.get_amount_as_i64().to_string();

        // Transaction type: Always use 0 (auto-capture) for PreAuthenticate
        let transaction_type = "0";

        // Build merchant parameters
        let merchant_params = requests::RedsysPreAuthMerchantParams {
            ds_merchant_order: order_id.clone(),
            ds_merchant_merchantcode: auth.merchant_code.expose(),
            ds_merchant_terminal: auth.terminal_id.expose(),
            ds_merchant_currency: currency_code,
            ds_merchant_transactiontype: transaction_type.to_string(),
            ds_merchant_amount: amount,
            ds_merchant_pan: Secret::new(card.card_number.peek().to_string()),
            ds_merchant_emv3ds: Some(requests::EmvThreeDsCardData {
                three_d_s_info: requests::ThreeDSInfo::CardData,
            }),
        };

        // Serialize to JSON
        let merchant_params_json = serde_json::to_string(&merchant_params)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;

        // Encode to base64
        let merchant_params_b64 = BASE64_ENGINE.encode(&merchant_params_json);

        // Generate signature
        let signature = RedsysSignature::generate_request_signature(
            &merchant_params_json,
            &order_id,
            &auth.secret_key,
        )?;

        Ok(Self {
            ds_signature_version: SIGNATURE_VERSION.to_string(),
            ds_merchant_parameters: Secret::new(merchant_params_b64),
            ds_signature: Secret::new(signature),
        })
    }
}

// Authorize Request
impl<T: PaymentMethodDataTypes + serde::Serialize>
    TryFrom<
        &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    > for RedsysTransaction
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData<T>,
            PaymentsResponseData,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = RedsysAuthType::try_from(&item.connector_auth_type)?;

        // Extract card data
        let card = match &item.request.payment_method_data {
            PaymentMethodData::Card(card_data) => card_data,
            _ => {
                return Err(errors::ConnectorError::NotSupported {
                    message: "Payment method".to_string(),
                    connector: "Redsys",
                }
                .into())
            }
        };

        let order_id = truncate_order_id(&item.resource_common_data.connector_request_reference_id);
        let currency_code = get_currency_code(item.request.currency)?;
        let amount = item.request.amount.get_amount_as_i64().to_string();

        // Transaction type
        let transaction_type = match item.request.capture_method {
            Some(enums::CaptureMethod::Manual) => "1",
            _ => "0",
        };

        // Get browser info from preprocessing_id (which contains 3DS server trans ID)
        let three_ds_server_trans_id = item.resource_common_data.preprocessing_id.clone();

        // Build browser info (required for 3DS)
        let browser_info = item.request.get_browser_info()?;

        let emv3ds = requests::EmvThreeDsAuthData {
            three_d_s_info: requests::ThreeDSInfo::AuthenticationData,
            protocol_version: Some("2.1.0".to_string()),
            browser_accept_header: browser_info.accept_header.clone(),
            browser_user_agent: browser_info.user_agent.clone(),
            browser_java_enabled: browser_info.java_enabled,
            browser_java_script_enabled: browser_info.java_script_enabled,
            browser_language: browser_info.language.clone(),
            browser_color_depth: browser_info.color_depth.map(|d| d.to_string()),
            browser_screen_height: browser_info.screen_height.map(|h| h.to_string()),
            browser_screen_width: browser_info.screen_width.map(|w| w.to_string()),
            browser_tz: browser_info.time_zone.map(|tz| tz.to_string()),
            three_d_s_server_trans_i_d: three_ds_server_trans_id,
            notification_url: item.request.complete_authorize_url.clone(),
            three_ds_comp_ind: Some("Y".to_string()),
        };

        // Build merchant parameters
        let merchant_params = requests::RedsysAuthorizeMerchantParams {
            ds_merchant_amount: amount,
            ds_merchant_currency: currency_code,
            ds_merchant_order: order_id.clone(),
            ds_merchant_merchantcode: auth.merchant_code.expose(),
            ds_merchant_terminal: auth.terminal_id.expose(),
            ds_merchant_transactiontype: transaction_type.to_string(),
            ds_merchant_pan: card.card_number.clone(),
            ds_merchant_expirydate: get_card_expiry_yymm(card)?,
            ds_merchant_cvv2: Some(card.card_cvc.clone()),
            ds_merchant_emv3ds: emv3ds,
            ds_merchant_merchanturl: item.request.webhook_url.clone(),
            ds_merchant_productdescription: item.resource_common_data.description.clone(),
            ds_merchant_titular: item.resource_common_data.get_optional_billing_full_name(),
        };

        // Serialize to JSON
        let merchant_params_json = serde_json::to_string(&merchant_params)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;

        // Encode to base64
        let merchant_params_b64 = BASE64_ENGINE.encode(&merchant_params_json);

        // Generate signature
        let signature = RedsysSignature::generate_request_signature(
            &merchant_params_json,
            &order_id,
            &auth.secret_key,
        )?;

        Ok(Self {
            ds_signature_version: SIGNATURE_VERSION.to_string(),
            ds_merchant_parameters: Secret::new(merchant_params_b64),
            ds_signature: Secret::new(signature),
        })
    }
}

// PostAuthenticate Request
impl<T: PaymentMethodDataTypes + serde::Serialize>
    TryFrom<
        &RouterDataV2<
            PostAuthenticate,
            PaymentFlowData,
            PaymentsPostAuthenticateData<T>,
            PaymentsResponseData,
        >,
    > for RedsysTransaction
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<
            PostAuthenticate,
            PaymentFlowData,
            PaymentsPostAuthenticateData<T>,
            PaymentsResponseData,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = RedsysAuthType::try_from(&item.connector_auth_type)?;

        // Extract card data from stored payment method data
        let card = match &item.request.payment_method_data {
            Some(PaymentMethodData::Card(card_data)) => card_data,
            _ => {
                return Err(errors::ConnectorError::NotSupported {
                    message: "Payment method".to_string(),
                    connector: "Redsys",
                }
                .into())
            }
        };

        let order_id = truncate_order_id(&item.resource_common_data.connector_request_reference_id);
        let currency_code = get_currency_code(item.request.currency.ok_or(
            errors::ConnectorError::MissingRequiredField {
                field_name: "currency",
            },
        )?)?;
        let amount = item.request.amount.get_amount_as_i64().to_string();

        // Transaction type: Use default auto-capture (0) for PostAuthenticate
        let transaction_type = "0";

        // Extract CRes from redirect_response.params
        let cres = item
            .request
            .redirect_response
            .as_ref()
            .and_then(|r| r.params.as_ref())
            .and_then(|p| {
                // Parse cres parameter from the query string
                p.peek()
                    .split('&')
                    .find(|param| param.starts_with("cres="))
                    .and_then(|param| param.strip_prefix("cres="))
                    .map(|s| s.to_string())
            })
            .ok_or(errors::ConnectorError::MissingRequiredField {
                field_name: "redirect_response.params (cres)",
            })?;

        let emv3ds = requests::EmvThreeDsChallengeResponse {
            three_d_s_info: requests::ThreeDSInfo::ChallengeResponse,
            protocol_version: Some("2.1.0".to_string()),
            cres: Some(cres),
        };

        // Build merchant parameters
        let merchant_params = requests::RedsysPostAuthMerchantParams {
            ds_merchant_order: order_id.clone(),
            ds_merchant_merchantcode: auth.merchant_code.expose(),
            ds_merchant_terminal: auth.terminal_id.expose(),
            ds_merchant_currency: currency_code,
            ds_merchant_transactiontype: transaction_type.to_string(),
            ds_merchant_amount: amount,
            ds_merchant_pan: card.card_number.clone(),
            ds_merchant_expirydate: get_card_expiry_yymm(card)?,
            ds_merchant_cvv2: Some(card.card_cvc.clone()),
            ds_merchant_emv3ds: emv3ds,
        };

        // Serialize to JSON
        let merchant_params_json = serde_json::to_string(&merchant_params)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;

        // Encode to base64
        let merchant_params_b64 = BASE64_ENGINE.encode(&merchant_params_json);

        // Generate signature
        let signature = RedsysSignature::generate_request_signature(
            &merchant_params_json,
            &order_id,
            &auth.secret_key,
        )?;

        Ok(Self {
            ds_signature_version: SIGNATURE_VERSION.to_string(),
            ds_merchant_parameters: Secret::new(merchant_params_b64),
            ds_signature: Secret::new(signature),
        })
    }
}

// Capture Request
impl TryFrom<&RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>>
    for RedsysTransaction
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let auth = RedsysAuthType::try_from(&item.connector_auth_type)?;

        let order_id = truncate_order_id(&item.resource_common_data.connector_request_reference_id);
        let currency_code = get_currency_code(item.request.currency)?;
        let amount = item
            .request
            .minor_amount_to_capture
            .get_amount_as_i64()
            .to_string();

        let merchant_params = requests::RedsysOperationMerchantParams {
            ds_merchant_amount: amount,
            ds_merchant_currency: currency_code,
            ds_merchant_order: order_id.clone(),
            ds_merchant_merchantcode: auth.merchant_code.expose(),
            ds_merchant_terminal: auth.terminal_id.expose(),
            ds_merchant_transactiontype: "2".to_string(), // Confirmation
        };

        let merchant_params_json = serde_json::to_string(&merchant_params)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;

        let merchant_params_b64 = BASE64_ENGINE.encode(&merchant_params_json);

        let signature = RedsysSignature::generate_request_signature(
            &merchant_params_json,
            &order_id,
            &auth.secret_key,
        )?;

        Ok(Self {
            ds_signature_version: SIGNATURE_VERSION.to_string(),
            ds_merchant_parameters: Secret::new(merchant_params_b64),
            ds_signature: Secret::new(signature),
        })
    }
}

// Void Request
impl TryFrom<&RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>>
    for RedsysTransaction
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let auth = RedsysAuthType::try_from(&item.connector_auth_type)?;

        let order_id = truncate_order_id(&item.resource_common_data.connector_request_reference_id);

        // Extract amount and currency from Option types
        let amount_value =
            item.request
                .amount
                .ok_or(errors::ConnectorError::MissingRequiredField {
                    field_name: "amount",
                })?;
        let currency =
            item.request
                .currency
                .ok_or(errors::ConnectorError::MissingRequiredField {
                    field_name: "currency",
                })?;

        let currency_code = get_currency_code(currency)?;
        let amount = amount_value.get_amount_as_i64().to_string();

        let merchant_params = requests::RedsysOperationMerchantParams {
            ds_merchant_amount: amount,
            ds_merchant_currency: currency_code,
            ds_merchant_order: order_id.clone(),
            ds_merchant_merchantcode: auth.merchant_code.expose(),
            ds_merchant_terminal: auth.terminal_id.expose(),
            ds_merchant_transactiontype: "9".to_string(), // Cancellation
        };

        let merchant_params_json = serde_json::to_string(&merchant_params)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;

        let merchant_params_b64 = BASE64_ENGINE.encode(&merchant_params_json);

        let signature = RedsysSignature::generate_request_signature(
            &merchant_params_json,
            &order_id,
            &auth.secret_key,
        )?;

        Ok(Self {
            ds_signature_version: SIGNATURE_VERSION.to_string(),
            ds_merchant_parameters: Secret::new(merchant_params_b64),
            ds_signature: Secret::new(signature),
        })
    }
}

// Refund Request
impl TryFrom<&RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>>
    for RedsysTransaction
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> Result<Self, Self::Error> {
        let auth = RedsysAuthType::try_from(&item.connector_auth_type)?;

        let order_id = truncate_order_id(&item.resource_common_data.connector_request_reference_id);
        let currency_code = get_currency_code(item.request.currency)?;
        let amount = item
            .request
            .minor_refund_amount
            .get_amount_as_i64()
            .to_string();

        let merchant_params = requests::RedsysOperationMerchantParams {
            ds_merchant_amount: amount,
            ds_merchant_currency: currency_code,
            ds_merchant_order: order_id.clone(),
            ds_merchant_merchantcode: auth.merchant_code.expose(),
            ds_merchant_terminal: auth.terminal_id.expose(),
            ds_merchant_transactiontype: "3".to_string(), // Refund
        };

        let merchant_params_json = serde_json::to_string(&merchant_params)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;

        let merchant_params_b64 = BASE64_ENGINE.encode(&merchant_params_json);

        let signature = RedsysSignature::generate_request_signature(
            &merchant_params_json,
            &order_id,
            &auth.secret_key,
        )?;

        Ok(Self {
            ds_signature_version: SIGNATURE_VERSION.to_string(),
            ds_merchant_parameters: Secret::new(merchant_params_b64),
            ds_signature: Secret::new(signature),
        })
    }
}

// ===== TRYFROM IMPLEMENTATIONS FOR RESPONSES =====

// PreAuthenticate Response
impl<T: PaymentMethodDataTypes>
    TryFrom<
        ResponseRouterData<
            RedsysPreAuthenticateResponse,
            RouterDataV2<
                PreAuthenticate,
                PaymentFlowData,
                PaymentsPreAuthenticateData<T>,
                PaymentsResponseData,
            >,
        >,
    >
    for RouterDataV2<
        PreAuthenticate,
        PaymentFlowData,
        PaymentsPreAuthenticateData<T>,
        PaymentsResponseData,
    >
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            RedsysPreAuthenticateResponse,
            RouterDataV2<
                PreAuthenticate,
                PaymentFlowData,
                PaymentsPreAuthenticateData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        // Decode merchant parameters
        let merchant_params_decoded = BASE64_ENGINE
            .decode(item.response.ds_merchant_parameters.expose())
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        let merchant_params_str = String::from_utf8(merchant_params_decoded)
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        let params: responses::RedsysPreAuthResponseParams =
            serde_json::from_str(&merchant_params_str)
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        // Extract 3DS server transaction ID from EMV3DS
        let preprocessing_id = params
            .ds_emv3ds
            .as_ref()
            .and_then(|emv| emv.three_d_s_server_trans_i_d.clone());

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::NoResponseId,
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(params.ds_order.clone()),
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            resource_common_data: PaymentFlowData {
                status: AttemptStatus::AuthenticationPending,
                preprocessing_id,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

// Authorize Response
impl<T: PaymentMethodDataTypes>
    TryFrom<
        ResponseRouterData<
            RedsysAuthorizeResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    > for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            RedsysAuthorizeResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        // Decode merchant parameters
        let merchant_params_decoded = BASE64_ENGINE
            .decode(item.response.ds_merchant_parameters.expose())
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        let merchant_params_str = String::from_utf8(merchant_params_decoded)
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        let params: responses::RedsysPaymentResponseParams =
            serde_json::from_str(&merchant_params_str)
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        let status = get_attempt_status_from_response_code(&params.ds_response);

        // Check if challenge is required
        let redirection_data = if requires_customer_action(&params.ds_response) {
            params.ds_emv3ds.as_ref().and_then(|emv| {
                emv.acs_url.as_ref().and_then(|acs_url| {
                    emv.creq.as_ref().map(|creq| {
                        Box::new(domain_types::router_response_types::RedirectForm::Form {
                            endpoint: acs_url.clone(),
                            method: common_utils::request::Method::Post,
                            form_fields: std::collections::HashMap::from([(
                                "creq".to_string(),
                                creq.clone(),
                            )]),
                        })
                    })
                })
            })
        } else {
            None
        };

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(params.ds_order.clone()),
                redirection_data,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(params.ds_order.clone()),
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

// PostAuthenticate Response
impl<T: PaymentMethodDataTypes>
    TryFrom<
        ResponseRouterData<
            RedsysPostAuthenticateResponse,
            RouterDataV2<
                PostAuthenticate,
                PaymentFlowData,
                PaymentsPostAuthenticateData<T>,
                PaymentsResponseData,
            >,
        >,
    >
    for RouterDataV2<
        PostAuthenticate,
        PaymentFlowData,
        PaymentsPostAuthenticateData<T>,
        PaymentsResponseData,
    >
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            RedsysPostAuthenticateResponse,
            RouterDataV2<
                PostAuthenticate,
                PaymentFlowData,
                PaymentsPostAuthenticateData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        // Decode merchant parameters
        let merchant_params_decoded = BASE64_ENGINE
            .decode(item.response.ds_merchant_parameters.expose())
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        let merchant_params_str = String::from_utf8(merchant_params_decoded)
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        let params: responses::RedsysPaymentResponseParams =
            serde_json::from_str(&merchant_params_str)
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        let status = get_attempt_status_from_response_code(&params.ds_response);

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(params.ds_order.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(params.ds_order.clone()),
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

// PSync Response
impl
    TryFrom<
        ResponseRouterData<
            RedsysPSyncResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    > for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            RedsysPSyncResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let merchant_params_decoded = BASE64_ENGINE
            .decode(item.response.ds_merchant_parameters.expose())
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        let merchant_params_str = String::from_utf8(merchant_params_decoded)
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        let params: responses::RedsysPaymentResponseParams =
            serde_json::from_str(&merchant_params_str)
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        let status = get_attempt_status_from_response_code(&params.ds_response);

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(params.ds_order.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(params.ds_order.clone()),
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

// Capture Response
impl
    TryFrom<
        ResponseRouterData<
            RedsysCaptureResponse,
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    > for RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            RedsysCaptureResponse,
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let merchant_params_decoded = BASE64_ENGINE
            .decode(item.response.ds_merchant_parameters.expose())
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        let merchant_params_str = String::from_utf8(merchant_params_decoded)
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        let params: responses::RedsysOperationResponseParams =
            serde_json::from_str(&merchant_params_str)
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        let status = get_attempt_status_from_response_code(&params.ds_response);

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(params.ds_order.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(params.ds_order.clone()),
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

// Void Response
impl
    TryFrom<
        ResponseRouterData<
            RedsysVoidResponse,
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        >,
    > for RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            RedsysVoidResponse,
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let merchant_params_decoded = BASE64_ENGINE
            .decode(item.response.ds_merchant_parameters.expose())
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        let merchant_params_str = String::from_utf8(merchant_params_decoded)
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        let params: responses::RedsysOperationResponseParams =
            serde_json::from_str(&merchant_params_str)
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        let status = get_attempt_status_from_response_code(&params.ds_response);

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(params.ds_order.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(params.ds_order.clone()),
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

// Refund Response
impl
    TryFrom<
        ResponseRouterData<
            RedsysRefundResponse,
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    > for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            RedsysRefundResponse,
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let merchant_params_decoded = BASE64_ENGINE
            .decode(item.response.ds_merchant_parameters.expose())
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        let merchant_params_str = String::from_utf8(merchant_params_decoded)
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        let params: responses::RedsysOperationResponseParams =
            serde_json::from_str(&merchant_params_str)
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        let status = match get_attempt_status_from_response_code(&params.ds_response) {
            AttemptStatus::Charged => enums::RefundStatus::Success,
            AttemptStatus::Pending => enums::RefundStatus::Pending,
            _ => enums::RefundStatus::Failure,
        };

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: params.ds_order.clone(),
                refund_status: status,
                status_code: item.http_code,
            }),
            resource_common_data: RefundFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

// RSync Response
impl
    TryFrom<
        ResponseRouterData<
            RedsysRSyncResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    > for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            RedsysRSyncResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let merchant_params_decoded = BASE64_ENGINE
            .decode(item.response.ds_merchant_parameters.expose())
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        let merchant_params_str = String::from_utf8(merchant_params_decoded)
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        let params: responses::RedsysOperationResponseParams =
            serde_json::from_str(&merchant_params_str)
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        let status = match get_attempt_status_from_response_code(&params.ds_response) {
            AttemptStatus::Charged => enums::RefundStatus::Success,
            AttemptStatus::Pending => enums::RefundStatus::Pending,
            _ => enums::RefundStatus::Failure,
        };

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: params.ds_order.clone(),
                refund_status: status,
                status_code: item.http_code,
            }),
            resource_common_data: RefundFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}
