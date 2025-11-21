// Redsys Transformers - Request/Response Transformations
//
// This file contains all TryFrom implementations and helper functions for transforming
// between Hyperswitch router data and Redsys connector requests/responses.

use base64::Engine;
use common_enums::{AttemptStatus, RefundStatus};
use common_utils::{crypto::SignMessage, errors::CustomResult};
use domain_types::{
    connector_types::{
        PaymentFlowData, PaymentVoidData, PaymentsAuthenticateData, PaymentsAuthorizeData,
        PaymentsCaptureData, PaymentsPostAuthenticateData, PaymentsResponseData, PaymentsSyncData,
        RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData, ResponseId,
    },
    errors,
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes},
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
};
use error_stack::ResultExt;
use hyperswitch_masking::PeekInterface;

use super::{
    requests::*,
    responses::*,
};
use crate::{
    connectors::redsys::{BASE64_ENGINE, SIGNATURE_VERSION, RedsysRouterData},
    types::ResponseRouterData,
};

// ============================================================================
// AUTHENTICATION TYPE CONVERSION
// ============================================================================

impl TryFrom<&ConnectorAuthType> for RedsysAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey {
                api_key,
                key1,
                api_secret,
            } => Ok(Self {
                merchant_id: api_key.clone(),
                terminal_id: key1.clone(),
                sha256_pwd: api_secret.clone(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/// Convert Currency enum to ISO 4217 numeric code for Redsys
fn get_currency_numeric_code(
    currency: common_enums::Currency,
) -> CustomResult<String, errors::ConnectorError> {
    use common_enums::Currency;

    let numeric_code = match currency {
        Currency::EUR => "978",
        Currency::USD => "840",
        Currency::GBP => "826",
        Currency::JPY => "392",
        Currency::CHF => "756",
        Currency::CAD => "124",
        Currency::AUD => "036",
        Currency::NZD => "554",
        Currency::SEK => "752",
        Currency::NOK => "578",
        Currency::DKK => "208",
        Currency::PLN => "985",
        Currency::CZK => "203",
        Currency::HUF => "348",
        Currency::RON => "946",
        Currency::BGN => "975",
        Currency::HRK => "191",
        Currency::RUB => "643",
        Currency::TRY => "949",
        Currency::BRL => "986",
        Currency::CNY => "156",
        Currency::HKD => "344",
        Currency::INR => "356",
        Currency::IDR => "360",
        Currency::ILS => "376",
        Currency::MYR => "458",
        Currency::MXN => "484",
        Currency::NIO => "558",
        Currency::PHP => "608",
        Currency::SGD => "702",
        Currency::KRW => "410",
        Currency::THB => "764",
        Currency::VND => "704",
        Currency::ZAR => "710",
        Currency::AED => "784",
        Currency::SAR => "682",
        Currency::QAR => "634",
        Currency::KWD => "414",
        Currency::BHD => "048",
        Currency::OMR => "512",
        Currency::JOD => "400",
        Currency::EGP => "818",
        Currency::MAD => "504",
        Currency::COP => "170",
        Currency::PEN => "604",
        Currency::CLP => "152",
        Currency::ARS => "032",
        Currency::UYU => "858",
        _ => {
            return Err(errors::ConnectorError::NotSupported {
                message: format!("Currency {} not supported by Redsys", currency),
                connector: "Redsys",
            }
            .into())
        }
    };

    Ok(numeric_code.to_string())
}

/// Get response status from Ds_Response code
pub fn get_payment_status(response_code: &str) -> AttemptStatus {
    let code = response_code.parse::<i32>().unwrap_or(9999);

    match code {
        0..=99 => AttemptStatus::Charged, // 0000-0099: Authorized
        900 => AttemptStatus::Charged,    // 0900: Refund/Confirmation authorized
        400 => AttemptStatus::Voided,     // 0400: Cancellation authorized
        9999 => AttemptStatus::AuthenticationPending, // 9999: Challenge required
        9998 => AttemptStatus::Pending,   // 9998: Operation in progress
        _ => AttemptStatus::Failure,
    }
}

pub fn get_refund_status(response_code: &str) -> RefundStatus {
    let code = response_code.parse::<i32>().unwrap_or(9999);

    match code {
        900 => RefundStatus::Success,
        9998 => RefundStatus::Pending,
        _ => RefundStatus::Failure,
    }
}

// ============================================================================
// SIGNATURE GENERATION
// ============================================================================

/// Generate 3DES encryption key from order ID and merchant secret
fn generate_3des_key(
    order_id: &str,
    secret_key: &str,
) -> CustomResult<Vec<u8>, errors::ConnectorError> {
    use des::cipher::{BlockEncrypt, KeyInit};
    use des::TdesEde3;

    // Decode the Base64 secret key
    let key_bytes = BASE64_ENGINE
        .decode(secret_key)
        .change_context(errors::ConnectorError::RequestEncodingFailed)?;

    // Create 3DES cipher
    let cipher = TdesEde3::new_from_slice(&key_bytes)
        .change_context(errors::ConnectorError::RequestEncodingFailed)?;

    // Pad order ID to 8 bytes (DES block size)
    let mut order_bytes = order_id.as_bytes().to_vec();
    while order_bytes.len() % 8 != 0 {
        order_bytes.push(0);
    }

    // Encrypt in blocks
    let mut encrypted = Vec::new();
    for chunk in order_bytes.chunks(8) {
        let mut block = des::cipher::Block::<TdesEde3>::clone_from_slice(chunk);
        cipher.encrypt_block(&mut block);
        encrypted.extend_from_slice(&block);
    }

    Ok(encrypted)
}

/// Generate HMAC-SHA256 signature for Redsys request
pub fn generate_signature(
    order_id: &str,
    merchant_params_b64: &str,
    secret_key: &str,
) -> CustomResult<String, errors::ConnectorError> {
    use common_utils::crypto;

    // Generate 3DES encryption key
    let operation_key = generate_3des_key(order_id, secret_key)?;

    // Calculate HMAC-SHA256
    let signature = crypto::HmacSha256::sign_message(
        &crypto::HmacSha256,
        &operation_key,
        merchant_params_b64.as_bytes(),
    )
    .change_context(errors::ConnectorError::RequestEncodingFailed)?;

    // Base64 encode the signature
    Ok(BASE64_ENGINE.encode(signature))
}

/// Create RedsysTransaction wrapper with signature
pub fn create_redsys_transaction<T: serde::Serialize>(
    params: &T,
    auth: &RedsysAuthType,
    order_id: &str,
) -> CustomResult<RedsysTransaction, errors::ConnectorError> {
    // Serialize and Base64 encode parameters
    let params_json = serde_json::to_string(params)
        .change_context(errors::ConnectorError::RequestEncodingFailed)?;
    let merchant_parameters = BASE64_ENGINE.encode(params_json);

    // Generate signature
    let signature = generate_signature(order_id, &merchant_parameters, &auth.sha256_pwd.peek())?;

    Ok(RedsysTransaction {
        ds_signature_version: SIGNATURE_VERSION.to_string(),
        ds_merchant_parameters: merchant_parameters,
        ds_signature: signature,
    })
}

/// Decode and parse Redsys response parameters
pub fn decode_response_params<T: serde::de::DeserializeOwned>(
    response: &RedsysTransactionResponse,
) -> CustomResult<T, errors::ConnectorError> {
    // Decode Base64 merchant parameters
    let params_json = BASE64_ENGINE
        .decode(&response.ds_merchant_parameters)
        .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

    // Parse JSON
    serde_json::from_slice(&params_json)
        .change_context(errors::ConnectorError::ResponseDeserializationFailed)
}

// ============================================================================
// TRYFROM IMPLEMENTATIONS - REQUEST TRANSFORMATIONS
// ============================================================================

// Authenticate Flow - 3DS Method Invocation (iniciaPeticionREST)
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    >
    TryFrom<
        RedsysRouterData<
            RouterDataV2<
                domain_types::connector_flow::Authenticate,
                PaymentFlowData,
                PaymentsAuthenticateData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for RedsysTransaction
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        wrapper: RedsysRouterData<
            RouterDataV2<
                domain_types::connector_flow::Authenticate,
                PaymentFlowData,
                PaymentsAuthenticateData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let item = &wrapper.router_data;
        let auth = RedsysAuthType::try_from(&item.connector_auth_type)?;

        // Extract card data from optional payment method data
        let payment_method_data = item.request.payment_method_data.clone().ok_or(
            errors::ConnectorError::MissingRequiredField {
                field_name: "payment_method_data",
            },
        )?;

        let card = match payment_method_data {
            PaymentMethodData::Card(card_data) => Ok(card_data),
            _ => Err(errors::ConnectorError::NotSupported {
                message: "Payment method not supported".to_string(),
                connector: "Redsys",
            }),
        }?;

        // Generate order ID from connector_request_reference_id (max 12 chars)
        let order_id = item
            .resource_common_data
            .connector_request_reference_id
            .clone();

        // Get currency (optional in Authenticate flow)
        let currency =
            item.request
                .currency
                .ok_or(errors::ConnectorError::MissingRequiredField {
                    field_name: "currency",
                })?;

        // Build request parameters
        let params = RedsysAuthenticateRequestParams {
            ds_merchant_order: order_id.clone(),
            ds_merchant_merchantcode: auth.merchant_id.peek().to_string(),
            ds_merchant_terminal: auth.terminal_id.peek().to_string(),
            ds_merchant_currency: get_currency_numeric_code(currency)?,
            ds_merchant_transactiontype: "0".to_string(), // 0 = payment
            ds_merchant_amount: item.request.amount.to_string(),
            ds_merchant_pan: card.card_number.peek().to_string(),
            ds_merchant_emv3ds: Some(RedsysEmv3DSRequest {
                three_ds_info: "CardData".to_string(),
                protocol_version: None,
                browser_accept_header: None,
                browser_user_agent: None,
                browser_java_enabled: None,
                browser_javascript_enabled: None,
                browser_language: None,
                browser_color_depth: None,
                browser_screen_height: None,
                browser_screen_width: None,
                browser_tz: None,
                three_ds_server_trans_id: None,
                notification_url: None,
                three_ds_comp_ind: Some("Y".to_string()),
                cres: None,
            }),
            ds_merchant_excep_sca: Some("Y".to_string()),
        };

        create_redsys_transaction(&params, &auth, &order_id)
    }
}

// PostAuthenticate Flow - Authorization after 3DS Method (trataPeticionREST)
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    >
    TryFrom<
        RedsysRouterData<
            RouterDataV2<
                domain_types::connector_flow::PostAuthenticate,
                PaymentFlowData,
                PaymentsPostAuthenticateData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for RedsysTransaction
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        wrapper: RedsysRouterData<
            RouterDataV2<
                domain_types::connector_flow::PostAuthenticate,
                PaymentFlowData,
                PaymentsPostAuthenticateData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let item = &wrapper.router_data;
        let auth = RedsysAuthType::try_from(&item.connector_auth_type)?;

        // Extract card data from optional payment method data
        let payment_method_data = item.request.payment_method_data.clone().ok_or(
            errors::ConnectorError::MissingRequiredField {
                field_name: "payment_method_data",
            },
        )?;

        let card = match payment_method_data {
            PaymentMethodData::Card(card_data) => Ok(card_data),
            _ => Err(errors::ConnectorError::NotSupported {
                message: "Payment method not supported".to_string(),
                connector: "Redsys",
            }),
        }?;

        let order_id = item
            .resource_common_data
            .connector_request_reference_id
            .clone();

        // Get currency (optional in PostAuthenticate flow)
        let currency =
            item.request
                .currency
                .ok_or(errors::ConnectorError::MissingRequiredField {
                    field_name: "currency",
                })?;

        // Get threeDSServerTransID from connector metadata
        let three_ds_server_trans_id = item
            .resource_common_data
            .connector_meta_data
            .as_ref()
            .and_then(|meta| {
                meta.peek()
                    .as_object()
                    .and_then(|obj| obj.get("threeDSServerTransID"))
                    .and_then(|v| v.as_str())
                    .map(String::from)
            });

        let params = RedsysPostAuthenticateRequestParams {
            ds_merchant_amount: item.request.amount.to_string(),
            ds_merchant_currency: get_currency_numeric_code(currency)?,
            ds_merchant_order: order_id.clone(),
            ds_merchant_merchantcode: auth.merchant_id.peek().to_string(),
            ds_merchant_terminal: auth.terminal_id.peek().to_string(),
            ds_merchant_transactiontype: "0".to_string(),
            ds_merchant_pan: card.card_number.peek().to_string(),
            ds_merchant_expirydate: format!(
                "{}{}",
                &card.card_exp_year.peek()[2..],
                card.card_exp_month.peek()
            ),
            ds_merchant_cvv2: Some(card.card_cvc.peek().to_string()),
            ds_merchant_emv3ds: RedsysEmv3DSRequest {
                three_ds_info: "AuthenticationData".to_string(),
                protocol_version: Some("2.1.0".to_string()),
                browser_accept_header: item
                    .request
                    .browser_info
                    .as_ref()
                    .and_then(|b| b.accept_header.clone()),
                browser_user_agent: item
                    .request
                    .browser_info
                    .as_ref()
                    .and_then(|b| b.user_agent.clone()),
                browser_java_enabled: item
                    .request
                    .browser_info
                    .as_ref()
                    .and_then(|b| b.java_enabled),
                browser_javascript_enabled: item.request.browser_info.as_ref().map(|_| true),
                browser_language: item
                    .request
                    .browser_info
                    .as_ref()
                    .and_then(|b| b.language.clone()),
                browser_color_depth: item
                    .request
                    .browser_info
                    .as_ref()
                    .and_then(|b| b.color_depth.map(|d| d.to_string())),
                browser_screen_height: item
                    .request
                    .browser_info
                    .as_ref()
                    .and_then(|b| b.screen_height.map(|h| h.to_string())),
                browser_screen_width: item
                    .request
                    .browser_info
                    .as_ref()
                    .and_then(|b| b.screen_width.map(|w| w.to_string())),
                browser_tz: item
                    .request
                    .browser_info
                    .as_ref()
                    .and_then(|b| b.time_zone.map(|tz| tz.to_string())),
                three_ds_server_trans_id,
                notification_url: item
                    .request
                    .continue_redirection_url
                    .as_ref()
                    .map(|url| url.to_string()),
                three_ds_comp_ind: Some("Y".to_string()),
                cres: None,
            },
            ds_merchant_merchanturl: item.resource_common_data.return_url.clone(),
            ds_merchant_productdescription: item.resource_common_data.description.clone(),
            ds_merchant_titular: None,
        };

        create_redsys_transaction(&params, &auth, &order_id)
    }
}

// Authorize Flow - Complete Authorization after Challenge (trataPeticionREST with cres)
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    >
    TryFrom<
        RedsysRouterData<
            RouterDataV2<
                domain_types::connector_flow::Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for RedsysTransaction
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        wrapper: RedsysRouterData<
            RouterDataV2<
                domain_types::connector_flow::Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let item = &wrapper.router_data;
        let auth = RedsysAuthType::try_from(&item.connector_auth_type)?;

        // For Authorize, payment_method_data is NOT optional
        let card = match &item.request.payment_method_data {
            PaymentMethodData::Card(card_data) => Ok(card_data.clone()),
            _ => Err(errors::ConnectorError::NotSupported {
                message: "Payment method not supported".to_string(),
                connector: "Redsys",
            }),
        }?;

        let order_id = item
            .resource_common_data
            .connector_request_reference_id
            .clone();

        // Get cres from authentication_data
        let cres = item
            .request
            .authentication_data
            .as_ref()
            .and_then(|auth_data| {
                auth_data
                    .acs_transaction_id
                    .as_ref()
                    .map(|id| id.to_string())
            });

        let params = RedsysAuthorizeRequestParams {
            ds_merchant_order: order_id.clone(),
            ds_merchant_merchantcode: auth.merchant_id.peek().to_string(),
            ds_merchant_terminal: auth.terminal_id.peek().to_string(),
            ds_merchant_currency: get_currency_numeric_code(item.request.currency)?,
            ds_merchant_transactiontype: "0".to_string(),
            ds_merchant_amount: item.request.amount.to_string(),
            ds_merchant_pan: card.card_number.peek().to_string(),
            ds_merchant_expirydate: format!(
                "{}{}",
                &card.card_exp_year.peek()[2..],
                card.card_exp_month.peek()
            ),
            ds_merchant_cvv2: Some(card.card_cvc.peek().to_string()),
            ds_merchant_emv3ds: RedsysEmv3DSRequest {
                three_ds_info: "ChallengeResponse".to_string(),
                protocol_version: Some("2.1.0".to_string()),
                browser_accept_header: None,
                browser_user_agent: None,
                browser_java_enabled: None,
                browser_javascript_enabled: None,
                browser_language: None,
                browser_color_depth: None,
                browser_screen_height: None,
                browser_screen_width: None,
                browser_tz: None,
                three_ds_server_trans_id: None,
                notification_url: None,
                three_ds_comp_ind: None,
                cres,
            },
        };

        create_redsys_transaction(&params, &auth, &order_id)
    }
}

// Capture Flow
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    >
    TryFrom<
        RedsysRouterData<
            RouterDataV2<
                domain_types::connector_flow::Capture,
                PaymentFlowData,
                PaymentsCaptureData,
                PaymentsResponseData,
            >,
            T,
        >,
    > for RedsysTransaction
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        wrapper: RedsysRouterData<
            RouterDataV2<
                domain_types::connector_flow::Capture,
                PaymentFlowData,
                PaymentsCaptureData,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let item = &wrapper.router_data;
        let auth = RedsysAuthType::try_from(&item.connector_auth_type)?;

        // Extract order ID from ResponseId
        let order_id = match &item.request.connector_transaction_id {
            ResponseId::ConnectorTransactionId(id) => id.clone(),
            _ => return Err(errors::ConnectorError::MissingConnectorTransactionID.into()),
        };

        let params = RedysCaptureRequestParams {
            ds_merchant_amount: item.request.minor_amount_to_capture.to_string(),
            ds_merchant_currency: get_currency_numeric_code(item.request.currency)?,
            ds_merchant_order: order_id.clone(),
            ds_merchant_merchantcode: auth.merchant_id.peek().to_string(),
            ds_merchant_terminal: auth.terminal_id.peek().to_string(),
            ds_merchant_transactiontype: "2".to_string(), // 2 = capture
        };

        create_redsys_transaction(&params, &auth, &order_id)
    }
}

// Void Flow
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    >
    TryFrom<
        RedsysRouterData<
            RouterDataV2<
                domain_types::connector_flow::Void,
                PaymentFlowData,
                PaymentVoidData,
                PaymentsResponseData,
            >,
            T,
        >,
    > for RedsysTransaction
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        wrapper: RedsysRouterData<
            RouterDataV2<
                domain_types::connector_flow::Void,
                PaymentFlowData,
                PaymentVoidData,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let item = &wrapper.router_data;
        let auth = RedsysAuthType::try_from(&item.connector_auth_type)?;
        let order_id = item.request.connector_transaction_id.clone();

        // Amount and currency are optional for void
        let amount = item
            .request
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

        let params = RedsysVoidRequestParams {
            ds_merchant_amount: amount.to_string(),
            ds_merchant_currency: get_currency_numeric_code(currency)?,
            ds_merchant_order: order_id.clone(),
            ds_merchant_merchantcode: auth.merchant_id.peek().to_string(),
            ds_merchant_terminal: auth.terminal_id.peek().to_string(),
            ds_merchant_transactiontype: "9".to_string(), // 9 = cancellation
        };

        create_redsys_transaction(&params, &auth, &order_id)
    }
}

// Refund Flow
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    >
    TryFrom<
        RedsysRouterData<
            RouterDataV2<
                domain_types::connector_flow::Refund,
                RefundFlowData,
                RefundsData,
                RefundsResponseData,
            >,
            T,
        >,
    > for RedsysTransaction
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        wrapper: RedsysRouterData<
            RouterDataV2<
                domain_types::connector_flow::Refund,
                RefundFlowData,
                RefundsData,
                RefundsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let item = &wrapper.router_data;
        let auth = RedsysAuthType::try_from(&item.connector_auth_type)?;
        let order_id = item.request.connector_transaction_id.clone();

        let params = RedsysRefundRequestParams {
            ds_merchant_amount: item.request.minor_refund_amount.to_string(),
            ds_merchant_currency: get_currency_numeric_code(item.request.currency)?,
            ds_merchant_order: order_id.clone(),
            ds_merchant_merchantcode: auth.merchant_id.peek().to_string(),
            ds_merchant_terminal: auth.terminal_id.peek().to_string(),
            ds_merchant_transactiontype: "3".to_string(), // 3 = refund
            ds_merchant_authorisationcode: None,
            ds_merchant_transactiondate: None,
        };

        create_redsys_transaction(&params, &auth, &order_id)
    }
}

// ============================================================================
// TRYFROM IMPLEMENTATIONS - RESPONSE TRANSFORMATIONS
// ============================================================================

// Response transformation for Authenticate flow
impl<F, T> TryFrom<ResponseRouterData<RedsysResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsAuthenticateData<T>, PaymentsResponseData>
where
    T: PaymentMethodDataTypes,
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: ResponseRouterData<RedsysResponse, Self>) -> Result<Self, Self::Error> {
        match item.response {
            RedsysResponse::Success(response) => {
                let params: RedsysAuthenticateResponseParams = decode_response_params(&response)?;

                Ok(Self {
                    response: Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::NoResponseId,
                        redirection_data: None,
                        mandate_reference: None,
                        connector_metadata: Some(serde_json::json!({
                            "threeDSServerTransID": params.ds_emv3ds.and_then(|e| e.three_ds_server_trans_id)
                        })),
                        network_txn_id: None,
                        connector_response_reference_id: Some(params.ds_order.clone()),
                        incremental_authorization_allowed: None,
                        status_code: item.http_code,
                    }),
                    ..item.router_data
                })
            }
            RedsysResponse::Error(_) => {
                Err(errors::ConnectorError::ResponseDeserializationFailed.into())
            }
        }
    }
}

// Response transformation for PostAuthenticate and Authorize flows
impl<F, T> TryFrom<ResponseRouterData<RedsysResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsPostAuthenticateData<T>, PaymentsResponseData>
where
    T: PaymentMethodDataTypes,
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: ResponseRouterData<RedsysResponse, Self>) -> Result<Self, Self::Error> {
        match item.response {
            RedsysResponse::Success(response) => {
                let params: RedsysPostAuthenticateResponseParams =
                    decode_response_params(&response)?;

                // Check if challenge is required
                let redirection_data = if let Some(emv3ds) = &params.ds_emv3ds {
                    if let (Some(acs_url), Some(creq)) = (&emv3ds.acs_url, &emv3ds.creq) {
                        Some(Box::new(RedirectForm::Form {
                            endpoint: acs_url.clone(),
                            method: common_utils::request::Method::Post,
                            form_fields: std::collections::HashMap::from([("creq".to_string(), creq.clone())]),
                        }))
                    } else {
                        None
                    }
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
                        connector_response_reference_id: params.ds_authorisation_code.clone(),
                        incremental_authorization_allowed: None,
                        status_code: item.http_code,
                    }),
                    ..item.router_data
                })
            }
            RedsysResponse::Error(_) => {
                Err(errors::ConnectorError::ResponseDeserializationFailed.into())
            }
        }
    }
}

// Similar implementation for Authorize
impl<F, T> TryFrom<ResponseRouterData<RedsysResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
where
    T: PaymentMethodDataTypes,
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: ResponseRouterData<RedsysResponse, Self>) -> Result<Self, Self::Error> {
        match item.response {
            RedsysResponse::Success(response) => {
                let params: RedsysAuthorizeResponseParams = decode_response_params(&response)?;

                Ok(Self {
                    response: Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(params.ds_order.clone()),
                        redirection_data: None,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: None,
                        connector_response_reference_id: params.ds_authorisation_code.clone(),
                        incremental_authorization_allowed: None,
                        status_code: item.http_code,
                    }),
                    ..item.router_data
                })
            }
            RedsysResponse::Error(_) => {
                Err(errors::ConnectorError::ResponseDeserializationFailed.into())
            }
        }
    }
}

// Void response
impl<F> TryFrom<ResponseRouterData<RedsysResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: ResponseRouterData<RedsysResponse, Self>) -> Result<Self, Self::Error> {
        match item.response {
            RedsysResponse::Success(response) => {
                let params: RedsysVoidResponseParams = decode_response_params(&response)?;

                Ok(Self {
                    response: Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(params.ds_order),
                        redirection_data: None,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: None,
                        connector_response_reference_id: params.ds_authorisation_code,
                        incremental_authorization_allowed: None,
                        status_code: item.http_code,
                    }),
                    ..item.router_data
                })
            }
            RedsysResponse::Error(_) => {
                Err(errors::ConnectorError::ResponseDeserializationFailed.into())
            }
        }
    }
}

// Capture response
impl<F> TryFrom<ResponseRouterData<RedsysResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: ResponseRouterData<RedsysResponse, Self>) -> Result<Self, Self::Error> {
        match item.response {
            RedsysResponse::Success(response) => {
                let params: RedysCaptureResponseParams = decode_response_params(&response)?;

                Ok(Self {
                    response: Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(params.ds_order),
                        redirection_data: None,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: None,
                        connector_response_reference_id: params.ds_authorisation_code,
                        incremental_authorization_allowed: None,
                        status_code: item.http_code,
                    }),
                    ..item.router_data
                })
            }
            RedsysResponse::Error(_) => {
                Err(errors::ConnectorError::ResponseDeserializationFailed.into())
            }
        }
    }
}

// Refund response
impl<F> TryFrom<ResponseRouterData<RedsysResponse, Self>>
    for RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: ResponseRouterData<RedsysResponse, Self>) -> Result<Self, Self::Error> {
        match item.response {
            RedsysResponse::Success(response) => {
                let params: RedsysRefundResponseParams = decode_response_params(&response)?;
                let status = get_refund_status(&params.ds_response);

                Ok(Self {
                    response: Ok(RefundsResponseData {
                        connector_refund_id: params.ds_order,
                        refund_status: status,
                        status_code: item.http_code,
                    }),
                    ..item.router_data
                })
            }
            RedsysResponse::Error(_) => {
                Err(errors::ConnectorError::ResponseDeserializationFailed.into())
            }
        }
    }
}

// PSync response
impl<F> TryFrom<ResponseRouterData<RedsysResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: ResponseRouterData<RedsysResponse, Self>) -> Result<Self, Self::Error> {
        match item.response {
            RedsysResponse::Success(response) => {
                let params: RedysPSyncResponseParams = decode_response_params(&response)?;

                Ok(Self {
                    response: Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(params.ds_order),
                        redirection_data: None,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: None,
                        connector_response_reference_id: params.ds_authorisation_code,
                        incremental_authorization_allowed: None,
                        status_code: item.http_code,
                    }),
                    ..item.router_data
                })
            }
            RedsysResponse::Error(_) => {
                Err(errors::ConnectorError::ResponseDeserializationFailed.into())
            }
        }
    }
}

// RSync response
impl<F> TryFrom<ResponseRouterData<RedsysResponse, Self>>
    for RouterDataV2<F, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: ResponseRouterData<RedsysResponse, Self>) -> Result<Self, Self::Error> {
        match item.response {
            RedsysResponse::Success(response) => {
                let params: RedsysRSyncResponseParams = decode_response_params(&response)?;
                let status = get_refund_status(&params.ds_response);

                Ok(Self {
                    response: Ok(RefundsResponseData {
                        connector_refund_id: params.ds_order,
                        refund_status: status,
                        status_code: item.http_code,
                    }),
                    ..item.router_data
                })
            }
            RedsysResponse::Error(_) => {
                Err(errors::ConnectorError::ResponseDeserializationFailed.into())
            }
        }
    }
}
