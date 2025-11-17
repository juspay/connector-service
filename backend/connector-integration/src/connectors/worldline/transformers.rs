use common_enums::AttemptStatus;
use common_utils::pii;
use domain_types::{
    connector_flow::{Authorize, Capture, PSync, RSync, Refund},
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData, ResponseId},
    errors,
    payment_method_data::{Card, PaymentMethodData, PaymentMethodDataTypes},
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, PeekInterface, Secret};
use serde::{Deserialize, Serialize};

use crate::{connectors::worldline::WorldlineRouterData, types::ResponseRouterData};

// ============================================================================
// AUTHENTICATION
// ============================================================================

#[derive(Debug, Clone)]
pub struct WorldlineAuthType {
    pub api_key: Secret<String>,
    pub api_secret: Secret<String>,
    pub merchant_account_id: Secret<String>,
}

impl WorldlineAuthType {
    /// Generate GCS v1HMAC Authorization header
    /// Format: GCS v1HMAC:{api_key}:{signature}
    /// Signature is base64(HMAC-SHA256(stringToSign, apiSecret))
    /// stringToSign = method + "\n" + contentType + "\n" + date + "\n" + CanonicalizedResource + "\n"
    pub fn generate_authorization_header(
        &self,
        http_method: &str,
        content_type: &str,
        date: &str,
        endpoint: &str,
    ) -> Result<String, error_stack::Report<errors::ConnectorError>> {
        use base64::{engine::general_purpose::STANDARD, Engine};
        use ring::hmac;

        // Build string to sign per Worldline spec (matching Hyperswitch implementation)
        // Format: "METHOD\ncontent-type\ndate\n/endpoint\n"
        // endpoint should have leading '/' from path extraction
        let string_to_sign = format!(
            "{}\n{}\n{}\n{}\n",
            http_method,
            content_type.trim(),
            date.trim(),
            endpoint.trim()
        );

        // Debug logging for HMAC signature troubleshooting
        tracing::debug!(
            "Worldline HMAC - String to sign: {:?}",
            string_to_sign
        );

        // Use api_secret directly as HMAC key (do NOT base64 decode)
        // This matches the working Hyperswitch implementation
        let key = hmac::Key::new(hmac::HMAC_SHA256, self.api_secret.peek().as_bytes());

        // Sign the string
        let signature_bytes = hmac::sign(&key, string_to_sign.as_bytes());

        // Base64 encode the signature
        let signature = STANDARD.encode(signature_bytes.as_ref());

        // Format: GCS v1HMAC:{api_key}:{signature}
        Ok(format!(
            "GCS v1HMAC:{}:{}",
            self.api_key.peek(),
            signature
        ))
    }

    /// Generate date string for the Date header in Worldline's expected format
    /// Format: "Day, DD Mon YYYY HH:MM:SS GMT" (NOT RFC 2822 which uses +0000)
    pub fn generate_date_header() -> String {
        use time::OffsetDateTime;

        // Worldline requires GMT suffix, not +0000 timezone offset
        let format = time::format_description::parse(
            "[weekday repr:short], [day] [month repr:short] [year] [hour]:[minute]:[second] GMT",
        );

        let now = OffsetDateTime::now_utc();

        match format {
            Ok(fmt) => now.format(&fmt).unwrap_or_else(|_| "Thu, 01 Jan 1970 00:00:00 GMT".to_string()),
            Err(_) => "Thu, 01 Jan 1970 00:00:00 GMT".to_string(),
        }
    }
}

impl TryFrom<&ConnectorAuthType> for WorldlineAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey {
                api_key,
                key1,
                api_secret,
            } => Ok(Self {
                api_key: api_key.to_owned(),
                api_secret: api_secret.to_owned(),
                merchant_account_id: key1.to_owned(),
            }),
            _ => Err(error_stack::report!(
                errors::ConnectorError::FailedToObtainAuthType
            ))
            .attach_printable("Worldline requires SignatureKey auth with api_key, key1 (merchant_account_id), and api_secret"),
        }
    }
}

// ============================================================================
// ERROR RESPONSE
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldlineErrorResponse {
    pub error_id: Option<String>,
    pub errors: Option<Vec<WorldlineErrorDetail>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorldlineErrorDetail {
    #[serde(rename = "Code")]
    pub code: Option<String>,
    #[serde(rename = "propertyName")]
    pub property_name: Option<String>,
    #[serde(rename = "Date")]
    pub date: Option<String>,
    #[serde(rename = "Message")]
    pub message: Option<String>,
}

impl WorldlineErrorResponse {
    /// Extract error code from the first error, or return generic code
    pub fn get_error_code(&self) -> String {
        self.errors
            .as_ref()
            .and_then(|errs| errs.first())
            .and_then(|err| err.code.clone())
            .unwrap_or_else(|| "UNKNOWN_ERROR".to_string())
    }

    /// Extract error message from the first error, or return generic message
    pub fn get_error_message(&self) -> String {
        self.errors
            .as_ref()
            .and_then(|errs| errs.first())
            .and_then(|err| err.message.clone())
            .unwrap_or_else(|| "Unknown error occurred".to_string())
    }
}

// ============================================================================
// PAYMENT REQUEST
// ============================================================================

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldlinePaymentRequest<T: PaymentMethodDataTypes> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card_payment_method_specific_input: Option<WorldlineCardPaymentMethodInput<T>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_payment_method_specific_input: Option<WorldlineRedirectPaymentMethodInput>,
    pub order: WorldlineOrder,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldlineCardPaymentMethodInput<T: PaymentMethodDataTypes> {
    pub payment_product_id: Option<i32>,
    pub card: WorldlineCard<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub three_d_secure: Option<WorldlineThreeDSecure>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldlineThreeDSecure {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_authentication: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirection_data: Option<WorldlineThreeDSecureRedirectionData>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldlineThreeDSecureRedirectionData {
    pub return_url: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldlineCard<T: PaymentMethodDataTypes> {
    pub card_number: domain_types::payment_method_data::RawCardNumber<T>,
    pub cardholder_name: Option<Secret<String>>,
    pub cvv: Secret<String>,
    pub expiry_date: Secret<String>,
    #[serde(skip)]
    _phantom: std::marker::PhantomData<T>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldlineRedirectPaymentMethodInput {
    pub payment_product_id: Option<i32>,
    pub redirection_data: Option<WorldlineRedirectionData>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldlineRedirectionData {
    pub return_url: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldlineOrder {
    pub amount_of_money: WorldlineAmount,
    pub customer: Option<WorldlineCustomer>,
    pub references: WorldlineReferences,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldlineAmount {
    pub amount: i64,
    pub currency_code: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldlineCustomer {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub billing_address: Option<WorldlineAddress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact_details: Option<WorldlineContactDetails>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merchant_customer_id: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldlineAddress {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub street: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zip: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country_code: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldlineContactDetails {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_address: Option<pii::Email>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldlineReferences {
    pub merchant_reference: String,
}

// ============================================================================
// PAYMENT RESPONSE
// ============================================================================

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldlinePaymentResponse {
    pub payment: Option<WorldlinePaymentObject>,
    pub creation_output: Option<WorldlineCreationOutput>,
    pub merchant_action: Option<WorldlineMerchantAction>,
}

// PSync response returns the payment object directly (not wrapped)
pub type WorldlinePaymentSyncResponse = WorldlinePaymentObject;

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldlinePaymentObject {
    pub id: String,
    pub status: String,
    pub status_output: Option<WorldlineStatusOutput>,
    pub payment_output: Option<WorldlinePaymentOutput>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldlineStatusOutput {
    pub is_authorized: Option<bool>,
    pub is_cancellable: Option<bool>,
    pub is_refundable: Option<bool>,
    pub status_category: Option<String>,
    pub status_code: Option<i32>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldlinePaymentOutput {
    pub amount_of_money: Option<WorldlineAmount>,
    pub references: Option<WorldlinePaymentReferences>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldlinePaymentReferences {
    pub payment_reference: Option<String>,
    pub merchant_reference: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldlineCreationOutput {
    pub token: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldlineMerchantAction {
    pub action_type: Option<String>,
    pub redirect_data: Option<WorldlineRedirectData>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub struct WorldlineRedirectData {
    #[serde(rename = "redirectURL")]
    pub redirect_url: Option<String>,
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/// Map card network to Worldline payment product ID
/// Reference: https://epayments-api.developer-ingenico.com/s2sapi/v1/en_US/rust/products.html
fn get_payment_product_id(card_network: &common_enums::CardNetwork) -> Option<i32> {
    match card_network {
        common_enums::CardNetwork::Visa => Some(1),
        common_enums::CardNetwork::Mastercard => Some(3),
        common_enums::CardNetwork::AmericanExpress => Some(2),
        common_enums::CardNetwork::Maestro => Some(117),
        // For other networks, return None and let Worldline auto-detect
        _ => None,
    }
}

/// Build three_d_secure object based on auth_type and enrolled_for_3ds
fn build_three_d_secure<T: PaymentMethodDataTypes>(
    router_data: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
) -> Option<WorldlineThreeDSecure> {
    // If auth_type is NO_THREE_DS, skip authentication
    let skip_authentication = matches!(
        router_data.resource_common_data.auth_type,
        common_enums::AuthenticationType::NoThreeDs
    );

    // Build redirection_data if return_url is present
    let redirection_data = router_data.request.router_return_url.as_ref().map(|url| {
        WorldlineThreeDSecureRedirectionData {
            return_url: url.clone(),
        }
    });

    Some(WorldlineThreeDSecure {
        skip_authentication: Some(skip_authentication),
        redirection_data,
    })
}

// ============================================================================
// REQUEST TRANSFORMERS
// ============================================================================

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    TryFrom<WorldlineRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>>
    for WorldlinePaymentRequest<T>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: WorldlineRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let amount = router_data.request.minor_amount.get_amount_as_i64();
        let currency = router_data.request.currency.to_string();

        // Build order
        let order = WorldlineOrder {
            amount_of_money: WorldlineAmount {
                amount,
                currency_code: currency,
            },
            customer: get_billing_info(router_data),
            references: WorldlineReferences {
                merchant_reference: router_data
                    .resource_common_data
                    .connector_request_reference_id
                    .clone(),
            },
        };

        // Build payment method specific input
        match &router_data.request.payment_method_data {
            PaymentMethodData::Card(card_data) => {
                let card = build_worldline_card(card_data, router_data)?;

                // Map card network to Worldline payment product ID
                let payment_product_id = card_data.card_network.as_ref()
                    .and_then(get_payment_product_id);

                // Build three_d_secure based on auth_type
                let three_d_secure = build_three_d_secure(router_data);

                Ok(Self {
                    card_payment_method_specific_input: Some(WorldlineCardPaymentMethodInput {
                        payment_product_id,
                        card,
                        three_d_secure,
                    }),
                    redirect_payment_method_specific_input: None,
                    order,
                })
            }
            _ => Err(errors::ConnectorError::NotImplemented(
                "Payment method not supported".to_string(),
            ))
            .attach_printable("Unsupported payment method"),
        }
    }
}

fn build_worldline_card<T: PaymentMethodDataTypes>(
    card: &Card<T>,
    router_data: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
) -> Result<WorldlineCard<T>, error_stack::Report<errors::ConnectorError>> {
    // Format expiry date as MMYY
    let expiry_date = format!(
        "{}{}",
        card.card_exp_month.peek(),
        card.card_exp_year.peek()
    );

    // Use card holder name from card data, or fallback to billing address name
    let cardholder_name = card.card_holder_name.clone().or_else(|| {
        router_data
            .resource_common_data
            .address
            .get_payment_billing()
            .and_then(|billing| billing.address.as_ref())
            .and_then(|addr| {
                let first_name = addr.first_name.as_ref()?.peek();
                let last_name = addr.last_name.as_ref()?.peek();
                Some(Secret::new(format!("{} {}", first_name, last_name)))
            })
    });

    Ok(WorldlineCard {
        card_number: card.card_number.clone(),
        cardholder_name,
        cvv: card.card_cvc.clone(),
        expiry_date: Secret::new(expiry_date),
        _phantom: std::marker::PhantomData,
    })
}

fn get_billing_info<T: PaymentMethodDataTypes>(
    router_data: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
) -> Option<WorldlineCustomer> {
    let address = &router_data.resource_common_data.address;
    let billing = address.get_payment_billing()?;

    Some(WorldlineCustomer {
        billing_address: billing.address.as_ref().map(|addr| WorldlineAddress {
            street: addr.line1.clone(),
            city: addr.city.as_ref().map(|c| c.clone().expose()),
            state: addr.state.as_ref().map(|s| s.clone().expose()),
            zip: addr.zip.clone(),
            country_code: addr.country.map(|c| c.to_string()),
        }),
        contact_details: router_data.request.email.as_ref().map(|email| {
            WorldlineContactDetails {
                email_address: Some(email.clone()),
            }
        }),
        merchant_customer_id: router_data.resource_common_data.connector_customer.clone(),
    })
}

// ============================================================================
// RESPONSE TRANSFORMERS
// ============================================================================

impl<T: PaymentMethodDataTypes>
    TryFrom<
        ResponseRouterData<
            WorldlinePaymentResponse,
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
            WorldlinePaymentResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let router_data = &item.router_data;

        // Extract payment object
        let payment = response
            .payment
            .as_ref()
            .ok_or(errors::ConnectorError::ResponseDeserializationFailed)
            .attach_printable("Missing payment object in response")?;

        // Map status
        let status = map_worldline_status(&payment.status, &payment.status_output);

        // Check for redirect
        let redirection_data = response
            .merchant_action
            .as_ref()
            .and_then(|action| action.redirect_data.as_ref())
            .and_then(|redirect| redirect.redirect_url.clone())
            .map(|url| {
                Box::new(domain_types::router_response_types::RedirectForm::Uri {
                    uri: url,
                })
            });

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(payment.id.clone()),
                redirection_data,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: payment
                    .payment_output
                    .as_ref()
                    .and_then(|output| output.references.as_ref())
                    .and_then(|refs| refs.payment_reference.clone()),
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data.clone()
            },
            ..router_data.clone()
        })
    }
}

// ============================================================================
// STATUS MAPPING
// ============================================================================

fn map_worldline_status(
    status: &str,
    status_output: &Option<WorldlineStatusOutput>,
) -> AttemptStatus {
    match status.to_uppercase().as_str() {
        "CREATED" | "PENDING_PAYMENT" | "PENDING_FRAUD_APPROVAL" => AttemptStatus::Pending,
        "AUTHORIZATION_REQUESTED" => AttemptStatus::Pending,
        "PENDING_APPROVAL" => {
            // Check if authorized - PENDING_APPROVAL with is_authorized=true means Authorized
            if let Some(output) = status_output {
                if output.is_authorized == Some(true) {
                    return AttemptStatus::Authorized;
                }
            }
            AttemptStatus::Pending
        }
        "PENDING_COMPLETION" => AttemptStatus::Pending,
        "PENDING_CAPTURE" => {
            // Check if authorized
            if let Some(output) = status_output {
                if output.is_authorized == Some(true) {
                    return AttemptStatus::Authorized;
                }
            }
            AttemptStatus::Pending
        }
        "CAPTURED" | "PAID" | "ACCOUNT_VERIFIED" => AttemptStatus::Charged,
        "CANCELLED" => AttemptStatus::Voided,
        "REJECTED" | "REJECTED_CAPTURE" => AttemptStatus::Failure,
        "REFUNDED" => AttemptStatus::Charged, // Payment was successful, refund is separate
        "REVERSED" => AttemptStatus::Voided,
        "CHARGEBACKED" => AttemptStatus::Charged, // Payment was successful, chargeback is separate
        _ => {
            // Check status category as fallback
            if let Some(output) = status_output {
                if let Some(category) = &output.status_category {
                    match category.to_uppercase().as_str() {
                        "COMPLETED" | "SUCCESSFUL" => return AttemptStatus::Charged,
                        "PENDING_PAYMENT" | "PENDING_MERCHANT" => return AttemptStatus::Pending,
                        "UNSUCCESSFUL" => return AttemptStatus::Failure,
                        "REJECTED" => return AttemptStatus::Failure,
                        _ => {}
                    }
                }
            }
            AttemptStatus::Pending
        }
    }
}

// ============================================================================
// PSYNC RESPONSE TRANSFORMER
// ============================================================================

impl
    TryFrom<
        ResponseRouterData<
            WorldlinePaymentSyncResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    > for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            WorldlinePaymentSyncResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let router_data = &item.router_data;

        // PSync response IS the payment object directly (no wrapper)
        let payment = response;

        // Map status using the same status mapping function as Authorize
        let status = map_worldline_status(&payment.status, &payment.status_output);

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(payment.id.clone()),
                redirection_data: None,  // PSync doesn't include merchant_action
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: payment
                    .payment_output
                    .as_ref()
                    .and_then(|output| output.references.as_ref())
                    .and_then(|refs| refs.payment_reference.clone()),
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data.clone()
            },
            ..router_data.clone()
        })
    }
}

// ============================================================================
// CAPTURE REQUEST/RESPONSE
// ============================================================================

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldlineCaptureRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<i64>, // For partial capture; omit for full capture
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldlineCaptureResponse {
    pub payment: Option<WorldlinePaymentObject>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card_payment_method_specific_output: Option<WorldlineCardCaptureOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mobile_payment_method_specific_output: Option<WorldlineMobileCaptureOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_method_specific_output: Option<WorldlinePaymentMethodCaptureOutput>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldlineCardCaptureOutput {
    pub void_response_id: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldlineMobileCaptureOutput {
    pub void_response_id: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldlinePaymentMethodCaptureOutput {
    pub void_response_id: Option<String>,
}

// ============================================================================
// CAPTURE REQUEST TRANSFORMER
// ============================================================================

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    TryFrom<
        WorldlineRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    > for WorldlineCaptureRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: WorldlineRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;

        // For Worldline, amount is optional in the capture request
        // If amount is present, it's a partial capture; if omitted, it's a full capture
        // According to spec, the amount is in minor units (integer)
        let amount = Some(router_data.request.minor_amount_to_capture.get_amount_as_i64());

        Ok(Self { amount })
    }
}

// ============================================================================
// CAPTURE RESPONSE TRANSFORMER
// ============================================================================

impl
    TryFrom<
        ResponseRouterData<
            WorldlineCaptureResponse,
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    > for RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            WorldlineCaptureResponse,
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let router_data = &item.router_data;

        // Extract payment object from response
        let payment = response
            .payment
            .as_ref()
            .ok_or(errors::ConnectorError::ResponseDeserializationFailed)
            .attach_printable("Missing payment object in Capture response")?;

        // Map status using the same status mapping function
        let status = map_worldline_status(&payment.status, &payment.status_output);

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(payment.id.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: payment
                    .payment_output
                    .as_ref()
                    .and_then(|output| output.references.as_ref())
                    .and_then(|refs| refs.payment_reference.clone()),
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data.clone()
            },
            ..router_data.clone()
        })
    }
}

// ============================================================================
// REFUND REQUEST/RESPONSE
// ============================================================================

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldlineRefundRequest {
    pub amount_of_money: WorldlineAmount,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldlineRefundResponse {
    pub id: String,
    pub status: String,
    pub status_output: Option<WorldlineRefundStatusOutput>,
    pub refund_output: Option<WorldlineRefundOutput>,
}

// Type alias for RSync response - same structure as refund response
pub type WorldlineRefundSyncResponse = WorldlineRefundResponse;

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldlineRefundStatusOutput {
    pub status_category: Option<String>,
    pub status_code: Option<i32>,
    pub is_cancellable: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldlineRefundOutput {
    pub amount_of_money: Option<WorldlineAmount>,
    pub references: Option<WorldlineRefundReferences>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldlineRefundReferences {
    pub payment_reference: Option<String>,
    pub merchant_reference: Option<String>,
}

// ============================================================================
// REFUND REQUEST TRANSFORMER
// ============================================================================

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    TryFrom<
        WorldlineRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    > for WorldlineRefundRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: WorldlineRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;

        Ok(Self {
            amount_of_money: WorldlineAmount {
                amount: router_data.request.minor_refund_amount.get_amount_as_i64(),
                currency_code: router_data.request.currency.to_string(),
            },
        })
    }
}

// ============================================================================
// REFUND RESPONSE TRANSFORMER
// ============================================================================

impl
    TryFrom<
        ResponseRouterData<
            WorldlineRefundResponse,
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    > for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            WorldlineRefundResponse,
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let router_data = &item.router_data;

        // Map refund status
        let status = map_worldline_refund_status(&response.status, &response.status_output);

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: response.id.clone(),
                refund_status: status,
                status_code: item.http_code,
            }),
            ..router_data.clone()
        })
    }
}

// ============================================================================
// REFUND STATUS MAPPING
// ============================================================================

fn map_worldline_refund_status(
    status: &str,
    status_output: &Option<WorldlineRefundStatusOutput>,
) -> common_enums::RefundStatus {
    match status.to_uppercase().as_str() {
        "CREATED" | "PENDING_APPROVAL" | "REFUND_REQUESTED" => common_enums::RefundStatus::Pending,
        "REFUNDED" | "CAPTURED" => common_enums::RefundStatus::Success,
        "CANCELLED" | "REJECTED" => common_enums::RefundStatus::Failure,
        _ => {
            // Check status category as fallback
            if let Some(output) = status_output {
                if let Some(category) = &output.status_category {
                    match category.to_uppercase().as_str() {
                        "COMPLETED" | "SUCCESSFUL" => return common_enums::RefundStatus::Success,
                        "PENDING_PAYMENT" | "PENDING_MERCHANT" => return common_enums::RefundStatus::Pending,
                        "UNSUCCESSFUL" | "REJECTED" => return common_enums::RefundStatus::Failure,
                        _ => {}
                    }
                }
            }
            common_enums::RefundStatus::Pending
        }
    }
}

// ============================================================================
// RSYNC RESPONSE TRANSFORMER
// ============================================================================

impl
    TryFrom<
        ResponseRouterData<
            WorldlineRefundSyncResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    > for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            WorldlineRefundSyncResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let router_data = &item.router_data;

        // Map refund status - same mapping as Refund flow
        let status = map_worldline_refund_status(&response.status, &response.status_output);

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: response.id.clone(),
                refund_status: status,
                status_code: item.http_code,
            }),
            ..router_data.clone()
        })
    }
}

// ============================================================================
// VOID REQUEST/RESPONSE
// ============================================================================

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldlineVoidRequest {
    // Worldline cancel/void doesn't require a request body, but we define empty struct
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldlineVoidResponse {
    pub payment: Option<WorldlinePaymentObject>,
}

// ============================================================================
// VOID REQUEST TRANSFORMER
// ============================================================================

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    TryFrom<
        WorldlineRouterData<
            RouterDataV2<domain_types::connector_flow::Void, PaymentFlowData, domain_types::connector_types::PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    > for WorldlineVoidRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        _item: WorldlineRouterData<
            RouterDataV2<domain_types::connector_flow::Void, PaymentFlowData, domain_types::connector_types::PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        // Worldline cancel endpoint doesn't require a request body
        Ok(Self {})
    }
}

// ============================================================================
// VOID RESPONSE TRANSFORMER
// ============================================================================

impl
    TryFrom<
        ResponseRouterData<
            WorldlineVoidResponse,
            RouterDataV2<domain_types::connector_flow::Void, PaymentFlowData, domain_types::connector_types::PaymentVoidData, PaymentsResponseData>,
        >,
    > for RouterDataV2<domain_types::connector_flow::Void, PaymentFlowData, domain_types::connector_types::PaymentVoidData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            WorldlineVoidResponse,
            RouterDataV2<domain_types::connector_flow::Void, PaymentFlowData, domain_types::connector_types::PaymentVoidData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let router_data = &item.router_data;

        // Extract payment object from response
        let payment = response
            .payment
            .as_ref()
            .ok_or(errors::ConnectorError::ResponseDeserializationFailed)
            .attach_printable("Missing payment object in Void response")?;

        // Map status using the same status mapping function
        let status = map_worldline_status(&payment.status, &payment.status_output);

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(payment.id.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: payment
                    .payment_output
                    .as_ref()
                    .and_then(|output| output.references.as_ref())
                    .and_then(|refs| refs.payment_reference.clone()),
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data.clone()
            },
            ..router_data.clone()
        })
    }
}
