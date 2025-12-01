use common_utils::{pii, types::StringMajorUnit};
use domain_types::{
    connector_flow::{Authorize, Capture, PSync, RSync, Refund, Void},
    connector_types::{
        PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData,
        RefundsResponseData, ResponseId,
    },
    errors,
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes, RawCardNumber},
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
};
use error_stack::ResultExt;
use hyperswitch_masking::{PeekInterface, Secret};
use serde::{Deserialize, Serialize};

use super::NuveiRouterData;
use crate::types::ResponseRouterData;

// Auth Type
#[derive(Debug, Clone)]
pub struct NuveiAuthType {
    pub(super) merchant_id: Secret<String>,
    pub(super) merchant_site_id: Secret<String>,
    pub(super) merchant_secret: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for NuveiAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey {
                api_key,
                api_secret,
                key1,
            } => Ok(Self {
                merchant_id: api_key.clone(),
                merchant_site_id: key1.clone(),
                merchant_secret: api_secret.clone(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

impl NuveiAuthType {
    pub fn generate_checksum(&self, params: &[&str]) -> String {
        use sha2::{Digest, Sha256};

        let mut concatenated = params.join("");
        concatenated.push_str(self.merchant_secret.peek());

        let mut hasher = Sha256::new();
        hasher.update(concatenated.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    pub fn get_timestamp(
    ) -> common_utils::date_time::DateTime<common_utils::date_time::YYYYMMDDHHmmss> {
        // Generate timestamp in YYYYMMDDHHmmss format using common_utils date_time
        common_utils::date_time::DateTime::from(common_utils::date_time::now())
    }
}

// Session Token Request
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NuveiSessionTokenRequest {
    pub merchant_id: Secret<String>,
    pub merchant_site_id: Secret<String>,
    pub client_request_id: String,
    pub time_stamp: common_utils::date_time::DateTime<common_utils::date_time::YYYYMMDDHHmmss>,
    pub checksum: String,
}

// Session Token Response
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NuveiSessionTokenResponse {
    pub session_token: Option<String>,
    pub internal_request_id: Option<i64>,
    pub status: String,
    pub err_code: Option<i32>,
    pub reason: Option<String>,
    pub merchant_id: Option<String>,
    pub merchant_site_id: Option<String>,
    pub version: Option<String>,
    pub client_request_id: Option<String>,
}

// Payment Request
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NuveiPaymentRequest<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    pub session_token: Option<String>,
    pub merchant_id: Secret<String>,
    pub merchant_site_id: Secret<String>,
    pub client_request_id: String,
    pub amount: StringMajorUnit,
    pub currency: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_token_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_unique_id: Option<String>,
    pub payment_option: NuveiPaymentOption<T>,
    pub transaction_type: TransactionType,
    pub device_details: NuveiDeviceDetails,
    pub billing_address: NuveiBillingAddress,
    pub time_stamp: common_utils::date_time::DateTime<common_utils::date_time::YYYYMMDDHHmmss>,
    pub checksum: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NuveiPaymentOption<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    pub card: NuveiCard<T>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NuveiCard<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    pub card_number: RawCardNumber<T>,
    pub card_holder_name: Secret<String>,
    pub expiration_month: Secret<String>,
    pub expiration_year: Secret<String>,
    #[serde(rename = "CVV")]
    pub cvv: Secret<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NuveiDeviceDetails {
    pub ip_address: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NuveiBillingAddress {
    // Required fields per Nuvei documentation
    pub email: pii::Email,
    pub first_name: Secret<String>,
    pub last_name: Secret<String>,
    pub country: String,
    // Optional fields
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address_line2: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address_line3: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zip: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<Secret<String>>,
}

// Payment Response
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NuveiPaymentResponse {
    pub order_id: Option<String>,
    pub transaction_id: Option<String>,
    pub transaction_status: Option<String>,
    pub status: String,
    pub err_code: Option<i32>,
    pub reason: Option<String>,
    #[serde(rename = "gwErrorCode")]
    pub gw_error_code: Option<i32>,
    #[serde(rename = "gwErrorReason")]
    pub gw_error_reason: Option<String>,
    pub auth_code: Option<String>,
    pub session_token: Option<String>,
    pub client_unique_id: Option<String>,
    pub client_request_id: Option<String>,
    pub internal_request_id: Option<i64>,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum NuveiPaymentStatus {
    #[serde(rename = "APPROVED")]
    Approved,
    #[serde(rename = "DECLINED")]
    Declined,
    #[serde(rename = "ERROR")]
    Error,
    #[serde(rename = "REDIRECT")]
    Redirect,
    #[serde(rename = "PENDING")]
    Pending,
}

// Transaction Type for initPayment
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub enum TransactionType {
    Auth,
    #[default]
    Sale,
}

impl TransactionType {
    fn get_from_capture_method(
        capture_method: Option<common_enums::CaptureMethod>,
        amount: &StringMajorUnit,
    ) -> Self {
        let amount_value = amount.get_amount_as_string().parse::<f64>();
        if capture_method == Some(common_enums::CaptureMethod::Manual) || amount_value == Ok(0.0) {
            Self::Auth
        } else {
            Self::Sale
        }
    }
}

// Sync Request
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NuveiSyncRequest {
    pub merchant_id: Secret<String>,
    pub merchant_site_id: Secret<String>,
    pub client_unique_id: String,
    pub transaction_id: String,
    pub time_stamp: common_utils::date_time::DateTime<common_utils::date_time::YYYYMMDDHHmmss>,
    pub checksum: String,
}

// Sync Response (getTransactionDetails has different structure than payment response)
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NuveiSyncResponse {
    pub status: String,
    pub err_code: Option<i32>,
    pub reason: Option<String>,
    pub internal_request_id: Option<i64>,
    pub merchant_id: Option<String>,
    pub merchant_site_id: Option<String>,
    pub version: Option<String>,
    pub transaction_details: Option<NuveiTransactionDetails>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NuveiTransactionDetails {
    pub transaction_id: Option<String>,
    pub transaction_status: Option<String>,
    pub auth_code: Option<String>,
    pub client_unique_id: Option<String>,
    pub date: Option<String>,
    pub original_transaction_date: Option<String>,
    pub credited: Option<String>,
    pub acquiring_bank_name: Option<String>,
    pub transaction_type: Option<String>,
}

// Capture Request
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NuveiCaptureRequest {
    pub merchant_id: Secret<String>,
    pub merchant_site_id: Secret<String>,
    pub client_request_id: String,
    pub client_unique_id: String,
    pub amount: StringMajorUnit,
    pub currency: String,
    pub related_transaction_id: String,
    pub time_stamp: common_utils::date_time::DateTime<common_utils::date_time::YYYYMMDDHHmmss>,
    pub checksum: String,
}

// Capture Response
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NuveiCaptureResponse {
    pub merchant_id: Option<String>,
    pub merchant_site_id: Option<String>,
    pub internal_request_id: Option<i64>,
    pub transaction_id: Option<String>,
    pub status: String,
    pub transaction_status: Option<String>,
    pub err_code: Option<i32>,
    pub reason: Option<String>,
}

// Refund Request
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NuveiRefundRequest {
    pub merchant_id: Secret<String>,
    pub merchant_site_id: Secret<String>,
    pub client_request_id: String,
    pub client_unique_id: String,
    pub amount: StringMajorUnit,
    pub currency: String,
    pub related_transaction_id: String,
    pub time_stamp: common_utils::date_time::DateTime<common_utils::date_time::YYYYMMDDHHmmss>,
    pub checksum: String,
}

// Refund Response
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NuveiRefundResponse {
    pub transaction_id: Option<String>,
    pub transaction_status: Option<String>,
    pub status: String,
    pub err_code: Option<i32>,
    pub reason: Option<String>,
}

// Refund Sync Request
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NuveiRefundSyncRequest {
    pub merchant_id: Secret<String>,
    pub merchant_site_id: Secret<String>,
    pub client_unique_id: String,
    pub transaction_id: String,
    pub time_stamp: common_utils::date_time::DateTime<common_utils::date_time::YYYYMMDDHHmmss>,
    pub checksum: String,
}

// Refund Sync Response (separate type to avoid macro conflicts)
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NuveiRefundSyncResponse {
    pub transaction_id: Option<String>,
    pub transaction_status: Option<String>,
    pub status: String,
    pub err_code: Option<i32>,
    pub reason: Option<String>,
}

// Void Request
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NuveiVoidRequest {
    pub merchant_id: Secret<String>,
    pub merchant_site_id: Secret<String>,
    pub client_request_id: String,
    pub client_unique_id: String,
    pub related_transaction_id: String,
    pub time_stamp: common_utils::date_time::DateTime<common_utils::date_time::YYYYMMDDHHmmss>,
    pub checksum: String,
}

// Void Response
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NuveiVoidResponse {
    pub transaction_id: Option<String>,
    pub transaction_status: Option<String>,
    pub status: String,
    pub err_code: Option<i32>,
    pub reason: Option<String>,
}

// Error Response
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NuveiErrorResponse {
    pub reason: Option<String>,
    pub err_code: Option<String>,
    pub status: Option<String>,
}

// Session Token Request Transformation
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        NuveiRouterData<
            RouterDataV2<
                domain_types::connector_flow::CreateSessionToken,
                PaymentFlowData,
                domain_types::connector_types::SessionTokenRequestData,
                domain_types::connector_types::SessionTokenResponseData,
            >,
            T,
        >,
    > for NuveiSessionTokenRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: NuveiRouterData<
            RouterDataV2<
                domain_types::connector_flow::CreateSessionToken,
                PaymentFlowData,
                domain_types::connector_types::SessionTokenRequestData,
                domain_types::connector_types::SessionTokenResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;

        // Extract auth data
        let auth = NuveiAuthType::try_from(&router_data.connector_auth_type)?;

        let time_stamp = NuveiAuthType::get_timestamp();
        let client_request_id = router_data
            .resource_common_data
            .connector_request_reference_id
            .clone();

        // Generate checksum for getSessionToken: merchantId + merchantSiteId + clientRequestId + timeStamp + merchantSecretKey
        let checksum = auth.generate_checksum(&[
            auth.merchant_id.peek(),
            auth.merchant_site_id.peek(),
            &client_request_id,
            &time_stamp.to_string(),
        ]);

        Ok(Self {
            merchant_id: auth.merchant_id,
            merchant_site_id: auth.merchant_site_id,
            client_request_id,
            time_stamp,
            checksum,
        })
    }
}

// Session Token Response Transformation
impl
    TryFrom<
        ResponseRouterData<
            NuveiSessionTokenResponse,
            RouterDataV2<
                domain_types::connector_flow::CreateSessionToken,
                PaymentFlowData,
                domain_types::connector_types::SessionTokenRequestData,
                domain_types::connector_types::SessionTokenResponseData,
            >,
        >,
    >
    for RouterDataV2<
        domain_types::connector_flow::CreateSessionToken,
        PaymentFlowData,
        domain_types::connector_types::SessionTokenRequestData,
        domain_types::connector_types::SessionTokenResponseData,
    >
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            NuveiSessionTokenResponse,
            RouterDataV2<
                domain_types::connector_flow::CreateSessionToken,
                PaymentFlowData,
                domain_types::connector_types::SessionTokenRequestData,
                domain_types::connector_types::SessionTokenResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let router_data = &item.router_data;

        // Check if the overall request status is SUCCESS or ERROR
        if response.status.to_uppercase() == "ERROR" {
            let error_code = response.err_code.map(|c| c.to_string()).unwrap_or_default();
            let error_message = response
                .reason
                .clone()
                .unwrap_or_else(|| "Unknown error".to_string());

            return Ok(Self {
                resource_common_data: PaymentFlowData {
                    status: common_enums::AttemptStatus::Failure,
                    ..router_data.resource_common_data.clone()
                },
                response: Err(domain_types::router_data::ErrorResponse {
                    code: error_code,
                    message: error_message.clone(),
                    reason: Some(error_message),
                    status_code: item.http_code,
                    attempt_status: Some(common_enums::AttemptStatus::Failure),
                    connector_transaction_id: None,
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                }),
                ..router_data.clone()
            });
        }

        // Extract session token
        let session_token =
            response
                .session_token
                .clone()
                .ok_or(errors::ConnectorError::MissingRequiredField {
                    field_name: "session_token",
                })?;

        let session_response_data = domain_types::connector_types::SessionTokenResponseData {
            session_token: session_token.clone(),
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status: common_enums::AttemptStatus::Pending,
                session_token: Some(session_token),
                ..router_data.resource_common_data.clone()
            },
            response: Ok(session_response_data),
            ..router_data.clone()
        })
    }
}

// Sync Request Transformation
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        NuveiRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    > for NuveiSyncRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: NuveiRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;

        // Extract auth data
        let auth = NuveiAuthType::try_from(&router_data.connector_auth_type)?;

        let time_stamp = NuveiAuthType::get_timestamp();

        // Per Hyperswitch pattern: ALWAYS send both transaction_id AND client_unique_id
        let client_unique_id = router_data
            .resource_common_data
            .connector_request_reference_id
            .clone();
        let transaction_id = match &router_data.request.connector_transaction_id {
            ResponseId::ConnectorTransactionId(id) => id.clone(),
            ResponseId::EncodedData(id) => id.clone(),
            ResponseId::NoResponseId => {
                return Err(errors::ConnectorError::MissingConnectorTransactionID.into());
            }
        };

        // Generate checksum for getTransactionDetails: merchantId + merchantSiteId + transactionId + clientUniqueId + timeStamp + merchantSecretKey
        let checksum = auth.generate_checksum(&[
            auth.merchant_id.peek(),
            auth.merchant_site_id.peek(),
            &transaction_id,
            &client_unique_id,
            &time_stamp.to_string(),
        ]);

        Ok(Self {
            merchant_id: auth.merchant_id,
            merchant_site_id: auth.merchant_site_id,
            client_unique_id,
            transaction_id,
            time_stamp,
            checksum,
        })
    }
}

// Request Transformation
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        NuveiRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for NuveiPaymentRequest<T>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: NuveiRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;

        // Extract auth data
        let auth = NuveiAuthType::try_from(&router_data.connector_auth_type)?;

        // Extract payment method data
        let payment_option = match &router_data.request.payment_method_data {
            PaymentMethodData::Card(card_data) => {
                let card_holder_name = router_data
                    .resource_common_data
                    .get_optional_billing_full_name()
                    .or(router_data.request.customer_name.clone().map(Secret::new))
                    .unwrap_or(Secret::new("".to_string()));

                NuveiPaymentOption {
                    card: NuveiCard {
                        card_number: card_data.card_number.clone(),
                        card_holder_name,
                        expiration_month: card_data.card_exp_month.clone(),
                        expiration_year: card_data.card_exp_year.clone(),
                        cvv: card_data.card_cvc.clone(),
                    },
                }
            }
            _ => {
                return Err(errors::ConnectorError::NotImplemented(
                    "Payment method not supported".to_string(),
                )
                .into())
            }
        };

        // Extract billing address - Nuvei requires email, firstName, lastName, and country
        // Try to get email from billing, if not available, try from request email field
        let email = router_data
            .resource_common_data
            .get_optional_billing_email()
            .or_else(|| router_data.request.email.clone())
            .ok_or(errors::ConnectorError::MissingRequiredField {
                field_name: "billing_address.email",
            })?;

        let country = router_data
            .resource_common_data
            .get_optional_billing_country()
            .ok_or(errors::ConnectorError::MissingRequiredField {
                field_name: "billing_address.country",
            })?;

        // Get first and last name from billing, with fallback to cardholder name or default
        let first_name = router_data
            .resource_common_data
            .get_optional_billing_first_name()
            .unwrap_or_else(|| Secret::new("NA".to_string()));

        let last_name = router_data
            .resource_common_data
            .get_optional_billing_last_name()
            .unwrap_or_else(|| Secret::new("NA".to_string()));

        // Use state code conversion (e.g., "California" -> "CA") for US/CA
        let state = router_data
            .resource_common_data
            .get_billing_address()
            .ok()
            .and_then(|addr| addr.to_state_code_as_optional().ok())
            .flatten();

        let billing_address = NuveiBillingAddress {
            email,
            first_name,
            last_name,
            country: country.to_string(),
            phone: router_data
                .resource_common_data
                .get_optional_billing_phone_number(),
            city: router_data.resource_common_data.get_optional_billing_city(),
            address: router_data
                .resource_common_data
                .get_optional_billing_line1(),
            address_line2: router_data
                .resource_common_data
                .get_optional_billing_line2(),
            address_line3: None, // No line3 method available in resource_common_data
            zip: router_data.resource_common_data.get_optional_billing_zip(),
            state,
        };

        // Get device details - ipAddress is required by Nuvei
        let ip_address = router_data
            .request
            .browser_info
            .as_ref()
            .and_then(|browser| browser.ip_address.as_ref())
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "0.0.0.0".to_string()); // Default IP if not provided

        let device_details = NuveiDeviceDetails { ip_address };

        let time_stamp = NuveiAuthType::get_timestamp();
        let client_request_id = router_data
            .resource_common_data
            .connector_request_reference_id
            .clone();

        // Convert amount using the connector's amount converter
        let amount = item
            .connector
            .amount_converter_webhooks
            .convert(
                router_data.request.minor_amount,
                router_data.request.currency,
            )
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;

        let currency = router_data.request.currency.to_string();

        // Extract session token from PaymentFlowData
        // The CreateSessionToken flow runs before Authorize and populates this field
        let session_token = router_data
            .resource_common_data
            .session_token
            .clone()
            .ok_or(errors::ConnectorError::MissingRequiredField {
                field_name: "session_token",
            })?;

        // Determine transaction type based on capture method
        let transaction_type =
            TransactionType::get_from_capture_method(router_data.request.capture_method, &amount);

        // Generate checksum: merchantId + merchantSiteId + clientRequestId + amount + currency + timeStamp + merchantSecretKey
        let checksum = auth.generate_checksum(&[
            auth.merchant_id.peek(),
            auth.merchant_site_id.peek(),
            &client_request_id,
            &amount.get_amount_as_string(),
            &currency,
            &time_stamp.to_string(),
        ]);

        Ok(Self {
            session_token: Some(session_token),
            merchant_id: auth.merchant_id,
            merchant_site_id: auth.merchant_site_id,
            client_request_id,
            amount,
            currency,
            user_token_id: None,
            client_unique_id: Some(
                router_data
                    .resource_common_data
                    .connector_request_reference_id
                    .clone(),
            ),
            payment_option,
            transaction_type,
            device_details,
            billing_address,
            time_stamp,
            checksum,
        })
    }
}

// Response Transformation
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        ResponseRouterData<
            NuveiPaymentResponse,
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
            NuveiPaymentResponse,
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

        // Check if the overall request status is SUCCESS or ERROR
        if response.status.to_uppercase() == "ERROR" {
            let error_code = response.err_code.map(|c| c.to_string()).unwrap_or_default();
            let error_message = response
                .reason
                .clone()
                .unwrap_or_else(|| "Unknown error".to_string());

            return Ok(Self {
                resource_common_data: PaymentFlowData {
                    status: common_enums::AttemptStatus::Failure,
                    ..router_data.resource_common_data.clone()
                },
                response: Err(domain_types::router_data::ErrorResponse {
                    code: error_code,
                    message: error_message.clone(),
                    reason: Some(error_message),
                    status_code: item.http_code,
                    attempt_status: Some(common_enums::AttemptStatus::Failure),
                    connector_transaction_id: response.transaction_id.clone(),
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                }),
                ..router_data.clone()
            });
        }

        // Map transaction status to attempt status
        let status = match response.transaction_status.as_deref() {
            Some("APPROVED") => {
                if router_data.request.is_auto_capture()? {
                    common_enums::AttemptStatus::Charged
                } else {
                    common_enums::AttemptStatus::Authorized
                }
            }
            Some("DECLINED") => common_enums::AttemptStatus::Failure,
            Some("ERROR") => common_enums::AttemptStatus::Failure,
            Some("REDIRECT") => common_enums::AttemptStatus::AuthenticationPending,
            Some("PENDING") => common_enums::AttemptStatus::Pending,
            _ => {
                // If transaction_status is not present but status is SUCCESS, default to Pending
                if response.status.to_uppercase() == "SUCCESS" {
                    common_enums::AttemptStatus::Pending
                } else {
                    common_enums::AttemptStatus::Failure
                }
            }
        };

        // Get connector transaction ID
        let connector_transaction_id = response
            .transaction_id
            .clone()
            .or(response.order_id.clone())
            .ok_or(errors::ConnectorError::MissingConnectorTransactionID)?;

        let payments_response_data = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(connector_transaction_id),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: response.client_request_id.clone(),
            incremental_authorization_allowed: None,
            status_code: item.http_code,
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data.clone()
            },
            response: Ok(payments_response_data),
            ..router_data.clone()
        })
    }
}

// Capture Request Transformation
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        NuveiRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    > for NuveiCaptureRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: NuveiRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;

        // Extract auth data
        let auth = NuveiAuthType::try_from(&router_data.connector_auth_type)?;

        let time_stamp = NuveiAuthType::get_timestamp();
        let client_request_id = router_data
            .resource_common_data
            .connector_request_reference_id
            .clone();
        let client_unique_id = router_data
            .resource_common_data
            .connector_request_reference_id
            .clone();

        // Extract relatedTransactionId from connector_transaction_id
        let related_transaction_id = match &router_data.request.connector_transaction_id {
            ResponseId::ConnectorTransactionId(id) => id.clone(),
            ResponseId::EncodedData(id) => id.clone(),
            ResponseId::NoResponseId => {
                return Err(errors::ConnectorError::MissingConnectorTransactionID.into());
            }
        };

        // Convert amount using the connector's amount converter
        let amount = item
            .connector
            .amount_converter_webhooks
            .convert(
                router_data.request.minor_amount_to_capture,
                router_data.request.currency,
            )
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;

        let currency = router_data.request.currency.to_string();

        // Generate checksum: merchantId + merchantSiteId + clientRequestId + clientUniqueId + amount + currency + relatedTransactionId + timeStamp + merchantSecretKey
        let checksum = auth.generate_checksum(&[
            auth.merchant_id.peek(),
            auth.merchant_site_id.peek(),
            &client_request_id,
            &client_unique_id,
            &amount.get_amount_as_string(),
            &currency,
            &related_transaction_id,
            &time_stamp.to_string(),
        ]);

        Ok(Self {
            merchant_id: auth.merchant_id,
            merchant_site_id: auth.merchant_site_id,
            client_request_id,
            client_unique_id,
            amount,
            currency,
            related_transaction_id,
            time_stamp,
            checksum,
        })
    }
}

// PSync Response Transformation
impl
    TryFrom<
        ResponseRouterData<
            NuveiSyncResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    > for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            NuveiSyncResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let router_data = &item.router_data;

        // Check if the overall request status is SUCCESS or ERROR
        if response.status.to_uppercase() == "ERROR" {
            let error_code = response.err_code.map(|c| c.to_string()).unwrap_or_default();
            let error_message = response
                .reason
                .clone()
                .unwrap_or_else(|| "Unknown error".to_string());

            return Ok(Self {
                resource_common_data: PaymentFlowData {
                    status: common_enums::AttemptStatus::Failure,
                    ..router_data.resource_common_data.clone()
                },
                response: Err(domain_types::router_data::ErrorResponse {
                    code: error_code,
                    message: error_message.clone(),
                    reason: Some(error_message),
                    status_code: item.http_code,
                    attempt_status: Some(common_enums::AttemptStatus::Failure),
                    connector_transaction_id: response
                        .transaction_details
                        .as_ref()
                        .and_then(|td| td.transaction_id.clone()),
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                }),
                ..router_data.clone()
            });
        }

        // Extract transaction details
        let transaction_details = response.transaction_details.as_ref().ok_or(
            errors::ConnectorError::MissingRequiredField {
                field_name: "transaction_details",
            },
        )?;

        // Map transaction status to attempt status
        let status = match transaction_details.transaction_status.as_deref() {
            Some("APPROVED") | Some("Approved") => {
                // For PSync, we need to determine if it was authorized or captured
                // Check transaction_type: "Auth" means authorized only, "Sale" means captured
                match transaction_details.transaction_type.as_deref() {
                    Some("Auth") => common_enums::AttemptStatus::Authorized,
                    Some("Sale") | Some("Settle") => common_enums::AttemptStatus::Charged,
                    _ => common_enums::AttemptStatus::Charged, // Default to Charged for unknown types
                }
            }
            Some("DECLINED") | Some("Declined") => common_enums::AttemptStatus::Failure,
            Some("ERROR") | Some("Error") => common_enums::AttemptStatus::Failure,
            Some("REDIRECT") | Some("Redirect") => {
                common_enums::AttemptStatus::AuthenticationPending
            }
            Some("PENDING") | Some("Pending") => common_enums::AttemptStatus::Pending,
            _ => {
                // If transaction_status is not present but status is SUCCESS, default to Pending
                if response.status.to_uppercase() == "SUCCESS" {
                    common_enums::AttemptStatus::Pending
                } else {
                    common_enums::AttemptStatus::Failure
                }
            }
        };

        // Get connector transaction ID from transaction_details
        let connector_transaction_id = transaction_details
            .transaction_id
            .clone()
            .ok_or(errors::ConnectorError::MissingConnectorTransactionID)?;

        let payments_response_data = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(connector_transaction_id),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: transaction_details.client_unique_id.clone(),
            incremental_authorization_allowed: None,
            status_code: item.http_code,
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data.clone()
            },
            response: Ok(payments_response_data),
            ..router_data.clone()
        })
    }
}

// Capture Response Transformation
impl
    TryFrom<
        ResponseRouterData<
            NuveiCaptureResponse,
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    > for RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            NuveiCaptureResponse,
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let router_data = &item.router_data;

        // Check if the overall request status is SUCCESS or ERROR
        if response.status.to_uppercase() == "ERROR" {
            let error_code = response.err_code.map(|c| c.to_string()).unwrap_or_default();
            let error_message = response
                .reason
                .clone()
                .unwrap_or_else(|| "Unknown error".to_string());

            return Ok(Self {
                resource_common_data: PaymentFlowData {
                    status: common_enums::AttemptStatus::Failure,
                    ..router_data.resource_common_data.clone()
                },
                response: Err(domain_types::router_data::ErrorResponse {
                    code: error_code,
                    message: error_message.clone(),
                    reason: Some(error_message),
                    status_code: item.http_code,
                    attempt_status: Some(common_enums::AttemptStatus::Failure),
                    connector_transaction_id: response.transaction_id.clone(),
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                }),
                ..router_data.clone()
            });
        }

        // Map transaction status to attempt status
        let status = match response.transaction_status.as_deref() {
            Some("APPROVED") => common_enums::AttemptStatus::Charged,
            Some("DECLINED") => common_enums::AttemptStatus::Failure,
            Some("ERROR") => common_enums::AttemptStatus::Failure,
            Some("PENDING") => common_enums::AttemptStatus::Pending,
            _ => {
                // If transaction_status is not present but status is SUCCESS, default to Charged
                if response.status.to_uppercase() == "SUCCESS" {
                    common_enums::AttemptStatus::Charged
                } else {
                    common_enums::AttemptStatus::Failure
                }
            }
        };

        // Get connector transaction ID
        let connector_transaction_id = response
            .transaction_id
            .clone()
            .ok_or(errors::ConnectorError::MissingConnectorTransactionID)?;

        let payments_response_data = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(connector_transaction_id),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: None,
            incremental_authorization_allowed: None,
            status_code: item.http_code,
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data.clone()
            },
            response: Ok(payments_response_data),
            ..router_data.clone()
        })
    }
}

// Refund Request Transformation
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        NuveiRouterData<RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>, T>,
    > for NuveiRefundRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: NuveiRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;

        // Extract auth data
        let auth = NuveiAuthType::try_from(&router_data.connector_auth_type)?;

        let time_stamp = NuveiAuthType::get_timestamp();
        let client_request_id = router_data
            .resource_common_data
            .connector_request_reference_id
            .clone();
        let client_unique_id = router_data
            .resource_common_data
            .connector_request_reference_id
            .clone();

        // Extract relatedTransactionId from connector_transaction_id
        let related_transaction_id = router_data.request.connector_transaction_id.clone();

        // Convert amount using the connector's amount converter
        let amount = item
            .connector
            .amount_converter_webhooks
            .convert(
                common_utils::types::MinorUnit::new(router_data.request.refund_amount),
                router_data.request.currency,
            )
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;

        let currency = router_data.request.currency.to_string();

        // Generate checksum: merchantId + merchantSiteId + clientRequestId + clientUniqueId + amount + currency + relatedTransactionId + timeStamp + merchantSecretKey
        let checksum = auth.generate_checksum(&[
            auth.merchant_id.peek(),
            auth.merchant_site_id.peek(),
            &client_request_id,
            &client_unique_id,
            &amount.get_amount_as_string(),
            &currency,
            &related_transaction_id,
            &time_stamp.to_string(),
        ]);

        Ok(Self {
            merchant_id: auth.merchant_id,
            merchant_site_id: auth.merchant_site_id,
            client_request_id,
            client_unique_id,
            amount,
            currency,
            related_transaction_id,
            time_stamp,
            checksum,
        })
    }
}

// Refund Sync Request Transformation
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        NuveiRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    > for NuveiRefundSyncRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: NuveiRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;

        // Extract auth data
        let auth = NuveiAuthType::try_from(&router_data.connector_auth_type)?;

        let time_stamp = NuveiAuthType::get_timestamp();

        // Per Hyperswitch pattern: ALWAYS send both transaction_id AND client_unique_id
        // NOTE: For RSync to work correctly, we need the ORIGINAL clientUniqueId from refund creation
        // Using current connector_request_reference_id may not match the original
        let client_unique_id = router_data
            .resource_common_data
            .connector_request_reference_id
            .clone();
        let transaction_id = router_data.request.connector_transaction_id.clone();

        if transaction_id.is_empty() {
            return Err(errors::ConnectorError::MissingConnectorTransactionID.into());
        }

        // Generate checksum for getTransactionDetails (per Hyperswitch PSync pattern)
        // Checksum order: merchantId + merchantSiteId + clientUniqueId + timeStamp + transactionId + merchantSecretKey
        let checksum = auth.generate_checksum(&[
            auth.merchant_id.peek(),
            auth.merchant_site_id.peek(),
            &client_unique_id,
            &time_stamp.to_string(),
            &transaction_id,
        ]);

        Ok(Self {
            merchant_id: auth.merchant_id,
            merchant_site_id: auth.merchant_site_id,
            client_unique_id,
            transaction_id,
            time_stamp,
            checksum,
        })
    }
}

// Refund Response Transformation
impl
    TryFrom<
        ResponseRouterData<
            NuveiRefundResponse,
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    > for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            NuveiRefundResponse,
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let router_data = &item.router_data;

        // Check if the overall request status is SUCCESS or ERROR
        if response.status.to_uppercase() == "ERROR" {
            let error_code = response.err_code.map(|c| c.to_string()).unwrap_or_default();
            let error_message = response
                .reason
                .clone()
                .unwrap_or_else(|| "Unknown error".to_string());

            return Ok(Self {
                resource_common_data: RefundFlowData {
                    status: common_enums::RefundStatus::Failure,
                    ..router_data.resource_common_data.clone()
                },
                response: Err(domain_types::router_data::ErrorResponse {
                    code: error_code,
                    message: error_message.clone(),
                    reason: Some(error_message),
                    status_code: item.http_code,
                    attempt_status: None,
                    connector_transaction_id: response.transaction_id.clone(),
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                }),
                ..router_data.clone()
            });
        }

        // Map transaction status to refund status
        let refund_status = match response.transaction_status.as_deref() {
            Some("APPROVED") => common_enums::RefundStatus::Success,
            Some("DECLINED") => common_enums::RefundStatus::Failure,
            Some("ERROR") => common_enums::RefundStatus::Failure,
            Some("PENDING") => common_enums::RefundStatus::Pending,
            _ => {
                // If transaction_status is not present but status is SUCCESS, default to Success
                if response.status.to_uppercase() == "SUCCESS" {
                    common_enums::RefundStatus::Success
                } else {
                    common_enums::RefundStatus::Failure
                }
            }
        };

        // Get connector refund ID
        let connector_refund_id = response
            .transaction_id
            .clone()
            .ok_or(errors::ConnectorError::MissingConnectorTransactionID)?;

        let refunds_response_data = RefundsResponseData {
            connector_refund_id,
            refund_status,
            status_code: item.http_code,
        };

        Ok(Self {
            resource_common_data: RefundFlowData {
                status: refund_status,
                ..router_data.resource_common_data.clone()
            },
            response: Ok(refunds_response_data),
            ..router_data.clone()
        })
    }
}

// Refund Sync Response Transformation
impl
    TryFrom<
        ResponseRouterData<
            NuveiRefundSyncResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    > for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            NuveiRefundSyncResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let router_data = &item.router_data;

        // Check if the overall request status is SUCCESS or ERROR
        if response.status.to_uppercase() == "ERROR" {
            let error_code = response.err_code.map(|c| c.to_string()).unwrap_or_default();
            let error_message = response
                .reason
                .clone()
                .unwrap_or_else(|| "Unknown error".to_string());

            return Ok(Self {
                resource_common_data: RefundFlowData {
                    status: common_enums::RefundStatus::Failure,
                    ..router_data.resource_common_data.clone()
                },
                response: Err(domain_types::router_data::ErrorResponse {
                    code: error_code,
                    message: error_message.clone(),
                    reason: Some(error_message),
                    status_code: item.http_code,
                    attempt_status: None,
                    connector_transaction_id: response.transaction_id.clone(),
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                }),
                ..router_data.clone()
            });
        }

        // Map transaction status to refund status
        let refund_status = match response.transaction_status.as_deref() {
            Some("APPROVED") => common_enums::RefundStatus::Success,
            Some("DECLINED") => common_enums::RefundStatus::Failure,
            Some("ERROR") => common_enums::RefundStatus::Failure,
            Some("PENDING") => common_enums::RefundStatus::Pending,
            _ => {
                // If transaction_status is not present but status is SUCCESS, default to Success
                if response.status.to_uppercase() == "SUCCESS" {
                    common_enums::RefundStatus::Success
                } else {
                    common_enums::RefundStatus::Failure
                }
            }
        };

        // Get connector refund ID
        let connector_refund_id = response
            .transaction_id
            .clone()
            .ok_or(errors::ConnectorError::MissingConnectorTransactionID)?;

        let refunds_response_data = RefundsResponseData {
            connector_refund_id,
            refund_status,
            status_code: item.http_code,
        };

        Ok(Self {
            resource_common_data: RefundFlowData {
                status: refund_status,
                ..router_data.resource_common_data.clone()
            },
            response: Ok(refunds_response_data),
            ..router_data.clone()
        })
    }
}

// Void Request Transformation
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        NuveiRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    > for NuveiVoidRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: NuveiRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;

        // Extract auth data
        let auth = NuveiAuthType::try_from(&router_data.connector_auth_type)?;

        let time_stamp = NuveiAuthType::get_timestamp();
        let client_request_id = router_data
            .resource_common_data
            .connector_request_reference_id
            .clone();
        let client_unique_id = router_data
            .resource_common_data
            .connector_request_reference_id
            .clone();

        // Extract relatedTransactionId from connector_transaction_id
        let related_transaction_id = router_data.request.connector_transaction_id.clone();

        // Generate checksum: merchantId + merchantSiteId + clientRequestId + clientUniqueId + "" + "" + relatedTransactionId + "" + "" + timeStamp + merchantSecretKey
        let checksum = auth.generate_checksum(&[
            auth.merchant_id.peek(),
            auth.merchant_site_id.peek(),
            &client_request_id,
            &client_unique_id,
            "", // amount (empty for void)
            "", // currency (empty for void)
            &related_transaction_id,
            "", // authCode (empty)
            "", // comment (empty)
            &time_stamp.to_string(),
        ]);

        Ok(Self {
            merchant_id: auth.merchant_id,
            merchant_site_id: auth.merchant_site_id,
            client_request_id,
            client_unique_id,
            related_transaction_id,
            time_stamp,
            checksum,
        })
    }
}

// Void Response Transformation
impl
    TryFrom<
        ResponseRouterData<
            NuveiVoidResponse,
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        >,
    > for RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            NuveiVoidResponse,
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let router_data = &item.router_data;

        // Check if the overall request status is SUCCESS or ERROR
        if response.status.to_uppercase() == "ERROR" {
            let error_code = response.err_code.map(|c| c.to_string()).unwrap_or_default();
            let error_message = response
                .reason
                .clone()
                .unwrap_or_else(|| "Unknown error".to_string());

            return Ok(Self {
                resource_common_data: PaymentFlowData {
                    status: common_enums::AttemptStatus::VoidFailed,
                    ..router_data.resource_common_data.clone()
                },
                response: Err(domain_types::router_data::ErrorResponse {
                    code: error_code,
                    message: error_message.clone(),
                    reason: Some(error_message),
                    status_code: item.http_code,
                    attempt_status: Some(common_enums::AttemptStatus::VoidFailed),
                    connector_transaction_id: response.transaction_id.clone(),
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                }),
                ..router_data.clone()
            });
        }

        // Map transaction status to attempt status
        let status = match response.transaction_status.as_deref() {
            Some("APPROVED") => common_enums::AttemptStatus::Voided,
            Some("DECLINED") => common_enums::AttemptStatus::VoidFailed,
            Some("ERROR") => common_enums::AttemptStatus::VoidFailed,
            Some("PENDING") => common_enums::AttemptStatus::Pending,
            _ => {
                // If transaction_status is not present but status is SUCCESS, default to Voided
                if response.status.to_uppercase() == "SUCCESS" {
                    common_enums::AttemptStatus::Voided
                } else {
                    common_enums::AttemptStatus::VoidFailed
                }
            }
        };

        // Get connector transaction ID
        let connector_transaction_id = response
            .transaction_id
            .clone()
            .ok_or(errors::ConnectorError::MissingConnectorTransactionID)?;

        let payments_response_data = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(connector_transaction_id),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: None,
            incremental_authorization_allowed: None,
            status_code: item.http_code,
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data.clone()
            },
            response: Ok(payments_response_data),
            ..router_data.clone()
        })
    }
}
