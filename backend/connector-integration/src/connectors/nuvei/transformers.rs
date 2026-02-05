use common_utils::{ext_traits::ByteSliceExt, pii, types::StringMajorUnit};
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
use serde_urlencoded;

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
    pub status: NuveiPaymentStatus,
    pub err_code: Option<i32>,
    pub reason: Option<String>,
    pub merchant_id: Option<String>,
    pub merchant_site_id: Option<String>,
    pub version: Option<String>,
    pub client_request_id: Option<String>,
}

// URL Details for redirect URLs
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NuveiUrlDetails {
    pub success_url: String,
    pub failure_url: String,
    pub pending_url: String,
}

// Payment Request
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NuveiPaymentRequest<
    T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize,
> {
    pub session_token: Option<String>,
    pub merchant_id: Secret<String>,
    pub merchant_site_id: Secret<String>,
    pub client_request_id: String,
    pub amount: StringMajorUnit,
    pub currency: common_enums::Currency,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_token_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_unique_id: Option<String>,
    pub payment_option: NuveiPaymentOption<T>,
    pub transaction_type: TransactionType,
    pub device_details: NuveiDeviceDetails,
    pub billing_address: NuveiBillingAddress,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url_details: Option<NuveiUrlDetails>,
    pub time_stamp: common_utils::date_time::DateTime<common_utils::date_time::YYYYMMDDHHmmss>,
    pub checksum: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NuveiPaymentOption<
    T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize,
> {
    pub card: NuveiCard<T>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NuveiCard<
    T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize,
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
    pub ip_address: Secret<String, pii::IpAddress>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NuveiBillingAddress {
    // Required fields per Nuvei documentation
    pub email: pii::Email,
    pub country: String,
    // Optional fields
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_name: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_name: Option<Secret<String>>,
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
    pub transaction_status: Option<NuveiTransactionStatus>,
    pub status: NuveiPaymentStatus,
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

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum NuveiPaymentStatus {
    Success,
    Failed,
    Error,
    #[default]
    Processing,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum NuveiTransactionStatus {
    #[serde(alias = "Approved", alias = "APPROVED")]
    Approved,
    #[serde(alias = "Declined", alias = "DECLINED")]
    Declined,
    #[serde(alias = "Filter Error", alias = "ERROR", alias = "Error")]
    Error,
    #[serde(alias = "Redirect", alias = "REDIRECT")]
    Redirect,
    #[serde(alias = "Pending", alias = "PENDING")]
    Pending,
    #[serde(alias = "Processing", alias = "PROCESSING")]
    #[default]
    Processing,
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
    pub status: NuveiPaymentStatus,
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
    pub transaction_status: Option<NuveiTransactionStatus>,
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
    pub currency: common_enums::Currency,
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
    pub status: NuveiPaymentStatus,
    pub transaction_status: Option<NuveiTransactionStatus>,
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
    pub currency: common_enums::Currency,
    pub related_transaction_id: String,
    pub time_stamp: common_utils::date_time::DateTime<common_utils::date_time::YYYYMMDDHHmmss>,
    pub checksum: String,
}

// Refund Response
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NuveiRefundResponse {
    pub transaction_id: Option<String>,
    pub transaction_status: Option<NuveiTransactionStatus>,
    pub status: NuveiPaymentStatus,
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
    pub transaction_status: Option<NuveiTransactionStatus>,
    pub status: NuveiPaymentStatus,
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
    pub amount: StringMajorUnit,
    pub currency: common_enums::Currency,
    pub related_transaction_id: String,
    pub time_stamp: common_utils::date_time::DateTime<common_utils::date_time::YYYYMMDDHHmmss>,
    pub checksum: String,
}

// Void Response
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NuveiVoidResponse {
    pub transaction_id: Option<String>,
    pub transaction_status: Option<NuveiTransactionStatus>,
    pub status: NuveiPaymentStatus,
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
impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
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
impl TryFrom<ResponseRouterData<NuveiSessionTokenResponse, Self>>
    for RouterDataV2<
        domain_types::connector_flow::CreateSessionToken,
        PaymentFlowData,
        domain_types::connector_types::SessionTokenRequestData,
        domain_types::connector_types::SessionTokenResponseData,
    >
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<NuveiSessionTokenResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let router_data = &item.router_data;

        // Check if the overall request status is SUCCESS or ERROR
        if matches!(response.status, NuveiPaymentStatus::Error) {
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
impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
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
impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
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
                    .ok_or(errors::ConnectorError::MissingRequiredField {
                        field_name: "billing_address.first_name and billing_address.last_name or customer_name",
                    })?;

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
                return Err(errors::ConnectorError::NotSupported {
                    message: "Payment method not supported".to_string(),
                    connector: "nuvei",
                }
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

        // Get first and last name from billing (optional fields)
        let first_name = router_data
            .resource_common_data
            .get_optional_billing_first_name();

        let last_name = router_data
            .resource_common_data
            .get_optional_billing_last_name();

        // Use state code conversion (e.g., "California" -> "CA") for US/CA
        let state = router_data
            .resource_common_data
            .get_optional_billing_state();

        // Get address_line3 directly from billing address
        let address_line3 = router_data
            .resource_common_data
            .get_optional_billing()
            .and_then(|billing| billing.address.as_ref())
            .and_then(|addr| addr.line3.clone());

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
            address_line3,
            zip: router_data.resource_common_data.get_optional_billing_zip(),
            state,
        };

        // Get device details - ipAddress is required by Nuvei
        let ip_address = router_data
            .request
            .browser_info
            .as_ref()
            .ok_or(errors::ConnectorError::MissingRequiredField {
                field_name: "browser_info",
            })?
            .ip_address
            .ok_or(errors::ConnectorError::MissingRequiredField {
                field_name: "browser_info.ip_address",
            })?;

        let device_details = NuveiDeviceDetails {
            ip_address: Secret::new(ip_address.to_string()),
        };

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

        let currency = router_data.request.currency;

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

        // Build urlDetails from router_return_url if available
        let url_details =
            router_data
                .request
                .router_return_url
                .as_ref()
                .map(|url| NuveiUrlDetails {
                    success_url: url.clone(),
                    failure_url: url.clone(),
                    pending_url: url.clone(),
                });

        // Generate checksum: merchantId + merchantSiteId + clientRequestId + amount + currency + timeStamp + merchantSecretKey
        let checksum = auth.generate_checksum(&[
            auth.merchant_id.peek(),
            auth.merchant_site_id.peek(),
            &client_request_id,
            &amount.get_amount_as_string(),
            &currency.to_string(),
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
            url_details,
            time_stamp,
            checksum,
        })
    }
}

// Response Transformation
impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<ResponseRouterData<NuveiPaymentResponse, Self>>
    for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: ResponseRouterData<NuveiPaymentResponse, Self>) -> Result<Self, Self::Error> {
        let response = &item.response;
        let router_data = &item.router_data;

        // Check if the overall request status is SUCCESS or ERROR
        if matches!(response.status, NuveiPaymentStatus::Error) {
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
        let status = match response.transaction_status {
            Some(NuveiTransactionStatus::Approved) => {
                if router_data.request.is_auto_capture()? {
                    common_enums::AttemptStatus::Charged
                } else {
                    common_enums::AttemptStatus::Authorized
                }
            }
            Some(NuveiTransactionStatus::Declined) => common_enums::AttemptStatus::Failure,
            Some(NuveiTransactionStatus::Error) => common_enums::AttemptStatus::Failure,
            Some(NuveiTransactionStatus::Redirect) => {
                common_enums::AttemptStatus::AuthenticationPending
            }
            Some(NuveiTransactionStatus::Pending) => common_enums::AttemptStatus::Pending,
            _ => {
                // If transaction_status is not present but status is SUCCESS, default to Pending
                if matches!(response.status, NuveiPaymentStatus::Success) {
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
impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
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

        let currency = router_data.request.currency;

        // Generate checksum: merchantId + merchantSiteId + clientRequestId + clientUniqueId + amount + currency + relatedTransactionId + timeStamp + merchantSecretKey
        let checksum = auth.generate_checksum(&[
            auth.merchant_id.peek(),
            auth.merchant_site_id.peek(),
            &client_request_id,
            &client_unique_id,
            &amount.get_amount_as_string(),
            &currency.to_string(),
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
impl TryFrom<ResponseRouterData<NuveiSyncResponse, Self>>
    for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: ResponseRouterData<NuveiSyncResponse, Self>) -> Result<Self, Self::Error> {
        let response = &item.response;
        let router_data = &item.router_data;

        // Check if the overall request status is SUCCESS or ERROR
        if matches!(response.status, NuveiPaymentStatus::Error) {
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
        let status = match transaction_details.transaction_status {
            Some(NuveiTransactionStatus::Approved) => {
                // For PSync, we need to determine if it was authorized or captured
                // Check transaction_type: "Auth" means authorized only, "Sale" means captured
                match transaction_details.transaction_type.as_deref() {
                    Some("Auth") => common_enums::AttemptStatus::Authorized,
                    Some("Sale") | Some("Settle") => common_enums::AttemptStatus::Charged,
                    _ => common_enums::AttemptStatus::Charged, // Default to Charged for unknown types
                }
            }
            Some(NuveiTransactionStatus::Declined) => common_enums::AttemptStatus::Failure,
            Some(NuveiTransactionStatus::Error) => common_enums::AttemptStatus::Failure,
            Some(NuveiTransactionStatus::Redirect) => {
                common_enums::AttemptStatus::AuthenticationPending
            }
            Some(NuveiTransactionStatus::Pending) => common_enums::AttemptStatus::Pending,
            _ => {
                // If transaction_status is not present but status is SUCCESS, default to Pending
                if matches!(response.status, NuveiPaymentStatus::Success) {
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
impl TryFrom<ResponseRouterData<NuveiCaptureResponse, Self>>
    for RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: ResponseRouterData<NuveiCaptureResponse, Self>) -> Result<Self, Self::Error> {
        let response = &item.response;
        let router_data = &item.router_data;

        // Check if the overall request status is SUCCESS or ERROR
        if matches!(response.status, NuveiPaymentStatus::Error) {
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
        let status = match response.transaction_status {
            Some(NuveiTransactionStatus::Approved) => common_enums::AttemptStatus::Charged,
            Some(NuveiTransactionStatus::Declined) => common_enums::AttemptStatus::Failure,
            Some(NuveiTransactionStatus::Error) => common_enums::AttemptStatus::Failure,
            Some(NuveiTransactionStatus::Pending) => common_enums::AttemptStatus::Pending,
            _ => {
                // If transaction_status is not present but status is SUCCESS, default to Charged
                if matches!(response.status, NuveiPaymentStatus::Success) {
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
impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
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

        let currency = router_data.request.currency;

        // Generate checksum: merchantId + merchantSiteId + clientRequestId + clientUniqueId + amount + currency + relatedTransactionId + timeStamp + merchantSecretKey
        let checksum = auth.generate_checksum(&[
            auth.merchant_id.peek(),
            auth.merchant_site_id.peek(),
            &client_request_id,
            &client_unique_id,
            &amount.get_amount_as_string(),
            &currency.to_string(),
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
impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
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

// Refund Response Transformation
impl TryFrom<ResponseRouterData<NuveiRefundResponse, Self>>
    for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: ResponseRouterData<NuveiRefundResponse, Self>) -> Result<Self, Self::Error> {
        let response = &item.response;
        let router_data = &item.router_data;

        // Check if the overall request status is SUCCESS or ERROR
        if matches!(response.status, NuveiPaymentStatus::Error) {
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
        let refund_status = match response.transaction_status {
            Some(NuveiTransactionStatus::Approved) => common_enums::RefundStatus::Success,
            Some(NuveiTransactionStatus::Declined) => common_enums::RefundStatus::Failure,
            Some(NuveiTransactionStatus::Error) => common_enums::RefundStatus::Failure,
            Some(NuveiTransactionStatus::Pending) => common_enums::RefundStatus::Pending,
            _ => {
                // If transaction_status is not present but status is SUCCESS, default to Success
                if matches!(response.status, NuveiPaymentStatus::Success) {
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
impl TryFrom<ResponseRouterData<NuveiRefundSyncResponse, Self>>
    for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<NuveiRefundSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let router_data = &item.router_data;

        // Check if the overall request status is SUCCESS or ERROR
        if matches!(response.status, NuveiPaymentStatus::Error) {
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
        let refund_status = match response.transaction_status {
            Some(NuveiTransactionStatus::Approved) => common_enums::RefundStatus::Success,
            Some(NuveiTransactionStatus::Declined) => common_enums::RefundStatus::Failure,
            Some(NuveiTransactionStatus::Error) => common_enums::RefundStatus::Failure,
            Some(NuveiTransactionStatus::Pending) => common_enums::RefundStatus::Pending,
            _ => {
                // If transaction_status is not present but status is SUCCESS, default to Success
                if matches!(response.status, NuveiPaymentStatus::Success) {
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
impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
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

        // Extract amount and currency from the request
        // For void, we need to send the original transaction amount and currency
        let minor_amount =
            router_data
                .request
                .amount
                .ok_or(errors::ConnectorError::MissingRequiredField {
                    field_name: "amount",
                })?;

        let currency =
            router_data
                .request
                .currency
                .ok_or(errors::ConnectorError::MissingRequiredField {
                    field_name: "currency",
                })?;

        let amount = item
            .connector
            .amount_converter_webhooks
            .convert(minor_amount, currency)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;

        // Generate checksum: merchantId + merchantSiteId + clientRequestId + clientUniqueId + amount + currency + relatedTransactionId + "" + "" + timeStamp + merchantSecretKey
        let checksum = auth.generate_checksum(&[
            auth.merchant_id.peek(),
            auth.merchant_site_id.peek(),
            &client_request_id,
            &client_unique_id,
            &amount.get_amount_as_string(),
            &currency.to_string(),
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
            amount,
            currency,
            related_transaction_id,
            time_stamp,
            checksum,
        })
    }
}

// Void Response Transformation
impl TryFrom<ResponseRouterData<NuveiVoidResponse, Self>>
    for RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: ResponseRouterData<NuveiVoidResponse, Self>) -> Result<Self, Self::Error> {
        let response = &item.response;
        let router_data = &item.router_data;

        // Check if the overall request status is SUCCESS or ERROR
        if matches!(response.status, NuveiPaymentStatus::Error) {
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
        let status = match response.transaction_status {
            Some(NuveiTransactionStatus::Approved) => common_enums::AttemptStatus::Voided,
            Some(NuveiTransactionStatus::Declined) => common_enums::AttemptStatus::VoidFailed,
            Some(NuveiTransactionStatus::Error) => common_enums::AttemptStatus::VoidFailed,
            Some(NuveiTransactionStatus::Pending) => common_enums::AttemptStatus::Pending,
            _ => {
                // If transaction_status is not present but status is SUCCESS, default to Voided
                if matches!(response.status, NuveiPaymentStatus::Success) {
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

// ============================================================================
// WEBHOOK TYPES AND FUNCTIONS
// ============================================================================

/// Represents the transaction type in Nuvei webhooks
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub enum NuveiTransactionType {
    Auth,
    Sale,
    Credit,
    Auth3D,
    InitAuth3D,
    Settle,
    Void,
}

/// Represents the overall status of the DMN
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum DmnStatus {
    Success,
    Approved,
    Error,
    Pending,
    Declined,
}

/// Represents the transaction status of the DMN
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum DmnApiTransactionStatus {
    Ok,
    Fail,
    Pending,
}

/// Represents any possible webhook notification from Nuvei
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum NuveiWebhook {
    PaymentDmn(PaymentDmnNotification),
    Chargeback(ChargebackNotification),
}

/// Represents a Payment Direct Merchant Notification (DMN) webhook
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentDmnNotification {
    // Status of the Api transaction
    #[serde(rename = "ppp_status")]
    pub ppp_status: DmnApiTransactionStatus,
    #[serde(rename = "PPP_TransactionID")]
    pub ppp_transaction_id: String,
    pub total_amount: String,
    pub currency: String,
    #[serde(rename = "TransactionID")]
    pub transaction_id: Option<String>,
    // Status of the Payment
    #[serde(rename = "Status")]
    pub status: Option<DmnStatus>,
    pub transaction_type: Option<NuveiTransactionType>,
    #[serde(rename = "ErrCode")]
    pub err_code: Option<String>,
    #[serde(rename = "Reason")]
    pub reason: Option<String>,
    #[serde(rename = "ReasonCode")]
    pub reason_code: Option<String>,
    #[serde(rename = "user_token_id")]
    pub user_token_id: Option<String>,
    #[serde(rename = "payment_method")]
    pub payment_method: Option<String>,
    #[serde(rename = "responseTimeStamp")]
    pub response_time_stamp: String,
    #[serde(rename = "merchant_id")]
    pub merchant_id: Option<Secret<String>>,
    #[serde(rename = "merchant_site_id")]
    pub merchant_site_id: Option<Secret<String>>,
    #[serde(rename = "responsechecksum")]
    pub response_checksum: Option<String>,
    #[serde(rename = "advanceResponseChecksum")]
    pub advance_response_checksum: Option<String>,
    pub product_id: Option<String>,
    pub merchant_advice_code: Option<String>,
    #[serde(rename = "AuthCode")]
    pub auth_code: Option<String>,
    pub acquirer_bank: Option<String>,
    pub client_request_id: Option<String>,
}

/// Represents a Chargeback webhook notification from the Nuvei Control Panel
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ChargebackNotification {
    pub client_name: Option<String>,
    pub event_date_u_t_c: Option<String>,
    pub event_correlation_id: Option<String>,
    pub chargeback: ChargebackData,
    pub transaction_details: ChargebackTransactionDetails,
    pub event_id: Option<String>,
    pub processing_entity_type: Option<String>,
    pub processing_entity_id: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ChargebackData {
    #[serde(with = "common_utils::custom_serde::iso8601::option")]
    pub date: Option<time::PrimitiveDateTime>,
    pub chargeback_status_category: Option<ChargebackStatusCategory>,
    #[serde(rename = "Type")]
    pub webhook_type: Option<ChargebackType>,
    pub status: Option<String>,
    pub amount: common_utils::types::FloatMajorUnit,
    pub currency: String,
    pub reported_amount: common_utils::types::FloatMajorUnit,
    pub reported_currency: String,
    pub chargeback_reason: Option<String>,
    pub chargeback_reason_category: Option<String>,
    pub reason_message: Option<String>,
    pub dispute_id: Option<String>,
    #[serde(with = "common_utils::custom_serde::iso8601::option")]
    pub dispute_due_date: Option<time::PrimitiveDateTime>,
    pub dispute_event_id: Option<String>,
    pub dispute_unified_status_code: Option<DisputeUnifiedStatusCode>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ChargebackTransactionDetails {
    pub transaction_id: i64,
    pub transaction_date: Option<String>,
    pub client_unique_id: Option<String>,
    pub acquirer_name: Option<String>,
    pub masked_card_number: Option<String>,
    pub arn: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum ChargebackType {
    Chargeback,
    Retrieval,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ChargebackStatusCategory {
    #[serde(rename = "Regular")]
    Regular,
    #[serde(rename = "cancelled")]
    Cancelled,
    #[serde(rename = "Duplicate")]
    Duplicate,
    #[serde(rename = "RDR-Refund")]
    RdrRefund,
    #[serde(rename = "Soft_CB")]
    SoftCb,
}

/// Dispute unified status codes from Nuvei
#[derive(Debug, Clone, Serialize, Deserialize, strum::Display)]
pub enum DisputeUnifiedStatusCode {
    #[serde(rename = "FC")]
    FirstChargebackInitiatedByIssuer,
    #[serde(rename = "CC")]
    CreditChargebackInitiatedByIssuer,
    #[serde(rename = "CC-A-ACPT")]
    CreditChargebackAcceptedAutomatically,
    #[serde(rename = "FC-A-EPRD")]
    FirstChargebackNoResponseExpired,
    #[serde(rename = "FC-M-ACPT")]
    FirstChargebackAcceptedByMerchant,
    #[serde(rename = "FC-A-ACPT")]
    FirstChargebackAcceptedAutomatically,
    #[serde(rename = "FC-A-ACPT-MCOLL")]
    FirstChargebackAcceptedAutomaticallyMcoll,
    #[serde(rename = "FC-M-PART")]
    FirstChargebackPartiallyAcceptedByMerchant,
    #[serde(rename = "FC-M-PART-EXP")]
    FirstChargebackPartiallyAcceptedByMerchantExpired,
    #[serde(rename = "FC-M-RJCT")]
    FirstChargebackRejectedByMerchant,
    #[serde(rename = "FC-M-RJCT-EXP")]
    FirstChargebackRejectedByMerchantExpired,
    #[serde(rename = "FC-A-RJCT")]
    FirstChargebackRejectedAutomatically,
    #[serde(rename = "FC-A-RJCT-EXP")]
    FirstChargebackRejectedAutomaticallyExpired,
    #[serde(rename = "IPA")]
    PreArbitrationInitiatedByIssuer,
    #[serde(rename = "MPA-I-ACPT")]
    MerchantPreArbitrationAcceptedByIssuer,
    #[serde(rename = "MPA-I-RJCT")]
    MerchantPreArbitrationRejectedByIssuer,
    #[serde(rename = "MPA-I-PART")]
    MerchantPreArbitrationPartiallyAcceptedByIssuer,
    #[serde(rename = "FC-CLSD-MF")]
    FirstChargebackClosedMerchantFavour,
    #[serde(rename = "FC-CLSD-CHF")]
    FirstChargebackClosedCardholderFavour,
    #[serde(rename = "FC-CLSD-RCL")]
    FirstChargebackClosedRecall,
    #[serde(rename = "FC-I-RCL")]
    FirstChargebackRecalledByIssuer,
    #[serde(rename = "PA-CLSD-MF")]
    PreArbitrationClosedMerchantFavour,
    #[serde(rename = "PA-CLSD-CHF")]
    PreArbitrationClosedCardholderFavour,
    #[serde(rename = "RDR")]
    Rdr,
    #[serde(rename = "FC-SPCSE")]
    FirstChargebackDisputeResponseNotAllowed,
    #[serde(rename = "MCC")]
    McCollaborationInitiatedByIssuer,
    #[serde(rename = "MCC-A-RJCT")]
    McCollaborationPreviouslyRefundedAuto,
    #[serde(rename = "MCC-M-ACPT")]
    McCollaborationRefundedByMerchant,
    #[serde(rename = "MCC-EXPR")]
    McCollaborationExpired,
    #[serde(rename = "MCC-M-RJCT")]
    McCollaborationRejectedByMerchant,
    #[serde(rename = "MCC-A-ACPT")]
    McCollaborationAutomaticAccept,
    #[serde(rename = "MCC-CLSD-MF")]
    McCollaborationClosedMerchantFavour,
    #[serde(rename = "MCC-CLSD-CHF")]
    McCollaborationClosedCardholderFavour,
    #[serde(rename = "INQ")]
    InquiryInitiatedByIssuer,
    #[serde(rename = "INQ-M-RSP")]
    InquiryRespondedByMerchant,
    #[serde(rename = "INQ-EXPR")]
    InquiryExpired,
    #[serde(rename = "INQ-A-RJCT")]
    InquiryAutomaticallyRejected,
    #[serde(rename = "INQ-A-CNLD")]
    InquiryCancelledAfterRefund,
    #[serde(rename = "INQ-M-RFND")]
    InquiryAcceptedFullRefund,
    #[serde(rename = "INQ-M-P-RFND")]
    InquiryPartialAcceptedPartialRefund,
    #[serde(rename = "INQ-UPD")]
    InquiryUpdated,
    #[serde(rename = "IPA-M-ACPT")]
    PreArbitrationAcceptedByMerchant,
    #[serde(rename = "IPA-M-PART")]
    PreArbitrationPartiallyAcceptedByMerchant,
    #[serde(rename = "IPA-M-PART-EXP")]
    PreArbitrationPartiallyAcceptedByMerchantExpired,
    #[serde(rename = "IPA-M-RJCT")]
    PreArbitrationRejectedByMerchant,
    #[serde(rename = "IPA-M-RJCT-EXP")]
    PreArbitrationRejectedByMerchantExpired,
    #[serde(rename = "IPA-A-ACPT")]
    PreArbitrationAutomaticallyAcceptedByMerchant,
    #[serde(rename = "PA-CLSD-RC")]
    PreArbitrationClosedRecall,
    #[serde(rename = "IPAR-M-ACPT")]
    RejectedPreArbAcceptedByMerchant,
    #[serde(rename = "IPAR-A-ACPT")]
    RejectedPreArbExpiredAutoAccepted,
    #[serde(rename = "CC-I-RCLL")]
    CreditChargebackRecalledByIssuer,
}

/// Helper function to parse webhook body
pub fn get_webhook_object_from_body(
    body: &[u8],
) -> error_stack::Result<NuveiWebhook, errors::ConnectorError> {
    // Try parsing as URL-encoded first (common for Nuvei payment DMNs)
    let url_encoded_result = serde_urlencoded::from_bytes::<NuveiWebhook>(body)
        .change_context(errors::ConnectorError::ResponseDeserializationFailed)
        .attach_printable("Failed to parse Nuvei webhook body as URL-encoded data");

    match url_encoded_result {
        Ok(webhook) => Ok(webhook),
        Err(err) => {
            // Fall back to JSON parsing (for chargeback notifications)
            body.parse_struct::<NuveiWebhook>("NuveiWebhook")
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)
                .attach_printable(
                    "Failed to parse Nuvei webhook body as JSON after URL-encoded parsing failed",
                )
                .attach(err)
        }
    }
}

/// Maps Nuvei DMN notification to UCS EventType
pub fn map_notification_to_event(
    status: DmnStatus,
    transaction_type: NuveiTransactionType,
) -> error_stack::Result<domain_types::connector_types::EventType, errors::ConnectorError> {
    use domain_types::connector_types::EventType;
    match (status, transaction_type) {
        (DmnStatus::Success | DmnStatus::Approved, NuveiTransactionType::Auth) => {
            Ok(EventType::PaymentIntentAuthorizationSuccess)
        }
        (DmnStatus::Success | DmnStatus::Approved, NuveiTransactionType::Sale) => {
            Ok(EventType::PaymentIntentSuccess)
        }
        (DmnStatus::Success | DmnStatus::Approved, NuveiTransactionType::Settle) => {
            Ok(EventType::PaymentIntentCaptureSuccess)
        }
        (DmnStatus::Success | DmnStatus::Approved, NuveiTransactionType::Void) => {
            Ok(EventType::PaymentIntentCancelled)
        }
        (DmnStatus::Success | DmnStatus::Approved, NuveiTransactionType::Credit) => {
            Ok(EventType::RefundSuccess)
        }
        (DmnStatus::Error | DmnStatus::Declined, NuveiTransactionType::Auth) => {
            Ok(EventType::PaymentIntentAuthorizationFailure)
        }
        (DmnStatus::Error | DmnStatus::Declined, NuveiTransactionType::Sale) => {
            Ok(EventType::PaymentIntentFailure)
        }
        (DmnStatus::Error | DmnStatus::Declined, NuveiTransactionType::Settle) => {
            Ok(EventType::PaymentIntentCaptureFailure)
        }
        (DmnStatus::Error | DmnStatus::Declined, NuveiTransactionType::Void) => {
            Ok(EventType::PaymentIntentCancelFailure)
        }
        (DmnStatus::Error | DmnStatus::Declined, NuveiTransactionType::Credit) => {
            Ok(EventType::RefundFailure)
        }
        (
            DmnStatus::Pending,
            NuveiTransactionType::Auth | NuveiTransactionType::Sale | NuveiTransactionType::Settle,
        ) => Ok(EventType::PaymentIntentProcessing),
        _ => Err(errors::ConnectorError::WebhookEventTypeNotFound.into()),
    }
}

/// Maps dispute notification to UCS EventType
pub fn map_dispute_notification_to_event(
    chargeback_data: &ChargebackData,
) -> error_stack::Result<domain_types::connector_types::EventType, errors::ConnectorError> {
    use domain_types::connector_types::EventType;
    let event_code = chargeback_data
        .dispute_unified_status_code
        .as_ref()
        .and_then(|code| match code {
            DisputeUnifiedStatusCode::FirstChargebackInitiatedByIssuer
            | DisputeUnifiedStatusCode::CreditChargebackInitiatedByIssuer
            | DisputeUnifiedStatusCode::McCollaborationInitiatedByIssuer
            | DisputeUnifiedStatusCode::FirstChargebackClosedRecall
            | DisputeUnifiedStatusCode::InquiryInitiatedByIssuer => Some(EventType::DisputeOpened),
            DisputeUnifiedStatusCode::CreditChargebackAcceptedAutomatically
            | DisputeUnifiedStatusCode::FirstChargebackAcceptedAutomatically
            | DisputeUnifiedStatusCode::FirstChargebackAcceptedAutomaticallyMcoll
            | DisputeUnifiedStatusCode::FirstChargebackAcceptedByMerchant
            | DisputeUnifiedStatusCode::FirstChargebackDisputeResponseNotAllowed
            | DisputeUnifiedStatusCode::Rdr
            | DisputeUnifiedStatusCode::McCollaborationRefundedByMerchant
            | DisputeUnifiedStatusCode::McCollaborationAutomaticAccept
            | DisputeUnifiedStatusCode::InquiryAcceptedFullRefund
            | DisputeUnifiedStatusCode::PreArbitrationAcceptedByMerchant
            | DisputeUnifiedStatusCode::PreArbitrationPartiallyAcceptedByMerchant
            | DisputeUnifiedStatusCode::PreArbitrationAutomaticallyAcceptedByMerchant
            | DisputeUnifiedStatusCode::RejectedPreArbAcceptedByMerchant
            | DisputeUnifiedStatusCode::RejectedPreArbExpiredAutoAccepted => {
                Some(EventType::DisputeAccepted)
            }
            DisputeUnifiedStatusCode::FirstChargebackNoResponseExpired
            | DisputeUnifiedStatusCode::FirstChargebackPartiallyAcceptedByMerchant
            | DisputeUnifiedStatusCode::FirstChargebackClosedCardholderFavour
            | DisputeUnifiedStatusCode::PreArbitrationClosedCardholderFavour
            | DisputeUnifiedStatusCode::McCollaborationClosedCardholderFavour => {
                Some(EventType::DisputeLost)
            }
            DisputeUnifiedStatusCode::FirstChargebackRejectedByMerchant
            | DisputeUnifiedStatusCode::FirstChargebackRejectedAutomatically
            | DisputeUnifiedStatusCode::PreArbitrationInitiatedByIssuer
            | DisputeUnifiedStatusCode::MerchantPreArbitrationRejectedByIssuer
            | DisputeUnifiedStatusCode::InquiryRespondedByMerchant
            | DisputeUnifiedStatusCode::PreArbitrationRejectedByMerchant => {
                Some(EventType::DisputeChallenged)
            }
            DisputeUnifiedStatusCode::FirstChargebackClosedMerchantFavour
            | DisputeUnifiedStatusCode::PreArbitrationClosedMerchantFavour
            | DisputeUnifiedStatusCode::McCollaborationClosedMerchantFavour => {
                Some(EventType::DisputeWon)
            }
            DisputeUnifiedStatusCode::FirstChargebackRecalledByIssuer
            | DisputeUnifiedStatusCode::CreditChargebackRecalledByIssuer
            | DisputeUnifiedStatusCode::InquiryCancelledAfterRefund
            | DisputeUnifiedStatusCode::PreArbitrationClosedRecall => {
                Some(EventType::DisputeCancelled)
            }
            _ => None,
        });

    event_code.ok_or(errors::ConnectorError::WebhookEventTypeNotFound.into())
}

/// Gets dispute stage from chargeback data
pub fn get_dispute_stage(
    chargeback_data: &ChargebackData,
) -> error_stack::Result<common_enums::DisputeStage, errors::ConnectorError> {
    use common_enums::DisputeStage;
    let dispute_stage = chargeback_data
        .dispute_unified_status_code
        .clone()
        .map(DisputeStage::from)
        .or(match chargeback_data.webhook_type {
            Some(ChargebackType::Retrieval) => Some(DisputeStage::PreDispute),
            Some(ChargebackType::Chargeback) | None => None,
        })
        .or(match chargeback_data.chargeback_status_category {
            Some(ChargebackStatusCategory::Cancelled)
            | Some(ChargebackStatusCategory::Duplicate) => Some(DisputeStage::Dispute),
            Some(ChargebackStatusCategory::Regular) => Some(DisputeStage::Dispute),
            Some(ChargebackStatusCategory::RdrRefund) => Some(DisputeStage::PreDispute),
            Some(ChargebackStatusCategory::SoftCb) => Some(DisputeStage::PreArbitration),
            None => None,
        });

    dispute_stage.ok_or(errors::ConnectorError::WebhookEventTypeNotFound.into())
}

/// Implementation to convert DisputeUnifiedStatusCode to DisputeStage
impl From<DisputeUnifiedStatusCode> for common_enums::DisputeStage {
    fn from(code: DisputeUnifiedStatusCode) -> Self {
        match code {
            // --- PreDispute ---
            DisputeUnifiedStatusCode::Rdr
            | DisputeUnifiedStatusCode::InquiryInitiatedByIssuer
            | DisputeUnifiedStatusCode::InquiryRespondedByMerchant
            | DisputeUnifiedStatusCode::InquiryExpired
            | DisputeUnifiedStatusCode::InquiryAutomaticallyRejected
            | DisputeUnifiedStatusCode::InquiryCancelledAfterRefund
            | DisputeUnifiedStatusCode::InquiryAcceptedFullRefund
            | DisputeUnifiedStatusCode::InquiryPartialAcceptedPartialRefund
            | DisputeUnifiedStatusCode::InquiryUpdated => Self::PreDispute,

            // --- Dispute ---
            DisputeUnifiedStatusCode::FirstChargebackInitiatedByIssuer
            | DisputeUnifiedStatusCode::CreditChargebackInitiatedByIssuer
            | DisputeUnifiedStatusCode::FirstChargebackNoResponseExpired
            | DisputeUnifiedStatusCode::FirstChargebackAcceptedByMerchant
            | DisputeUnifiedStatusCode::FirstChargebackAcceptedAutomatically
            | DisputeUnifiedStatusCode::FirstChargebackAcceptedAutomaticallyMcoll
            | DisputeUnifiedStatusCode::FirstChargebackPartiallyAcceptedByMerchant
            | DisputeUnifiedStatusCode::FirstChargebackPartiallyAcceptedByMerchantExpired
            | DisputeUnifiedStatusCode::FirstChargebackRejectedByMerchant
            | DisputeUnifiedStatusCode::FirstChargebackRejectedByMerchantExpired
            | DisputeUnifiedStatusCode::FirstChargebackRejectedAutomatically
            | DisputeUnifiedStatusCode::FirstChargebackRejectedAutomaticallyExpired
            | DisputeUnifiedStatusCode::FirstChargebackClosedMerchantFavour
            | DisputeUnifiedStatusCode::FirstChargebackClosedCardholderFavour
            | DisputeUnifiedStatusCode::FirstChargebackClosedRecall
            | DisputeUnifiedStatusCode::FirstChargebackRecalledByIssuer
            | DisputeUnifiedStatusCode::FirstChargebackDisputeResponseNotAllowed
            | DisputeUnifiedStatusCode::McCollaborationInitiatedByIssuer
            | DisputeUnifiedStatusCode::McCollaborationPreviouslyRefundedAuto
            | DisputeUnifiedStatusCode::McCollaborationRefundedByMerchant
            | DisputeUnifiedStatusCode::McCollaborationExpired
            | DisputeUnifiedStatusCode::McCollaborationRejectedByMerchant
            | DisputeUnifiedStatusCode::McCollaborationAutomaticAccept
            | DisputeUnifiedStatusCode::McCollaborationClosedMerchantFavour
            | DisputeUnifiedStatusCode::McCollaborationClosedCardholderFavour
            | DisputeUnifiedStatusCode::CreditChargebackAcceptedAutomatically => Self::Dispute,

            // --- PreArbitration ---
            DisputeUnifiedStatusCode::PreArbitrationInitiatedByIssuer
            | DisputeUnifiedStatusCode::MerchantPreArbitrationAcceptedByIssuer
            | DisputeUnifiedStatusCode::MerchantPreArbitrationRejectedByIssuer
            | DisputeUnifiedStatusCode::MerchantPreArbitrationPartiallyAcceptedByIssuer
            | DisputeUnifiedStatusCode::PreArbitrationClosedMerchantFavour
            | DisputeUnifiedStatusCode::PreArbitrationClosedCardholderFavour
            | DisputeUnifiedStatusCode::PreArbitrationAcceptedByMerchant
            | DisputeUnifiedStatusCode::PreArbitrationPartiallyAcceptedByMerchant
            | DisputeUnifiedStatusCode::PreArbitrationPartiallyAcceptedByMerchantExpired
            | DisputeUnifiedStatusCode::PreArbitrationRejectedByMerchant
            | DisputeUnifiedStatusCode::PreArbitrationRejectedByMerchantExpired
            | DisputeUnifiedStatusCode::PreArbitrationAutomaticallyAcceptedByMerchant
            | DisputeUnifiedStatusCode::PreArbitrationClosedRecall
            | DisputeUnifiedStatusCode::RejectedPreArbAcceptedByMerchant
            | DisputeUnifiedStatusCode::RejectedPreArbExpiredAutoAccepted => Self::PreArbitration,

            // --- Dispute (for recalled chargebacks) ---
            DisputeUnifiedStatusCode::CreditChargebackRecalledByIssuer => Self::Dispute,
        }
    }
}

/// Convert PaymentDmnNotification to WebhookDetailsResponse
impl TryFrom<PaymentDmnNotification> for domain_types::connector_types::WebhookDetailsResponse {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(notification: PaymentDmnNotification) -> Result<Self, Self::Error> {
        use common_enums::AttemptStatus;
        use domain_types::connector_types::ResponseId;

        let status = match (notification.ppp_status, notification.status.as_ref()) {
            (DmnApiTransactionStatus::Ok, Some(DmnStatus::Success | DmnStatus::Approved)) => {
                AttemptStatus::Charged
            }
            (DmnApiTransactionStatus::Ok, Some(DmnStatus::Pending)) => AttemptStatus::Pending,
            (DmnApiTransactionStatus::Pending, _) => AttemptStatus::Pending,
            (DmnApiTransactionStatus::Fail, _)
            | (_, Some(DmnStatus::Error | DmnStatus::Declined)) => AttemptStatus::Failure,
            _ => AttemptStatus::Pending,
        };

        Ok(Self {
            resource_id: notification
                .transaction_id
                .clone()
                .map(ResponseId::ConnectorTransactionId),
            status,
            connector_response_reference_id: notification.transaction_id.clone(),
            mandate_reference: None,
            error_code: notification.err_code.clone(),
            error_message: notification.reason.clone(),
            error_reason: notification.reason.clone(),
            raw_connector_response: None,
            status_code: 200,
            response_headers: None,
            transformation_status: common_enums::WebhookTransformationStatus::Complete,
            amount_captured: None,
            minor_amount_captured: None,
            network_txn_id: None,
        })
    }
}

/// Convert PaymentDmnNotification to RefundWebhookDetailsResponse for refund transactions
impl TryFrom<PaymentDmnNotification>
    for domain_types::connector_types::RefundWebhookDetailsResponse
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(notification: PaymentDmnNotification) -> Result<Self, Self::Error> {
        use common_enums::RefundStatus;

        let status = match (notification.ppp_status, notification.status.as_ref()) {
            (DmnApiTransactionStatus::Ok, Some(DmnStatus::Success | DmnStatus::Approved)) => {
                RefundStatus::Success
            }
            (DmnApiTransactionStatus::Pending, _) => RefundStatus::Pending,
            (DmnApiTransactionStatus::Fail, _)
            | (_, Some(DmnStatus::Error | DmnStatus::Declined)) => RefundStatus::Failure,
            _ => RefundStatus::Pending,
        };

        Ok(Self {
            connector_refund_id: notification.transaction_id.clone(),
            status,
            connector_response_reference_id: notification.transaction_id.clone(),
            error_code: notification.err_code.clone(),
            error_message: notification.reason.clone(),
            raw_connector_response: None,
            status_code: 200,
            response_headers: None,
        })
    }
}
