use crate::{connectors::mollie::MollieRouterData, types::ResponseRouterData};
use common_enums::CountryAlpha2;
use common_utils::{
    pii::Email,
    types::{AmountConvertor, StringMajorUnit, StringMajorUnitForConnector},
};
use domain_types::{
    connector_flow::{
        Authorize, Capture, CreateOrder, PSync, PaymentMethodToken, RSync, Refund, Void,
    },
    connector_types::{
        PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData,
        PaymentMethodTokenResponse, PaymentMethodTokenizationData, PaymentVoidData,
        PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData, PaymentsSyncData,
        RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData, ResponseId,
    },
    errors,
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes, RawCardNumber},
    router_data::ConnectorSpecificConfig,
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, PeekInterface, Secret};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct MollieAuthType {
    pub api_key: Secret<String>,
    pub profile_token: Option<Secret<String>>,
}

impl TryFrom<&ConnectorSpecificConfig> for MollieAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorSpecificConfig) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorSpecificConfig::Mollie {
                api_key,
                profile_token,
                ..
            } => Ok(Self {
                api_key: api_key.to_owned(),
                profile_token: profile_token.to_owned(),
            }),
            _ => Err(error_stack::report!(
                errors::ConnectorError::FailedToObtainAuthType
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MollieErrorResponse {
    pub status: u16,
    pub title: String,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    #[serde(rename = "_links", skip_serializing_if = "Option::is_none")]
    pub links: Option<serde_json::Value>,
}

// Mollie Amount structure - uses object format with currency and value
#[derive(Debug, Serialize, Deserialize)]
pub struct MollieAmount {
    pub currency: common_enums::Currency,
    pub value: StringMajorUnit,
}

// Mollie Metadata structure - used in payments and refunds
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MollieMetadata {
    pub order_id: String,
}

// Mollie Payment Request structure
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MolliePaymentsRequest {
    pub amount: MollieAmount,
    pub description: String,
    pub redirect_url: String,
    pub webhook_url: String,
    pub metadata: serde_json::Value,
    #[serde(flatten)]
    pub payment_method_data: MolliePaymentMethodData,
    pub sequence_type: SequenceType,
    pub capture_mode: MollieCaptureMode,
    // These fields are always null in Hyperswitch but must be present
    pub locale: Option<String>,
    pub cancel_url: Option<String>,
    pub customer_id: Option<String>,
}

// Mollie Payment Method Data enum
#[derive(Debug, Serialize)]
#[serde(tag = "method")]
#[serde(rename_all = "lowercase")]
pub enum MolliePaymentMethodData {
    #[serde(rename = "creditcard")]
    CreditCard(Box<CreditCardMethodData>),
}

// Credit Card Method Data
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreditCardMethodData {
    pub card_token: Option<Secret<String>>,
    pub billing_address: Option<MollieAddress>,
    pub shipping_address: Option<MollieAddress>,
}

// Mollie Address structure
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MollieAddress {
    pub street_and_number: Secret<String>,
    pub postal_code: Secret<String>,
    pub city: String,
    pub region: Option<Secret<String>>,
    pub country: common_enums::CountryAlpha2,
}

// Sequence Type enum
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SequenceType {
    Oneoff,
    First,
    Recurring,
}

// Capture Mode enum
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum MollieCaptureMode {
    Manual,
    Automatic,
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        MollieRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for MolliePaymentsRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: MollieRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let item = item.router_data;
        // Convert amount to string major unit format (e.g., "10.00" for $10.00)
        let converter = StringMajorUnitForConnector;
        let amount_value = converter
            .convert(item.request.amount, item.request.currency)
            .change_context(errors::ConnectorError::RequestEncodingFailed)
            .attach_printable("Failed to convert amount to string major unit")?;

        // Extract payment method data based on payment method type
        let payment_method_data = match &item.request.payment_method_data {
            PaymentMethodData::Card(_card_data) => {
                // Extract card token from payment_method_token
                // Following Hyperswitch pattern: ALL tokens (cst_ and tkn_) go to cardToken field
                let card_token = item.resource_common_data.payment_method_token.as_ref().map(
                    |token| match token {
                        domain_types::router_data::PaymentMethodToken::Token(t) => t.clone(),
                    },
                );

                // Extract billing address if available
                // Match Hyperswitch format: comma separator, no region
                let billing_address = item
                    .resource_common_data
                    .address
                    .get_payment_method_billing()
                    .and_then(|billing| {
                        let address = billing.address.as_ref()?;
                        let line1 = address.line1.as_ref()?.peek().to_string();
                        let street_and_number = match address.line2.as_ref() {
                            Some(line2) => format!("{},{}", line1, line2.peek().as_str()),
                            None => line1,
                        };

                        Some(MollieAddress {
                            street_and_number: Secret::new(street_and_number),
                            postal_code: Secret::new(address.zip.as_ref()?.peek().to_string()),
                            city: address.city.as_ref()?.peek().to_string(),
                            region: None, // Match Hyperswitch: always null
                            country: address.country?,
                        })
                    });

                MolliePaymentMethodData::CreditCard(Box::new(CreditCardMethodData {
                    card_token,
                    billing_address,
                    shipping_address: None,
                }))
            }
            _ => {
                return Err(errors::ConnectorError::NotSupported {
                    message: "Payment method ".to_string(),
                    connector: "mollie",
                }
                .into());
            }
        };

        // For regular payments, always use oneoff sequence type
        // Following Hyperswitch pattern: only use "first" or "recurring" for explicit mandate flows
        let sequence_type = SequenceType::Oneoff;

        // captureMode is required for oneoff payments
        let capture_mode =
            if item.request.capture_method == Some(common_enums::CaptureMethod::Automatic) {
                MollieCaptureMode::Automatic
            } else {
                MollieCaptureMode::Manual
            };

        // Build metadata - match Hyperswitch format with orderId
        // Always use orderId format, not connector_meta_data
        let mut metadata_map = serde_json::Map::new();
        metadata_map.insert(
            "orderId".to_string(),
            serde_json::Value::String(
                item.resource_common_data
                    .connector_request_reference_id
                    .clone(),
            ),
        );

        Ok(Self {
            amount: MollieAmount {
                currency: item.request.currency,
                value: amount_value,
            },
            description: item.resource_common_data.description.clone().ok_or(
                errors::ConnectorError::MissingRequiredField {
                    field_name: "description",
                },
            )?,
            redirect_url: item.request.router_return_url.clone().unwrap_or_default(),
            // Use empty string for webhook_url since we can't support webhook callbacks
            // in test environment (localhost is unreachable from Mollie's servers).
            // This matches Hyperswitch implementation pattern.
            webhook_url: "".to_string(),
            metadata: serde_json::Value::Object(metadata_map),
            payment_method_data,
            sequence_type,
            capture_mode,
            // Match Hyperswitch: these are always null
            locale: None,
            cancel_url: None,
            customer_id: None,
        })
    }
}

// Mollie Payment Status enum
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum MolliePaymentStatus {
    Open,
    Pending,
    Authorized,
    Paid,
    Canceled,
    Expired,
    Failed,
}

// Mollie Link structure
#[derive(Debug, Serialize, Deserialize)]
pub struct MollieLink {
    pub href: String,
    #[serde(rename = "type")]
    pub link_type: String,
}

// Mollie Links structure
#[derive(Debug, Serialize, Deserialize)]
pub struct MollieLinks {
    #[serde(rename = "self")]
    pub self_link: MollieLink,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkout: Option<MollieLink>,
}

// Mollie Payment Response structure
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MolliePaymentsResponse {
    pub id: String,
    pub resource: String,
    pub mode: String,
    pub status: MolliePaymentStatus,
    pub amount: MollieAmount,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(rename = "_links")]
    pub links: MollieLinks,
}

// Status mapping implementation - CRITICAL: NEVER HARDCODE STATUS VALUES
impl MolliePaymentStatus {
    fn to_attempt_status(&self) -> common_enums::AttemptStatus {
        match self {
            Self::Open => common_enums::AttemptStatus::AuthenticationPending,
            Self::Pending => common_enums::AttemptStatus::Pending,
            Self::Authorized => common_enums::AttemptStatus::Authorized,
            Self::Paid => common_enums::AttemptStatus::Charged,
            Self::Canceled => common_enums::AttemptStatus::Voided,
            Self::Expired => common_enums::AttemptStatus::Failure,
            Self::Failed => common_enums::AttemptStatus::Failure,
        }
    }
}

impl<T: PaymentMethodDataTypes> TryFrom<ResponseRouterData<MolliePaymentsResponse, Self>>
    for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<MolliePaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        // Map status from Mollie response - NEVER HARDCODE
        let status = item.response.status.to_attempt_status();

        // Extract redirection URL if available
        let redirection_data = item.response.links.checkout.as_ref().and_then(|checkout| {
            url::Url::parse(&checkout.href).ok().map(|url| {
                Box::new(RedirectForm::from((
                    url,
                    common_utils::request::Method::Get,
                )))
            })
        });

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id.clone()),
                redirection_data,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(item.response.id),
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

// PSync Response Transformer - Reuses MolliePaymentsResponse
impl TryFrom<ResponseRouterData<MolliePaymentsResponse, Self>>
    for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<MolliePaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        // Map status from Mollie response - NEVER HARDCODE
        let status = item.response.status.to_attempt_status();

        // Extract redirection URL if available
        let redirection_data = item.response.links.checkout.as_ref().and_then(|checkout| {
            url::Url::parse(&checkout.href).ok().map(|url| {
                Box::new(RedirectForm::from((
                    url,
                    common_utils::request::Method::Get,
                )))
            })
        });

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id.clone()),
                redirection_data,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(item.response.id),
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

// ===== REFUND FLOW TYPES AND TRANSFORMERS =====

// Mollie Refund Request structure
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MollieRefundRequest {
    pub amount: MollieAmount,
    pub description: Option<String>,
    pub metadata: MollieMetadata,
}

// Mollie Refund Status enum
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MollieRefundStatus {
    Queued,
    Pending,
    Processing,
    Refunded,
    Failed,
    Canceled,
}

// Mollie Refund Links structure
#[derive(Debug, Serialize, Deserialize)]
pub struct MollieRefundLinks {
    #[serde(rename = "self")]
    pub self_link: MollieLink,
    pub payment: MollieLink,
}

// Mollie Refund Response structure
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MollieRefundResponse {
    pub id: String,
    pub resource: String,
    pub mode: String,
    pub status: MollieRefundStatus,
    pub amount: MollieAmount,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    pub payment_id: String,
    pub created_at: String,
    #[serde(rename = "_links")]
    pub links: MollieRefundLinks,
}

// Refund status mapping implementation - CRITICAL: NEVER HARDCODE STATUS VALUES
impl MollieRefundStatus {
    fn to_refund_status(&self) -> common_enums::RefundStatus {
        match self {
            Self::Queued => common_enums::RefundStatus::Pending,
            Self::Pending => common_enums::RefundStatus::Pending,
            Self::Processing => common_enums::RefundStatus::Pending,
            Self::Refunded => common_enums::RefundStatus::Success,
            Self::Failed => common_enums::RefundStatus::Failure,
            Self::Canceled => common_enums::RefundStatus::Failure,
        }
    }
}

// Request transformer for Refund flow
impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        MollieRouterData<RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>, T>,
    > for MollieRefundRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: MollieRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let item = item.router_data;
        // Convert amount to string major unit format (e.g., "10.00" for $10.00)
        let converter = StringMajorUnitForConnector;
        let amount_value = converter
            .convert(item.request.minor_refund_amount, item.request.currency)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;

        Ok(Self {
            amount: MollieAmount {
                currency: item.request.currency,
                value: amount_value,
            },
            description: item.request.reason.to_owned(),
            metadata: MollieMetadata {
                order_id: item.request.refund_id.clone(),
            },
        })
    }
}

// Response transformer for Refund flow
impl TryFrom<ResponseRouterData<MollieRefundResponse, Self>>
    for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: ResponseRouterData<MollieRefundResponse, Self>) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.id.clone(),
                refund_status: item.response.status.to_refund_status(),
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

// Response transformer for RSync flow - reuses MollieRefundResponse
impl TryFrom<ResponseRouterData<MollieRefundResponse, Self>>
    for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: ResponseRouterData<MollieRefundResponse, Self>) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.id.clone(),
                refund_status: item.response.status.to_refund_status(),
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

// ===== VOID FLOW TRANSFORMER =====

// Void Response Transformer - Reuses MolliePaymentsResponse
// No request structure needed - DELETE endpoint with path parameter only
impl TryFrom<ResponseRouterData<MolliePaymentsResponse, Self>>
    for RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<MolliePaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        // Map status from Mollie response - NEVER HARDCODE
        // Status "canceled" maps to AttemptStatus::Voided
        let status = item.response.status.to_attempt_status();

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(item.response.id),
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

// ===== PAYMENT METHOD TOKEN FLOW TYPES AND TRANSFORMERS =====

// Mollie Customer Request structure (for tokenization)
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MollieCustomerRequest {
    pub name: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<Email>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

// Mollie Customer Response structure
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MollieCustomerResponse {
    pub id: String,       // cust_xxx format
    pub resource: String, // "customer"
    pub mode: String,     // "test" or "live"
    pub name: Option<Secret<String>>,
    pub email: Option<Email>, // Optional - can be null
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

// Mollie Card Token Request structure (for /card-tokens endpoint)
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MollieCardTokenRequest<T: PaymentMethodDataTypes> {
    pub card_holder: Secret<String>,
    pub card_number: RawCardNumber<T>,
    pub card_cvv: Secret<String>,
    pub card_expiry_date: Secret<String>, // Format: "MM/YY" (e.g., "12/25")
    pub locale: String,
    pub testmode: bool,
    pub profile_token: Secret<String>,
}

// Mollie Card Token Response structure
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MollieCardTokenResponse {
    pub card_token: Secret<String>, // tkn_xxx format
}

// Request transformer for PaymentMethodToken flow - Card Token Request
impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        MollieRouterData<
            RouterDataV2<
                PaymentMethodToken,
                PaymentFlowData,
                PaymentMethodTokenizationData<T>,
                PaymentMethodTokenResponse,
            >,
            T,
        >,
    > for MollieCardTokenRequest<T>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: MollieRouterData<
            RouterDataV2<
                PaymentMethodToken,
                PaymentFlowData,
                PaymentMethodTokenizationData<T>,
                PaymentMethodTokenResponse,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let item = item.router_data;
        // Extract card data from payment method
        let card_data = match &item.request.payment_method_data {
            PaymentMethodData::Card(card) => Ok(card),
            _ => Err(errors::ConnectorError::NotImplemented(
                "Only card payment method is supported for tokenization".to_string(),
            )),
        }?;

        // Get profile token from auth
        let auth = MollieAuthType::try_from(&item.connector_config)?;
        let profile_token =
            auth.profile_token
                .ok_or(errors::ConnectorError::InvalidConnectorConfig {
                    config: "profile_token",
                })?;

        // Format expiry date as "MM/YY" (required by Mollie Components API)
        // Using CardData util for consistent formatting
        let card_expiry_date =
            card_data.get_card_expiry_month_year_2_digit_with_delimiter("/".to_string())?;

        // Extract browser info and get language - use default if not available
        // Note: When called via UCS gRPC from Hyperswitch, browser_info may not be passed
        // in the PaymentMethodServiceTokenizeRequest proto (it doesn't have that field)
        let locale = item
            .request
            .browser_info
            .as_ref()
            .and_then(|bi| bi.language.clone())
            .unwrap_or_else(|| "en-US".to_string());

        // test_mode is required - error if not provided (matching Hyperswitch)
        let testmode = item.resource_common_data.test_mode.ok_or(
            errors::ConnectorError::MissingRequiredField {
                field_name: "test_mode",
            },
        )?;

        Ok(Self {
            card_holder: card_data
                .card_holder_name
                .clone()
                .unwrap_or_else(|| Secret::new("Cardholder".to_string())),
            card_number: card_data.card_number.clone(),
            card_cvv: card_data.card_cvc.clone(),
            card_expiry_date,
            locale,
            testmode,
            profile_token,
        })
    }
}

// Response transformer for PaymentMethodToken flow - Card Token Response
impl<T: PaymentMethodDataTypes> TryFrom<ResponseRouterData<MollieCardTokenResponse, Self>>
    for RouterDataV2<
        PaymentMethodToken,
        PaymentFlowData,
        PaymentMethodTokenizationData<T>,
        PaymentMethodTokenResponse,
    >
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<MollieCardTokenResponse, Self>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(PaymentMethodTokenResponse {
                token: item.response.card_token.expose(), // Return tkn_ token
            }),
            resource_common_data: PaymentFlowData {
                status: common_enums::AttemptStatus::Charged, // Tokenization successful
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

// ===== CAPTURE FLOW TYPES AND TRANSFORMERS =====

// Mollie Capture Request structure
// POST /payments/{id}/captures
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MollieCaptureRequest {
    pub amount: Option<MollieAmount>,
    pub description: String,
}

// Request transformer for Capture flow
impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        MollieRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    > for MollieCaptureRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: MollieRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let item = item.router_data;
        // Convert amount to string major unit format (e.g., "10.00" for $10.00)
        let converter = StringMajorUnitForConnector;
        let amount_value = converter
            .convert(item.request.minor_amount_to_capture, item.request.currency)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;

        Ok(Self {
            amount: Some(MollieAmount {
                currency: item.request.currency,
                value: amount_value,
            }),
            description: item.resource_common_data.description.clone().ok_or(
                errors::ConnectorError::MissingRequiredField {
                    field_name: "description",
                },
            )?,
        })
    }
}

// Response transformer for Capture flow - reuses MolliePaymentsResponse
impl TryFrom<ResponseRouterData<MolliePaymentsResponse, Self>>
    for RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<MolliePaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        // Map status from Mollie response - NEVER HARDCODE
        let status = item.response.status.to_attempt_status();

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(item.response.id),
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

// Type aliases for reused response types to avoid macro redefinition errors
pub type MollieCaptureResponse = MolliePaymentsResponse;
pub type MolliePSyncResponse = MolliePaymentsResponse;
pub type MollieVoidResponse = MolliePaymentsResponse;
pub type MollieRSyncResponse = MollieRefundResponse;

// ===== ORDER CREATE FLOW TYPES AND TRANSFORMERS =====

// Mollie Order Line structure
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MollieOrderLine {
    #[serde(rename = "type")]
    pub line_type: String,
    pub name: String,
    pub quantity: i32,
    pub vat_rate: String,
    pub unit_price: MollieAmount,
    pub total_amount: MollieAmount,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discount_amount: Option<MollieAmount>,
    pub vat_amount: MollieAmount,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sku: Option<String>,
}

// Mollie Order Address structure
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MollieOrderAddress {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub given_name: String,
    pub family_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_name: Option<String>,
    pub street_and_number: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub street_additional: Option<String>,
    pub city: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    pub postal_code: String,
    pub country: common_enums::CountryAlpha2,
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
}

// Mollie Order Create Request structure
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MollieOrderCreateRequest {
    pub amount: MollieAmount,
    pub order_number: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cancel_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook_url: Option<String>,
    pub billing_address: MollieOrderAddress,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shipping_address: Option<MollieOrderAddress>,
    pub lines: Vec<MollieOrderLine>,
    pub locale: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

// Mollie Order Status enum
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum MollieOrderStatus {
    Created,
    Pending,
    Authorized,
    Paid,
    Shipping,
    Canceled,
    Expired,
    Completed,
}

// Mollie Order Links structure
#[derive(Debug, Serialize, Deserialize)]
pub struct MollieOrderLinks {
    #[serde(rename = "self")]
    pub self_link: MollieLink,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkout: Option<MollieLink>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dashboard: Option<MollieLink>,
}

// Mollie Order Create Response structure
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MollieOrderCreateResponse {
    pub id: String,
    pub resource: String,
    pub mode: String,
    pub status: MollieOrderStatus,
    pub amount: MollieAmount,
    pub order_number: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_url: Option<String>,
    pub webhook_url: String,
    pub billing_address: MollieOrderAddress,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shipping_address: Option<MollieOrderAddress>,
    pub lines: Vec<MollieOrderLine>,
    pub locale: String,
    pub created_at: String,
    #[serde(rename = "_links")]
    pub links: MollieOrderLinks,
}

// Order status mapping implementation
impl MollieOrderStatus {
    fn to_attempt_status(&self) -> common_enums::AttemptStatus {
        match self {
            Self::Created => common_enums::AttemptStatus::AuthenticationPending,
            Self::Pending => common_enums::AttemptStatus::Pending,
            Self::Authorized => common_enums::AttemptStatus::Authorized,
            Self::Paid => common_enums::AttemptStatus::Charged,
            Self::Shipping => common_enums::AttemptStatus::Charged,
            Self::Canceled => common_enums::AttemptStatus::Voided,
            Self::Expired => common_enums::AttemptStatus::Failure,
            Self::Completed => common_enums::AttemptStatus::Charged,
        }
    }
}

// Request transformer for Order Create flow
impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        MollieRouterData<
            RouterDataV2<
                CreateOrder,
                PaymentFlowData,
                PaymentCreateOrderData,
                PaymentCreateOrderResponse,
            >,
            T,
        >,
    > for MollieOrderCreateRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: MollieRouterData<
            RouterDataV2<
                CreateOrder,
                PaymentFlowData,
                PaymentCreateOrderData,
                PaymentCreateOrderResponse,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let item = item.router_data;

        // Convert amount to string major unit format
        let converter = StringMajorUnitForConnector;
        let amount_value = converter
            .convert(item.request.amount, item.request.currency)
            .change_context(errors::ConnectorError::RequestEncodingFailed)
            .attach_printable("Failed to convert amount to string major unit")?;

        // Get order number from connector_request_reference_id
        let order_number = item
            .resource_common_data
            .connector_request_reference_id
            .clone();

        // Extract billing address from address field, or use defaults for testing
        let billing_address = item
            .resource_common_data
            .address
            .get_payment_method_billing()
            .and_then(|billing| {
                let address = billing.address.as_ref()?;
                let first_name = address.first_name.as_ref()?.peek().to_string();
                let last_name = address.last_name.as_ref()?.peek().to_string();
                let line1 = address.line1.as_ref()?.peek().to_string();
                let street_and_number = match address.line2.as_ref() {
                    Some(line2) => format!("{}, {}", line1, line2.peek().as_str()),
                    None => line1,
                };

                // Get email from billing address email field if available
                let email = billing.email.as_ref()?.peek().to_string();

                Some(MollieOrderAddress {
                    title: None,
                    given_name: first_name,
                    family_name: last_name,
                    organization_name: None,
                    street_and_number,
                    street_additional: None,
                    city: address.city.as_ref()?.peek().to_string(),
                    region: address.state.as_ref().map(|s| s.peek().to_string()),
                    postal_code: address.zip.as_ref()?.peek().to_string(),
                    country: address.country?,
                    email,
                    phone: None,
                })
            })
            .unwrap_or_else(|| {
                // Default billing address for testing when not provided
                MollieOrderAddress {
                    title: None,
                    given_name: "Test".to_string(),
                    family_name: "User".to_string(),
                    organization_name: None,
                    street_and_number: "123 Test Street".to_string(),
                    street_additional: None,
                    city: "Amsterdam".to_string(),
                    region: None,
                    postal_code: "1234AB".to_string(),
                    country: common_enums::CountryAlpha2::NL,
                    email: "test@example.com".to_string(),
                    phone: None,
                }
            });

        // Create a single order line with the full amount
        let zero_amount = common_utils::types::MinorUnit(0);
        let order_line = MollieOrderLine {
            line_type: "physical".to_string(),
            name: format!("Order {}", order_number),
            quantity: 1,
            vat_rate: "0.00".to_string(),
            unit_price: MollieAmount {
                currency: item.request.currency,
                value: amount_value.clone(),
            },
            total_amount: MollieAmount {
                currency: item.request.currency,
                value: amount_value.clone(),
            },
            discount_amount: None,
            vat_amount: MollieAmount {
                currency: item.request.currency,
                value: converter
                    .convert(zero_amount, item.request.currency)
                    .change_context(errors::ConnectorError::RequestEncodingFailed)?,
            },
            sku: None,
        };

        Ok(Self {
            amount: MollieAmount {
                currency: item.request.currency,
                value: amount_value,
            },
            order_number,
            redirect_url: Some("https://example.com/redirect".to_string()),
            cancel_url: Some("https://example.com/cancel".to_string()),
            webhook_url: item.request.webhook_url.clone(),
            billing_address,
            shipping_address: None,
            lines: vec![order_line],
            locale: "en_US".to_string(),
            // Method is optional - if provided, Mollie expects specific values like "creditcard", "ideal", etc.
            // Omitting it allows Mollie to present all available payment methods on the checkout page
            method: None,
            profile_id: None,
            expires_at: None,
        })
    }
}

// Response transformer for Order Create flow
impl TryFrom<ResponseRouterData<MollieOrderCreateResponse, Self>>
    for RouterDataV2<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    >
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<MollieOrderCreateResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let response = PaymentCreateOrderResponse {
            order_id: item.response.id.clone(),
            session_token: None,
        };

        Ok(Self {
            response: Ok(response),
            resource_common_data: PaymentFlowData {
                status: item.response.status.to_attempt_status(),
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}
