use crate::types::ResponseRouterData;
use common_enums::{AttemptStatus, CaptureMethod};
use common_utils::types::FloatMajorUnit;
use domain_types::{
    connector_flow::{Authorize, Capture, PSync},
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData, PaymentsSyncData, ResponseId},
    errors,
    payment_method_data::{Card, PaymentMethodData, PaymentMethodDataTypes},
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
};
use error_stack::ResultExt;
use hyperswitch_masking::{PeekInterface, Secret};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct GetnetAuthType {
    pub username: Secret<String>,
    pub password: Secret<String>,
    pub merchant_id: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for GetnetAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey {
                api_key,
                key1,
                api_secret,
            } => Ok(Self {
                username: key1.to_owned(),
                password: api_key.to_owned(),
                merchant_id: api_secret.to_owned(),
            }),
            _ => Err(error_stack::report!(
                errors::ConnectorError::FailedToObtainAuthType
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetnetErrorResponse {
    pub code: String,
    pub message: String,
}

// Transaction Type Enum
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum GetnetTransactionType {
    Purchase,
    Authorization,
    CaptureAuthorization,
    RefundPurchase,
    RefundCapture,
    VoidAuthorization,
    VoidPurchase,
}

// Payment Status Enum
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum GetnetPaymentStatus {
    Success,
    Failed,
    #[serde(rename = "inprogress")]
    InProgress,
}

// Amount Structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetnetAmount {
    pub value: f64,
    pub currency: String,
}

// Merchant Account ID Structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetnetMerchantAccountId {
    pub value: Secret<String>,
}

// Address Structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetnetAddress {
    pub street1: Option<String>,
    pub city: Option<String>,
    pub state: Option<String>,
    pub country: Option<common_enums::CountryAlpha2>,
}

// Account Holder Structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetnetAccountHolder {
    #[serde(rename = "first-name")]
    pub first_name: Option<Secret<String>>,
    #[serde(rename = "last-name")]
    pub last_name: Option<Secret<String>>,
    pub email: Option<common_utils::pii::Email>,
    pub phone: Option<Secret<String>>,
    pub address: Option<GetnetAddress>,
}

// Card Structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetnetCard {
    #[serde(rename = "account-number")]
    pub account_number: Secret<String>,
    #[serde(rename = "expiration-month")]
    pub expiration_month: Secret<String>,
    #[serde(rename = "expiration-year")]
    pub expiration_year: Secret<String>,
    #[serde(rename = "card-security-code")]
    pub card_security_code: Secret<String>,
    #[serde(rename = "card-type")]
    pub card_type: String,
}

// Payment Method Container
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetnetPaymentMethod {
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetnetPaymentMethodContainer {
    #[serde(rename = "payment-method")]
    pub payment_method: Vec<GetnetPaymentMethod>,
}

// Notification Container
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetnetNotification {
    pub url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetnetNotificationContainer {
    pub format: String,
    pub notification: Vec<GetnetNotification>,
}

// Main Payment Request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetnetPaymentObject {
    #[serde(rename = "merchant-account-id")]
    pub merchant_account_id: GetnetMerchantAccountId,
    #[serde(rename = "request-id")]
    pub request_id: String,
    #[serde(rename = "transaction-type")]
    pub transaction_type: GetnetTransactionType,
    #[serde(rename = "requested-amount")]
    pub requested_amount: GetnetAmount,
    #[serde(rename = "account-holder")]
    pub account_holder: GetnetAccountHolder,
    pub card: GetnetCard,
    #[serde(rename = "ip-address")]
    pub ip_address: Option<Secret<String>>,
    #[serde(rename = "payment-methods")]
    pub payment_methods: GetnetPaymentMethodContainer,
    pub notifications: GetnetNotificationContainer,
}

#[derive(Debug, Serialize)]
pub struct GetnetPaymentsRequest {
    pub payment: GetnetPaymentObject,
}

impl<T: PaymentMethodDataTypes> TryFrom<(&FloatMajorUnit, &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>)> for GetnetPaymentsRequest {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        (amount, item): (&FloatMajorUnit, &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>),
    ) -> Result<Self, Self::Error> {
        // Determine transaction type based on capture method
        let transaction_type = match item.request.capture_method {
            Some(CaptureMethod::Automatic) => GetnetTransactionType::Purchase,
            Some(CaptureMethod::Manual) | Some(CaptureMethod::SequentialAutomatic) => {
                GetnetTransactionType::Authorization
            }
            Some(CaptureMethod::ManualMultiple) | Some(CaptureMethod::Scheduled) | None => {
                return Err(errors::ConnectorError::CaptureMethodNotSupported.into())
            }
        };

        // Extract card data
        let card_data = match &item.request.payment_method_data {
            PaymentMethodData::Card(card) => card,
            _ => {
                return Err(errors::ConnectorError::NotImplemented(
                    "Payment method not supported".to_string(),
                )
                .into())
            }
        };

        // Build account holder
        let account_holder = build_account_holder(item, card_data)?;

        // Build card object
        let card = GetnetCard {
            account_number: Secret::new(card_data.card_number.peek().to_string()),
            expiration_month: card_data.card_exp_month.clone(),
            expiration_year: card_data.card_exp_year.clone(),
            card_security_code: card_data.card_cvc.clone(),
            card_type: card_data
                .card_network
                .clone()
                .map(|network| network.to_string().to_lowercase())
                .unwrap_or_default(),
        };

        // Get IP address from browser info
        let ip_address = item
            .request
            .browser_info
            .as_ref()
            .and_then(|info| info.ip_address.clone())
            .map(|ip| Secret::new(ip.to_string()));

        // Build webhook URL
        let webhook_url = item
            .request
            .get_webhook_url()
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;

        // Extract merchant_id from auth
        let auth = GetnetAuthType::try_from(&item.connector_auth_type)?;

        Ok(Self {
            payment: GetnetPaymentObject {
                merchant_account_id: GetnetMerchantAccountId {
                    value: auth.merchant_id.clone(),
                },
                request_id: item.resource_common_data.payment_id.clone(),
                transaction_type,
                requested_amount: GetnetAmount {
                    value: amount.0,
                    currency: item.request.currency.to_string(),
                },
                account_holder,
                card,
                ip_address,
                payment_methods: GetnetPaymentMethodContainer {
                    payment_method: vec![GetnetPaymentMethod {
                        name: "creditcard".to_string(),
                    }],
                },
                notifications: GetnetNotificationContainer {
                    format: "application/json-signed".to_string(),
                    notification: vec![GetnetNotification {
                        url: Some(webhook_url),
                    }],
                },
            },
        })
    }
}

// Helper function to build account holder
fn build_account_holder<T: PaymentMethodDataTypes>(
    item: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    card_data: &Card<T>,
) -> Result<GetnetAccountHolder, error_stack::Report<errors::ConnectorError>> {
    let billing_address = item.resource_common_data.get_billing_address()?;

    // Split cardholder name into first and last name
    let (first_name, last_name) = card_data
        .card_holder_name
        .clone()
        .map(|name| {
            let parts: Vec<&str> = name.peek().split_whitespace().collect();
            let first = parts.first().map(|s| Secret::new(s.to_string()));
            let last = if parts.len() > 1 {
                Some(Secret::new(parts[1..].join(" ")))
            } else {
                None
            };
            (first, last)
        })
        .unwrap_or((None, None));

    Ok(GetnetAccountHolder {
        first_name,
        last_name,
        email: item.request.email.clone(),
        phone: None, // Phone is not available in AddressDetails
        address: Some(GetnetAddress {
            street1: billing_address
                .line1
                .as_ref()
                .map(|s| s.peek().to_string()),
            city: billing_address.city.as_ref().map(|s| s.peek().to_string()),
            state: billing_address
                .state
                .as_ref()
                .map(|s| s.peek().to_string()),
            country: billing_address.country,
        }),
    })
}

// Card Token Structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetnetCardToken {
    #[serde(rename = "token-id")]
    pub token_id: String,
    #[serde(rename = "masked-account-number")]
    pub masked_account_number: Option<String>,
}

// Status Structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetnetStatus {
    pub code: String,
    pub description: String,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetnetStatuses {
    pub status: Vec<GetnetStatus>,
}

// Main Payment Response
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GetnetPaymentResponseObject {
    pub statuses: Option<GetnetStatuses>,
    #[serde(rename = "merchant-account-id")]
    pub merchant_account_id: Option<GetnetMerchantAccountId>,
    #[serde(rename = "transaction-id")]
    pub transaction_id: String,
    #[serde(rename = "request-id")]
    pub request_id: Option<String>,
    #[serde(rename = "transaction-type")]
    pub transaction_type: GetnetTransactionType,
    #[serde(rename = "transaction-state")]
    pub transaction_state: GetnetPaymentStatus,
    #[serde(rename = "completion-time-stamp")]
    pub completion_time_stamp: Option<i64>,
    #[serde(rename = "requested-amount")]
    pub requested_amount: Option<GetnetAmount>,
    #[serde(rename = "card-token")]
    pub card_token: Option<GetnetCardToken>,
    #[serde(rename = "api-id")]
    pub api_id: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GetnetPaymentsResponse {
    pub payment: GetnetPaymentResponseObject,
}

impl<T: PaymentMethodDataTypes>
    TryFrom<
        ResponseRouterData<
            GetnetPaymentsResponse,
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
            GetnetPaymentsResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        let payment = &item.response.payment;

        // Determine status based on transaction state, transaction type, and capture method
        let is_auto_capture = matches!(
            item.router_data.request.capture_method,
            Some(CaptureMethod::Automatic)
        );

        let status = match (&payment.transaction_state, &payment.transaction_type) {
            (GetnetPaymentStatus::Success, GetnetTransactionType::Purchase) => {
                AttemptStatus::Charged
            }
            (GetnetPaymentStatus::Success, GetnetTransactionType::Authorization) => {
                AttemptStatus::Authorized
            }
            (GetnetPaymentStatus::InProgress, _) => AttemptStatus::Pending,
            (GetnetPaymentStatus::Failed, _) => AttemptStatus::Failure,
            _ => {
                if is_auto_capture {
                    AttemptStatus::Charged
                } else {
                    AttemptStatus::Authorized
                }
            }
        };

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(payment.transaction_id.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: payment.request_id.clone(),
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

// PSync Response Transformer
impl
    TryFrom<
        ResponseRouterData<
            GetnetPaymentsResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    > for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            GetnetPaymentsResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let payment = &item.response.payment;

        // Determine status based on transaction state, transaction type, and capture method
        // For PSync, we need to determine the original capture method
        let is_auto_capture = matches!(
            item.router_data.request.capture_method,
            Some(CaptureMethod::Automatic)
        );

        let status = psync_attempt_status_from_transaction_state(
            payment.transaction_state.clone(),
            is_auto_capture,
            payment.transaction_type.clone(),
        );

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(payment.transaction_id.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: payment.request_id.clone(),
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

// Status determination logic for PSync
pub fn psync_attempt_status_from_transaction_state(
    getnet_status: GetnetPaymentStatus,
    is_auto_capture: bool,
    transaction_type: GetnetTransactionType,
) -> AttemptStatus {
    match getnet_status {
        GetnetPaymentStatus::Success => {
            // For auto-capture flow
            if is_auto_capture {
                match transaction_type {
                    GetnetTransactionType::Purchase => AttemptStatus::Charged,
                    GetnetTransactionType::CaptureAuthorization => AttemptStatus::Charged,
                    _ => AttemptStatus::Charged,
                }
            } else {
                // For manual capture flow
                match transaction_type {
                    GetnetTransactionType::Authorization => AttemptStatus::Authorized,
                    GetnetTransactionType::CaptureAuthorization => AttemptStatus::Charged,
                    _ => AttemptStatus::Authorized,
                }
            }
        }
        GetnetPaymentStatus::InProgress => AttemptStatus::Pending,
        GetnetPaymentStatus::Failed => AttemptStatus::Failure,
    }
}

// ===== CAPTURE REQUEST STRUCTURES =====

// Capture Payment Object
#[derive(Debug, Clone, Serialize)]
pub struct GetnetCapturePaymentObject {
    #[serde(rename = "merchant-account-id")]
    pub merchant_account_id: GetnetMerchantAccountId,
    #[serde(rename = "request-id")]
    pub request_id: String,
    #[serde(rename = "transaction-type")]
    pub transaction_type: GetnetTransactionType,
    #[serde(rename = "parent-transaction-id")]
    pub parent_transaction_id: String,
    #[serde(rename = "requested-amount")]
    pub requested_amount: GetnetAmount,
    pub notifications: GetnetNotificationContainer,
    #[serde(rename = "ip-address")]
    pub ip_address: Option<Secret<String>>,
}

#[derive(Debug, Serialize)]
pub struct GetnetCaptureRequest {
    pub payment: GetnetCapturePaymentObject,
}

impl TryFrom<(&FloatMajorUnit, &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>)> for GetnetCaptureRequest {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        (amount, item): (&FloatMajorUnit, &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>),
    ) -> Result<Self, Self::Error> {
        // Extract merchant_id from auth
        let auth = GetnetAuthType::try_from(&item.connector_auth_type)?;

        // Get parent transaction ID (original authorization) - convert ResponseId to String
        let parent_transaction_id = match &item.request.connector_transaction_id {
            ResponseId::ConnectorTransactionId(txn_id) => txn_id.clone(),
            ResponseId::EncodedData(data) => data.clone(),
            ResponseId::NoResponseId => {
                return Err(errors::ConnectorError::MissingConnectorTransactionID.into())
            }
        };

        // Get connector_request_reference_id from resource_common_data
        let request_id = item.resource_common_data.connector_request_reference_id.clone();

        // Get IP address from browser info
        let ip_address = item
            .request
            .browser_info
            .as_ref()
            .and_then(|info| info.ip_address.clone())
            .map(|ip| Secret::new(ip.to_string()));

        // Build webhook URL - use a placeholder or empty for now as it's not available in PaymentsCaptureData
        // In production, this should be configured through connector metadata or environment
        let webhook_url = format!(
            "https://api.hyperswitch.io/webhooks/{}",
            auth.merchant_id.peek()
        );

        Ok(Self {
            payment: GetnetCapturePaymentObject {
                merchant_account_id: GetnetMerchantAccountId {
                    value: auth.merchant_id.clone(),
                },
                request_id,
                transaction_type: GetnetTransactionType::CaptureAuthorization,
                parent_transaction_id,
                requested_amount: GetnetAmount {
                    value: amount.0,
                    currency: item.request.currency.to_string(),
                },
                notifications: GetnetNotificationContainer {
                    format: "application/json-signed".to_string(),
                    notification: vec![GetnetNotification {
                        url: Some(webhook_url),
                    }],
                },
                ip_address,
            },
        })
    }
}

// ===== CAPTURE RESPONSE TRANSFORMER =====
impl
    TryFrom<
        ResponseRouterData<
            GetnetPaymentsResponse,
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    > for RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            GetnetPaymentsResponse,
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let payment = &item.response.payment;

        // Determine status based on transaction state for capture
        // success -> Charged
        // inprogress -> Pending
        // failed -> Authorized (capture failed, remains authorized)
        let status = match &payment.transaction_state {
            GetnetPaymentStatus::Success => AttemptStatus::Charged,
            GetnetPaymentStatus::InProgress => AttemptStatus::Pending,
            GetnetPaymentStatus::Failed => AttemptStatus::Authorized, // Capture failed, remains authorized
        };

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(payment.transaction_id.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: payment.request_id.clone(),
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

// ===== REFUND REQUEST STRUCTURES =====

// Refund Payment Object
#[derive(Debug, Clone, Serialize)]
pub struct GetnetRefundPaymentObject {
    #[serde(rename = "merchant-account-id")]
    pub merchant_account_id: GetnetMerchantAccountId,
    #[serde(rename = "request-id")]
    pub request_id: String,
    #[serde(rename = "transaction-type")]
    pub transaction_type: GetnetTransactionType,
    #[serde(rename = "parent-transaction-id")]
    pub parent_transaction_id: String,
    pub notifications: GetnetNotificationContainer,
    #[serde(rename = "ip-address")]
    pub ip_address: Option<Secret<String>>,
}

#[derive(Debug, Serialize)]
pub struct GetnetRefundRequest {
    pub payment: GetnetRefundPaymentObject,
}

impl TryFrom<&domain_types::router_data_v2::RouterDataV2<domain_types::connector_flow::Refund, domain_types::connector_types::RefundFlowData, domain_types::connector_types::RefundsData, domain_types::connector_types::RefundsResponseData>> for GetnetRefundRequest {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &domain_types::router_data_v2::RouterDataV2<domain_types::connector_flow::Refund, domain_types::connector_types::RefundFlowData, domain_types::connector_types::RefundsData, domain_types::connector_types::RefundsResponseData>,
    ) -> Result<Self, Self::Error> {
        // Extract merchant_id from auth
        let auth = GetnetAuthType::try_from(&item.connector_auth_type)?;

        // Get parent transaction ID (original payment transaction ID)
        let parent_transaction_id = item.request.connector_transaction_id.clone();

        // Determine transaction type based on capture method
        let transaction_type = match item.request.capture_method {
            Some(CaptureMethod::Automatic) => GetnetTransactionType::RefundPurchase,
            Some(CaptureMethod::Manual) | Some(CaptureMethod::SequentialAutomatic) => {
                GetnetTransactionType::RefundCapture
            }
            Some(CaptureMethod::ManualMultiple)
            | Some(CaptureMethod::Scheduled)
            | None => {
                return Err(errors::ConnectorError::CaptureMethodNotSupported.into());
            }
        };

        // Get IP address from browser info
        let ip_address = item
            .request
            .browser_info
            .as_ref()
            .and_then(|info| info.ip_address.clone())
            .map(|ip| Secret::new(ip.to_string()));

        // Build webhook URL
        let webhook_url = format!(
            "https://api.hyperswitch.io/webhooks/{}",
            auth.merchant_id.peek()
        );

        Ok(Self {
            payment: GetnetRefundPaymentObject {
                merchant_account_id: GetnetMerchantAccountId {
                    value: auth.merchant_id.clone(),
                },
                request_id: item.request.refund_id.clone(),
                transaction_type,
                parent_transaction_id,
                notifications: GetnetNotificationContainer {
                    format: "application/json-signed".to_string(),
                    notification: vec![GetnetNotification {
                        url: Some(webhook_url),
                    }],
                },
                ip_address,
            },
        })
    }
}

// ===== REFUND RESPONSE STRUCTURES =====

// Main Refund Response
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GetnetRefundResponseObject {
    pub statuses: Option<GetnetStatuses>,
    #[serde(rename = "merchant-account-id")]
    pub merchant_account_id: Option<GetnetMerchantAccountId>,
    #[serde(rename = "transaction-id")]
    pub transaction_id: String,
    #[serde(rename = "request-id")]
    pub request_id: Option<String>,
    #[serde(rename = "transaction-type")]
    pub transaction_type: GetnetTransactionType,
    #[serde(rename = "transaction-state")]
    pub transaction_state: GetnetPaymentStatus,
    #[serde(rename = "completion-time-stamp")]
    pub completion_time_stamp: Option<i64>,
    #[serde(rename = "requested-amount")]
    pub requested_amount: Option<GetnetAmount>,
    #[serde(rename = "parent-transaction-id")]
    pub parent_transaction_id: Option<String>,
    #[serde(rename = "parent-transaction-amount")]
    pub parent_transaction_amount: Option<GetnetAmount>,
    #[serde(rename = "card-token")]
    pub card_token: Option<GetnetCardToken>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GetnetRefundResponse {
    pub payment: GetnetRefundResponseObject,
}

// ===== REFUND RESPONSE TRANSFORMER =====
impl
    TryFrom<
        ResponseRouterData<
            GetnetRefundResponse,
            domain_types::router_data_v2::RouterDataV2<
                domain_types::connector_flow::Refund,
                domain_types::connector_types::RefundFlowData,
                domain_types::connector_types::RefundsData,
                domain_types::connector_types::RefundsResponseData,
            >,
        >,
    >
    for domain_types::router_data_v2::RouterDataV2<
        domain_types::connector_flow::Refund,
        domain_types::connector_types::RefundFlowData,
        domain_types::connector_types::RefundsData,
        domain_types::connector_types::RefundsResponseData,
    >
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            GetnetRefundResponse,
            domain_types::router_data_v2::RouterDataV2<
                domain_types::connector_flow::Refund,
                domain_types::connector_types::RefundFlowData,
                domain_types::connector_types::RefundsData,
                domain_types::connector_types::RefundsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        let payment = &item.response.payment;

        // Map Getnet status to RefundStatus
        let refund_status = match &payment.transaction_state {
            GetnetPaymentStatus::Success => common_enums::RefundStatus::Success,
            GetnetPaymentStatus::InProgress => common_enums::RefundStatus::Pending,
            GetnetPaymentStatus::Failed => common_enums::RefundStatus::Failure,
        };

        Ok(Self {
            response: Ok(domain_types::connector_types::RefundsResponseData {
                connector_refund_id: payment.transaction_id.clone(),
                refund_status,
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

// ===== REFUND SYNC RESPONSE TRANSFORMER =====
impl
    TryFrom<
        ResponseRouterData<
            GetnetRefundResponse,
            domain_types::router_data_v2::RouterDataV2<
                domain_types::connector_flow::RSync,
                domain_types::connector_types::RefundFlowData,
                domain_types::connector_types::RefundSyncData,
                domain_types::connector_types::RefundsResponseData,
            >,
        >,
    >
    for domain_types::router_data_v2::RouterDataV2<
        domain_types::connector_flow::RSync,
        domain_types::connector_types::RefundFlowData,
        domain_types::connector_types::RefundSyncData,
        domain_types::connector_types::RefundsResponseData,
    >
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            GetnetRefundResponse,
            domain_types::router_data_v2::RouterDataV2<
                domain_types::connector_flow::RSync,
                domain_types::connector_types::RefundFlowData,
                domain_types::connector_types::RefundSyncData,
                domain_types::connector_types::RefundsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        let payment = &item.response.payment;

        // Map Getnet status to RefundStatus
        let refund_status = match &payment.transaction_state {
            GetnetPaymentStatus::Success => common_enums::RefundStatus::Success,
            GetnetPaymentStatus::InProgress => common_enums::RefundStatus::Pending,
            GetnetPaymentStatus::Failed => common_enums::RefundStatus::Failure,
        };

        Ok(Self {
            response: Ok(domain_types::connector_types::RefundsResponseData {
                connector_refund_id: payment.transaction_id.clone(),
                refund_status,
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

// ===== VOID REQUEST STRUCTURES =====

// Void Payment Object
#[derive(Debug, Clone, Serialize)]
pub struct GetnetVoidPaymentObject {
    #[serde(rename = "merchant-account-id")]
    pub merchant_account_id: GetnetMerchantAccountId,
    #[serde(rename = "request-id")]
    pub request_id: String,
    #[serde(rename = "transaction-type")]
    pub transaction_type: GetnetTransactionType,
    #[serde(rename = "parent-transaction-id")]
    pub parent_transaction_id: String,
    pub notifications: GetnetNotificationContainer,
    #[serde(rename = "ip-address")]
    pub ip_address: Option<Secret<String>>,
}

#[derive(Debug, Serialize)]
pub struct GetnetVoidRequest {
    pub payment: GetnetVoidPaymentObject,
}

impl TryFrom<&domain_types::router_data_v2::RouterDataV2<domain_types::connector_flow::Void, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::PaymentVoidData, domain_types::connector_types::PaymentsResponseData>> for GetnetVoidRequest {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &domain_types::router_data_v2::RouterDataV2<domain_types::connector_flow::Void, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::PaymentVoidData, domain_types::connector_types::PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        // Extract merchant_id from auth
        let auth = GetnetAuthType::try_from(&item.connector_auth_type)?;

        // Get parent transaction ID (original payment transaction ID)
        let parent_transaction_id = item.request.connector_transaction_id.clone();

        // Determine transaction type based on capture method from connector_metadata
        // The capture_method is stored in connector_metadata during authorize/purchase
        // Default to VoidAuthorization (most common case - voiding authorized payments)
        let transaction_type = if let Some(metadata) = &item.request.connector_metadata {
            let metadata_value = metadata.peek();

            // Check if metadata is a JSON object with capture_method field
            if let Some(serde_json::Value::String(cm)) = metadata_value.get("capture_method") {
                match cm.as_str() {
                    "automatic" => GetnetTransactionType::VoidPurchase,
                    _ => GetnetTransactionType::VoidAuthorization,
                }
            } else {
                // Default to VoidAuthorization
                GetnetTransactionType::VoidAuthorization
            }
        } else {
            // No metadata, default to VoidAuthorization (most common case)
            GetnetTransactionType::VoidAuthorization
        };

        // Get connector_request_reference_id from resource_common_data
        let request_id = item.resource_common_data.connector_request_reference_id.clone();

        // Get IP address from browser info
        let ip_address = item
            .request
            .browser_info
            .as_ref()
            .and_then(|info| info.ip_address.clone())
            .map(|ip| Secret::new(ip.to_string()));

        // Build webhook URL
        let webhook_url = format!(
            "https://api.hyperswitch.io/webhooks/{}",
            auth.merchant_id.peek()
        );

        Ok(Self {
            payment: GetnetVoidPaymentObject {
                merchant_account_id: GetnetMerchantAccountId {
                    value: auth.merchant_id.clone(),
                },
                request_id,
                transaction_type,
                parent_transaction_id,
                notifications: GetnetNotificationContainer {
                    format: "application/json-signed".to_string(),
                    notification: vec![GetnetNotification {
                        url: Some(webhook_url),
                    }],
                },
                ip_address,
            },
        })
    }
}

// ===== VOID RESPONSE TRANSFORMER =====
// Reuse GetnetPaymentsResponse for void responses
impl
    TryFrom<
        ResponseRouterData<
            GetnetPaymentsResponse,
            domain_types::router_data_v2::RouterDataV2<
                domain_types::connector_flow::Void,
                domain_types::connector_types::PaymentFlowData,
                domain_types::connector_types::PaymentVoidData,
                domain_types::connector_types::PaymentsResponseData,
            >,
        >,
    >
    for domain_types::router_data_v2::RouterDataV2<
        domain_types::connector_flow::Void,
        domain_types::connector_types::PaymentFlowData,
        domain_types::connector_types::PaymentVoidData,
        domain_types::connector_types::PaymentsResponseData,
    >
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            GetnetPaymentsResponse,
            domain_types::router_data_v2::RouterDataV2<
                domain_types::connector_flow::Void,
                domain_types::connector_types::PaymentFlowData,
                domain_types::connector_types::PaymentVoidData,
                domain_types::connector_types::PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        let payment = &item.response.payment;

        // Determine status based on transaction state for void
        // success -> Voided
        // inprogress -> Pending
        // failed -> VoidFailed
        let status = match &payment.transaction_state {
            GetnetPaymentStatus::Success => AttemptStatus::Voided,
            GetnetPaymentStatus::InProgress => AttemptStatus::Pending,
            GetnetPaymentStatus::Failed => AttemptStatus::VoidFailed,
        };

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(payment.transaction_id.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: payment.request_id.clone(),
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
