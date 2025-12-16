use crate::types::ResponseRouterData;
use common_enums::{AttemptStatus, Currency, enums as storage_enums};
use common_utils::types::FloatMajorUnit;
use domain_types::{
    connector_flow::{Authorize, Capture, PSync, RSync, Refund, Void},
    connector_types::{
        PaymentFlowData, PaymentVoidData, PaymentsCaptureData, PaymentsAuthorizeData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData,
        RefundsResponseData, ResponseId,
    },
    errors,
    payment_method_data::PaymentMethodData,
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
};
use error_stack::ResultExt;
use hyperswitch_masking::{PeekInterface, Secret};
use serde::{Deserialize, Serialize};

// ============================================================================
// Authentication
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetnetAuthType {
    pub(super) username: Secret<String>,
    pub(super) password: Secret<String>,
    pub(super) merchant_id: Secret<String>,
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
                username: key1.clone(),
                password: api_key.clone(),
                merchant_id: api_secret.clone(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

// ============================================================================
// Common Types
// ============================================================================

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct MerchantAccountId {
    pub value: Secret<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Amount {
    pub value: FloatMajorUnit,
    pub currency: Currency,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Address {
    pub street1: Option<Secret<String>>,
    pub city: Option<String>,
    pub state: Option<Secret<String>>,
    pub country: Option<storage_enums::CountryAlpha2>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct AccountHolder {
    pub first_name: Option<Secret<String>>,
    pub last_name: Option<Secret<String>>,
    pub email: Option<common_utils::pii::Email>,
    pub phone: Option<Secret<String>>,
    pub address: Option<Address>,
}

#[derive(Debug, Default, Serialize, PartialEq)]
pub struct Card<T: domain_types::payment_method_data::PaymentMethodDataTypes> {
    #[serde(rename = "account-number")]
    pub account_number: domain_types::payment_method_data::RawCardNumber<T>,
    #[serde(rename = "expiration-month")]
    pub expiration_month: Secret<String>,
    #[serde(rename = "expiration-year")]
    pub expiration_year: Secret<String>,
    #[serde(rename = "card-security-code")]
    pub card_security_code: Secret<String>,
    #[serde(rename = "card-type")]
    pub card_type: String,
    #[serde(skip)]
    _phantom: std::marker::PhantomData<T>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum GetnetPaymentMethods {
    #[serde(rename = "creditcard")]
    CreditCard,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PaymentMethod {
    pub name: GetnetPaymentMethods,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Notification {
    pub url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum NotificationFormat {
    #[serde(rename = "application/json-signed")]
    JsonSigned,
    #[serde(rename = "application/json")]
    Json,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct NotificationContainer {
    pub format: NotificationFormat,
    pub notification: Vec<Notification>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct PaymentMethodContainer {
    #[serde(rename = "payment-method")]
    pub payment_method: Vec<PaymentMethod>,
}

impl TryFrom<storage_enums::PaymentMethodType> for PaymentMethodContainer {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(payment_method_type: storage_enums::PaymentMethodType) -> Result<Self, Self::Error> {
        match payment_method_type {
            storage_enums::PaymentMethodType::Card => {
                Ok(Self {
                    payment_method: vec![PaymentMethod {
                        name: GetnetPaymentMethods::CreditCard,
                    }],
                })
            }
            _ => Err(errors::ConnectorError::NotSupported {
                message: "Payment method type not supported".to_string(),
                connector: "getnet",
            }
            .into()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum GetnetTransactionType {
    Purchase,
    Authorization,
    CaptureAuthorization,
    VoidAuthorization,
    VoidPurchase,
    RefundCapture,
    RefundPurchase,
}

// ============================================================================
// Authorize Request & Response
// ============================================================================

#[derive(Debug, Serialize)]
pub struct GetnetPaymentsRequest<T: domain_types::payment_method_data::PaymentMethodDataTypes> {
    pub payment: PaymentData<T>,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct PaymentData<T: domain_types::payment_method_data::PaymentMethodDataTypes> {
    #[serde(rename = "merchant-account-id")]
    pub merchant_account_id: MerchantAccountId,
    #[serde(rename = "request-id")]
    pub request_id: String,
    #[serde(rename = "transaction-type")]
    pub transaction_type: GetnetTransactionType,
    #[serde(rename = "requested-amount")]
    pub requested_amount: Amount,
    #[serde(rename = "account-holder")]
    pub account_holder: Option<AccountHolder>,
    pub card: Card<T>,
    #[serde(rename = "ip-address")]
    pub ip_address: Option<Secret<String, common_utils::pii::IpAddress>>,
    #[serde(rename = "payment-methods")]
    pub payment_methods: PaymentMethodContainer,
    pub notifications: Option<NotificationContainer>,
    #[serde(skip)]
    _phantom: std::marker::PhantomData<T>,
}

impl<T: domain_types::payment_method_data::PaymentMethodDataTypes>
    TryFrom<&RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>
    for GetnetPaymentsRequest<T>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let auth_type = GetnetAuthType::try_from(&item.connector_auth_type)?;

        // Convert amount from minor units to major units
        let amount = common_utils::types::AmountConvertor::convert(
            &common_utils::types::FloatMajorUnitForConnector,
            item.request.minor_amount,
            item.request.currency,
        )
        .change_context(errors::ConnectorError::RequestEncodingFailed)?;

        let payment_method_data = &item.request.payment_method_data;

        let card = match payment_method_data {
            PaymentMethodData::Card(card_data) => {
                // Check if 3DS is enabled
                if item.resource_common_data.auth_type == storage_enums::AuthenticationType::ThreeDs {
                    return Err(errors::ConnectorError::NotSupported {
                        message: "3DS payments".to_string(),
                        connector: "getnet",
                    }
                    .into());
                }

                Card {
                    account_number: card_data.card_number.clone(),
                    expiration_month: card_data.card_exp_month.clone(),
                    expiration_year: card_data.card_exp_year.clone(),
                    card_security_code: card_data.card_cvc.clone(),
                    card_type: card_data
                        .card_network
                        .as_ref()
                        .map(|network| network.to_string().to_lowercase())
                        .unwrap_or_default(),
                    _phantom: std::marker::PhantomData,
                }
            }
            _ => {
                return Err(errors::ConnectorError::NotSupported {
                    message: "Payment method not supported".to_string(),
                    connector: "getnet",
                }
                .into())
            }
        };

        let billing = item.resource_common_data.get_optional_billing();
        let address = billing.as_ref().and_then(|billing| {
            billing.address.as_ref().map(|addr| Address {
                street1: addr.line2.clone(),
                city: addr.city.clone().map(|c| c.peek().clone()),
                state: addr.state.clone(),
                country: addr.country,
            })
        });

        let account_holder = Some(AccountHolder {
            first_name: billing
                .as_ref()
                .and_then(|b| b.address.as_ref())
                .and_then(|addr| addr.first_name.clone()),
            last_name: billing
                .as_ref()
                .and_then(|b| b.address.as_ref())
                .and_then(|addr| addr.last_name.clone()),
            email: billing.as_ref().and_then(|b| b.email.clone()),
            phone: billing
                .as_ref()
                .and_then(|b| b.phone.as_ref())
                .and_then(|p| p.number.clone()),
            address,
        });

        let transaction_type = if item.request.is_auto_capture()? {
            GetnetTransactionType::Purchase
        } else {
            GetnetTransactionType::Authorization
        };

        let notifications = item.request.webhook_url.as_ref().map(|url| NotificationContainer {
            format: NotificationFormat::JsonSigned,
            notification: vec![Notification {
                url: Some(url.to_string()),
            }],
        });

        let payment_method_type = item.request.payment_method_type.unwrap_or(storage_enums::PaymentMethodType::Card);
        let payment_methods = PaymentMethodContainer::try_from(payment_method_type)?;

        let ip_address = item
            .request
            .browser_info
            .as_ref()
            .and_then(|b| b.ip_address.map(|ip| Secret::new(ip.to_string())));

        Ok(Self {
            payment: PaymentData {
                merchant_account_id: MerchantAccountId {
                    value: auth_type.merchant_id,
                },
                request_id: item.resource_common_data.payment_id.clone(),
                transaction_type,
                requested_amount: Amount {
                    value: amount,
                    currency: item.request.currency,
                },
                account_holder,
                card,
                ip_address,
                payment_methods,
                notifications,
                _phantom: std::marker::PhantomData,
            },
        })
    }
}

// ============================================================================
// Payment Response (for Authorize and PSync)
// ============================================================================

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum GetnetPaymentStatus {
    Success,
    Failed,
    #[default]
    #[serde(rename = "in-progress")]
    InProgress,
}

impl From<GetnetPaymentStatus> for AttemptStatus {
    fn from(item: GetnetPaymentStatus) -> Self {
        match item {
            GetnetPaymentStatus::Success => Self::Charged,
            GetnetPaymentStatus::Failed => Self::Failure,
            GetnetPaymentStatus::InProgress => Self::Pending,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Status {
    pub code: String,
    pub description: String,
    pub severity: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Statuses {
    pub status: Vec<Status>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct CardToken {
    #[serde(rename = "token-id")]
    pub token_id: Secret<String>,
    #[serde(rename = "masked-account-number")]
    pub masked_account_number: Secret<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct PaymentResponseData {
    pub statuses: Statuses,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub descriptor: Option<String>,
    pub notifications: NotificationContainer,
    pub merchant_account_id: MerchantAccountId,
    pub transaction_id: String,
    pub request_id: String,
    pub transaction_type: GetnetTransactionType,
    pub transaction_state: GetnetPaymentStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completion_time_stamp: Option<i64>,
    pub requested_amount: Amount,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_holder: Option<AccountHolder>,
    pub card_token: CardToken,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<Secret<String, common_utils::pii::IpAddress>>,
    pub payment_methods: PaymentMethodContainer,
    pub api_id: String,
    #[serde(rename = "self")]
    pub self_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetnetPaymentsResponse {
    pub payment: PaymentResponseData,
}

// Type aliases for different flows
pub type GetnetAuthorizeResponse = GetnetPaymentsResponse;
pub type GetnetPSyncResponse = GetnetPaymentsResponse;
pub type GetnetCaptureResponse = GetnetPaymentsResponse;
pub type GetnetVoidResponse = GetnetPaymentsResponse;

pub fn authorization_attempt_status_from_transaction_state(
    getnet_status: GetnetPaymentStatus,
    is_auto_capture: bool,
) -> AttemptStatus {
    match getnet_status {
        GetnetPaymentStatus::Success => {
            if is_auto_capture {
                AttemptStatus::Charged
            } else {
                AttemptStatus::Authorized
            }
        }
        GetnetPaymentStatus::InProgress => AttemptStatus::Pending,
        GetnetPaymentStatus::Failed => AttemptStatus::Failure,
    }
}

impl<T: domain_types::payment_method_data::PaymentMethodDataTypes>
    TryFrom<
        ResponseRouterData<
            GetnetPaymentsResponse,
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        >,
    >
    for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            GetnetPaymentsResponse,
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let status = authorization_attempt_status_from_transaction_state(
            item.response.payment.transaction_state.clone(),
            item.router_data.request.is_auto_capture()?,
        );

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    item.response.payment.transaction_id,
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(item.response.payment.request_id),
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

// ============================================================================
// PSync Response (uses same response structure as Authorize)
// ============================================================================

impl TryFrom<
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
        // For PSync, check if the transaction was auto-captured based on the transaction type
        let is_auto_capture = matches!(
            item.response.payment.transaction_type,
            GetnetTransactionType::Purchase | GetnetTransactionType::CaptureAuthorization
        );

        let status = authorization_attempt_status_from_transaction_state(
            item.response.payment.transaction_state.clone(),
            is_auto_capture,
        );

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    item.response.payment.transaction_id,
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(item.response.payment.request_id),
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

// ============================================================================
// Capture Request & Response
// ============================================================================

#[derive(Debug, Serialize)]
pub struct GetnetCaptureRequest {
    pub payment: CapturePaymentData,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct CapturePaymentData {
    #[serde(rename = "merchant-account-id")]
    pub merchant_account_id: MerchantAccountId,
    #[serde(rename = "request-id")]
    pub request_id: String,
    #[serde(rename = "transaction-type")]
    pub transaction_type: GetnetTransactionType,
    #[serde(rename = "parent-transaction-id")]
    pub parent_transaction_id: String,
    #[serde(rename = "requested-amount")]
    pub requested_amount: Amount,
    pub notifications: NotificationContainer,
    #[serde(rename = "ip-address")]
    pub ip_address: Option<Secret<String, common_utils::pii::IpAddress>>,
}

impl TryFrom<&RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>>
    for GetnetCaptureRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let auth_type = GetnetAuthType::try_from(&item.connector_auth_type)?;

        // Convert amount from minor units to major units
        let amount = common_utils::types::AmountConvertor::convert(
            &common_utils::types::FloatMajorUnitForConnector,
            item.request.minor_amount_to_capture,
            item.request.currency,
        )
        .change_context(errors::ConnectorError::RequestEncodingFailed)?;

        let parent_transaction_id = item
            .request
            .connector_transaction_id
            .get_connector_transaction_id()
            .change_context(errors::ConnectorError::MissingConnectorTransactionID)?;

        // Use return URL for notifications if available, otherwise use None
        let webhook_url = item.resource_common_data.return_url.clone();
        let notifications = NotificationContainer {
            format: NotificationFormat::JsonSigned,
            notification: vec![Notification { url: webhook_url }],
        };

        let ip_address = item
            .request
            .browser_info
            .as_ref()
            .and_then(|b| b.ip_address.map(|ip| Secret::new(ip.to_string())));

        Ok(Self {
            payment: CapturePaymentData {
                merchant_account_id: MerchantAccountId {
                    value: auth_type.merchant_id,
                },
                request_id: item.resource_common_data.connector_request_reference_id.clone(),
                transaction_type: GetnetTransactionType::CaptureAuthorization,
                parent_transaction_id,
                requested_amount: Amount {
                    value: amount,
                    currency: item.request.currency,
                },
                notifications,
                ip_address,
            },
        })
    }
}

pub fn capture_status_from_transaction_state(getnet_status: GetnetPaymentStatus) -> AttemptStatus {
    match getnet_status {
        GetnetPaymentStatus::Success => AttemptStatus::Charged,
        GetnetPaymentStatus::InProgress => AttemptStatus::Pending,
        GetnetPaymentStatus::Failed => AttemptStatus::Authorized,
    }
}

impl TryFrom<
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
        let status = capture_status_from_transaction_state(item.response.payment.transaction_state);

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    item.response.payment.transaction_id,
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(item.response.payment.request_id),
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

// ============================================================================
// Void Request & Response
// ============================================================================

#[derive(Debug, Serialize)]
pub struct GetnetCancelRequest {
    pub payment: CancelPaymentData,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct CancelPaymentData {
    #[serde(rename = "merchant-account-id")]
    pub merchant_account_id: MerchantAccountId,
    #[serde(rename = "request-id")]
    pub request_id: String,
    #[serde(rename = "transaction-type")]
    pub transaction_type: GetnetTransactionType,
    #[serde(rename = "parent-transaction-id")]
    pub parent_transaction_id: String,
    pub notifications: NotificationContainer,
    #[serde(rename = "ip-address")]
    pub ip_address: Option<Secret<String, common_utils::pii::IpAddress>>,
}

impl TryFrom<&RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>>
    for GetnetCancelRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let auth_type = GetnetAuthType::try_from(&item.connector_auth_type)?;

        // Default to VoidAuthorization since we don't have capture_method in PaymentVoidData
        let transaction_type = GetnetTransactionType::VoidAuthorization;

        // Use return URL for notifications if available, otherwise use None
        let webhook_url = item.resource_common_data.return_url.clone();
        let notifications = NotificationContainer {
            format: NotificationFormat::JsonSigned,
            notification: vec![Notification { url: webhook_url }],
        };

        let ip_address = item
            .request
            .browser_info
            .as_ref()
            .and_then(|b| b.ip_address.map(|ip| Secret::new(ip.to_string())));

        Ok(Self {
            payment: CancelPaymentData {
                merchant_account_id: MerchantAccountId {
                    value: auth_type.merchant_id,
                },
                request_id: item.resource_common_data.connector_request_reference_id.clone(),
                transaction_type,
                parent_transaction_id: item.request.connector_transaction_id.clone(),
                notifications,
                ip_address,
            },
        })
    }
}

impl TryFrom<
        ResponseRouterData<
            GetnetPaymentsResponse,
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        >,
    > for RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            GetnetPaymentsResponse,
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let status = if item.response.payment.transaction_state == GetnetPaymentStatus::Success {
            AttemptStatus::Voided
        } else {
            AttemptStatus::from(item.response.payment.transaction_state)
        };

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    item.response.payment.transaction_id,
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(item.response.payment.request_id),
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

// ============================================================================
// Refund Request & Response
// ============================================================================

#[derive(Debug, Serialize)]
pub struct GetnetRefundRequest {
    pub payment: RefundPaymentData,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct RefundPaymentData {
    #[serde(rename = "merchant-account-id")]
    pub merchant_account_id: MerchantAccountId,
    #[serde(rename = "request-id")]
    pub request_id: String,
    #[serde(rename = "transaction-type")]
    pub transaction_type: GetnetTransactionType,
    #[serde(rename = "parent-transaction-id")]
    pub parent_transaction_id: String,
    pub notifications: NotificationContainer,
    #[serde(rename = "ip-address")]
    pub ip_address: Option<Secret<String, common_utils::pii::IpAddress>>,
}

impl TryFrom<&RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>>
    for GetnetRefundRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> Result<Self, Self::Error> {
        let auth_type = GetnetAuthType::try_from(&item.connector_auth_type)?;

        let transaction_type = match item.request.capture_method {
            Some(common_enums::CaptureMethod::Automatic) | None => {
                GetnetTransactionType::RefundPurchase
            }
            Some(common_enums::CaptureMethod::Manual)
            | Some(common_enums::CaptureMethod::ManualMultiple)
            | Some(common_enums::CaptureMethod::Scheduled)
            | Some(common_enums::CaptureMethod::SequentialAutomatic) => {
                GetnetTransactionType::RefundCapture
            }
        };

        let webhook_url = item.request.webhook_url.clone();
        let notifications = NotificationContainer {
            format: NotificationFormat::JsonSigned,
            notification: vec![Notification { url: webhook_url }],
        };

        let ip_address = item
            .request
            .browser_info
            .as_ref()
            .and_then(|b| b.ip_address.map(|ip| Secret::new(ip.to_string())));

        Ok(Self {
            payment: RefundPaymentData {
                merchant_account_id: MerchantAccountId {
                    value: auth_type.merchant_id,
                },
                request_id: item
                    .resource_common_data
                    .refund_id
                    .clone()
                    .unwrap_or_default(),
                transaction_type,
                parent_transaction_id: item.request.connector_transaction_id.clone(),
                notifications,
                ip_address,
            },
        })
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum RefundStatus {
    Success,
    Failed,
    #[default]
    #[serde(rename = "in-progress")]
    InProgress,
}

impl From<RefundStatus> for storage_enums::RefundStatus {
    fn from(item: RefundStatus) -> Self {
        match item {
            RefundStatus::Success => Self::Success,
            RefundStatus::Failed => Self::Failure,
            RefundStatus::InProgress => Self::Pending,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct RefundResponseData {
    pub statuses: Statuses,
    pub descriptor: String,
    pub notifications: NotificationContainer,
    pub merchant_account_id: MerchantAccountId,
    pub transaction_id: String,
    pub request_id: String,
    pub transaction_type: GetnetTransactionType,
    pub transaction_state: RefundStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completion_time_stamp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_transaction_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_holder: Option<AccountHolder>,
    pub card_token: CardToken,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<Secret<String, common_utils::pii::IpAddress>>,
    pub payment_methods: PaymentMethodContainer,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_transaction_amount: Option<Amount>,
    pub api_id: String,
    #[serde(rename = "self")]
    pub self_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefundResponse {
    pub payment: RefundResponseData,
}

pub type GetnetRSyncResponse = RefundResponse;

impl TryFrom<
        ResponseRouterData<
            RefundResponse,
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    > for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            RefundResponse,
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let refund_status = storage_enums::RefundStatus::from(item.response.payment.transaction_state);

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.payment.transaction_id,
                refund_status,
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

// ============================================================================
// RSync Response (uses same response structure as Refund)
// ============================================================================

impl TryFrom<
        ResponseRouterData<
            RefundResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    > for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            RefundResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let refund_status = storage_enums::RefundStatus::from(item.response.payment.transaction_state);

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.payment.transaction_id,
                refund_status,
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

// ============================================================================
// Error Response
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetnetErrorResponse {
    pub payment: ErrorPaymentData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ErrorPaymentData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,
    pub statuses: Statuses,
}

impl GetnetErrorResponse {
    pub fn code(&self) -> String {
        self.payment
            .statuses
            .status
            .first()
            .map(|s| s.code.clone())
            .unwrap_or_else(|| "unknown_error".to_string())
    }

    pub fn message(&self) -> String {
        self.payment
            .statuses
            .status
            .first()
            .map(|s| s.description.clone())
            .unwrap_or_else(|| "Unknown error occurred".to_string())
    }
}

// ============================================================================
// GetnetRouterData Wrapper Implementations
// ============================================================================

use super::GetnetRouterData;

impl<T: domain_types::payment_method_data::PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + serde::Serialize>
    TryFrom<GetnetRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>>
    for GetnetPaymentsRequest<T>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: GetnetRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        Self::try_from(&item.router_data)
    }
}

impl<T: domain_types::payment_method_data::PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + serde::Serialize>
    TryFrom<GetnetRouterData<RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>, T>>
    for GetnetCaptureRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: GetnetRouterData<RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        Self::try_from(&item.router_data)
    }
}

impl<T: domain_types::payment_method_data::PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + serde::Serialize>
    TryFrom<GetnetRouterData<RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>, T>>
    for GetnetCancelRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: GetnetRouterData<RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        Self::try_from(&item.router_data)
    }
}

impl<T: domain_types::payment_method_data::PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + serde::Serialize>
    TryFrom<GetnetRouterData<RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>, T>>
    for GetnetRefundRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: GetnetRouterData<RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        Self::try_from(&item.router_data)
    }
}
