use crate::types::ResponseRouterData;
use common_enums::{AttemptStatus, RefundStatus};
use domain_types::{
    connector_flow::{Authorize, Capture, PSync, PaymentMethodToken, RSync, Refund, Void},
    connector_types::{
        PaymentFlowData, PaymentMethodTokenResponse, PaymentMethodTokenizationData,
        PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData,
        PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData,
        ResponseId,
    },
    errors,
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes},
    router_data::{ConnectorAuthType, PaymentMethodToken as PaymentMethodTokenType},
    router_data_v2::RouterDataV2,
};
use error_stack::ResultExt;
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct HipayAuthType {
    pub api_key: Secret<String>,
    pub api_secret: Option<Secret<String>>,
}

impl TryFrom<&ConnectorAuthType> for HipayAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::HeaderKey { api_key } => Ok(Self {
                api_key: api_key.to_owned(),
                api_secret: None,
            }),
            ConnectorAuthType::BodyKey {
                api_key,
                key1: api_secret,
            } => Ok(Self {
                api_key: api_key.to_owned(),
                api_secret: Some(api_secret.to_owned()),
            }),
            ConnectorAuthType::SignatureKey {
                api_key,
                api_secret,
                ..
            } => Ok(Self {
                api_key: api_key.to_owned(),
                api_secret: Some(api_secret.to_owned()),
            }),
            _ => Err(error_stack::report!(
                errors::ConnectorError::FailedToObtainAuthType
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HipayErrorResponse {
    pub code: String,
    pub message: String,
}

// HiPay Payment Status Enum - Type-safe status codes from HiPay API
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum HipayPaymentStatus {
    #[serde(rename = "109")]
    AuthenticationFailed,
    #[serde(rename = "110")]
    Blocked,
    #[serde(rename = "111")]
    Denied,
    #[serde(rename = "112")]
    AuthorizedAndPending,
    #[serde(rename = "113")]
    Refused,
    #[serde(rename = "114")]
    Expired,
    #[serde(rename = "115")]
    Cancelled,
    #[serde(rename = "116")]
    Authorized,
    #[serde(rename = "117")]
    CaptureRequested,
    #[serde(rename = "118")]
    Captured,
    #[serde(rename = "119")]
    PartiallyCaptured,
    #[serde(rename = "129")]
    ChargedBack,
    #[serde(rename = "173")]
    CaptureRefused,
    #[serde(rename = "174")]
    AwaitingTerminal,
    #[serde(rename = "175")]
    AuthorizationCancellationRequested,
    #[serde(rename = "177")]
    ChallengeRequested,
    #[serde(rename = "178")]
    SoftDeclined,
    #[serde(rename = "200")]
    PendingPayment,
    #[serde(rename = "101")]
    Created,
    #[serde(rename = "105")]
    UnableToAuthenticate,
    #[serde(rename = "106")]
    CardholderAuthenticated,
    #[serde(rename = "107")]
    AuthenticationAttempted,
    #[serde(rename = "108")]
    CouldNotAuthenticate,
    #[serde(rename = "120")]
    Collected,
    #[serde(rename = "121")]
    PartiallyCollected,
    #[serde(rename = "122")]
    Settled,
    #[serde(rename = "123")]
    PartiallySettled,
    #[serde(rename = "140")]
    AuthenticationRequested,
    #[serde(rename = "141")]
    Authenticated,
    #[serde(rename = "151")]
    AcquirerNotFound,
    #[serde(rename = "161")]
    RiskAccepted,
    #[serde(rename = "163")]
    AuthorizationRefused,
}

impl From<HipayPaymentStatus> for AttemptStatus {
    fn from(status: HipayPaymentStatus) -> Self {
        match status {
            HipayPaymentStatus::AuthenticationFailed => Self::AuthenticationFailed,
            HipayPaymentStatus::Blocked
            | HipayPaymentStatus::Refused
            | HipayPaymentStatus::Expired
            | HipayPaymentStatus::Denied => Self::Failure,
            HipayPaymentStatus::AuthorizedAndPending => Self::Pending,
            HipayPaymentStatus::Cancelled => Self::Voided,
            HipayPaymentStatus::Authorized => Self::Authorized,
            HipayPaymentStatus::CaptureRequested => Self::CaptureInitiated,
            HipayPaymentStatus::Captured => Self::Charged,
            HipayPaymentStatus::PartiallyCaptured => Self::PartialCharged,
            HipayPaymentStatus::CaptureRefused => Self::CaptureFailed,
            HipayPaymentStatus::AwaitingTerminal => Self::Pending,
            HipayPaymentStatus::AuthorizationCancellationRequested => Self::VoidInitiated,
            HipayPaymentStatus::ChallengeRequested => Self::AuthenticationPending,
            HipayPaymentStatus::SoftDeclined => Self::Failure,
            HipayPaymentStatus::PendingPayment => Self::Pending,
            HipayPaymentStatus::ChargedBack => Self::Failure,
            HipayPaymentStatus::Created => Self::Started,
            HipayPaymentStatus::UnableToAuthenticate
            | HipayPaymentStatus::CouldNotAuthenticate => Self::AuthenticationFailed,
            HipayPaymentStatus::CardholderAuthenticated => Self::Pending,
            HipayPaymentStatus::AuthenticationAttempted => Self::AuthenticationPending,
            HipayPaymentStatus::Collected
            | HipayPaymentStatus::PartiallySettled
            | HipayPaymentStatus::PartiallyCollected
            | HipayPaymentStatus::Settled => Self::Charged,
            HipayPaymentStatus::AuthenticationRequested => Self::AuthenticationPending,
            HipayPaymentStatus::Authenticated => Self::AuthenticationSuccessful,
            HipayPaymentStatus::AcquirerNotFound => Self::Failure,
            HipayPaymentStatus::RiskAccepted => Self::Pending,
            HipayPaymentStatus::AuthorizationRefused => Self::Failure,
        }
    }
}

// HiPay Refund Status Enum - Type-safe refund status codes
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum HipayRefundStatus {
    #[serde(rename = "124")]
    RefundRequested,
    #[serde(rename = "125")]
    Refunded,
    #[serde(rename = "126")]
    PartiallyRefunded,
    #[serde(rename = "165")]
    RefundRefused,
}

impl From<HipayRefundStatus> for RefundStatus {
    fn from(item: HipayRefundStatus) -> Self {
        match item {
            HipayRefundStatus::RefundRequested => Self::Pending,
            HipayRefundStatus::Refunded | HipayRefundStatus::PartiallyRefunded => Self::Success,
            HipayRefundStatus::RefundRefused => Self::Failure,
        }
    }
}

// Sync Response Types
// Nested transaction details structure for PSync response
#[derive(Debug, Serialize, Deserialize)]
pub struct HipayTransactionDetails {
    pub status: HipayPaymentStatus,
    pub message: String,
    #[serde(rename = "transactionReference")]
    pub transaction_reference: String,
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum HipaySyncResponse {
    Response {
        transaction: HipayTransactionDetails,
    },
    Error {
        message: String,
        code: u32
    },
}

// XML wrapper for refund sync response - HiPay returns XML for sync operations
#[derive(Debug, Serialize, Deserialize)]
pub struct HipayRefundSyncXmlResponse {
    pub transaction: HipayRefundTransactionDetails,
}

// Refund transaction details from XML response
#[derive(Debug, Serialize, Deserialize)]
pub struct HipayRefundTransactionDetails {
    pub status: HipayRefundStatus,
    pub message: String,
    pub transaction_reference: String,
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, serde_json::Value>,
}

// Type alias for backward compatibility
pub type HipayRefundSyncResponse = HipayRefundSyncXmlResponse;

#[derive(Debug, Serialize, Deserialize)]
pub struct HipayPaymentsRequest<T: PaymentMethodDataTypes> {
    pub payment_product: String,
    pub orderid: String,
    pub operation: String,
    pub description: String,
    pub currency: String,
    pub amount: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cardtoken: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card_security_code: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub firstname: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lastname: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipaddr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accept_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decline_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cancel_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exception_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eci: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication_indicator: Option<String>,
    #[serde(skip)]
    _phantom: std::marker::PhantomData<T>,
}

impl<T: PaymentMethodDataTypes>
    TryFrom<
        &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    > for HipayPaymentsRequest<T>
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
        use hyperswitch_masking::PeekInterface;

        // Get payment method - determine payment_product
        let payment_product = match &item.request.payment_method_data {
            PaymentMethodData::Card(_) => {
                // Use "visa" as default for cards - could be enhanced based on card type
                "visa".to_string()
            }
            PaymentMethodData::CardToken(_) => "visa".to_string(),
            _ => {
                return Err(errors::ConnectorError::NotImplemented(
                    "Payment method not supported".to_string(),
                ))
                .change_context(errors::ConnectorError::NotImplemented(
                    "Payment method".to_string(),
                ))
            }
        };

        // Determine operation based on capture method
        let operation = match item.request.capture_method {
            Some(common_enums::CaptureMethod::Manual) => "Authorization".to_string(),
            _ => "Sale".to_string(), // Automatic capture or default
        };

        // Extract customer information
        let (firstname, lastname) = item
            .resource_common_data
            .get_optional_billing_full_name()
            .map(|name| {
                let name_str = name.peek();
                let parts: Vec<&str> = name_str.split_whitespace().collect();
                if parts.len() > 1 {
                    (
                        Some(Secret::new(parts[0].to_string())),
                        Some(Secret::new(parts[1..].join(" "))),
                    )
                } else if parts.len() == 1 {
                    (Some(Secret::new(parts[0].to_string())), None)
                } else {
                    (None, None)
                }
            })
            .unwrap_or((None, None));

        // Get email - convert Email type to Secret<String>
        let email = item.request.email.as_ref().map(|e| {
            use hyperswitch_masking::PeekInterface;
            Secret::new(e.peek().to_string())
        });

        // Get IP address
        let ipaddr = item
            .request
            .browser_info
            .as_ref()
            .and_then(|b| b.ip_address.as_ref())
            .map(|ip| ip.to_string());

        // Get return URLs from router data
        let accept_url = item.request.complete_authorize_url.clone();
        let decline_url = accept_url.clone();
        let pending_url = accept_url.clone();
        let cancel_url = accept_url.clone();
        let exception_url = accept_url.clone();

        // Convert amount to string (HiPay expects string with decimals)
        use common_utils::types::AmountConvertor;
        let amount_converter = common_utils::types::StringMajorUnitForConnector;
        let amount = amount_converter
            .convert(item.request.minor_amount, item.request.currency)
            .change_context(errors::ConnectorError::AmountConversionFailed)?
            .get_amount_as_string();

        // Extract card token from payment_method_token if present,
        // or from connector_customer as fallback (when token is passed via gRPC)
        let cardtoken = item
            .resource_common_data
            .payment_method_token
            .as_ref()
            .and_then(|pmt| match pmt {
                PaymentMethodTokenType::Token(token) => Some(token.peek().to_string()),
                _ => None,
            })
            .or_else(|| item.resource_common_data.connector_customer.clone());

        // Extract CVC for tokenized payments (HiPay requires CVC with token)
        let card_security_code = match &item.request.payment_method_data {
            PaymentMethodData::CardToken(token_data) => token_data.card_cvc.clone(),
            PaymentMethodData::Card(card_data) => Some(card_data.card_cvc.clone()),
            _ => None,
        };

        Ok(Self {
            payment_product,
            orderid: item
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            operation,
            description: item
                .request
                .statement_descriptor
                .clone()
                .unwrap_or_else(|| "Payment".to_string()),
            currency: item.request.currency.to_string(),
            amount,
            cardtoken,
            card_security_code,
            email,
            firstname,
            lastname,
            ipaddr,
            accept_url,
            decline_url,
            pending_url,
            cancel_url,
            exception_url,
            eci: None,
            authentication_indicator: None,
            _phantom: std::marker::PhantomData,
        })
    }
}

// Response Structures aligned with Hyperswitch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentOrder {
    id: String,
}

// Authorize Response - matches HiPay's order API response (camelCase from HiPay API)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HipayPaymentsResponse {
    status: HipayPaymentStatus,
    message: String,
    order: PaymentOrder,
    #[serde(default)]
    #[serde(rename = "forwardUrl")]
    forward_url: String,
    #[serde(rename = "transactionReference")]
    transaction_reference: String,
}

// Generic Maintenance Response for Capture/Void/Refund operations (camelCase from HiPay API)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HipayMaintenanceResponse<S> {
    status: S,
    message: String,
    #[serde(rename = "transactionReference")]
    transaction_reference: String,
}

// Type aliases for different flows - operation-specific types
pub type HipayAuthorizeResponse = HipayPaymentsResponse;
pub type HipayCaptureResponse = HipayMaintenanceResponse<HipayPaymentStatus>;
pub type HipayVoidResponse = HipayMaintenanceResponse<HipayPaymentStatus>;
pub type HipayRefundResponse = HipayMaintenanceResponse<HipayRefundStatus>;
pub type HipayPSyncResponse = HipaySyncResponse;
pub type HipayRSyncResponse = HipayRefundSyncResponse;


impl<T: PaymentMethodDataTypes>
    TryFrom<
        ResponseRouterData<
            HipayAuthorizeResponse,
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
            HipayAuthorizeResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        // Convert HipayPaymentStatus enum directly to AttemptStatus using From trait
        let status = AttemptStatus::from(item.response.status.clone());

        // Check if status is failure to return error response
        let response = if status == AttemptStatus::Failure {
            Err(domain_types::router_data::ErrorResponse {
                code: "DECLINED".to_string(),
                message: item.response.message.clone(),
                reason: Some(item.response.message.clone()),
                status_code: item.http_code,
                attempt_status: None,
                connector_transaction_id: Some(item.response.transaction_reference.clone()),
                network_decline_code: None,
                network_advice_code: None,
                network_error_message: None,
            })
        } else {
            // Check if redirection is needed (for 3DS flows)
            let redirection_data = if !item.response.forward_url.is_empty() {
                Some(Box::new(
                    domain_types::router_response_types::RedirectForm::Uri {
                        uri: item.response.forward_url.clone(),
                    },
                ))
            } else {
                None
            };

            Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    item.response.transaction_reference.clone(),
                ),
                redirection_data,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(item.response.order.id.clone()),
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            })
        };

        Ok(Self {
            response,
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

// Tokenization Structures
#[derive(Debug, Serialize, Deserialize)]
pub struct HipayTokenRequest<T: PaymentMethodDataTypes> {
    pub card_number: domain_types::payment_method_data::RawCardNumber<T>,
    pub card_expiry_month: Secret<String>,
    pub card_expiry_year: Secret<String>,
    pub card_holder: Secret<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cvc: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub multi_use: Option<String>,
}

impl<T: PaymentMethodDataTypes>
    TryFrom<
        &RouterDataV2<
            PaymentMethodToken,
            PaymentFlowData,
            PaymentMethodTokenizationData<T>,
            PaymentMethodTokenResponse,
        >,
    > for HipayTokenRequest<T>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<
            PaymentMethodToken,
            PaymentFlowData,
            PaymentMethodTokenizationData<T>,
            PaymentMethodTokenResponse,
        >,
    ) -> Result<Self, Self::Error> {
        match &item.request.payment_method_data {
            PaymentMethodData::Card(card_data) => Ok(Self {
                card_number: card_data.card_number.clone(),
                card_expiry_month: card_data.card_exp_month.clone(),
                card_expiry_year: card_data.card_exp_year.clone(),
                card_holder: item
                    .resource_common_data
                    .get_optional_billing_full_name()
                    .unwrap_or(Secret::new("".to_string())),
                cvc: Some(card_data.card_cvc.clone()),
                multi_use: Some("1".to_string()), // 1 for multi-use token
            }),
            PaymentMethodData::CardRedirect(_)
            | PaymentMethodData::Wallet(_)
            | PaymentMethodData::PayLater(_)
            | PaymentMethodData::BankRedirect(_)
            | PaymentMethodData::BankDebit(_)
            | PaymentMethodData::BankTransfer(_)
            | PaymentMethodData::Crypto(_)
            | PaymentMethodData::MandatePayment
            | PaymentMethodData::Reward
            | PaymentMethodData::RealTimePayment(_)
            | PaymentMethodData::MobilePayment(_)
            | PaymentMethodData::Upi(_)
            | PaymentMethodData::Voucher(_)
            | PaymentMethodData::GiftCard(_)
            | PaymentMethodData::CardToken(_)
            | PaymentMethodData::OpenBanking(_)
            | PaymentMethodData::NetworkToken(_)
            | PaymentMethodData::CardDetailsForNetworkTransactionId(_) => {
                Err(errors::ConnectorError::NotImplemented(
                    "Payment method not supported for tokenization".to_string(),
                ))
                .change_context(errors::ConnectorError::NotImplemented(
                    "Payment method".to_string(),
                ))
            }
        }
    }
}


#[derive(Debug, Deserialize, Serialize)]
pub struct HipayTokenResponse {
    pub token: String,
    pub request_id: String,
    pub brand: String,
    pub pan: String,
    pub card_holder: String,
    pub card_expiry_month: String,
    pub card_expiry_year: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
}

impl<T: PaymentMethodDataTypes>
    TryFrom<
        ResponseRouterData<
            HipayTokenResponse,
            RouterDataV2<
                PaymentMethodToken,
                PaymentFlowData,
                PaymentMethodTokenizationData<T>,
                PaymentMethodTokenResponse,
            >,
        >,
    >
    for RouterDataV2<
        PaymentMethodToken,
        PaymentFlowData,
        PaymentMethodTokenizationData<T>,
        PaymentMethodTokenResponse,
    >
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            HipayTokenResponse,
            RouterDataV2<
                PaymentMethodToken,
                PaymentFlowData,
                PaymentMethodTokenizationData<T>,
                PaymentMethodTokenResponse,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(PaymentMethodTokenResponse {
                token: item.response.token,
            }),
            ..item.router_data
        })
    }
}


// Payment Sync Response Implementation
// Uses HipaySyncResponse enum with get_sync_status helper
impl
    TryFrom<
        ResponseRouterData<
            HipayPSyncResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    > for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            HipayPSyncResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        // Handle sync response - could be Response or Error variant
        match item.response {
            HipaySyncResponse::Response { transaction } => {
                // Convert HipayPaymentStatus enum directly to AttemptStatus using From trait
                let attempt_status = AttemptStatus::from(transaction.status.clone());

                Ok(Self {
                    response: Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(
                            transaction.transaction_reference.clone(),
                        ),
                        redirection_data: None,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: None,
                        connector_response_reference_id: None,
                        incremental_authorization_allowed: None,
                        status_code: item.http_code,
                    }),
                    resource_common_data: PaymentFlowData {
                        status: attempt_status,
                        ..item.router_data.resource_common_data
                    },
                    ..item.router_data
                })
            }
            HipaySyncResponse::Error { message, code } => {
                Ok(Self {
                    response: Err(domain_types::router_data::ErrorResponse {
                        code: code.to_string(),
                        message: message.clone(),
                        reason: Some(message),
                        status_code: item.http_code,
                        attempt_status: None,
                        connector_transaction_id: item.router_data.request.connector_transaction_id.get_connector_transaction_id().ok(),
                        network_decline_code: None,
                        network_advice_code: None,
                        network_error_message: None,
                    }),
                    resource_common_data: PaymentFlowData {
                        status: AttemptStatus::Failure,
                        ..item.router_data.resource_common_data
                    },
                    ..item.router_data
                })
            }
        }
    }
}

// Capture Request Structure
#[derive(Debug, Serialize, Deserialize)]
pub struct HipayCaptureRequest {
    pub operation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
}

impl TryFrom<&RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>>
    for HipayCaptureRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        // Convert amount to string with decimals (HiPay expects decimal format)
        use common_utils::types::AmountConvertor;
        let amount_converter = common_utils::types::StringMajorUnitForConnector;
        let amount = amount_converter
            .convert(item.request.minor_amount_to_capture, item.request.currency)
            .change_context(errors::ConnectorError::AmountConversionFailed)?
            .get_amount_as_string();

        Ok(Self {
            operation: "capture".to_string(),
            amount: Some(amount),
            currency: Some(item.request.currency.to_string()),
            operation_id: Some(
                item.resource_common_data
                    .connector_request_reference_id
                    .clone(),
            ),
        })
    }
}

// Capture Response Implementation
// Uses HipayMaintenanceResponse<HipayPaymentStatus> with direct enum conversion
impl
    TryFrom<
        ResponseRouterData<
            HipayCaptureResponse,
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    > for RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            HipayCaptureResponse,
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        // Convert HipayPaymentStatus enum directly to AttemptStatus using From trait
        let status = AttemptStatus::from(item.response.status.clone());

        // Check if status indicates failure
        let response = if status == AttemptStatus::Failure || status == AttemptStatus::CaptureFailed {
            Err(domain_types::router_data::ErrorResponse {
                code: "CAPTURE_FAILED".to_string(),
                message: item.response.message.clone(),
                reason: Some(item.response.message.clone()),
                status_code: item.http_code,
                attempt_status: None,
                connector_transaction_id: Some(item.response.transaction_reference.clone()),
                network_decline_code: None,
                network_advice_code: None,
                network_error_message: None,
            })
        } else {
            Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    item.response.transaction_reference.clone(),
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            })
        };

        Ok(Self {
            response,
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

// Refund Request Structure
#[derive(Debug, Serialize, Deserialize)]
pub struct HipayRefundRequest {
    pub operation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
}

impl TryFrom<&RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>>
    for HipayRefundRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> Result<Self, Self::Error> {
        // Convert minor unit amount to decimal format (HiPay expects decimal format)
        use common_utils::types::AmountConvertor;
        let amount_converter = common_utils::types::StringMajorUnitForConnector;
        let amount = amount_converter
            .convert(item.request.minor_refund_amount, item.request.currency)
            .change_context(errors::ConnectorError::AmountConversionFailed)?
            .get_amount_as_string();

        Ok(Self {
            operation: "refund".to_string(),
            amount: Some(amount),
            currency: Some(item.request.currency.to_string()),
            operation_id: Some(item.request.refund_id.clone()),
        })
    }
}

// Refund Response Implementation
// Uses HipayMaintenanceResponse<HipayRefundStatus> with From trait conversion
impl
    TryFrom<
        ResponseRouterData<
            HipayRefundResponse,
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    > for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            HipayRefundResponse,
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        // Convert HipayRefundStatus enum directly to RefundStatus using From trait
        let refund_status = RefundStatus::from(item.response.status.clone());

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.transaction_reference.clone(),
                refund_status,
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

// Refund Sync Response Implementation
// Uses HipayRefundSyncResponse enum to handle both success and error responses
impl
    TryFrom<
        ResponseRouterData<
            HipayRSyncResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    > for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            HipayRSyncResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        // Handle refund sync XML response
        let transaction = &item.response.transaction;

        // Convert HipayRefundStatus enum directly to RefundStatus using From trait
        let refund_status = RefundStatus::from(transaction.status.clone());

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: transaction.transaction_reference.clone(),
                refund_status,
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

// Void Request Structure
#[derive(Debug, Serialize, Deserialize)]
pub struct HipayVoidRequest {
    pub operation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

impl TryFrom<&RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>>
    for HipayVoidRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            operation: "cancel".to_string(),
            operation_id: Some(
                item.resource_common_data
                    .connector_request_reference_id
                    .clone(),
            ),
            source: None,
        })
    }
}

// Void Response Implementation
// Uses HipayMaintenanceResponse<HipayPaymentStatus> with direct enum conversion
impl
    TryFrom<
        ResponseRouterData<
            HipayVoidResponse,
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        >,
    > for RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            HipayVoidResponse,
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        // Convert HipayPaymentStatus enum directly to AttemptStatus using From trait
        let status = AttemptStatus::from(item.response.status.clone());

        // Check if status indicates void failure
        let response = if status == AttemptStatus::Failure || status == AttemptStatus::VoidFailed {
            Err(domain_types::router_data::ErrorResponse {
                code: "VOID_FAILED".to_string(),
                message: item.response.message.clone(),
                reason: Some(item.response.message.clone()),
                status_code: item.http_code,
                attempt_status: None,
                connector_transaction_id: Some(item.response.transaction_reference.clone()),
                network_decline_code: None,
                network_advice_code: None,
                network_error_message: None,
            })
        } else {
            Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    item.response.transaction_reference.clone(),
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            })
        };

        Ok(Self {
            response,
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}
