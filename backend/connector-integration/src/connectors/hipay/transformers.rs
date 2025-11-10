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
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

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

#[derive(Debug, Serialize)]
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
        // or from connector_customer as fallback (when token is passed from PreAuthenticate via gRPC)
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

#[derive(Debug, Deserialize, Serialize)]
pub struct HipayPaymentsResponse {
    pub transaction_reference: String,
    pub state: String,
    #[serde(deserialize_with = "deserialize_status")]
    pub status: i32,
    pub authorized_amount: Option<String>,
    pub captured_amount: Option<String>,
    pub decimals: Option<String>,
    pub currency: Option<String>,
    pub payment_product: Option<String>,
    pub forward_url: Option<String>,
    pub message: Option<String>,
    // Additional fields that may be present in HiPay responses (including order, reason, etc.)
    #[serde(flatten)]
    pub additional_fields: std::collections::HashMap<String, Value>,
}

// Custom deserializer for status field that can handle both string and integer
fn deserialize_status<'de, D>(deserializer: D) -> Result<i32, D::Error>
where
    D: Deserializer<'de>,
{
    let value: Value = Deserialize::deserialize(deserializer)?;

    match value {
        Value::Number(n) => n
            .as_i64()
            .and_then(|i| i32::try_from(i).ok())
            .ok_or_else(|| serde::de::Error::custom("Invalid number for status")),
        Value::String(s) => s
            .parse::<i32>()
            .map_err(|_| serde::de::Error::custom("Invalid string for status")),
        _ => Err(serde::de::Error::custom("Expected number or string for status")),
    }
}

// Helper function to extract order ID from Value (handles both structured and $text wrapped)
fn extract_order_id(order: &Value) -> Option<String> {
    order
        .as_object()
        .and_then(|obj| obj.get("id"))
        .and_then(|id_val| {
            // Handle {"$text": "value"} case
            if let Some(text_obj) = id_val.as_object() {
                text_obj.get("$text").and_then(|v| v.as_str()).map(|s| s.to_string())
            } else {
                // Handle direct string case
                id_val.as_str().map(|s| s.to_string())
            }
        })
}

// Type aliases for different flows to avoid macro templating conflicts
pub type HipayAuthorizeResponse = HipayPaymentsResponse;
pub type HipayPSyncResponse = HipayPaymentsResponse;
pub type HipayCaptureResponse = HipayPaymentsResponse;
pub type HipayVoidResponse = HipayPaymentsResponse;
pub type HipayRefundResponse = HipayPaymentsResponse;
pub type HipayRSyncResponse = HipayPaymentsResponse;


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
        // Map HiPay state to AttemptStatus
        let status = match item.response.state.as_str() {
            "completed" => {
                // Check if it's authorized or charged based on capture status
                if item.response.captured_amount.is_some()
                    && item.response.captured_amount.as_ref().unwrap() != "0.00"
                {
                    AttemptStatus::Charged
                } else {
                    AttemptStatus::Authorized
                }
            }
            "forwarding" => AttemptStatus::AuthenticationPending,
            "pending" => AttemptStatus::Pending,
            "declined" => AttemptStatus::Failure,
            "error" => AttemptStatus::Failure,
            _ => {
                // Additional status code checks
                match item.response.status {
                    116 => AttemptStatus::Charged,    // Captured
                    117 => AttemptStatus::Authorized, // Authorized
                    118 => AttemptStatus::Voided,     // Cancelled
                    119 => AttemptStatus::Voided,     // Refund Requested
                    _ => AttemptStatus::Pending,
                }
            }
        };

        // Handle redirection if forward_url is present
        let redirection_data = item.response.forward_url.as_ref().map(|url| {
            Box::new(domain_types::router_response_types::RedirectForm::Uri { uri: url.clone() })
        });

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    item.response.transaction_reference.clone(),
                ),
                redirection_data,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: item
                    .response
                    .additional_fields
                    .get("order")
                    .and_then(extract_order_id),
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

// Tokenization Structures
#[derive(Debug, Serialize)]
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

// PreAuthenticate transformer (same as PaymentMethodToken for HiPay tokenization)
impl<T: PaymentMethodDataTypes>
    TryFrom<
        &RouterDataV2<
            domain_types::connector_flow::PreAuthenticate,
            PaymentFlowData,
            domain_types::connector_types::PaymentsPreAuthenticateData<T>,
            PaymentsResponseData,
        >,
    > for HipayTokenRequest<T>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<
            domain_types::connector_flow::PreAuthenticate,
            PaymentFlowData,
            domain_types::connector_types::PaymentsPreAuthenticateData<T>,
            PaymentsResponseData,
        >,
    ) -> Result<Self, Self::Error> {
        match &item.request.payment_method_data {
            Some(PaymentMethodData::Card(card_data)) => Ok(Self {
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
            _ => Err(errors::ConnectorError::NotImplemented(
                "Payment method not supported for PreAuthenticate tokenization".to_string(),
            ))
            .change_context(errors::ConnectorError::NotImplemented(
                "Payment method".to_string(),
            )),
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

// PreAuthenticate response transformer - stores token in payment_method_token
impl<T: PaymentMethodDataTypes>
    TryFrom<
        ResponseRouterData<
            HipayTokenResponse,
            RouterDataV2<
                domain_types::connector_flow::PreAuthenticate,
                PaymentFlowData,
                domain_types::connector_types::PaymentsPreAuthenticateData<T>,
                PaymentsResponseData,
            >,
        >,
    >
    for RouterDataV2<
        domain_types::connector_flow::PreAuthenticate,
        PaymentFlowData,
        domain_types::connector_types::PaymentsPreAuthenticateData<T>,
        PaymentsResponseData,
    >
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            HipayTokenResponse,
            RouterDataV2<
                domain_types::connector_flow::PreAuthenticate,
                PaymentFlowData,
                domain_types::connector_types::PaymentsPreAuthenticateData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        // Store token in payment_method_token so Authorize can use it
        let payment_method_token = Some(PaymentMethodTokenType::Token(
            Secret::new(item.response.token.clone()),
        ));

        Ok(Self {
            response: Ok(PaymentsResponseData::PreAuthenticateResponse {
                redirection_data: None,
                connector_response_reference_id: Some(item.response.request_id),
                status_code: item.http_code,
            }),
            resource_common_data: PaymentFlowData {
                payment_method_token,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

// Payment Sync Response Implementation
// Reuses HipayPaymentsResponse structure as the sync endpoint returns the same format
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
        // Map HiPay state to AttemptStatus (same mapping logic as authorize)
        let status = match item.response.state.as_str() {
            "completed" => {
                // Check if it's authorized or charged based on capture status
                if item.response.captured_amount.is_some()
                    && item.response.captured_amount.as_ref().unwrap() != "0.00"
                {
                    AttemptStatus::Charged
                } else {
                    AttemptStatus::Authorized
                }
            }
            "forwarding" => AttemptStatus::AuthenticationPending,
            "pending" => AttemptStatus::Pending,
            "declined" => AttemptStatus::Failure,
            "error" => AttemptStatus::Failure,
            _ => {
                // Additional status code checks
                match item.response.status {
                    116 => AttemptStatus::Charged,    // Captured
                    117 => AttemptStatus::Authorized, // Authorized
                    118 => AttemptStatus::Voided,     // Cancelled
                    119 => AttemptStatus::Voided,     // Refund Requested
                    _ => AttemptStatus::Pending,
                }
            }
        };

        // Handle redirection if forward_url is present
        let redirection_data = item.response.forward_url.as_ref().map(|url| {
            Box::new(domain_types::router_response_types::RedirectForm::Uri { uri: url.clone() })
        });

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    item.response.transaction_reference.clone(),
                ),
                redirection_data,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: item
                    .response
                    .additional_fields
                    .get("order")
                    .and_then(extract_order_id),
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

// Capture Request Structure
#[derive(Debug, Serialize)]
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
// Reuses HipayPaymentsResponse structure as the capture endpoint returns the same format
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
        // Map HiPay state to AttemptStatus for capture
        let status = match item.response.state.as_str() {
            "completed" => {
                // For capture flow, completed should map to Charged
                if item.response.captured_amount.is_some()
                    && item.response.captured_amount.as_ref().unwrap() != "0.00"
                {
                    AttemptStatus::Charged
                } else {
                    AttemptStatus::Pending
                }
            }
            "pending" => AttemptStatus::Pending,
            "declined" => AttemptStatus::Failure,
            "error" => AttemptStatus::Failure,
            _ => {
                // Additional status code checks specific to capture
                match item.response.status {
                    116 => AttemptStatus::Charged,        // Captured
                    117 => AttemptStatus::PartialCharged, // Partial capture
                    _ => AttemptStatus::Pending,
                }
            }
        };

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    item.response.transaction_reference.clone(),
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: item
                    .response
                    .additional_fields
                    .get("order")
                    .and_then(extract_order_id),
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

// Refund Request Structure
#[derive(Debug, Serialize)]
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
// Reuses HipayPaymentsResponse structure as the maintenance/refund endpoint returns the same format
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
        // Map HiPay state to RefundStatus
        let refund_status = match item.response.state.as_str() {
            "completed" => RefundStatus::Success,
            "pending" => RefundStatus::Pending,
            "declined" | "error" => RefundStatus::Failure,
            _ => {
                // Additional status code checks specific to refund
                match item.response.status {
                    124 => RefundStatus::Success, // Refund
                    125 => RefundStatus::Pending, // Refund Requested
                    _ => RefundStatus::Pending,
                }
            }
        };

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
// Reuses HipayPaymentsResponse structure for refund sync
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
        // Map HiPay state to RefundStatus (same mapping logic as refund)
        let refund_status = match item.response.state.as_str() {
            "completed" => RefundStatus::Success,
            "pending" => RefundStatus::Pending,
            "declined" | "error" => RefundStatus::Failure,
            _ => {
                // Additional status code checks specific to refund
                match item.response.status {
                    124 => RefundStatus::Success, // Refund
                    125 => RefundStatus::Pending, // Refund Requested
                    _ => RefundStatus::Pending,
                }
            }
        };

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

// Void Request Structure
#[derive(Debug, Serialize)]
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
// Reuses HipayPaymentsResponse structure as the maintenance/void endpoint returns the same format
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
        // Map HiPay state to AttemptStatus for void
        let status = match item.response.state.as_str() {
            "completed" => {
                // Status 118 indicates cancellation
                if item.response.status == 118 {
                    AttemptStatus::Voided
                } else {
                    AttemptStatus::VoidFailed
                }
            }
            "pending" => AttemptStatus::Pending,
            "declined" | "error" => AttemptStatus::VoidFailed,
            _ => {
                // Check status code for void-specific statuses
                match item.response.status {
                    118 => AttemptStatus::Voided, // Cancelled
                    _ => AttemptStatus::VoidFailed,
                }
            }
        };

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    item.response.transaction_reference.clone(),
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: item
                    .response
                    .additional_fields
                    .get("order")
                    .and_then(extract_order_id),
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
