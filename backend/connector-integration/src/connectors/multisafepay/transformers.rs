use crate::types::ResponseRouterData;
use common_enums::{AttemptStatus, RefundStatus};
use common_utils::types::MinorUnit;
use domain_types::{
    connector_flow::{Authorize, PSync, RSync},
    connector_types::{
        PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData,
        RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData, ResponseId,
    },
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
};
use hyperswitch_masking::{ExposeInterface, PeekInterface, Secret};
use serde::{Deserialize, Serialize};

// ===== HELPER FUNCTIONS =====

/// Determines the order type based on payment method
/// Cards use direct flow, other payment methods use redirect flow
fn get_order_type_from_payment_method<T: PaymentMethodDataTypes>(
    payment_method_data: &domain_types::payment_method_data::PaymentMethodData<T>,
) -> &'static str {
    use domain_types::payment_method_data::PaymentMethodData;

    match payment_method_data {
        PaymentMethodData::Card(_) => "direct",
        _ => "redirect",
    }
}

/// Maps payment method data to MultiSafepay gateway identifier
fn get_gateway_from_payment_method<T: PaymentMethodDataTypes>(
    payment_method_data: &domain_types::payment_method_data::PaymentMethodData<T>,
) -> Option<String> {
    use domain_types::payment_method_data::PaymentMethodData;

    match payment_method_data {
        PaymentMethodData::Card(card_data) => {
            // Map card network to gateway identifier
            card_data.card_network.as_ref().map(|network| {
                match network {
                    common_enums::CardNetwork::Visa => "VISA",
                    common_enums::CardNetwork::Mastercard => "MASTERCARD",
                    common_enums::CardNetwork::AmericanExpress => "AMEX",
                    common_enums::CardNetwork::Maestro => "MAESTRO",
                    common_enums::CardNetwork::DinersClub => "DINER",
                    common_enums::CardNetwork::Discover => "DISCOVER",
                    _ => "CREDITCARD", // Default for unrecognized card networks
                }
                .to_string()
            })
        }
        PaymentMethodData::BankRedirect(_) => Some("IDEAL".to_string()), // Example for iDEAL
        PaymentMethodData::Wallet(_) => Some("PAYPAL".to_string()),      // Example for PayPal
        // Add more payment methods as needed
        _ => None,
    }
}

/// Helper function to extract card number as string from RawCardNumber
/// For direct transactions, we need actual PCI data (DefaultPCIHolder), not vault tokens
fn get_card_number_string<T: PaymentMethodDataTypes>(
    card_number: &domain_types::payment_method_data::RawCardNumber<T>,
) -> Result<String, error_stack::Report<errors::ConnectorError>> {
    use error_stack::ResultExt;

    // Serialize the card number and extract the string value
    // This works for both DefaultPCIHolder (cards::CardNumber) and VaultTokenHolder (String)
    let serialized = serde_json::to_value(card_number)
        .change_context(errors::ConnectorError::RequestEncodingFailed)
        .attach_printable("Failed to serialize card number")?;

    // Extract the string from the JSON value
    serialized
        .as_str()
        .map(|s| s.to_string())
        .ok_or(errors::ConnectorError::RequestEncodingFailed)
        .attach_printable("Card number is not a valid string")
        .map_err(error_stack::Report::from)
}

// ===== STATUS ENUMS =====

/// MultiSafepay payment status enum
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum MultisafepayPaymentStatus {
    Completed,
    Declined,
    #[default]
    Initialized,
    Void,
    Uncleared,
}

impl From<MultisafepayPaymentStatus> for AttemptStatus {
    fn from(status: MultisafepayPaymentStatus) -> Self {
        match status {
            MultisafepayPaymentStatus::Completed => Self::Charged,
            MultisafepayPaymentStatus::Declined => Self::Failure,
            MultisafepayPaymentStatus::Initialized => Self::AuthenticationPending,
            MultisafepayPaymentStatus::Uncleared => Self::Pending,
            MultisafepayPaymentStatus::Void => Self::Voided,
        }
    }
}

/// MultiSafepay refund status enum
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum MultisafepayRefundStatus {
    Succeeded,
    Failed,
    #[default]
    Processing,
}

impl From<MultisafepayRefundStatus> for RefundStatus {
    fn from(status: MultisafepayRefundStatus) -> Self {
        match status {
            MultisafepayRefundStatus::Succeeded => Self::Success,
            MultisafepayRefundStatus::Failed => Self::Failure,
            MultisafepayRefundStatus::Processing => Self::Pending,
        }
    }
}

#[derive(Debug, Clone)]
pub struct MultisafepayAuthType {
    pub api_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for MultisafepayAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::HeaderKey { api_key } => Ok(Self {
                api_key: api_key.to_owned(),
            }),
            _ => Err(error_stack::report!(
                errors::ConnectorError::FailedToObtainAuthType
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisafepayErrorResponse {
    pub success: bool,
    pub data: Option<MultisafepayErrorData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisafepayErrorData {
    pub error_code: Option<i32>,
    pub error_info: Option<String>,
}

// ===== DIRECT TRANSACTION STRUCTURES =====

#[derive(Debug, Serialize)]
pub struct PaymentOptions {
    pub redirect_url: String,
    pub cancel_url: String,
}

#[derive(Debug, Serialize)]
pub struct CustomerInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    pub email: String,
}

#[derive(Debug, Serialize)]
pub struct GatewayInfo {
    pub card_number: Secret<String>,
    pub card_expiry_date: i64,  // Format: YYMM as integer
    pub card_cvc: Secret<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card_holder_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flexible_3d: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub moto: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub term_url: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DeliveryObject {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address1: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub house_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zip_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
}

// ===== PAYMENT REQUEST STRUCTURES =====

#[derive(Debug, Serialize)]
pub struct MultisafepayPaymentsRequest {
    #[serde(rename = "type")]
    pub order_type: String,
    pub order_id: String,
    pub gateway: String,
    pub currency: String,
    pub amount: MinorUnit,
    pub description: String,
    // Required fields for direct transactions
    pub payment_options: PaymentOptions,
    pub customer: CustomerInfo,
    pub gateway_info: GatewayInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delivery: Option<DeliveryObject>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub days_active: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seconds_active: Option<i32>,
}

// Implementation for macro-generated wrapper type
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    >
    TryFrom<
        crate::connectors::multisafepay::MultisafepayRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for MultisafepayPaymentsRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        wrapper: crate::connectors::multisafepay::MultisafepayRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        use domain_types::payment_method_data::PaymentMethodData;
        use error_stack::ResultExt;

        let item = &wrapper.router_data;
        let order_type = get_order_type_from_payment_method(&item.request.payment_method_data);
        let gateway = get_gateway_from_payment_method(&item.request.payment_method_data)
            .unwrap_or_else(|| "VISA".to_string());

        // Extract card data for direct transactions - requires actual PCI data, not tokens
        let card = match &item.request.payment_method_data {
            PaymentMethodData::Card(card_data) => card_data,
            _ => {
                return Err(errors::ConnectorError::NotImplemented(
                    "Non-card payment methods not supported for direct transactions".to_string(),
                ))?
            }
        };

        // Build gateway_info with card details
        // Format card expiry as YYMM (2-digit year + 2-digit month) as integer
        let card_exp_year_str = card.card_exp_year.peek();
        let card_exp_year_2digit = if card_exp_year_str.len() == 4 {
            &card_exp_year_str[2..]
        } else {
            card_exp_year_str
        };

        let card_expiry_str = format!(
            "{}{}",
            card_exp_year_2digit,
            card.card_exp_month.peek()
        );

        let card_expiry_date: i64 = card_expiry_str
            .parse::<i64>()
            .change_context(errors::ConnectorError::RequestEncodingFailed)
            .attach_printable("Failed to parse card expiry date as integer")?;

        // Get card number as string - for direct transactions we need PCI data
        let card_number_str = get_card_number_string(&card.card_number)?;

        let gateway_info = GatewayInfo {
            card_number: Secret::new(card_number_str),
            card_expiry_date,
            card_cvc: card.card_cvc.clone(),
            card_holder_name: card.card_holder_name.clone().map(|s| s.expose()),
            flexible_3d: None,
            moto: None,
            term_url: None,
        };

        // Build customer info
        let customer = CustomerInfo {
            locale: None,
            ip_address: None,
            reference: Some(item.resource_common_data.connector_request_reference_id.clone()),
            email: item
                .request
                .email
                .clone()
                .ok_or(errors::ConnectorError::MissingRequiredField {
                    field_name: "email",
                })
                .attach_printable("Missing email for direct transaction")?
                .expose()
                .expose(),
        };

        // Build payment_options
        let payment_options = PaymentOptions {
            redirect_url: item
                .request
                .router_return_url
                .clone()
                .ok_or(errors::ConnectorError::MissingRequiredField {
                    field_name: "router_return_url",
                })
                .attach_printable("Missing return URL for direct transaction")?,
            cancel_url: item
                .request
                .router_return_url
                .clone()
                .ok_or(errors::ConnectorError::MissingRequiredField {
                    field_name: "router_return_url",
                })
                .attach_printable("Missing cancel URL for direct transaction")?,
        };

        // Build delivery object from billing address if available
        let delivery = item
            .resource_common_data
            .get_billing()
            .ok()
            .and_then(|billing| billing.address.as_ref())
            .map(|address| DeliveryObject {
                first_name: address.first_name.clone().map(|s| s.expose()),
                last_name: address.last_name.clone().map(|s| s.expose()),
                address1: address.line1.clone().map(|s| s.expose()),
                house_number: address.line2.clone().map(|s| s.expose()),
                zip_code: address.zip.clone().map(|s| s.expose()),
                city: address.city.clone(),
                country: address.country.map(|c| c.to_string()),
            });

        Ok(Self {
            order_type: order_type.to_string(),
            order_id: item
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            gateway,
            currency: item.request.currency.to_string(),
            amount: item.request.minor_amount,
            description: item
                .request
                .statement_descriptor
                .clone()
                .unwrap_or_else(|| "Payment".to_string()),
            payment_options,
            customer,
            gateway_info,
            delivery,
            days_active: Some(30),
            seconds_active: Some(259200),
        })
    }
}

// Keep the original implementation for backwards compatibility
impl<T: PaymentMethodDataTypes>
    TryFrom<
        &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    > for MultisafepayPaymentsRequest
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
        use domain_types::payment_method_data::PaymentMethodData;
        use error_stack::ResultExt;

        let order_type = get_order_type_from_payment_method(&item.request.payment_method_data);
        let gateway = get_gateway_from_payment_method(&item.request.payment_method_data)
            .unwrap_or_else(|| "VISA".to_string());

        // Extract card data for direct transactions - requires actual PCI data, not tokens
        let card = match &item.request.payment_method_data {
            PaymentMethodData::Card(card_data) => card_data,
            _ => {
                return Err(errors::ConnectorError::NotImplemented(
                    "Non-card payment methods not supported for direct transactions".to_string(),
                ))?
            }
        };

        // Build gateway_info with card details
        // Format card expiry as YYMM (2-digit year + 2-digit month) as integer
        let card_exp_year_str = card.card_exp_year.peek();
        let card_exp_year_2digit = if card_exp_year_str.len() == 4 {
            &card_exp_year_str[2..]
        } else {
            card_exp_year_str
        };

        let card_expiry_str = format!(
            "{}{}",
            card_exp_year_2digit,
            card.card_exp_month.peek()
        );

        let card_expiry_date: i64 = card_expiry_str
            .parse::<i64>()
            .change_context(errors::ConnectorError::RequestEncodingFailed)
            .attach_printable("Failed to parse card expiry date as integer")?;

        // Get card number as string - for direct transactions we need PCI data
        let card_number_str = get_card_number_string(&card.card_number)?;

        let gateway_info = GatewayInfo {
            card_number: Secret::new(card_number_str),
            card_expiry_date,
            card_cvc: card.card_cvc.clone(),
            card_holder_name: card.card_holder_name.clone().map(|s| s.expose()),
            flexible_3d: None,
            moto: None,
            term_url: None,
        };

        // Build customer info
        let customer = CustomerInfo {
            locale: None,
            ip_address: None,
            reference: Some(item.resource_common_data.connector_request_reference_id.clone()),
            email: item
                .request
                .email
                .clone()
                .ok_or(errors::ConnectorError::MissingRequiredField {
                    field_name: "email",
                })
                .attach_printable("Missing email for direct transaction")?
                .expose()
                .expose(),
        };

        // Build payment_options
        let payment_options = PaymentOptions {
            redirect_url: item
                .request
                .router_return_url
                .clone()
                .ok_or(errors::ConnectorError::MissingRequiredField {
                    field_name: "router_return_url",
                })
                .attach_printable("Missing return URL for direct transaction")?,
            cancel_url: item
                .request
                .router_return_url
                .clone()
                .ok_or(errors::ConnectorError::MissingRequiredField {
                    field_name: "router_return_url",
                })
                .attach_printable("Missing cancel URL for direct transaction")?,
        };

        // Build delivery object from billing address if available
        let delivery = item
            .resource_common_data
            .get_billing()
            .ok()
            .and_then(|billing| billing.address.as_ref())
            .map(|address| DeliveryObject {
                first_name: address.first_name.clone().map(|s| s.expose()),
                last_name: address.last_name.clone().map(|s| s.expose()),
                address1: address.line1.clone().map(|s| s.expose()),
                house_number: address.line2.clone().map(|s| s.expose()),
                zip_code: address.zip.clone().map(|s| s.expose()),
                city: address.city.clone(),
                country: address.country.map(|c| c.to_string()),
            });

        Ok(Self {
            order_type: order_type.to_string(),
            order_id: item
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            gateway,
            currency: item.request.currency.to_string(),
            amount: item.request.minor_amount,
            description: item
                .request
                .statement_descriptor
                .clone()
                .unwrap_or_else(|| "Payment".to_string()),
            payment_options,
            customer,
            gateway_info,
            delivery,
            days_active: Some(30),
            seconds_active: Some(259200),
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MultisafepayPaymentsResponse {
    pub success: bool,
    pub data: MultisafepayResponseData,
}

// Type aliases for different flows to avoid duplicate templating structs in macros
pub type MultisafepayPaymentsSyncResponse = MultisafepayPaymentsResponse;
pub type MultisafepayRefundSyncResponse = MultisafepayRefundResponse;

#[derive(Debug, Deserialize, Serialize)]
pub struct MultisafepayResponseData {
    #[serde(default)]
    pub order_id: Option<String>,
    pub payment_url: Option<String>,
    // transaction_id can be either a string or integer in different responses
    #[serde(deserialize_with = "deserialize_transaction_id", default)]
    pub transaction_id: Option<String>,
    #[serde(default)]
    pub status: MultisafepayPaymentStatus,
    pub amount: Option<MinorUnit>,
    pub currency: Option<String>,
    // Additional fields that may appear in GET response - using flatten to ignore unknown fields
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, serde_json::Value>,
}

// Custom deserializer to handle transaction_id as either string or integer
fn deserialize_transaction_id<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;
    let value: Option<serde_json::Value> = Option::deserialize(deserializer)?;
    Ok(value.and_then(|v| match v {
        serde_json::Value::String(s) => Some(s),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }))
}

impl<T: PaymentMethodDataTypes>
    TryFrom<
        ResponseRouterData<
            MultisafepayPaymentsResponse,
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
            MultisafepayPaymentsResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        let response_data = &item.response.data;

        let status = response_data.status.clone().into();

        let redirection_data = response_data.payment_url.as_ref().map(|url| {
            Box::new(domain_types::router_response_types::RedirectForm::Uri { uri: url.clone() })
        });

        let transaction_id = response_data
            .transaction_id
            .clone()
            .or_else(|| response_data.order_id.clone())
            .unwrap_or_else(|| "unknown".to_string());

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(transaction_id),
                redirection_data,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: response_data.order_id.clone(),
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

// PSync Response Transformer - Reuses MultisafepayPaymentsResponse structure
impl
    TryFrom<
        ResponseRouterData<
            MultisafepayPaymentsResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    > for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            MultisafepayPaymentsResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let response_data = &item.response.data;

        let status = response_data.status.clone().into();

        let transaction_id = response_data
            .transaction_id
            .clone()
            .or_else(|| response_data.order_id.clone())
            .unwrap_or_else(|| "unknown".to_string());

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(transaction_id),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: response_data.order_id.clone(),
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

// ===== CAPTURE FLOW STRUCTURES =====
// Capture flow not implemented - MultiSafepay doesn't support capture
// (requires manual capture support which MultiSafepay doesn't provide)

// ===== REFUND FLOW STRUCTURES =====

#[derive(Debug, Serialize)]
pub struct MultisafepayRefundRequest {
    pub currency: String,
    pub amount: MinorUnit,
}

// Implementation for macro-generated wrapper type
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    >
    TryFrom<
        crate::connectors::multisafepay::MultisafepayRouterData<
            RouterDataV2<
                domain_types::connector_flow::Refund,
                RefundFlowData,
                RefundsData,
                RefundsResponseData,
            >,
            T,
        >,
    > for MultisafepayRefundRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        wrapper: crate::connectors::multisafepay::MultisafepayRouterData<
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
        Ok(Self {
            currency: item.request.currency.to_string(),
            amount: item.request.minor_refund_amount,
        })
    }
}

// Keep the original implementation for backwards compatibility
impl<F> TryFrom<&RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>>
    for MultisafepayRefundRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            currency: item.request.currency.to_string(),
            amount: item.request.minor_refund_amount,
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MultisafepayRefundResponse {
    pub success: bool,
    pub data: MultisafepayRefundData,
}

#[derive(Debug, Deserialize, Serialize, Default, Clone)]
pub struct MultisafepayRefundData {
    pub transaction_id: i64,
    pub refund_id: i64,
    pub order_id: Option<String>,
    pub error_code: Option<i32>,
    pub error_info: Option<String>,
}

impl<F>
    TryFrom<
        ResponseRouterData<
            MultisafepayRefundResponse,
            RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    > for RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            MultisafepayRefundResponse,
            RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let refund_status = if item.response.success {
            MultisafepayRefundStatus::Succeeded
        } else {
            MultisafepayRefundStatus::Failed
        };

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.data.refund_id.to_string(),
                refund_status: refund_status.into(),
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

// Refund Sync Response - Uses MultisafepayRefundResponse
impl
    TryFrom<
        ResponseRouterData<
            MultisafepayRefundResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    > for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            MultisafepayRefundResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let refund_status = if item.response.success {
            MultisafepayRefundStatus::Succeeded
        } else {
            MultisafepayRefundStatus::Failed
        };

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.data.refund_id.to_string(),
                refund_status: refund_status.into(),
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

// ===== VOID FLOW STRUCTURES =====
// Void flow not implemented - MultiSafepay doesn't support void
// (requires manual capture support which MultiSafepay doesn't provide)
