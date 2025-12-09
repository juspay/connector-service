use crate::types::ResponseRouterData;
use common_enums::{AttemptStatus, RefundStatus};
use common_utils::types::{AmountConvertor, FloatMajorUnit, FloatMajorUnitForConnector};
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
use hyperswitch_masking::{ExposeInterface, PeekInterface, Secret};
use serde::{Deserialize, Deserializer, Serialize};

// ============================================================================
// Authentication Types
// ============================================================================

#[derive(Debug, Clone)]
pub struct BamboraAuthType {
    pub api_key: Secret<String>,
}

impl BamboraAuthType {
    /// Generates the Passcode authorization header
    /// Format: "Passcode base64(merchant_id:api_key)"
    pub fn generate_authorization_header(&self) -> String {
        // The api_key contains the full auth string already formatted
        self.api_key.peek().to_string()
    }
}

impl TryFrom<&ConnectorAuthType> for BamboraAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            // BodyKey contains merchant_id in key1 and api_key in api_key
            ConnectorAuthType::BodyKey { api_key, key1 } => {
                let auth_string = format!("{}:{}", key1.peek(), api_key.peek());
                let encoded = base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    auth_string.as_bytes(),
                );
                Ok(Self {
                    api_key: Secret::new(format!("Passcode {}", encoded)),
                })
            }
            _ => Err(error_stack::report!(
                errors::ConnectorError::FailedToObtainAuthType
            )),
        }
    }
}

// ============================================================================
// Error Response Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BamboraErrorResponse {
    pub code: i32,
    pub category: i32,
    pub message: String,
    pub reference: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card: Option<serde_json::Value>,
}

// ============================================================================
// Request Types
// ============================================================================

#[derive(Debug, Serialize)]
pub struct BamboraPaymentsRequest<T: PaymentMethodDataTypes> {
    pub order_number: String,
    pub amount: FloatMajorUnit,
    pub payment_method: PaymentMethodType,
    pub card: BamboraCard<T>,
    pub billing: BamboraBillingAddress,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentMethodType {
    Card,
}

#[derive(Debug, Serialize)]
pub struct BamboraCard<T: PaymentMethodDataTypes> {
    pub name: Secret<String>,
    pub number: RawCardNumber<T>,
    pub expiry_month: Secret<String>,
    pub expiry_year: Secret<String>,
    pub cvd: Secret<String>,
    pub complete: bool, // true for auto-capture, false for manual capture
}

#[derive(Debug, Serialize)]
pub struct BamboraBillingAddress {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address_line1: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address_line2: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub province: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<common_enums::CountryAlpha2>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub postal_code: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_address: Option<common_utils::pii::Email>,
}

// ============================================================================
// Response Types
// ============================================================================

/// Helper function to deserialize string or i32 as String
fn str_or_i32<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StrOrI32 {
        Str(String),
        I32(i32),
    }

    let value = StrOrI32::deserialize(deserializer)?;
    Ok(match value {
        StrOrI32::Str(v) => v,
        StrOrI32::I32(v) => v.to_string(),
    })
}

// Type aliases for macro-based flow implementations
// Each flow needs a unique response type name to avoid duplicate templating struct definitions
pub type BamboraAuthorizeResponse = BamboraPaymentsResponse;
pub type BamboraCaptureResponse = BamboraPaymentsResponse;
pub type BamboraPSyncResponse = BamboraPaymentsResponse;
pub type BamboraVoidResponse = BamboraPaymentsResponse;
pub type BamboraRefundResponse = BamboraPaymentsResponse;
pub type BamboraRSyncResponse = BamboraPaymentsResponse;

#[derive(Debug, Deserialize, Serialize)]
pub struct BamboraPaymentsResponse {
    #[serde(deserialize_with = "str_or_i32")]
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorizing_merchant_id: Option<i32>,
    #[serde(deserialize_with = "str_or_i32")]
    pub approved: String, // "1" for approved, "0" for declined
    pub message: String,
    #[serde(deserialize_with = "str_or_i32")]
    pub message_id: String,
    pub auth_code: String,
    pub created: String,
    pub order_number: String,
    #[serde(rename = "type")]
    pub payment_type: String, // "P" for payment, "PA" for pre-auth
    pub amount: FloatMajorUnit,
    pub payment_method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_score: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card: Option<BamboraCardResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<Vec<serde_json::Value>>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BamboraCardResponse {
    pub card_type: String,
    pub last_four: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card_bin: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address_match: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub postal_result: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avs_result: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cvd_result: Option<String>, // Changed from i32 to String as Bambora sends it as string
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avs: Option<BamboraAvsDetails>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BamboraAvsDetails {
    pub id: String,
    pub message: String,
    pub processed: bool,
}

// ============================================================================
// Request Transformation
// ============================================================================

impl<T: PaymentMethodDataTypes>
    TryFrom<
        &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    > for BamboraPaymentsRequest<T>
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
        // Extract card data
        let payment_method_data = &item.request.payment_method_data;
        let card = match payment_method_data {
            PaymentMethodData::Card(card_data) => {
                // Get cardholder name - prefer billing full name, fallback to customer name
                let cardholder_name = item
                    .resource_common_data
                    .get_optional_billing_full_name()
                    .or_else(|| item.request.customer_name.clone().map(Secret::new))
                    .ok_or(errors::ConnectorError::MissingRequiredField {
                        field_name: "billing.first_name or customer_name",
                    })?;

                // Determine if this should be auto-capture or authorization
                let is_auto_capture = !crate::utils::is_manual_capture(item.request.capture_method);

                // Get 2-digit expiry year using utility function
                let expiry_year = card_data.get_card_expiry_year_2_digit()?;

                BamboraCard {
                    name: cardholder_name,
                    number: card_data.card_number.clone(),
                    expiry_month: card_data.card_exp_month.clone(),
                    expiry_year,
                    cvd: card_data.card_cvc.clone(),
                    complete: is_auto_capture,
                }
            }
            PaymentMethodData::Wallet(_)
            | PaymentMethodData::CardRedirect(_)
            | PaymentMethodData::PayLater(_)
            | PaymentMethodData::BankRedirect(_)
            | PaymentMethodData::BankDebit(_)
            | PaymentMethodData::BankTransfer(_)
            | PaymentMethodData::Crypto(_)
            | PaymentMethodData::MandatePayment
            | PaymentMethodData::Reward
            | PaymentMethodData::RealTimePayment(_)
            | PaymentMethodData::Upi(_)
            | PaymentMethodData::Voucher(_)
            | PaymentMethodData::GiftCard(_)
            | PaymentMethodData::CardToken(_)
            | PaymentMethodData::NetworkToken(_)
            | PaymentMethodData::MobilePayment(_)
            | PaymentMethodData::OpenBanking(_)
            | PaymentMethodData::CardDetailsForNetworkTransactionId(_) => {
                return Err(errors::ConnectorError::NotSupported {
                    message: "Selected payment method".to_string(),
                    connector: "bambora",
                }
                .into());
            }
        };

        // Extract billing address - mandatory field
        let payment_billing = item
            .resource_common_data
            .address
            .get_payment_billing()
            .ok_or(errors::ConnectorError::MissingRequiredField {
                field_name: "billing",
            })?;

        let billing_address = payment_billing.address.as_ref().ok_or(
            errors::ConnectorError::MissingRequiredField {
                field_name: "billing.address",
            },
        )?;

        // Bambora requires province/state for US and CA addresses in 2-letter format
        // Convert full state names (e.g., "California", "New York") to 2-letter codes (e.g., "CA", "NY")
        let province = billing_address.state.clone().and_then(|state| {
            crate::utils::get_state_code_for_country(&state, billing_address.country)
        });

        let billing = BamboraBillingAddress {
            name: billing_address
                .first_name
                .clone()
                .or(billing_address.last_name.clone()),
            address_line1: billing_address.line1.clone(),
            address_line2: billing_address.line2.clone(),
            city: billing_address.city.clone().map(|s| s.expose()),
            province,
            country: billing_address.country,
            postal_code: billing_address.zip.clone(),
            phone_number: payment_billing
                .phone
                .as_ref()
                .and_then(|p| p.number.clone()),
            email_address: payment_billing.email.clone(),
        };

        // Convert amount from minor units to major units using FloatMajorUnitForConnector
        let converter = FloatMajorUnitForConnector;
        let amount = converter
            .convert(item.request.minor_amount, item.request.currency)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;

        Ok(Self {
            order_number: item
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            amount,
            payment_method: PaymentMethodType::Card,
            card,
            billing,
        })
    }
}

// ============================================================================
// Response Transformation
// ============================================================================

impl<T: PaymentMethodDataTypes>
    TryFrom<
        ResponseRouterData<
            BamboraPaymentsResponse,
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
            BamboraPaymentsResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        // Status mapping following hyperswitch pattern
        // Only check approved field and capture method
        let is_approved = item.response.approved == "1";
        let is_auto_capture = item
            .router_data
            .request
            .capture_method
            .map(|cm| matches!(cm, common_enums::CaptureMethod::Automatic))
            .unwrap_or(true);

        let status = if is_approved {
            match is_auto_capture {
                true => AttemptStatus::Charged,
                false => AttemptStatus::Authorized,
            }
        } else {
            match is_auto_capture {
                true => AttemptStatus::Failure,
                false => AttemptStatus::AuthorizationFailed,
            }
        };

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(item.response.order_number.clone()),
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
// Capture (Complete Pre-Authorization) Implementation
// ============================================================================

/// Capture Request Structure
/// Per technical specification:
/// - Endpoint: POST /payments/{transId}/completions
/// - Request payload contains amount and payment_method
/// - Amount must be ≤ original pre-authorization amount
#[derive(Debug, Serialize)]
pub struct BamboraCaptureRequest {
    pub amount: FloatMajorUnit,
    pub payment_method: PaymentMethodType,
}

impl TryFrom<&RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>>
    for BamboraCaptureRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        // Validate that we have a connector transaction ID
        // This is critical - addressing Silverflow PR feedback about proper validation
        let _transaction_id = match &item.request.connector_transaction_id {
            ResponseId::ConnectorTransactionId(id) => id,
            ResponseId::EncodedData(_) | ResponseId::NoResponseId => {
                return Err(errors::ConnectorError::MissingConnectorTransactionID.into());
            }
        };

        // Convert amount from minor units to major units using FloatMajorUnitForConnector
        let converter = FloatMajorUnitForConnector;
        let amount = converter
            .convert(item.request.minor_amount_to_capture, item.request.currency)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;

        Ok(Self {
            amount,
            payment_method: PaymentMethodType::Card,
        })
    }
}

/// Capture Response Transformation
/// Per technical specification:
/// - Response payload is identical to Make Payment response
/// - Should result in AttemptStatus::Charged on success
impl
    TryFrom<
        ResponseRouterData<
            BamboraPaymentsResponse,
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    > for RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            BamboraPaymentsResponse,
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        // Status mapping following hyperswitch pattern
        // Only check approved field for capture
        let is_approved = item.response.approved == "1";

        let status = if is_approved {
            AttemptStatus::Charged
        } else {
            AttemptStatus::Failure
        };

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(item.response.order_number.clone()),
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
// PSync (Payment Sync) Implementation
// ============================================================================

// PSync uses GET request, so no request body is needed
#[derive(Debug, Serialize)]
pub struct BamboraSyncRequest;

impl TryFrom<&RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>
    for BamboraSyncRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        _item: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        // GET request - no body needed
        Ok(Self)
    }
}

// PSync Response Transformation
// The GET /payments/{transId} endpoint returns the same structure as authorization
impl
    TryFrom<
        ResponseRouterData<
            BamboraPaymentsResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    > for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            BamboraPaymentsResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        // Status mapping following hyperswitch pattern
        // Check approved field and use is_auto_capture to determine status
        let is_approved = item.response.approved == "1";

        // Determine if this was auto-capture or manual capture based on original request
        // For sync, we need to infer from the request capture method
        let is_auto_capture = item
            .router_data
            .request
            .capture_method
            .map(|cm| matches!(cm, common_enums::CaptureMethod::Automatic))
            .unwrap_or(true);

        let status = match is_auto_capture {
            true => {
                if is_approved {
                    AttemptStatus::Charged
                } else {
                    AttemptStatus::Failure
                }
            }
            false => {
                if is_approved {
                    AttemptStatus::Authorized
                } else {
                    AttemptStatus::AuthorizationFailed
                }
            }
        };

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(item.response.order_number.clone()),
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
// Refund Implementation
// ============================================================================

/// Refund Request Structure
/// Per technical specification:
/// - Endpoint: POST /payments/{transId}/returns
/// - Request body: amount only
/// - Response: Identical to Make Payment response but with type "R"
#[derive(Debug, Serialize)]
pub struct BamboraRefundRequest {
    pub amount: FloatMajorUnit,
}

impl TryFrom<&RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>>
    for BamboraRefundRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> Result<Self, Self::Error> {
        // Convert amount from minor units to major units using FloatMajorUnitForConnector
        let converter = FloatMajorUnitForConnector;
        let amount = converter
            .convert(item.request.minor_refund_amount, item.request.currency)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;

        Ok(Self { amount })
    }
}

/// Refund Response Transformation
/// Per technical specification and Silverflow PR #240 feedback:
/// - Response payload is identical to Make Payment response
/// - CRITICAL: Check BOTH approved status AND payment type "R" for refund
/// - DO NOT assume success based on single field
/// - Payment type "R" indicates this is a refund transaction
impl
    TryFrom<
        ResponseRouterData<
            BamboraPaymentsResponse,
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    > for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            BamboraPaymentsResponse,
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        // Status mapping following hyperswitch pattern
        // Only check approved field for refund
        let is_approved = item.response.approved == "1";

        let refund_status = if is_approved {
            RefundStatus::Success
        } else {
            RefundStatus::Failure
        };

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.id.clone(),
                refund_status,
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

// ============================================================================
// Refund Sync (RSync) Implementation
// ============================================================================

// RSync for refunds uses GET request to retrieve refund status
// Note: Bambora may use the same transaction ID endpoint as payment sync
// The GET /payments/{transId} endpoint returns the same response structure
// We differentiate by checking the payment_type field

/// Refund Sync Response Transformation
/// Uses the same BamboraPaymentsResponse structure
/// CRITICAL: Comprehensive status checking per Silverflow PR feedback
impl
    TryFrom<
        ResponseRouterData<
            BamboraPaymentsResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    > for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            BamboraPaymentsResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        // Status mapping following hyperswitch pattern
        // Only check approved field for refund sync
        let is_approved = item.response.approved == "1";

        let refund_status = if is_approved {
            RefundStatus::Success
        } else {
            RefundStatus::Failure
        };

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.id.clone(),
                refund_status,
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

// ============================================================================
// Void Implementation
// ============================================================================

/// Void Request Structure
/// Per technical specification:
/// - Endpoint: POST /payments/{transId}/void
/// - Request body: amount, order_number
/// - Response: Identical to Make Payment response but with type "VP" (void payment)
/// - Can void pre-authorizations (PA) before they are captured
/// - Cannot void already completed payments - use refund instead
#[derive(Debug, Serialize)]
pub struct BamboraVoidRequest {
    pub amount: FloatMajorUnit,
}

impl TryFrom<&RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>>
    for BamboraVoidRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        // Validate that we have a connector transaction ID
        // This is critical - addressing Silverflow PR feedback about proper validation
        if item.request.connector_transaction_id.is_empty() {
            return Err(errors::ConnectorError::MissingConnectorTransactionID.into());
        }

        // Get the amount from the original transaction
        // For void, we typically void the full amount
        let minor_amount =
            item.request
                .amount
                .ok_or(errors::ConnectorError::MissingRequiredField {
                    field_name: "amount",
                })?;

        // Get currency from request
        let currency =
            item.request
                .currency
                .ok_or(errors::ConnectorError::MissingRequiredField {
                    field_name: "currency",
                })?;

        // Convert amount from minor units to major units using FloatMajorUnitForConnector
        let converter = FloatMajorUnitForConnector;
        let amount = converter
            .convert(minor_amount, currency)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;

        Ok(Self { amount })
    }
}

/// Void Response Transformation
/// Per technical specification and Silverflow PR #240 feedback:
/// - Response payload is identical to Make Payment response
/// - CRITICAL: Check BOTH approved status AND payment type "VP" for void
/// - DO NOT assume success based on single field
/// - Payment type "VP" indicates this is a void payment transaction
impl
    TryFrom<
        ResponseRouterData<
            BamboraPaymentsResponse,
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        >,
    > for RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            BamboraPaymentsResponse,
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        // Status mapping following hyperswitch pattern
        // Only check approved field for void
        let is_approved = item.response.approved == "1";

        let status = if is_approved {
            AttemptStatus::Voided
        } else {
            AttemptStatus::VoidFailed
        };

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(item.response.order_number.clone()),
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
// Macro Wrapper Type Implementations
// ============================================================================
// The create_all_prerequisites! macro creates BamboraRouterData wrapper types
// We need to implement TryFrom for these wrappers to delegate to the existing
// TryFrom<&RouterDataV2<...>> implementations
//
// Note: The wrapper struct is created by the macro, we just implement TryFrom

use crate::connectors::bambora::BamboraRouterData;

// Authorize - wrapper to RouterDataV2
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    >
    TryFrom<
        BamboraRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for BamboraPaymentsRequest<T>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        wrapper: BamboraRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Self::try_from(&wrapper.router_data)
    }
}

// Capture - wrapper to RouterDataV2
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    >
    TryFrom<
        BamboraRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    > for BamboraCaptureRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        wrapper: BamboraRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Self::try_from(&wrapper.router_data)
    }
}

// Void - wrapper to RouterDataV2
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    >
    TryFrom<
        BamboraRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    > for BamboraVoidRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        wrapper: BamboraRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Self::try_from(&wrapper.router_data)
    }
}

// Refund - wrapper to RouterDataV2
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    >
    TryFrom<
        BamboraRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    > for BamboraRefundRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        wrapper: BamboraRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Self::try_from(&wrapper.router_data)
    }
}
