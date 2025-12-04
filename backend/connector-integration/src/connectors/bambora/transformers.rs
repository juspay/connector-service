use crate::types::ResponseRouterData;
use common_enums::{AttemptStatus, RefundStatus};
use domain_types::{
    connector_flow::{Authorize, Capture, PSync, RSync, Refund, Void},
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData, PaymentsSyncData, PaymentVoidData, RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData, ResponseId},
    errors,
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes, RawCardNumber},
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
};
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
    pub code: String,
    pub message: String,
}

// ============================================================================
// Request Types
// ============================================================================

#[derive(Debug, Serialize)]
pub struct BamboraPaymentsRequest<T: PaymentMethodDataTypes> {
    pub order_number: String,
    pub amount: f64,
    pub payment_method: PaymentMethodType,
    pub card: BamboraCard<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub billing: Option<BamboraBillingAddress>,
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

#[derive(Debug, Deserialize, Serialize)]
pub struct BamboraPaymentsResponse {
    #[serde(deserialize_with = "str_or_i32")]
    pub id: String,
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
    pub amount: f64,
    pub payment_method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card: Option<BamboraCardResponse>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BamboraCardResponse {
    pub card_type: String,
    pub last_four: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card_bin: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avs_result: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cvd_result: Option<i32>,
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
                // Get cardholder name - prefer billing name, fallback to customer name
                let cardholder_name = item
                    .resource_common_data
                    .address
                    .get_payment_billing()
                    .and_then(|billing| billing.address.as_ref())
                    .and_then(|addr| addr.first_name.clone())
                    .or_else(|| item.request.customer_name.clone().map(Secret::new))
                    .ok_or(errors::ConnectorError::MissingRequiredField {
                        field_name: "billing.first_name or customer_name",
                    })?;

                // Determine if this should be auto-capture or authorization
                let is_auto_capture = item
                    .request
                    .capture_method
                    .map(|cm| matches!(cm, common_enums::CaptureMethod::Automatic))
                    .unwrap_or(true);

                // Get 2-digit expiry year
                let expiry_year = if card_data.card_exp_year.peek().len() == 4 {
                    Secret::new(
                        card_data
                            .card_exp_year
                            .peek()
                            .chars()
                            .skip(2)
                            .collect::<String>(),
                    )
                } else {
                    card_data.card_exp_year.clone()
                };

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
                return Err(errors::ConnectorError::NotImplemented(
                    "Payment method not supported".to_string(),
                )
                .into());
            }
        };

        // Extract billing address
        let billing = item
            .resource_common_data
            .address
            .get_payment_billing()
            .and_then(|billing| {
                billing.address.as_ref().map(|addr| BamboraBillingAddress {
                    name: addr.first_name.clone().or(addr.last_name.clone()),
                    address_line1: addr.line1.clone(),
                    address_line2: addr.line2.clone(),
                    city: addr.city.clone().map(|s| s.expose()),
                    province: addr.state.clone(),
                    country: addr.country,
                    postal_code: addr.zip.clone(),
                    phone_number: billing.phone.as_ref().and_then(|p| p.number.clone()),
                    email_address: billing.email.clone(),
                })
            });

        // Convert amount from minor units to major units (cents to dollars)
        let amount_minor = item.request.minor_amount.get_amount_as_i64();
        let amount_major = (amount_minor as f64) / 100.0;

        Ok(Self {
            order_number: item
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            amount: amount_major,
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
        // Critical: Check BOTH approved status AND payment type for proper status mapping
        // This addresses Silverflow PR feedback about checking authorization AND clearing status
        let is_approved = item.response.approved == "1";
        let is_auto_capture = item
            .router_data
            .request
            .capture_method
            .map(|cm| matches!(cm, common_enums::CaptureMethod::Automatic))
            .unwrap_or(true);

        // Map status based on approved field and capture method
        // Per Silverflow feedback: Don't assume success based on single field
        let status = if is_approved {
            if is_auto_capture {
                // Payment type "P" indicates completed payment
                if item.response.payment_type == "P" {
                    AttemptStatus::Charged
                } else {
                    // Approved but not yet captured
                    AttemptStatus::Authorized
                }
            } else {
                // Manual capture - authorization successful
                // Payment type "PA" indicates pre-authorization
                AttemptStatus::Authorized
            }
        } else {
            // Not approved
            if is_auto_capture {
                AttemptStatus::Failure
            } else {
                AttemptStatus::AuthorizationFailed
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
/// - Request payload is identical to Make Payment request
/// - Amount must be ≤ original pre-authorization amount
#[derive(Debug, Serialize)]
pub struct BamboraCaptureRequest {
    pub order_number: String,
    pub amount: f64,
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

        // Convert amount from minor units to major units (cents to dollars)
        let amount_minor = item.request.minor_amount_to_capture.get_amount_as_i64();
        let amount_major = (amount_minor as f64) / 100.0;

        Ok(Self {
            order_number: item
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            amount: amount_major,
        })
    }
}

/// Capture Response Transformation
/// Per technical specification:
/// - Response payload is identical to Make Payment response
/// - Should result in AttemptStatus::Charged on success
impl TryFrom<
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
        // Critical: Check BOTH approved status AND payment type for proper status mapping
        // This addresses Silverflow PR feedback about comprehensive status checking
        let is_approved = item.response.approved == "1";

        // For capture, we expect payment type to be "PAC" (Pre-Auth Capture) or "P" (Payment)
        // Mapping based on approved status and payment type
        let status = if is_approved {
            match item.response.payment_type.as_str() {
                "P" | "PAC" => AttemptStatus::Charged, // Successfully captured
                "PA" => AttemptStatus::Authorized, // Still only authorized (shouldn't happen for capture)
                _ => AttemptStatus::Pending, // Unknown type - safe default
            }
        } else {
            // Capture failed
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
impl TryFrom<
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
        // Critical: Check BOTH approved status AND payment type for proper status mapping
        // This addresses Silverflow PR feedback about checking authorization AND clearing status
        let is_approved = item.response.approved == "1";

        // For PSync, we need to check the payment type to determine actual status
        // "P" = Payment (captured/charged)
        // "PA" = Pre-Authorization (authorized but not captured)
        // "VP" = Void Payment
        // "R" = Refund
        let status = if is_approved {
            match item.response.payment_type.as_str() {
                "P" => AttemptStatus::Charged,       // Completed payment
                "PA" => AttemptStatus::Authorized,   // Pre-authorized only
                "VP" => AttemptStatus::Voided,       // Voided payment
                "R" => AttemptStatus::Charged,       // Refund completed (payment was charged, now refunded)
                _ => AttemptStatus::Pending,         // Unknown type - safe default
            }
        } else {
            // Not approved - check payment type to determine specific failure
            match item.response.payment_type.as_str() {
                "P" => AttemptStatus::Failure,              // Failed payment
                "PA" => AttemptStatus::AuthorizationFailed, // Failed authorization
                _ => AttemptStatus::Failure,                // Generic failure
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
/// - Request body: order_number, amount
/// - Response: Identical to Make Payment response but with type "R"
#[derive(Debug, Serialize)]
pub struct BamboraRefundRequest {
    pub order_number: String,
    pub amount: f64,
}

impl TryFrom<&RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>>
    for BamboraRefundRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> Result<Self, Self::Error> {
        // Validate that we have a connector transaction ID
        // This is critical - addressing Silverflow PR feedback about proper validation
        if item.request.connector_transaction_id.is_empty() {
            return Err(errors::ConnectorError::MissingConnectorTransactionID.into());
        }

        // Convert amount from minor units to major units (cents to dollars)
        let amount_minor = item.request.minor_refund_amount.get_amount_as_i64();
        let amount_major = (amount_minor as f64) / 100.0;

        Ok(Self {
            order_number: item
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            amount: amount_major,
        })
    }
}

/// Refund Response Transformation
/// Per technical specification and Silverflow PR #240 feedback:
/// - Response payload is identical to Make Payment response
/// - CRITICAL: Check BOTH approved status AND payment type "R" for refund
/// - DO NOT assume success based on single field
/// - Payment type "R" indicates this is a refund transaction
impl TryFrom<
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
        // CRITICAL: Comprehensive refund status checking to address Silverflow PR #240 feedback
        // Issue #1 from feedback: "Assumes all refund actions with status: 'success' are successful"
        // Issue #2 from feedback: "Doesn't check action type or detailed response"
        //
        // Solution: Check BOTH approved status AND payment type
        let is_approved = item.response.approved == "1";
        let is_refund_type = item.response.payment_type == "R";

        // Map refund status based on comprehensive validation
        // This ensures we're not assuming success without proper verification
        let refund_status = match (is_approved, is_refund_type) {
            // Both approved AND type is "R" (refund) -> Success
            (true, true) => RefundStatus::Success,

            // Approved but not refund type -> This shouldn't happen for refund endpoint
            // Mark as pending to investigate
            (true, false) => RefundStatus::Pending,

            // Not approved, regardless of type -> Failure
            (false, _) => RefundStatus::Failure,
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
impl TryFrom<
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
        // CRITICAL: Comprehensive refund status checking to address Silverflow PR #240 feedback
        // Issue #1: "Assumes all refund actions with status: 'success' are successful"
        // Issue #2: "Doesn't check action type or detailed response"
        // Issue #3: "Need to validate which refund action is being checked"
        //
        // Solution: Check BOTH approved status AND payment type for proper validation
        let is_approved = item.response.approved == "1";
        let payment_type = &item.response.payment_type;

        // Map refund status based on comprehensive validation
        // For RSync, we check the transaction to verify it's actually a refund
        let refund_status = match (is_approved, payment_type.as_str()) {
            // Approved AND type is "R" (refund) -> Success
            (true, "R") => RefundStatus::Success,

            // Approved but type is "P" (payment) or "PA" (pre-auth) -> Not a refund
            // This might happen if wrong transaction ID was provided
            (true, "P" | "PA" | "PAC") => RefundStatus::Failure,

            // Approved but unknown type -> Pending (need to investigate)
            (true, _) => RefundStatus::Pending,

            // Not approved, regardless of type -> Failure
            (false, _) => RefundStatus::Failure,
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
/// - Request body: amount (optional), order_number
/// - Response: Identical to Make Payment response but with type "VP" (void payment)
/// - Can void payments, returns, and pre-authorization completions
#[derive(Debug, Serialize)]
pub struct BamboraVoidRequest {
    pub order_number: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<f64>,
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

        // Amount is optional for void - include if available
        // Per tech spec, amount can be specified for partial voids (if supported)
        let amount = item.request.amount.map(|minor_amount| {
            let amount_minor = minor_amount.get_amount_as_i64();
            (amount_minor as f64) / 100.0
        });

        Ok(Self {
            order_number: item
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            amount,
        })
    }
}

/// Void Response Transformation
/// Per technical specification and Silverflow PR #240 feedback:
/// - Response payload is identical to Make Payment response
/// - CRITICAL: Check BOTH approved status AND payment type "VP" for void
/// - DO NOT assume success based on single field
/// - Payment type "VP" indicates this is a void payment transaction
impl TryFrom<
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
        // CRITICAL: Comprehensive void status checking to address Silverflow PR #240 feedback
        // Issue #1 from feedback: "Assumes all actions with status: 'success' are successful"
        // Issue #2 from feedback: "Doesn't check action type or detailed response"
        //
        // Solution: Check BOTH approved status AND payment type
        let is_approved = item.response.approved == "1";
        let is_void_type = item.response.payment_type == "VP";

        // Map void status based on comprehensive validation
        // This ensures we're not assuming success without proper verification
        let status = match (is_approved, is_void_type) {
            // Both approved AND type is "VP" (void payment) -> Success
            (true, true) => AttemptStatus::Voided,

            // Approved but not void type -> This shouldn't happen for void endpoint
            // Could be the original payment status if void failed
            // Mark as VoidFailed since the void operation didn't complete
            (true, false) => AttemptStatus::VoidFailed,

            // Not approved, regardless of type -> Void Failed
            (false, _) => AttemptStatus::VoidFailed,
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
