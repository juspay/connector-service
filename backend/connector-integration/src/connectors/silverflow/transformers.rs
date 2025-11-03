use crate::types::ResponseRouterData;
use common_enums::{AttemptStatus, CaptureMethod};
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
use hyperswitch_masking::{ExposeInterface, Secret};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct SilverflowAuthType {
    pub api_key: Secret<String>,
    pub api_secret: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for SilverflowAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey {
                api_key,
                api_secret,
                key1: _,
            } => Ok(Self {
                api_key: api_key.to_owned(),
                api_secret: api_secret.to_owned(),
            }),
            _ => Err(error_stack::report!(
                errors::ConnectorError::FailedToObtainAuthType
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SilverflowErrorResponse {
    pub code: Option<String>,
    pub message: Option<String>,
    pub detail: Option<String>,
    #[serde(rename = "traceId")]
    pub trace_id: Option<String>,
}

impl Default for SilverflowErrorResponse {
    fn default() -> Self {
        Self {
            code: Some("UNKNOWN_ERROR".to_string()),
            message: Some("An unknown error occurred".to_string()),
            detail: None,
            trace_id: None,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SilverflowPaymentsRequest<T: PaymentMethodDataTypes> {
    #[serde(rename = "merchantAcceptorResolver")]
    pub merchant_acceptor_resolver: SilverflowMerchantAcceptorResolver,
    pub card: SilverflowCard<T>,
    #[serde(rename = "type")]
    pub payment_type: SilverflowPaymentType,
    pub amount: SilverflowAmount,
    #[serde(rename = "clearingMode")]
    pub clearing_mode: String,
}

#[derive(Debug, Serialize)]
pub struct SilverflowMerchantAcceptorResolver {
    #[serde(rename = "merchantAcceptorKey")]
    pub merchant_acceptor_key: String,
}

#[derive(Debug, Serialize)]
pub struct SilverflowCard<T: PaymentMethodDataTypes> {
    pub number: RawCardNumber<T>,
    #[serde(rename = "expiryYear")]
    pub expiry_year: u16,
    #[serde(rename = "expiryMonth")]
    pub expiry_month: u8,
    pub cvc: Secret<String>,
    #[serde(rename = "holderName")]
    pub holder_name: Option<Secret<String>>,
}

#[derive(Debug, Serialize)]
pub struct SilverflowPaymentType {
    pub intent: String,
    #[serde(rename = "cardEntry")]
    pub card_entry: String,
    pub order: String,
}

#[derive(Debug, Serialize)]
pub struct SilverflowAmount {
    pub value: i64,
    pub currency: String,
}

impl<T: PaymentMethodDataTypes>
    TryFrom<
        &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    > for SilverflowPaymentsRequest<T>
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
        // Extract card data from payment method
        let card_data = match &item.request.payment_method_data {
            PaymentMethodData::Card(card) => card,
            _ => {
                return Err(errors::ConnectorError::NotImplemented(
                    "Only card payments are supported".to_string(),
                )
                .into())
            }
        };

        // Parse expiry year and month
        let expiry_year = card_data
            .card_exp_year
            .clone()
            .expose()
            .parse::<u16>()
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;

        let expiry_month = card_data
            .card_exp_month
            .clone()
            .expose()
            .parse::<u8>()
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;

        Ok(Self {
            merchant_acceptor_resolver: SilverflowMerchantAcceptorResolver {
                // This should be configurable, using a placeholder for now
                merchant_acceptor_key: "mac-default".to_string(),
            },
            card: SilverflowCard {
                number: card_data.card_number.clone(),
                expiry_year,
                expiry_month,
                cvc: card_data.card_cvc.clone(),
                holder_name: item.request.customer_name.clone().map(Secret::new),
            },
            payment_type: SilverflowPaymentType {
                intent: "purchase".to_string(),
                card_entry: "e-commerce".to_string(),
                order: "checkout".to_string(),
            },
            amount: SilverflowAmount {
                value: item.request.minor_amount.get_amount_as_i64(),
                currency: item.request.currency.to_string(),
            },
            clearing_mode: match item.request.capture_method {
                Some(CaptureMethod::Manual) | Some(CaptureMethod::ManualMultiple) => {
                    "manual".to_string()
                }
                _ => "auto".to_string(),
            },
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SilverflowPaymentsResponse {
    pub key: String,
    #[serde(rename = "merchantAcceptorRef")]
    pub merchant_acceptor_ref: Option<SilverflowMerchantAcceptorRef>,
    pub card: Option<SilverflowCardResponse>,
    pub amount: SilverflowAmountResponse,
    #[serde(rename = "type")]
    pub payment_type: SilverflowPaymentTypeResponse,
    #[serde(rename = "clearingMode")]
    pub clearing_mode: Option<String>,
    pub status: SilverflowStatus,
    pub authentication: Option<SilverflowAuthentication>,
    #[serde(rename = "localTransactionDateTime")]
    pub local_transaction_date_time: Option<String>,
    #[serde(rename = "fraudLiability")]
    pub fraud_liability: Option<String>,
    #[serde(rename = "authorizationIsoFields")]
    pub authorization_iso_fields: Option<SilverflowAuthorizationIsoFields>,
    pub created: Option<String>,
    pub version: Option<i32>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SilverflowMerchantAcceptorRef {
    pub key: String,
    pub version: i32,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SilverflowCardResponse {
    #[serde(rename = "maskedNumber")]
    pub masked_number: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SilverflowAmountResponse {
    pub value: i64,
    pub currency: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SilverflowPaymentTypeResponse {
    pub intent: String,
    #[serde(rename = "cardEntry")]
    pub card_entry: String,
    pub order: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SilverflowStatus {
    pub authentication: String,
    pub authorization: String,
    pub clearing: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SilverflowAuthentication {
    pub sca: Option<SilverflowSca>,
    pub cvc: Option<String>,
    pub avs: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SilverflowSca {
    pub compliance: String,
    #[serde(rename = "complianceReason")]
    pub compliance_reason: String,
    pub method: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SilverflowAuthorizationIsoFields {
    #[serde(rename = "responseCode")]
    pub response_code: String,
    #[serde(rename = "responseCodeDescription")]
    pub response_code_description: String,
    #[serde(rename = "authorizationCode")]
    pub authorization_code: String,
    #[serde(rename = "networkCode")]
    pub network_code: String,
    #[serde(rename = "systemTraceAuditNumber")]
    pub system_trace_audit_number: String,
    #[serde(rename = "retrievalReferenceNumber")]
    pub retrieval_reference_number: String,
    pub eci: String,
    #[serde(rename = "networkSpecificFields")]
    pub network_specific_fields: Option<SilverflowNetworkSpecificFields>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SilverflowNetworkSpecificFields {
    #[serde(rename = "transactionIdentifier")]
    pub transaction_identifier: Option<String>,
    #[serde(rename = "cvv2ResultCode")]
    pub cvv2_result_code: Option<String>,
}

impl<T: PaymentMethodDataTypes>
    TryFrom<
        ResponseRouterData<
            SilverflowPaymentsResponse,
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
            SilverflowPaymentsResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        // Map status based on Silverflow's authorization and clearing status
        let status = match item.response.status.authorization.as_str() {
            "approved" => {
                // Check clearing status for final status determination
                match item.response.status.clearing.as_str() {
                    "cleared" | "settled" => AttemptStatus::Charged,
                    "pending" => AttemptStatus::Authorized,
                    _ => AttemptStatus::Authorized,
                }
            }
            "pending" => AttemptStatus::Pending,
            "declined" | "failed" => AttemptStatus::Failure,
            "voided" => AttemptStatus::Voided,
            _ => AttemptStatus::Pending,
        };

        // Extract network transaction ID from authorization ISO fields
        let network_txn_id = item
            .response
            .authorization_iso_fields
            .as_ref()
            .and_then(|iso| iso.network_specific_fields.as_ref())
            .and_then(|nsf| nsf.transaction_identifier.clone());

        // Extract authorization code for connector response reference
        let connector_response_reference_id = item
            .response
            .authorization_iso_fields
            .as_ref()
            .map(|iso| iso.authorization_code.clone());

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.key),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id,
                connector_response_reference_id,
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

// PSync flow structures
#[derive(Debug, Serialize)]
pub struct SilverflowSyncRequest;

// Reuse SilverflowPaymentsResponse for sync response since GET /charges/{chargeKey} returns the same structure
pub type SilverflowSyncResponse = SilverflowPaymentsResponse;

// PSync Request Transformation (empty for GET-based connector)
impl TryFrom<&RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>
    for SilverflowSyncRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        _item: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        // Empty request for GET-based sync
        Ok(Self)
    }
}

// PSync Response Transformation
impl
    TryFrom<
        ResponseRouterData<
            SilverflowSyncResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    > for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            SilverflowSyncResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        // Map status based on Silverflow's status fields
        let status = match item.response.status.authorization.as_str() {
            "approved" => {
                // Check clearing status for final status determination
                match item.response.status.clearing.as_str() {
                    "cleared" | "settled" => AttemptStatus::Charged,
                    "pending" => AttemptStatus::Authorized,
                    _ => AttemptStatus::Authorized,
                }
            }
            "pending" => AttemptStatus::Pending,
            "declined" | "failed" => AttemptStatus::Failure,
            "voided" => AttemptStatus::Voided,
            _ => AttemptStatus::Pending,
        };

        // Extract network transaction ID from authorization ISO fields
        let network_txn_id = item
            .response
            .authorization_iso_fields
            .as_ref()
            .and_then(|iso| iso.network_specific_fields.as_ref())
            .and_then(|nsf| nsf.transaction_identifier.clone());

        // Extract authorization code for connector response reference
        let connector_response_reference_id = item
            .response
            .authorization_iso_fields
            .as_ref()
            .map(|iso| iso.authorization_code.clone());

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.key),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id,
                connector_response_reference_id,
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
// Capture flow structures
#[derive(Debug, Serialize)]
pub struct SilverflowCaptureRequest {
    pub amount: Option<i64>,
    #[serde(rename = "closeCharge")]
    pub close_charge: Option<bool>,
    pub reference: Option<String>,
}

// Capture response structure based on Silverflow clear API
#[derive(Debug, Deserialize, Serialize)]
pub struct SilverflowCaptureResponse {
    #[serde(rename = "type")]
    pub action_type: String, // Should be "clearing"
    pub key: String, // Action key (act-...)
    #[serde(rename = "chargeKey")]
    pub charge_key: String,
    pub status: String, // "completed", "pending", etc.
    pub reference: Option<String>,
    pub amount: SilverflowAmountResponse,
    #[serde(rename = "closeCharge")]
    pub close_charge: Option<bool>,
    #[serde(rename = "clearAfter")]
    pub clear_after: Option<String>,
    pub created: Option<String>,
    #[serde(rename = "lastModified")]
    pub last_modified: Option<String>,
    pub version: Option<i32>,
}

// Capture Request Transformation
impl TryFrom<&RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>>
    for SilverflowCaptureRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        // Use the capture amount for partial capture, omit for full capture
        let amount = Some(item.request.minor_amount_to_capture.get_amount_as_i64());

        // Get connector transaction ID string for reference
        let reference = Some(
            item.request
                .connector_transaction_id
                .get_connector_transaction_id()
                .change_context(errors::ConnectorError::MissingConnectorTransactionID)?,
        );

        Ok(Self {
            amount,
            close_charge: Some(true), // Close the charge after capture
            reference,
        })
    }
}

// Capture Response Transformation
impl
    TryFrom<
        ResponseRouterData<
            SilverflowCaptureResponse,
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    > for RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            SilverflowCaptureResponse,
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        // Map status based on Silverflow's action status for capture flow
        let status = match item.response.status.as_str() {
            "completed" => AttemptStatus::Charged,
            "pending" => AttemptStatus::Pending,
            "failed" | "declined" => AttemptStatus::Failure,
            _ => AttemptStatus::Pending,
        };

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.charge_key),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(item.response.key),
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

// Refund flow structures
#[derive(Debug, Serialize)]
pub struct SilverflowRefundRequest {
    #[serde(rename = "refundAmount")]
    pub refund_amount: Option<i64>,
    pub reference: Option<String>,
}

// Refund response structure based on Silverflow refund API
#[derive(Debug, Deserialize, Serialize)]
pub struct SilverflowRefundResponse {
    #[serde(rename = "type")]
    pub action_type: String, // Should be "refund"
    pub key: String, // Action key (act-...)
    #[serde(rename = "chargeKey")]
    pub charge_key: String,
    #[serde(rename = "refundChargeKey")]
    pub refund_charge_key: Option<String>,
    pub reference: Option<String>,
    pub amount: SilverflowAmountResponse,
    pub status: String,
    #[serde(rename = "authorizationResponse")]
    pub authorization_response: Option<SilverflowAuthorizationResponse>,
    pub created: Option<String>,
    #[serde(rename = "lastModified")]
    pub last_modified: Option<String>,
    pub version: Option<i32>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SilverflowAuthorizationResponse {
    pub network: Option<String>,
    #[serde(rename = "responseCode")]
    pub response_code: Option<String>,
    #[serde(rename = "responseCodeDescription")]
    pub response_code_description: Option<String>,
}

// Void/Reversal status structure (simpler than charge status)
#[derive(Debug, Deserialize, Serialize)]
pub struct SilverflowVoidStatus {
    pub authorization: String,
}

// Refund Request Transformation
impl TryFrom<&RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>>
    for SilverflowRefundRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> Result<Self, Self::Error> {
        // Use the refund amount for partial refund, omit for full refund
        let amount = Some(item.request.minor_refund_amount.get_amount_as_i64());

        // Get refund ID as reference
        let reference = Some(item.request.refund_id.clone());

        Ok(Self {
            refund_amount: amount,
            reference,
        })
    }
}

// Refund Response Transformation
impl
    TryFrom<
        ResponseRouterData<
            SilverflowRefundResponse,
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    > for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            SilverflowRefundResponse,
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        // Map refund status based on Silverflow's status string
        let refund_status = match item.response.status.as_str() {
            "success" => common_enums::RefundStatus::Success,
            "pending" => common_enums::RefundStatus::Pending,
            "failed" | "declined" => common_enums::RefundStatus::Failure,
            _ => common_enums::RefundStatus::Pending,
        };

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.key,
                refund_status,
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

// Refund Sync flow structures
#[derive(Debug, Serialize)]
pub struct SilverflowRefundSyncRequest;

// Reuse SilverflowPaymentsResponse for refund sync response since GET /charges/{chargeKey} returns the same structure
pub type SilverflowRefundSyncResponse = SilverflowPaymentsResponse;

// Refund Sync Request Transformation (empty for GET-based connector)
impl TryFrom<&RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>>
    for SilverflowRefundSyncRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        _item: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
    ) -> Result<Self, Self::Error> {
        // Empty request for GET-based sync
        Ok(Self)
    }
}

// Refund Sync Response Transformation
impl
    TryFrom<
        ResponseRouterData<
            SilverflowRefundSyncResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    > for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            SilverflowRefundSyncResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        // Map refund status based on Silverflow's status fields for sync
        let refund_status = match item.response.status.authorization.as_str() {
            "approved" => common_enums::RefundStatus::Success,
            "pending" => common_enums::RefundStatus::Pending,
            "declined" | "failed" => common_enums::RefundStatus::Failure,
            _ => common_enums::RefundStatus::Pending,
        };

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.key,
                refund_status,
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
} // Void flow structures
#[derive(Debug, Serialize)]
pub struct SilverflowVoidRequest {
    #[serde(rename = "replacementAmount")]
    pub replacement_amount: Option<i64>,
    pub reference: Option<String>,
}

// Void response structure based on Silverflow reverse API
#[derive(Debug, Deserialize, Serialize)]
pub struct SilverflowVoidResponse {
    #[serde(rename = "type")]
    pub action_type: String, // Should be "reversal"
    pub key: String, // Action key (act-...)
    #[serde(rename = "chargeKey")]
    pub charge_key: String,
    pub reference: Option<String>,
    #[serde(rename = "replacementAmount")]
    pub replacement_amount: Option<SilverflowAmountResponse>,
    pub status: SilverflowVoidStatus, // Reversal has different status structure
    #[serde(rename = "authorizationResponse")]
    pub authorization_response: Option<SilverflowAuthorizationResponse>,
    pub created: Option<String>,
    #[serde(rename = "lastModified")]
    pub last_modified: Option<String>,
    pub version: Option<i32>,
}

// Void Request Transformation
impl TryFrom<&RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>>
    for SilverflowVoidRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        // Get connector transaction ID string for reference
        let reference = Some(item.request.connector_transaction_id.clone());

        Ok(Self {
            replacement_amount: Some(0), // 0 means full reversal according to Silverflow docs
            reference,
        })
    }
}

// Void Response Transformation
impl
    TryFrom<
        ResponseRouterData<
            SilverflowVoidResponse,
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        >,
    > for RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            SilverflowVoidResponse,
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        // Map status based on Silverflow's authorization status for void operations
        let status = match item.response.status.authorization.as_str() {
            "approved" => AttemptStatus::Voided, // Successful reversal
            "pending" => AttemptStatus::Pending,
            "declined" | "failed" => AttemptStatus::Failure,
            _ => AttemptStatus::Pending,
        };

        // Extract network transaction ID from authorization response (if available)
        let network_txn_id = item
            .response
            .authorization_response
            .as_ref()
            .and_then(|auth| auth.network.clone());

        // Extract authorization code for connector response reference
        let connector_response_reference_id = item
            .response
            .authorization_response
            .as_ref()
            .and_then(|auth| auth.response_code.clone());

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.key),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id,
                connector_response_reference_id,
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
