use crate::types::ResponseRouterData;
use common_enums::{AttemptStatus, RefundStatus};
use common_utils::types::{AmountConvertor, FloatMajorUnit, FloatMajorUnitForConnector};
use domain_types::{
    connector_flow::{Authorize, Capture, PSync, RSync, Refund, Void},
    connector_types::{
        MandateReference, PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData,
        PaymentsCaptureData, PaymentsResponseData, PaymentsSyncData, RefundFlowData,
        RefundSyncData, RefundsData, RefundsResponseData, ResponseId,
    },
    errors,
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes, RawCardNumber},
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
};

// Note: Refund and RefundsData are used for the Refund flow implementation
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, Secret};
use serde::{Deserialize, Serialize};
use serde_json;

// ===== AUTHENTICATION =====

#[derive(Debug, Clone)]
pub struct NmiAuthType {
    pub api_key: Secret<String>,
    pub public_key: Option<Secret<String>>,
}

impl TryFrom<&ConnectorAuthType> for NmiAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::HeaderKey { api_key } => Ok(Self {
                api_key: api_key.to_owned(),
                public_key: None,
            }),
            ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self {
                api_key: api_key.to_owned(),
                public_key: Some(key1.to_owned()),
            }),
            _ => Err(error_stack::report!(
                errors::ConnectorError::FailedToObtainAuthType
            )),
        }
    }
}

// ===== TRANSACTION TYPES =====

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TransactionType {
    Auth,
    Sale,
    Capture,
    Refund,
    Void,
    Validate,
}

// ===== PAYMENT METHOD DATA =====

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum NmiPaymentMethod<T: PaymentMethodDataTypes> {
    Card(Box<CardData<T>>),
}

#[derive(Debug, Serialize)]
pub struct CardData<T: PaymentMethodDataTypes> {
    ccnumber: RawCardNumber<T>,
    ccexp: Secret<String>, // MMYY format
    cvv: Secret<String>,
}

// ===== MERCHANT DEFINED FIELDS =====

#[derive(Debug, Serialize)]
pub struct NmiMerchantDefinedField {
    #[serde(flatten)]
    inner: std::collections::BTreeMap<String, Secret<String>>,
}

impl NmiMerchantDefinedField {
    pub fn new(metadata: &serde_json::Value) -> Self {
        let metadata_as_string = metadata.to_string();
        let hash_map: std::collections::BTreeMap<String, serde_json::Value> =
            serde_json::from_str(&metadata_as_string).unwrap_or(std::collections::BTreeMap::new());
        let inner = hash_map
            .into_iter()
            .enumerate()
            .map(|(index, (hs_key, hs_value))| {
                let nmi_key = format!("merchant_defined_field_{}", index + 1);
                let nmi_value = format!("{hs_key}={hs_value}");
                (nmi_key, Secret::new(nmi_value))
            })
            .collect();
        Self { inner }
    }
}

// ===== PAYMENT REQUEST =====

#[derive(Debug, Serialize)]
pub struct NmiPaymentsRequest<T: PaymentMethodDataTypes> {
    security_key: Secret<String>,
    #[serde(rename = "type")]
    transaction_type: TransactionType,
    amount: FloatMajorUnit,
    currency: common_enums::Currency,
    orderid: String,
    #[serde(flatten)]
    payment_method: NmiPaymentMethod<T>,
    #[serde(flatten)]
    merchant_defined_field: Option<NmiMerchantDefinedField>,
}

// Implementation for NmiRouterData wrapper (needed by macros)
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        super::NmiRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for NmiPaymentsRequest<T>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: super::NmiRouterData<
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
        let auth = NmiAuthType::try_from(&router_data.connector_auth_type)?;

        // Determine transaction type based on auto_capture
        let transaction_type = if router_data.request.is_auto_capture()? {
            TransactionType::Sale
        } else {
            TransactionType::Auth
        };

        // Extract payment method data
        let payment_method = NmiPaymentMethod::try_from(&router_data.request.payment_method_data)?;

        // Convert amount from minor units to major units using framework converter
        let converter = FloatMajorUnitForConnector;
        let amount = converter
            .convert(
                router_data.request.minor_amount,
                router_data.request.currency,
            )
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;

        Ok(Self {
            security_key: auth.api_key,
            transaction_type,
            amount,
            currency: router_data.request.currency,
            orderid: router_data
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            payment_method,
            merchant_defined_field: router_data
                .request
                .metadata
                .as_ref()
                .map(NmiMerchantDefinedField::new),
        })
    }
}

// ===== PAYMENT METHOD TRANSFORMATION =====

impl<T: PaymentMethodDataTypes> TryFrom<&PaymentMethodData<T>> for NmiPaymentMethod<T> {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(pm_data: &PaymentMethodData<T>) -> Result<Self, Self::Error> {
        match pm_data {
            PaymentMethodData::Card(card_data) => {
                // Extract expiry date in MMYY format using framework utility
                let ccexp =
                    card_data.get_card_expiry_month_year_2_digit_with_delimiter("".to_string())?;

                let card = CardData {
                    ccnumber: card_data.card_number.clone(),
                    ccexp,
                    cvv: card_data.card_cvc.clone(),
                };
                Ok(Self::Card(Box::new(card)))
            }
            _ => Err(error_stack::report!(
                errors::ConnectorError::NotImplemented("Payment method not supported".to_string())
            )),
        }
    }
}

// ===== PAYMENT RESPONSE =====

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct StandardResponse {
    pub response: String, // "1" = approved, "2" = declined, "3" = error
    pub responsetext: String,
    pub authcode: Option<String>,
    pub transactionid: String,
    pub avsresponse: Option<String>,
    pub cvvresponse: Option<String>,
    pub orderid: String,
    pub response_code: String,
    #[serde(default)]
    pub customer_vault_id: Option<Secret<String>>,
}

// Type alias for consistency with nmi.rs
pub type NmiPaymentsResponse = StandardResponse;

impl<T: PaymentMethodDataTypes>
    TryFrom<
        ResponseRouterData<
            StandardResponse,
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
            StandardResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;

        // Determine status based on response code
        let status = match response.response.as_str() {
            "1" => {
                // Approved - check if it was auth or sale
                // For auth type, status is Authorized
                // For sale type, status is Charged
                // We need to check the original request's auto_capture flag
                if item.router_data.request.is_auto_capture()? {
                    AttemptStatus::Charged
                } else {
                    AttemptStatus::Authorized
                }
            }
            "2" => AttemptStatus::Failure, // Declined
            "3" => AttemptStatus::Failure, // Error
            _ => AttemptStatus::Pending,
        };

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(response.transactionid.clone()),
                redirection_data: None,
                mandate_reference: response.customer_vault_id.as_ref().map(|vault_id| {
                    Box::new(MandateReference {
                        connector_mandate_id: Some(vault_id.clone().expose()),
                        payment_method_id: None,
                    })
                }),
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(response.orderid.clone()),
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

// ===== ERROR RESPONSE =====

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NmiErrorResponse {
    pub code: String,
    pub message: String,
}

// ===== PAYMENT SYNC (PSYNC) REQUEST =====

#[derive(Debug, Serialize)]
pub struct NmiSyncRequest {
    security_key: Secret<String>,
    order_id: String, // Uses attempt_id, NOT connector_transaction_id
}

// Implementation for NmiRouterData wrapper (needed by macros)
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        super::NmiRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    > for NmiSyncRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: super::NmiRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let auth = NmiAuthType::try_from(&router_data.connector_auth_type)?;

        // PSync uses attempt_id as order_id (NOT connector_transaction_id)
        // The connector_transaction_id contains the attempt_id for sync operations
        let order_id = router_data
            .resource_common_data
            .connector_request_reference_id
            .clone();

        Ok(Self {
            security_key: auth.api_key,
            order_id,
        })
    }
}

// ===== PAYMENT SYNC (PSYNC) RESPONSE =====

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename = "nm_response")]
pub struct SyncResponse {
    #[serde(default)]
    pub transaction: Vec<SyncTransactionData>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SyncTransactionData {
    pub transaction_id: String,
    pub condition: String, // Maps to status
}

impl
    TryFrom<
        ResponseRouterData<
            SyncResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    > for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            SyncResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;

        // Get the requested transaction_id to find the correct transaction
        let requested_transaction_id = item
            .router_data
            .request
            .connector_transaction_id
            .get_connector_transaction_id()
            .change_context(errors::ConnectorError::MissingConnectorTransactionID)?;

        // Find the transaction matching the requested transaction_id
        // If not found, use the most recent one (last in list)
        let transaction = response
            .transaction
            .iter()
            .find(|txn| txn.transaction_id == requested_transaction_id)
            .or_else(|| response.transaction.last());

        // Handle empty response (means AuthenticationPending) or transaction data
        let (status, transaction_id) = if let Some(transaction) = transaction {
            // Map condition field from XML to AttemptStatus
            let status = match transaction.condition.as_str() {
                "pending" => AttemptStatus::Authorized,
                "pendingsettlement" => AttemptStatus::Charged,
                "complete" => AttemptStatus::Charged,
                "in_progress" => AttemptStatus::AuthenticationPending,
                "abandoned" => AttemptStatus::AuthenticationFailed,
                "cancelled" | "canceled" => AttemptStatus::Voided,
                "failed" => AttemptStatus::Failure,
                _ => AttemptStatus::Pending,
            };
            (status, Some(transaction.transaction_id.clone()))
        } else {
            // Empty XML response = AuthenticationPending (during 3DS flow)
            (AttemptStatus::AuthenticationPending, None)
        };

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: transaction_id
                    .map(ResponseId::ConnectorTransactionId)
                    .unwrap_or(ResponseId::NoResponseId),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: None,
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

// ===== CAPTURE REQUEST =====

#[derive(Debug, Serialize)]
pub struct NmiCaptureRequest {
    security_key: Secret<String>,
    #[serde(rename = "type")]
    transaction_type: TransactionType,
    transactionid: String,
    amount: FloatMajorUnit,
}

// Implementation for NmiRouterData wrapper (needed by macros)
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        super::NmiRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    > for NmiCaptureRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: super::NmiRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let auth = NmiAuthType::try_from(&router_data.connector_auth_type)?;

        // Get the original transaction ID from connector_transaction_id
        let transactionid = router_data
            .request
            .connector_transaction_id
            .get_connector_transaction_id()
            .change_context(errors::ConnectorError::MissingRequiredField {
                field_name: "connector_transaction_id",
            })?;

        // Convert amount from minor to major units using framework converter
        let converter = FloatMajorUnitForConnector;
        let amount = converter
            .convert(
                router_data.request.minor_amount_to_capture,
                router_data.request.currency,
            )
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;

        Ok(Self {
            security_key: auth.api_key,
            transaction_type: TransactionType::Capture,
            transactionid,
            amount,
        })
    }
}

// ===== CAPTURE RESPONSE =====

impl
    TryFrom<
        ResponseRouterData<
            StandardResponse,
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    > for RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            StandardResponse,
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;

        // Capture success = Charged status
        // Capture failure = Failure status
        let status = match response.response.as_str() {
            "1" => AttemptStatus::Charged,       // Capture successful
            "2" | "3" => AttemptStatus::Failure, // Capture failed
            _ => AttemptStatus::Pending,
        };

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(response.transactionid.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(response.orderid.clone()),
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

// ===== REFUND REQUEST =====

#[derive(Debug, Serialize)]
pub struct NmiRefundRequest {
    security_key: Secret<String>,
    #[serde(rename = "type")]
    transaction_type: TransactionType,
    transactionid: String,
    orderid: String,
    amount: FloatMajorUnit, // 0.00 for full refund
    #[serde(skip_serializing_if = "Option::is_none")]
    payment: Option<PaymentType>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PaymentType {
    Creditcard,
    Check,
}

// Implementation for NmiRouterData wrapper (needed by macros)
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        super::NmiRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    > for NmiRefundRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: super::NmiRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let auth = NmiAuthType::try_from(&router_data.connector_auth_type)?;

        // Get the original payment transaction ID
        let transactionid = router_data.request.connector_transaction_id.clone();

        // Get the refund ID (refund_id) as orderid
        // If refund_id is not present, use connector_request_reference_id as fallback
        let orderid = router_data
            .resource_common_data
            .refund_id
            .clone()
            .unwrap_or_else(|| {
                router_data
                    .resource_common_data
                    .connector_request_reference_id
                    .clone()
            });

        // Convert amount from minor to major units using framework converter
        let converter = FloatMajorUnitForConnector;
        let amount = converter
            .convert(
                router_data.request.minor_refund_amount,
                router_data.request.currency,
            )
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;

        Ok(Self {
            security_key: auth.api_key,
            transaction_type: TransactionType::Refund,
            transactionid,
            orderid,
            amount,
            payment: None, // NMI infers payment type from the referenced transaction
        })
    }
}

// ===== REFUND RESPONSE =====

impl
    TryFrom<
        ResponseRouterData<
            StandardResponse,
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    > for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            StandardResponse,
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;

        // Map response code to RefundStatus
        // "1" = Success, "2"/"3" = Failure
        let status = match response.response.as_str() {
            "1" => RefundStatus::Success,
            "2" | "3" => RefundStatus::Failure,
            _ => RefundStatus::Pending,
        };

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: response.transactionid.clone(),
                refund_status: status,
                status_code: item.http_code,
            }),
            resource_common_data: RefundFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

// ===== REFUND SYNC (RSYNC) REQUEST =====

#[derive(Debug, Serialize)]
pub struct NmiRefundSyncRequest {
    security_key: Secret<String>,
    order_id: String, // Uses connector_refund_id
}

// Implementation for NmiRouterData wrapper (needed by macros)
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        super::NmiRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    > for NmiRefundSyncRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: super::NmiRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let auth = NmiAuthType::try_from(&router_data.connector_auth_type)?;

        // RSync uses connector_refund_id as order_id (per tech spec section 3.6)
        let order_id = router_data.request.connector_refund_id.clone();

        Ok(Self {
            security_key: auth.api_key,
            order_id,
        })
    }
}

// ===== REFUND SYNC (RSYNC) RESPONSE =====
// Reusing SyncResponse structure as XML format is same (per tech spec section 3.9)

impl
    TryFrom<
        ResponseRouterData<
            SyncResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    > for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            SyncResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;

        // Get the last transaction from the list (most recent)
        let transaction = response.transaction.last();

        // Map condition field from XML to RefundStatus (per tech spec section 3.10)
        let (status, connector_refund_id) = if let Some(transaction) = transaction {
            let status = match transaction.condition.as_str() {
                "complete" | "pendingsettlement" => RefundStatus::Success,
                "pending" => RefundStatus::Pending,
                "failed" | "abandoned" | "cancelled" | "canceled" => RefundStatus::Failure,
                _ => RefundStatus::Pending,
            };
            (status, Some(transaction.transaction_id.clone()))
        } else {
            // Empty response - treat as pending
            (RefundStatus::Pending, None)
        };

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: connector_refund_id.unwrap_or_default(),
                refund_status: status,
                status_code: item.http_code,
            }),
            resource_common_data: RefundFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

// ===== VOID REQUEST =====

#[derive(Debug, Serialize)]
pub struct NmiVoidRequest {
    security_key: Secret<String>,
    #[serde(rename = "type")]
    transaction_type: TransactionType,
    transactionid: String,
    void_reason: VoidReason,
    #[serde(skip_serializing_if = "Option::is_none")]
    payment: Option<PaymentType>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VoidReason {
    Fraud,
    UserCancel,
    IccRejected,
}

// Implementation for NmiRouterData wrapper (needed by macros)
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        super::NmiRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    > for NmiVoidRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: super::NmiRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let auth = NmiAuthType::try_from(&router_data.connector_auth_type)?;

        // Get the original payment transaction ID
        let transactionid = router_data.request.connector_transaction_id.clone();

        // Map cancellation reason to NMI's void reason
        let void_reason = router_data
            .request
            .cancellation_reason
            .as_ref()
            .and_then(|reason| match reason.as_str() {
                "fraud" => Some(VoidReason::Fraud),
                "user_cancel" | "requested_by_customer" => Some(VoidReason::UserCancel),
                _ => None,
            })
            .unwrap_or(VoidReason::UserCancel); // Default to UserCancel

        Ok(Self {
            security_key: auth.api_key,
            transaction_type: TransactionType::Void,
            transactionid,
            void_reason,
            payment: None, // NMI infers payment type from the referenced transaction
        })
    }
}

// ===== VOID RESPONSE =====

impl
    TryFrom<
        ResponseRouterData<
            StandardResponse,
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        >,
    > for RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            StandardResponse,
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;

        // Void success = Voided status
        // Void failure = VoidFailed status
        let status = match response.response.as_str() {
            "1" => AttemptStatus::Voided,           // Void successful
            "2" | "3" => AttemptStatus::VoidFailed, // Void failed
            _ => AttemptStatus::Pending,
        };

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(response.transactionid.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(response.orderid.clone()),
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
