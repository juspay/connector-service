use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::types::ResponseRouterData;
use base64::{engine::general_purpose, Engine};
use common_enums::AttemptStatus;
use common_utils::{
    crypto::{self, SignMessage},
    types::{AmountConvertor, StringMajorUnit, StringMajorUnitForConnector},
};
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
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct FiservemeaAuthType {
    pub api_key: Secret<String>,
    pub api_secret: Secret<String>,
}

impl FiservemeaAuthType {
    pub fn generate_hmac_signature(
        &self,
        api_key: &str,
        client_request_id: &str,
        timestamp: &str,
        request_body: &str,
    ) -> Result<String, error_stack::Report<errors::ConnectorError>> {
        // Raw signature: apiKey + ClientRequestId + time + requestBody
        let raw_signature = format!(
            "{}{}{}{}",
            api_key, client_request_id, timestamp, request_body
        );

        // Generate HMAC-SHA256 with API Secret as key
        let signature = crypto::HmacSha256
            .sign_message(
                self.api_secret.clone().expose().as_bytes(),
                raw_signature.as_bytes(),
            )
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;

        // Base64 encode the result
        Ok(general_purpose::STANDARD.encode(signature))
    }

    pub fn generate_client_request_id() -> String {
        Uuid::new_v4().to_string()
    }

    pub fn generate_timestamp() -> String {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .to_string()
    }
}

impl TryFrom<&ConnectorAuthType> for FiservemeaAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey {
                api_key,
                api_secret,
                ..
            } => Ok(Self {
                api_key: api_key.to_owned(),
                api_secret: api_secret.to_owned(),
            }),
            ConnectorAuthType::BodyKey { api_key, key1, .. } => Ok(Self {
                api_key: api_key.to_owned(),
                api_secret: key1.to_owned(), // key1 is the API secret for fiservemea
            }),
            _ => Err(error_stack::report!(
                errors::ConnectorError::FailedToObtainAuthType
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FiservemeaErrorResponse {
    pub code: Option<String>,
    pub message: Option<String>,
    #[serde(rename = "details")]
    pub details: Option<Vec<ErrorDetail>>,
    #[serde(rename = "apiTraceId")]
    pub api_trace_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorDetail {
    pub field: Option<String>,
    pub message: Option<String>,
}

impl Default for FiservemeaErrorResponse {
    fn default() -> Self {
        Self {
            code: Some("UNKNOWN_ERROR".to_string()),
            message: Some("Unknown error occurred".to_string()),
            details: None,
            api_trace_id: None,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct FiservemeaPaymentsRequest<T: PaymentMethodDataTypes> {
    #[serde(rename = "requestType")]
    pub request_type: String,
    #[serde(rename = "merchantTransactionId")]
    pub merchant_transaction_id: String,
    #[serde(rename = "transactionAmount")]
    pub transaction_amount: TransactionAmount,
    #[serde(rename = "order")]
    pub order: OrderDetails,
    #[serde(rename = "paymentMethod")]
    pub payment_method: PaymentMethod<T>,
}

#[derive(Debug, Serialize)]
pub struct PaymentCardSaleTransaction<T: PaymentMethodDataTypes> {
    #[serde(rename = "requestType")]
    pub request_type: String,
    #[serde(rename = "transactionAmount")]
    pub transaction_amount: TransactionAmount,
    #[serde(rename = "paymentMethod")]
    pub payment_method: PaymentMethod<T>,
    #[serde(rename = "transactionType")]
    pub transaction_type: String,
}

#[derive(Debug, Serialize)]
pub struct PaymentCardPreAuthTransaction<T: PaymentMethodDataTypes> {
    #[serde(rename = "requestType")]
    pub request_type: String,
    #[serde(rename = "transactionAmount")]
    pub transaction_amount: TransactionAmount,
    #[serde(rename = "paymentMethod")]
    pub payment_method: PaymentMethod<T>,
    #[serde(rename = "transactionType")]
    pub transaction_type: String,
}

#[derive(Debug, Serialize)]
pub struct TransactionAmount {
    pub total: StringMajorUnit,
    pub currency: common_enums::Currency,
}

#[derive(Debug, Serialize)]
pub struct OrderDetails {
    #[serde(rename = "orderId")]
    pub order_id: String,
}

#[derive(Debug, Serialize)]
#[serde(tag = "paymentCard")]
pub struct PaymentMethod<T: PaymentMethodDataTypes> {
    #[serde(rename = "paymentCard")]
    pub payment_card: PaymentCard<T>,
}

#[derive(Debug, Serialize)]
pub struct PaymentCard<T: PaymentMethodDataTypes> {
    pub number: RawCardNumber<T>,
    #[serde(rename = "expiryDate")]
    pub expiry_date: ExpiryDate,
    #[serde(rename = "securityCode")]
    pub security_code: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub holder: Option<String>,
    #[serde(skip)]
    _phantom: std::marker::PhantomData<T>,
}

#[derive(Debug, Serialize)]
pub struct ExpiryDate {
    pub month: String,
    pub year: String,
}

// Capture Request Structure - PostAuthTransaction for Secondary Transaction endpoint
#[derive(Debug, Serialize)]
pub struct PostAuthTransaction {
    #[serde(rename = "requestType")]
    pub request_type: String,
    #[serde(rename = "transactionAmount")]
    pub transaction_amount: TransactionAmount,
}

// Refund Request Structure - ReturnTransaction for Secondary Transaction endpoint
#[derive(Debug, Serialize)]
pub struct ReturnTransaction {
    #[serde(rename = "requestType")]
    pub request_type: String,
    #[serde(rename = "transactionAmount")]
    pub transaction_amount: TransactionAmount,
}

// Void Request Structure - VoidTransaction for Secondary Transaction endpoint
#[derive(Debug, Serialize)]
pub struct VoidTransaction {
    #[serde(rename = "requestType")]
    pub request_type: String,
}

// Type aliases for flow-specific responses (to avoid macro templating conflicts)
pub type FiservemeaAuthorizeResponse = FiservemeaPaymentsResponse;
pub type FiservemeaSyncResponse = FiservemeaPaymentsResponse;
pub type FiservemeaCaptureResponse = FiservemeaPaymentsResponse;
pub type FiservemeaVoidResponse = FiservemeaPaymentsResponse;
pub type FiservemeaRefundResponse = FiservemeaPaymentsResponse;
pub type FiservemeaRefundSyncResponse = FiservemeaPaymentsResponse;

// The macro creates a FiservemeaRouterData type. We need to provide the use statement.
use super::FiservemeaRouterData;

// Implementations for FiservemeaRouterData - needed for the macro framework
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        FiservemeaRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for FiservemeaPaymentsRequest<T>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: FiservemeaRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        // Delegate to the existing TryFrom implementation
        FiservemeaPaymentsRequest::try_from(&item.router_data)
    }
}

// Note: Response conversions use the existing TryFrom implementations
// for FiservemeaPaymentsResponse since all response aliases point to it

// TryFrom for Capture
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        FiservemeaRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    > for PostAuthTransaction
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: FiservemeaRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        PostAuthTransaction::try_from(&item.router_data)
    }
}

// TryFrom for Void
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        FiservemeaRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    > for VoidTransaction
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: FiservemeaRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        VoidTransaction::try_from(&item.router_data)
    }
}

// TryFrom for Refund
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        FiservemeaRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    > for ReturnTransaction
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: FiservemeaRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        ReturnTransaction::try_from(&item.router_data)
    }
}

impl<T: PaymentMethodDataTypes>
    TryFrom<
        &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    > for FiservemeaPaymentsRequest<T>
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
        // Use StringMajorUnitForConnector to properly convert minor to major unit
        let converter = StringMajorUnitForConnector;
        let amount_major = converter
            .convert(item.request.minor_amount, item.request.currency)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;

        let transaction_amount = TransactionAmount {
            total: amount_major,
            currency: item.request.currency,
        };

        // Extract payment method data
        let payment_method = match &item.request.payment_method_data {
            PaymentMethodData::Card(card_data) => {
                // Convert year to YY format (last 2 digits)
                let year_str = card_data.card_exp_year.peek();
                let year_yy = if year_str.len() == 4 {
                    // YYYY format - take last 2 digits
                    Secret::new(year_str[2..].to_string())
                } else {
                    // Already YY format
                    card_data.card_exp_year.clone()
                };

                let payment_card = PaymentCard {
                    number: card_data.card_number.clone(),
                    expiry_date: ExpiryDate {
                        month: card_data.card_exp_month.peek().clone(),
                        year: year_yy.peek().clone(),
                    },
                    security_code: Some(card_data.card_cvc.clone()),
                    holder: item.request.customer_name.clone(),
                    _phantom: std::marker::PhantomData,
                };
                PaymentMethod { payment_card }
            }
            _ => {
                return Err(error_stack::report!(
                    errors::ConnectorError::NotImplemented(
                        "Only card payments are supported".to_string()
                    )
                ))
            }
        };

        // Determine transaction type based on capture_method
        let is_manual_capture = item
            .request
            .capture_method
            .map(|cm| matches!(cm, common_enums::CaptureMethod::Manual))
            .unwrap_or(false);

        // Generate unique merchant transaction ID using connector request reference ID
        // This provides a meaningful, unique identifier for each transaction
        let merchant_transaction_id = item
            .resource_common_data
            .connector_request_reference_id
            .clone();

        // Create order details with same ID
        let order = OrderDetails {
            order_id: merchant_transaction_id.clone(),
        };

        if is_manual_capture {
            Ok(Self {
                request_type: "PaymentCardPreAuthTransaction".to_string(),
                merchant_transaction_id,
                transaction_amount,
                order,
                payment_method,
            })
        } else {
            Ok(Self {
                request_type: "PaymentCardSaleTransaction".to_string(),
                merchant_transaction_id,
                transaction_amount,
                order,
                payment_method,
            })
        }
    }
}

impl TryFrom<&RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>>
    for PostAuthTransaction
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        // Use StringMajorUnitForConnector to properly convert minor to major unit
        let converter = StringMajorUnitForConnector;
        let amount_major = converter
            .convert(item.request.minor_amount_to_capture, item.request.currency)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;

        let transaction_amount = TransactionAmount {
            total: amount_major,
            currency: item.request.currency,
        };

        Ok(Self {
            request_type: "PostAuthTransaction".to_string(),
            transaction_amount,
        })
    }
}

impl TryFrom<&RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>>
    for ReturnTransaction
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> Result<Self, Self::Error> {
        // Use StringMajorUnitForConnector to properly convert minor to major unit
        let converter = StringMajorUnitForConnector;
        let amount_major = converter
            .convert(item.request.minor_refund_amount, item.request.currency)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;

        let transaction_amount = TransactionAmount {
            total: amount_major,
            currency: item.request.currency,
        };

        Ok(Self {
            request_type: "ReturnTransaction".to_string(),
            transaction_amount,
        })
    }
}

impl TryFrom<&RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>>
    for VoidTransaction
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        _item: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        // For void transactions, we only need to specify the transaction type
        // The transaction ID is passed in the URL path parameter
        Ok(Self {
            request_type: "VoidPreAuthTransactions".to_string(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum FiservemeaTransactionType {
    Sale,
    Preauth,
    Credit,
    Void,
    Return,
    Postauth,
    #[serde(other)]
    Unknown,
}

impl From<FiservemeaTransactionType> for AttemptStatus {
    fn from(transaction_type: FiservemeaTransactionType) -> Self {
        match transaction_type {
            FiservemeaTransactionType::Sale => Self::Charged,
            FiservemeaTransactionType::Preauth => Self::Authorized,
            FiservemeaTransactionType::Credit => Self::Charged,
            FiservemeaTransactionType::Void => Self::Voided,
            FiservemeaTransactionType::Return => Self::Charged,
            FiservemeaTransactionType::Postauth => Self::Charged,
            FiservemeaTransactionType::Unknown => Self::Pending,
        }
    }
}

impl From<FiservemeaTransactionType> for common_enums::RefundStatus {
    fn from(transaction_type: FiservemeaTransactionType) -> Self {
        match transaction_type {
            FiservemeaTransactionType::Return => Self::Success,
            FiservemeaTransactionType::Sale
            | FiservemeaTransactionType::Preauth
            | FiservemeaTransactionType::Credit
            | FiservemeaTransactionType::Postauth => Self::Success,
            FiservemeaTransactionType::Void => Self::Pending,
            FiservemeaTransactionType::Unknown => Self::Pending,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FiservemeaPaymentsResponse {
    #[serde(rename = "clientRequestId")]
    pub client_request_id: Option<String>,
    #[serde(rename = "apiTraceId")]
    pub api_trace_id: Option<String>,
    #[serde(rename = "responseType")]
    pub response_type: Option<String>,
    #[serde(rename = "type")]
    pub response_type_field: Option<String>,
    #[serde(rename = "ipgTransactionId")]
    pub ipg_transaction_id: String,
    #[serde(rename = "orderId")]
    pub order_id: Option<String>,
    #[serde(rename = "userId")]
    pub user_id: Option<String>,
    #[serde(rename = "transactionType")]
    pub transaction_type: FiservemeaTransactionType,
    #[serde(rename = "paymentToken")]
    pub payment_token: Option<PaymentToken>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PaymentToken {
    pub value: Option<String>,
    pub reusable: Option<bool>,
    #[serde(rename = "declineDuplicates")]
    pub decline_duplicates: Option<bool>,
}

impl<T: PaymentMethodDataTypes>
    TryFrom<
        ResponseRouterData<
            FiservemeaPaymentsResponse,
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
            FiservemeaPaymentsResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        // Map transaction type to status using From implementation
        let status = AttemptStatus::from(item.response.transaction_type.clone());

        // Prepare connector metadata if available
        let connector_metadata = item.response.payment_token.as_ref().map(|token| {
            let mut metadata = HashMap::new();
            if let Some(value) = &token.value {
                metadata.insert("payment_token".to_string(), value.clone());
            }
            if let Some(reusable) = token.reusable {
                metadata.insert("token_reusable".to_string(), reusable.to_string());
            }
            serde_json::Value::Object(
                metadata
                    .into_iter()
                    .map(|(k, v)| (k, serde_json::Value::String(v)))
                    .collect(),
            )
        });

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    item.response.ipg_transaction_id.clone(),
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata,
                network_txn_id: item.response.api_trace_id.clone(),
                connector_response_reference_id: item.response.client_request_id.clone(),
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

impl
    TryFrom<
        ResponseRouterData<
            FiservemeaPaymentsResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    > for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            FiservemeaPaymentsResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        // Map transaction type to status using From implementation
        let status = AttemptStatus::from(item.response.transaction_type.clone());

        // Prepare connector metadata if available
        let connector_metadata = item.response.payment_token.as_ref().map(|token| {
            let mut metadata = HashMap::new();
            if let Some(value) = &token.value {
                metadata.insert("payment_token".to_string(), value.clone());
            }
            if let Some(reusable) = token.reusable {
                metadata.insert("token_reusable".to_string(), reusable.to_string());
            }
            serde_json::Value::Object(
                metadata
                    .into_iter()
                    .map(|(k, v)| (k, serde_json::Value::String(v)))
                    .collect(),
            )
        });

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    item.response.ipg_transaction_id.clone(),
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata,
                network_txn_id: item.response.api_trace_id.clone(),
                connector_response_reference_id: item.response.client_request_id.clone(),
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

impl
    TryFrom<
        ResponseRouterData<
            FiservemeaPaymentsResponse,
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    > for RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            FiservemeaPaymentsResponse,
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        // Map transaction type to status using From implementation
        let status = AttemptStatus::from(item.response.transaction_type.clone());

        // Prepare connector metadata if available
        let connector_metadata = item.response.payment_token.as_ref().map(|token| {
            let mut metadata = HashMap::new();
            if let Some(value) = &token.value {
                metadata.insert("payment_token".to_string(), value.clone());
            }
            if let Some(reusable) = token.reusable {
                metadata.insert("token_reusable".to_string(), reusable.to_string());
            }
            serde_json::Value::Object(
                metadata
                    .into_iter()
                    .map(|(k, v)| (k, serde_json::Value::String(v)))
                    .collect(),
            )
        });

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    item.response.ipg_transaction_id.clone(),
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata,
                network_txn_id: item.response.api_trace_id.clone(),
                connector_response_reference_id: item.response.client_request_id.clone(),
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

impl
    TryFrom<
        ResponseRouterData<
            FiservemeaPaymentsResponse,
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    > for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            FiservemeaPaymentsResponse,
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        // Map transaction type to refund status using From implementation
        let refund_status =
            common_enums::RefundStatus::from(item.response.transaction_type.clone());

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.ipg_transaction_id.clone(),
                refund_status,
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

impl
    TryFrom<
        ResponseRouterData<
            FiservemeaPaymentsResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    > for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            FiservemeaPaymentsResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        // Map transaction type to refund status using From implementation
        let refund_status =
            common_enums::RefundStatus::from(item.response.transaction_type.clone());

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.ipg_transaction_id.clone(),
                refund_status,
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

impl
    TryFrom<
        ResponseRouterData<
            FiservemeaPaymentsResponse,
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        >,
    > for RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            FiservemeaPaymentsResponse,
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        // Map transaction type to void status
        // Note: For void operations, any non-VOID response means the void failed
        let status = match item.response.transaction_type {
            FiservemeaTransactionType::Void => AttemptStatus::Voided,
            _ => AttemptStatus::VoidFailed,
        };

        // Prepare connector metadata if available
        let connector_metadata = item.response.payment_token.as_ref().map(|token| {
            let mut metadata = HashMap::new();
            if let Some(value) = &token.value {
                metadata.insert("payment_token".to_string(), value.clone());
            }
            if let Some(reusable) = token.reusable {
                metadata.insert("token_reusable".to_string(), reusable.to_string());
            }
            serde_json::Value::Object(
                metadata
                    .into_iter()
                    .map(|(k, v)| (k, serde_json::Value::String(v)))
                    .collect(),
            )
        });

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    item.response.ipg_transaction_id.clone(),
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata,
                network_txn_id: item.response.api_trace_id.clone(),
                connector_response_reference_id: item.response.client_request_id.clone(),
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
