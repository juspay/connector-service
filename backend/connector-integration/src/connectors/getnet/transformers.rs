use crate::{connectors::getnet::GetnetRouterData, types::ResponseRouterData};
use common_enums::{AttemptStatus, Currency, RefundStatus};
use common_utils::{id_type::CustomerId, types::MinorUnit};
use domain_types::{
    connector_flow::{Authorize, Capture, CreateAccessToken, PSync, RSync, Refund, Void},
    connector_types::{
        AccessTokenRequestData, AccessTokenResponseData, PaymentFlowData, PaymentVoidData,
        PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData, PaymentsSyncData,
        RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData, ResponseId,
    },
    errors,
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes, RawCardNumber},
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, PeekInterface, Secret};
use serde::{Deserialize, Serialize};

const PAYMENT_METHOD_CREDIT: &str = "CREDIT";
const TRANSACTION_TYPE_FULL: &str = "FULL";
const DEFAULT_INSTALLMENTS: i32 = 1;
const DEFAULT_CARD_HOLDER_NAME: &str = "Card Holder";

#[derive(Debug, Clone)]
pub struct GetnetAuthType {
    pub api_key: Secret<String>,
    pub api_secret: Secret<String>,
    pub seller_id: Secret<String>,
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
                api_key: api_key.to_owned(),
                api_secret: api_secret.to_owned(),
                seller_id: key1.to_owned(),
            }),
            _other => Err(error_stack::report!(
                errors::ConnectorError::FailedToObtainAuthType
            )),
        }
    }
}

// ===== ERROR RESPONSE =====
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetnetErrorResponse {
    #[serde(rename = "error_code")]
    pub code: Option<String>,
    pub message: String,
    pub details: Option<Vec<GetnetErrorDetail>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetnetErrorDetail {
    pub field: Option<String>,
    pub message: Option<String>,
}

// ===== STATUS ENUMS =====
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum GetnetPaymentStatus {
    Approved,
    Captured,
    Pending,
    Waiting,
    Authorized,
    Denied,
    Failed,
    Error,
    Canceled,
    Cancelled,
    #[serde(other)]
    Unknown,
}

impl From<&GetnetPaymentStatus> for AttemptStatus {
    fn from(status: &GetnetPaymentStatus) -> Self {
        match status {
            GetnetPaymentStatus::Approved | GetnetPaymentStatus::Captured => AttemptStatus::Charged,
            GetnetPaymentStatus::Pending
            | GetnetPaymentStatus::Waiting
            | GetnetPaymentStatus::Authorized => AttemptStatus::Pending,
            GetnetPaymentStatus::Denied
            | GetnetPaymentStatus::Failed
            | GetnetPaymentStatus::Error => AttemptStatus::Failure,
            GetnetPaymentStatus::Canceled | GetnetPaymentStatus::Cancelled => AttemptStatus::Voided,
            GetnetPaymentStatus::Unknown => AttemptStatus::Pending,
        }
    }
}

impl From<&GetnetPaymentStatus> for RefundStatus {
    fn from(status: &GetnetPaymentStatus) -> Self {
        match status {
            GetnetPaymentStatus::Canceled | GetnetPaymentStatus::Cancelled => RefundStatus::Success,
            GetnetPaymentStatus::Pending | GetnetPaymentStatus::Waiting => RefundStatus::Pending,
            GetnetPaymentStatus::Denied
            | GetnetPaymentStatus::Failed
            | GetnetPaymentStatus::Error => RefundStatus::Failure,
            _ => RefundStatus::Pending,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct GetnetAuthorizeRequest<T: PaymentMethodDataTypes> {
    pub request_id: String,
    pub idempotency_key: String,
    pub order_id: String,
    pub data: GetnetPaymentData<T>,
}

#[derive(Debug, Serialize)]
pub struct GetnetPaymentData<T: PaymentMethodDataTypes> {
    pub customer_id: String,
    pub amount: MinorUnit,
    pub currency: Currency,
    pub payment: GetnetPayment<T>,
}

#[derive(Debug, Serialize)]
pub struct GetnetPayment<T: PaymentMethodDataTypes> {
    pub payment_id: String,
    pub payment_method: String,
    pub transaction_type: String,
    pub number_installments: i32,
    pub card: GetnetCard<T>,
}

#[derive(Debug, Serialize)]
pub struct GetnetCard<T: PaymentMethodDataTypes> {
    pub number: RawCardNumber<T>,
    pub expiration_month: Secret<String>,
    pub expiration_year: Secret<String>,
    pub cardholder_name: Secret<String>,
    pub security_code: Secret<String>,
    #[serde(skip)]
    _phantom: std::marker::PhantomData<T>,
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    >
    TryFrom<
        GetnetRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for GetnetAuthorizeRequest<T>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        wrapper: GetnetRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let item = &wrapper.router_data;
        let card_data = match &item.request.payment_method_data {
            PaymentMethodData::Card(card) => card,
            _ => {
                return Err(errors::ConnectorError::NotImplemented(
                    "Payment method not supported".to_string(),
                )
                .into())
            }
        };

        // Convert 4-digit year to 2-digit year (e.g., "2025" -> "25")
        let year_str = card_data.card_exp_year.peek();
        let expiration_year = if year_str.len() >= 2 {
            Secret::new(year_str[year_str.len() - 2..].to_string())
        } else {
            card_data.card_exp_year.clone()
        };

        let cardholder_name = if let Some(ref holder_name) = card_data.card_holder_name {
            holder_name.clone()
        } else if let Some(billing_addr) = item.resource_common_data.get_optional_billing() {
            let first_name = billing_addr
                .address
                .as_ref()
                .and_then(|addr| addr.first_name.as_ref().map(|n| n.peek().clone()))
                .unwrap_or_default();
            let last_name = billing_addr
                .address
                .as_ref()
                .and_then(|addr| addr.last_name.as_ref().map(|n| n.peek().clone()))
                .unwrap_or_default();

            if !first_name.is_empty() || !last_name.is_empty() {
                Secret::new(format!("{} {}", first_name, last_name).trim().to_string())
            } else {
                Secret::new(DEFAULT_CARD_HOLDER_NAME.to_string())
            }
        } else {
            Secret::new(DEFAULT_CARD_HOLDER_NAME.to_string())
        };

        let card = GetnetCard {
            number: card_data.card_number.clone(),
            expiration_month: card_data.card_exp_month.clone(),
            expiration_year,
            cardholder_name,
            security_code: card_data.card_cvc.clone(),
            _phantom: std::marker::PhantomData,
        };

        let payment = GetnetPayment {
            payment_id: uuid::Uuid::new_v4().to_string(),
            payment_method: PAYMENT_METHOD_CREDIT.to_string(),
            transaction_type: TRANSACTION_TYPE_FULL.to_string(),
            number_installments: DEFAULT_INSTALLMENTS,
            card,
        };

        let customer_id = item
            .resource_common_data
            .get_customer_id()
            .unwrap_or_else(|_| CustomerId::default())
            .get_string_repr()
            .to_string();

        let data = GetnetPaymentData {
            customer_id,
            amount: item.request.minor_amount,
            currency: item.request.currency,
            payment,
        };

        let request_ref_id = item
            .resource_common_data
            .connector_request_reference_id
            .clone();

        Ok(Self {
            request_id: uuid::Uuid::new_v4().to_string(),
            idempotency_key: request_ref_id.clone(),
            order_id: request_ref_id,
            data,
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GetnetAuthorizeResponse {
    pub payment_id: String,
    pub order_id: Option<String>,
    pub amount: MinorUnit,
    pub currency: Option<Currency>,
    pub status: GetnetPaymentStatus,
    pub payment_method: Option<String>,
    pub received_at: Option<String>,
    pub transaction_id: Option<String>,
    pub authorization_code: Option<String>,
    pub brand: Option<String>,
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    >
    TryFrom<
        ResponseRouterData<
            GetnetAuthorizeResponse,
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
            GetnetAuthorizeResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        let status = AttemptStatus::from(&item.response.status);

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.payment_id.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: item.response.transaction_id.clone(),
                connector_response_reference_id: item.response.order_id.clone(),
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

#[derive(Debug, Serialize)]
pub struct GetnetCaptureRequest {
    pub idempotency_key: String,
    pub payment_id: String,
    pub amount: MinorUnit,
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    >
    TryFrom<
        GetnetRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    > for GetnetCaptureRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: GetnetRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;

        let payment_id = router_data
            .request
            .connector_transaction_id
            .get_connector_transaction_id()
            .change_context(errors::ConnectorError::MissingConnectorTransactionID)?;

        let capture_amount = router_data.request.amount_to_capture;

        let capture_amount_minor = MinorUnit::new(capture_amount);

        Ok(Self {
            idempotency_key: router_data
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            payment_id,
            amount: capture_amount_minor,
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GetnetCaptureResponse {
    pub idempotency_key: Option<String>,
    pub seller_id: Option<String>,
    pub payment_id: String,
    pub order_id: Option<String>,
    pub amount: MinorUnit,
    pub currency: Option<Currency>,
    pub status: GetnetPaymentStatus,
    pub reason_code: Option<String>,
    pub reason_message: Option<String>,
    pub captured_at: Option<String>,
}

impl
    TryFrom<
        ResponseRouterData<
            GetnetCaptureResponse,
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    > for RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            GetnetCaptureResponse,
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let status = AttemptStatus::from(&item.response.status);

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.payment_id.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: item.response.order_id.clone(),
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

// ===== PSYNC RESPONSE =====
#[derive(Debug, Deserialize, Serialize)]
pub struct GetnetSyncResponse {
    pub payment_id: String,
    pub order_id: Option<String>,
    pub status: GetnetPaymentStatus,
    pub payment: Option<GetnetSyncPaymentDetails>,
    pub records: Option<Vec<GetnetSyncRecord>>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GetnetSyncPaymentDetails {
    pub payment_method: Option<String>,
    pub transaction_type: Option<String>,
    pub card: Option<GetnetSyncCardDetails>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GetnetSyncCardDetails {
    pub number: Option<String>,
    pub brand: Option<String>,
    pub cardholder_name: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GetnetSyncRecord {
    pub rel: Option<String>,
    pub registered_at: Option<String>,
    pub idempotency_key: Option<String>,
    pub href: Option<String>,
}

impl
    TryFrom<
        ResponseRouterData<
            GetnetSyncResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    > for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            GetnetSyncResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let status = AttemptStatus::from(&item.response.status);

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.payment_id.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: item.response.order_id.clone(),
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
pub struct GetnetRefundRequest {
    pub idempotency_key: String,
    pub payment_id: String,
    pub amount: MinorUnit,
    pub payment_method: String,
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    >
    TryFrom<
        GetnetRouterData<RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>, T>,
    > for GetnetRefundRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: GetnetRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;

        let payment_id = router_data.request.connector_transaction_id.clone();

        Ok(Self {
            idempotency_key: router_data
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            payment_id,
            amount: router_data.request.minor_refund_amount,
            payment_method: PAYMENT_METHOD_CREDIT.to_string(),
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GetnetRefundResponse {
    pub idempotency_key: Option<String>,
    pub seller_id: Option<String>,
    pub payment_id: String,
    pub order_id: Option<String>,
    pub amount: MinorUnit,
    pub status: GetnetPaymentStatus,
    pub reason_code: Option<String>,
    pub reason_message: Option<String>,
    pub canceled_at: Option<String>,
}

impl
    TryFrom<
        ResponseRouterData<
            GetnetRefundResponse,
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    > for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            GetnetRefundResponse,
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let refund_status = RefundStatus::from(&item.response.status);

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.payment_id.clone(),
                refund_status,
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

// ===== RSYNC RESPONSE =====
pub type GetnetRefundSyncResponse = GetnetSyncResponse;

impl
    TryFrom<
        ResponseRouterData<
            GetnetRefundSyncResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    > for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            GetnetRefundSyncResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let refund_status = RefundStatus::from(&item.response.status);

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.payment_id.clone(),
                refund_status,
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

#[derive(Debug, Serialize)]
pub struct GetnetAccessTokenRequest {
    pub grant_type: String,
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    >
    TryFrom<
        GetnetRouterData<
            RouterDataV2<
                CreateAccessToken,
                PaymentFlowData,
                AccessTokenRequestData,
                AccessTokenResponseData,
            >,
            T,
        >,
    > for GetnetAccessTokenRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: GetnetRouterData<
            RouterDataV2<
                CreateAccessToken,
                PaymentFlowData,
                AccessTokenRequestData,
                AccessTokenResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            grant_type: item.router_data.request.grant_type,
        })
    }
}

// ===== ACCESS TOKEN RESPONSE =====
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GetnetAccessTokenResponse {
    pub access_token: Secret<String>,
    pub token_type: String,
    pub expires_in: i64,
    pub scope: Option<String>,
}

impl<F, T>
    TryFrom<
        ResponseRouterData<
            GetnetAccessTokenResponse,
            RouterDataV2<F, PaymentFlowData, T, AccessTokenResponseData>,
        >,
    > for RouterDataV2<F, PaymentFlowData, T, AccessTokenResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            GetnetAccessTokenResponse,
            RouterDataV2<F, PaymentFlowData, T, AccessTokenResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(AccessTokenResponseData {
                access_token: item.response.access_token.expose(),
                expires_in: Some(item.response.expires_in),
                token_type: Some(item.response.token_type),
            }),
            ..item.router_data
        })
    }
}

// ===== VOID REQUEST =====
// Getnet uses the same endpoint for both void and refund
pub type GetnetVoidRequest = GetnetRefundRequest;

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    >
    TryFrom<
        GetnetRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    > for GetnetVoidRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: GetnetRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;

        let payment_id = router_data.request.connector_transaction_id.clone();

        let void_amount =
            router_data
                .request
                .amount
                .ok_or(errors::ConnectorError::MissingRequiredField {
                    field_name: "amount",
                })?;

        Ok(Self {
            idempotency_key: router_data
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            payment_id,
            amount: void_amount,
            payment_method: PAYMENT_METHOD_CREDIT.to_string(),
        })
    }
}

// ===== VOID RESPONSE =====
// Getnet uses the same endpoint for both void and refund
pub type GetnetVoidResponse = GetnetRefundResponse;

impl
    TryFrom<
        ResponseRouterData<
            GetnetVoidResponse,
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        >,
    > for RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            GetnetVoidResponse,
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let status = AttemptStatus::from(&item.response.status);

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.payment_id.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: item.response.order_id.clone(),
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
