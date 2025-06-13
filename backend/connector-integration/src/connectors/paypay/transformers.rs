use std::collections::HashMap;
use std::convert::TryFrom;

use error_stack::ResultExt;
use hyperswitch_api_models::enums::{self, AttemptStatus, CardNetwork};

use hyperswitch_cards::CardNumber;
use hyperswitch_common_enums::RefundStatus;
use hyperswitch_common_utils::{
    ext_traits::ByteSliceExt, pii::Email, request::Method, types::MinorUnit,
};

use domain_types::{
    connector_flow::{Authorize, Capture, CreateOrder, RSync, Refund},
    connector_types::{
        PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData, PaymentsAuthorizeData,
        PaymentsCaptureData, PaymentsResponseData, RefundFlowData, RefundSyncData, RefundsData,
        RefundsResponseData, ResponseId,
    },
};
use hyperswitch_domain_models::{
    payment_method_data::{Card, PaymentMethodData},
    router_data::{ConnectorAuthType, RouterData},
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
};
use hyperswitch_interfaces::errors;
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub enum Currency {
    #[default]
    JPY
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MoneyAmount {
    pub amount: MinorUnit,
    pub currency: Currency,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MerchantOrderItem {
    pub name: String,
    pub category: String,
    pub quantity: u32,
    pub product_id: String,
    pub unit_price: MoneyAmount,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum PaymentMethodType {
    Wallet,
    PayLaterCc,
    CreditCard,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ProductType {
    VirtualBonusInvestment,
    PayLaterRepayment,
    RealInvestment,
    Point,
    PaylaterPaymentAllocation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum OnetimeUseCashback {
    Enabled,
    Disabled,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaypayPaymentRequest {
    pub merchant_payment_id: String,
    pub user_authorization_id: String,
    pub amount: MoneyAmount,
    pub requested_at: u64,
    pub store_id: Option<String>,
    pub terminal_id: Option<String>,
    pub order_receipt_number: Option<String>,
    pub order_description: Option<String>,
    pub order_items: Option<Vec<MerchantOrderItem>>,
    pub payment_method_type: Option<PaymentMethodType>,
    pub payment_method_id: Option<String>,
    pub product_type: Option<ProductType>,
    pub onetime_use_cashback: Option<OnetimeUseCashback>,
}

pub struct PaypayRouterData<T> {
    pub amount: MinorUnit,
    pub router_data: T,
}

impl<T> TryFrom<(MinorUnit, T)> for PaypayRouterData<T> {
    type Error = hyperswitch_interfaces::errors::ConnectorError;
    fn try_from((amount, item): (MinorUnit, T)) -> Result<Self, Self::Error> {
        Ok(Self {
            amount,
            router_data: item,
        })
    }
}

impl
    TryFrom<
        &PaypayRouterData<
            &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        >,
    > for PaypayPaymentRequest
{
    type Error = hyperswitch_interfaces::errors::ConnectorError;

    fn try_from(
        item: &PaypayRouterData<
            &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let amount = MoneyAmount {
            amount: item.amount,
            currency: Currency::JPY, // PayPay primarily uses JPY
        };

        let merchant_payment_id = if item.router_data.connector_request_reference_id.clone().is_empty() {
            return Err(hyperswitch_interfaces::errors::ConnectorError::MissingRequiredField {
                field_name: "merchant_payment_id",
            });
        } else {
            item.router_data.payment_id.clone()
        };

        // For PayPay, user_authorization_id is typically obtained from user authorization flow
        // This might need to be passed through metadata or a separate field
        let user_authorization_id = if item.router_data.payment_id.is_empty() {
            return Err(hyperswitch_interfaces::errors::ConnectorError::MissingRequiredField {
                field_name: "user_authorization_id",
            });
        } else {
            item.router_data.payment_id.clone()
        };

        let requested_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Optional fields - set to None as they are not required
        let store_id = None;
        let terminal_id = None;
        let order_receipt_number = None;
        let order_description = None;
        let order_items = None;
        let payment_method_type = None;
        let payment_method_id = None;
        let product_type = None;
        let onetime_use_cashback = None;

        Ok(PaypayPaymentRequest {
            merchant_payment_id,
            user_authorization_id,
            amount,
            requested_at,
            store_id,
            terminal_id,
            order_receipt_number,
            order_description,
            order_items,
            payment_method_type,
            payment_method_id,
            product_type,
            onetime_use_cashback,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaypayPaymentResponse {
    pub result_info: PaypayResultInfo,
    pub data: PaypayPaymentData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaypaySyncRequest {
    // Empty structure as requested
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaypaySyncResponse {
    pub result_info: PaypayResultInfo,
    pub data: PaypaySyncData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaypaySyncData {
    pub payment_id: String,
    pub status: PaypayPaymentStatus,
    pub accepted_at: u64,
    pub refunds: Option<PaypayRefunds>,
    pub merchant_payment_id: String,
    pub user_authorization_id: String,
    pub amount: MoneyAmount,
    pub requested_at: u64,
    pub store_id: Option<String>,
    pub terminal_id: Option<String>,
    pub order_receipt_number: Option<String>,
    pub order_description: Option<String>,
    pub order_items: Option<Vec<MerchantOrderItem>>,
    pub payment_methods: Option<Vec<PaypayPaymentMethod>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaypayRefundRequest {
    pub merchant_refund_id: String,
    pub payment_id: String,
    pub amount: MoneyAmount,
    pub requested_at: u64,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaypayResultInfo {
    pub code: String,
    pub message: String,
    pub code_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaypayPaymentData {
    pub payment_id: String,
    pub status: PaypayPaymentStatus,
    pub accepted_at: u64,
    pub refunds: Option<PaypayRefunds>,
    pub merchant_payment_id: String,
    pub user_authorization_id: String,
    pub amount: MoneyAmount,
    pub requested_at: u64,
    pub store_id: Option<String>,
    pub terminal_id: Option<String>,
    pub order_receipt_number: Option<String>,
    pub order_description: Option<String>,
    pub order_items: Option<Vec<MerchantOrderItem>>,
    pub payment_methods: Option<Vec<PaypayPaymentMethod>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum PaypayPaymentStatus {
    Created,
    Pending,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaypayRefunds {
    pub data: Vec<PaypayRefundData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaypayRefundData {
    pub status: PaypayRefundStatus,
    pub accepted_at: u64,
    pub merchant_refund_id: String,
    pub payment_id: String,
    pub amount: MoneyAmount,
    pub requested_at: u64,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum PaypayRefundStatus {
    Created,
    Pending,
    Completed,
    Failed,
    Canceled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaypayPaymentMethod {
    pub amount: MoneyAmount,
    #[serde(rename = "type")]
    pub payment_type: PaypayPaymentMethodType,
    pub breakdown: Option<PaypayBreakdown>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum PaypayPaymentMethodType {
    Wallet,
    PayLaterCc,
    CreditCard,
    Point,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaypayBreakdown {
    pub points: Option<Vec<PaypayPoint>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaypayPoint {
    pub amount: MinorUnit,
    #[serde(rename = "type")]
    pub point_type: PaypayPointType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum PaypayPointType {
    Regular,
    Bonus,
    Campaign,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaypayErrorResponse {
    pub error: PaypayError,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaypayError {
    pub code: String,
    pub description: String,
    pub source: String,
    pub step: String,
    pub reason: String,
    pub metadata: Option<PaypayErrorMetadata>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaypayErrorMetadata {
    pub order_id: Option<String>,
}

pub struct PaypayAuthType {
    pub(super) key_id: Secret<String>,
    pub(super) secret_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for PaypayAuthType {
    type Error = hyperswitch_interfaces::errors::ConnectorError;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self {
                key_id: api_key.to_owned(),
                secret_key: key1.to_owned(),
            }),
            _ => Err(hyperswitch_interfaces::errors::ConnectorError::FailedToObtainAuthType),
        }
    }
}

pub trait ForeignTryFrom<F>: Sized {
    type Error;
    fn foreign_try_from(from: F) -> Result<Self, Self::Error>;
}

impl<F, Req>
    ForeignTryFrom<(
        PaypayPaymentResponse,
        RouterDataV2<F, PaymentFlowData, Req, PaymentsResponseData>,
        u16,
        Option<hyperswitch_api_models::enums::CaptureMethod>,
        bool,
        Option<hyperswitch_api_models::enums::PaymentMethodType>,
    )> for RouterDataV2<F, PaymentFlowData, Req, PaymentsResponseData>
{
    type Error = hyperswitch_interfaces::errors::ConnectorError;

    fn foreign_try_from(
        (response, data, _http_code, _capture_method, _is_multiple_capture_psync_flow, _pmt): (
            PaypayPaymentResponse,
            RouterDataV2<F, PaymentFlowData, Req, PaymentsResponseData>,
            u16,
            Option<hyperswitch_api_models::enums::CaptureMethod>,
            bool,
            Option<hyperswitch_api_models::enums::PaymentMethodType>,
        ),
    ) -> Result<Self, Self::Error> {
        let status = match response.data.status {
            PaypayPaymentStatus::Created => AttemptStatus::Pending,
            PaypayPaymentStatus::Pending => AttemptStatus::Pending,
            PaypayPaymentStatus::Completed => AttemptStatus::Charged,
            PaypayPaymentStatus::Failed => AttemptStatus::Failure
        };

        let payment_response_data = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(response.data.payment_id),
            redirection_data: Box::new(None),
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: Some(response.data.merchant_payment_id),
            incremental_authorization_allowed: None,
            mandate_reference: Box::new(None),
            raw_connector_response: None,
        };

        Ok(Self {
            response: Ok(payment_response_data),
            resource_common_data: PaymentFlowData {
                status,
                ..data.resource_common_data
            },
            ..data
        })
    }
}

impl<F, Req>
    ForeignTryFrom<(
        PaypaySyncResponse,
        RouterDataV2<F, PaymentFlowData, Req, PaymentsResponseData>,
        u16,
        Option<hyperswitch_api_models::enums::CaptureMethod>,
        bool,
        Option<hyperswitch_api_models::enums::PaymentMethodType>,
    )> for RouterDataV2<F, PaymentFlowData, Req, PaymentsResponseData>
{
    type Error = hyperswitch_interfaces::errors::ConnectorError;

    fn foreign_try_from(
        (response, data, _http_code, _capture_method, _is_multiple_capture_psync_flow, _pmt): (
            PaypaySyncResponse,
            RouterDataV2<F, PaymentFlowData, Req, PaymentsResponseData>,
            u16,
            Option<hyperswitch_api_models::enums::CaptureMethod>,
            bool,
            Option<hyperswitch_api_models::enums::PaymentMethodType>,
        ),
    ) -> Result<Self, Self::Error> {
        let status = match response.data.status {
            PaypayPaymentStatus::Created => AttemptStatus::Pending,
            PaypayPaymentStatus::Pending => AttemptStatus::Pending,
            PaypayPaymentStatus::Completed => AttemptStatus::Charged,
            PaypayPaymentStatus::Failed => AttemptStatus::Failure
        };

        let payment_response_data = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(response.data.payment_id),
            redirection_data: Box::new(None),
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: Some(response.data.merchant_payment_id),
            incremental_authorization_allowed: None,
            mandate_reference: Box::new(None),
            raw_connector_response: None,
        };

        Ok(Self {
            response: Ok(payment_response_data),
            resource_common_data: PaymentFlowData {
                status,
                ..data.resource_common_data
            },
            ..data
        })
    }
}

impl
    TryFrom<
        &PaypayRouterData<
            &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    > for PaypayRefundRequest
{
    type Error = hyperswitch_interfaces::errors::ConnectorError;

    fn try_from(
        item: &PaypayRouterData<
            &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let amount = MoneyAmount {
            amount: item.amount,
            currency: Currency::JPY, // PayPay primarily uses JPY
        };

        let merchant_refund_id = if item.router_data.request.refund_id.is_empty() {
            return Err(hyperswitch_interfaces::errors::ConnectorError::MissingRequiredField {
                field_name: "merchant_refund_id",
            });
        } else {
            item.router_data.request.refund_id.clone()
        };

        let payment_id = if item.router_data.request.connector_transaction_id.is_empty() {
            return Err(hyperswitch_interfaces::errors::ConnectorError::MissingRequiredField {
                field_name: "payment_id",
            });
        } else {
            item.router_data.request.connector_transaction_id.clone()
        };

        let requested_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let reason = item.router_data.request.reason.clone();

        Ok(PaypayRefundRequest {
            merchant_refund_id,
            payment_id,
            amount,
            requested_at,
            reason,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaypayRefundResponse {
    pub result_info: PaypayResultInfo,
    pub data: PaypayRefundData,
}

impl
    ForeignTryFrom<(
        PaypayRefundResponse,
        RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    )> for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = hyperswitch_interfaces::errors::ConnectorError;

    fn foreign_try_from(
        (response, data): (
            PaypayRefundResponse,
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ),
    ) -> Result<Self, Self::Error> {
        let status = match response.data.status {
            PaypayRefundStatus::Created => RefundStatus::Pending,
            PaypayRefundStatus::Pending => RefundStatus::Pending,
            PaypayRefundStatus::Completed => RefundStatus::Success,
            PaypayRefundStatus::Failed => RefundStatus::Failure,
            PaypayRefundStatus::Canceled => RefundStatus::Failure,
        };

        let refunds_response_data = RefundsResponseData {
            connector_refund_id: response.data.merchant_refund_id,
            refund_status: status,
            raw_connector_response: None,
        };

        Ok(Self {
            response: Ok(refunds_response_data),
            resource_common_data: RefundFlowData {
                status,
                ..data.resource_common_data
            },
            ..data
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaypayRsyncRequest {
    // Empty structure as it's a GET request with path parameter
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaypayRsyncResponse {
    pub result_info: PaypayResultInfo,
    pub data: PaypayRefundData,
}

impl
    TryFrom<
        &PaypayRouterData<
            &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    > for PaypayRsyncRequest
{
    type Error = hyperswitch_interfaces::errors::ConnectorError;

    fn try_from(
        _item: &PaypayRouterData<
            &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        // RSync is a GET request, so no request body needed
        Ok(PaypayRsyncRequest {})
    }
}

impl
    ForeignTryFrom<(
        PaypayRsyncResponse,
        RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
    )> for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = hyperswitch_interfaces::errors::ConnectorError;

    fn foreign_try_from(
        (response, data): (
            PaypayRsyncResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ),
    ) -> Result<Self, Self::Error> {
        let status = match response.data.status {
            PaypayRefundStatus::Created => RefundStatus::Pending,
            PaypayRefundStatus::Pending => RefundStatus::Pending,
            PaypayRefundStatus::Completed => RefundStatus::Success,
            PaypayRefundStatus::Failed => RefundStatus::Failure,
            PaypayRefundStatus::Canceled => RefundStatus::Failure,
        };

        let refunds_response_data = RefundsResponseData {
            connector_refund_id: response.data.merchant_refund_id,
            refund_status: status,
            raw_connector_response: None,
        };

        Ok(Self {
            response: Ok(refunds_response_data),
            resource_common_data: RefundFlowData {
                status,
                ..data.resource_common_data
            },
            ..data
        })
    }
}
