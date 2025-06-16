use std::convert::TryFrom;

use hyperswitch_api_models::enums::AttemptStatus;

use hyperswitch_common_enums::RefundStatus;
use hyperswitch_common_utils::types::MinorUnit;

use domain_types::{
    connector_flow::{Authorize, Capture, RSync, Refund, SetupMandate, Void},
    connector_types::{
        MandateReference, PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData,
        PaymentsCaptureData, PaymentsResponseData, RefundFlowData, RefundSyncData, RefundsData,
        RefundsResponseData, ResponseId, SetupMandateRequestData,
    },
};
use hyperswitch_domain_models::{router_data::ConnectorAuthType, router_data_v2::RouterDataV2};
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub enum Currency {
    #[default]
    JPY,
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
            currency: map_currency_to_paypay_currency_type(item.router_data.request.currency), // PayPay primarily uses JPY
        };

        let merchant_payment_id = if item.router_data.connector_request_reference_id.is_empty() {
            return Err(
                hyperswitch_interfaces::errors::ConnectorError::MissingRequiredField {
                    field_name: "merchant_payment_id",
                },
            );
        } else {
            item.router_data.connector_request_reference_id.clone()
        };
        let user_authorization_id = if item
            .router_data
            .connector_customer
            .as_ref()
            .is_none_or(|s| s.is_empty())
        {
            return Err(
                hyperswitch_interfaces::errors::ConnectorError::MissingRequiredField {
                    field_name: "user_authorization_id",
                },
            );
        } else {
            item.router_data.connector_customer.clone().unwrap()
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
        let payment_method_type = map_payment_method_to_paypay_type(
            &item.router_data.resource_common_data.payment_method,
        );
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
    Refunded,
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
    pub reason: Option<String>,
    pub assume_merchant: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum PaypayRefundStatus {
    Created,
    Pending,
    Completed,
    Failed,
    Canceled,
    Refunded,
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
    pub(super) merchant_id: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for PaypayAuthType {
    type Error = hyperswitch_interfaces::errors::ConnectorError;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey {
                api_key,
                key1,
                api_secret,
            } => Ok(Self {
                key_id: api_key.to_owned(),
                secret_key: key1.to_owned(),
                merchant_id: api_secret.to_owned(),
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
        let status = map_paypay_payment_status(response.data.status);

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
        let status = map_paypay_payment_status(response.data.status);

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
        &PaypayRouterData<&RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>>,
    > for PaypayRefundRequest
{
    type Error = hyperswitch_interfaces::errors::ConnectorError;

    fn try_from(
        item: &PaypayRouterData<
            &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let amount = MoneyAmount {
            amount: item.router_data.request.minor_refund_amount,
            currency: map_currency_to_paypay_currency_type(item.router_data.request.currency), // PayPay primarily uses JPY
        };

        let merchant_refund_id = if item.router_data.request.refund_id.is_empty() {
            return Err(
                hyperswitch_interfaces::errors::ConnectorError::MissingRequiredField {
                    field_name: "merchant_refund_id",
                },
            );
        } else {
            item.router_data.request.refund_id.clone()
        };

        let payment_id = if item.router_data.request.connector_transaction_id.is_empty() {
            return Err(
                hyperswitch_interfaces::errors::ConnectorError::MissingRequiredField {
                    field_name: "payment_id",
                },
            );
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
        let status = map_paypay_refund_status(response.data.status);

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

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

// Helper function to map PayPay payment status to internal AttemptStatus
fn map_paypay_payment_status(paypay_status: PaypayPaymentStatus) -> AttemptStatus {
    match paypay_status {
        PaypayPaymentStatus::Created => AttemptStatus::Pending,
        PaypayPaymentStatus::Pending => AttemptStatus::Pending,
        PaypayPaymentStatus::Completed => AttemptStatus::Charged,
        PaypayPaymentStatus::Failed => AttemptStatus::Failure,
        PaypayPaymentStatus::Refunded => AttemptStatus::Charged,
    }
}

// Helper function to map PayPay refund status to internal RefundStatus
fn map_paypay_refund_status(paypay_status: PaypayRefundStatus) -> RefundStatus {
    match paypay_status {
        PaypayRefundStatus::Created => RefundStatus::Pending,
        PaypayRefundStatus::Pending => RefundStatus::Pending,
        PaypayRefundStatus::Completed => RefundStatus::Success,
        PaypayRefundStatus::Failed => RefundStatus::Failure,
        PaypayRefundStatus::Canceled => RefundStatus::Failure,
        PaypayRefundStatus::Refunded => RefundStatus::Success,
    }
}

// Helper function to convert PaymentMethod to PayPay PaymentMethodType
fn map_payment_method_to_paypay_type(
    payment_method: &hyperswitch_common_enums::PaymentMethod,
) -> Option<PaymentMethodType> {
    match payment_method {
        hyperswitch_common_enums::PaymentMethod::Card => Some(PaymentMethodType::CreditCard),
        hyperswitch_common_enums::PaymentMethod::Wallet => Some(PaymentMethodType::Wallet),
        hyperswitch_common_enums::PaymentMethod::PayLater => Some(PaymentMethodType::PayLaterCc),
        // For other payment methods, return None as they might not be supported by PayPay
        _ => None,
    }
}

// Helper function to convert hyperswitch currency to PayPay currency type
fn map_currency_to_paypay_currency_type(currency: hyperswitch_common_enums::Currency) -> Currency {
    match currency {
        hyperswitch_common_enums::Currency::JPY => Currency::JPY,
        // For other currencies, default to JPY as PayPay primarily uses JPY
        _ => Currency::JPY,
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
        let status = map_paypay_refund_status(response.data.status);

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
pub struct PaypayCaptureRequest {
    pub merchant_payment_id: String,
    pub amount: MoneyAmount,
    pub merchant_capture_id: String,
    pub requested_at: u64,
    pub order_description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaypayCaptureResponse {
    pub result_info: PaypayResultInfo,
    pub data: PaypayCaptureData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaypayCaptureData {
    pub payment_id: String,
    pub status: PaypayPaymentStatus,
    pub accepted_at: u64,
    pub refunds: Option<PaypayRefunds>,
    pub captures: Option<PaypayCaptures>,
    pub merchant_payment_id: String,
    pub user_authorization_id: String,
    pub amount: MoneyAmount,
    pub requested_at: u64,
    pub expires_at: Option<u64>,
    pub store_id: Option<String>,
    pub terminal_id: Option<String>,
    pub order_receipt_number: Option<String>,
    pub order_description: Option<String>,
    pub order_items: Option<Vec<MerchantOrderItem>>,
    pub assume_merchant: Option<String>,
    pub payment_methods: Option<Vec<PaypayPaymentMethod>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaypayCaptures {
    pub data: Vec<PaypayCaptureDataItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaypayCaptureDataItem {
    pub accepted_at: u64,
    pub merchant_capture_id: String,
    pub amount: MoneyAmount,
    pub order_description: String,
    pub requested_at: u64,
    pub status: PaypayCaptureStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum PaypayCaptureStatus {
    Created,
    Pending,
    Completed,
    Failed,
}

impl
    TryFrom<
        &PaypayRouterData<
            &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    > for PaypayCaptureRequest
{
    type Error = hyperswitch_interfaces::errors::ConnectorError;

    fn try_from(
        item: &PaypayRouterData<
            &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let amount = MoneyAmount {
            amount: item.router_data.request.minor_amount_to_capture,
            currency: map_currency_to_paypay_currency_type(item.router_data.request.currency), // PayPay primarily uses JPY
        };

        let merchant_payment_id = item
            .router_data
            .request
            .connector_transaction_id
            .get_connector_transaction_id()
            .map_err(
                |_| hyperswitch_interfaces::errors::ConnectorError::MissingRequiredField {
                    field_name: "merchant_payment_id",
                },
            )?
            .to_string();

        let merchant_capture_id = if item.router_data.request.multiple_capture_data.is_some() {
            // Use capture reference if available
            item.router_data
                .request
                .multiple_capture_data
                .as_ref()
                .map(|data| data.capture_reference.clone())
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())
        } else {
            uuid::Uuid::new_v4().to_string()
        };

        let requested_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let order_description = format!("Capture for payment {}", merchant_payment_id);

        Ok(PaypayCaptureRequest {
            merchant_payment_id,
            amount,
            merchant_capture_id,
            requested_at,
            order_description,
        })
    }
}

impl<F, Req>
    ForeignTryFrom<(
        PaypayCaptureResponse,
        RouterDataV2<F, PaymentFlowData, Req, PaymentsResponseData>,
    )> for RouterDataV2<F, PaymentFlowData, Req, PaymentsResponseData>
{
    type Error = hyperswitch_interfaces::errors::ConnectorError;

    fn foreign_try_from(
        (response, data): (
            PaypayCaptureResponse,
            RouterDataV2<F, PaymentFlowData, Req, PaymentsResponseData>,
        ),
    ) -> Result<Self, Self::Error> {
        let status = map_paypay_payment_status(response.data.status);

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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaypaySetupMandateRequest {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaypaySetupMandateResponse {
    pub result_info: PaypayResultInfo,
    pub data: PaypaySetupMandateData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaypaySetupMandateData {
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

impl
    TryFrom<
        &PaypayRouterData<
            &RouterDataV2<
                SetupMandate,
                PaymentFlowData,
                SetupMandateRequestData,
                PaymentsResponseData,
            >,
        >,
    > for PaypaySetupMandateRequest
{
    type Error = hyperswitch_interfaces::errors::ConnectorError;

    fn try_from(
        item: &PaypayRouterData<
            &RouterDataV2<
                SetupMandate,
                PaymentFlowData,
                SetupMandateRequestData,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        let amount = MoneyAmount {
            amount: item.amount,
            currency: map_currency_to_paypay_currency_type(item.router_data.request.currency), // PayPay primarily uses JPY
        };

        let merchant_payment_id = if item
            .router_data
            .request
            .merchant_order_reference_id
            .as_ref()
            .is_none_or(|s| s.is_empty())
        {
            return Err(
                hyperswitch_interfaces::errors::ConnectorError::MissingRequiredField {
                    field_name: "merchant_payment_id",
                },
            );
        } else {
            item.router_data
                .request
                .merchant_order_reference_id
                .clone()
                .unwrap()
        };

        // For PayPay, user_authorization_id is typically obtained from user authorization flow
        // This might need to be passed through metadata or a separate field
        let user_authorization_id = item
            .router_data
            .payment_method_token
            .as_ref()
            .cloned()
            .ok_or_else(|| {
                hyperswitch_interfaces::errors::ConnectorError::MissingRequiredField {
                    field_name: "user_authorization_id",
                }
            })?;

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

        Ok(PaypaySetupMandateRequest {
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

impl<F, Req>
    ForeignTryFrom<(
        PaypaySetupMandateResponse,
        RouterDataV2<F, PaymentFlowData, Req, PaymentsResponseData>,
    )> for RouterDataV2<F, PaymentFlowData, Req, PaymentsResponseData>
{
    type Error = hyperswitch_interfaces::errors::ConnectorError;

    fn foreign_try_from(
        (response, data): (
            PaypaySetupMandateResponse,
            RouterDataV2<F, PaymentFlowData, Req, PaymentsResponseData>,
        ),
    ) -> Result<Self, Self::Error> {
        let status = map_paypay_payment_status(response.data.status);

        let payment_response_data = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(response.data.payment_id.clone()),
            redirection_data: Box::new(None),
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: Some(response.data.merchant_payment_id),
            incremental_authorization_allowed: None,
            mandate_reference: Box::new(Some(MandateReference {
                connector_mandate_id: Some(response.data.payment_id),
                payment_method_id: None,
            })),
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

// ============================================================================
// VOID (CANCEL) FLOW STRUCTS AND IMPLEMENTATIONS
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaypayVoidRequest {
    // Empty structure as it's a DELETE request with path parameter
    // The merchant_payment_id is passed in the URL path
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaypayVoidResponse {
    pub result_info: PaypayResultInfo,
    pub data: PaypayVoidData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaypayVoidData {
    // Empty structure as per PayPay API response
    // The response only contains resultInfo and empty data object
}

impl
    TryFrom<
        &PaypayRouterData<
            &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        >,
    > for PaypayVoidRequest
{
    type Error = hyperswitch_interfaces::errors::ConnectorError;

    fn try_from(
        _item: &PaypayRouterData<
            &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        // Void is a DELETE request, so no request body needed
        // The merchant_payment_id is passed in the URL path
        Ok(PaypayVoidRequest {})
    }
}

impl<F, Req>
    ForeignTryFrom<(
        PaypayVoidResponse,
        RouterDataV2<F, PaymentFlowData, Req, PaymentsResponseData>,
    )> for RouterDataV2<F, PaymentFlowData, Req, PaymentsResponseData>
{
    type Error = hyperswitch_interfaces::errors::ConnectorError;

    fn foreign_try_from(
        (_response, data): (
            PaypayVoidResponse,
            RouterDataV2<F, PaymentFlowData, Req, PaymentsResponseData>,
        ),
    ) -> Result<Self, Self::Error> {
        // For PayPay void/cancel, we consider it successful if we get a 202 response
        // The status should be set to Voided
        let status = AttemptStatus::Voided;

        let payment_response_data = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(data.payment_id.clone()),
            redirection_data: Box::new(None),
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: Some(data.payment_id.clone()),
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
