use std::collections::HashMap;

use common_utils::{
    ext_traits::ValueExt,
    request::Method,
};
use domain_types::{
    connector_flow::{Authorize, PSync, RSync},
    connector_types::{
        PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData,
        RefundFlowData, RefundSyncData, RefundsResponseData,
    },
    errors::{self, ConnectorError},
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
};
use error_stack::ResultExt;
use hyperswitch_masking::{Maskable, PeekInterface, Secret};
use serde::{Deserialize, Serialize};

use crate::{connectors::zaakpay::ZaakPayRouterData, types::ResponseRouterData};

// Request types based on Haskell implementation

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayPaymentsRequest {
    pub data: ZaakPayTransactDataRequest,
    pub checksum: String,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayTransactDataRequest {
    pub merchant_identifier: String,
    pub encryption_key_id: Option<String>,
    pub show_mobile: Option<String>,
    pub mode: String,
    pub return_url: String,
    pub order_detail: ZaakPayOrderDetailTransType,
    pub billing_address: ZaakPayBillingAddressType,
    pub shipping_address: Option<ZaakPayShippingAddressType>,
    pub payment_instrument: ZaakPayPaymentInstrumentTransType,
}

#[derive(Default, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayOrderDetailTransType {
    pub order_id: String,
    pub amount: String,
    pub currency: String,
    pub product_description: String,
    pub email: String,
    pub phone: String,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayBillingAddressType {
    pub address: String,
    pub city: String,
    pub state: String,
    pub country: String,
    pub pincode: Secret<String>,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayShippingAddressType {
    pub address: Option<String>,
    pub city: Option<String>,
    pub state: Option<String>,
    pub country: Option<String>,
    pub pincode: Option<Secret<String>>,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayPaymentInstrumentTransType {
    pub payment_mode: String,
    pub card: Option<ZaakPayCardTransType>,
    pub netbanking: Option<ZaakPayNetTransType>,
    pub upi: Option<ZaakPayUpiTransType>,
}

#[derive(Default, Debug, Serialize)]
pub struct ZaakPayCardTransType;

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayNetTransType {
    pub bankid: String,
    pub bank_name: String,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayUpiTransType {
    pub bankid: String,
}

// Sync request types
#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayPaymentsSyncRequest {
    pub data: ZaakPayCheckDataRequest,
    pub checksum: String,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayCheckDataRequest {
    pub merchant_identifier: String,
    pub mode: String,
    pub order_detail: ZaakPayOrderDetailType,
    pub refund_detail: Option<ZaakPayRefundDetail>,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayRefundDetail {
    pub merchant_ref_id: String,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayOrderDetailType {
    pub order_id: String,
    pub amount: Option<String>,
}

// Refund sync request
#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayRefundSyncRequest {
    pub data: ZaakPayCheckDataRequest,
    pub checksum: String,
}

// Response types based on Haskell implementation

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ZaakPayPaymentsResponse {
    Success(ZaakPayTransactResponse),
    Error(ZaakPayErrorResponse),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayTransactResponse {
    pub order_detail: ZaakPayOrderDetailTransType,
    pub response_code: String,
    pub response_description: String,
    pub do_redirect: String,
    pub payment_instrument: Option<ZaakPayPaymentInstrumentResType>,
    pub payment_mode: Option<String>,
    pub post_url: Option<String>,
    pub bank_post_data: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayPaymentInstrumentResType {
    pub payment_mode: String,
    pub card: Option<ZaakPayCardResType>,
    pub netbanking: Option<ZaakPayNetBankingRespType>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayCardResType {
    pub card_token: Option<String>,
    pub card_scheme: Option<String>,
    pub first4: Option<String>,
    pub last4: Option<String>,
    pub bank: Option<String>,
    pub card_hash_id: Option<String>,
    pub payment_method: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayNetBankingRespType {
    pub bankid: String,
    pub bank_name: Option<String>,
}

// Sync response types
#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ZaakPayPaymentsSyncResponse {
    Success(ZaakPayCheckResponse),
    Error(ZaakPayErrorResponse),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayCheckResponse {
    pub merchant_identifier: String,
    pub orders: Vec<ZaakPayOrderDetailsResponse>,
    pub version: String,
    pub success: Option<bool>,
    pub checksum: Option<String>,
    pub partial_refund_amt: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayOrderDetailsResponse {
    pub order_detail: Option<ZaakPayOrderDetailResType>,
    pub paymentinstrument: Option<ZaakPayPaymentinstrumentType>,
    pub response_code: String,
    pub response_description: String,
    pub txn_status: Option<String>,
    pub txn_date: Option<String>,
    pub user_account_debited: Option<bool>,
    pub partial_refund_amt: Option<String>,
    pub refund_details: Option<Vec<ZaakPayRefundDetails>>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayRefundDetails {
    pub amount: String,
    pub arn: Option<String>,
    pub merchant_ref_id: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayOrderDetailResType {
    pub order_id: String,
    pub txnid: Option<String>,
    pub amount: Option<String>,
    pub product_description: Option<String>,
    pub create_date: Option<String>,
    pub product1_description: Option<String>,
    pub product2_description: Option<String>,
    pub product3_description: Option<String>,
    pub product4_description: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayPaymentinstrumentType {
    pub payment_mode: Option<String>,
    pub card: Option<ZaakPayCardType>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayCardType {
    pub card_token: String,
    pub card_id: String,
    pub card_scheme: String,
    pub bank: String,
    pub card_hash_id: String,
    pub payment_method: String,
    pub first4: String,
    pub last4: String,
}

// Refund sync response
#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ZaakPayRefundSyncResponse {
    Success(ZaakPayCheckResponse),
    Error(ZaakPayErrorResponse),
}

// Error response
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayErrorResponse {
    pub response_code: String,
    pub response_description: String,
}

// Authentication types
#[derive(Default, Debug, Deserialize)]
pub struct ZaakPayAuthType {
    pub api_key: Secret<String>,
    pub merchant_identifier: String,
}

#[derive(Default, Debug, Deserialize)]
pub struct ZaakPayAuth {
    pub api_key: Secret<String>,
    pub merchant_identifier: String,
}

impl TryFrom<&ConnectorAuthType> for ZaakPayAuth {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey { api_key, .. } => {
                let auth = api_key
                    .to_owned()
                    .parse_value::<ZaakPayAuthType>("ZaakPayAuthType")
                    .change_context(errors::ConnectorError::InvalidDataFormat {
                        field_name: "auth_key",
                    })?;

                Ok(Self {
                    api_key: auth.api_key,
                    merchant_identifier: auth.merchant_identifier,
                })
            }
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

// Status mapping
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ZaakPayTransactionStatus {
    #[default]
    Pending,
    Success,
    Failure,
    Processing,
    Refunded,
    PartialRefunded,
}

impl From<ZaakPayTransactionStatus> for common_enums::AttemptStatus {
    fn from(item: ZaakPayTransactionStatus) -> Self {
        match item {
            ZaakPayTransactionStatus::Success => Self::Charged,
            ZaakPayTransactionStatus::Failure => Self::Failure,
            ZaakPayTransactionStatus::Pending | ZaakPayTransactionStatus::Processing => {
                Self::AuthenticationPending
            }
            ZaakPayTransactionStatus::Refunded => Self::AutoRefunded,
            ZaakPayTransactionStatus::PartialRefunded => Self::PartialAutoRefunded,
        }
    }
}

// Helper function to get authentication data
fn get_zaakpay_auth(
    connector_auth_type: &ConnectorAuthType,
) -> Result<ZaakPayAuth, errors::ConnectorError> {
    ZaakPayAuth::try_from(connector_auth_type)
        .change_context(errors::ConnectorError::FailedToObtainAuthType)
}

// Helper function to generate checksum (placeholder - actual implementation would use ZaakPay's algorithm)
fn generate_checksum(data: &str, secret: &str) -> String {
    // This is a placeholder - actual implementation should use ZaakPay's checksum algorithm
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(format!("{}{}", data, secret));
    format!("{:x}", hasher.finalize())
}

// Implement TryFrom for Authorize request
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        ZaakPayRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for ZaakPayPaymentsRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ZaakPayRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = get_zaakpay_auth(&item.router_data.connector_auth_type)?;
        let customer_id = item.router_data.resource_common_data.get_customer_id()?;
        let return_url = item.router_data.request.get_router_return_url()?;
        
        // Extract amount using the amount converter
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        // Build order details
        let order_detail = ZaakPayOrderDetailTransType {
            order_id: item
                .router_data
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            amount: amount.clone(),
            currency: item.router_data.request.currency.to_string(),
            product_description: item
                .router_data
                .request
                .description
                .clone()
                .unwrap_or_else(|| "Payment".to_string()),
            email: item
                .router_data
                .request
                .email
                .clone()
                .map(|e| e.to_string())
                .unwrap_or_else(|| format!("{}@example.com", customer_id)),
            phone: item
                .router_data
                .request
                .phone
                .clone()
                .map(|p| p.to_string())
                .unwrap_or_else(|| "0000000000".to_string()),
        };

        // Build billing address (using default values for now)
        let billing_address = ZaakPayBillingAddressType {
            address: "Default Address".to_string(),
            city: "Default City".to_string(),
            state: "Default State".to_string(),
            country: "IN".to_string(),
            pincode: Secret::new("000000".to_string()),
        };

        // Build payment instrument based on payment method type
        let payment_instrument = match item.router_data.request.payment_method_type {
            Some(common_enums::PaymentMethodType::Upi) => {
                ZaakPayPaymentInstrumentTransType {
                    payment_mode: "upi".to_string(),
                    card: None,
                    netbanking: None,
                    upi: Some(ZaakPayUpiTransType {
                        bankid: "default".to_string(),
                    }),
                }
            }
            Some(common_enums::PaymentMethodType::Netbanking) => {
                ZaakPayPaymentInstrumentTransType {
                    payment_mode: "netbanking".to_string(),
                    card: None,
                    netbanking: Some(ZaakPayNetTransType {
                        bankid: "default".to_string(),
                        bank_name: "Default Bank".to_string(),
                    }),
                    upi: None,
                }
            }
            _ => {
                return Err(errors::ConnectorError::NotImplemented(
                    "Payment method not supported".to_string(),
                )
                .into());
            }
        };

        // Build data object
        let data = ZaakPayTransactDataRequest {
            merchant_identifier: auth.merchant_identifier,
            encryption_key_id: None,
            show_mobile: None,
            mode: if item.router_data.resource_common_data.test_mode.unwrap_or(false) {
                "0".to_string() // Test mode
            } else {
                "1".to_string() // Live mode
            },
            return_url,
            order_detail,
            billing_address,
            shipping_address: None,
            payment_instrument,
        };

        // Generate checksum (placeholder)
        let data_str = serde_json::to_string(&data)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;
        let checksum = generate_checksum(&data_str, &auth.api_key.peek());

        Ok(Self { data, checksum })
    }
}

// Implement TryFrom for PSync request
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > TryFrom<ZaakPayRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>>
    for ZaakPayPaymentsSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ZaakPayRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let auth = get_zaakpay_auth(&item.router_data.connector_auth_type)?;
        
        // Extract amount using the amount converter
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        let order_detail = ZaakPayOrderDetailType {
            order_id: item
                .router_data
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            amount: Some(amount),
        };

        let data = ZaakPayCheckDataRequest {
            merchant_identifier: auth.merchant_identifier,
            mode: if item.router_data.resource_common_data.test_mode.unwrap_or(false) {
                "0".to_string()
            } else {
                "1".to_string()
            },
            order_detail,
            refund_detail: None,
        };

        // Generate checksum
        let data_str = serde_json::to_string(&data)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;
        let checksum = generate_checksum(&data_str, &auth.api_key.peek());

        Ok(Self { data, checksum })
    }
}

// Implement TryFrom for RSync request
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > TryFrom<ZaakPayRouterData<RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>, T>>
    for ZaakPayRefundSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ZaakPayRouterData<RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let auth = get_zaakpay_auth(&item.router_data.connector_auth_type)?;

        // For RSync, we don't have amount in the request, use None
        let order_detail = ZaakPayOrderDetailType {
            order_id: item
                .router_data
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            amount: None,
        };

        let refund_detail = ZaakPayRefundDetail {
            merchant_ref_id: item
                .router_data
                .resource_common_data
                .connector_request_reference_id
                .clone(),
        };

        let data = ZaakPayCheckDataRequest {
            merchant_identifier: auth.merchant_identifier,
            mode: "1".to_string(), // Default to live mode for sync
            order_detail,
            refund_detail: Some(refund_detail),
        };

        // Generate checksum
        let data_str = serde_json::to_string(&data)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;
        let checksum = generate_checksum(&data_str, &auth.api_key.peek());

        Ok(Self { data, checksum })
    }
}

// Response transformation for Authorize
impl<
        F,
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize
            + Serialize,
    > TryFrom<ResponseRouterData<ZaakPayPaymentsResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<ZaakPayPaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let (status, response) = match response {
            ZaakPayPaymentsResponse::Success(response_data) => {
                let redirection_data = if response_data.do_redirect == "true" {
                    Some(Box::new(RedirectForm::Form {
                        endpoint: response_data.post_url.unwrap_or_default(),
                        method: Method::Post,
                        form_fields: response_data
                            .bank_post_data
                            .unwrap_or_default()
                            .into_iter()
                            .map(|(k, v)| (k, v.to_string()))
                            .collect(),
                    }))
                } else {
                    None
                };

                (
                    common_enums::AttemptStatus::AuthenticationPending,
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: domain_types::connector_types::ResponseId::ConnectorTransactionId(
                            router_data
                                .resource_common_data
                                .connector_request_reference_id
                                .clone(),
                        ),
                        redirection_data,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: None,
                        connector_response_reference_id: None,
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                    }),
                )
            }
            ZaakPayPaymentsResponse::Error(error_data) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: error_data.response_code.to_string(),
                    status_code: item.http_code,
                    message: error_data.response_description.clone(),
                    reason: Some(error_data.response_description),
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }),
            ),
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            response,
            ..router_data
        })
    }
}

// Response transformation for PSync
impl<
        F,
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize
            + Serialize,
    > TryFrom<ResponseRouterData<ZaakPayPaymentsSyncResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<ZaakPayPaymentsSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let (status, response) = match response {
            ZaakPayPaymentsSyncResponse::Success(response_data) => {
                // Get the first order's status
                let order_status = response_data
                    .orders
                    .first()
                    .and_then(|order| order.txn_status.clone())
                    .unwrap_or_else(|| "pending".to_string());

                let status = match order_status.as_str() {
                    "success" => common_enums::AttemptStatus::Charged,
                    "failure" => common_enums::AttemptStatus::Failure,
                    "pending" | "processing" => common_enums::AttemptStatus::AuthenticationPending,
                    "refunded" => common_enums::AttemptStatus::AutoRefunded,
                    _ => common_enums::AttemptStatus::AuthenticationPending,
                };

                (
                    status,
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: domain_types::connector_types::ResponseId::ConnectorTransactionId(
                            router_data
                                .resource_common_data
                                .connector_request_reference_id
                                .clone(),
                        ),
                        redirection_data: None,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: response_data
                            .orders
                            .first()
                            .and_then(|order| order.order_detail.as_ref())
                            .and_then(|detail| detail.txnid.clone()),
                        connector_response_reference_id: None,
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                    }),
                )
            }
            ZaakPayPaymentsSyncResponse::Error(error_data) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: error_data.response_code.to_string(),
                    status_code: item.http_code,
                    message: error_data.response_description.clone(),
                    reason: Some(error_data.response_description),
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }),
            ),
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            response,
            ..router_data
        })
    }
}

// Response transformation for RSync
impl<
        F,
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize
            + Serialize,
    > TryFrom<ResponseRouterData<ZaakPayRefundSyncResponse, Self>>
    for RouterDataV2<F, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<ZaakPayRefundSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let (status, response) = match response {
            ZaakPayRefundSyncResponse::Success(response_data) => {
                // Get the first order's refund status
                let refund_status = response_data
                    .orders
                    .first()
                    .and_then(|order| order.refund_details.as_ref())
                    .and_then(|refunds| refunds.first())
                    .map(|_| "success");

                let status = match refund_status {
                    Some("success") => common_enums::RefundStatus::RefundSuccess,
                    _ => common_enums::RefundStatus::RefundFailure,
                };

                (
                    status,
                    Ok(RefundsResponseData {
                        connector_refund_id: router_data
                            .resource_common_data
                            .connector_request_reference_id
                            .clone(),
                        refund_status: status,
                        status_code: http_code,
                    }),
                )
            }
            ZaakPayRefundSyncResponse::Error(error_data) => (
                common_enums::RefundStatus::RefundFailure,
                Err(ErrorResponse {
                    code: error_data.response_code.to_string(),
                    status_code: item.http_code,
                    message: error_data.response_description.clone(),
                    reason: Some(error_data.response_description),
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }),
            ),
        };

        Ok(Self {
            resource_common_data: RefundFlowData {
                status,
                ..router_data.resource_common_data
            },
            response,
            ..router_data
        })
    }
}