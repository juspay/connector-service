use std::collections::HashMap;

use common_utils::{
    errors::CustomResult,
    ext_traits::ValueExt,
    request::Method,
    types::StringMinorUnit,
    Email,
};
use domain_types::{
    connector_flow::{Authorize, PSync, RSync},
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsResponseData, ResponseId},
    errors::{self, ConnectorError},
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
    utils,
};
use error_stack::ResultExt;
use hyperswitch_masking::{PeekInterface, Secret};
use serde::{Deserialize, Serialize};

use crate::{connectors::zaakpay::ZaakPayRouterData, types::ResponseRouterData};

// Request types based on Haskell implementation
#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayPaymentsRequest {
    #[serde(rename = "_data")]
    pub data: TransactDataRequest,
    pub checksum: String,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactDataRequest {
    pub merchant_identifier: String,
    pub encryption_key_id: Option<String>,
    pub show_mobile: Option<String>,
    pub mode: String,
    pub return_url: String,
    pub order_detail: OrderDetailTransType,
    pub billing_address: BillingAddressType,
    pub shipping_address: Option<ShippingAddressType>,
    pub payment_instrument: PaymentInstrumentTransType,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrderDetailTransType {
    pub order_id: String,
    pub amount: String,
    pub currency: String,
    pub product_description: String,
    pub email: Option<Email>,
    pub phone: Option<String>,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BillingAddressType {
    pub address: String,
    pub city: String,
    pub state: String,
    pub country: String,
    pub pincode: Secret<String>,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ShippingAddressType {
    pub address: Option<String>,
    pub city: Option<String>,
    pub state: Option<String>,
    pub country: Option<String>,
    pub pincode: Option<Secret<String>>,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentInstrumentTransType {
    pub payment_mode: String,
    pub card: Option<CardTransType>,
    pub netbanking: Option<NetTransType>,
    pub upi: Option<UpiTransType>,
}

#[derive(Default, Debug, Serialize)]
pub struct CardTransType;

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetTransType {
    pub bankid: String,
    pub bank_name: String,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpiTransType {
    pub bankid: String,
}

// Response types based on Haskell implementation
#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ZaakPayPaymentsResponse {
    ZaakPayError(ZaakPayErrorResponse),
    ZaakPayData(ZaakPayPaymentsResponseData),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayPaymentsResponseData {
    pub order_detail: OrderDetailTransType,
    pub response_code: String,
    pub response_description: String,
    pub do_redirect: String,
    pub payment_instrument: Option<PaymentInstrumentResType>,
    pub payment_mode: Option<String>,
    pub post_url: Option<String>,
    pub bank_post_data: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentInstrumentResType {
    pub payment_mode: String,
    pub card: Option<CardResType>,
    pub netbanking: Option<NetBankingRespType>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CardResType {
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
pub struct NetBankingRespType {
    pub bankid: String,
    pub bank_name: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ZaakPayErrorResponse {
    pub response_code: String,
    pub response_description: String,
}

// PSync request/response types
#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayPaymentsSyncRequest {
    #[serde(rename = "_data")]
    pub data: CheckDataRequest,
    pub checksum: String,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckDataRequest {
    pub merchant_identifier: String,
    pub mode: String,
    pub order_detail: OrderDetailType,
    pub refund_detail: Option<RefundDetail>,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrderDetailType {
    pub order_id: String,
    pub amount: Option<String>,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RefundDetail {
    pub merchant_ref_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayPaymentsSyncResponse {
    pub merchant_identifier: String,
    pub orders: Vec<OrderDetailsResponse>,
    pub version: String,
    pub success: Option<bool>,
    pub checksum: Option<String>,
    pub partial_refund_amt: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrderDetailsResponse {
    pub order_detail: Option<OrderDetailResType>,
    pub paymentinstrument: Option<PaymentinstrumentType>,
    pub response_code: String,
    pub response_description: String,
    pub txn_status: Option<String>,
    pub txn_date: Option<String>,
    pub user_account_debited: Option<bool>,
    pub partial_refund_amt: Option<String>,
    pub refund_details: Option<Vec<RefundDetails>>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrderDetailResType {
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
pub struct PaymentinstrumentType {
    pub payment_mode: Option<String>,
    pub card: Option<CardType>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CardType {
    pub card_token: String,
    pub card_id: String,
    pub card_scheme: String,
    pub bank: String,
    pub card_hash_id: String,
    pub payment_method: String,
    pub first4: String,
    pub last4: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RefundDetails {
    pub amount: String,
    pub arn: Option<String>,
    pub merchant_ref_id: Option<String>,
}

// RSync request/response types
#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayRefundSyncRequest {
    #[serde(rename = "_data")]
    pub data: CheckDataRequest,
    pub checksum: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayRefundSyncResponse {
    pub merchant_identifier: String,
    pub orders: Vec<OrderDetailsResponse>,
    pub version: String,
    pub success: Option<bool>,
    pub checksum: Option<String>,
    pub partial_refund_amt: Option<String>,
}

// Stub types for unsupported flows
#[derive(Debug, Clone, Serialize)]
pub struct ZaakPayVoidRequest;
#[derive(Debug, Clone)]
pub struct ZaakPayVoidResponse;

#[derive(Debug, Clone, Serialize)]
pub struct ZaakPayCaptureRequest;
#[derive(Debug, Clone)]
pub struct ZaakPayCaptureResponse;

#[derive(Debug, Clone, Serialize)]
pub struct ZaakPayRefundRequest;
#[derive(Debug, Clone)]
pub struct ZaakPayRefundResponse;

#[derive(Debug, Clone, Serialize)]
pub struct ZaakPayCreateOrderRequest;
#[derive(Debug, Clone)]
pub struct ZaakPayCreateOrderResponse;

#[derive(Debug, Clone, Serialize)]
pub struct ZaakPaySessionTokenRequest;
#[derive(Debug, Clone)]
pub struct ZaakPaySessionTokenResponse;

#[derive(Debug, Clone, Serialize)]
pub struct ZaakPaySetupMandateRequest;
#[derive(Debug, Clone)]
pub struct ZaakPaySetupMandateResponse;

#[derive(Debug, Clone, Serialize)]
pub struct ZaakPayRepeatPaymentRequest;
#[derive(Debug, Clone)]
pub struct ZaakPayRepeatPaymentResponse;

#[derive(Debug, Clone, Serialize)]
pub struct ZaakPayAcceptDisputeRequest;
#[derive(Debug, Clone)]
pub struct ZaakPayAcceptDisputeResponse;

#[derive(Debug, Clone, Serialize)]
pub struct ZaakPayDefendDisputeRequest;
#[derive(Debug, Clone)]
pub struct ZaakPayDefendDisputeResponse;

#[derive(Debug, Clone, Serialize)]
pub struct ZaakPaySubmitEvidenceRequest;
#[derive(Debug, Clone)]
pub struct ZaakPaySubmitEvidenceResponse;

// Authentication types
#[derive(Default, Debug, Deserialize)]
pub struct ZaakPayAuthType {
    pub merchant_identifier: Secret<String>,
    pub secret_key: Secret<String>,
}

#[derive(Default, Debug, Deserialize)]
pub struct ZaakPayAuth {
    pub merchant_identifier: Secret<String>,
    pub secret_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for ZaakPayAuth {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey { api_key, .. } => {
                let auth: ZaakPayAuthType = api_key
                    .to_owned()
                    .parse_value("ZaakPayAuthType")
                    .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
                Ok(Self {
                    merchant_identifier: auth.merchant_identifier,
                    secret_key: auth.secret_key,
                })
            }
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ZaakPayPaymentStatus {
    Success,
    Failure,
    Pending,
    #[default]
    Processing,
}

impl From<ZaakPayPaymentStatus> for common_enums::AttemptStatus {
    fn from(item: ZaakPayPaymentStatus) -> Self {
        match item {
            ZaakPayPaymentStatus::Success => Self::Charged,
            ZaakPayPaymentStatus::Failure => Self::Failure,
            ZaakPayPaymentStatus::Pending => Self::AuthenticationPending,
            ZaakPayPaymentStatus::Processing => Self::Pending,
        }
    }
}

fn get_checksum(data: &str, secret_key: &str) -> String {
    // Implement checksum calculation based on ZaakPay's algorithm
    // This is a placeholder - actual implementation would use SHA256 or similar
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(format!("{}{}", data, secret_key));
    format!("{:x}", hasher.finalize())
}

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
        let customer_id = item.router_data.resource_common_data.get_customer_id()?;
        let return_url = item.router_data.request.get_router_return_url()?;
        let auth_type = ZaakPayAuth::try_from(&item.router_data.connector_auth_type)?;
        
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        // Only support UPI payments as per requirements
        match item.router_data.resource_common_data.payment_method {
            common_enums::PaymentMethod::Upi => {
                let order_detail = OrderDetailTransType {
                    order_id: item
                        .router_data
                        .resource_common_data
                        .connector_request_reference_id
                        .clone(),
                    amount,
                    currency: item.router_data.request.currency.to_string(),
                    product_description: item
                        .router_data
                        .request
                        .description
                        .clone()
                        .unwrap_or_else(|| "Payment".to_string()),
                    email: item.router_data.request.email.clone(),
                    phone: item.router_data.request.phone_number.clone().map(|p| p.to_string()),
                };

                let billing_address = BillingAddressType {
                    address: item
                        .router_data
                        .request
                        .billing_address
                        .as_ref()
                        .map(|addr| addr.address.to_string())
                        .unwrap_or_else(|| "N/A".to_string()),
                    city: item
                        .router_data
                        .request
                        .billing_address
                        .as_ref()
                        .and_then(|addr| addr.city.clone())
                        .unwrap_or_else(|| "N/A".to_string()),
                    state: item
                        .router_data
                        .request
                        .billing_address
                        .as_ref()
                        .and_then(|addr| addr.state.clone())
                        .unwrap_or_else(|| "N/A".to_string()),
                    country: item
                        .router_data
                        .request
                        .billing_address
                        .as_ref()
                        .and_then(|addr| addr.country.clone())
                        .map(|c| c.to_string())
                        .unwrap_or_else(|| "IN".to_string()),
                    pincode: Secret::new(
                        item
                            .router_data
                            .request
                            .billing_address
                            .as_ref()
                            .and_then(|addr| addr.zip.clone())
                            .map(|z| z.to_string())
                            .unwrap_or_else(|| "000000".to_string()),
                    ),
                };

                let payment_instrument = PaymentInstrumentTransType {
                    payment_mode: "upi".to_string(),
                    card: None,
                    netbanking: None,
                    upi: Some(UpiTransType {
                        bankid: "default".to_string(), // UPI doesn't require specific bank ID
                    }),
                };

                let data = TransactDataRequest {
                    merchant_identifier: auth_type.merchant_identifier.peek().clone(),
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

                let data_json = serde_json::to_string(&data)
                    .change_context(errors::ConnectorError::RequestEncodingFailed)?;
                let checksum = get_checksum(&data_json, auth_type.secret_key.peek());

                Ok(Self { data, checksum })
            }
            _ => Err(errors::ConnectorError::NotImplemented(
                "Only UPI payments are supported".to_string(),
            )
            .into()),
        }
    }
}

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
            ZaakPayPaymentsResponse::ZaakPayError(error_data) => (
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
            ZaakPayPaymentsResponse::ZaakPayData(response_data) => {
                if response_data.do_redirect == "true" {
                    let redirection_data = RedirectForm::Form {
                        endpoint: response_data.post_url.unwrap_or_default(),
                        method: Method::Post,
                        form_fields: response_data
                            .bank_post_data
                            .unwrap_or_default()
                            .into_iter()
                            .map(|(k, v)| (k, v.to_string()))
                            .collect(),
                    };
                    (
                        common_enums::AttemptStatus::AuthenticationPending,
                        Ok(PaymentsResponseData::TransactionResponse {
                            resource_id: ResponseId::ConnectorTransactionId(
                                response_data.order_detail.order_id,
                            ),
                            redirection_data: Some(Box::new(redirection_data)),
                            mandate_reference: None,
                            connector_metadata: None,
                            network_txn_id: None,
                            connector_response_reference_id: None,
                            incremental_authorization_allowed: None,
                            status_code: http_code,
                        }),
                    )
                } else {
                    (
                        common_enums::AttemptStatus::Charged,
                        Ok(PaymentsResponseData::TransactionResponse {
                            resource_id: ResponseId::ConnectorTransactionId(
                                response_data.order_detail.order_id,
                            ),
                            redirection_data: None,
                            mandate_reference: None,
                            connector_metadata: None,
                            network_txn_id: None,
                            connector_response_reference_id: None,
                            incremental_authorization_allowed: None,
                            status_code: http_code,
                        }),
                    )
                }
            }
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

// PSync transformer implementation
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
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    > for ZaakPayPaymentsSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ZaakPayRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth_type = ZaakPayAuth::try_from(&item.router_data.connector_auth_type)?;
        
        let order_detail = OrderDetailType {
            order_id: item
                .router_data
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            amount: None, // Amount not required for status check
        };

        let data = CheckDataRequest {
            merchant_identifier: auth_type.merchant_identifier.peek().clone(),
            mode: if item.router_data.resource_common_data.test_mode.unwrap_or(false) {
                "0".to_string()
            } else {
                "1".to_string()
            },
            order_detail,
            refund_detail: None,
        };

        let data_json = serde_json::to_string(&data)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;
        let checksum = get_checksum(&data_json, auth_type.secret_key.peek());

        Ok(Self { data, checksum })
    }
}

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

        let order = response.orders.first().ok_or(errors::ConnectorError::MissingRequiredField {
            field_name: "orders",
        })?;

        let status = match order.txn_status.as_deref() {
            Some("success") => common_enums::AttemptStatus::Charged,
            Some("failure") => common_enums::AttemptStatus::Failure,
            Some("pending") => common_enums::AttemptStatus::Pending,
            _ => common_enums::AttemptStatus::AuthenticationPending,
        };

        let amount_received = order
            .order_detail
            .as_ref()
            .and_then(|od| od.amount.as_ref())
            .and_then(|amt| amt.parse::<i64>().ok())
            .map(common_utils::types::MinorUnit);

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    order
                        .order_detail
                        .as_ref()
                        .map(|od| od.order_id.clone())
                        .unwrap_or_default(),
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: order
                    .order_detail
                    .as_ref()
                    .and_then(|od| od.txnid.clone()),
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                status_code: http_code,
            }),
            ..router_data
        })
    }
}

// RSync transformer implementation
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
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    > for ZaakPayRefundSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ZaakPayRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth_type = ZaakPayAuth::try_from(&item.router_data.connector_auth_type)?;
        
        let order_detail = OrderDetailType {
            order_id: item
                .router_data
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            amount: None,
        };

        let refund_detail = RefundDetail {
            merchant_ref_id: item
                .router_data
                .request
                .connector_refund_id
                .get_connector_refund_id()
                .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?
                .to_string(),
        };

        let data = CheckDataRequest {
            merchant_identifier: auth_type.merchant_identifier.peek().clone(),
            mode: if item.router_data.resource_common_data.test_mode.unwrap_or(false) {
                "0".to_string()
            } else {
                "1".to_string()
            },
            order_detail,
            refund_detail: Some(refund_detail),
        };

        let data_json = serde_json::to_string(&data)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;
        let checksum = get_checksum(&data_json, auth_type.secret_key.peek());

        Ok(Self { data, checksum })
    }
}