use std::collections::HashMap;

use common_enums::{AttemptStatus, PaymentMethodType};
use common_utils::{
    errors::CustomResult,
    ext_traits::ValueExt,
    request::RequestContent,
    types::{self, MinorUnit},
};
use domain_types::{
    connector_flow::{Authorize, PSync, RSync},
    connector_types::{
        PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData,
        RefundFlowData, RefundSyncData, RefundsResponseData,
    },
    errors,
    payment_method_data::UpiData,
    router_data_v2::RouterDataV2,
    types::{self as domain_types},
};
use error_stack::ResultExt;
use hyperswitch_masking::Secret;
use masking::{ExposeInterface, Mask};
use serde::{Deserialize, Serialize};

use crate::{
    services,
    utils::{self, ConnectorCommonData},
    connectors::zaakpay::constants::*,
};

// Request types
#[derive(Debug, Serialize)]
pub struct ZaakPayPaymentsRequest {
    #[serde(rename = "_data")]
    pub data: ZaakPayTransactDataRequest,
    pub checksum: String,
}

#[derive(Debug, Serialize)]
pub struct ZaakPayTransactDataRequest {
    #[serde(rename = "merchantIdentifier")]
    pub merchant_identifier: String,
    #[serde(rename = "encryptionKeyId")]
    pub encryption_key_id: Option<String>,
    #[serde(rename = "showMobile")]
    pub show_mobile: Option<String>,
    pub mode: String,
    #[serde(rename = "returnUrl")]
    pub return_url: String,
    #[serde(rename = "orderDetail")]
    pub order_detail: ZaakPayOrderDetailTransType,
    #[serde(rename = "billingAddress")]
    pub billing_address: ZaakPayBillingAddressType,
    #[serde(rename = "shippingAddress")]
    pub shipping_address: Option<ZaakPayShippingAddressType>,
    #[serde(rename = "paymentInstrument")]
    pub payment_instrument: ZaakPayPaymentInstrumentTransType,
}

#[derive(Debug, Serialize)]
pub struct ZaakPayOrderDetailTransType {
    #[serde(rename = "orderId")]
    pub order_id: String,
    pub amount: String,
    pub currency: String,
    #[serde(rename = "productDescription")]
    pub product_description: String,
    pub email: String,
    pub phone: String,
}

#[derive(Debug, Serialize)]
pub struct ZaakPayBillingAddressType {
    pub address: String,
    pub city: String,
    pub state: String,
    pub country: String,
    pub pincode: Secret<String>,
}

#[derive(Debug, Serialize)]
pub struct ZaakPayShippingAddressType {
    pub address: Option<String>,
    pub city: Option<String>,
    pub state: Option<String>,
    pub country: Option<String>,
    pub pincode: Option<Secret<String>>,
}

#[derive(Debug, Serialize)]
pub struct ZaakPayPaymentInstrumentTransType {
    #[serde(rename = "paymentMode")]
    pub payment_mode: String,
    pub card: Option<ZaakPayCardTransType>,
    pub netbanking: Option<ZaakPayNetTransType>,
    pub upi: Option<ZaakPayUpiTransType>,
}

#[derive(Debug, Serialize)]
pub struct ZaakPayCardTransType;

#[derive(Debug, Serialize)]
pub struct ZaakPayNetTransType {
    #[serde(rename = "bankid")]
    pub bank_id: String,
    #[serde(rename = "bankName")]
    pub bank_name: String,
}

#[derive(Debug, Serialize)]
pub struct ZaakPayUpiTransType {
    #[serde(rename = "bankid")]
    pub bank_id: String,
}

// Sync request types
#[derive(Debug, Serialize)]
pub struct ZaakPayPaymentsSyncRequest {
    #[serde(rename = "_data")]
    pub data: ZaakPayCheckDataRequest,
    pub checksum: String,
}

#[derive(Debug, Serialize)]
pub struct ZaakPayCheckDataRequest {
    #[serde(rename = "merchantIdentifier")]
    pub merchant_identifier: String,
    pub mode: String,
    #[serde(rename = "orderDetail")]
    pub order_detail: ZaakPayOrderDetailType,
    #[serde(rename = "refundDetail")]
    pub refund_detail: Option<ZaakPayRefundDetail>,
}

#[derive(Debug, Serialize)]
pub struct ZaakPayRefundDetail {
    #[serde(rename = "merchantRefId")]
    pub merchant_ref_id: String,
}

#[derive(Debug, Serialize)]
pub struct ZaakPayOrderDetailType {
    #[serde(rename = "orderId")]
    pub order_id: String,
    pub amount: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ZaakPayRefundSyncRequest {
    #[serde(rename = "_data")]
    pub data: ZaakPayCheckDataRequest,
    pub checksum: String,
}

// Response types
#[derive(Debug, Deserialize)]
pub struct ZaakPayPaymentsResponse {
    #[serde(rename = "orderDetail")]
    pub order_detail: ZaakPayOrderDetailTransType,
    #[serde(rename = "responseCode")]
    pub response_code: String,
    #[serde(rename = "responseDescription")]
    pub response_description: String,
    #[serde(rename = "doRedirect")]
    pub do_redirect: String,
    #[serde(rename = "paymentInstrument")]
    pub payment_instrument: Option<ZaakPayPaymentInstrumentResType>,
    #[serde(rename = "paymentMode")]
    pub payment_mode: Option<String>,
    #[serde(rename = "postUrl")]
    pub post_url: Option<String>,
    #[serde(rename = "bankPostData")]
    pub bank_post_data: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Deserialize)]
pub struct ZaakPayPaymentInstrumentResType {
    #[serde(rename = "paymentMode")]
    pub payment_mode: String,
    pub card: Option<ZaakPayCardResType>,
    pub netbanking: Option<ZaakPayNetBankingRespType>,
}

#[derive(Debug, Deserialize)]
pub struct ZaakPayCardResType {
    #[serde(rename = "cardToken")]
    pub card_token: Option<String>,
    #[serde(rename = "cardScheme")]
    pub card_scheme: Option<String>,
    #[serde(rename = "first4")]
    pub first4: Option<String>,
    #[serde(rename = "last4")]
    pub last4: Option<String>,
    pub bank: Option<String>,
    #[serde(rename = "cardHashId")]
    pub card_hash_id: Option<String>,
    #[serde(rename = "paymentMethod")]
    pub payment_method: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ZaakPayNetBankingRespType {
    #[serde(rename = "bankid")]
    pub bank_id: String,
    #[serde(rename = "bankName")]
    pub bank_name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ZaakPayPaymentsSyncResponse {
    #[serde(rename = "merchantIdentifier")]
    pub merchant_identifier: String,
    pub orders: Vec<ZaakPayOrderDetailsResponse>,
    pub version: String,
    pub success: Option<bool>,
    pub checksum: Option<String>,
    #[serde(rename = "partialRefundAmt")]
    pub partial_refund_amt: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ZaakPayOrderDetailsResponse {
    #[serde(rename = "orderDetail")]
    pub order_detail: Option<ZaakPayOrderDetailResType>,
    pub paymentinstrument: Option<ZaakPayPaymentinstrumentType>,
    #[serde(rename = "responseCode")]
    pub response_code: String,
    #[serde(rename = "responseDescription")]
    pub response_description: String,
    #[serde(rename = "txnStatus")]
    pub txn_status: Option<String>,
    #[serde(rename = "txnDate")]
    pub txn_date: Option<String>,
    #[serde(rename = "userAccountDebited")]
    pub user_account_debited: Option<bool>,
    #[serde(rename = "partialRefundAmt")]
    pub partial_refund_amt: Option<String>,
    #[serde(rename = "refundDetails")]
    pub refund_details: Option<Vec<ZaakPayRefundDetails>>,
}

#[derive(Debug, Deserialize)]
pub struct ZaakPayRefundDetails {
    pub amount: String,
    pub arn: Option<String>,
    #[serde(rename = "merchantRefId")]
    pub merchant_ref_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ZaakPayOrderDetailResType {
    #[serde(rename = "orderId")]
    pub order_id: String,
    #[serde(rename = "txnid")]
    pub txn_id: Option<String>,
    pub amount: Option<String>,
    #[serde(rename = "productDescription")]
    pub product_description: Option<String>,
    #[serde(rename = "createDate")]
    pub create_date: Option<String>,
    #[serde(rename = "product1Description")]
    pub product1_description: Option<String>,
    #[serde(rename = "product2Description")]
    pub product2_description: Option<String>,
    #[serde(rename = "product3Description")]
    pub product3_description: Option<String>,
    #[serde(rename = "product4Description")]
    pub product4_description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ZaakPayPaymentinstrumentType {
    #[serde(rename = "paymentMode")]
    pub payment_mode: Option<String>,
    pub card: Option<ZaakPayCardType>,
}

#[derive(Debug, Deserialize)]
pub struct ZaakPayCardType {
    #[serde(rename = "cardToken")]
    pub card_token: String,
    #[serde(rename = "cardId")]
    pub card_id: String,
    #[serde(rename = "cardScheme")]
    pub card_scheme: String,
    pub bank: String,
    #[serde(rename = "cardHashId")]
    pub card_hash_id: String,
    #[serde(rename = "paymentMethod")]
    pub payment_method: String,
    #[serde(rename = "first4")]
    pub first4: String,
    #[serde(rename = "last4")]
    pub last4: String,
}

#[derive(Debug, Deserialize)]
pub struct ZaakPayRefundSyncResponse {
    #[serde(rename = "merchantIdentifier")]
    pub merchant_identifier: String,
    pub orders: Vec<ZaakPayOrderDetailsResponse>,
    pub version: String,
    pub success: Option<bool>,
    pub checksum: Option<String>,
    #[serde(rename = "partialRefundAmt")]
    pub partial_refund_amt: Option<String>,
}

// Transformer implementations
impl<T> TryFrom<&RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>
    for ZaakPayPaymentsRequest
where
    T: domain_types::payment_method_data::PaymentMethodDataTypes,
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        // Extract merchant identifier from auth
        let merchant_identifier = match &item.router_data.connector_auth_type {
            domain_types::connector_types::ConnectorAuthType::SignatureKey(auth) => {
                auth.api_key.clone()
            }
            domain_types::connector_types::ConnectorAuthType::HeaderKey(auth) => {
                auth.api_key.clone()
            }
            domain_types::connector_types::ConnectorAuthType::BodyKey(auth) => {
                auth.api_key.clone()
            }
            _ => {
                return Err(errors::ConnectorError::MissingRequiredField {
                    field_name: "merchant_identifier",
                }
                .into());
            }
        };

        // Extract amount using amount converter
        let amount = item.amount.get_amount_as_string();
        let currency = item.router_data.request.currency.to_string();

        // Extract customer details
        let customer_id = item
            .router_data
            .resource_common_data
            .get_customer_id()
            .change_context(errors::ConnectorError::MissingRequiredField {
                field_name: "customer_id",
            })?;
        let customer_id_string = customer_id.get_string_repr();

        // Extract email and phone
        let email = item
            .router_data
            .request
            .email
            .clone()
            .unwrap_or_else(|| format!("{}@example.com", customer_id_string));
        let phone = item
            .router_data
            .request
            .phone
            .clone()
            .unwrap_or_else(|| "9999999999".to_string());

        // Extract return URL
        let return_url = item
            .router_data
            .request
            .get_router_return_url()
            .change_context(errors::ConnectorError::MissingRequiredField {
                field_name: "return_url",
            })?;

        // Determine mode (test/live)
        let mode = if item.router_data.resource_common_data.test_mode.unwrap_or(false) {
            "0"
        } else {
            "1"
        };

        // Create order detail
        let order_detail = ZaakPayOrderDetailTransType {
            order_id: item
                .router_data
                .request
                .connector_transaction_id
                .get_connector_transaction_id()
                .change_context(errors::ConnectorError::MissingRequiredField {
                    field_name: "connector_transaction_id",
                })?,
            amount,
            currency,
            product_description: item
                .router_data
                .request
                .description
                .clone()
                .unwrap_or_else(|| "Payment".to_string()),
            email,
            phone,
        };

        // Create billing address (using default values if not provided)
        let billing_address = ZaakPayBillingAddressType {
            address: item
                .router_data
                .request
                .billing_address
                .as_ref()
                .and_then(|addr| addr.address.clone())
                .unwrap_or_else(|| "Default Address".to_string()),
            city: item
                .router_data
                .request
                .billing_address
                .as_ref()
                .and_then(|addr| addr.city.clone())
                .unwrap_or_else(|| "Default City".to_string()),
            state: item
                .router_data
                .request
                .billing_address
                .as_ref()
                .and_then(|addr| addr.state.clone())
                .unwrap_or_else(|| "Default State".to_string()),
            country: item
                .router_data
                .request
                .billing_address
                .as_ref()
                .and_then(|addr| addr.country.clone())
                .map(|c| c.to_string())
                .unwrap_or_else(|| "IN".to_string()),
            pincode: Secret::new(
                item.router_data
                    .request
                    .billing_address
                    .as_ref()
                    .and_then(|addr| addr.zip.clone())
                    .unwrap_or_else(|| "110001".to_string()),
            ),
        };

        // Create shipping address (optional)
        let shipping_address = item
            .router_data
            .request
            .shipping_address
            .as_ref()
            .map(|addr| ZaakPayShippingAddressType {
                address: addr.address.clone(),
                city: addr.city.clone(),
                state: addr.state.clone(),
                country: addr.country.clone().map(|c| c.to_string()),
                pincode: addr.zip.clone().map(Secret::new),
            });

        // Create payment instrument based on payment method type
        let payment_instrument = match item.router_data.request.payment_method_type {
            PaymentMethodType::Upi => {
                let upi_data = item
                    .router_data
                    .request
                    .payment_method_data
                    .get_upi_data()
                    .change_context(errors::ConnectorError::MissingRequiredField {
                        field_name: "upi_data",
                    })?;

                ZaakPayPaymentInstrumentTransType {
                    payment_mode: "upi".to_string(),
                    card: None,
                    netbanking: None,
                    upi: Some(ZaakPayUpiTransType {
                        bank_id: upi_data
                            .vpa
                            .clone()
                            .unwrap_or_else(|| "default@upi".to_string()),
                    }),
                }
            }
            _ => {
                return Err(errors::ConnectorError::NotImplemented(format!(
                    "Payment method {:?} not supported",
                    item.router_data.request.payment_method_type
                ))
                .into());
            }
        };

        // Create transact data request
        let transact_data = ZaakPayTransactDataRequest {
            merchant_identifier,
            encryption_key_id: None,
            show_mobile: None,
            mode: mode.to_string(),
            return_url,
            order_detail,
            billing_address,
            shipping_address,
            payment_instrument,
        };

        // Generate checksum (simplified - in real implementation, this would use proper crypto)
        let data_string = serde_json::to_string(&transact_data)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;
        let checksum = format!("checksum_{}", data_string.len());

        Ok(Self {
            data: transact_data,
            checksum,
        })
    }
}

impl<T> TryFrom<ZaakPayPaymentsResponse> for PaymentsResponseData {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(response: ZaakPayPaymentsResponse) -> Result<Self, Self::Error> {
        let status = match response.response_code.as_str() {
            "100" => AttemptStatus::AuthenticationFailed,
            "101" => AttemptStatus::Failure,
            "102" => AttemptStatus::Failure,
            "103" => AttemptStatus::Failure,
            "200" => AttemptStatus::Charged,
            "201" => AttemptStatus::Pending,
            "202" => AttemptStatus::Pending,
            _ => AttemptStatus::Pending,
        };

        let amount_received = response.order_detail.amount.parse::<f64>()
            .ok()
            .map(|amt| MinorUnit::from_major_unit_as_i64(amt));

        Ok(Self {
            status,
            response: Ok(services::Response {
                status_code: 200,
                response_body: serde_json::to_value(response)
                    .change_context(errors::ConnectorError::ResponseDeserializationFailed)?,
                headers: HashMap::new(),
            }),
            amount_captured: amount_received,
            connector_transaction_id: Some(response.order_detail.order_id),
            ..Default::default()
        })
    }
}

impl<T> TryFrom<&RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>
    for ZaakPayPaymentsSyncRequest
where
    T: domain_types::payment_method_data::PaymentMethodDataTypes,
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        // Extract merchant identifier from auth
        let merchant_identifier = match &item.router_data.connector_auth_type {
            domain_types::connector_types::ConnectorAuthType::SignatureKey(auth) => {
                auth.api_key.clone()
            }
            domain_types::connector_types::ConnectorAuthType::HeaderKey(auth) => {
                auth.api_key.clone()
            }
            domain_types::connector_types::ConnectorAuthType::BodyKey(auth) => {
                auth.api_key.clone()
            }
            _ => {
                return Err(errors::ConnectorError::MissingRequiredField {
                    field_name: "merchant_identifier",
                }
                .into());
            }
        };

        // Extract amount using amount converter
        let amount = item.amount.get_amount_as_string();

        // Determine mode (test/live)
        let mode = if item.router_data.resource_common_data.test_mode.unwrap_or(false) {
            "0"
        } else {
            "1"
        };

        // Create order detail
        let order_detail = ZaakPayOrderDetailType {
            order_id: item
                .router_data
                .request
                .connector_transaction_id
                .get_connector_transaction_id()
                .change_context(errors::ConnectorError::MissingRequiredField {
                    field_name: "connector_transaction_id",
                })?,
            amount: Some(amount),
        };

        // Create check data request
        let check_data = ZaakPayCheckDataRequest {
            merchant_identifier,
            mode: mode.to_string(),
            order_detail,
            refund_detail: None,
        };

        // Generate checksum (simplified)
        let data_string = serde_json::to_string(&check_data)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;
        let checksum = format!("checksum_{}", data_string.len());

        Ok(Self {
            data: check_data,
            checksum,
        })
    }
}

impl<T> TryFrom<ZaakPayPaymentsSyncResponse> for PaymentsResponseData {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(response: ZaakPayPaymentsSyncResponse) -> Result<Self, Self::Error> {
        // Get the first order from the response
        let order = response.orders.first().ok_or_else(|| {
            errors::ConnectorError::ResponseDeserializationFailed
                .attach_printable("No orders found in response")
        })?;

        let status = match order.txn_status.as_deref() {
            Some("success") => AttemptStatus::Charged,
            Some("pending") => AttemptStatus::Pending,
            Some("failure") => AttemptStatus::Failure,
            _ => AttemptStatus::Pending,
        };

        let amount_received = order
            .order_detail
            .as_ref()
            .and_then(|od| od.amount.as_ref())
            .and_then(|amt| amt.parse::<f64>().ok())
            .map(|amt| MinorUnit::from_major_unit_as_i64(amt));

        let connector_transaction_id = order
            .order_detail
            .as_ref()
            .map(|od| od.order_id.clone());

        Ok(Self {
            status,
            response: Ok(services::Response {
                status_code: 200,
                response_body: serde_json::to_value(response)
                    .change_context(errors::ConnectorError::ResponseDeserializationFailed)?,
                headers: HashMap::new(),
            }),
            amount_captured: amount_received,
            connector_transaction_id,
            ..Default::default()
        })
    }
}

impl<T> TryFrom<&RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>>
    for ZaakPayRefundSyncRequest
where
    T: domain_types::payment_method_data::PaymentMethodDataTypes,
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
    ) -> Result<Self, Self::Error> {
        // Extract merchant identifier from auth
        let merchant_identifier = match &item.router_data.connector_auth_type {
            domain_types::connector_types::ConnectorAuthType::SignatureKey(auth) => {
                auth.api_key.clone()
            }
            domain_types::connector_types::ConnectorAuthType::HeaderKey(auth) => {
                auth.api_key.clone()
            }
            domain_types::connector_types::ConnectorAuthType::BodyKey(auth) => {
                auth.api_key.clone()
            }
            _ => {
                return Err(errors::ConnectorError::MissingRequiredField {
                    field_name: "merchant_identifier",
                }
                .into());
            }
        };

        // Extract amount using amount converter
        let amount = item.amount.get_amount_as_string();

        // Determine mode (test/live)
        let mode = if item.router_data.resource_common_data.test_mode.unwrap_or(false) {
            "0"
        } else {
            "1"
        };

        // Create order detail
        let order_detail = ZaakPayOrderDetailType {
            order_id: item
                .router_data
                .request
                .connector_transaction_id
                .get_connector_transaction_id()
                .change_context(errors::ConnectorError::MissingRequiredField {
                    field_name: "connector_transaction_id",
                })?,
            amount: Some(amount),
        };

        // Create refund detail if refund ID is available
        let refund_detail = item
            .router_data
            .request
            .refund_id
            .clone()
            .map(|refund_id| ZaakPayRefundDetail {
                merchant_ref_id: refund_id.get_string_repr(),
            });

        // Create check data request
        let check_data = ZaakPayCheckDataRequest {
            merchant_identifier,
            mode: mode.to_string(),
            order_detail,
            refund_detail,
        };

        // Generate checksum (simplified)
        let data_string = serde_json::to_string(&check_data)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;
        let checksum = format!("checksum_{}", data_string.len());

        Ok(Self {
            data: check_data,
            checksum,
        })
    }
}

impl<T> TryFrom<ZaakPayRefundSyncResponse> for RefundsResponseData {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(response: ZaakPayRefundSyncResponse) -> Result<Self, Self::Error> {
        // Get the first order from the response
        let order = response.orders.first().ok_or_else(|| {
            errors::ConnectorError::ResponseDeserializationFailed
                .attach_printable("No orders found in response")
        })?;

        // Check refund details
        let refund_status = if let Some(refund_details) = &order.refund_details {
            if !refund_details.is_empty() {
                match order.txn_status.as_deref() {
                    Some("success") => domain_types::RefundStatus::Success,
                    Some("pending") => domain_types::RefundStatus::Pending,
                    Some("failure") => domain_types::RefundStatus::Failure,
                    _ => domain_types::RefundStatus::Pending,
                }
            } else {
                domain_types::RefundStatus::Pending
            }
        } else {
            domain_types::RefundStatus::Pending
        };

        let refund_amount = order
            .refund_details
            .as_ref()
            .and_then(|details| details.first())
            .and_then(|detail| detail.amount.parse::<f64>().ok())
            .map(|amt| MinorUnit::from_major_unit_as_i64(amt));

        let connector_refund_id = order
            .refund_details
            .as_ref()
            .and_then(|details| details.first())
            .and_then(|detail| detail.arn.clone());

        Ok(Self {
            refund_status,
            response: Ok(services::Response {
                status_code: 200,
                response_body: serde_json::to_value(response)
                    .change_context(errors::ConnectorError::ResponseDeserializationFailed)?,
                headers: HashMap::new(),
            }),
            refund_amount,
            connector_refund_id,
            ..Default::default()
        })
    }
}