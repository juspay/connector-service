use std::fmt::Debug;

use common_enums::{AttemptStatus, PaymentMethodType};
use common_utils::{
    types::MinorUnit,
};
use domain_types::{
    connector_types::PaymentsResponseData,
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data_v2::RouterDataV2,
};
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};

// Request/Response types based on Haskell implementation

#[derive(Debug, Clone, Serialize)]
pub struct ZaakPayPaymentsRequest {
    pub data: TransactDataRequest,
    pub checksum: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TransactDataRequest {
    pub merchantIdentifier: String,
    pub encryptionKeyId: Option<String>,
    pub showMobile: Option<String>,
    pub mode: String,
    pub returnUrl: String,
    pub orderDetail: OrderDetailTransType,
    pub billingAddress: BillingAddressType,
    pub shippingAddress: Option<ShippingAddressType>,
    pub paymentInstrument: PaymentInstrumentTransType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderDetailTransType {
    pub orderId: String,
    pub amount: String,
    pub currency: String,
    pub productDescription: String,
    pub email: String,
    pub phone: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BillingAddressType {
    pub address: String,
    pub city: String,
    pub state: String,
    pub country: String,
    pub pincode: Secret<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ShippingAddressType {
    pub address: Option<String>,
    pub city: Option<String>,
    pub state: Option<String>,
    pub country: Option<String>,
    pub pincode: Option<Secret<String>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PaymentInstrumentTransType {
    pub paymentMode: String,
    pub card: Option<CardTransType>,
    pub netbanking: Option<NetTransType>,
    pub upi: Option<UpiTransType>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CardTransType {}

#[derive(Debug, Clone, Serialize)]
pub struct NetTransType {
    pub bankid: String,
    pub bankName: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct UpiTransType {
    pub bankid: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ZaakPayPaymentsResponse {
    pub orderDetail: OrderDetailTransType,
    pub responseCode: String,
    pub responseDescription: String,
    pub doRedirect: String,
    pub paymentInstrument: Option<PaymentInstrumentResType>,
    pub paymentMode: Option<String>,
    pub postUrl: Option<String>,
    pub bankPostData: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PaymentInstrumentResType {
    pub paymentMode: String,
    pub card: Option<CardResType>,
    pub netbanking: Option<NetBankingRespType>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CardResType {
    pub cardToken: Option<String>,
    pub cardScheme: Option<String>,
    pub first4: Option<String>,
    pub last4: Option<String>,
    pub bank: Option<String>,
    pub cardHashId: Option<String>,
    pub paymentMethod: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NetBankingRespType {
    pub bankid: String,
    pub bankName: Option<String>,
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

// Sync response types
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

impl<T: PaymentMethodDataTypes + Debug> TryFrom<&RouterDataV2<domain_types::connector_flow::Authorize, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::PaymentsAuthorizeData<T>, PaymentsResponseData>>
    for ZaakPayPaymentsRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: &RouterDataV2<domain_types::connector_flow::Authorize, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::PaymentsAuthorizeData<T>, PaymentsResponseData>) -> Result<Self, Self::Error> {
        // Extract amount using amount converter
        let amount = item.request.amount.to_string();
        let currency = item.request.currency.to_string();
        
        // Extract customer data
        let customer_id = item.resource_common_data.get_customer_id()?;
        let customer_id_string = customer_id.get_string_repr();
        
        // Extract transaction ID
        let transaction_id = item.request.payment_id.clone();
        
        // Extract return URL
        let return_url = item.request.get_router_return_url()?;
        
        // Extract email
        let email = item.request.email.clone().unwrap_or_default();
        
        // Extract phone - not available in PaymentsAuthorizeData
        let phone = String::new();
        
        // Extract billing address from address details
        let billing_address = &item.request.address.billing;
        
        // Create order detail
        let order_detail = OrderDetailTransType {
            orderId: transaction_id,
            amount,
            currency,
            productDescription: item.request.order_description.clone().unwrap_or_default(),
            email: email.peek().clone(),
            phone: phone.to_string(),
        };
        
        // Create billing address
        let billing_address_type = BillingAddressType {
            address: billing_address.address.clone().unwrap_or_default(),
            city: billing_address.city.clone().unwrap_or_default(),
            state: billing_address.state.clone().unwrap_or_default(),
            country: billing_address.country.clone().unwrap_or_default(),
            pincode: Secret::new(billing_address.zip.clone().unwrap_or_default()),
        };
        
        // Create shipping address (optional)
        let shipping_address_type = item.request.address.shipping.as_ref().map(|addr| {
            ShippingAddressType {
                address: addr.address.clone(),
                city: addr.city.clone(),
                state: addr.state.clone(),
                country: addr.country.clone(),
                pincode: addr.zip.clone().map(Secret::new),
            }
        });
        
        // Create payment instrument based on payment method type
        let payment_instrument = match item.request.payment_method_type {
            PaymentMethodType::UpiCollect => {
                PaymentInstrumentTransType {
                    paymentMode: "upi".to_string(),
                    card: None,
                    netbanking: None,
                    upi: Some(UpiTransType {
                        bankid: customer_id_string.to_string(),
                    }),
                }
            }
            _ => {
                return Err(errors::ConnectorError::NotImplemented("Payment method not supported".to_string()).into());
            }
        };
        
        // Create transact data
        let transact_data = TransactDataRequest {
            merchantIdentifier: customer_id_string.to_string(),
            encryptionKeyId: None,
            showMobile: None,
            mode: if item.resource_common_data.test_mode.unwrap_or(false) { "test" } else { "live" }.to_string(),
            returnUrl: return_url.to_string(),
            orderDetail: order_detail,
            billingAddress: billing_address_type,
            shippingAddress: shipping_address_type,
            paymentInstrument: payment_instrument,
        };
        
        // Generate checksum (simplified - in real implementation this would use proper crypto)
        let checksum = format!("checksum_{}", transaction_id);
        
        Ok(Self {
            data: transact_data,
            checksum,
        })
    }
}

impl TryFrom<ZaakPayPaymentsResponse> for PaymentsResponseData {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(response: ZaakPayPaymentsResponse) -> Result<Self, Self::Error> {
        let status = match response.responseCode.as_str() {
            "100" => AttemptStatus::Charged,
            "101" => AttemptStatus::Pending,
            "102" => AttemptStatus::Failure,
            _ => AttemptStatus::Failure,
        };

        Ok(PaymentsResponseData {
            status,
            amount: response.orderDetail.amount.parse().ok().map(|amt: i64| {
                MinorUnit::new(amt)
            }),
            currency: Some(response.orderDetail.currency.parse().unwrap_or(common_enums::Currency::USD)),
            connector_transaction_id: Some(response.orderDetail.orderId),
            capture_method: Some(common_enums::CaptureMethod::Automatic),
            error_message: Some(response.responseDescription),
            ..Default::default()
        })
    }
}

impl<T: PaymentMethodDataTypes + Debug> 
    TryFrom<crate::types::ResponseRouterData<ZaakPayPaymentsResponse, RouterDataV2<domain_types::connector_flow::Authorize, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::PaymentsAuthorizeData<T>, PaymentsResponseData>>>
    for RouterDataV2<domain_types::connector_flow::Authorize, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        value: crate::types::ResponseRouterData<ZaakPayPaymentsResponse, RouterDataV2<domain_types::connector_flow::Authorize, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::PaymentsAuthorizeData<T>, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let crate::types::ResponseRouterData {
            response,
            router_data,
            http_code: _,
        } = value;
        
        let payments_response = PaymentsResponseData::try_from(response)?;
        Ok(router_data.with_response(payments_response))
    }
}