use std::fmt::Debug;

use common_enums::{AttemptStatus, PaymentMethodType};
use common_utils::{
    errors::CustomResult,
    ext_traits::ByteSliceExt,
    types::{FloatMajorUnit, StringMinorUnit, MinorUnit},
};
use domain_types::{
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data_v2::RouterDataV2,
    router_response_types::{RedirectResponse, RedirectMethod},
    types::{PaymentsResponseData, RefundsResponseData},
};
use error_stack::ResultExt;
use hyperswitch_masking::{Mask, Maskable, PeekInterface, Secret};
use masking::ExposeInterface;
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

#[derive(Debug, Clone, Serialize)]
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

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
pub struct PaymentInstrumentResType {
    pub paymentMode: String,
    pub card: Option<CardResType>,
    pub netbanking: Option<NetBankingRespType>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CardResType {
    pub cardToken: Option<String>,
    pub cardScheme: Option<String>,
    pub first4: Option<String>,
    pub last4: Option<String>,
    pub bank: Option<String>,
    pub cardHashId: Option<String>,
    pub paymentMethod: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NetBankingRespType {
    pub bankid: String,
    pub bankName: Option<String>,
}

// Sync request/response types
#[derive(Debug, Clone, Serialize)]
pub struct ZaakPayPaymentsSyncRequest {
    pub data: CheckDataRequest,
    pub checksum: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CheckDataRequest {
    pub merchantIdentifier: String,
    pub mode: String,
    pub orderDetail: OrderDetailType,
    pub refundDetail: Option<RefundDetail>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RefundDetail {
    pub merchantRefId: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct OrderDetailType {
    pub orderId: String,
    pub amount: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ZaakPayPaymentsSyncResponse {
    pub merchantIdentifier: String,
    pub orders: Vec<OrderDetailsResponse>,
    pub version: String,
    pub success: Option<bool>,
    pub checksum: Option<String>,
    pub partialRefundAmt: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OrderDetailsResponse {
    pub orderDetail: Option<OrderDetailResType>,
    pub paymentinstrument: Option<PaymentinstrumentType>,
    pub responseCode: String,
    pub responseDescription: String,
    pub txnStatus: Option<String>,
    pub txnDate: Option<String>,
    pub userAccountDebited: Option<bool>,
    pub partialRefundAmt: Option<String>,
    pub refundDetails: Option<Vec<RefundDetails>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RefundDetails {
    pub amount: String,
    pub arn: Option<String>,
    pub merchantRefId: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OrderDetailResType {
    pub orderId: String,
    pub txnid: Option<String>,
    pub amount: Option<String>,
    pub productDescription: Option<String>,
    pub createDate: Option<String>,
    pub product1Description: Option<String>,
    pub product2Description: Option<String>,
    pub product3Description: Option<String>,
    pub product4Description: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PaymentinstrumentType {
    pub paymentMode: Option<String>,
    pub card: Option<CardType>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CardType {
    pub cardToken: String,
    pub cardId: String,
    pub cardScheme: String,
    pub bank: String,
    pub cardHashId: String,
    pub paymentMethod: String,
    pub first4: String,
    pub last4: String,
}

// Refund sync types
#[derive(Debug, Clone, Serialize)]
pub struct ZaakPayRefundSyncRequest {
    pub data: CheckDataRequest,
    pub checksum: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ZaakPayRefundSyncResponse {
    pub merchantIdentifier: String,
    pub orders: Vec<OrderDetailsResponse>,
    pub version: String,
    pub success: Option<bool>,
    pub checksum: Option<String>,
    pub partialRefundAmt: Option<String>,
}

// Webhook types
#[derive(Debug, Clone, Deserialize)]
pub struct ZaakPayWebhookResponse {
    pub txnData: String,
    pub checksum: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ZaakPayWebResponse {
    pub merchantIdentifier: String,
    pub txns: Vec<TxnDetailResponse>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TxnDetailResponse {}

// Error response type
#[derive(Debug, Clone, Deserialize)]
pub struct ZaakPayErrorResponse {
    pub errorCode: String,
    pub errorDescription: String,
}

// Stub types for unimplemented flows
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

// Transformer implementations

impl<T: PaymentMethodDataTypes + Debug> TryFrom<&RouterDataV2<domain_types::connector_flow::Authorize, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::PaymentsAuthorizeData<T>, PaymentsResponseData>>
    for ZaakPayPaymentsRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: &RouterDataV2<domain_types::connector_flow::Authorize, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::PaymentsAuthorizeData<T>, PaymentsResponseData>) -> Result<Self, Self::Error> {
        // Extract amount using amount converter
        let amount = item.amount.get_amount_as_string();
        let currency = item.router_data.request.currency.to_string();
        
        // Extract customer data
        let customer_id = item.router_data.resource_common_data.get_customer_id()?;
        let customer_id_string = customer_id.get_string_repr();
        
        // Extract transaction ID
        let transaction_id = item.router_data.request.connector_transaction_id
            .get_connector_transaction_id()
            .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?;
        
        // Extract return URL
        let return_url = item.router_data.request.get_router_return_url()?;
        
        // Extract email
        let email = item.router_data.request.email.clone().unwrap_or_default();
        
        // Extract phone
        let phone = item.router_data.request.phone.clone().unwrap_or_default();
        
        // Extract billing address
        let billing_address = item.router_data.request.billing_address.as_ref()
            .ok_or(errors::ConnectorError::MissingRequiredField {
                field_name: "billing_address",
            })?;
        
        // Create order detail
        let order_detail = OrderDetailTransType {
            orderId: transaction_id,
            amount,
            currency,
            productDescription: item.router_data.request.description.clone().unwrap_or_default(),
            email: email.to_string(),
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
        let shipping_address_type = item.router_data.request.shipping_address.as_ref().map(|addr| {
            ShippingAddressType {
                address: addr.address.clone(),
                city: addr.city.clone(),
                state: addr.state.clone(),
                country: addr.country.clone(),
                pincode: addr.zip.clone().map(Secret::new),
            }
        });
        
        // Create payment instrument based on payment method type
        let payment_instrument = match item.router_data.request.payment_method_type {
            PaymentMethodType::Upi => {
                PaymentInstrumentTransType {
                    paymentMode: "upi".to_string(),
                    card: None,
                    netbanking: None,
                    upi: Some(UpiTransType {
                        bankid: customer_id_string,
                    }),
                }
            }
            _ => {
                return Err(errors::ConnectorError::NotImplemented("Payment method not supported".to_string()).into());
            }
        };
        
        // Create transact data
        let transact_data = TransactDataRequest {
            merchantIdentifier: customer_id_string,
            encryptionKeyId: None,
            showMobile: None,
            mode: if item.router_data.resource_common_data.test_mode.unwrap_or(false) { "test" } else { "live" }.to_string(),
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

        let redirect_response = if response.doRedirect == "true" {
            Some(RedirectResponse {
                url: response.postUrl.unwrap_or_default(),
                method: RedirectMethod::Post,
                form_data: response.bankPostData.map(|data| {
                    data.as_object()
                        .unwrap_or(&serde_json::Map::new())
                        .iter()
                        .map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_string()))
                        .collect()
                }).unwrap_or_default(),
            })
        } else {
            None
        };

        Ok(Self {
            status,
            amount: response.orderDetail.amount.parse().ok().map(|amt: f64| {
                MinorUnit::from_major_unit_as_i64(amt)
            }),
            currency: Some(response.orderDetail.currency.parse().unwrap_or(common_enums::Currency::USD)),
            connector_transaction_id: Some(response.orderDetail.orderId),
            capture_method: Some(common_enums::CaptureMethod::Automatic),
            error_message: Some(response.responseDescription),
            redirect: redirect_response,
            ..Default::default()
        })
    }
}

impl TryFrom<&RouterDataV2<domain_types::connector_flow::PSync, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::PaymentsSyncData, PaymentsResponseData>>
    for ZaakPayPaymentsSyncRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: &RouterDataV2<domain_types::connector_flow::PSync, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::PaymentsSyncData, PaymentsResponseData>) -> Result<Self, Self::Error> {
        // Extract customer data
        let customer_id = item.router_data.resource_common_data.get_customer_id()?;
        let customer_id_string = customer_id.get_string_repr();
        
        // Extract transaction ID
        let transaction_id = item.router_data.request.connector_transaction_id
            .get_connector_transaction_id()
            .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?;
        
        // Create order detail
        let order_detail = OrderDetailType {
            orderId: transaction_id,
            amount: None,
        };
        
        // Create check data
        let check_data = CheckDataRequest {
            merchantIdentifier: customer_id_string,
            mode: if item.router_data.resource_common_data.test_mode.unwrap_or(false) { "test" } else { "live" }.to_string(),
            orderDetail: order_detail,
            refundDetail: None,
        };
        
        // Generate checksum
        let checksum = format!("checksum_{}", transaction_id);
        
        Ok(Self {
            data: check_data,
            checksum,
        })
    }
}

impl TryFrom<ZaakPayPaymentsSyncResponse> for PaymentsResponseData {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(response: ZaakPayPaymentsSyncResponse) -> Result<Self, Self::Error> {
        let order = response.orders.first().ok_or(errors::ConnectorError::MissingRequiredField {
            field_name: "orders",
        })?;

        let status = match order.txnStatus.as_deref() {
            Some("success") => AttemptStatus::Charged,
            Some("pending") => AttemptStatus::Pending,
            Some("failure") => AttemptStatus::Failure,
            _ => AttemptStatus::Pending,
        };

        let amount = order.orderDetail.as_ref()
            .and_then(|od| od.amount.as_ref())
            .and_then(|amt| amt.parse().ok())
            .map(|amt: f64| MinorUnit::from_major_unit_as_i64(amt));

        let currency = order.orderDetail.as_ref()
            .and_then(|od| od.currency.as_ref())
            .and_then(|curr| curr.parse().ok());

        Ok(Self {
            status,
            amount,
            currency,
            connector_transaction_id: order.orderDetail.as_ref().map(|od| od.orderId.clone()),
            capture_method: Some(common_enums::CaptureMethod::Automatic),
            error_message: Some(order.responseDescription.clone()),
            ..Default::default()
        })
    }
}

impl TryFrom<&RouterDataV2<domain_types::connector_flow::RSync, domain_types::connector_types::RefundFlowData, domain_types::connector_types::RefundSyncData, RefundsResponseData>>
    for ZaakPayRefundSyncRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: &RouterDataV2<domain_types::connector_flow::RSync, domain_types::connector_types::RefundFlowData, domain_types::connector_types::RefundSyncData, RefundsResponseData>) -> Result<Self, Self::Error> {
        // Extract customer data
        let customer_id = item.router_data.resource_common_data.get_customer_id()?;
        let customer_id_string = customer_id.get_string_repr();
        
        // Extract transaction ID
        let transaction_id = item.router_data.request.connector_transaction_id
            .get_connector_transaction_id()
            .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?;
        
        // Extract refund ID
        let refund_id = item.router_data.request.connector_refund_id
            .get_connector_refund_id()
            .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?;
        
        // Create order detail
        let order_detail = OrderDetailType {
            orderId: transaction_id,
            amount: None,
        };
        
        // Create refund detail
        let refund_detail = RefundDetail {
            merchantRefId: refund_id,
        };
        
        // Create check data
        let check_data = CheckDataRequest {
            merchantIdentifier: customer_id_string,
            mode: if item.router_data.resource_common_data.test_mode.unwrap_or(false) { "test" } else { "live" }.to_string(),
            orderDetail: order_detail,
            refundDetail: Some(refund_detail),
        };
        
        // Generate checksum
        let checksum = format!("checksum_{}", transaction_id);
        
        Ok(Self {
            data: check_data,
            checksum,
        })
    }
}

impl TryFrom<ZaakPayRefundSyncResponse> for RefundsResponseData {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(response: ZaakPayRefundSyncResponse) -> Result<Self, Self::Error> {
        let order = response.orders.first().ok_or(errors::ConnectorError::MissingRequiredField {
            field_name: "orders",
        })?;

        let status = match order.txnStatus.as_deref() {
            Some("success") => common_enums::RefundStatus::Success,
            Some("pending") => common_enums::RefundStatus::Pending,
            Some("failure") => common_enums::RefundStatus::Failure,
            _ => common_enums::RefundStatus::Pending,
        };

        let refund_amount = order.refundDetails.as_ref()
            .and_then(|refunds| refunds.first())
            .and_then(|refund| refund.amount.parse().ok())
            .map(|amt: f64| MinorUnit::from_major_unit_as_i64(amt));

        Ok(Self {
            refund_id: order.refundDetails.as_ref()
                .and_then(|refunds| refunds.first())
                .and_then(|refund| refund.merchantRefId.clone()),
            status,
            amount: refund_amount,
            connector_refund_id: order.orderDetail.as_ref().map(|od| od.orderId.clone()),
            ..Default::default()
        })
    }
}