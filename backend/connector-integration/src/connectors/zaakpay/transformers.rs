use std::collections::HashMap;

use common_enums::{AttemptStatus, PaymentMethodType};
use common_utils::{
    errors::CustomResult,
    ext_traits::ValueExt,
    types::{StringMinorUnit, MinorUnit},
};
use domain_types::{
    connector_flow::{Authorize, PSync, RSync},
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, RefundSyncData, RefundsResponseData},
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType},
    router_data_v2::RouterDataV2,
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, Secret};
use serde::{Deserialize, Serialize};

use crate::types;

// Request/Response types based on Haskell implementation

#[derive(Debug, Serialize)]
pub struct ZaakPayPaymentsRequest {
    pub data: ZaakPayTransactDataRequest,
    pub checksum: String,
}

#[derive(Debug, Serialize)]
pub struct ZaakPayTransactDataRequest {
    pub merchantIdentifier: String,
    pub encryptionKeyId: Option<String>,
    pub showMobile: Option<String>,
    pub mode: String,
    pub returnUrl: String,
    pub orderDetail: ZaakPayOrderDetailTransType,
    pub billingAddress: ZaakPayBillingAddressType,
    pub shippingAddress: Option<ZaakPayShippingAddressType>,
    pub paymentInstrument: ZaakPayPaymentInstrumentTransType,
}

#[derive(Debug, Serialize)]
pub struct ZaakPayOrderDetailTransType {
    pub orderId: String,
    pub amount: String,
    pub currency: String,
    pub productDescription: String,
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
    pub paymentMode: String,
    pub card: Option<ZaakPayCardTransType>,
    pub netbanking: Option<ZaakPayNetTransType>,
    pub upi: Option<ZaakPayUpiTransType>,
}

#[derive(Debug, Serialize)]
pub struct ZaakPayCardTransType {}

#[derive(Debug, Serialize)]
pub struct ZaakPayNetTransType {
    pub bankid: String,
    pub bankName: String,
}

#[derive(Debug, Serialize)]
pub struct ZaakPayUpiTransType {
    pub bankid: String,
}

#[derive(Debug, Deserialize)]
pub struct ZaakPayPaymentsResponse {
    pub orderDetail: ZaakPayOrderDetailTransType,
    pub responseCode: String,
    pub responseDescription: String,
    pub doRedirect: String,
    pub paymentInstrument: Option<ZaakPayPaymentInstrumentResType>,
    pub paymentMode: Option<String>,
    pub postUrl: Option<String>,
    pub bankPostData: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Deserialize)]
pub struct ZaakPayPaymentInstrumentResType {
    pub paymentMode: String,
    pub card: Option<ZaakPayCardResType>,
    pub netbanking: Option<ZaakPayNetBankingRespType>,
}

#[derive(Debug, Deserialize)]
pub struct ZaakPayCardResType {
    pub cardToken: Option<String>,
    pub cardScheme: Option<String>,
    pub first4: Option<String>,
    pub last4: Option<String>,
    pub bank: Option<String>,
    pub cardHashId: Option<String>,
    pub paymentMethod: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ZaakPayNetBankingRespType {
    pub bankid: String,
    pub bankName: Option<String>,
}

// Sync request/response types
#[derive(Debug, Serialize)]
pub struct ZaakPayPaymentsSyncRequest {
    pub data: ZaakPayCheckDataRequest,
    pub checksum: String,
}

#[derive(Debug, Serialize)]
pub struct ZaakPayCheckDataRequest {
    pub merchantIdentifier: String,
    pub mode: String,
    pub orderDetail: ZaakPayOrderDetailType,
    pub refundDetail: Option<ZaakPayRefundDetail>,
}

#[derive(Debug, Serialize)]
pub struct ZaakPayRefundDetail {
    pub merchantRefId: String,
}

#[derive(Debug, Serialize)]
pub struct ZaakPayOrderDetailType {
    pub orderId: String,
    pub amount: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ZaakPayPaymentsSyncResponse {
    pub merchantIdentifier: String,
    pub orders: Vec<ZaakPayOrderDetailsResponse>,
    pub version: String,
    pub success: Option<bool>,
    pub checksum: Option<String>,
    pub partialRefundAmt: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ZaakPayOrderDetailsResponse {
    pub orderDetail: Option<ZaakPayOrderDetailResType>,
    pub paymentinstrument: Option<ZaakPayPaymentinstrumentType>,
    pub responseCode: String,
    pub responseDescription: String,
    pub txnStatus: Option<String>,
    pub txnDate: Option<String>,
    pub userAccountDebited: Option<bool>,
    pub partialRefundAmt: Option<String>,
    pub refundDetails: Option<Vec<ZaakPayRefundDetails>>,
}

#[derive(Debug, Deserialize)]
pub struct ZaakPayRefundDetails {
    pub amount: String,
    pub arn: Option<String>,
    pub merchantRefId: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ZaakPayOrderDetailResType {
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

#[derive(Debug, Deserialize)]
pub struct ZaakPayPaymentinstrumentType {
    pub paymentMode: Option<String>,
    pub card: Option<ZaakPayCardType>,
}

#[derive(Debug, Deserialize)]
pub struct ZaakPayCardType {
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
#[derive(Debug, Serialize)]
pub struct ZaakPayRefundSyncRequest {
    pub data: ZaakPayCheckDataRequest,
    pub checksum: String,
}

#[derive(Debug, Deserialize)]
pub struct ZaakPayRefundSyncResponse {
    pub merchantIdentifier: String,
    pub orders: Vec<ZaakPayOrderDetailsResponse>,
    pub version: String,
    pub success: Option<bool>,
    pub checksum: Option<String>,
    pub partialRefundAmt: Option<String>,
}

// Error response type
#[derive(Debug, Deserialize)]
pub struct ZaakPayErrorResponse {
    pub responseCode: String,
    pub responseDescription: String,
}

// Transformer implementations

impl<T: PaymentMethodDataTypes> TryFrom<&RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>
    for ZaakPayPaymentsRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>) -> Result<Self, Self::Error> {
        // Extract merchant identifier from auth type
        let merchant_identifier = match &item.connector_auth_type {
            ConnectorAuthType::HeaderKey { api_key } => {
                api_key.expose().clone()
            }
            _ => return Err(errors::ConnectorError::AuthenticationFailed.into()),
        };

        // Get amount using amount converter
        let amount = item.amount.get_amount_as_string();
        let currency = item.router_data.request.currency.to_string();

        // Extract customer information
        let customer_id = item.router_data.resource_common_data.get_customer_id()?;
        let customer_id_string = customer_id.get_string_repr();
        
        let email = item.router_data.request.email.as_ref()
            .ok_or(errors::ConnectorError::MissingRequiredField { field: "email" })?
            .to_string();

        let phone = item.router_data.request.phone.as_ref()
            .map(|p| p.to_string())
            .unwrap_or_default();

        // Get return URL
        let return_url = item.router_data.request.get_router_return_url()?;

        // Extract billing address
        let billing_address = item.router_data.request.billing_address.as_ref()
            .ok_or(errors::ConnectorError::MissingRequiredField { field: "billing_address" })?;

        let billing_address_type = ZaakPayBillingAddressType {
            address: billing_address.address.as_ref()
                .map(|addr| addr.get_full_address())
                .unwrap_or_default(),
            city: billing_address.city.as_ref()
                .map(|city| city.to_string())
                .unwrap_or_default(),
            state: billing_address.state.as_ref()
                .map(|state| state.to_string())
                .unwrap_or_default(),
            country: billing_address.country.as_ref()
                .map(|country| country.to_string())
                .unwrap_or_default(),
            pincode: Secret::new(billing_address.zip.as_ref()
                .map(|zip| zip.to_string())
                .unwrap_or_default()),
        };

        // Extract shipping address (optional)
        let shipping_address = item.router_data.request.shipping_address.as_ref()
            .map(|addr| ZaakPayShippingAddressType {
                address: addr.address.as_ref()
                    .map(|addr| addr.get_full_address()),
                city: addr.city.as_ref()
                    .map(|city| city.to_string()),
                state: addr.state.as_ref()
                    .map(|state| state.to_string()),
                country: addr.country.as_ref()
                    .map(|country| country.to_string()),
                pincode: addr.zip.as_ref()
                    .map(|zip| Secret::new(zip.to_string())),
            });

        // Determine payment mode and instrument based on payment method type
        let (payment_mode, payment_instrument) = match item.router_data.request.payment_method_type {
            PaymentMethodType::Upi => {
                let upi_data = item.router_data.request.payment_method_data.as_ref()
                    .and_then(|data| data.get_upi_data())
                    .ok_or(errors::ConnectorError::MissingRequiredField { field: "upi_data" })?;

                let upi_trans = ZaakPayUpiTransType {
                    bankid: upi_data.vpa.as_ref()
                        .map(|vpa| vpa.to_string())
                        .unwrap_or_default(),
                };

                ("UPI".to_string(), ZaakPayPaymentInstrumentTransType {
                    paymentMode: "UPI".to_string(),
                    card: None,
                    netbanking: None,
                    upi: Some(upi_trans),
                })
            }
            _ => return Err(errors::ConnectorError::NotImplemented("Payment method not supported".to_string()).into()),
        };

        // Create order detail
        let order_detail = ZaakPayOrderDetailTransType {
            orderId: item.router_data.request.connector_transaction_id
                .get_connector_transaction_id()
                .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?,
            amount,
            currency,
            productDescription: item.router_data.request.description.as_ref()
                .map(|desc| desc.to_string())
                .unwrap_or_else(|| "Payment".to_string()),
            email,
            phone,
        };

        // Create transact data request
        let transact_data = ZaakPayTransactDataRequest {
            merchantIdentifier: merchant_identifier.clone(),
            encryptionKeyId: None,
            showMobile: None,
            mode: if item.router_data.resource_common_data.test_mode.unwrap_or(false) { "0" } else { "1" }.to_string(),
            returnUrl: return_url.to_string(),
            orderDetail: order_detail.clone(),
            billingAddress: billing_address_type,
            shippingAddress: shipping_address,
            paymentInstrument: payment_instrument,
        };

        // Generate checksum (simplified - in real implementation, this would use proper crypto)
        let checksum = format!("checksum_{}", merchant_identifier);

        Ok(Self {
            data: transact_data,
            checksum,
        })
    }
}

impl TryFrom<(ZaakPayPaymentsResponse, &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<()>, PaymentsResponseData>)>
    for PaymentsResponseData
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from((response, _req): (ZaakPayPaymentsResponse, &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<()>, PaymentsResponseData>)) -> Result<Self, Self::Error> {
        let status = match response.responseCode.as_str() {
            "100" => common_enums::AttemptStatus::Charged,
            "101" => common_enums::AttemptStatus::Pending,
            "102" => common_enums::AttemptStatus::Failure,
            _ => common_enums::AttemptStatus::Failure,
        };

        let amount_received = response.orderDetail.amount.parse::<f64>()
            .ok()
            .map(|amt| MinorUnit::from_major_unit_as_f64(amt));

        Ok(Self {
            status,
            amount_captured: amount_received,
            connector_transaction_id: Some(response.orderDetail.orderId),
            error_message: Some(response.responseDescription),
            // Add other required fields as needed
            ..Default::default()
        })
    }
}

impl<T: PaymentMethodDataTypes> TryFrom<&RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>
    for ZaakPayPaymentsSyncRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>) -> Result<Self, Self::Error> {
        // Extract merchant identifier from auth type
        let merchant_identifier = match &item.connector_auth_type {
            ConnectorAuthType::HeaderKey { api_key } => {
                api_key.expose().clone()
            }
            _ => return Err(errors::ConnectorError::AuthenticationFailed.into()),
        };

        // Get amount using amount converter
        let amount = item.amount.get_amount_as_string();

        // Create order detail
        let order_detail = ZaakPayOrderDetailType {
            orderId: item.router_data.request.connector_transaction_id
                .get_connector_transaction_id()
                .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?,
            amount: Some(amount),
        };

        // Create check data request
        let check_data = ZaakPayCheckDataRequest {
            merchantIdentifier: merchant_identifier.clone(),
            mode: if item.router_data.resource_common_data.test_mode.unwrap_or(false) { "0" } else { "1" }.to_string(),
            orderDetail: order_detail,
            refundDetail: None,
        };

        // Generate checksum
        let checksum = format!("checksum_{}", merchant_identifier);

        Ok(Self {
            data: check_data,
            checksum,
        })
    }
}

impl<T: PaymentMethodDataTypes> TryFrom<(ZaakPayPaymentsSyncResponse, &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>)>
    for PaymentsResponseData
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from((response, req): (ZaakPayPaymentsSyncResponse, &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>)) -> Result<Self, Self::Error> {
        // Get the first order from the response
        let order = response.orders.first()
            .ok_or(errors::ConnectorError::MissingRequiredField { field: "orders" })?;

        let status = match order.txnStatus.as_deref() {
            Some("success") => AttemptStatus::Charged,
            Some("pending") => AttemptStatus::Pending,
            Some("failure") => AttemptStatus::Failure,
            _ => AttemptStatus::Failure,
        };

        let amount_received = order.orderDetail.as_ref()
            .and_then(|od| od.amount.as_ref())
            .and_then(|amt| amt.parse::<f64>().ok())
            .map(|amt| MinorUnit::from_major_unit_as_f64(amt));

        Ok(Self {
            status,
            amount_captured: amount_received,
            connector_transaction_id: order.orderDetail.as_ref().map(|od| od.orderId.clone()),
            error_message: Some(order.responseDescription.clone()),
            // Add other required fields as needed
            ..Default::default()
        })
    }
}

impl<T: PaymentMethodDataTypes> TryFrom<&RouterDataV2<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>>
    for ZaakPayRefundSyncRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: &RouterDataV2<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>) -> Result<Self, Self::Error> {
        // Extract merchant identifier from auth type
        let merchant_identifier = match &item.connector_auth_type {
            ConnectorAuthType::HeaderKey { api_key } => {
                api_key.expose().clone()
            }
            _ => return Err(errors::ConnectorError::AuthenticationFailed.into()),
        };

        // Get amount using amount converter
        let amount = item.amount.get_amount_as_string();

        // Create order detail
        let order_detail = ZaakPayOrderDetailType {
            orderId: item.router_data.request.connector_transaction_id
                .get_connector_transaction_id()
                .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?,
            amount: Some(amount),
        };

        // Create refund detail
        let refund_detail = ZaakPayRefundDetail {
            merchantRefId: item.router_data.request.refund_id.clone(),
        };

        // Create check data request
        let check_data = ZaakPayCheckDataRequest {
            merchantIdentifier: merchant_identifier.clone(),
            mode: if item.router_data.resource_common_data.test_mode.unwrap_or(false) { "0" } else { "1" }.to_string(),
            orderDetail: order_detail,
            refundDetail: Some(refund_detail),
        };

        // Generate checksum
        let checksum = format!("checksum_{}", merchant_identifier);

        Ok(Self {
            data: check_data,
            checksum,
        })
    }
}

impl<T: PaymentMethodDataTypes> TryFrom<(ZaakPayRefundSyncResponse, &RouterDataV2<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>)>
    for RefundsResponseData
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from((response, req): (ZaakPayRefundSyncResponse, &RouterDataV2<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>)) -> Result<Self, Self::Error> {
        // Get the first order from the response
        let order = response.orders.first()
            .ok_or(errors::ConnectorError::MissingRequiredField { field: "orders" })?;

        let status = match order.txnStatus.as_deref() {
            Some("success") => common_enums::RefundStatus::Success,
            Some("pending") => common_enums::RefundStatus::Pending,
            Some("failure") => common_enums::RefundStatus::Failure,
            _ => common_enums::RefundStatus::Failure,
        };

        let refund_amount = order.refundDetails.as_ref()
            .and_then(|refunds| refunds.first())
            .and_then(|refund| refund.amount.parse::<f64>().ok())
            .map(|amt| MinorUnit::from_major_unit_as_f64(amt));

        Ok(Self {
            refund_id: order.refundDetails.as_ref()
                .and_then(|refunds| refunds.first())
                .and_then(|refund| refund.merchantRefId.clone()),
            status,
            amount: refund_amount,
            // Add other required fields as needed
            ..Default::default()
        })
    }
}