use std::collections::HashMap;

use common_utils::{
    errors::CustomResult, ext_traits::ValueExt, types::StringMinorUnit,
    AmountConvertor, Email,
};
use hyperswitch_masking::ExposeInterface;
use common_enums::Currency;
use domain_types::{
    connector_flow::{Authorize, PSync, RSync},
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsResponseData},
    errors::{self, ConnectorError},
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
    
};
use error_stack::ResultExt;
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};



// Authentication structures for ZaakPay
#[derive(Default, Debug, Deserialize)]
pub struct ZaakpayAuthType {
    pub auths: HashMap<Currency, ZaakpayAuth>,
}

#[derive(Default, Debug, Deserialize)]
pub struct ZaakpayAuth {
    pub merchant_identifier: Secret<String>,
    pub secret_key: Option<Secret<String>>,
    pub encryption_key_id: Option<Secret<String>>,
}

// TryFrom implementations for auth types
impl TryFrom<&ConnectorAuthType> for ZaakpayAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::CurrencyAuthKey { auth_key_map } => {
                let transformed_auths = auth_key_map
                    .iter()
                    .map(|(currency, identity_auth_key)| {
                        let zaakpay_auth = identity_auth_key
                            .to_owned()
                            .parse_value::<ZaakpayAuth>("ZaakpayAuth")
                            .change_context(errors::ConnectorError::InvalidDataFormat {
                                field_name: "auth_key_map",
                            })?;

                        Ok((currency.to_owned(), zaakpay_auth))
                    })
                    .collect::<Result<_, Self::Error>>()?;

                Ok(Self {
                    auths: transformed_auths,
                })
            }
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

impl TryFrom<(&ConnectorAuthType, &Currency)> for ZaakpayAuth {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(value: (&ConnectorAuthType, &Currency)) -> Result<Self, Self::Error> {
        let (auth_type, currency) = value;

        if let ConnectorAuthType::CurrencyAuthKey { auth_key_map } = auth_type {
            if let Some(identity_auth_key) = auth_key_map.get(currency) {
                let zaakpay_auth: Self = identity_auth_key
                    .to_owned()
                    .parse_value("ZaakpayAuth")
                    .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
                Ok(zaakpay_auth)
            } else {
                Err(errors::ConnectorError::CurrencyNotSupported {
                    message: currency.to_string(),
                    connector: "Zaakpay",
                }
                .into())
            }
        } else {
            Err(errors::ConnectorError::FailedToObtainAuthType.into())
        }
    }
}

// Request structures based on Haskell ZaakPay types
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakpayPaymentsRequest {
    pub merchant_identifier: Secret<String>,
    pub encryption_key_id: Option<Secret<String>>,
    pub show_mobile: Option<Secret<String>>,
    pub mode: String,
    pub return_url: String,
    pub order_detail: OrderDetailRequest,
    pub billing_address: BillingAddressRequest,
    pub shipping_address: Option<ShippingAddressRequest>,
    pub payment_instrument: PaymentInstrumentRequest,
    pub checksum: Secret<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrderDetailRequest {
    pub order_id: String,
    pub amount: StringMinorUnit,
    pub currency: Currency,
    pub product_description: String,
    pub email: Email,
    pub phone: Secret<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BillingAddressRequest {
    pub address: String,
    pub city: String,
    pub state: String,
    pub country: String,
    pub pincode: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ShippingAddressRequest {
    pub address: Option<String>,
    pub city: Option<String>,
    pub state: Option<String>,
    pub country: Option<String>,
    pub pincode: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentInstrumentRequest {
    pub payment_mode: String,
    pub upi: Option<UpiRequest>,
    pub card: Option<CardRequest>,
    pub netbanking: Option<NetbankingRequest>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpiRequest {
    pub bank_id: String,
    pub vpa: Option<String>,  // Virtual Payment Address for UPI
}

#[derive(Debug, Serialize)]
pub struct CardRequest {
    // ZaakPay card structure - minimal as per Haskell
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetbankingRequest {
    pub bank_id: String,
    pub bank_name: String,
}

// Sync Request structures
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakpayPaymentsSyncRequest {
    pub merchant_identifier: Secret<String>,
    pub mode: String,
    pub order_detail: OrderDetailSyncRequest,
    pub refund_detail: Option<RefundDetailRequest>,
    pub checksum: Secret<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrderDetailSyncRequest {
    pub order_id: String,
    pub amount: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RefundDetailRequest {
    pub merchant_ref_id: String,
}

// Refund Sync Request
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakpayRefundSyncRequest {
    pub merchant_identifier: Secret<String>,
    pub mode: String,
    pub order_detail: OrderDetailSyncRequest,
    pub checksum: Secret<String>,
}

// Response structures based on Haskell ZaakPay types
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakpayPaymentsResponse {
    pub order_detail: OrderDetailResponse,
    pub response_code: String,
    pub response_description: String,
    pub do_redirect: String,
    pub payment_instrument: Option<PaymentInstrumentResponse>,
    pub payment_mode: Option<String>,
    pub post_url: Option<String>,
    pub bank_post_data: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrderDetailResponse {
    pub order_id: String,
    pub amount: Option<String>,
    pub currency: Option<Currency>,
    pub product_description: Option<String>,
    pub email: Option<Email>,
    pub phone: Option<String>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentInstrumentResponse {
    pub payment_mode: String,
    pub card: Option<CardResponse>,
    pub netbanking: Option<NetbankingResponse>,
    pub upi: Option<UpiResponse>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CardResponse {
    pub card_token: Option<String>,
    pub card_scheme: Option<String>,
    pub first4: Option<String>,
    pub last4: Option<String>,
    pub bank: Option<String>,
    pub card_hash_id: Option<String>,
    pub payment_method: Option<String>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetbankingResponse {
    pub bank_id: String,
    pub bank_name: Option<String>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpiResponse {
    pub bank_id: String,
}

// Sync Response structures
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakpayPaymentsSyncResponse {
    pub merchant_identifier: String,
    pub orders: Vec<OrderDetailsResponse>,
    pub version: String,
    pub success: Option<bool>,
    pub checksum: Option<String>,
    pub partial_refund_amt: Option<String>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrderDetailsResponse {
    pub order_detail: Option<OrderDetailResType>,
    pub payment_instrument: Option<PaymentInstrumentType>,
    pub response_code: String,
    pub response_description: String,
    pub txn_status: Option<String>,
    pub txn_date: Option<String>,
    pub user_account_debited: Option<bool>,
    pub partial_refund_amt: Option<String>,
    pub refund_details: Option<Vec<RefundDetails>>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrderDetailResType {
    pub order_id: String,
    pub txn_id: Option<String>,
    pub amount: Option<String>,
    pub product_description: Option<String>,
    pub create_date: Option<String>,
    pub product1_description: Option<String>,
    pub product2_description: Option<String>,
    pub product3_description: Option<String>,
    pub product4_description: Option<String>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentInstrumentType {
    pub payment_mode: Option<String>,
    pub card: Option<CardType>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
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

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RefundDetails {
    pub amount: String,
    pub arn: Option<String>,
    pub merchant_ref_id: Option<String>,
}

// Refund Sync Response
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakpayRefundSyncResponse {
    pub merchant_identifier: String,
    pub orders: Vec<OrderDetailsResponse>,
    pub version: String,
    pub success: Option<bool>,
    pub checksum: Option<String>,
    pub partial_refund_amt: Option<String>,
}

// Error response
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakpayErrorResponse {
    pub response_code: String,
    pub response_description: String,
}

// Stub types for unsupported flows
#[derive(Debug, Clone, Serialize)]
pub struct ZaakpayVoidRequest;
#[derive(Debug, Clone)]
pub struct ZaakpayVoidResponse;

#[derive(Debug, Clone, Serialize)]
pub struct ZaakpayCaptureRequest;
#[derive(Debug, Clone)]
pub struct ZaakpayCaptureResponse;

#[derive(Debug, Clone, Serialize)]
pub struct ZaakpayRefundRequest;
#[derive(Debug, Clone)]
pub struct ZaakpayRefundResponse;

#[derive(Debug, Clone, Serialize)]
pub struct ZaakpayCreateOrderRequest;
#[derive(Debug, Clone)]
pub struct ZaakpayCreateOrderResponse;

#[derive(Debug, Clone, Serialize)]
pub struct ZaakpaySessionTokenRequest;
#[derive(Debug, Clone)]
pub struct ZaakpaySessionTokenResponse;

#[derive(Debug, Clone, Serialize)]
pub struct ZaakpaySetupMandateRequest;
#[derive(Debug, Clone)]
pub struct ZaakpaySetupMandateResponse;

#[derive(Debug, Clone, Serialize)]
pub struct ZaakpayRepeatPaymentRequest;
#[derive(Debug, Clone)]
pub struct ZaakpayRepeatPaymentResponse;

#[derive(Debug, Clone, Serialize)]
pub struct ZaakpayAcceptDisputeRequest;
#[derive(Debug, Clone)]
pub struct ZaakpayAcceptDisputeResponse;

#[derive(Debug, Clone, Serialize)]
pub struct ZaakpaySubmitEvidenceRequest;
#[derive(Debug, Clone)]
pub struct ZaakpaySubmitEvidenceResponse;

#[derive(Debug, Clone, Serialize)]
pub struct ZaakpayDefendDisputeRequest;
#[derive(Debug, Clone)]
pub struct ZaakpayDefendDisputeResponse;

// TryFrom implementations for request transformations

// ZaakpayPaymentsRequest transformation
impl<T: domain_types::payment_method_data::PaymentMethodDataTypes> TryFrom<&RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>
    for ZaakpayPaymentsRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let _customer_id = item.resource_common_data.get_customer_id()?;
        let return_url = item.request.get_router_return_url()?;
        
        // Get amount using StringMinorUnit
        let amount = common_utils::types::StringMinorUnitForConnector
            .convert(common_utils::types::MinorUnit::new(item.request.amount), item.request.currency)
            .change_context(errors::ConnectorError::InvalidDataFormat {
                field_name: "amount",
            })?;
        
        let auth = ZaakpayAuth::try_from((&item.connector_auth_type, &item.request.currency))?;
        
        // Extract email with proper typing
        let email = item.request.email.clone()
            .ok_or_else(|| errors::ConnectorError::MissingRequiredField {
                field_name: "email",
            })?;
        
        // Extract phone number (defaulting to empty for now since it might not be available)
        let phone = Secret::new("".to_string());
        
        // Create order detail
        let order_detail = OrderDetailRequest {
            order_id: item.resource_common_data.connector_request_reference_id.clone(),
            amount,
            currency: item.request.currency,
            product_description: "Payment".to_string(),
            email,
            phone,
        };
        
        // Create billing address (basic implementation)
        let billing_address = BillingAddressRequest {
            address: "".to_string(),
            city: "".to_string(),
            state: "".to_string(),
            country: "IN".to_string(), // Default to India for UPI
            pincode: "".to_string(),
        };
        
        // Create payment instrument (UPI focused)
        let payment_instrument = PaymentInstrumentRequest {
            payment_mode: crate::connectors::zaakpay::constants::PAYMENT_MODE_UPI.to_string(),
            upi: Some(UpiRequest {
                bank_id: "default".to_string(), // Will be updated based on UPI selection
                vpa: match &item.request.payment_method_data {
                    domain_types::payment_method_data::PaymentMethodData::Upi(domain_types::payment_method_data::UpiData::UpiCollect(upi_data)) => {
                        Some(upi_data.vpa_id.as_ref().map(|v| v.clone().expose().to_string()).unwrap_or_default())
                    },
                    domain_types::payment_method_data::PaymentMethodData::Upi(domain_types::payment_method_data::UpiData::UpiIntent(_)) => Some("".to_string()),
                    _ => Some("".to_string()),
                },
            }),
            card: None,
            netbanking: None,
        };
        
        // Generate checksum (placeholder - should implement actual checksum calculation)
        let checksum = Secret::new("placeholder_checksum".to_string());
        
        Ok(Self {
            merchant_identifier: auth.merchant_identifier,
            encryption_key_id: auth.encryption_key_id,
            show_mobile: None,
            mode: get_zaakpay_mode(false), // Refund operations don't have test_mode, default to live
            return_url,
            order_detail,
            billing_address,
            shipping_address: None, // Optional
            payment_instrument,
            checksum,
        })
    }
}

// ZaakpayPaymentsRequest transformation for ZaakpayRouterData
impl<T: domain_types::payment_method_data::PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize> TryFrom<crate::connectors::zaakpay::ZaakpayRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>>
    for ZaakpayPaymentsRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: crate::connectors::zaakpay::ZaakpayRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        Self::try_from(&item.router_data)
    }
}

// Helper function to determine ZaakPay mode (TEST/LIVE)
fn get_zaakpay_mode(is_test: bool) -> String {
    if is_test {
        "TEST".to_string()
    } else {
        "LIVE".to_string()
    }
}

// Helper function to get authentication headers
pub fn get_zaakpay_auth_headers(
    auth_type: &ConnectorAuthType,
) -> CustomResult<Vec<(String, Secret<String>)>, errors::ConnectorError> {
    let auth = ZaakpayAuth::try_from((auth_type, &common_enums::Currency::INR))?;
    
    Ok(vec![
        ("X-Merchant-Identifier".to_string(), auth.merchant_identifier),
    ])
}

// TryFrom implementations for sync requests

// Payment Sync Request transformation
impl TryFrom<&RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>
    for ZaakpayPaymentsSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let auth = ZaakpayAuth::try_from((&item.connector_auth_type, &common_enums::Currency::INR))?;
        
        let order_detail = OrderDetailSyncRequest {
            order_id: item.resource_common_data.connector_request_reference_id.clone(),
            amount: None,
        };
        
        let checksum = Secret::new("placeholder_checksum".to_string());
        
        Ok(Self {
            merchant_identifier: auth.merchant_identifier,
            mode: get_zaakpay_mode(false), // Refund operations don't have test_mode, default to live
            order_detail,
            refund_detail: None,
            checksum,
        })
    }
}

// Payment Sync Request transformation for ZaakpayRouterData
impl<T: domain_types::payment_method_data::PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize> TryFrom<crate::connectors::zaakpay::ZaakpayRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>>
    for ZaakpayPaymentsSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: crate::connectors::zaakpay::ZaakpayRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        Self::try_from(&item.router_data)
    }
}

// Refund Sync Request transformation
impl TryFrom<&RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>>
    for ZaakpayRefundSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
    ) -> Result<Self, Self::Error> {
        let auth = ZaakpayAuth::try_from((&item.connector_auth_type, &common_enums::Currency::INR))?;
        
        let order_detail = OrderDetailSyncRequest {
            order_id: item.resource_common_data.connector_request_reference_id.clone(),
            amount: None,
        };
        
        let checksum = Secret::new("placeholder_checksum".to_string());
        
        Ok(Self {
            merchant_identifier: auth.merchant_identifier,
            mode: get_zaakpay_mode(false), // Refund operations don't have test_mode, default to live
            order_detail,
            checksum,
        })
    }
}

// Refund Sync Request transformation for ZaakpayRouterData
impl<T: domain_types::payment_method_data::PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize> TryFrom<crate::connectors::zaakpay::ZaakpayRouterData<RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>, T>>
    for ZaakpayRefundSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: crate::connectors::zaakpay::ZaakpayRouterData<RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        Self::try_from(&item.router_data)
    }
}

// TryFrom implementations for response transformations

impl TryFrom<ZaakpayPaymentsResponse> for PaymentsResponseData {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(response: ZaakpayPaymentsResponse) -> Result<Self, Self::Error> {
        let _status = map_zaakpay_status(&response.response_code)?;
        let _amount = response.order_detail.amount
            .and_then(|amt| amt.parse::<i64>().ok())
            .map(|a| common_utils::MinorUnit::new(a));

        // TODO: Fix PaymentsResponseData structure - it appears to be an enum or needs specific constructor
        Err(errors::ConnectorError::NotImplemented("PaymentsResponseData construction".to_string()).into())
    }
}

impl TryFrom<ZaakpayPaymentsSyncResponse> for PaymentsResponseData {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(response: ZaakpayPaymentsSyncResponse) -> Result<Self, Self::Error> {
        if let Some(first_order) = response.orders.first() {
            let _status = map_zaakpay_status(&first_order.response_code)?;
            let _amount = first_order.order_detail.as_ref()
                .and_then(|od| od.amount.as_ref())
                .and_then(|amt| amt.parse::<i64>().ok())
                .map(|a| common_utils::MinorUnit::new(a));

            // TODO: Fix PaymentsResponseData structure - it appears to be an enum or needs specific constructor
            Err(errors::ConnectorError::NotImplemented("PaymentsResponseData construction".to_string()).into())
        } else {
            Err(errors::ConnectorError::ResponseDeserializationFailed
                .into())
        }
    }
}

impl TryFrom<ZaakpayRefundSyncResponse> for RefundsResponseData {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(response: ZaakpayRefundSyncResponse) -> Result<Self, Self::Error> {
        if let Some(first_order) = response.orders.first() {
            let _status = map_zaakpay_status(&first_order.response_code)?;
            let _refund_amount = first_order.partial_refund_amt.as_ref()
                .and_then(|amt| amt.parse::<i64>().ok())
                .map(|a| common_utils::MinorUnit::new(a));

            Ok(Self {
                connector_refund_id: first_order.order_detail.as_ref()
                    .map(|od| od.order_id.clone())
                    .unwrap_or_default(),
                refund_status: common_enums::RefundStatus::Success,
                status_code: 200u16,
            })
        } else {
            Err(errors::ConnectorError::ResponseDeserializationFailed.into())
        }
    }
}

// Helper function to map ZaakPay status codes to AttemptStatus
fn map_zaakpay_status(response_code: &str) -> Result<common_enums::AttemptStatus, errors::ConnectorError> {
    match response_code {
        "100" => Ok(common_enums::AttemptStatus::Charged),
        "200" => Ok(common_enums::AttemptStatus::Pending),
        "300" => Ok(common_enums::AttemptStatus::Failure),
        "301" => Ok(common_enums::AttemptStatus::AutoRefunded),
        "302" => Ok(common_enums::AttemptStatus::VoidInitiated),
        "303" => Ok(common_enums::AttemptStatus::Voided),
        _ => Ok(common_enums::AttemptStatus::AuthenticationFailed),
    }
}

// ResponseRouterData TryFrom implementations for macro support
impl<T: domain_types::payment_method_data::PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize> TryFrom<crate::types::ResponseRouterData<ZaakpayPaymentsResponse, RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>>
    for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: crate::types::ResponseRouterData<ZaakpayPaymentsResponse, RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let response_data = PaymentsResponseData::try_from(item.response)?;
        Ok(Self {
            response: Ok(response_data),
            ..item.router_data
        })
    }
}

impl TryFrom<crate::types::ResponseRouterData<ZaakpayPaymentsSyncResponse, RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>>
    for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: crate::types::ResponseRouterData<ZaakpayPaymentsSyncResponse, RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let response_data = PaymentsResponseData::try_from(item.response)?;
        Ok(Self {
            response: Ok(response_data),
            ..item.router_data
        })
    }
}

impl TryFrom<crate::types::ResponseRouterData<ZaakpayRefundSyncResponse, RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>>>
    for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: crate::types::ResponseRouterData<ZaakpayRefundSyncResponse, RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let response_data = RefundsResponseData::try_from(item.response)?;
        Ok(Self {
            response: Ok(response_data),
            ..item.router_data
        })
    }
}