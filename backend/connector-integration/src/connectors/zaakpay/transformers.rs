use std::collections::HashMap;

use common_utils::{
    errors::CustomResult,
    ext_traits::ValueExt,
    request::Method,
    types::StringMinorUnit,
    Email,
};
use domain_types::{
    connector_flow::{Authorize, PSync},
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, ResponseId},
    errors::{self, ConnectorError},
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
    utils,
};
use error_stack::ResultExt;
use hyperswitch_masking::{Mask, Maskable, PeekInterface, Secret};
use serde::{Deserialize, Serialize};

use crate::{connectors::zaakpay::ZaakPayRouterData, types::ResponseRouterData};

// Request/Response types based on Haskell implementation

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayPaymentsRequest {
    pub data: ZaakPayTransactDataRequest,
    pub checksum: String,
}

#[derive(Debug, Serialize)]
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

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayOrderDetailTransType {
    pub order_id: String,
    pub amount: String,
    pub currency: String,
    pub product_description: String,
    pub email: String,
    pub phone: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayBillingAddressType {
    pub address: String,
    pub city: String,
    pub state: String,
    pub country: String,
    pub pincode: Secret<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayShippingAddressType {
    pub address: Option<String>,
    pub city: Option<String>,
    pub state: Option<String>,
    pub country: Option<String>,
    pub pincode: Option<Secret<String>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayPaymentInstrumentTransType {
    pub payment_mode: String,
    pub card: Option<ZaakPayCardTransType>,
    pub netbanking: Option<ZaakPayNetTransType>,
    pub upi: Option<ZaakPayUpiTransType>,
}

#[derive(Debug, Serialize)]
pub struct ZaakPayCardTransType;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayNetTransType {
    pub bankid: String,
    pub bank_name: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayUpiTransType {
    pub bankid: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayPaymentsResponse {
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

// PSync request/response types
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayPaymentsSyncRequest {
    pub data: ZaakPayCheckDataRequest,
    pub checksum: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayCheckDataRequest {
    pub merchant_identifier: String,
    pub mode: String,
    pub order_detail: ZaakPayOrderDetailType,
    pub refund_detail: Option<ZaakPayRefundDetail>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayOrderDetailType {
    pub order_id: String,
    pub amount: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayRefundDetail {
    pub merchant_ref_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayPaymentsSyncResponse {
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

// Webhook response types
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayWebhookResponse {
    pub order_id: String,
    pub txn_data: String,
    pub checksum: String,
}

// Error response type
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayErrorResponse {
    pub response_code: String,
    pub response_description: String,
}

// Authentication types
#[derive(Debug, Deserialize)]
pub struct ZaakPayAuthType {
    pub merchant_identifier: Secret<String>,
    pub secret_key: Secret<String>,
}

#[derive(Debug)]
pub struct ZaakPayAuth {
    pub merchant_identifier: Secret<String>,
    pub secret_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for ZaakPayAuth {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey { api_key, key1, api_secret } => {
                let auth_data: ZaakPayAuthType = key1
                    .to_owned()
                    .parse_value("ZaakPayAuthType")
                    .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
                
                Ok(Self {
                    merchant_identifier: auth_data.merchant_identifier,
                    secret_key: auth_data.secret_key,
                })
            }
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

// Checksum generation function
pub fn generate_checksum(payload: &str, secret: &str) -> String {
    use sha2::{Sha256, Digest};
    
    let mut hasher = Sha256::new();
    hasher.update(payload.as_bytes());
    hasher.update(secret.as_bytes());
    let result = hasher.finalize();
    
    hex::encode(result)
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
pub struct ZaakPayRefundSyncRequest;
#[derive(Debug, Clone)]
pub struct ZaakPayRefundSyncResponse;

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

// Payment status mapping
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ZaakPayPaymentStatus {
    #[default]
    Pending,
    Success,
    Failure,
    Processing,
}

impl From<ZaakPayPaymentStatus> for common_enums::AttemptStatus {
    fn from(item: ZaakPayPaymentStatus) -> Self {
        match item {
            ZaakPayPaymentStatus::Success => Self::Charged,
            ZaakPayPaymentStatus::Failure => Self::Failure,
            ZaakPayPaymentStatus::Processing => Self::AuthenticationPending,
            ZaakPayPaymentStatus::Pending => Self::Pending,
        }
    }
}

// Request transformation implementations
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
        
        // Extract authentication data
        let auth = ZaakPayAuth::try_from(&item.router_data.connector_auth_type)?;
        
        // Get amount using proper converter
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        // Create order details
        let order_detail = ZaakPayOrderDetailTransType {
            order_id: item.router_data.resource_common_data.connector_request_reference_id.clone(),
            amount: amount,
            currency: item.router_data.request.currency.to_string(),
            product_description: "Payment".to_string(),
            email: item.router_data.request.email.clone().map(|e| e.peek().to_string()).unwrap_or_default(),
            phone: "0000000000".to_string(), // Default phone number
        };

        // Create billing address (using default values for now)
        let billing_address = ZaakPayBillingAddressType {
            address: "Default Address".to_string(),
            city: "Default City".to_string(),
            state: "Default State".to_string(),
            country: "IN".to_string(), // Default to India for UPI
            pincode: Secret::new("000000".to_string()),
        };

        // Create payment instrument based on payment method type
        let payment_instrument = match item.router_data.request.payment_method_type {
            Some(common_enums::PaymentMethodType::UpiCollect) => {
                ZaakPayPaymentInstrumentTransType {
                    payment_mode: "upi".to_string(),
                    card: None,
                    netbanking: None,
                    upi: Some(ZaakPayUpiTransType {
                        bankid: "default".to_string(), // This should come from payment method data
                    }),
                }
            },
            Some(common_enums::PaymentMethodType::Paypal) => {
                ZaakPayPaymentInstrumentTransType {
                    payment_mode: "netbanking".to_string(),
                    card: None,
                    netbanking: Some(ZaakPayNetTransType {
                        bankid: "default".to_string(), // This should come from payment method data
                        bank_name: "Default Bank".to_string(),
                    }),
                    upi: None,
                }
            },
            _ => {
                ZaakPayPaymentInstrumentTransType {
                    payment_mode: "upi".to_string(),
                    card: None,
                    netbanking: None,
                    upi: Some(ZaakPayUpiTransType {
                        bankid: "default".to_string(),
                    }),
                }
            }
        };

        // Create transaction data
        let transact_data = ZaakPayTransactDataRequest {
            merchant_identifier: auth.merchant_identifier.peek().to_string(),
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

        // Generate checksum
        let payload = serde_json::to_string(&transact_data)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;
        let checksum = generate_checksum(&payload, auth.secret_key.peek());

        Ok(Self {
            data: transact_data,
            checksum,
        })
    }
}

// PSync request transformation
impl TryFrom<&RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>
    for ZaakPayPaymentsSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let auth = ZaakPayAuth::try_from(&item.connector_auth_type)?;
        
        let order_detail = ZaakPayOrderDetailType {
            order_id: item.resource_common_data.connector_request_reference_id.clone(),
            amount: None, // Not required for status check
        };

        let check_data = ZaakPayCheckDataRequest {
            merchant_identifier: auth.merchant_identifier.peek().to_string(),
            mode: if item.resource_common_data.test_mode.unwrap_or(false) {
                "0".to_string()
            } else {
                "1".to_string()
            },
            order_detail,
            refund_detail: None,
        };

        let payload = serde_json::to_string(&check_data)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;
        let checksum = generate_checksum(&payload, auth.secret_key.peek());

        Ok(Self {
            data: check_data,
            checksum,
        })
    }
}

// Response transformation implementations
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

        let status = match response.response_code.as_str() {
            "100" => common_enums::AttemptStatus::Charged, // Success
            "101" => common_enums::AttemptStatus::AuthenticationPending, // Redirect required
            _ => common_enums::AttemptStatus::Failure, // Error
        };

        let redirection_data = if response.do_redirect == "1" && response.post_url.is_some() {
            Some(Box::new(RedirectForm::Form {
                endpoint: response.post_url.unwrap_or_default(),
                method: Method::Post,
                form_fields: response.bank_post_data
                    .unwrap_or_default()
                    .into_iter()
                    .map(|(k, v)| (k, v.to_string()))
                    .collect(),
            }))
        } else {
            None
        };

        let connector_request_reference_id = router_data.resource_common_data.connector_request_reference_id.clone();

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(connector_request_reference_id),
                redirection_data,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                status_code: http_code,
            }),
            ..router_data
        })
    }
}

// PSync response transformation
impl TryFrom<ResponseRouterData<ZaakPayPaymentsSyncResponse, Self>>
    for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
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

        // Get the first order's status
        let order_status = response.orders.first()
            .and_then(|order| order.txn_status.as_deref())
            .unwrap_or("pending");

        let status = match order_status {
            "success" => common_enums::AttemptStatus::Charged,
            "pending" => common_enums::AttemptStatus::Pending,
            "failure" => common_enums::AttemptStatus::Failure,
            _ => common_enums::AttemptStatus::Pending,
        };

        let connector_request_reference_id = router_data.resource_common_data.connector_request_reference_id.clone();
        let network_txn_id = response.orders.first()
            .and_then(|order| order.order_detail.as_ref())
            .and_then(|detail| detail.txnid.clone());

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(connector_request_reference_id),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                status_code: http_code,
            }),
            ..router_data
        })
    }
}