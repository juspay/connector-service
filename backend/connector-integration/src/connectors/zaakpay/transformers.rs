use std::collections::HashMap;

use common_utils::{
    errors::CustomResult, request::Method, types::StringMinorUnit,
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
};
use error_stack::ResultExt;
use hyperswitch_masking::{Secret, ExposeInterface};
use serde::{Deserialize, Serialize};

use crate::{connectors::zaakpay::ZaakPayRouterData, types::ResponseRouterData};

// Authentication types for ZaakPay
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZaakPayAuth {
    pub merchant_identifier: Secret<String>,
    pub secret_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for ZaakPayAuth {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey { api_key, key1, api_secret: _ } => Ok(Self {
                merchant_identifier: api_key.clone(),
                secret_key: key1.clone(),
            }),
            ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self {
                merchant_identifier: api_key.clone(),
                secret_key: key1.clone(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

// Request types based on Haskell implementation

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

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayOrderDetailTransType {
    pub order_id: String,
    pub amount: String,
    pub currency: String,
    pub product_description: String,
    pub email: String,
    pub phone: String,
    pub txnid: Option<String>, // Add missing field
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

// Sync request types
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

// Response types based on Haskell implementation

#[derive(Debug, Deserialize, Clone, Serialize)]
#[serde(untagged)]
pub enum ZaakPayPaymentsResponse {
    Success(ZaakPayTransactResponse),
    Error(ZaakPayErrorResponse),
}

#[derive(Debug, Deserialize, Clone, Serialize)]
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

#[derive(Debug, Deserialize, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayPaymentInstrumentResType {
    pub payment_mode: String,
    pub card: Option<ZaakPayCardResType>,
    pub netbanking: Option<ZaakPayNetBankingRespType>,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
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

#[derive(Debug, Deserialize, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayNetBankingRespType {
    pub bankid: String,
    pub bank_name: Option<String>,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayErrorResponse {
    pub error_code: String,
    pub error_description: String,
}

// Sync response types
#[derive(Debug, Deserialize, Clone, Serialize)]
#[serde(untagged)]
pub enum ZaakPayPaymentsSyncResponse {
    Success(ZaakPayCheckResponse),
    Error(ZaakPayErrorResponse),
}

#[derive(Debug, Deserialize, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayCheckResponse {
    pub merchant_identifier: String,
    pub orders: Vec<ZaakPayOrderDetailsResponse>,
    pub version: String,
    pub success: Option<bool>,
    pub checksum: Option<String>,
    pub partial_refund_amt: Option<String>,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
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

#[derive(Debug, Deserialize, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayRefundDetails {
    pub amount: String,
    pub arn: Option<String>,
    pub merchant_ref_id: Option<String>,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
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

#[derive(Debug, Deserialize, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayPaymentinstrumentType {
    pub payment_mode: Option<String>,
    pub card: Option<ZaakPayCardType>,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
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

// Status mapping
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ZaakPayTransactionStatus {
    Success,
    Pending,
    Failure,
    #[serde(other)]
    Unknown,
}

impl From<ZaakPayTransactionStatus> for common_enums::AttemptStatus {
    fn from(item: ZaakPayTransactionStatus) -> Self {
        match item {
            ZaakPayTransactionStatus::Success => Self::Charged,
            ZaakPayTransactionStatus::Pending => Self::AuthenticationPending,
            ZaakPayTransactionStatus::Failure => Self::Failure,
            ZaakPayTransactionStatus::Unknown => Self::AuthenticationPending,
        }
    }
}

impl From<&str> for ZaakPayTransactionStatus {
    fn from(status: &str) -> Self {
        match status {
            "100" | "success" => Self::Success,
            "001" | "pending" => Self::Pending,
            "000" | "failure" => Self::Failure,
            _ => Self::Unknown,
        }
    }
}

// Request conversion implementations

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<ZaakPayRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>>
    for ZaakPayPaymentsRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ZaakPayRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let auth = ZaakPayAuth::try_from(&item.router_data.connector_auth_type)?;
        
        let customer_id = item.router_data.resource_common_data.get_customer_id()?;
        let return_url = item.router_data.request.get_router_return_url()?;
        
        // Use amount converter to get the amount in the correct format
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        // Extract email from request
        let email = item.router_data.request.email.clone()
            .map(|e| e.to_string())
            .unwrap_or_else(|| format!("{}@example.com", customer_id.get_string_repr()));
        
        let phone = "9999999999".to_string(); // Default phone number

        // Create billing address (using default values)
        let billing_address = ZaakPayBillingAddressType {
            address: "Default Address".to_string(),
            city: "Default City".to_string(),
            state: "Default State".to_string(),
            country: "IN".to_string(),
            pincode: Secret::new("110001".to_string()),
        };

        // Create payment instrument based on payment method type
        let payment_instrument = match item.router_data.request.payment_method_type {
            Some(common_enums::PaymentMethodType::UpiCollect) => {
                ZaakPayPaymentInstrumentTransType {
                    payment_mode: "UPI".to_string(),
                    card: None,
                    netbanking: None,
                    upi: Some(ZaakPayUpiTransType {
                        bankid: "default".to_string(), // Will be populated from payment method data
                    }),
                }
            },
            Some(common_enums::PaymentMethodType::NetbankingRedirect) => {
                ZaakPayPaymentInstrumentTransType {
                    payment_mode: "NB".to_string(),
                    card: None,
                    netbanking: Some(ZaakPayNetTransType {
                        bankid: "default".to_string(), // Will be populated from payment method data
                        bank_name: "Default Bank".to_string(),
                    }),
                    upi: None,
                }
            },
            _ => {
                return Err(errors::ConnectorError::NotImplemented(
                    "Payment method not supported by ZaakPay".to_string()
                ).into());
            }
        };

        // Create order detail
        let order_detail = ZaakPayOrderDetailTransType {
            order_id: item.router_data.resource_common_data.connector_request_reference_id.clone(),
            amount: amount.to_string(),
            currency: item.router_data.request.currency.to_string(),
            product_description: "Payment".to_string(),
            email: email.clone(),
            phone,
            txnid: None,
        };

        // Create transact data request
        let transact_data = ZaakPayTransactDataRequest {
            merchant_identifier: auth.merchant_identifier.expose().clone(),
            encryption_key_id: None,
            show_mobile: None,
            mode: if item.router_data.resource_common_data.test_mode.unwrap_or(false) {
                "TEST".to_string()
            } else {
                "LIVE".to_string()
            },
            return_url: return_url.to_string(),
            order_detail,
            billing_address,
            shipping_address: None, // Optional shipping address
            payment_instrument,
        };

        // Generate checksum (simplified - in real implementation, this would use proper checksum algorithm)
        let checksum = generate_checksum(&transact_data, &auth.secret_key)?;

        Ok(Self {
            data: transact_data,
            checksum,
        })
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<ZaakPayRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>>
    for ZaakPayPaymentsSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ZaakPayRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let auth = ZaakPayAuth::try_from(&item.router_data.connector_auth_type)?;
        
        let order_detail = ZaakPayOrderDetailType {
            order_id: item.router_data.request.connector_transaction_id
                .get_connector_transaction_id()
                .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?,
            amount: None, // Amount is optional for check requests
        };

        let check_data = ZaakPayCheckDataRequest {
            merchant_identifier: auth.merchant_identifier.expose().clone(),
            mode: if item.router_data.resource_common_data.test_mode.unwrap_or(false) {
                "TEST".to_string()
            } else {
                "LIVE".to_string()
            },
            order_detail,
            refund_detail: None, // Not implementing refunds in this migration
        };

        // Generate checksum
        let checksum = generate_checksum_check(&check_data, &auth.secret_key)?;

        Ok(Self {
            data: check_data,
            checksum,
        })
    }
}

// Response conversion implementations

impl<F, T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<ResponseRouterData<ZaakPayPaymentsResponse, Self>>
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
            ZaakPayPaymentsResponse::Success(success_response) => {
                let transaction_status = ZaakPayTransactionStatus::from(success_response.response_code.as_str());
                
                if success_response.do_redirect == "1" {
                    // Redirect case
                    let redirect_form = RedirectForm::Form {
                        endpoint: success_response.post_url.unwrap_or_else(|| "https://api.zaakpay.com".to_string()),
                        method: Method::Post,
                        form_fields: success_response.bank_post_data
                            .unwrap_or_default()
                            .into_iter()
                            .map(|(k, v)| (k, v.to_string()))
                            .collect(),
                    };

                    (
                        common_enums::AttemptStatus::AuthenticationPending,
                        Ok(PaymentsResponseData::TransactionResponse {
                            resource_id: ResponseId::ConnectorTransactionId(
                                router_data.resource_common_data.connector_request_reference_id.clone(),
                            ),
                            redirection_data: Some(Box::new(redirect_form)),
                            mandate_reference: None,
                            connector_metadata: None,
                            network_txn_id: success_response.order_detail.txnid,
                            connector_response_reference_id: None,
                            incremental_authorization_allowed: None,
                            status_code: http_code,
                        }),
                    )
                } else {
                    // Non-redirect case
                    (
                        transaction_status.into(),
                        Ok(PaymentsResponseData::TransactionResponse {
                            resource_id: ResponseId::ConnectorTransactionId(
                                router_data.resource_common_data.connector_request_reference_id.clone(),
                            ),
                            redirection_data: None,
                            mandate_reference: None,
                            connector_metadata: None,
                            network_txn_id: success_response.order_detail.txnid,
                            connector_response_reference_id: None,
                            incremental_authorization_allowed: None,
                            status_code: http_code,
                        }),
                    )
                }
            },
            ZaakPayPaymentsResponse::Error(error_response) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: error_response.error_code,
                    status_code: http_code,
                    message: error_response.error_description.clone(),
                    reason: Some(error_response.error_description),
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

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<ResponseRouterData<ZaakPayPaymentsSyncResponse, Self>>
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

        let (status, response) = match response {
            ZaakPayPaymentsSyncResponse::Success(success_response) => {
                // Get the first order from the response
                if let Some(order) = success_response.orders.first() {
                    let transaction_status = ZaakPayTransactionStatus::from(order.response_code.as_str());
                    
                    (
                        transaction_status.into(),
                        Ok(PaymentsResponseData::TransactionResponse {
                            resource_id: ResponseId::ConnectorTransactionId(
                                router_data.request.connector_transaction_id.get_connector_transaction_id()
                                    .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?,
                            ),
                            redirection_data: None,
                            mandate_reference: None,
                            connector_metadata: None,
                            network_txn_id: order.order_detail.as_ref()
                                .and_then(|od| od.txnid.clone()),
                            connector_response_reference_id: None,
                            incremental_authorization_allowed: None,
                            status_code: http_code,
                        }),
                    )
                } else {
                    (
                        common_enums::AttemptStatus::Failure,
                        Err(ErrorResponse {
                            code: "NO_ORDERS".to_string(),
                            status_code: http_code,
                            message: "No orders found in response".to_string(),
                            reason: Some("No orders found in response".to_string()),
                            attempt_status: None,
                            connector_transaction_id: None,
                            network_advice_code: None,
                            network_decline_code: None,
                            network_error_message: None,
                        }),
                    )
                }
            },
            ZaakPayPaymentsSyncResponse::Error(error_response) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: error_response.error_code,
                    status_code: http_code,
                    message: error_response.error_description.clone(),
                    reason: Some(error_response.error_description),
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

// Helper functions

fn generate_checksum(
    transact_data: &ZaakPayTransactDataRequest,
    secret_key: &Secret<String>,
) -> CustomResult<String, ConnectorError> {
    // In a real implementation, this would generate a proper checksum using the secret key
    // For now, we'll return a placeholder checksum
    let data_string = format!(
        "{}{}{}{}",
        transact_data.merchant_identifier,
        transact_data.order_detail.order_id,
        transact_data.order_detail.amount,
        secret_key.expose()
    );
    
    // Simple hash for demonstration - in production, use proper SHA256 with salt
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    let mut hasher = DefaultHasher::new();
    data_string.hash(&mut hasher);
    Ok(format!("{:x}", hasher.finish()))
}

fn generate_checksum_check(
    check_data: &ZaakPayCheckDataRequest,
    secret_key: &Secret<String>,
) -> CustomResult<String, ConnectorError> {
    // In a real implementation, this would generate a proper checksum using the secret key
    let data_string = format!(
        "{}{}{}",
        check_data.merchant_identifier,
        check_data.order_detail.order_id,
        secret_key.expose()
    );
    
    // Simple hash for demonstration - in production, use proper SHA256 with salt
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    let mut hasher = DefaultHasher::new();
    data_string.hash(&mut hasher);
    Ok(format!("{:x}", hasher.finish()))
}