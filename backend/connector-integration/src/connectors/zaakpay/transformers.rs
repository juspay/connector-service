use std::collections::HashMap;

use common_utils::{
    errors::CustomResult, ext_traits::ValueExt, request::Method, types::StringMinorUnit,
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
use hyperswitch_masking::{Mask, Maskable, Secret};
use serde::{Deserialize, Serialize};

use crate::{connectors::zaakpay::ZaakPayRouterData, types::ResponseRouterData};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayPaymentsRequest {
    pub data: ZaakPayTransactDataRequest,
    pub checksum: String,
}

#[derive(Debug, Clone, Serialize)]
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

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayOrderDetailTransType {
    pub order_id: String,
    pub amount: String,
    pub currency: String,
    pub product_description: String,
    pub email: String,
    pub phone: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayBillingAddressType {
    pub address: String,
    pub city: String,
    pub state: String,
    pub country: String,
    pub pincode: Secret<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayShippingAddressType {
    pub address: Option<String>,
    pub city: Option<String>,
    pub state: Option<String>,
    pub country: Option<String>,
    pub pincode: Option<Secret<String>>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayPaymentInstrumentTransType {
    pub payment_mode: String,
    pub card: Option<ZaakPayCardTransType>,
    pub netbanking: Option<ZaakPayNetTransType>,
    pub upi: Option<ZaakPayUpiTransType>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ZaakPayCardTransType;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayNetTransType {
    pub bankid: String,
    pub bank_name: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayUpiTransType {
    pub bankid: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayPaymentsSyncRequest {
    pub data: ZaakPayCheckDataRequest,
    pub checksum: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayCheckDataRequest {
    pub merchant_identifier: String,
    pub mode: String,
    pub order_detail: ZaakPayOrderDetailType,
    pub refund_detail: Option<ZaakPayRefundDetail>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayOrderDetailType {
    pub order_id: String,
    pub amount: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayRefundDetail {
    pub merchant_ref_id: String,
}

// Response types
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ZaakPayPaymentsResponse {
    Success(ZaakPayTransactResponse),
    Error(ZaakPayErrorResponse),
}

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayPaymentInstrumentResType {
    pub payment_mode: String,
    pub card: Option<ZaakPayCardResType>,
    pub netbanking: Option<ZaakPayNetBankingRespType>,
}

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayNetBankingRespType {
    pub bankid: String,
    pub bank_name: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayPaymentsSyncResponse {
    pub merchant_identifier: String,
    pub orders: Vec<ZaakPayOrderDetailsResponse>,
    pub version: String,
    pub success: Option<bool>,
    pub checksum: Option<String>,
    pub partial_refund_amt: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayRefundDetails {
    pub amount: String,
    pub arn: Option<String>,
    pub merchant_ref_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayPaymentinstrumentType {
    pub payment_mode: Option<String>,
    pub card: Option<ZaakPayCardType>,
}

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaakPayErrorResponse {
    pub response_code: String,
    pub response_description: String,
}

// Auth types
#[derive(Debug, Clone, Deserialize)]
pub struct ZaakPayAuthType {
    pub merchant_identifier: Secret<String>,
    pub secret_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for ZaakPayAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey { api_key, api_secret, .. } => Ok(Self {
                merchant_identifier: api_key.clone(),
                secret_key: api_secret.clone(),
            }),
            ConnectorAuthType::HeaderKey { api_key } => Err(errors::ConnectorError::FailedToObtainAuthType
                .into_change_context("ZaakPay requires both merchant identifier and secret key")),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

// Helper functions
fn get_merchant_identifier(
    connector_auth_type: &ConnectorAuthType,
) -> Result<Secret<String>, errors::ConnectorError> {
    let auth = ZaakPayAuthType::try_from(connector_auth_type)?;
    Ok(auth.merchant_identifier)
}

fn get_secret_key(
    connector_auth_type: &ConnectorAuthType,
) -> Result<Secret<String>, errors::ConnectorError> {
    let auth = ZaakPayAuthType::try_from(connector_auth_type)?;
    Ok(auth.secret_key)
}

fn generate_checksum(data: &str, secret_key: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(format!("{}|{}", data, secret_key));
    format!("{:x}", hasher.finalize())
}

// Request conversions
impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + serde::Serialize,
> TryFrom<ZaakPayRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>>
    for ZaakPayPaymentsRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ZaakPayRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let auth = ZaakPayAuthType::try_from(&item.router_data.connector_auth_type)?;
        let merchant_identifier = auth.merchant_identifier.expose();
        let secret_key = auth.secret_key.expose();

        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        let order_id = item
            .router_data
            .resource_common_data
            .connector_request_reference_id
            .clone();

        let return_url = item.router_data.request.get_router_return_url()?;

        let email = item.router_data.request.email.clone().unwrap_or_else(|| Email::from(""));

        let phone = item
            .router_data
            .request
            .payment_method_data
            .as_ref()
            .and_then(|pm| pm.get_phone_number())
            .map(|p| p.to_string())
            .unwrap_or_else(|| "".to_string());

        let order_detail = ZaakPayOrderDetailTransType {
            order_id: order_id.clone(),
            amount: amount.get_amount_as_string(),
            currency: item.router_data.request.currency.to_string(),
            product_description: "Payment".to_string(),
            email: email.to_string(),
            phone,
        };

        let billing_address = ZaakPayBillingAddressType {
            address: item
                .router_data
                .request
                .billing_address
                .as_ref()
                .map(|addr| addr.address.to_string())
                .unwrap_or_else(|| "".to_string()),
            city: item
                .router_data
                .request
                .billing_address
                .as_ref()
                .map(|addr| addr.city.to_string())
                .unwrap_or_else(|| "".to_string()),
            state: item
                .router_data
                .request
                .billing_address
                .as_ref()
                .map(|addr| addr.state.to_string())
                .unwrap_or_else(|| "".to_string()),
            country: item
                .router_data
                .request
                .billing_address
                .as_ref()
                .map(|addr| addr.country.to_string())
                .unwrap_or_else(|| "".to_string()),
            pincode: Secret::new(
                item.router_data
                    .request
                    .billing_address
                    .as_ref()
                    .map(|addr| addr.zip.to_string())
                    .unwrap_or_else(|| "".to_string()),
            ),
        };

        let payment_instrument = match item.router_data.request.payment_method_type {
            Some(common_enums::PaymentMethodType::Upi) => {
                ZaakPayPaymentInstrumentTransType {
                    payment_mode: "upi".to_string(),
                    card: None,
                    netbanking: None,
                    upi: Some(ZaakPayUpiTransType {
                        bankid: "".to_string(), // Will be populated from payment method data
                    }),
                }
            }
            Some(common_enums::PaymentMethodType::NetBanking) => {
                ZaakPayPaymentInstrumentTransType {
                    payment_mode: "netbanking".to_string(),
                    card: None,
                    netbanking: Some(ZaakPayNetTransType {
                        bankid: "".to_string(), // Will be populated from payment method data
                        bank_name: "".to_string(),
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

        let transact_data = ZaakPayTransactDataRequest {
            merchant_identifier,
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

        let data_str = serde_json::to_string(&transact_data)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;

        let checksum = generate_checksum(&data_str, &secret_key);

        Ok(Self {
            data: transact_data,
            checksum,
        })
    }
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + serde::Serialize,
> TryFrom<ZaakPayRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>>
    for ZaakPayPaymentsSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ZaakPayRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let auth = ZaakPayAuthType::try_from(&item.router_data.connector_auth_type)?;
        let merchant_identifier = auth.merchant_identifier.expose();
        let secret_key = auth.secret_key.expose();

        let order_id = item
            .router_data
            .request
            .connector_transaction_id
            .get_connector_transaction_id()
            .map_err(|_| errors::ConnectorError::MissingRequiredField {
                field_name: "connector_transaction_id",
            })?;

        let order_detail = ZaakPayOrderDetailType {
            order_id,
            amount: None,
        };

        let check_data = ZaakPayCheckDataRequest {
            merchant_identifier,
            mode: if item.router_data.resource_common_data.test_mode.unwrap_or(false) {
                "0".to_string()
            } else {
                "1".to_string()
            },
            order_detail,
            refund_detail: None,
        };

        let data_str = serde_json::to_string(&check_data)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;

        let checksum = generate_checksum(&data_str, &secret_key);

        Ok(Self {
            data: check_data,
            checksum,
        })
    }
}

// Response conversions
impl<
    F,
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + serde::Serialize,
> TryFrom<ResponseRouterData<ZaakPayPaymentsResponse, RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>>
    for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<ZaakPayPaymentsResponse, RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let (status, response) = match response {
            ZaakPayPaymentsResponse::Success(success_data) => {
                let attempt_status = if success_data.response_code == "100" {
                    common_enums::AttemptStatus::Charged
                } else if success_data.response_code == "101" {
                    common_enums::AttemptStatus::AuthenticationPending
                } else {
                    common_enums::AttemptStatus::Failure
                };

                let redirection_data = if success_data.do_redirect == "1" {
                    if let Some(post_url) = &success_data.post_url {
                        Some(Box::new(RedirectForm::Form {
                            endpoint: post_url.clone(),
                            method: Method::Post,
                            form_fields: success_data
                                .bank_post_data
                                .clone()
                                .unwrap_or_default()
                                .into_iter()
                                .map(|(k, v)| (k, v.to_string()))
                                .collect(),
                        }))
                    } else {
                        None
                    }
                } else {
                    None
                };

                (
                    attempt_status,
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(
                            router_data
                                .resource_common_data
                                .connector_request_reference_id
                                .clone(),
                        ),
                        redirection_data,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: success_data
                            .order_detail
                            .order_id
                            .parse::<i64>()
                            .ok()
                            .map(|id| id.to_string()),
                        connector_response_reference_id: None,
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                    }),
                )
            }
            ZaakPayPaymentsResponse::Error(error_data) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: error_data.response_code.clone(),
                    status_code: http_code,
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

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + serde::Serialize,
> TryFrom<ResponseRouterData<ZaakPayPaymentsSyncResponse, RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>>
    for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<ZaakPayPaymentsSyncResponse, RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let order = response.orders.first().ok_or_else(|| {
            errors::ConnectorError::ResponseDeserializationFailed
                .attach_printable("No order found in response")
        })?;

        let attempt_status = match order.response_code.as_str() {
            "100" => common_enums::AttemptStatus::Charged,
            "101" => common_enums::AttemptStatus::AuthenticationPending,
            "102" => common_enums::AttemptStatus::Failure,
            _ => common_enums::AttemptStatus::Pending,
        };

        let amount_received = order
            .order_detail
            .as_ref()
            .and_then(|od| od.amount.as_ref())
            .and_then(|amt| amt.parse::<f64>().ok())
            .map(|amt| {
                let minor_amount = (amt * 100.0).round() as i64;
                common_utils::types::MinorUnit::new(minor_amount)
            });

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status: attempt_status,
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