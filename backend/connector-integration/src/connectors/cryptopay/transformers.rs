use domain_types::{
    connector_flow::Authorize,
    connector_types::{
        PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, ResponseId,
    },
};

use crate::connectors::cryptopay::CryptopayRouterData;
use crate::types::ResponseRouterData;
use common_utils::{
    pii,
    types::{AmountConvertor, StringMajorUnit, StringMajorUnitForConnector},
};
use error_stack::ResultExt;
use url::Url;

use domain_types::{
    payment_method_data::PaymentMethodData,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
    utils::{get_unimplemented_payment_method_error_message, is_payment_failure},
};

use domain_types::errors::{self, ConnectorError};

use common_utils::consts;

use serde::{Deserialize, Serialize};

use hyperswitch_masking::Secret;

#[derive(Default, Debug, Serialize)]
pub struct CryptopayPaymentsRequest {
    price_amount: StringMajorUnit,
    price_currency: common_enums::Currency,
    pay_currency: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    network: Option<String>,
    success_redirect_url: Option<String>,
    unsuccess_redirect_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<pii::SecretSerdeValue>,
    custom_id: String,
}

impl
    TryFrom<
        CryptopayRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        >,
    > for CryptopayPaymentsRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: CryptopayRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let cryptopay_request = match item.router_data.request.payment_method_data {
            PaymentMethodData::Crypto(ref cryptodata) => {
                let pay_currency = cryptodata.get_pay_currency()?;
                let amount = item
                    .connector
                    .amount_converter
                    .convert(
                        item.router_data.request.minor_amount,
                        item.router_data.request.currency,
                    )
                    .change_context(ConnectorError::AmountConversionFailed)?;
                Ok(Self {
                    price_amount: amount,
                    price_currency: item.router_data.request.currency,
                    pay_currency,
                    network: cryptodata.network.to_owned(),
                    success_redirect_url: item.router_data.request.router_return_url.clone(),
                    unsuccess_redirect_url: item.router_data.request.router_return_url.clone(),
                    //Cryptopay only accepts metadata as Object. If any other type, payment will fail with error.
                    metadata: item.router_data.request.get_metadata_as_object(),
                    custom_id: item
                        .router_data
                        .resource_common_data
                        .connector_request_reference_id
                        .clone(),
                })
            }
            PaymentMethodData::Card(_)
            | PaymentMethodData::CardRedirect(_)
            | PaymentMethodData::Wallet(_)
            | PaymentMethodData::PayLater(_)
            | PaymentMethodData::BankRedirect(_)
            | PaymentMethodData::BankDebit(_)
            | PaymentMethodData::BankTransfer(_)
            | PaymentMethodData::MandatePayment
            | PaymentMethodData::Reward
            | PaymentMethodData::RealTimePayment(_)
            | PaymentMethodData::Upi(_)
            | PaymentMethodData::MobilePayment(_)
            | PaymentMethodData::Voucher(_)
            | PaymentMethodData::GiftCard(_)
            | PaymentMethodData::OpenBanking(_)
            | PaymentMethodData::CardToken(_)
            | PaymentMethodData::NetworkToken(_)
            | PaymentMethodData::CardDetailsForNetworkTransactionId(_) => {
                Err(errors::ConnectorError::NotImplemented(
                    get_unimplemented_payment_method_error_message("CryptoPay"),
                ))
            }
        }?;
        Ok(cryptopay_request)
    }
}

// Auth Struct
pub struct CryptopayAuthType {
    pub(super) api_key: Secret<String>,
    pub(super) api_secret: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for CryptopayAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        if let ConnectorAuthType::BodyKey { api_key, key1 } = auth_type {
            Ok(Self {
                api_key: api_key.to_owned(),
                api_secret: key1.to_owned(),
            })
        } else {
            Err(errors::ConnectorError::FailedToObtainAuthType.into())
        }
    }
}
// PaymentsResponse
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CryptopayPaymentStatus {
    New,
    Completed,
    Unresolved,
    Refunded,
    Cancelled,
}

impl From<CryptopayPaymentStatus> for common_enums::AttemptStatus {
    fn from(item: CryptopayPaymentStatus) -> Self {
        match item {
            CryptopayPaymentStatus::New => Self::AuthenticationPending,
            CryptopayPaymentStatus::Completed => Self::Charged,
            CryptopayPaymentStatus::Cancelled => Self::Failure,
            CryptopayPaymentStatus::Unresolved | CryptopayPaymentStatus::Refunded => {
                Self::Unresolved
            } //mapped refunded to Unresolved because refund api is not available, also merchant has done the action on the connector dashboard.
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CryptopayPaymentsResponse {
    pub data: CryptopayPaymentResponseData,
}

impl<F> TryFrom<ResponseRouterData<CryptopayPaymentsResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<CryptopayPaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response: cryptopay_response,
            router_data,
            http_code,
        } = item;
        let status = common_enums::AttemptStatus::from(cryptopay_response.data.status.clone());
        let response = if is_payment_failure(status) {
            let payment_response = &cryptopay_response.data;
            Err(ErrorResponse {
                code: payment_response
                    .name
                    .clone()
                    .unwrap_or(consts::NO_ERROR_CODE.to_string()),
                message: payment_response
                    .status_context
                    .clone()
                    .unwrap_or(consts::NO_ERROR_MESSAGE.to_string()),
                reason: payment_response.status_context.clone(),
                status_code: item.http_code,
                attempt_status: None,
                connector_transaction_id: Some(payment_response.id.clone()),
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
                raw_connector_response: None,
            })
        } else {
            let redirection_data = cryptopay_response
                .data
                .hosted_page_url
                .map(|x| RedirectForm::from((x, common_utils::request::Method::Get)));
            Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(cryptopay_response.data.id.clone()),
                redirection_data: redirection_data.map(Box::new),
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: cryptopay_response
                    .data
                    .custom_id
                    .or(Some(cryptopay_response.data.id)),
                incremental_authorization_allowed: None,
                raw_connector_response: None,
                status_code: Some(http_code),
            })
        };
        let amount_captured_in_minor_units = match cryptopay_response.data.price_amount {
            Some(ref amount) => Some(
                StringMajorUnitForConnector
                    .convert_back(amount.clone(), router_data.request.currency)
                    .change_context(errors::ConnectorError::AmountConversionFailed)?,
            ),
            None => None,
        };
        match amount_captured_in_minor_units {
            Some(minor_amount) => {
                let amount_captured = Some(minor_amount.get_amount_as_i64());
                Ok(Self {
                    resource_common_data: PaymentFlowData {
                        status,
                        amount_captured,
                        minor_amount_captured: amount_captured_in_minor_units,
                        ..router_data.resource_common_data
                    },
                    response,
                    ..router_data
                })
            }
            None => Ok(Self {
                resource_common_data: PaymentFlowData {
                    status,
                    ..router_data.resource_common_data
                },
                response,
                ..router_data
            }),
        }
    }
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct CryptopayErrorData {
    pub code: String,
    pub message: String,
    pub reason: Option<String>,
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct CryptopayErrorResponse {
    pub error: CryptopayErrorData,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CryptopayPaymentResponseData {
    pub id: String,
    pub custom_id: Option<String>,
    pub customer_id: Option<String>,
    pub status: CryptopayPaymentStatus,
    pub status_context: Option<String>,
    pub address: Option<Secret<String>>,
    pub network: Option<String>,
    pub uri: Option<String>,
    pub price_amount: Option<StringMajorUnit>,
    pub price_currency: Option<String>,
    pub pay_amount: Option<StringMajorUnit>,
    pub pay_currency: Option<String>,
    pub fee: Option<String>,
    pub fee_currency: Option<String>,
    pub paid_amount: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub success_redirect_url: Option<String>,
    pub unsuccess_redirect_url: Option<String>,
    pub hosted_page_url: Option<Url>,
    pub created_at: Option<String>,
    pub expires_at: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CryptopayWebhookDetails {
    #[serde(rename = "type")]
    pub service_type: String,
    pub event: WebhookEvent,
    pub data: CryptopayPaymentResponseData,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebhookEvent {
    TransactionCreated,
    TransactionConfirmed,
    StatusChanged,
}

impl<F> TryFrom<ResponseRouterData<CryptopayPaymentsResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<CryptopayPaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response: cryptopay_response,
            router_data,
            http_code,
        } = item;
        let status = common_enums::AttemptStatus::from(cryptopay_response.data.status.clone());
        let response = if is_payment_failure(status) {
            let payment_response = &cryptopay_response.data;
            Err(ErrorResponse {
                code: payment_response
                    .name
                    .clone()
                    .unwrap_or(consts::NO_ERROR_CODE.to_string()),
                message: payment_response
                    .status_context
                    .clone()
                    .unwrap_or(consts::NO_ERROR_MESSAGE.to_string()),
                reason: payment_response.status_context.clone(),
                status_code: item.http_code,
                attempt_status: None,
                connector_transaction_id: Some(payment_response.id.clone()),
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
                raw_connector_response: None,
            })
        } else {
            let redirection_data = cryptopay_response
                .data
                .hosted_page_url
                .map(|x| RedirectForm::from((x, common_utils::request::Method::Get)));
            Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(cryptopay_response.data.id.clone()),
                redirection_data: redirection_data.map(Box::new),
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: cryptopay_response
                    .data
                    .custom_id
                    .or(Some(cryptopay_response.data.id)),
                incremental_authorization_allowed: None,
                raw_connector_response: None,
                status_code: Some(http_code),
            })
        };
        let amount_captured_in_minor_units = match cryptopay_response.data.price_amount {
            Some(ref amount) => Some(
                StringMajorUnitForConnector
                    .convert_back(amount.clone(), router_data.request.currency)
                    .change_context(errors::ConnectorError::AmountConversionFailed)?,
            ),
            None => None,
        };
        match amount_captured_in_minor_units {
            Some(minor_amount) => {
                let amount_captured = Some(minor_amount.get_amount_as_i64());
                Ok(Self {
                    resource_common_data: PaymentFlowData {
                        status,
                        amount_captured,
                        minor_amount_captured: amount_captured_in_minor_units,
                        ..router_data.resource_common_data
                    },
                    response,
                    ..router_data
                })
            }
            None => Ok(Self {
                resource_common_data: PaymentFlowData {
                    status,
                    ..router_data.resource_common_data
                },
                response,
                ..router_data
            }),
        }
    }
}
