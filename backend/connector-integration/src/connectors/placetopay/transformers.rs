use common_utils::types::MinorUnit;
use domain_types::{
    connector_flow::{Authorize, Capture, CreateOrder, PSync, RSync, Void},
    connector_types::{
        PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData, PaymentVoidData,
        PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData, PaymentsSyncData,
        RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData, ResponseId,
    },
    errors::ConnectorError,
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes, RawCardNumber},
    router_data::ConnectorSpecificConfig,
    router_data_v2::RouterDataV2,
    utils,
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, PeekInterface, Secret};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

use crate::{connectors::placetopay::PlacetopayRouterData, types::ResponseRouterData};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlacetopayAuthType {
    pub(super) login: Secret<String>,
    pub(super) tran_key: Secret<String>,
}

impl TryFrom<&ConnectorSpecificConfig> for PlacetopayAuthType {
    type Error = ConnectorError;
    fn try_from(auth_type: &ConnectorSpecificConfig) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorSpecificConfig::Placetopay {
                login, tran_key, ..
            } => Ok(Self {
                login: login.to_owned(),
                tran_key: tran_key.to_owned(),
            }),
            _ => Err(ConnectorError::FailedToObtainAuthType),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlacetopayAuth {
    login: Secret<String>,
    tran_key: Secret<String>,
    nonce: Secret<String>,
    seed: String,
}

impl TryFrom<&ConnectorSpecificConfig> for PlacetopayAuth {
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(auth_type: &ConnectorSpecificConfig) -> Result<Self, Self::Error> {
        let placetopay_auth = PlacetopayAuthType::try_from(auth_type)?;

        let nonce_bytes = utils::generate_random_bytes(16);
        let now = common_utils::date_time::date_as_yyyymmddthhmmssmmmz()
            .change_context(ConnectorError::RequestEncodingFailed)?;
        let seed = format!("{}+00:00", now.split_at(now.len() - 5).0);

        let nonce_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            nonce_bytes.clone(),
        );

        let mut hasher = ring::digest::Context::new(&ring::digest::SHA256);
        hasher.update(&nonce_bytes);
        hasher.update(seed.as_bytes());
        hasher.update(placetopay_auth.tran_key.peek().as_bytes());
        let encoded_digest =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, hasher.finish());

        let nonce = Secret::new(nonce_b64);

        Ok(Self {
            login: placetopay_auth.login,
            tran_key: encoded_digest.into(),
            nonce,
            seed,
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlacetopayPaymentsRequest<
    T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize,
> {
    auth: PlacetopayAuth,
    payment: PlacetopayPayment,
    instrument: PlacetopayInstrument<T>,
    ip_address: Secret<String, common_utils::pii::IpAddress>,
    user_agent: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlacetopayPayment {
    reference: String,
    description: String,
    amount: PlacetopayAmount,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlacetopayAmount {
    currency: common_enums::Currency,
    total: MinorUnit,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlacetopayInstrument<
    T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize,
> {
    card: PlacetopayCard<T>,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PlacetopayCard<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> {
    number: RawCardNumber<T>,
    expiration: Secret<String>,
    cvv: Secret<String>,
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        PlacetopayRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for PlacetopayPaymentsRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: PlacetopayRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let browser_info = item.router_data.request.get_browser_info()?;
        let ip_address = browser_info.get_ip_address()?;
        let user_agent = browser_info.get_user_agent()?;
        let auth = PlacetopayAuth::try_from(&item.router_data.connector_config)?;
        let payment = PlacetopayPayment {
            reference: item
                .router_data
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            description: item.router_data.resource_common_data.get_description()?,
            amount: PlacetopayAmount {
                currency: item.router_data.request.currency,
                total: item.router_data.request.minor_amount,
            },
        };

        match item.router_data.request.payment_method_data.clone() {
            PaymentMethodData::Card(req_card) => {
                let card = PlacetopayCard {
                    number: req_card.card_number.clone(),
                    expiration: req_card
                        .clone()
                        .get_card_expiry_month_year_2_digit_with_delimiter("/".to_owned())?,
                    cvv: req_card.card_cvc.clone(),
                };
                Ok(Self {
                    ip_address,
                    user_agent,
                    auth,
                    payment,
                    instrument: PlacetopayInstrument {
                        card: card.to_owned(),
                    },
                })
            }
            PaymentMethodData::Wallet(_)
            | PaymentMethodData::CardRedirect(_)
            | PaymentMethodData::PayLater(_)
            | PaymentMethodData::BankRedirect(_)
            | PaymentMethodData::BankDebit(_)
            | PaymentMethodData::BankTransfer(_)
            | PaymentMethodData::Crypto(_)
            | PaymentMethodData::MandatePayment
            | PaymentMethodData::Reward
            | PaymentMethodData::RealTimePayment(_)
            | PaymentMethodData::MobilePayment(_)
            | PaymentMethodData::Upi(_)
            | PaymentMethodData::Voucher(_)
            | PaymentMethodData::GiftCard(_)
            | PaymentMethodData::OpenBanking(_)
            | PaymentMethodData::CardToken(_)
            | PaymentMethodData::NetworkToken(_)
            | PaymentMethodData::CardDetailsForNetworkTransactionId(_) => {
                Err(ConnectorError::NotImplemented(
                    utils::get_unimplemented_payment_method_error_message("Placetopay"),
                )
                .into())
            }
        }
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        PlacetopayRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    > for PlacetopayNextActionRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: PlacetopayRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = PlacetopayAuth::try_from(&item.router_data.connector_config)?;
        let internal_reference = item
            .router_data
            .request
            .connector_transaction_id
            .parse::<u64>()
            .change_context(ConnectorError::RequestEncodingFailed)?;
        let action = PlacetopayNextAction::Void;
        Ok(Self {
            auth,
            internal_reference,
            action,
        })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PlacetopayTransactionStatus {
    Ok,
    Failed,
    Approved,
    Rejected,
    Pending,
    PendingValidation,
    PendingProcess,
    Error,
}

impl From<PlacetopayTransactionStatus> for common_enums::AttemptStatus {
    fn from(item: PlacetopayTransactionStatus) -> Self {
        match item {
            PlacetopayTransactionStatus::Approved | PlacetopayTransactionStatus::Ok => {
                Self::Charged
            }
            PlacetopayTransactionStatus::Failed
            | PlacetopayTransactionStatus::Rejected
            | PlacetopayTransactionStatus::Error => Self::Failure,
            PlacetopayTransactionStatus::Pending
            | PlacetopayTransactionStatus::PendingValidation
            | PlacetopayTransactionStatus::PendingProcess => Self::Pending,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlacetopayStatusResponse {
    status: PlacetopayTransactionStatus,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlacetopayPaymentsResponse {
    status: PlacetopayStatusResponse,
    internal_reference: u64,
    authorization: Option<Secret<String>>,
}

// Authorize flow uses the unified payment response handling with capture method consideration
impl<F, T> TryFrom<ResponseRouterData<PlacetopayPaymentsResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, T, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<PlacetopayPaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            resource_common_data: PaymentFlowData {
                status: common_enums::AttemptStatus::from(item.response.status.status),
                ..item.router_data.resource_common_data
            },
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    item.response.internal_reference.to_string(),
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: item
                    .response
                    .authorization
                    .clone()
                    .map(|authorization| serde_json::json!(authorization)),
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlacetopayPsyncRequest {
    auth: PlacetopayAuth,
    internal_reference: u64,
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        PlacetopayRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    > for PlacetopayPsyncRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: PlacetopayRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = PlacetopayAuth::try_from(&item.router_data.connector_config)?;

        let internal_reference = item
            .router_data
            .request
            .get_connector_transaction_id()?
            .parse::<u64>()
            .change_context(ConnectorError::RequestEncodingFailed)?;

        Ok(Self {
            auth,
            internal_reference,
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlacetopayNextActionRequest {
    auth: PlacetopayAuth,
    internal_reference: u64,
    action: PlacetopayNextAction,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PlacetopayNextAction {
    Refund,
    Reverse,
    Void,
    Process,
    Checkout,
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        PlacetopayRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    > for PlacetopayNextActionRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: PlacetopayRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = PlacetopayAuth::try_from(&item.router_data.connector_config)?;
        let internal_reference = item
            .router_data
            .request
            .get_connector_transaction_id()
            .change_context(ConnectorError::RequestEncodingFailed)?
            .parse::<u64>()
            .change_context(ConnectorError::RequestEncodingFailed)?;
        let action = PlacetopayNextAction::Checkout;
        Ok(Self {
            auth,
            internal_reference,
            action,
        })
    }
}

// REFUND TYPES
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlacetopayRefundRequest {
    auth: PlacetopayAuth,
    internal_reference: u64,
    action: PlacetopayNextAction,
    authorization: Option<Secret<String>>,
}

impl<F, T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        PlacetopayRouterData<RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>, T>,
    > for PlacetopayRefundRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: PlacetopayRouterData<
            RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        if item.router_data.request.minor_refund_amount
            == item.router_data.request.minor_payment_amount
        {
            let auth = PlacetopayAuth::try_from(&item.router_data.connector_config)?;

            let internal_reference = item
                .router_data
                .request
                .connector_transaction_id
                .parse::<u64>()
                .change_context(ConnectorError::RequestEncodingFailed)?;
            let action = PlacetopayNextAction::Reverse;
            let authorization = match item.router_data.request.connector_feature_data.clone() {
                Some(metadata) => metadata.expose().as_str().map(|auth| auth.to_string()),
                None => None,
            };
            Ok(Self {
                auth,
                internal_reference,
                action,
                authorization: authorization.map(Secret::new),
            })
        } else {
            Err(ConnectorError::NotSupported {
                message: "Partial Refund".to_string(),
                connector: "placetopay",
            }
            .into())
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PlacetopayRefundStatus {
    Ok,
    Failed,
    Approved,
    Rejected,
    Pending,
    PendingValidation,
    PendingProcess,
    Refunded,
    Error,
}

impl From<PlacetopayRefundStatus> for common_enums::RefundStatus {
    fn from(item: PlacetopayRefundStatus) -> Self {
        match item {
            PlacetopayRefundStatus::Ok
            | PlacetopayRefundStatus::Approved
            | PlacetopayRefundStatus::Refunded => Self::Success,
            PlacetopayRefundStatus::Failed
            | PlacetopayRefundStatus::Rejected
            | PlacetopayRefundStatus::Error => Self::Failure,
            PlacetopayRefundStatus::Pending
            | PlacetopayRefundStatus::PendingProcess
            | PlacetopayRefundStatus::PendingValidation => Self::Pending,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlacetopayRefundStatusResponse {
    status: PlacetopayRefundStatus,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlacetopayRefundResponse {
    status: PlacetopayRefundStatusResponse,
    internal_reference: u64,
}

impl<F> TryFrom<ResponseRouterData<PlacetopayRefundResponse, Self>>
    for RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<PlacetopayRefundResponse, Self>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.internal_reference.to_string(),
                refund_status: common_enums::RefundStatus::from(item.response.status.status),
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlacetopayRsyncRequest {
    auth: PlacetopayAuth,
    internal_reference: u64,
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        PlacetopayRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    > for PlacetopayRsyncRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: PlacetopayRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = PlacetopayAuth::try_from(&item.router_data.connector_config)?;
        let internal_reference = item
            .router_data
            .request
            .connector_transaction_id
            .parse::<u64>()
            .change_context(ConnectorError::RequestEncodingFailed)?;
        Ok(Self {
            auth,
            internal_reference,
        })
    }
}

impl<F> TryFrom<ResponseRouterData<PlacetopayRefundResponse, Self>>
    for RouterDataV2<F, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<PlacetopayRefundResponse, Self>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.internal_reference.to_string(),
                refund_status: common_enums::RefundStatus::from(item.response.status.status),
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlacetopayErrorResponse {
    pub status: PlacetopayError,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlacetopayError {
    pub status: PlacetopayErrorStatus,
    pub message: Option<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PlacetopayErrorStatus {
    Failed,
}

// OrderCreate flow types and implementations

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlacetopayOrderCreateRequest {
    pub locale: String,
    pub auth: PlacetopayAuth,
    pub payment: PlacetopayOrderPayment,
    pub expiration: String,
    pub return_url: String,
    pub cancel_url: String,
    pub skip_result: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlacetopayOrderPayment {
    pub reference: String,
    pub description: String,
    pub amount: PlacetopayOrderAmount,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlacetopayOrderAmount {
    pub currency: common_enums::Currency,
    pub total: f64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlacetopayOrderCreateResponse {
    pub status: PlacetopayOrderStatus,
    pub request_id: u64,
    pub process_url: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlacetopayOrderStatus {
    pub status: String,
    pub reason: Option<String>,
    pub message: Option<String>,
    pub date: String,
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        PlacetopayRouterData<
            RouterDataV2<
                CreateOrder,
                PaymentFlowData,
                PaymentCreateOrderData,
                PaymentCreateOrderResponse,
            >,
            T,
        >,
    > for PlacetopayOrderCreateRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: PlacetopayRouterData<
            RouterDataV2<
                CreateOrder,
                PaymentFlowData,
                PaymentCreateOrderData,
                PaymentCreateOrderResponse,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = PlacetopayAuth::try_from(&item.router_data.connector_config)?;

        let now = common_utils::date_time::now();
        let expiration = now
            + time::Duration::minutes(
                item.router_data
                    .request
                    .metadata
                    .as_ref()
                    .and_then(|m| {
                        m.clone()
                            .expose()
                            .get("expiration_minutes")
                            .and_then(|v| v.as_u64())
                    })
                    .unwrap_or(30) as i64,
            );
        let expiration_str = expiration.to_string();

        let total = item.router_data.request.amount.get_amount_as_i64() as f64 / 100.0; // Convert minor unit to major unit

        let payment = PlacetopayOrderPayment {
            reference: item
                .router_data
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            description: item
                .router_data
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            amount: PlacetopayOrderAmount {
                currency: item.router_data.request.currency,
                total,
            },
        };

        let return_url = item
            .router_data
            .request
            .metadata
            .as_ref()
            .and_then(|m| {
                m.clone()
                    .expose()
                    .get("return_url")
                    .and_then(|v| v.as_str())
                    .map(String::from)
            })
            .unwrap_or_else(|| "https://example.com/return".to_string());

        let cancel_url = item
            .router_data
            .request
            .metadata
            .as_ref()
            .and_then(|m| {
                m.clone()
                    .expose()
                    .get("cancel_url")
                    .and_then(|v| v.as_str())
                    .map(String::from)
            })
            .unwrap_or_else(|| "https://example.com/cancel".to_string());

        Ok(Self {
            locale: "en_US".to_string(),
            auth,
            payment,
            expiration: expiration_str,
            return_url,
            cancel_url,
            skip_result: false,
        })
    }
}

impl TryFrom<ResponseRouterData<PlacetopayOrderCreateResponse, Self>>
    for RouterDataV2<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    >
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<PlacetopayOrderCreateResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let order_id = item.response.request_id.to_string();
        let _process_url = item.response.process_url.clone();

        let status = match item.response.status.status.as_str() {
            "OK" => common_enums::AttemptStatus::Pending,
            "APPROVED" => common_enums::AttemptStatus::Pending,
            "PENDING" => common_enums::AttemptStatus::Pending,
            _ => common_enums::AttemptStatus::Failure,
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            response: Ok(PaymentCreateOrderResponse {
                order_id,
                session_token: None,
            }),
            ..item.router_data
        })
    }
}
