use crate::{connectors::hyperpg::HyperpgRouterData, types::ResponseRouterData};
use common_enums::{AttemptStatus, Currency, RefundStatus};
use domain_types::router_response_types::RedirectForm;
use common_utils::{id_type::CustomerId, types::MinorUnit};
use domain_types::{
    connector_flow::{Authorize, CreateOrder, PSync, RSync, Refund, Void, CreateConnectorCustomer},
    connector_types::{
        ConnectorCustomerData, ConnectorCustomerResponse,
        PaymentCreateOrderData, PaymentCreateOrderResponse,
        PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData, PaymentsResponseData,
        PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData,
        ResponseId,
    },
    errors,
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes, RawCardNumber},
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, PeekInterface, Secret};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone)]
pub struct HyperpgAuthType {
    pub username: Secret<String>,
    pub password: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for HyperpgAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self {
                username: api_key.to_owned(),
                password: key1.to_owned(),
            }),
            _other => Err(error_stack::report!(
                errors::ConnectorError::FailedToObtainAuthType
            )),
        }
    }
}

// ===== ERROR RESPONSE =====
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HyperpgErrorResponse {
    #[serde(rename = "error_code")]
    pub code: Option<String>,
    pub message: String,
    pub description: Option<String>,
}

// ===== STATUS ENUMS =====
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum HyperpgPaymentStatus {
    New,
    Pending,
    PendingVbv,
    Charged,
    Failed,
    Cancelled,
    Refunded,
    #[serde(other)]
    Unknown,
}

impl From<&HyperpgPaymentStatus> for AttemptStatus {
    fn from(status: &HyperpgPaymentStatus) -> Self {
        match status {
            HyperpgPaymentStatus::Charged => Self::Charged,
            HyperpgPaymentStatus::New
            | HyperpgPaymentStatus::Pending
            | HyperpgPaymentStatus::PendingVbv => Self::Pending,
            HyperpgPaymentStatus::Failed => Self::Failure,
            HyperpgPaymentStatus::Cancelled => Self::Voided,
            HyperpgPaymentStatus::Refunded => Self::Charged,
            HyperpgPaymentStatus::Unknown => Self::Pending,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum HyperpgRefundStatus {
    Pending,
    Success,
    Failed,
    #[serde(other)]
    Unknown,
}

impl From<&HyperpgRefundStatus> for RefundStatus {
    fn from(status: &HyperpgRefundStatus) -> Self {
        match status {
            HyperpgRefundStatus::Success => Self::Success,
            HyperpgRefundStatus::Pending => Self::Pending,
            HyperpgRefundStatus::Failed => Self::Failure,
            HyperpgRefundStatus::Unknown => Self::Pending,
        }
    }
}

// ===== REQUEST TYPES =====

#[derive(Debug, Serialize)]
pub struct HyperpgAuthorizeRequest {
    pub order_id: String,
    pub amount: f64,
    pub currency: String,
    pub customer_id: String,
    pub customer_email: Option<String>,
    pub customer_phone: Option<String>,
    pub description: Option<String>,
    pub return_url: Option<String>,
    pub payment_method_type: String,
    pub payment_method: Option<String>,
    pub card_number: Option<Secret<String>>,
    pub name_on_card: Option<String>,
    pub card_exp_month: Option<String>,
    pub card_exp_year: Option<String>,
    pub card_security_code: Option<Secret<String>>,
    pub save_to_locker: bool,
    pub tokenize: bool,
    pub redirect_after_payment: bool,
    pub format: String,
}

impl<T: PaymentMethodDataTypes + fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        HyperpgRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            T,
        >,
    > for HyperpgAuthorizeRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        wrapper: HyperpgRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = wrapper.router_data;

        let payment_method_data = router_data.request.payment_method_data.clone();

        let (payment_method_type, payment_method, card_number, name_on_card, card_exp_month, card_exp_year, card_security_code) =
            match payment_method_data {
                PaymentMethodData::Card(card) => {
                    let card_number = Some(Secret::new(card.card_number.peek().to_string()));
                    let card_exp_month = Some(card.card_exp_month.peek().clone());
                    let card_exp_year = Some(card.card_exp_year.peek().clone());
                    let card_security_code = Some(card.card_cvc.clone());
                    let name_on_card = card.card_holder_name.as_ref().map(|n| n.peek().clone());

                    let payment_method = match card.card_network {
                        Some(network) => Some(network.to_string()),
                        None => None,
                    };

                    ("CARD".to_string(), payment_method, card_number, name_on_card, card_exp_month, card_exp_year, card_security_code)
                }
                PaymentMethodData::Wallet(wallet) => {
                    return Err(error_stack::report!(errors::ConnectorError::NotSupported {
                        message: format!("{} wallet is not supported", format!("{:?}", wallet)),
                        connector: "hyperpg",
                    }));
                }
                PaymentMethodData::PayLater(_paylater) => {
                    return Err(error_stack::report!(errors::ConnectorError::NotSupported {
                        message: "PayLater payment method is not supported".to_string(),
                        connector: "hyperpg",
                    }));
                }
                PaymentMethodData::Voucher(_voucher) => {
                    return Err(error_stack::report!(errors::ConnectorError::NotSupported {
                        message: "Voucher payment method is not supported".to_string(),
                        connector: "hyperpg",
                    }));
                }
                _ => {
                    return Err(error_stack::report!(errors::ConnectorError::NotImplemented(
                        "This payment method is not implemented".to_string(),
                    )));
                }
            };

        let amount_minor = router_data.request.amount.get_amount_as_i64();
        let amount_major = amount_minor as f64 / 100.0;

        Ok(Self {
            order_id: router_data.resource_common_data.connector_request_reference_id.clone(),
            amount: amount_major,
            currency: router_data.request.currency.to_string(),
            customer_id: router_data.request.customer_id
                .as_ref()
                .map(|id| format!("{:?}", id))
                .unwrap_or_else(String::new),
            customer_email: router_data.request.email.as_ref().map(|e| e.peek().clone()),
            customer_phone: None,
            description: None,
            return_url: router_data.request.router_return_url.clone(),
            payment_method_type,
            payment_method,
            card_number,
            name_on_card,
            card_exp_month,
            card_exp_year,
            card_security_code,
            save_to_locker: false,
            tokenize: false,
            redirect_after_payment: false,
            format: "json".to_string(),
        })
    }
}

#[derive(Debug, Serialize)]
pub struct HyperpgVoidRequest {
    pub unique_request_id: String,
    pub amount: f64,
}

impl<T: PaymentMethodDataTypes + fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        HyperpgRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    > for HyperpgVoidRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        wrapper: HyperpgRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = wrapper.router_data;

        // For void, use the amount from the connector_transaction_id or a default of full amount
        // Since PaymentVoidData doesn't have amount_to_cancel, we'll use the connector_transaction_id
        // and let the connector handle the full amount void
        let amount_major = 0.0; // Will be handled by connector based on order_id

        Ok(Self {
            unique_request_id: router_data.resource_common_data.connector_request_reference_id.clone(),
            amount: amount_major,
        })
    }
}

#[derive(Debug, Serialize)]
pub struct HyperpgRefundRequest {
    pub unique_request_id: String,
    pub amount: f64,
}

impl<T: PaymentMethodDataTypes + fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        HyperpgRouterData<RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>, T>,
    > for HyperpgRefundRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        wrapper: HyperpgRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = wrapper.router_data;

        let amount_minor = router_data.request.minor_refund_amount;
        let amount_major = amount_minor.get_amount_as_i64() as f64 / 100.0;

        Ok(Self {
            unique_request_id: router_data.resource_common_data.connector_request_reference_id.clone(),
            amount: amount_major,
        })
    }
}

#[derive(Debug, Serialize)]
pub struct HyperpgCreateOrderRequest {
    pub order_id: String,
    pub amount: f64,
    pub currency: String,
    pub customer_id: String,
    pub customer_email: Option<String>,
    pub customer_phone: Option<String>,
    pub description: Option<String>,
    pub return_url: Option<String>,
    pub product_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options_get_client_auth_token: Option<bool>,
}

impl<T: PaymentMethodDataTypes + fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        HyperpgRouterData<
            RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>,
            T,
        >,
    > for HyperpgCreateOrderRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        wrapper: HyperpgRouterData<
            RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = wrapper.router_data;

        let amount_minor = router_data.request.amount.get_amount_as_i64();
        let amount_major = amount_minor as f64 / 100.0;

        Ok(Self {
            order_id: router_data.resource_common_data.connector_request_reference_id.clone(),
            amount: amount_major,
            currency: router_data.request.currency.to_string(),
            customer_id: "".to_string(), // CreateOrder doesn't have customer_id in request
            customer_email: None,
            customer_phone: None,
            description: None,
            return_url: router_data.request.webhook_url.clone(),
            product_id: None,
            options_get_client_auth_token: Some(true),
        })
    }
}

// ===== RESPONSE TYPES =====

#[derive(Debug, Deserialize, Serialize)]
pub struct HyperpgAuthorizeResponse {
    pub id: String,
    pub order_id: String,
    pub status: String,
    pub amount: i64,
    pub currency: String,
    pub txn_id: Option<String>,
    pub payment_method_type: Option<String>,
    pub payment_method: Option<String>,
    pub payment_links: Option<HyperpgPaymentLinks>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct HyperpgCreateOrderResponse {
    pub id: String,
    pub order_id: String,
    pub status: String,
    pub amount: i64,
    pub currency: String,
    pub customer_id: String,
    pub customer_email: Option<String>,
    pub customer_phone: Option<String>,
    pub payment_links: Option<HyperpgPaymentLinks>,
    pub hyperpg: Option<HyperpgClientAuth>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct HyperpgClientAuth {
    pub client_auth_token: Option<String>,
    pub client_auth_token_expiry: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct HyperpgPaymentLinks {
    pub web: Option<String>,
    pub mobile: Option<String>,
    pub iframe: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct HyperpgSyncResponse {
    pub id: String,
    pub order_id: String,
    pub status: String,
    pub amount: i64,
    pub currency: String,
    pub txn_id: Option<String>,
    pub payment_method_type: Option<String>,
    pub payment_method: Option<String>,
    pub refunded: bool,
    pub amount_refunded: i64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct HyperpgRefundSyncResponse {
    pub id: String,
    pub order_id: String,
    pub status: String,
    pub amount: i64,
    pub currency: String,
    pub txn_id: Option<String>,
    pub payment_method_type: Option<String>,
    pub payment_method: Option<String>,
    pub refunded: bool,
    pub amount_refunded: i64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct HyperpgRefundResponse {
    pub id: String,
    pub order_id: String,
    pub status: String,
    pub amount: i64,
    pub currency: String,
    pub refunded: bool,
    pub amount_refunded: i64,
    pub refunds: Option<Vec<HyperpgRefundItem>>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct HyperpgVoidResponse {
    pub id: String,
    pub order_id: String,
    pub status: String,
    pub amount: i64,
    pub currency: String,
    pub refunded: bool,
    pub amount_refunded: i64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct HyperpgRefundItem {
    pub id: Option<String>,
    pub unique_request_id: String,
    pub status: String,
    pub amount: i64,
    pub created: Option<String>,
}

// ===== RESPONSE TRANSFORMERS =====

impl<T: PaymentMethodDataTypes + fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        ResponseRouterData<
            HyperpgAuthorizeResponse,
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        >,
    > for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            HyperpgAuthorizeResponse,
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let router_data = item.router_data;

        let status = HyperpgPaymentStatus::deserialize(&response.status)
            .map(|s| AttemptStatus::from(&s))
            .unwrap_or(AttemptStatus::Pending);

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(response.id.clone()),
                connector_response_reference_id: Some(response.id.clone()),
                redirection_data: response.payment_links.as_ref().and_then(|links| {
                    links.web.as_ref().map(|url| {
                        Box::new(RedirectForm::Uri {
                            uri: url.clone(),
                        })
                    })
                }),
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: response.txn_id.clone(),
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data.clone()
            },
            ..router_data
        })
    }
}

impl TryFrom<
        ResponseRouterData<
            HyperpgSyncResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    > for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            HyperpgSyncResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let router_data = item.router_data;

        let status = HyperpgPaymentStatus::deserialize(&response.status)
            .map(|s| AttemptStatus::from(&s))
            .unwrap_or(AttemptStatus::Pending);

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(response.id.clone()),
                connector_response_reference_id: Some(response.id.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: response.txn_id.clone(),
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data.clone()
            },
            ..router_data
        })
    }
}

impl TryFrom<
        ResponseRouterData<
            HyperpgVoidResponse,
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        >,
    > for RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            HyperpgVoidResponse,
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let router_data = item.router_data;

        let status = HyperpgPaymentStatus::deserialize(&response.status)
            .map(|s| AttemptStatus::from(&s))
            .unwrap_or(AttemptStatus::Pending);

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(response.id.clone()),
                connector_response_reference_id: Some(response.id.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data.clone()
            },
            ..router_data
        })
    }
}

impl TryFrom<
        ResponseRouterData<
            HyperpgRefundResponse,
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    > for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            HyperpgRefundResponse,
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;

        let refund_status = response
            .refunds
            .as_ref()
            .and_then(|refunds| refunds.first())
            .and_then(|refund| {
                HyperpgRefundStatus::deserialize(&refund.status)
                    .map(|s| RefundStatus::from(&s))
            })
            .unwrap_or(RefundStatus::Pending);

        let connector_refund_id = response
            .refunds
            .as_ref()
            .and_then(|refunds| refunds.first())
            .and_then(|refund| refund.id.clone())
            .unwrap_or_else(|| response.id.clone());

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id,
                refund_status,
                status_code: item.http_code,
            }),
            resource_common_data: RefundFlowData {
                status: refund_status,
                ..item.router_data.resource_common_data.clone()
            },
            ..item.router_data
        })
    }
}

impl TryFrom<
        ResponseRouterData<
            HyperpgRefundSyncResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    > for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            HyperpgRefundSyncResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;

        let refund_status = if response.refunded {
            RefundStatus::Success
        } else {
            RefundStatus::Pending
        };

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: response.id.clone(),
                refund_status,
                status_code: item.http_code,
            }),
            resource_common_data: RefundFlowData {
                status: refund_status,
                ..item.router_data.resource_common_data.clone()
            },
            ..item.router_data
        })
    }
}

// CreateOrder Response Transformer
impl TryFrom<
    ResponseRouterData<
        HyperpgCreateOrderResponse,
        RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>,
    >,
> for RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            HyperpgCreateOrderResponse,
            RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>,
        >,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let router_data = item.router_data;

        let status = HyperpgPaymentStatus::deserialize(&response.status)
            .map(|s| AttemptStatus::from(&s))
            .unwrap_or(AttemptStatus::Pending);

        Ok(Self {
            response: Ok(PaymentCreateOrderResponse {
                order_id: response.id.clone(),
            }),
            resource_common_data: PaymentFlowData {
                status,
                reference_id: Some(response.id.clone()),
                ..router_data.resource_common_data
            },
            ..router_data
        })
    }
}

// ===== HELPER FUNCTIONS =====

impl HyperpgPaymentStatus {
    fn deserialize(status: &str) -> Option<Self> {
        match status.to_uppercase().as_str() {
            "NEW" => Some(Self::New),
            "PENDING" => Some(Self::Pending),
            "PENDING_VBV" => Some(Self::PendingVbv),
            "CHARGED" => Some(Self::Charged),
            "FAILED" => Some(Self::Failed),
            "CANCELLED" => Some(Self::Cancelled),
            "REFUNDED" => Some(Self::Refunded),
            _ => Some(Self::Unknown),
        }
    }
}

impl HyperpgRefundStatus {
    fn deserialize(status: &str) -> Option<Self> {
        match status.to_uppercase().as_str() {
            "PENDING" => Some(Self::Pending),
            "SUCCESS" | "COMPLETED" => Some(Self::Success),
            "FAILED" => Some(Self::Failed),
            _ => Some(Self::Unknown),
        }
    }
}