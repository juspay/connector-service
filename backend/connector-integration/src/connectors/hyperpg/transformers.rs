use crate::{connectors::hyperpg::HyperpgRouterData, types::ResponseRouterData};
use common_enums::{AttemptStatus, RefundStatus};
use domain_types::router_response_types::RedirectForm;
use common_utils::{AmountConvertor, FloatMajorUnit, types::MinorUnit, FloatMajorUnitForConnector};
use domain_types::{
    connector_flow::{Authorize, PSync, RSync, Refund, Void, CreateConnectorCustomer},
    connector_types::{
        ConnectorCustomerData, ConnectorCustomerResponse,
        PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData, PaymentsResponseData,
        PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData,
        ResponseId,
    },
    errors,
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes, RawCardNumber},
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
    utils,
};
use hyperswitch_masking::{PeekInterface, Secret};
use serde::{Deserialize, Serialize};
use std::fmt;
use error_stack::ResultExt;

#[derive(Debug, Clone)]
pub struct HyperpgAuthType {
    pub username: Secret<String>,
    pub password: Secret<String>,
    pub merchant_id: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for HyperpgAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey { api_key, key1, api_secret } => Ok(Self {
                username: api_key.to_owned(),
                password: key1.to_owned(),
                merchant_id: api_secret.to_owned(),
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
    pub error_message: Option<String>,
    pub status: Option<String>,
    pub error_code: Option<String>,
    pub error_info: Option<HyperpgErrorInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HyperpgErrorInfo {
    pub user_message: Option<String>,
    pub fields: Option<Vec<HyperpgErrorField>>,
    pub request_id: Option<String>,
    pub developer_message: Option<String>,
    pub code: Option<String>,
    pub category: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HyperpgErrorField {
    pub field_name: Option<String>,
    pub reason: Option<String>,
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
    pub merchant_id: String,
    pub payment_method_type: String,
    pub payment_method: Option<String>,
    pub card_number: Option<Secret<String>>,
    pub card_security_code: Option<Secret<String>>,
    pub card_exp_month: Option<String>,
    pub card_exp_year: Option<String>,
    pub name_on_card: Option<String>,
    pub format: String,
    pub redirect_after_payment: bool,
    pub save_to_locker: bool,
    pub order: HyperpgOrderData,
}

#[derive(Debug, Serialize)]
pub struct HyperpgOrderData {
    pub order_id: String,
    pub amount: FloatMajorUnit,
    pub currency: String,
    pub return_url: Option<String>,
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

        // Convert amount using the connector's amount_converter
        let amount = utils::convert_amount(
            wrapper.connector.amount_converter,
            router_data.request.amount,
            router_data.request.currency,
        )?;

        let auth_type = HyperpgAuthType::try_from(&router_data.connector_auth_type)?;

        println!("$$$$$ merchant: {}", auth_type.merchant_id.peek().to_string());

        Ok(Self {
            merchant_id: "hyperswitchsbx".to_string(),
            payment_method_type,
            payment_method,
            card_number,
            card_security_code,
            card_exp_month,
            card_exp_year,
            name_on_card,
            format: "json".to_string(),
            redirect_after_payment: true,
            save_to_locker: true,
            order: HyperpgOrderData {
                order_id: router_data.resource_common_data.connector_request_reference_id.clone(),
                amount,
                currency: router_data.request.currency.to_string(),
                return_url: router_data.request.router_return_url.clone(),
            },
        })
    }
}

#[derive(Debug, Serialize)]
pub struct HyperpgVoidRequest {
    pub unique_request_id: String,
    pub amount: FloatMajorUnit,
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

        // For void, use 0.0 as amount - the connector handles the full amount void based on order_id
        // Currency is optional in PaymentVoidData, use USD as default if not provided
        let currency = router_data.request.currency.unwrap_or(common_enums::Currency::USD);
        let amount = utils::convert_amount(
            wrapper.connector.amount_converter,
            MinorUnit::new(0),
            currency,
        )?;

        Ok(Self {
            unique_request_id: router_data.resource_common_data.connector_request_reference_id.clone(),
            amount,
        })
    }
}

#[derive(Debug, Serialize)]
pub struct HyperpgRefundRequest {
    pub unique_request_id: String,
    pub amount: FloatMajorUnit,
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

        // let amount = utils::convert_amount(
        //     wrapper.connector.amount_converter,
        //     router_data.request.minor_refund_amount,
        //     router_data.request.currency,
        // )?;
        let converter = FloatMajorUnitForConnector;
        let amount = converter
            .convert(router_data.request.minor_refund_amount, router_data.request.currency)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;

        println!("Refund amount after conversion: {}", router_data.request.refund_amount);

        Ok(Self {
            unique_request_id: router_data.request.connector_transaction_id.clone(),
            amount,
        })
    }
}

// ===== RESPONSE TYPES =====

#[derive(Debug, Deserialize, Serialize)]
pub struct HyperpgAuthorizeResponse {
    pub order_id: String,
    pub status: String,
    pub txn_id: String,
    pub payment: Option<PaymentResponse>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PaymentResponse {
    pub authentication: Option<Authentication>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Authentication {
    pub url: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct HyperpgSyncResponse {
    pub id: String,
    pub order_id: String,
    pub status: String,
    pub amount: FloatMajorUnit,
    pub currency: String,
    pub txn_id: Option<String>,
    pub payment_method_type: Option<String>,
    pub payment_method: Option<String>,
    pub refunded: bool,
    pub amount_refunded: FloatMajorUnit,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct HyperpgRefundSyncResponse {
    pub id: String,
    pub order_id: String,
    pub status: String,
    pub amount: FloatMajorUnit,
    pub currency: String,
    pub txn_id: Option<String>,
    pub payment_method_type: Option<String>,
    pub payment_method: Option<String>,
    pub refunded: bool,
    pub amount_refunded: FloatMajorUnit,
    pub refunds: Option<Vec<HyperpgRefundItem>>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct HyperpgRefundResponse {
    pub id: String,
    pub order_id: String,
    pub status: String,
    pub amount: FloatMajorUnit,
    pub currency: String,
    pub refunded: bool,
    pub amount_refunded: FloatMajorUnit,
    pub refunds: Option<Vec<HyperpgRefundItem>>,
    pub txn_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct HyperpgVoidResponse {
    pub id: String,
    pub order_id: String,
    pub status: String,
    pub amount: FloatMajorUnit,
    pub currency: String,
    pub refunded: bool,
    pub amount_refunded: FloatMajorUnit,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct HyperpgRefundItem {
    pub id: Option<String>,
    pub amount: FloatMajorUnit,
    pub unique_request_id: String,
    #[serde(rename = "ref")]
    pub reference: Option<String>,
    pub created: Option<String>,
    pub last_updated: Option<String>,
    pub status: String,
    pub error_message: Option<String>,
    pub sent_to_gateway: Option<bool>,
    pub initiated_by: Option<String>,
    pub refund_type: Option<String>,
    pub pg_processed_at: Option<String>,
    pub error_code: Option<String>,
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
                resource_id: ResponseId::ConnectorTransactionId(response.txn_id.clone()),
                connector_response_reference_id: Some(response.order_id.clone()),
                redirection_data: response.payment.as_ref().and_then(|links| {
                    links.authentication.as_ref().map(|authentication| {
                        Box::new(RedirectForm::Uri {
                            uri: authentication.url.clone(),
                        })
                    })
                }),
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
                resource_id: ResponseId::NoResponseId,
                connector_response_reference_id: None,
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

        let connector_refund_id = response.txn_id.clone();

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

        // Use status from refunds array to determine refund status
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