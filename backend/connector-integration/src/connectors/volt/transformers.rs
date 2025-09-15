use common_enums::{self, AttemptStatus, Currency};
use common_utils::{consts, id_type::CustomerId, request::Method, types::MinorUnit};
use domain_types::{
    connector_flow::{Authorize, CreateAccessToken, PSync},
    connector_types::{
        AccessTokenRequestData, AccessTokenResponseData, PaymentFlowData, PaymentsAuthorizeData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundsData, RefundsResponseData,
        ResponseId,
    },
    errors,
    payment_method_data::{BankRedirectData, PaymentMethodData, PaymentMethodDataTypes},
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
    utils,
};
use hyperswitch_masking::{ExposeInterface, Secret};
use interfaces::webhooks::IncomingWebhookEvent;
use serde::{Deserialize, Serialize};

use crate::connectors::volt::VoltRouterData;
use crate::types::ResponseRouterData;

// Type alias for refunds router data following existing patterns
pub type RefundsResponseRouterData<F, T> =
    ResponseRouterData<T, RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>>;

// Empty request type for PSync GET requests
#[derive(Debug, Serialize, Default)]
pub struct VoltPsyncRequest;

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        VoltRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    > for VoltPsyncRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        _item: VoltRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self)
    }
}

fn get_attempt_status((item, current_status): (VoltPaymentStatus, AttemptStatus)) -> AttemptStatus {
    match item {
        VoltPaymentStatus::Received | VoltPaymentStatus::Settled => AttemptStatus::Charged,
        VoltPaymentStatus::Completed | VoltPaymentStatus::DelayedAtBank => AttemptStatus::Pending,
        VoltPaymentStatus::NewPayment
        | VoltPaymentStatus::BankRedirect
        | VoltPaymentStatus::AwaitingCheckoutAuthorisation => AttemptStatus::AuthenticationPending,
        VoltPaymentStatus::RefusedByBank
        | VoltPaymentStatus::RefusedByRisk
        | VoltPaymentStatus::NotReceived
        | VoltPaymentStatus::ErrorAtBank
        | VoltPaymentStatus::CancelledByUser
        | VoltPaymentStatus::AbandonedByUser
        | VoltPaymentStatus::Failed => AttemptStatus::Failure,
        VoltPaymentStatus::Unknown => current_status,
    }
}

const PASSWORD: &str = "password";

pub mod webhook_headers {
    pub const X_VOLT_SIGNED: &str = "X-Volt-Signed";
    pub const X_VOLT_TIMED: &str = "X-Volt-Timed";
    pub const USER_AGENT: &str = "User-Agent";
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VoltPaymentsRequest {
    amount: MinorUnit,
    currency_code: Currency,
    #[serde(rename = "type")]
    transaction_type: TransactionType,
    merchant_internal_reference: String,
    shopper: ShopperDetails,
    payment_success_url: Option<String>,
    payment_failure_url: Option<String>,
    payment_pending_url: Option<String>,
    payment_cancel_url: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TransactionType {
    Bills,
    Goods,
    PersonToPerson,
    Other,
    Services,
}

#[derive(Debug, Serialize)]
pub struct ShopperDetails {
    reference: common_utils::id_type::CustomerId,
    email: Option<common_utils::pii::Email>,
    first_name: Secret<String>,
    last_name: Secret<String>,
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    >
    TryFrom<
        VoltRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for VoltPaymentsRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: VoltRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        match &item.router_data.request.payment_method_data {
            PaymentMethodData::BankRedirect(bank_redirect) => match bank_redirect {
                BankRedirectData::OpenBankingUk { .. } => {
                    let amount = item.router_data.request.amount;
                    let currency_code = item.router_data.request.currency;
                    let merchant_internal_reference = item
                        .router_data
                        .resource_common_data
                        .connector_request_reference_id
                        .clone();
                    let payment_success_url = item.router_data.request.router_return_url.clone();
                    let payment_failure_url = item.router_data.request.router_return_url.clone();
                    let payment_pending_url = item.router_data.request.router_return_url.clone();
                    let payment_cancel_url = item.router_data.request.router_return_url.clone();
                    let shopper = ShopperDetails {
                        email: item.router_data.request.email.clone(),
                        first_name: item
                            .router_data
                            .resource_common_data
                            .get_billing_first_name()?,
                        last_name: item
                            .router_data
                            .resource_common_data
                            .get_billing_last_name()?,
                        reference: item
                            .router_data
                            .resource_common_data
                            .get_customer_id()
                            .unwrap_or_else(|_| CustomerId::default()),
                    };
                    let transaction_type = TransactionType::Services; //transaction_type is a form of enum, it is pre defined and value for this can not be taken from user so we are keeping it as Services as this transaction is type of service.

                    Ok(Self {
                        amount: MinorUnit::new(amount),
                        currency_code,
                        merchant_internal_reference,
                        payment_success_url,
                        payment_failure_url,
                        payment_pending_url,
                        payment_cancel_url,
                        shopper,
                        transaction_type,
                    })
                }
                BankRedirectData::BancontactCard { .. }
                | BankRedirectData::Bizum {}
                | BankRedirectData::Blik { .. }
                | BankRedirectData::Eft { .. }
                | BankRedirectData::Eps { .. }
                | BankRedirectData::Giropay { .. }
                | BankRedirectData::Ideal { .. }
                | BankRedirectData::Interac { .. }
                | BankRedirectData::OnlineBankingCzechRepublic { .. }
                | BankRedirectData::OnlineBankingFinland { .. }
                | BankRedirectData::OnlineBankingPoland { .. }
                | BankRedirectData::OnlineBankingSlovakia { .. }
                | BankRedirectData::Przelewy24 { .. }
                | BankRedirectData::Sofort { .. }
                | BankRedirectData::Trustly { .. }
                | BankRedirectData::OnlineBankingFpx { .. }
                | BankRedirectData::OnlineBankingThailand { .. }
                | BankRedirectData::LocalBankRedirect {} => {
                    Err(errors::ConnectorError::NotImplemented(
                        utils::get_unimplemented_payment_method_error_message("Volt"),
                    )
                    .into())
                }
            },
            PaymentMethodData::Card(_)
            | PaymentMethodData::CardRedirect(_)
            | PaymentMethodData::Wallet(_)
            | PaymentMethodData::PayLater(_)
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
                Err(errors::ConnectorError::NotImplemented(
                    utils::get_unimplemented_payment_method_error_message("Volt"),
                )
                .into())
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct VoltAuthUpdateRequest {
    grant_type: String,
    client_id: Secret<String>,
    client_secret: Secret<String>,
    username: Secret<String>,
    password: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for VoltAuthUpdateRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        let auth = VoltAuthType::try_from(auth_type)?;
        Ok(Self {
            grant_type: PASSWORD.to_string(),
            username: auth.username,
            password: auth.password,
            client_id: auth.client_id,
            client_secret: auth.client_secret,
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
    >
    TryFrom<
        VoltRouterData<
            RouterDataV2<
                CreateAccessToken,
                PaymentFlowData,
                AccessTokenRequestData,
                AccessTokenResponseData,
            >,
            T,
        >,
    > for VoltAuthUpdateRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: VoltRouterData<
            RouterDataV2<
                CreateAccessToken,
                PaymentFlowData,
                AccessTokenRequestData,
                AccessTokenResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Self::try_from(&item.router_data.connector_auth_type)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VoltAuthUpdateResponse {
    pub access_token: Secret<String>,
    pub token_type: String,
    pub expires_in: i64,
}

impl<F, T>
    TryFrom<
        ResponseRouterData<
            VoltAuthUpdateResponse,
            RouterDataV2<F, PaymentFlowData, T, AccessTokenResponseData>,
        >,
    > for RouterDataV2<F, PaymentFlowData, T, AccessTokenResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<
            VoltAuthUpdateResponse,
            RouterDataV2<F, PaymentFlowData, T, AccessTokenResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(AccessTokenResponseData {
                access_token: item.response.access_token.expose(),
                expires_in: Some(item.response.expires_in),
                token_type: Some(item.response.token_type),
            }),
            ..item.router_data
        })
    }
}

pub struct VoltAuthType {
    pub(super) username: Secret<String>,
    pub(super) password: Secret<String>,
    pub(super) client_id: Secret<String>,
    pub(super) client_secret: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for VoltAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::MultiAuthKey {
                api_key,
                key1,
                api_secret,
                key2,
            } => Ok(Self {
                username: api_key.to_owned(),
                password: api_secret.to_owned(),
                client_id: key1.to_owned(),
                client_secret: key2.to_owned(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VoltPaymentsResponse {
    checkout_url: String,
    id: String,
}

impl<F, T>
    TryFrom<
        ResponseRouterData<
            VoltPaymentsResponse,
            RouterDataV2<F, PaymentFlowData, T, PaymentsResponseData>,
        >,
    > for RouterDataV2<F, PaymentFlowData, T, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<
            VoltPaymentsResponse,
            RouterDataV2<F, PaymentFlowData, T, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let url = item.response.checkout_url;
        let redirection_data = Some(RedirectForm::Form {
            endpoint: url,
            method: Method::Get,
            form_fields: Default::default(),
        });
        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id.clone()),
                redirection_data: redirection_data.map(Box::new),
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(item.response.id),
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

#[derive(Debug, Serialize, Clone, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[derive(strum::Display)]
pub enum VoltPaymentStatus {
    NewPayment,
    Completed,
    Received,
    NotReceived,
    BankRedirect,
    DelayedAtBank,
    AwaitingCheckoutAuthorisation,
    RefusedByBank,
    RefusedByRisk,
    ErrorAtBank,
    CancelledByUser,
    AbandonedByUser,
    Failed,
    Settled,
    Unknown,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum VoltPaymentsResponseData {
    PsyncResponse(VoltPsyncResponse),
    WebhookResponse(VoltPaymentWebhookObjectResource),
}

#[derive(Debug, Serialize, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VoltPsyncResponse {
    status: VoltPaymentStatus,
    id: String,
    merchant_internal_reference: Option<String>,
}

impl<F> TryFrom<ResponseRouterData<VoltPsyncResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: ResponseRouterData<VoltPsyncResponse, Self>) -> Result<Self, Self::Error> {
        let current_status = match &item.router_data.response {
            Ok(_) => AttemptStatus::Pending,
            Err(err) => err.attempt_status.unwrap_or(AttemptStatus::Pending),
        };
        let status = get_attempt_status((item.response.status.clone(), current_status));
        let payments_response_data = match status {
            AttemptStatus::Failure => Err(ErrorResponse {
                code: item.response.status.clone().to_string(),
                message: item.response.status.clone().to_string(),
                reason: Some(item.response.status.to_string()),
                status_code: item.http_code,
                attempt_status: Some(status),
                connector_transaction_id: Some(item.response.id),
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
            }),
            _ => Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: item
                    .response
                    .merchant_internal_reference
                    .or(Some(item.response.id)),
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            response: payments_response_data,
            ..item.router_data
        })
    }
}

impl<F, T>
    TryFrom<
        ResponseRouterData<
            VoltPaymentsResponseData,
            RouterDataV2<F, PaymentFlowData, T, PaymentsResponseData>,
        >,
    > for RouterDataV2<F, PaymentFlowData, T, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<
            VoltPaymentsResponseData,
            RouterDataV2<F, PaymentFlowData, T, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        match item.response {
            VoltPaymentsResponseData::PsyncResponse(payment_response) => {
                let current_status = match &item.router_data.response {
                    Ok(_) => AttemptStatus::Pending,
                    Err(err) => err.attempt_status.unwrap_or(AttemptStatus::Pending),
                };
                let status = get_attempt_status((payment_response.status.clone(), current_status));
                let mut router_data = item.router_data;
                router_data.response = match status {
                    AttemptStatus::Failure => Err(ErrorResponse {
                        code: payment_response.status.clone().to_string(),
                        message: payment_response.status.clone().to_string(),
                        reason: Some(payment_response.status.to_string()),
                        status_code: item.http_code,
                        attempt_status: Some(status),
                        connector_transaction_id: Some(payment_response.id),
                        network_advice_code: None,
                        network_decline_code: None,
                        network_error_message: None,
                    }),
                    _ => Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(
                            payment_response.id.clone(),
                        ),
                        redirection_data: None,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: None,
                        connector_response_reference_id: payment_response
                            .merchant_internal_reference
                            .or(Some(payment_response.id)),
                        incremental_authorization_allowed: None,
                        status_code: item.http_code,
                    }),
                };
                Ok(router_data)
            }
            VoltPaymentsResponseData::WebhookResponse(webhook_response) => {
                let detailed_status = webhook_response.detailed_status.clone();
                let status = AttemptStatus::from(webhook_response.status);
                let mut router_data = item.router_data;
                router_data.response = match status {
                    AttemptStatus::Failure => Err(ErrorResponse {
                        code: detailed_status
                            .clone()
                            .map(|volt_status| volt_status.to_string())
                            .unwrap_or_else(|| consts::NO_ERROR_CODE.to_owned()),
                        message: detailed_status
                            .clone()
                            .map(|volt_status| volt_status.to_string())
                            .unwrap_or_else(|| consts::NO_ERROR_MESSAGE.to_owned()),
                        reason: detailed_status
                            .clone()
                            .map(|volt_status| volt_status.to_string()),
                        status_code: item.http_code,
                        attempt_status: Some(status),
                        connector_transaction_id: Some(webhook_response.payment.clone()),
                        network_advice_code: None,
                        network_decline_code: None,
                        network_error_message: None,
                    }),
                    _ => Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(
                            webhook_response.payment.clone(),
                        ),
                        redirection_data: None,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: None,
                        connector_response_reference_id: webhook_response
                            .merchant_internal_reference
                            .or(Some(webhook_response.payment)),
                        incremental_authorization_allowed: None,
                        status_code: item.http_code,
                    }),
                };
                Ok(router_data)
            }
        }
    }
}
impl From<VoltWebhookPaymentStatus> for AttemptStatus {
    fn from(status: VoltWebhookPaymentStatus) -> Self {
        match status {
            VoltWebhookPaymentStatus::Received => Self::Charged,
            VoltWebhookPaymentStatus::Failed | VoltWebhookPaymentStatus::NotReceived => {
                Self::Failure
            }
            VoltWebhookPaymentStatus::Completed | VoltWebhookPaymentStatus::Pending => {
                Self::Pending
            }
        }
    }
}

// REFUND :
// Type definition for RefundRequest
#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VoltRefundRequest {
    pub amount: MinorUnit,
    pub external_reference: String,
}

impl<
        F,
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    > TryFrom<VoltRouterData<RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>, T>>
    for VoltRefundRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: VoltRouterData<RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            amount: MinorUnit::new(item.router_data.request.refund_amount),
            external_reference: item.router_data.request.refund_id.clone(),
        })
    }
}

#[derive(Default, Debug, Clone, Deserialize, Serialize)]
pub struct RefundResponse {
    id: String,
}

impl<F> TryFrom<RefundsResponseRouterData<F, RefundResponse>>
    for RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: RefundsResponseRouterData<F, RefundResponse>) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.id.to_string(),
                refund_status: common_enums::RefundStatus::Pending, //We get Refund Status only by Webhooks
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

#[derive(Debug, Deserialize, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VoltPaymentWebhookBodyReference {
    pub payment: String,
    pub merchant_internal_reference: Option<String>,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VoltRefundWebhookBodyReference {
    pub refund: String,
    pub external_reference: Option<String>,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[serde(untagged)]
pub enum WebhookResponse {
    // the enum order shouldn't be changed as this is being used during serialization and deserialization
    Refund(VoltRefundWebhookBodyReference),
    Payment(VoltPaymentWebhookBodyReference),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum VoltWebhookBodyEventType {
    Payment(VoltPaymentsWebhookBodyEventType),
    Refund(VoltRefundsWebhookBodyEventType),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VoltPaymentsWebhookBodyEventType {
    pub status: VoltWebhookPaymentStatus,
    pub detailed_status: Option<VoltDetailedStatus>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VoltRefundsWebhookBodyEventType {
    pub status: VoltWebhookRefundsStatus,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum VoltWebhookObjectResource {
    Payment(VoltPaymentWebhookObjectResource),
    Refund(VoltRefundWebhookObjectResource),
}

#[derive(Debug, Deserialize, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VoltPaymentWebhookObjectResource {
    #[serde(alias = "id")]
    pub payment: String,
    pub merchant_internal_reference: Option<String>,
    pub status: VoltWebhookPaymentStatus,
    pub detailed_status: Option<VoltDetailedStatus>,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VoltRefundWebhookObjectResource {
    pub refund: String,
    pub external_reference: Option<String>,
    pub status: VoltWebhookRefundsStatus,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VoltWebhookPaymentStatus {
    Completed,
    Failed,
    Pending,
    Received,
    NotReceived,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VoltWebhookRefundsStatus {
    RefundConfirmed,
    RefundFailed,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[derive(strum::Display)]
pub enum VoltDetailedStatus {
    RefusedByRisk,
    RefusedByBank,
    ErrorAtBank,
    CancelledByUser,
    AbandonedByUser,
    Failed,
    Completed,
    BankRedirect,
    DelayedAtBank,
    AwaitingCheckoutAuthorisation,
}

impl From<VoltWebhookBodyEventType> for IncomingWebhookEvent {
    fn from(status: VoltWebhookBodyEventType) -> Self {
        match status {
            VoltWebhookBodyEventType::Payment(payment_data) => match payment_data.status {
                VoltWebhookPaymentStatus::Received => Self::PaymentIntentSuccess,
                VoltWebhookPaymentStatus::Failed | VoltWebhookPaymentStatus::NotReceived => {
                    Self::PaymentIntentFailure
                }
                VoltWebhookPaymentStatus::Completed | VoltWebhookPaymentStatus::Pending => {
                    Self::PaymentIntentProcessing
                }
            },
            VoltWebhookBodyEventType::Refund(refund_data) => match refund_data.status {
                VoltWebhookRefundsStatus::RefundConfirmed => Self::RefundSuccess,
                VoltWebhookRefundsStatus::RefundFailed => Self::RefundFailure,
            },
        }
    }
}

#[derive(Default, Debug, Serialize, Deserialize, PartialEq)]
pub struct VoltErrorResponse {
    pub exception: VoltErrorException,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct VoltAuthErrorResponse {
    pub code: u64,
    pub message: String,
}

#[derive(Default, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VoltErrorException {
    pub code: u64,
    pub message: String,
    pub error_list: Option<Vec<VoltErrorList>>,
}

#[derive(Default, Debug, Serialize, Deserialize, PartialEq)]
pub struct VoltErrorList {
    pub property: String,
    pub message: String,
}
