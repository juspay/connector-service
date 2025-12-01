use crate::connectors::revolut::RevolutRouterData;
use domain_types::{
    connector_flow::{Authorize, PSync},
    connector_types::{
        PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, ResponseId,
    },
    errors::ConnectorError,
    payment_method_data::PaymentMethodDataTypes,
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
};

use crate::types::ResponseRouterData;
use common_utils::types::MinorUnit;
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

pub struct RevolutAuthType {
    pub api_key: Secret<String>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Serialize)]
pub struct RevolutOrderCreateRequest {
    pub amount: MinorUnit,
    pub currency: String,
    pub settlement_currency: Option<String>,
    pub description: Option<String>,
    pub customer: Option<RevolutCustomer>,
    pub enforce_challenge: Option<RevolutEnforceChallengeMode>,
    pub line_items: Option<Vec<RevolutLineItem>>,
    pub shipping: Option<RevolutShipping>,
    pub capture_mode: Option<String>,
    pub cancel_authorised_after: Option<String>,
    pub location_id: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub industry_data: Option<serde_json::Value>,
    pub merchant_order_data: Option<serde_json::Value>,
    pub upcoming_payment_data: Option<serde_json::Value>,
    pub redirect_url: Option<String>,
    pub statement_descriptor_suffix: Option<String>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevolutCustomer {
    pub id: Option<String>,
    pub full_name: Option<Secret<String>>,
    pub phone: Option<Secret<String>>,
    pub email: Option<common_utils::pii::Email>,
    pub date_of_birth: Option<String>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RevolutEnforceChallengeMode {
    #[default]
    Automatic,
    Forced,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevolutLineItem {
    pub name: String,
    pub r#type: RevolutLineItemType,
    pub quantity: RevolutLineItemQuantity,
    pub unit_price_amount: MinorUnit, //integer(int64)
    pub total_amount: MinorUnit,      //integer(int64)
    pub external_id: Option<String>,
    pub discounts: Option<Vec<RevolutLineItemDiscount>>,
    pub taxes: Option<Vec<RevolutLineItemTax>>,
    pub image_urls: Option<Vec<String>>,
    pub description: Option<String>,
    pub url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RevolutLineItemType {
    Physical,
    Service,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevolutLineItemQuantity {
    pub value: f64, // number(double)
    pub unit: Option<String>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevolutLineItemDiscount {
    pub name: String,
    pub amount: MinorUnit,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevolutLineItemTax {
    pub name: String,
    pub amount: MinorUnit,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevolutShipping {
    pub address: Option<RevolutAddress>,
    pub contact: Option<RevolutContact>,
    pub shipments: Option<Vec<RevolutShipment>>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevolutAddress {
    pub street_line_1: Option<String>,
    pub street_line_2: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub country_code: Option<String>,
    pub postcode: Option<String>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevolutContact {
    pub full_name: Option<Secret<String>>,
    pub phone: Option<Secret<String>>,
    pub email: Option<common_utils::pii::Email>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevolutShipment {
    pub shipping_company_name: String,
    pub tracking_number: String,
    pub estimated_delivery_date: Option<String>,
    pub tracking_url: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum RevolutErrorResponse {
    StandardError {
        code: String,
        message: String,
        timestamp: i64,
    },
    ErrorIdResponse {
        #[serde(rename = "errorId")]
        error_id: String,
        timestamp: i64,
        code: Option<i64>,
    },
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RevolutOrderCreateResponse {
    pub id: String,
    pub token: String,
    pub r#type: RevolutOrderType,
    pub state: RevolutOrderState,
    pub created_at: String,
    pub updated_at: String,
    pub description: Option<String>,
    pub capture_mode: Option<RevolutCaptureMode>,
    pub cancel_authorised_after: Option<String>,
    pub amount: MinorUnit,
    pub outstanding_amount: Option<MinorUnit>,
    pub refunded_amount: Option<MinorUnit>,
    pub currency: String,
    pub settlement_currency: Option<String>,
    pub customer: Option<RevolutCustomer>,
    pub payments: Option<Vec<RevolutPayment>>,
    pub location_id: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub industry_data: Option<serde_json::Value>,
    pub merchant_order_data: Option<RevolutMerchantOrderData>,
    pub upcoming_payment_data: Option<RevolutUpcomingPaymentData>,
    pub checkout_url: Option<String>,
    pub redirect_url: Option<String>,
    pub shipping: Option<RevolutShipping>,
    pub enforce_challenge: Option<RevolutEnforceChallengeMode>,
    pub line_items: Option<Vec<RevolutLineItem>>,
    pub statement_descriptor_suffix: Option<String>,
    pub related_order_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevolutOrderType {
    Payment,
    PaymentRequest,
    Refund,
    Chargeback,
    ChargebackReversal,
    CreditReimbursement,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevolutOrderState {
    Pending,
    Processing,
    Authorised,
    Completed,
    Cancelled,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RevolutCaptureMode {
    Automatic,
    Manual,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevolutPayment {
    pub id: String,
    pub state: RevolutPaymentState,
    pub decline_reason: Option<RevolutDeclineReason>,
    pub bank_message: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub token: Option<String>,
    pub amount: MinorUnit,
    pub currency: String,
    pub settled_amount: Option<MinorUnit>,
    pub settled_currency: Option<String>,
    pub payment_method: Option<RevolutPaymentMethod>,
    pub authentication_challenge: Option<RevolutAuthenticationChallenge>,
    pub billing_address: Option<RevolutAddress>,
    pub risk_level: Option<RevolutRiskLevel>,
    pub fees: Option<Vec<RevolutFee>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevolutPaymentState {
    Pending,
    AuthenticationChallenge,
    AuthenticationVerified,
    AuthorisationStarted,
    AuthorisationPassed,
    Authorised,
    CaptureStarted,
    Captured,
    RefundValidated,
    RefundStarted,
    CancellationStarted,
    Declining,
    Completing,
    Cancelling,
    Failing,
    Completed,
    Declined,
    SoftDeclined,
    Cancelled,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevolutDeclineReason {
    #[serde(rename = "3ds_challenge_abandoned")]
    ThreeDsChallengeAbandoned,
    #[serde(rename = "3ds_challenge_failed_manually")]
    ThreeDsChallengeFailedManually,
    CardholderNameMissing,
    CustomerChallengeAbandoned,
    CustomerChallengeFailed,
    CustomerNameMismatch,
    DoNotHonour,
    ExpiredCard,
    HighRisk,
    InsufficientFunds,
    InvalidAddress,
    InvalidAmount,
    InvalidCard,
    InvalidCountry,
    InvalidCvv,
    InvalidEmail,
    InvalidExpiry,
    InvalidMerchant,
    InvalidPhone,
    InvalidPin,
    IssuerNotAvailable,
    PickUpCard,
    RejectedByCustomer,
    RestrictedCard,
    SuspectedFraud,
    TechnicalError,
    TransactionNotAllowedForCardholder,
    UnknownCard,
    WithdrawalLimitExceeded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevolutMerchantOrderData {
    pub url: Option<String>,
    pub reference: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevolutUpcomingPaymentData {
    pub date: String,
    pub payment_method_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevolutRiskLevel {
    Low,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevolutFee {
    pub r#type: RevolutFeeType,
    pub amount: MinorUnit,
    pub currency: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevolutFeeType {
    Fx,
    Acquiring,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RevolutPaymentMethod {
    ApplePay(RevolutCardDetails),
    Card(RevolutCardDetails),
    GooglePay(RevolutCardDetails),
    RevolutPayCard(RevolutCardDetails),
    RevolutPayAccount(RevolutAccountDetails),
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevolutCardDetails {
    pub id: Option<String>,
    pub card_brand: Option<RevolutCardBrand>,
    pub funding: Option<RevolutCardFunding>,
    pub card_country_code: Option<String>,
    pub card_bin: Option<String>,
    pub card_last_four: Option<String>,
    pub card_expiry: Option<String>,
    pub cardholder_name: Option<Secret<String>>,
    pub checks: Option<RevolutPaymentChecks>,
    pub authorisation_code: Option<String>,
    pub arn: Option<String>,
    pub fingerprint: Option<String>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevolutAccountDetails {
    pub id: Option<String>,
    pub fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevolutCardBrand {
    Visa,
    Mastercard,
    AmericanExpress,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevolutCardFunding {
    Credit,
    Debit,
    Prepaid,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevolutPaymentChecks {
    pub three_ds: Option<RevolutThreeDsCheck>,
    pub cvv_verification: Option<RevolutVerificationResult>,
    pub address: Option<RevolutVerificationResult>,
    pub postcode: Option<RevolutVerificationResult>,
    pub cardholder: Option<RevolutVerificationResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevolutThreeDsCheck {
    pub eci: Option<String>,
    pub state: Option<RevolutThreeDsState>,
    pub version: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevolutThreeDsState {
    Verified,
    Failed,
    Challenge,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevolutVerificationResult {
    Match,
    NotMatch,
    #[serde(rename = "n_a")]
    NA,
    Invalid,
    #[serde(rename = "incorrect")]
    Incorrect,
    #[serde(rename = "not_processed")]
    NotProcessed,
}
#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RevolutAuthenticationChallenge {
    ThreeDs(RevolutThreeDsChallenge),
    ThreeDsFingerprint(RevolutThreeDsFingerprintChallenge),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevolutThreeDsChallenge {
    pub acs_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevolutThreeDsFingerprintChallenge {
    pub fingerprint_url: String,
    pub fingerprint_data: String,
}

#[allow(dead_code)]
#[serde_with::skip_serializing_none]
#[derive(Debug, Serialize)]
pub struct RevolutPaymentsRequest<T: PaymentMethodDataTypes> {
    pub saved_payment_method: RevolutSavedPaymentMethod,
    #[serde(skip)]
    pub _phantom: std::marker::PhantomData<T>,
}

#[allow(dead_code)]
#[serde_with::skip_serializing_none]
#[derive(Debug, Serialize)]
pub struct RevolutSavedPaymentMethod {
    pub r#type: RevolutPaymentMethodType,
    pub id: String,
    pub initiator: RevolutPaymentInitiator,
    pub environment: Option<RevolutEnvironment>,
}

#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevolutPaymentMethodType {
    Card,
    RevolutPay,
}

#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevolutPaymentInitiator {
    Customer,
    Merchant,
}

#[allow(dead_code)]
#[serde_with::skip_serializing_none]
#[derive(Debug, Serialize)]
pub struct RevolutEnvironment {
    pub r#type: String, // "browser"
    pub time_zone_utc_offset: i32,
    pub color_depth: i32,
    pub screen_width: i32,
    pub screen_height: i32,
    pub java_enabled: bool,
    pub challenge_window_width: Option<i32>,
    pub browser_url: Option<String>,
}

#[allow(dead_code)]
#[serde_with::skip_serializing_none]
#[derive(Debug, Deserialize, Serialize)]
pub struct RevolutPaymentsResponse {
    pub id: String,
    pub order_id: String,
    pub payment_method: RevolutPaymentMethod,
    pub state: RevolutPaymentState,
    pub authentication_challenge: Option<RevolutAuthenticationChallenge>,
}

impl TryFrom<&ConnectorAuthType> for RevolutAuthType {
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::HeaderKey { api_key } => Ok(Self {
                api_key: api_key.to_owned(),
            }),
            _ => Err(ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        RevolutRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for RevolutOrderCreateRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: RevolutRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;

        let customer = router_data
            .request
            .email
            .as_ref()
            .map(|email| RevolutCustomer {
                id: None,
                full_name: router_data
                    .request
                    .customer_name
                    .as_ref()
                    .map(|name| Secret::new(name.clone())),
                phone: None,
                email: Some(email.clone()),
                date_of_birth: None,
            });

        Ok(Self {
            amount: router_data.request.amount,
            currency: router_data.request.currency.to_string(),
            settlement_currency: None,
            description: router_data.resource_common_data.description.clone(),
            customer,
            enforce_challenge: None,
            line_items: None,
            shipping: None,
            capture_mode: None,
            cancel_authorised_after: None,
            location_id: None,
            metadata: router_data.request.metadata.clone(),
            industry_data: None,
            merchant_order_data: None,
            upcoming_payment_data: None,
            redirect_url: router_data.request.router_return_url.clone(),
            statement_descriptor_suffix: router_data.request.statement_descriptor_suffix.clone(),
        })
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        ResponseRouterData<
            RevolutOrderCreateResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    > for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            RevolutOrderCreateResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        let response = item.response;

        let status = match response.state {
            RevolutOrderState::Authorised => common_enums::AttemptStatus::Authorized,
            RevolutOrderState::Completed => common_enums::AttemptStatus::Charged,
            RevolutOrderState::Failed => common_enums::AttemptStatus::Failure,
            RevolutOrderState::Cancelled => common_enums::AttemptStatus::Voided,
            RevolutOrderState::Pending => common_enums::AttemptStatus::AuthenticationPending,
            RevolutOrderState::Processing => common_enums::AttemptStatus::Pending,
        };

        let redirection_data = response
            .checkout_url
            .as_ref()
            .map(|url| Box::new(RedirectForm::Uri { uri: url.clone() }));

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(response.id.clone()),
                redirection_data,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(response.id),
                incremental_authorization_allowed: None,
                status_code: 200,
            }),
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

impl
    TryFrom<
        ResponseRouterData<
            RevolutOrderCreateResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    > for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            RevolutOrderCreateResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let response = item.response;

        let (status, payment_id) = if let Some(payments) = &response.payments {
            if let Some(first_payment) = payments.first() {
                let status = match first_payment.state {
                    RevolutPaymentState::Authorised => common_enums::AttemptStatus::Authorized,
                    RevolutPaymentState::Captured | RevolutPaymentState::Completed => {
                        common_enums::AttemptStatus::Charged
                    }
                    RevolutPaymentState::Failed | RevolutPaymentState::Declined => {
                        common_enums::AttemptStatus::Failure
                    }
                    RevolutPaymentState::Cancelled => common_enums::AttemptStatus::Voided,
                    RevolutPaymentState::Pending => common_enums::AttemptStatus::Pending,
                    RevolutPaymentState::AuthenticationChallenge => {
                        common_enums::AttemptStatus::AuthenticationPending
                    }
                    _ => common_enums::AttemptStatus::Pending,
                };
                (status, Some(first_payment.id.clone()))
            } else {
                (map_order_state(response.state), None)
            }
        } else {
            (map_order_state(response.state), None)
        };

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    payment_id.unwrap_or_else(|| response.id.clone()),
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(response.id.clone()),
                incremental_authorization_allowed: None,
                status_code: 200,
            }),
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

fn map_order_state(state: RevolutOrderState) -> common_enums::AttemptStatus {
    match state {
        RevolutOrderState::Authorised => common_enums::AttemptStatus::Authorized,
        RevolutOrderState::Completed => common_enums::AttemptStatus::Charged,
        RevolutOrderState::Failed => common_enums::AttemptStatus::Failure,
        RevolutOrderState::Cancelled => common_enums::AttemptStatus::Voided,
        RevolutOrderState::Pending => common_enums::AttemptStatus::AuthenticationPending,
        RevolutOrderState::Processing => common_enums::AttemptStatus::Pending,
    }
}
