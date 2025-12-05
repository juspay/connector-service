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
use time::Date;

pub struct RevolutAuthType {
    pub api_key: Secret<String>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Serialize)]
pub struct RevolutOrderCreateRequest {
    pub amount: MinorUnit,
    pub currency: common_enums::Currency,
    pub settlement_currency: Option<common_enums::Currency>,
    pub description: Option<String>,
    pub customer: Option<RevolutCustomer>,
    pub enforce_challenge: Option<RevolutEnforceChallengeMode>,
    pub line_items: Option<Vec<RevolutLineItem>>,
    pub shipping: Option<RevolutShipping>,
    pub capture_mode: Option<RevolutCaptureMode>,
    pub cancel_authorised_after: Option<String>,
    pub location_id: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub industry_data: Option<serde_json::Value>,
    pub merchant_order_data: Option<serde_json::Value>,
    pub upcoming_payment_data: Option<serde_json::Value>,
    pub redirect_url: Option<url::Url>,
    pub statement_descriptor_suffix: Option<String>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevolutCustomer {
    pub id: Option<String>,
    pub full_name: Option<Secret<String>>,
    pub phone: Option<Secret<String>>,
    pub email: Option<common_utils::pii::Email>,
    pub date_of_birth: Option<Date>,
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
    #[serde(rename = "type")]
    pub line_item_type: RevolutLineItemType,
    pub quantity: RevolutLineItemQuantity,
    pub unit_price_amount: MinorUnit, //integer(int64)
    pub total_amount: MinorUnit,      //integer(int64)
    pub external_id: Option<String>,
    pub discounts: Option<Vec<RevolutLineItemDiscount>>,
    pub taxes: Option<Vec<RevolutLineItemTax>>,
    pub image_urls: Option<Vec<url::Url>>,
    pub description: Option<String>,
    pub url: Option<url::Url>,
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
    pub street_line_1: Option<Secret<String>>,
    pub street_line_2: Option<Secret<String>>,
    pub region: Option<Secret<String>>,
    pub city: Option<Secret<String>>,
    pub country_code: Option<common_enums::CountryAlpha2>,
    pub postcode: Option<Secret<String>>,
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
    pub estimated_delivery_date: Option<Date>,
    pub tracking_url: Option<url::Url>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevolutErrorCode {
    Unauthenticated,
    Unauthorized,
    NotFound,
    InvalidRequest,
    PaymentDeclined,
    BadRequest,
    #[serde(other)]
    Unknown,
}

impl From<RevolutErrorCode> for common_enums::AttemptStatus {
    fn from(code: RevolutErrorCode) -> Self {
        match code {
            RevolutErrorCode::Unauthenticated => Self::AuthenticationFailed,
            RevolutErrorCode::Unauthorized => Self::AuthorizationFailed,
            RevolutErrorCode::NotFound => Self::Failure,
            RevolutErrorCode::InvalidRequest => Self::Failure,
            RevolutErrorCode::PaymentDeclined => Self::Failure,
            RevolutErrorCode::BadRequest => Self::Failure,
            RevolutErrorCode::Unknown => Self::Failure,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum RevolutErrorResponse {
    StandardError {
        code: RevolutErrorCode,
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
    pub token: Secret<String>,
    #[serde(rename = "type")]
    pub order_type: RevolutOrderType,
    pub state: RevolutOrderState,
    pub created_at: String,
    pub updated_at: String,
    pub description: Option<String>,
    pub capture_mode: Option<RevolutCaptureMode>,
    pub cancel_authorised_after: Option<String>,
    pub amount: MinorUnit,
    pub outstanding_amount: Option<MinorUnit>,
    pub refunded_amount: Option<MinorUnit>,
    pub currency: common_enums::Currency,
    pub settlement_currency: Option<common_enums::Currency>,
    pub customer: Option<RevolutCustomer>,
    pub payments: Option<Vec<RevolutPayment>>,
    pub location_id: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub industry_data: Option<serde_json::Value>,
    pub merchant_order_data: Option<RevolutMerchantOrderData>,
    pub upcoming_payment_data: Option<RevolutUpcomingPaymentData>,
    pub checkout_url: Option<url::Url>,
    pub redirect_url: Option<url::Url>,
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

#[derive(Debug, Clone, Serialize, Deserialize, strum::Display)]
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
    pub token: Option<Secret<String>>,
    pub amount: MinorUnit,
    pub currency: common_enums::Currency,
    pub settled_amount: Option<MinorUnit>,
    pub settled_currency: Option<common_enums::Currency>,
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
    pub url: Option<url::Url>,
    pub reference: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevolutUpcomingPaymentData {
    #[serde(with = "common_utils::custom_serde::iso8601")]
    pub date: time::PrimitiveDateTime,
    pub payment_method_id: Secret<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevolutRiskLevel {
    Low,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevolutFee {
    #[serde(rename = "type")]
    pub fee_type: RevolutFeeType,
    pub amount: MinorUnit,
    pub currency: common_enums::Currency,
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

        let customer = Some(RevolutCustomer {
            id: None,
            full_name: router_data
                .resource_common_data
                .get_billing_full_name()
                .ok(),
            phone: router_data
                .resource_common_data
                .get_billing_phone_number()
                .ok(),
            email: router_data.resource_common_data.get_billing_email().ok(),
            date_of_birth: None,
        });

        let shipping = Some(RevolutShipping {
            address: Some(RevolutAddress {
                street_line_1: router_data
                    .resource_common_data
                    .get_optional_shipping_line1(),
                street_line_2: router_data
                    .resource_common_data
                    .get_optional_shipping_line2(),
                region: router_data
                    .resource_common_data
                    .get_optional_shipping_state(),
                city: router_data
                    .resource_common_data
                    .get_optional_shipping_city(),
                country_code: router_data
                    .resource_common_data
                    .get_optional_shipping_country(),
                postcode: router_data.resource_common_data.get_optional_shipping_zip(),
            }),
            contact: Some(RevolutContact {
                full_name: router_data
                    .resource_common_data
                    .get_optional_shipping_full_name(),
                phone: router_data
                    .resource_common_data
                    .get_optional_shipping_phone_number(),
                email: router_data
                    .resource_common_data
                    .get_optional_shipping_email(),
            }),
            shipments: None,
        });

        let capture_mode = if router_data.request.is_auto_capture()? {
            Some(RevolutCaptureMode::Automatic)
        } else {
            Some(RevolutCaptureMode::Manual)
        };

        let request = Self {
            amount: router_data.request.amount,
            currency: router_data.request.currency,
            settlement_currency: None,
            description: router_data.request.statement_descriptor.clone(),
            customer,
            enforce_challenge: None,
            line_items: None,
            shipping,
            capture_mode,
            cancel_authorised_after: None,
            location_id: None,
            metadata: router_data.request.metadata.clone(),
            industry_data: None,
            merchant_order_data: None,
            upcoming_payment_data: None,
            redirect_url: router_data
                .request
                .router_return_url
                .clone()
                .and_then(|url| url::Url::parse(&url).ok()),
            statement_descriptor_suffix: router_data.request.statement_descriptor_suffix.clone(),
        };

        Ok(request)
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

        let status = response.state.into();

        let redirection_data = response.checkout_url.as_ref().map(|url| {
            Box::new(RedirectForm::Uri {
                uri: url.to_string(),
            })
        });

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(response.id.clone()),
                redirection_data,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(response.id),
                incremental_authorization_allowed: None,
                status_code: item.http_code,
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
        let state_for_error = response.state.clone();

        let (status, _payment_id) = response
            .payments
            .as_ref()
            .and_then(|payments| payments.first())
            .map(|first_payment| {
                first_payment
                    .state
                    .clone()
                    .try_into()
                    .map(|status| (status, Some(first_payment.id.clone())))
            })
            .transpose()
            .map_err(|_| ConnectorError::ResponseDeserializationFailed)?
            .unwrap_or_else(|| (response.state.into(), None));

        let redirection_data = response.checkout_url.as_ref().map(|url| {
            Box::new(RedirectForm::Uri {
                uri: url.to_string(),
            })
        });

        let response_result = if domain_types::utils::is_payment_failure(status) {
            Err(create_failure_error_response(
                state_for_error,
                Some(response.id.clone()),
                item.http_code,
            ))
        } else {
            Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(response.id.clone()),
                redirection_data,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(response.id.clone()),
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            })
        };

        Ok(Self {
            response: response_result,
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

impl From<RevolutOrderState> for common_enums::AttemptStatus {
    fn from(state: RevolutOrderState) -> Self {
        match state {
            RevolutOrderState::Authorised => Self::Authorized,
            RevolutOrderState::Completed => Self::Charged,
            RevolutOrderState::Failed => Self::Failure,
            RevolutOrderState::Cancelled => Self::Voided,
            RevolutOrderState::Pending => Self::AuthenticationPending,
            RevolutOrderState::Processing => Self::Pending,
        }
    }
}

impl TryFrom<RevolutPaymentState> for common_enums::AttemptStatus {
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(state: RevolutPaymentState) -> Result<Self, Self::Error> {
        match state {
            RevolutPaymentState::Authorised => Ok(Self::Authorized),
            RevolutPaymentState::Captured | RevolutPaymentState::Completed => Ok(Self::Charged),
            RevolutPaymentState::Failed | RevolutPaymentState::Declined => Ok(Self::Failure),
            RevolutPaymentState::Cancelled => Ok(Self::Voided),
            RevolutPaymentState::Pending => Ok(Self::Pending),
            RevolutPaymentState::AuthenticationChallenge => Ok(Self::AuthenticationPending),
            RevolutPaymentState::SoftDeclined
            | RevolutPaymentState::AuthenticationVerified
            | RevolutPaymentState::AuthorisationStarted
            | RevolutPaymentState::AuthorisationPassed
            | RevolutPaymentState::CaptureStarted
            | RevolutPaymentState::RefundValidated
            | RevolutPaymentState::RefundStarted
            | RevolutPaymentState::CancellationStarted
            | RevolutPaymentState::Declining
            | RevolutPaymentState::Completing
            | RevolutPaymentState::Cancelling
            | RevolutPaymentState::Failing => Ok(Self::Pending),
        }
    }
}

fn create_failure_error_response<T: ToString>(
    status: T,
    connector_id: Option<String>,
    http_code: u16,
) -> domain_types::router_data::ErrorResponse {
    let status_string = status.to_string();
    domain_types::router_data::ErrorResponse {
        code: status_string.clone(),
        message: status_string.clone(),
        reason: Some(status_string),
        attempt_status: None,
        connector_transaction_id: connector_id,
        status_code: http_code,
        network_advice_code: None,
        network_decline_code: None,
        network_error_message: None,
    }
}
