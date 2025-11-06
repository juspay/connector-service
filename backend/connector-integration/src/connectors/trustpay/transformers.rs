use crate::utils;
use crate::{connectors::trustpay::TrustpayRouterData, types::ResponseRouterData};
use common_enums::enums;
use common_utils::{
    consts::{NO_ERROR_CODE, NO_ERROR_MESSAGE},
    errors::CustomResult,
    request::Method,
    types::{FloatMajorUnit, StringMajorUnit},
    Email,
};
use domain_types::{
    connector_flow::CreateAccessToken,
    connector_types::{
        AccessTokenRequestData, AccessTokenResponseData, PaymentFlowData, PaymentsResponseData,
        ResponseId,
    },
    errors::{self, ConnectorError},
    payment_method_data::{BankRedirectData, BankTransferData, PaymentMethodDataTypes},
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
};
# use hyperswitch_masking::{ExposeInterface, Secret};
use serde::{Deserialize, Serialize};

use reqwest::Url;
use std::collections::HashMap;

type Error = error_stack::Report<errors::ConnectorError>;

#[allow(dead_code)]
pub struct TrustpayAuthType {
    pub(super) api_key: Secret<String>,
    pub(super) project_id: Secret<String>,
    pub(super) secret_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for TrustpayAuthType {
    type Error = Error;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        if let ConnectorAuthType::SignatureKey {
            api_key,
            key1,
            api_secret,
        } = auth_type
        {
            Ok(Self {
                api_key: api_key.to_owned(),
                project_id: key1.to_owned(),
                secret_key: api_secret.to_owned(),
            })
        } else {
            Err(errors::ConnectorError::FailedToObtainAuthType.into())
        }
    }
}

const CLIENT_CREDENTIAL: &str = "client_credentials";

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum TrustpayPaymentMethod {
    #[serde(rename = "EPS")]
    Eps,
    Giropay,
    IDeal,
    Sofort,
    Blik,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum TrustpayBankTransferPaymentMethod {
    SepaCreditTransfer,
    #[serde(rename = "Wire")]
    InstantBankTransfer,
    InstantBankTransferFI,
    InstantBankTransferPL,
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct MerchantIdentification {
    pub project_id: Secret<String>,
}

#[derive(Default, Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct References {
    pub merchant_reference: String,
}

#[derive(Default, Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct Amount {
    pub amount: StringMajorUnit,
    pub currency: String,
}

#[derive(Default, Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct Reason {
    pub code: Option<String>,
    pub reject_reason: Option<String>,
}

#[derive(Default, Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct StatusReasonInformation {
    pub reason: Reason,
}

#[derive(Default, Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct DebtorInformation {
    pub name: Secret<String>,
    pub email: Email,
}

#[derive(Default, Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct BankPaymentInformation {
    pub amount: Amount,
    pub references: References,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub debtor: Option<DebtorInformation>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct BankPaymentInformationResponse {
    pub status: TrustpayBankRedirectPaymentStatus,
    pub status_reason_information: Option<StatusReasonInformation>,
    pub references: ReferencesResponse,
    pub amount: WebhookAmount,
}

#[derive(Debug, Serialize, Eq, PartialEq)]
pub struct CallbackURLs {
    pub success: String,
    pub cancel: String,
    pub error: String,
}

impl TryFrom<&BankRedirectData> for TrustpayPaymentMethod {
    type Error = Error;
    fn try_from(value: &BankRedirectData) -> Result<Self, Self::Error> {
        match value {
            BankRedirectData::Giropay { .. } => Ok(Self::Giropay),
            BankRedirectData::Eps { .. } => Ok(Self::Eps),
            BankRedirectData::Ideal { .. } => Ok(Self::IDeal),
            BankRedirectData::Sofort { .. } => Ok(Self::Sofort),
            BankRedirectData::Blik { .. } => Ok(Self::Blik),
            BankRedirectData::BancontactCard { .. }
            | BankRedirectData::Bizum {}
            | BankRedirectData::Eft { .. }
            | BankRedirectData::Interac { .. }
            | BankRedirectData::OnlineBankingCzechRepublic { .. }
            | BankRedirectData::OnlineBankingFinland { .. }
            | BankRedirectData::OnlineBankingPoland { .. }
            | BankRedirectData::OnlineBankingSlovakia { .. }
            | BankRedirectData::OpenBankingUk { .. }
            | BankRedirectData::Przelewy24 { .. }
            | BankRedirectData::Trustly { .. }
            | BankRedirectData::OnlineBankingFpx { .. }
            | BankRedirectData::OnlineBankingThailand { .. }
            | BankRedirectData::LocalBankRedirect {} => {
                Err(errors::ConnectorError::NotImplemented(
                    utils::get_unimplemented_payment_method_error_message("trustpay"),
                )
                .into())
            }
        }
    }
}

impl TryFrom<&BankTransferData> for TrustpayBankTransferPaymentMethod {
    type Error = Error;
    fn try_from(value: &BankTransferData) -> Result<Self, Self::Error> {
        match value {
            BankTransferData::SepaBankTransfer { .. } => Ok(Self::SepaCreditTransfer),
            BankTransferData::InstantBankTransfer {} => Ok(Self::InstantBankTransfer),
            BankTransferData::InstantBankTransferFinland {} => Ok(Self::InstantBankTransferFI),
            BankTransferData::InstantBankTransferPoland {} => Ok(Self::InstantBankTransferPL),
            _ => Err(errors::ConnectorError::NotImplemented(
                utils::get_unimplemented_payment_method_error_message("trustpay"),
            )
            .into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustpayPaymentStatusCode {
    // CVV and card validation errors
    EmptyCvvNotAllowed,

    // Authentication and session errors
    SessionRejected,
    UserAuthenticationFailed,
    RiskManagementTimeout,
    PaResValidationFailed,
    ThreeDSecureSystemError,
    DirectoryServerError,
    ThreeDSystemError,
    AuthenticationInvalidFormat,
    AuthenticationSuspectedFraud,

    // Input and parameter errors
    InvalidInputData,
    AmountOutsideBoundaries,
    InvalidOrMissingParameter,

    // Transaction decline reasons
    AdditionalAuthRequired,
    CardNotEnrolledIn3DS,
    AuthenticationError,
    TransactionDeclinedAuth,
    InvalidTransaction1,
    InvalidTransaction2,
    NoDescription,

    // Refund errors
    CannotRefund,
    TooManyTransactions,
    TestAccountsNotAllowed,

    // General decline reasons
    DeclinedUnknownReason,
    DeclinedInvalidCard,
    DeclinedByAuthSystem,
    DeclinedInvalidCvv,
    DeclinedExceedsCredit,
    DeclinedWrongExpiry,
    DeclinedSuspectingManipulation,
    DeclinedCardBlocked,
    DeclinedLimitExceeded,
    DeclinedFrequencyExceeded,
    DeclinedCardLost,
    DeclinedRestrictedCard,
    DeclinedNotPermitted,
    DeclinedPickUpCard,
    DeclinedAccountBlocked,
    DeclinedInvalidConfig,
    AccountClosed,
    InsufficientFunds,
    RejectedByThrottling,
    CountryBlacklisted,
    BinBlacklisted,
    SessionBeingProcessed,

    // Communication errors
    CommunicationError,
    TimeoutUncertainResult,

    // Success or other status
    Unknown,
}

impl TrustpayPaymentStatusCode {
    pub fn error_message(&self) -> &'static str {
        match self {
            Self::EmptyCvvNotAllowed => "Empty CVV for VISA, MASTER not allowed",
            Self::SessionRejected => "Referenced session is rejected (no action possible)",
            Self::UserAuthenticationFailed => "User authentication failed",
            Self::RiskManagementTimeout => "Risk management transaction timeout",
            Self::PaResValidationFailed => "PARes validation failed - problem with signature",
            Self::ThreeDSecureSystemError => "Transaction rejected because of technical error in 3DSecure system",
            Self::DirectoryServerError => "Communication error to VISA/Mastercard Directory Server",
            Self::ThreeDSystemError => "Technical error in 3D system",
            Self::AuthenticationInvalidFormat => "Authentication failed due to invalid message format",
            Self::AuthenticationSuspectedFraud => "Authentication failed due to suspected fraud",
            Self::InvalidInputData => "Invalid input data",
            Self::AmountOutsideBoundaries => "Amount is outside allowed ticket size boundaries",
            Self::InvalidOrMissingParameter => "Invalid or missing parameter",
            Self::AdditionalAuthRequired => "Transaction declined (additional customer authentication required)",
            Self::CardNotEnrolledIn3DS => "Card not enrolled in 3DS",
            Self::AuthenticationError => "Authentication error",
            Self::TransactionDeclinedAuth => "Transaction declined (auth. declined)",
            Self::InvalidTransaction1 => "Invalid transaction",
            Self::InvalidTransaction2 => "Invalid transaction",
            Self::NoDescription => "No description available.",
            Self::CannotRefund => "Cannot refund (refund volume exceeded or tx reversed or invalid workflow)",
            Self::TooManyTransactions => "Referenced session contains too many transactions",
            Self::TestAccountsNotAllowed => "Test accounts not allowed in production",
            Self::DeclinedUnknownReason => "Transaction declined for unknown reason",
            Self::DeclinedInvalidCard => "Transaction declined (invalid card)",
            Self::DeclinedByAuthSystem => "Transaction declined by authorization system",
            Self::DeclinedInvalidCvv => "Transaction declined (invalid CVV)",
            Self::DeclinedExceedsCredit => "Transaction declined (amount exceeds credit)",
            Self::DeclinedWrongExpiry => "Transaction declined (wrong expiry date)",
            Self::DeclinedSuspectingManipulation => "transaction declined (suspecting manipulation)",
            Self::DeclinedCardBlocked => "transaction declined (card blocked)",
            Self::DeclinedLimitExceeded => "Transaction declined (limit exceeded)",
            Self::DeclinedFrequencyExceeded => "Transaction declined (maximum transaction frequency exceeded)",
            Self::DeclinedCardLost => "Transaction declined (card lost)",
            Self::DeclinedRestrictedCard => "Transaction declined (restricted card)",
            Self::DeclinedNotPermitted => "Transaction declined (transaction not permitted)",
            Self::DeclinedPickUpCard => "transaction declined (pick up card)",
            Self::DeclinedAccountBlocked => "Transaction declined (account blocked)",
            Self::DeclinedInvalidConfig => "Transaction declined (invalid configuration data)",
            Self::AccountClosed => "Account Closed",
            Self::InsufficientFunds => "Insufficient Funds",
            Self::RejectedByThrottling => "Rejected by throttling",
            Self::CountryBlacklisted => "Country blacklisted",
            Self::BinBlacklisted => "Bin blacklisted",
            Self::SessionBeingProcessed => "Transaction for the same session is currently being processed, please try again later",
            Self::CommunicationError => "Unexpected communication error with connector/acquirer",
            Self::TimeoutUncertainResult => "Timeout, uncertain result",
            Self::Unknown => "",
        }
    }

    pub fn is_failure(&self) -> bool {
        !matches!(self, Self::Unknown)
    }
}

impl From<&str> for TrustpayPaymentStatusCode {
    fn from(status_code: &str) -> Self {
        match status_code {
            "100.100.600" => Self::EmptyCvvNotAllowed,
            "100.350.100" => Self::SessionRejected,
            "100.380.401" => Self::UserAuthenticationFailed,
            "100.380.501" => Self::RiskManagementTimeout,
            "100.390.103" => Self::PaResValidationFailed,
            "100.390.105" => Self::ThreeDSecureSystemError,
            "100.390.111" => Self::DirectoryServerError,
            "100.390.112" => Self::ThreeDSystemError,
            "100.390.115" => Self::AuthenticationInvalidFormat,
            "100.390.118" => Self::AuthenticationSuspectedFraud,
            "100.400.304" => Self::InvalidInputData,
            "100.550.312" => Self::AmountOutsideBoundaries,
            "200.300.404" => Self::InvalidOrMissingParameter,
            "300.100.100" => Self::AdditionalAuthRequired,
            "400.001.301" => Self::CardNotEnrolledIn3DS,
            "400.001.600" => Self::AuthenticationError,
            "400.001.601" => Self::TransactionDeclinedAuth,
            "400.001.602" => Self::InvalidTransaction1,
            "400.001.603" => Self::InvalidTransaction2,
            "400.003.600" => Self::NoDescription,
            "700.400.200" => Self::CannotRefund,
            "700.500.001" => Self::TooManyTransactions,
            "700.500.003" => Self::TestAccountsNotAllowed,
            "800.100.100" => Self::DeclinedUnknownReason,
            "800.100.151" => Self::DeclinedInvalidCard,
            "800.100.152" => Self::DeclinedByAuthSystem,
            "800.100.153" => Self::DeclinedInvalidCvv,
            "800.100.155" => Self::DeclinedExceedsCredit,
            "800.100.157" => Self::DeclinedWrongExpiry,
            "800.100.158" => Self::DeclinedSuspectingManipulation,
            "800.100.160" => Self::DeclinedCardBlocked,
            "800.100.162" => Self::DeclinedLimitExceeded,
            "800.100.163" => Self::DeclinedFrequencyExceeded,
            "800.100.165" => Self::DeclinedCardLost,
            "800.100.168" => Self::DeclinedRestrictedCard,
            "800.100.170" => Self::DeclinedNotPermitted,
            "800.100.171" => Self::DeclinedPickUpCard,
            "800.100.172" => Self::DeclinedAccountBlocked,
            "800.100.190" => Self::DeclinedInvalidConfig,
            "800.100.202" => Self::AccountClosed,
            "800.100.203" => Self::InsufficientFunds,
            "800.120.100" => Self::RejectedByThrottling,
            "800.300.102" => Self::CountryBlacklisted,
            "800.300.401" => Self::BinBlacklisted,
            "800.700.100" => Self::SessionBeingProcessed,
            "900.100.100" => Self::CommunicationError,
            "900.100.300" => Self::TimeoutUncertainResult,
            _ => Self::Unknown,
        }
    }
}

fn is_payment_failed(payment_status: &str) -> (bool, &'static str) {
    let status_code = TrustpayPaymentStatusCode::from(payment_status);
    (status_code.is_failure(), status_code.error_message())
}

fn is_payment_successful(payment_status: &str) -> CustomResult<bool, errors::ConnectorError> {
    match payment_status {
        "000.400.100" => Ok(true),
        _ => {
            let allowed_prefixes = [
                "000.000.",
                "000.100.1",
                "000.3",
                "000.6",
                "000.400.01",
                "000.400.02",
                "000.400.04",
                "000.400.05",
                "000.400.06",
                "000.400.07",
                "000.400.08",
                "000.400.09",
            ];
            let is_valid = allowed_prefixes
                .iter()
                .any(|&prefix| payment_status.starts_with(prefix));
            Ok(is_valid)
        }
    }
}

fn get_pending_status_based_on_redirect_url(redirect_url: Option<Url>) -> enums::AttemptStatus {
    match redirect_url {
        Some(_url) => enums::AttemptStatus::AuthenticationPending,
        None => enums::AttemptStatus::Pending,
    }
}

fn get_transaction_status(
    payment_status: Option<String>,
    redirect_url: Option<Url>,
) -> CustomResult<(enums::AttemptStatus, Option<String>), errors::ConnectorError> {
    // We don't get payment_status only in case, when the user doesn't complete the authentication step.
    // If we receive status, then return the proper status based on the connector response
    if let Some(payment_status) = payment_status {
        let (is_failed, failure_message) = is_payment_failed(&payment_status);
        if is_failed {
            Ok((
                enums::AttemptStatus::Failure,
                Some(failure_message.to_string()),
            ))
        } else if is_payment_successful(&payment_status)? {
            Ok((enums::AttemptStatus::Charged, None))
        } else {
            let pending_status = get_pending_status_based_on_redirect_url(redirect_url);
            Ok((pending_status, None))
        }
    } else {
        Ok((enums::AttemptStatus::AuthenticationPending, None))
    }
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub enum TrustpayBankRedirectPaymentStatus {
    Paid,
    Authorized,
    Rejected,
    Authorizing,
    Pending,
}

impl From<TrustpayBankRedirectPaymentStatus> for enums::AttemptStatus {
    fn from(item: TrustpayBankRedirectPaymentStatus) -> Self {
        match item {
            TrustpayBankRedirectPaymentStatus::Paid => Self::Charged,
            TrustpayBankRedirectPaymentStatus::Rejected => Self::AuthorizationFailed,
            TrustpayBankRedirectPaymentStatus::Authorized => Self::Authorized,
            TrustpayBankRedirectPaymentStatus::Authorizing => Self::Authorizing,
            TrustpayBankRedirectPaymentStatus::Pending => Self::Authorizing,
        }
    }
}

impl From<TrustpayBankRedirectPaymentStatus> for enums::RefundStatus {
    fn from(item: TrustpayBankRedirectPaymentStatus) -> Self {
        match item {
            TrustpayBankRedirectPaymentStatus::Paid => Self::Success,
            TrustpayBankRedirectPaymentStatus::Rejected => Self::Failure,
            _ => Self::Pending,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PaymentsResponseCards {
    pub status: i64,
    pub description: Option<String>,
    pub instance_id: String,
    pub payment_status: Option<String>,
    pub payment_description: Option<String>,
    pub redirect_url: Option<Url>,
    pub redirect_params: Option<HashMap<String, String>>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct PaymentsResponseBankRedirect {
    pub payment_request_id: i64,
    pub gateway_url: Url,
    pub payment_result_info: Option<ResultInfo>,
    pub payment_method_response: Option<TrustpayPaymentMethod>,
    pub merchant_identification_response: Option<MerchantIdentification>,
    pub payment_information_response: Option<BankPaymentInformationResponse>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct ErrorResponseBankRedirect {
    #[serde(rename = "ResultInfo")]
    pub payment_result_info: ResultInfo,
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct ReferencesResponse {
    pub payment_request_id: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct SyncResponseBankRedirect {
    pub payment_information: BankPaymentInformationResponse,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum TrustpayPaymentsResponse {
    CardsPayments(Box<PaymentsResponseCards>),
    BankRedirectPayments(Box<PaymentsResponseBankRedirect>),
    BankRedirectSync(Box<SyncResponseBankRedirect>),
    BankRedirectError(Box<ErrorResponseBankRedirect>),
    WebhookResponse(Box<WebhookPaymentInformation>),
}

impl<F, T> TryFrom<ResponseRouterData<TrustpayPaymentsResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, T, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<TrustpayPaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let (status, error, payment_response_data) = get_trustpay_response(
            item.response,
            item.http_code,
            item.router_data.resource_common_data.status,
        )?;
        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            response: error.map_or_else(|| Ok(payment_response_data), Err),
            ..item.router_data
        })
    }
}

fn handle_cards_response(
    response: PaymentsResponseCards,
    status_code: u16,
) -> CustomResult<
    (
        enums::AttemptStatus,
        Option<ErrorResponse>,
        PaymentsResponseData,
    ),
    errors::ConnectorError,
> {
    let (status, message) = get_transaction_status(
        response.payment_status.to_owned(),
        response.redirect_url.to_owned(),
    )?;

    let form_fields = response.redirect_params.unwrap_or_default();
    let redirection_data = response.redirect_url.map(|url| RedirectForm::Form {
        endpoint: url.to_string(),
        method: Method::Post,
        form_fields,
    });
    let error = if message.is_some() {
        Some(ErrorResponse {
            code: response
                .payment_status
                .unwrap_or_else(|| NO_ERROR_CODE.to_string()),
            message: message
                .clone()
                .unwrap_or_else(|| NO_ERROR_MESSAGE.to_string()),
            reason: message,
            status_code,
            attempt_status: None,
            connector_transaction_id: Some(response.instance_id.clone()),
            network_advice_code: None,
            network_decline_code: None,
            network_error_message: None,
        })
    } else {
        None
    };
    let payment_response_data = PaymentsResponseData::TransactionResponse {
        resource_id: ResponseId::ConnectorTransactionId(response.instance_id.clone()),
        redirection_data: redirection_data.map(Box::new),
        mandate_reference: None,
        connector_metadata: None,
        network_txn_id: None,
        connector_response_reference_id: None,
        incremental_authorization_allowed: None,
        status_code,
    };
    Ok((status, error, payment_response_data))
}

fn handle_bank_redirects_response(
    response: PaymentsResponseBankRedirect,
    status_code: u16,
) -> CustomResult<
    (
        enums::AttemptStatus,
        Option<ErrorResponse>,
        PaymentsResponseData,
    ),
    errors::ConnectorError,
> {
    let status = enums::AttemptStatus::AuthenticationPending;
    let error = None;
    let payment_response_data = PaymentsResponseData::TransactionResponse {
        resource_id: ResponseId::ConnectorTransactionId(response.payment_request_id.to_string()),
        redirection_data: Some(Box::new(RedirectForm::from((
            response.gateway_url,
            Method::Get,
        )))),
        mandate_reference: None,
        connector_metadata: None,
        network_txn_id: None,
        connector_response_reference_id: None,
        incremental_authorization_allowed: None,
        status_code,
    };
    Ok((status, error, payment_response_data))
}

fn handle_bank_redirects_error_response(
    response: ErrorResponseBankRedirect,
    status_code: u16,
    previous_attempt_status: enums::AttemptStatus,
) -> CustomResult<
    (
        enums::AttemptStatus,
        Option<ErrorResponse>,
        PaymentsResponseData,
    ),
    errors::ConnectorError,
> {
    let status = if matches!(response.payment_result_info.result_code, 1132014 | 1132005) {
        previous_attempt_status
    } else {
        enums::AttemptStatus::AuthorizationFailed
    };
    let error = Some(ErrorResponse {
        code: response.payment_result_info.result_code.to_string(),
        // message vary for the same code, so relying on code alone as it is unique
        message: response.payment_result_info.result_code.to_string(),
        reason: response.payment_result_info.additional_info,
        status_code,
        attempt_status: Some(status),
        connector_transaction_id: None,
        network_advice_code: None,
        network_decline_code: None,
        network_error_message: None,
    });
    let payment_response_data = PaymentsResponseData::TransactionResponse {
        resource_id: ResponseId::NoResponseId,
        redirection_data: None,
        mandate_reference: None,
        connector_metadata: None,
        network_txn_id: None,
        connector_response_reference_id: None,
        incremental_authorization_allowed: None,
        status_code,
    };
    Ok((status, error, payment_response_data))
}

fn handle_bank_redirects_sync_response(
    response: SyncResponseBankRedirect,
    status_code: u16,
) -> CustomResult<
    (
        enums::AttemptStatus,
        Option<ErrorResponse>,
        PaymentsResponseData,
    ),
    errors::ConnectorError,
> {
    let status = enums::AttemptStatus::from(response.payment_information.status);
    let error = if domain_types::utils::is_payment_failure(status) {
        let reason_info = response
            .payment_information
            .status_reason_information
            .unwrap_or_default();
        Some(ErrorResponse {
            code: reason_info
                .reason
                .code
                .clone()
                .unwrap_or(NO_ERROR_CODE.to_string()),
            // message vary for the same code, so relying on code alone as it is unique
            message: reason_info
                .reason
                .code
                .unwrap_or(NO_ERROR_MESSAGE.to_string()),
            reason: reason_info.reason.reject_reason,
            status_code,
            attempt_status: None,
            connector_transaction_id: Some(
                response
                    .payment_information
                    .references
                    .payment_request_id
                    .clone(),
            ),
            network_advice_code: None,
            network_decline_code: None,
            network_error_message: None,
        })
    } else {
        None
    };
    let payment_response_data = PaymentsResponseData::TransactionResponse {
        resource_id: ResponseId::ConnectorTransactionId(
            response
                .payment_information
                .references
                .payment_request_id
                .clone(),
        ),
        redirection_data: None,
        mandate_reference: None,
        connector_metadata: None,
        network_txn_id: None,
        connector_response_reference_id: None,
        incremental_authorization_allowed: None,
        status_code,
    };
    Ok((status, error, payment_response_data))
}

pub fn handle_webhook_response(
    payment_information: WebhookPaymentInformation,
    status_code: u16,
) -> CustomResult<
    (
        enums::AttemptStatus,
        Option<ErrorResponse>,
        PaymentsResponseData,
    ),
    errors::ConnectorError,
> {
    let status = enums::AttemptStatus::try_from(payment_information.status)?;
    let error = if domain_types::utils::is_payment_failure(status) {
        let reason_info = payment_information
            .status_reason_information
            .unwrap_or_default();
        Some(ErrorResponse {
            code: reason_info
                .reason
                .code
                .clone()
                .unwrap_or(NO_ERROR_CODE.to_string()),
            // message vary for the same code, so relying on code alone as it is unique
            message: reason_info
                .reason
                .code
                .unwrap_or(NO_ERROR_MESSAGE.to_string()),
            reason: reason_info.reason.reject_reason,
            status_code,
            attempt_status: None,
            connector_transaction_id: payment_information.references.payment_request_id.clone(),
            network_advice_code: None,
            network_decline_code: None,
            network_error_message: None,
        })
    } else {
        None
    };
    let payment_response_data = PaymentsResponseData::TransactionResponse {
        resource_id: ResponseId::NoResponseId,
        redirection_data: None,
        mandate_reference: None,
        connector_metadata: None,
        network_txn_id: None,
        connector_response_reference_id: None,
        incremental_authorization_allowed: None,
        status_code,
    };
    Ok((status, error, payment_response_data))
}

pub fn get_trustpay_response(
    response: TrustpayPaymentsResponse,
    status_code: u16,
    previous_attempt_status: enums::AttemptStatus,
) -> CustomResult<
    (
        enums::AttemptStatus,
        Option<ErrorResponse>,
        PaymentsResponseData,
    ),
    errors::ConnectorError,
> {
    match response {
        TrustpayPaymentsResponse::CardsPayments(response) => {
            handle_cards_response(*response, status_code)
        }
        TrustpayPaymentsResponse::BankRedirectPayments(response) => {
            handle_bank_redirects_response(*response, status_code)
        }
        TrustpayPaymentsResponse::BankRedirectSync(response) => {
            handle_bank_redirects_sync_response(*response, status_code)
        }
        TrustpayPaymentsResponse::BankRedirectError(response) => {
            handle_bank_redirects_error_response(*response, status_code, previous_attempt_status)
        }
        TrustpayPaymentsResponse::WebhookResponse(response) => {
            handle_webhook_response(*response, status_code)
        }
    }
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct ResultInfo {
    pub result_code: i64,
    pub additional_info: Option<String>,
    pub correlation_id: Option<String>,
}

#[derive(Default, Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct Errors {
    pub code: i64,
    pub description: String,
}

#[derive(Default, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TrustpayErrorResponse {
    pub status: i64,
    pub description: Option<String>,
    pub errors: Option<Vec<Errors>>,
    pub instance_id: Option<String>,
    pub payment_description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum CreditDebitIndicator {
    Crdt,
    Dbit,
}

#[derive(strum::Display, Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum WebhookStatus {
    Paid,
    Rejected,
    Refunded,
    Chargebacked,
    #[serde(other)]
    Unknown,
}

impl TryFrom<WebhookStatus> for enums::AttemptStatus {
    type Error = errors::ConnectorError;
    fn try_from(item: WebhookStatus) -> Result<Self, Self::Error> {
        match item {
            WebhookStatus::Paid => Ok(Self::Charged),
            WebhookStatus::Rejected => Ok(Self::AuthorizationFailed),
            _ => Err(errors::ConnectorError::WebhookEventTypeNotFound),
        }
    }
}

impl TryFrom<WebhookStatus> for enums::RefundStatus {
    type Error = errors::ConnectorError;
    fn try_from(item: WebhookStatus) -> Result<Self, Self::Error> {
        match item {
            WebhookStatus::Paid => Ok(Self::Success),
            WebhookStatus::Refunded => Ok(Self::Success),
            WebhookStatus::Rejected => Ok(Self::Failure),
            _ => Err(errors::ConnectorError::WebhookEventTypeNotFound),
        }
    }
}

#[derive(Default, Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct WebhookReferences {
    pub merchant_reference: Option<String>,
    pub payment_id: Option<String>,
    pub payment_request_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct WebhookAmount {
    pub amount: FloatMajorUnit,
    pub currency: enums::Currency,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct WebhookPaymentInformation {
    pub credit_debit_indicator: CreditDebitIndicator,
    pub references: WebhookReferences,
    pub status: WebhookStatus,
    pub amount: WebhookAmount,
    pub status_reason_information: Option<StatusReasonInformation>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct TrustpayAuthUpdateRequest {
    pub grant_type: String,
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        TrustpayRouterData<
            RouterDataV2<
                CreateAccessToken,
                PaymentFlowData,
                AccessTokenRequestData,
                AccessTokenResponseData,
            >,
            T,
        >,
    > for TrustpayAuthUpdateRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        _item: TrustpayRouterData<
            RouterDataV2<
                CreateAccessToken,
                PaymentFlowData,
                AccessTokenRequestData,
                AccessTokenResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            grant_type: CLIENT_CREDENTIAL.to_string(),
        })
    }
}

#[derive(Default, Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct TrustpayAuthUpdateResponse {
    pub access_token: Option<Secret<String>>,
    pub token_type: Option<String>,
    pub expires_in: Option<i64>,
    #[serde(rename = "ResultInfo")]
    pub result_info: ResultInfo,
}

impl
    TryFrom<
        ResponseRouterData<
            TrustpayAuthUpdateResponse,
            RouterDataV2<
                CreateAccessToken,
                PaymentFlowData,
                AccessTokenRequestData,
                AccessTokenResponseData,
            >,
        >,
    >
    for RouterDataV2<
        CreateAccessToken,
        PaymentFlowData,
        AccessTokenRequestData,
        AccessTokenResponseData,
    >
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            TrustpayAuthUpdateResponse,
            RouterDataV2<
                CreateAccessToken,
                PaymentFlowData,
                AccessTokenRequestData,
                AccessTokenResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        match (item.response.access_token, item.response.expires_in) {
            (Some(access_token), Some(expires_in)) => Ok(Self {
                response: Ok(AccessTokenResponseData {
                    access_token: access_token.expose(),
                    expires_in: Some(expires_in),
                    token_type: Some(item.router_data.request.grant_type.clone()),
                }),
                ..item.router_data
            }),
            _ => Ok(Self {
                response: Err(ErrorResponse {
                    code: item.response.result_info.result_code.to_string(),
                    // message vary for the same code, so relying on code alone as it is unique
                    message: item.response.result_info.result_code.to_string(),
                    reason: item.response.result_info.additional_info,
                    status_code: item.http_code,
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }),
                ..item.router_data
            }),
        }
    }
}
