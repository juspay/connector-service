use crate::{connectors::deutschebank::DeutschebankRouterData, types::ResponseRouterData, utils};

use common_enums::{enums, PaymentMethod};
use common_utils::{consts, ext_traits::ValueExt, pii::Email, types::MinorUnit};
use domain_types::{
    connector_flow::{Authorize, Capture, PSync, RSync, Refund, Void},
    connector_types::{
        MandateReferenceId, PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData,
        PaymentsCaptureData, PaymentsResponseData, PaymentsSyncData, RefundFlowData,
        RefundSyncData, RefundsData, RefundsResponseData, ResponseId,
    },
    errors::ConnectorError,
    payment_method_data::{
        BankDebitData, PaymentMethodData, PaymentMethodDataTypes, RawCardNumber,
    },
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
};
use error_stack::ResultExt;

use hyperswitch_masking::{ExposeInterface, PeekInterface, Secret};
use serde::{Deserialize, Serialize};

#[allow(dead_code)]
pub struct DeutschebankAuthType {
    pub(super) client_id: Secret<String>,
    pub(super) merchant_id: Secret<String>,
    pub(super) client_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for DeutschebankAuthType {
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey {
                api_key,
                key1,
                api_secret,
            } => Ok(Self {
                client_id: api_key.to_owned(),
                merchant_id: key1.to_owned(),
                client_key: api_secret.to_owned(),
            }),
            _ => Err(ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

#[derive(Default, Debug, Serialize, PartialEq)]
pub struct DeutschebankAccessTokenRequest {
    pub grant_type: String,
    pub client_id: Secret<String>,
    pub client_secret: Secret<String>,
    pub scope: String,
}

#[derive(Default, Debug, Clone, Deserialize, PartialEq, Serialize)]
pub struct DeutschebankAccessTokenResponse {
    pub access_token: Secret<String>,
    pub expires_in: i64,
    pub expires_on: i64,
    pub scope: String,
    pub token_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum DeutschebankSEPAApproval {
    Click,
    Email,
    Sms,
    Dynamic,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct DeutschebankMandatePostRequest {
    approval_by: DeutschebankSEPAApproval,
    email_address: Email,
    iban: Secret<String>,
    first_name: Secret<String>,
    last_name: Secret<String>,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum DeutschebankPaymentsRequest<
    T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize,
> {
    MandatePost(DeutschebankMandatePostRequest),
    DirectDebit(DeutschebankDirectDebitRequest),
    CreditCard(Box<DeutschebankThreeDSInitializeRequest<T>>),
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct DeutschebankThreeDSInitializeRequest<
    T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize,
> {
    means_of_payment: DeutschebankThreeDSInitializeRequestMeansOfPayment<T>,
    tds_20_data: DeutschebankThreeDSInitializeRequestTds20Data,
    amount_total: DeutschebankThreeDSInitializeRequestAmountTotal,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct DeutschebankThreeDSInitializeRequestMeansOfPayment<
    T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize,
> {
    credit_card: DeutschebankThreeDSInitializeRequestCreditCard<T>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct DeutschebankThreeDSInitializeRequestCreditCard<
    T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize,
> {
    number: RawCardNumber<T>,
    expiry_date: DeutschebankThreeDSInitializeRequestCreditCardExpiry,
    code: Secret<String>,
    cardholder: Secret<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct DeutschebankThreeDSInitializeRequestCreditCardExpiry {
    year: Secret<String>,
    month: Secret<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct DeutschebankThreeDSInitializeRequestAmountTotal {
    amount: MinorUnit,
    currency: enums::Currency,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct DeutschebankThreeDSInitializeRequestTds20Data {
    communication_data: DeutschebankThreeDSInitializeRequestCommunicationData,
    customer_data: DeutschebankThreeDSInitializeRequestCustomerData,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct DeutschebankThreeDSInitializeRequestCommunicationData {
    method_notification_url: String,
    cres_notification_url: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct DeutschebankThreeDSInitializeRequestCustomerData {
    billing_address: DeutschebankThreeDSInitializeRequestCustomerBillingData,
    cardholder_email: Email,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct DeutschebankThreeDSInitializeRequestCustomerBillingData {
    street: Secret<String>,
    postal_code: Secret<String>,
    city: String,
    state: Secret<String>,
    country: String,
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        DeutschebankRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for DeutschebankPaymentsRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: DeutschebankRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        match item
            .router_data
            .request
            .mandate_id
            .clone()
            .and_then(|mandate_id| mandate_id.mandate_reference_id)
        {
            None => {
                // To facilitate one-off payments via SEPA with Deutsche Bank, we are considering not storing the connector mandate ID in our system if future usage is on-session.
                // We will only check for customer acceptance to make a one-off payment. we will be storing the connector mandate details only when setup future usage is off-session.
                match item.router_data.request.payment_method_data.clone() {
                    PaymentMethodData::BankDebit(BankDebitData::SepaBankDebit { iban, .. }) => {
                        if item.router_data.request.customer_acceptance.is_some() {
                            let billing_address = item
                                .router_data
                                .resource_common_data
                                .get_billing_address()?;
                            Ok(Self::MandatePost(DeutschebankMandatePostRequest {
                                approval_by: DeutschebankSEPAApproval::Click,
                                email_address: item.router_data.request.get_email()?,
                                iban: Secret::from(iban.peek().replace(" ", "")),
                                first_name: billing_address.get_first_name()?.clone(),
                                last_name: billing_address.get_last_name()?.clone(),
                            }))
                        } else {
                            Err(ConnectorError::MissingRequiredField {
                                field_name: "customer_acceptance",
                            }
                            .into())
                        }
                    }
                    PaymentMethodData::Card(ccard) => {
                        if !item.router_data.clone().resource_common_data.is_three_ds() {
                            Err(ConnectorError::NotSupported {
                                message: "Non-ThreeDs".to_owned(),
                                connector: "deutschebank",
                            }
                            .into())
                        } else {
                            let billing_address = item
                                .router_data
                                .resource_common_data
                                .get_billing_address()?;
                            Ok(Self::CreditCard(Box::new(DeutschebankThreeDSInitializeRequest {
                                    means_of_payment: DeutschebankThreeDSInitializeRequestMeansOfPayment {
                                        credit_card: DeutschebankThreeDSInitializeRequestCreditCard {
                                            number: ccard.clone().card_number,
                                            expiry_date: DeutschebankThreeDSInitializeRequestCreditCardExpiry {
                                                year: ccard.get_expiry_year_4_digit(),
                                                month: ccard.card_exp_month,
                                            },
                                            code: ccard.card_cvc,
                                            cardholder: item.router_data.resource_common_data.get_billing_full_name()?,
                                        }},
                                    amount_total: DeutschebankThreeDSInitializeRequestAmountTotal {
                                        amount: item.router_data.request.amount,
                                        currency: item.router_data.request.currency,
                                    },
                                    tds_20_data: DeutschebankThreeDSInitializeRequestTds20Data {
                                        communication_data: DeutschebankThreeDSInitializeRequestCommunicationData {
                                            method_notification_url: item.router_data.request.get_complete_authorize_url()?,
                                            cres_notification_url: item.router_data.request.get_complete_authorize_url()?,
                                        },
                                        customer_data: DeutschebankThreeDSInitializeRequestCustomerData {
                                            billing_address: DeutschebankThreeDSInitializeRequestCustomerBillingData {
                                                street: billing_address.get_line1()?.clone(),
                                                postal_code: billing_address.get_zip()?.clone(),
                                                city: billing_address.get_city()?.clone().expose().to_string(),
                                                state: billing_address.get_state()?.clone(),
                                                country: item.router_data.resource_common_data.get_billing_country()?.to_string(),
                                            },
                                            cardholder_email: item.router_data.request.get_email()?,
                                        }
                                    }
                                })))
                        }
                    }
                    _ => Err(ConnectorError::NotImplemented(
                        utils::get_unimplemented_payment_method_error_message("deutschebank"),
                    )
                    .into()),
                }
            }
            Some(MandateReferenceId::ConnectorMandateId(mandate_data)) => {
                let mandate_metadata: DeutschebankMandateMetadata = mandate_data
                    .get_mandate_metadata()
                    .ok_or(ConnectorError::MissingConnectorMandateMetadata)?
                    .clone()
                    .parse_value("DeutschebankMandateMetadata")
                    .change_context(ConnectorError::ParsingFailed)?;
                Ok(Self::DirectDebit(DeutschebankDirectDebitRequest {
                    amount_total: DeutschebankAmount {
                        amount: item.router_data.request.amount,
                        currency: item.router_data.request.currency,
                    },
                    means_of_payment: DeutschebankMeansOfPayment {
                        bank_account: DeutschebankBankAccount {
                            account_holder: mandate_metadata.account_holder,
                            iban: mandate_metadata.iban,
                        },
                    },
                    mandate: DeutschebankMandate {
                        reference: mandate_metadata.reference,
                        signed_on: mandate_metadata.signed_on,
                    },
                }))
            }
            Some(MandateReferenceId::NetworkTokenWithNTI(_))
            | Some(MandateReferenceId::NetworkMandateId(_)) => Err(ConnectorError::NotImplemented(
                utils::get_unimplemented_payment_method_error_message("deutschebank"),
            )
            .into()),
        }
    }
}

#[derive(Debug, Serialize, Default)]
pub struct DeutschebankPsyncRequest;

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        DeutschebankRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    > for DeutschebankPsyncRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        _item: DeutschebankRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeutschebankThreeDSInitializeResponse {
    outcome: DeutschebankThreeDSInitializeResponseOutcome,
    challenge_required: Option<DeutschebankThreeDSInitializeResponseChallengeRequired>,
    processed: Option<DeutschebankThreeDSInitializeResponseProcessed>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeutschebankThreeDSInitializeResponseProcessed {
    rc: String,
    message: String,
    tx_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DeutschebankThreeDSInitializeResponseOutcome {
    Processed,
    ChallengeRequired,
    MethodRequired,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeutschebankThreeDSInitializeResponseChallengeRequired {
    acs_url: String,
    creq: String,
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<ResponseRouterData<DeutschebankThreeDSInitializeResponse, Self>>
    for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<DeutschebankThreeDSInitializeResponse, Self>,
    ) -> Result<Self, Self::Error> {
        match item.response.outcome {
            DeutschebankThreeDSInitializeResponseOutcome::Processed => {
                match item.response.processed {
                    Some(processed) => Ok(Self {
                        resource_common_data: PaymentFlowData {
                        status: if is_response_success(&processed.rc) {
                            match item.router_data.request.is_auto_capture()? {
                                true => common_enums::AttemptStatus::Charged,
                                false => common_enums::AttemptStatus::Authorized,
                            }
                        } else {
                            common_enums::AttemptStatus::AuthenticationFailed
                        }, ..item.router_data.resource_common_data},
                        response: Ok(PaymentsResponseData::TransactionResponse {
                            status_code: item.http_code,
                            resource_id: ResponseId::ConnectorTransactionId(
                                processed.tx_id.clone(),
                            ),
                            redirection_data: None,
                            mandate_reference: None,
                            connector_metadata: None,
                            network_txn_id: None,
                            connector_response_reference_id: Some(processed.tx_id.clone()),
                            incremental_authorization_allowed: None,
                        }),
                        ..item.router_data
                    }),
                    None => {
                        let response_string = format!("{:?}", item.response);
                        Err(
                            ConnectorError::UnexpectedResponseError(bytes::Bytes::from(
                                response_string,
                            ))
                            .into(),
                        )
                    }
                }
            }
            DeutschebankThreeDSInitializeResponseOutcome::ChallengeRequired => {
                match item.response.challenge_required {
                    Some(challenge) => Ok(Self {
                        resource_common_data: PaymentFlowData {
                        status: common_enums::AttemptStatus::AuthenticationPending,
                        ..item.router_data.resource_common_data
                        },
                        response: Ok(PaymentsResponseData::TransactionResponse {
                            status_code: item.http_code,
                            resource_id: ResponseId::NoResponseId,
                            redirection_data: Some(Box::new(
                                RedirectForm::DeutschebankThreeDSChallengeFlow {
                                    acs_url: challenge.acs_url,
                                    creq: challenge.creq,
                                },
                            )),
                            mandate_reference: None,
                            connector_metadata: None,
                            network_txn_id: None,
                            connector_response_reference_id: None,
                            incremental_authorization_allowed: None,
                        }),
                        ..item.router_data
                    }),
                    None => {
                        let response_string = format!("{:?}", item.response);
                        Err(
                            ConnectorError::UnexpectedResponseError(bytes::Bytes::from(
                                response_string,
                            ))
                            .into(),
                        )
                    }
                }
            }
            DeutschebankThreeDSInitializeResponseOutcome::MethodRequired => Ok(Self {
                resource_common_data: PaymentFlowData {
                        status: common_enums::AttemptStatus::Failure,
                        ..item.router_data.resource_common_data
                        },
                response: Err(ErrorResponse {
                    code: consts::NO_ERROR_CODE.to_owned(),
                    message: "METHOD_REQUIRED Flow not supported for deutschebank 3ds payments".to_owned(),
                    reason: Some("METHOD_REQUIRED Flow is not currently supported for deutschebank 3ds payments".to_owned()),
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DeutschebankSEPAMandateStatus {
    Created,
    PendingApproval,
    PendingSecondaryApproval,
    PendingReview,
    PendingSubmission,
    Submitted,
    Active,
    Failed,
    Discarded,
    Expired,
    Replaced,
}

impl From<DeutschebankSEPAMandateStatus> for common_enums::AttemptStatus {
    fn from(item: DeutschebankSEPAMandateStatus) -> Self {
        match item {
            DeutschebankSEPAMandateStatus::Active
            | DeutschebankSEPAMandateStatus::Created
            | DeutschebankSEPAMandateStatus::PendingApproval
            | DeutschebankSEPAMandateStatus::PendingSecondaryApproval
            | DeutschebankSEPAMandateStatus::PendingReview
            | DeutschebankSEPAMandateStatus::PendingSubmission
            | DeutschebankSEPAMandateStatus::Submitted => Self::AuthenticationPending,
            DeutschebankSEPAMandateStatus::Failed
            | DeutschebankSEPAMandateStatus::Discarded
            | DeutschebankSEPAMandateStatus::Expired
            | DeutschebankSEPAMandateStatus::Replaced => Self::Failure,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeutschebankMandateMetadata {
    account_holder: Secret<String>,
    iban: Secret<String>,
    reference: Secret<String>,
    signed_on: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeutschebankMandatePostResponse {
    rc: String,
    message: String,
    mandate_id: Option<String>,
    reference: Option<String>,
    approval_date: Option<String>,
    language: Option<String>,
    approval_by: Option<DeutschebankSEPAApproval>,
    state: Option<DeutschebankSEPAMandateStatus>,
}

fn get_error_response(error_code: String, error_reason: String, status_code: u16) -> ErrorResponse {
    ErrorResponse {
        code: error_code.to_string(),
        message: error_reason.clone(),
        reason: Some(error_reason),
        status_code,
        attempt_status: None,
        connector_transaction_id: None,
        network_advice_code: None,
        network_decline_code: None,
        network_error_message: None,
    }
}

fn is_response_success(rc: &String) -> bool {
    rc == "0"
}

impl TryFrom<ResponseRouterData<DeutschebankPaymentsResponse, Self>>
    for RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<DeutschebankPaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let response_code = item.response.rc.clone();
        if is_response_success(&response_code) {
            Ok(Self {
                resource_common_data: PaymentFlowData {
                    status: common_enums::AttemptStatus::Charged,
                    ..item.router_data.resource_common_data
                },
                response: Ok(PaymentsResponseData::TransactionResponse {
                    status_code: item.http_code,
                    resource_id: ResponseId::ConnectorTransactionId(item.response.tx_id),
                    redirection_data: None,
                    mandate_reference: None,
                    connector_metadata: None,
                    network_txn_id: None,
                    connector_response_reference_id: None,
                    incremental_authorization_allowed: None,
                }),
                ..item.router_data
            })
        } else {
            Ok(Self {
                resource_common_data: PaymentFlowData {
                    status: common_enums::AttemptStatus::Failure,
                    ..item.router_data.resource_common_data
                },
                response: Err(get_error_response(
                    response_code.clone(),
                    item.response.message.clone(),
                    item.http_code,
                )),
                ..item.router_data
            })
        }
    }
}

impl TryFrom<ResponseRouterData<DeutschebankPaymentsResponse, Self>>
    for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<DeutschebankPaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let response_code = item.response.rc.clone();
        if is_response_success(&response_code) {
            Ok(Self {
                response: Ok(RefundsResponseData {
                    status_code: item.http_code,
                    connector_refund_id: item.response.tx_id,
                    refund_status: enums::RefundStatus::Success,
                }),
                ..item.router_data
            })
        } else {
            Ok(Self {
                resource_common_data: RefundFlowData {
                    status: common_enums::RefundStatus::Failure,
                    ..item.router_data.resource_common_data
                },
                response: Err(get_error_response(
                    response_code.clone(),
                    item.response.message.clone(),
                    item.http_code,
                )),
                ..item.router_data
            })
        }
    }
}

impl TryFrom<ResponseRouterData<DeutschebankPaymentsResponse, Self>>
    for RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<DeutschebankPaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let response_code = item.response.rc.clone();
        if is_response_success(&response_code) {
            Ok(Self {
                resource_common_data: PaymentFlowData {
                    status: common_enums::AttemptStatus::Voided,
                    ..item.router_data.resource_common_data
                },
                response: Ok(PaymentsResponseData::TransactionResponse {
                    resource_id: ResponseId::ConnectorTransactionId(item.response.tx_id),
                    redirection_data: None,
                    mandate_reference: None,
                    connector_metadata: None,
                    network_txn_id: None,
                    connector_response_reference_id: None,
                    incremental_authorization_allowed: None,
                    status_code: item.http_code,
                }),
                ..item.router_data
            })
        } else {
            Ok(Self {
                resource_common_data: PaymentFlowData {
                    status: common_enums::AttemptStatus::VoidFailed,
                    ..item.router_data.resource_common_data
                },
                response: Err(get_error_response(
                    response_code.clone(),
                    item.response.message.clone(),
                    item.http_code,
                )),
                ..item.router_data
            })
        }
    }
}

impl TryFrom<ResponseRouterData<DeutschebankPaymentsResponse, Self>>
    for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<DeutschebankPaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let response_code = item.response.rc.clone();
        let status = if is_response_success(&response_code) {
            item.response
                .tx_action
                .and_then(|tx_action| match tx_action {
                    DeutschebankTXAction::Preauthorization => {
                        Some(common_enums::AttemptStatus::Authorized)
                    }
                    DeutschebankTXAction::Authorization | DeutschebankTXAction::Capture => {
                        Some(common_enums::AttemptStatus::Charged)
                    }
                    DeutschebankTXAction::Credit
                    | DeutschebankTXAction::Refund
                    | DeutschebankTXAction::Reversal
                    | DeutschebankTXAction::RiskCheck
                    | DeutschebankTXAction::VerifyMop
                    | DeutschebankTXAction::Payment
                    | DeutschebankTXAction::AccountInformation => None,
                })
        } else {
            Some(common_enums::AttemptStatus::Failure)
        };
        match status {
            Some(common_enums::AttemptStatus::Failure) => Ok(Self {
                resource_common_data: PaymentFlowData {
                    status: common_enums::AttemptStatus::Failure,
                    ..item.router_data.resource_common_data
                },
                response: Err(get_error_response(
                    response_code.clone(),
                    item.response.message.clone(),
                    item.http_code,
                )),
                ..item.router_data
            }),
            Some(status) => Ok(Self {
                resource_common_data: PaymentFlowData {
                    status,
                    ..item.router_data.resource_common_data
                },
                response: Ok(PaymentsResponseData::TransactionResponse {
                    resource_id: ResponseId::ConnectorTransactionId(item.response.event_id.unwrap().clone()),
                    redirection_data: None,
                    mandate_reference: None,
                    connector_metadata: None,
                    network_txn_id: None,
                    connector_response_reference_id: None,
                    incremental_authorization_allowed: None,
                    status_code: item.http_code,
                }),
                ..item.router_data
            }),
            None => Ok(Self { ..item.router_data }),
        }
    }
}

impl TryFrom<ResponseRouterData<DeutschebankPaymentsResponse, Self>>
    for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<DeutschebankPaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let response_code = item.response.rc.clone();
        let status = if is_response_success(&response_code) {
            item.response
                .tx_action
                .and_then(|tx_action| match tx_action {
                    DeutschebankTXAction::Credit | DeutschebankTXAction::Refund => {
                        Some(enums::RefundStatus::Success)
                    }
                    DeutschebankTXAction::Preauthorization
                    | DeutschebankTXAction::Authorization
                    | DeutschebankTXAction::Capture
                    | DeutschebankTXAction::Reversal
                    | DeutschebankTXAction::RiskCheck
                    | DeutschebankTXAction::VerifyMop
                    | DeutschebankTXAction::Payment
                    | DeutschebankTXAction::AccountInformation => None,
                })
        } else {
            Some(enums::RefundStatus::Failure)
        };

        match status {
            Some(enums::RefundStatus::Failure) => Ok(Self {
                resource_common_data: RefundFlowData {
                    status: common_enums::RefundStatus::Failure,
                    ..item.router_data.resource_common_data
                },
                response: Err(get_error_response(
                    response_code.clone(),
                    item.response.message.clone(),
                    item.http_code,
                )),
                ..item.router_data
            }),
            Some(refund_status) => Ok(Self {
                response: Ok(RefundsResponseData {
                    status_code: item.http_code,
                    refund_status,
                    connector_refund_id: item.router_data.request.connector_refund_id.clone(),
                }),
                ..item.router_data
            }),
            None => Ok(Self { ..item.router_data }),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct DeutschebankAmount {
    amount: MinorUnit,
    currency: enums::Currency,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct DeutschebankMeansOfPayment {
    bank_account: DeutschebankBankAccount,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct DeutschebankBankAccount {
    account_holder: Secret<String>,
    iban: Secret<String>,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct DeutschebankMandate {
    reference: Secret<String>,
    signed_on: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct DeutschebankDirectDebitRequest {
    amount_total: DeutschebankAmount,
    means_of_payment: DeutschebankMeansOfPayment,
    mandate: DeutschebankMandate,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DeutschebankTXAction {
    Authorization,
    Capture,
    Credit,
    Preauthorization,
    Refund,
    Reversal,
    RiskCheck,
    #[serde(rename = "verify-mop")]
    VerifyMop,
    Payment,
    AccountInformation,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct BankAccount {
    account_holder: Option<Secret<String>>,
    bank_name: Option<Secret<String>>,
    bic: Option<Secret<String>>,
    iban: Option<Secret<String>>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct TransactionBankAccountInfo {
    bank_account: Option<BankAccount>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct DeutschebankTransactionInfo {
    back_state: Option<String>,
    ip_address: Option<Secret<String>>,
    #[serde(rename = "type")]
    pm_type: Option<String>,
    transaction_bankaccount_info: Option<TransactionBankAccountInfo>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct DeutschebankPaymentsResponse {
    rc: String,
    message: String,
    timestamp: String,
    back_ext_id: Option<String>,
    back_rc: Option<String>,
    event_id: Option<String>,
    kind: Option<String>,
    tx_action: Option<DeutschebankTXAction>,
    tx_id: String,
    amount_total: Option<DeutschebankAmount>,
    transaction_info: Option<DeutschebankTransactionInfo>,
}

#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum DeutschebankTransactionKind {
    Directdebit,
    #[serde(rename = "CREDITCARD_3DS20")]
    Creditcard3ds20,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct DeutschebankCaptureRequest {
    changed_amount: MinorUnit,
    kind: DeutschebankTransactionKind,
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        DeutschebankRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    > for DeutschebankCaptureRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: DeutschebankRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        if matches!(
            item.router_data.resource_common_data.payment_method,
            PaymentMethod::BankDebit
        ) {
            Ok(Self {
                changed_amount: item.router_data.request.minor_amount_to_capture,
                kind: DeutschebankTransactionKind::Directdebit,
            })
        } else if matches!(
            item.router_data.resource_common_data.payment_method,
            PaymentMethod::Card
        ) {
            Ok(Self {
                changed_amount: item.router_data.request.minor_amount_to_capture,
                kind: DeutschebankTransactionKind::Creditcard3ds20,
            })
        } else {
            Err(ConnectorError::NotImplemented(
                utils::get_unimplemented_payment_method_error_message("deutschebank"),
            )
            .into())
        }
    }
}

#[derive(Debug, Serialize)]
pub struct DeutschebankRefundRequest {
    changed_amount: MinorUnit,
    kind: DeutschebankTransactionKind,
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        DeutschebankRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    > for DeutschebankRefundRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: DeutschebankRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        if matches!(
            item.router_data.resource_common_data.payment_method,
            Some(PaymentMethod::BankDebit)
        ) {
            Ok(Self {
                changed_amount: item
                    .connector
                    .amount_converter
                    .convert(
                        item.router_data.request.minor_refund_amount,
                        item.router_data.request.currency,
                    )
                    .change_context(ConnectorError::AmountConversionFailed)?,
                kind: DeutschebankTransactionKind::Directdebit,
            })
        } else if matches!(
            item.router_data.resource_common_data.payment_method,
            Some(PaymentMethod::Card)
        ) {
            Ok(Self {
                changed_amount: item
                    .connector
                    .amount_converter
                    .convert(
                        item.router_data.request.minor_refund_amount,
                        item.router_data.request.currency,
                    )
                    .change_context(ConnectorError::AmountConversionFailed)?,
                kind: DeutschebankTransactionKind::Creditcard3ds20,
            })
        } else {
            Err(ConnectorError::NotImplemented(
                utils::get_unimplemented_payment_method_error_message("deutschebank"),
            )
            .into())
        }
    }
}

#[derive(Debug, Serialize)]
pub struct DeutschebankCancelRequest {
    kind: DeutschebankTransactionKind,
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        DeutschebankRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    > for DeutschebankCancelRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: DeutschebankRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        if matches!(
            item.router_data.resource_common_data.payment_method,
            PaymentMethod::BankDebit
        ) {
            Ok(Self {
                kind: DeutschebankTransactionKind::Directdebit,
            })
        } else if matches!(
            item.router_data.resource_common_data.payment_method,
            PaymentMethod::Card
        ) {
            Ok(Self {
                kind: DeutschebankTransactionKind::Creditcard3ds20,
            })
        } else {
            Err(ConnectorError::NotImplemented(
                utils::get_unimplemented_payment_method_error_message("deutschebank"),
            )
            .into())
        }
    }
}

#[derive(Default, Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct PaymentsErrorResponse {
    pub rc: String,
    pub message: String,
}

#[derive(Default, Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct AccessTokenErrorResponse {
    pub cause: String,
    pub description: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum DeutschebankError {
    PaymentsErrorResponse(PaymentsErrorResponse),
    AccessTokenErrorResponse(AccessTokenErrorResponse),
}
