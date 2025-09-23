use std::collections::HashMap;

use cards::CardNumber;
use common_utils::{
    ext_traits::OptionExt,
    pii,
    request::Method,
    types::{MinorUnit, StringMinorUnit},
};
use domain_types::{
    connector_flow::{self, Authorize, PSync, RSync, RepeatPayment, SetupMandate, Void, Capture},
    connector_types::{
        MandateReference, MandateReferenceId, PaymentFlowData, PaymentVoidData,
        PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData, PaymentsSyncData,
        RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData, RepeatPaymentData,
        ResponseId, SetupMandateRequestData,
    },
    errors::{self, ConnectorError},
    payment_method_data::{
        PaymentMethodData, PaymentMethodDataTypes, RawCardNumber,
        WalletData as WalletDataPaymentMethod,
    },
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
    utils,
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, Secret, PeekInterface};
use serde::{Deserialize, Serialize};
use strum::Display;

use crate::types::ResponseRouterData;

const TRANSACTION_ALREADY_CANCELLED: &str = "transaction already canceled";
const TRANSACTION_ALREADY_SETTLED: &str = "already settled";
const REDIRECTION_SBX_URL: &str = "https://pay.sandbox.datatrans.com";
const REDIRECTION_PROD_URL: &str = "https://pay.datatrans.com";

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct DatatransErrorResponse {
    pub error: DatatransError,
}

pub struct DatatransAuthType {
    pub(super) merchant_id: Secret<String>,
    pub(super) passcode: Secret<String>,
}

#[derive(Debug, Serialize)]
pub struct DatatransRouterData<T, U> {
    pub amount: MinorUnit,
    pub router_data: T,
    pub payment_method_data: std::marker::PhantomData<U>,
}

impl<T, U> TryFrom<(MinorUnit, T)> for DatatransRouterData<T, U> {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from((amount, item): (MinorUnit, T)) -> Result<Self, Self::Error> {
        Ok(Self {
            amount,
            router_data: item,
            payment_method_data: std::marker::PhantomData,
        })
    }
}

impl<T, U> TryFrom<(&common_enums::CurrencyUnit, common_enums::Currency, MinorUnit, T)> for DatatransRouterData<T, U> {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from((currency_unit, currency, amount, item): (&common_enums::CurrencyUnit, common_enums::Currency, MinorUnit, T)) -> Result<Self, Self::Error> {
        Ok(Self {
            amount,
            router_data: item,
            payment_method_data: std::marker::PhantomData,
        })
    }
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DatatransPaymentsRequest<
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize,
> {
    pub amount: Option<MinorUnit>,
    pub currency: common_enums::Currency,
    pub card: DataTransPaymentDetails<T>,
    pub refno: String,
    pub auto_settle: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect: Option<RedirectUrls>,
    pub option: Option<DataTransCreateAlias>,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DataTransCreateAlias {
    pub create_alias: bool,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RedirectUrls {
    pub success_url: Option<String>,
    pub cancel_url: Option<String>,
    pub error_url: Option<String>,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionType {
    Payment,
    Credit,
    CardCheck,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionStatus {
    Initialized,
    Authenticated,
    Authorized,
    Settled,
    Canceled,
    Transmitted,
    Failed,
    ChallengeOngoing,
    ChallengeRequired,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
#[serde(untagged)]
pub enum DatatransSyncResponse {
    Error(DatatransError),
    Response(SyncResponse),
}

#[derive(Debug, Deserialize, Serialize)]
pub enum DataTransCaptureResponse {
    Error(DatatransError),
    Empty,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum DataTransCancelResponse {
    Error(DatatransError),
    Empty,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SyncResponse {
    pub transaction_id: String,
    #[serde(rename = "type")]
    pub res_type: TransactionType,
    pub status: TransactionStatus,
    pub detail: SyncDetails,
    pub card: Option<SyncCardDetails>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SyncCardDetails {
    pub alias: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SyncDetails {
    fail: Option<FailDetails>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct FailDetails {
    reason: Option<String>,
    message: Option<String>,
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
#[serde(untagged)]
pub enum DataTransPaymentDetails<
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize,
> {
    Cards(PlainCardDetails<T>),
    Mandate(MandateDetails),
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct PlainCardDetails<
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize,
> {
    #[serde(rename = "type")]
    pub res_type: String,
    pub number: RawCardNumber<T>,
    pub expiry_month: Secret<String>,
    pub expiry_year: Secret<String>,
    pub cvv: Secret<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "3D")]
    pub three_ds: Option<ThreeDSecureData>,
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct MandateDetails {
    #[serde(rename = "type")]
    pub res_type: String,
    pub alias: String,
    pub expiry_month: Secret<String>,
    pub expiry_year: Secret<String>,
}

#[derive(Serialize, Clone, Debug)]
pub struct ThreedsInfo {
    cardholder: CardHolder,
}

#[derive(Serialize, Clone, Debug)]
#[serde(untagged)]
pub enum ThreeDSecureData {
    Cardholder(ThreedsInfo),
    Authentication(ThreeDSData),
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ThreeDSData {
    #[serde(rename = "threeDSTransactionId")]
    pub three_ds_transaction_id: Option<Secret<String>>,
    pub cavv: Secret<String>,
    pub eci: Option<String>,
    pub xid: Option<Secret<String>>,
    #[serde(rename = "threeDSVersion")]
    pub three_ds_version: Option<String>,
    #[serde(rename = "authenticationResponse")]
    pub authentication_response: String,
}

#[derive(Debug, Serialize, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CardHolder {
    cardholder_name: Secret<String>,
    email: pii::Email,
}

#[derive(Debug, Clone, Serialize, Default, Deserialize)]
pub struct DatatransError {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DatatransResponse {
    TransactionResponse(DatatransSuccessResponse),
    ErrorResponse(DatatransError),
    ThreeDSResponse(Datatrans3DSResponse),
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DatatransSuccessResponse {
    pub transaction_id: String,
    pub acquirer_authorization_code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DatatransRefundsResponse {
    Success(DatatransSuccessResponse),
    Error(DatatransError),
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Datatrans3DSResponse {
    pub transaction_id: String,
    #[serde(rename = "3D")]
    pub three_ds_enrolled: ThreeDSEnolled,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThreeDSEnolled {
    pub enrolled: bool,
}

#[derive(Default, Debug, Serialize)]
pub struct DatatransRefundRequest {
    pub amount: MinorUnit,
    pub currency: common_enums::Currency,
    pub refno: String,
}

#[derive(Default, Debug, Serialize)]
pub struct DatatransSyncRequest {
    // Empty request body for sync operations
}

#[derive(Default, Debug, Serialize)]
pub struct DatatransVoidRequest {
    // Empty request body for void operations
}

#[derive(Default, Debug, Serialize)]
pub struct DatatransRSyncRequest {
    // Empty request body for refund sync operations
}

#[derive(Debug, Deserialize, Clone, Serialize)]
#[serde(untagged)]
pub enum DatatransRSyncResponse {
    Error(DatatransError),
    Response(SyncResponse),
}

#[derive(Debug, Serialize, Clone)]
pub struct DataPaymentCaptureRequest {
    pub amount: MinorUnit,
    pub currency: common_enums::Currency,
    pub refno: String,
}

// Type aliases for unique flow types
pub type DatatransSetupMandateRequest<T> = DatatransPaymentsRequest<T>;
pub type DatatransSetupMandateResponse = DatatransResponse;

impl TryFrom<&ConnectorAuthType> for DatatransAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self {
                merchant_id: key1.clone(),
                passcode: api_key.clone(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

fn get_status(item: &DatatransResponse, is_auto_capture: bool) -> common_enums::AttemptStatus {
    match item {
        DatatransResponse::ErrorResponse(_) => common_enums::AttemptStatus::Failure,
        DatatransResponse::TransactionResponse(_) => {
            if is_auto_capture {
                common_enums::AttemptStatus::Charged
            } else {
                common_enums::AttemptStatus::Authorized
            }
        }
        DatatransResponse::ThreeDSResponse(_) => common_enums::AttemptStatus::AuthenticationPending,
    }
}

fn create_card_details<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>(
    item: &DatatransRouterData<
        RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        T,
    >,
    card: &domain_types::payment_method_data::Card<T>,
) -> Result<DataTransPaymentDetails<T>, error_stack::Report<errors::ConnectorError>> {
    let mut details = PlainCardDetails {
        res_type: "PLAIN".to_string(),
        number: card.card_number.clone(),
        expiry_month: card.card_exp_month.clone(),
        expiry_year: card.get_card_expiry_year_2_digit()?,
        cvv: card.card_cvc.clone(),
        three_ds: None,
    };

    if let Some(auth_data) = &item.router_data.request.authentication_data {
        details.three_ds = Some(ThreeDSecureData::Authentication(ThreeDSData {
            three_ds_transaction_id: auth_data
                .threeds_server_transaction_id
                .clone()
                .map(Secret::new),
            cavv: auth_data.cavv.clone(),
            eci: auth_data.eci.clone(),
            xid: auth_data.ds_trans_id.clone().map(Secret::new),
            three_ds_version: auth_data
                .message_version
                .clone()
                .map(|version| version.to_string()),
            authentication_response: "Y".to_string(),
        }));
    } else if item.router_data.resource_common_data.is_three_ds() {
        details.three_ds = Some(ThreeDSecureData::Cardholder(ThreedsInfo {
            cardholder: CardHolder {
                cardholder_name: item.router_data.resource_common_data.get_billing_full_name()?,
                email: item.router_data.resource_common_data.get_billing_email()?,
            },
        }));
    }
    Ok(DataTransPaymentDetails::Cards(details))
}

fn create_mandate_details<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>(
    item: &DatatransRouterData<
        RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        T,
    >,
) -> Result<DataTransPaymentDetails<T>, error_stack::Report<errors::ConnectorError>> {
    let alias = item.router_data.request.get_connector_mandate_id()?;
    Ok(DataTransPaymentDetails::Mandate(MandateDetails {
        res_type: "ALIAS".to_string(),
        alias,
        expiry_month: Secret::new("12".to_string()), // Default values for mandate payments
        expiry_year: Secret::new("25".to_string()),
    }))
}

impl From<SyncResponse> for common_enums::AttemptStatus {
    fn from(item: SyncResponse) -> Self {
        match item.res_type {
            TransactionType::Payment => match item.status {
                TransactionStatus::Authorized => Self::Authorized,
                TransactionStatus::Settled | TransactionStatus::Transmitted => Self::Charged,
                TransactionStatus::ChallengeOngoing | TransactionStatus::ChallengeRequired => {
                    Self::AuthenticationPending
                }
                TransactionStatus::Canceled => Self::Voided,
                TransactionStatus::Failed => Self::Failure,
                TransactionStatus::Initialized | TransactionStatus::Authenticated => Self::Pending,
            },
            TransactionType::CardCheck => match item.status {
                TransactionStatus::Settled
                | TransactionStatus::Transmitted
                | TransactionStatus::Authorized => Self::Charged,
                TransactionStatus::ChallengeOngoing | TransactionStatus::ChallengeRequired => {
                    Self::AuthenticationPending
                }
                TransactionStatus::Canceled => Self::Voided,
                TransactionStatus::Failed => Self::Failure,
                TransactionStatus::Initialized | TransactionStatus::Authenticated => Self::Pending,
            },
            TransactionType::Credit => Self::Failure,
        }
    }
}

impl From<SyncResponse> for common_enums::RefundStatus {
    fn from(item: SyncResponse) -> Self {
        match item.res_type {
            TransactionType::Credit => match item.status {
                TransactionStatus::Settled | TransactionStatus::Transmitted => Self::Success,
                TransactionStatus::ChallengeOngoing | TransactionStatus::ChallengeRequired => {
                    Self::Pending
                }
                TransactionStatus::Initialized
                | TransactionStatus::Authenticated
                | TransactionStatus::Authorized
                | TransactionStatus::Canceled
                | TransactionStatus::Failed => Self::Failure,
            },
            TransactionType::Payment | TransactionType::CardCheck => Self::Failure,
        }
    }
}

// SetupMandate TryFrom implementation
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<&RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>>
    for DatatransPaymentsRequest<T>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: &RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        match item.request.payment_method_data.clone() {
            PaymentMethodData::Card(req_card) => Ok(Self {
                amount: None,
                currency: item.request.currency,
                card: DataTransPaymentDetails::Cards(PlainCardDetails {
                    res_type: "PLAIN".to_string(),
                    number: req_card.card_number.clone(),
                    expiry_month: req_card.card_exp_month.clone(),
                    expiry_year: req_card.get_card_expiry_year_2_digit()?,
                    cvv: req_card.card_cvc.clone(),
                    three_ds: Some(ThreeDSecureData::Cardholder(ThreedsInfo {
                        cardholder: CardHolder {
                            cardholder_name: item.resource_common_data.get_billing_full_name()?,
                            email: item.resource_common_data.get_billing_email()?,
                        },
                    })),
                }),
                refno: item.resource_common_data.connector_request_reference_id.clone(),
                auto_settle: true, // zero auth doesn't support manual capture
                option: Some(DataTransCreateAlias { create_alias: true }),
                redirect: Some(RedirectUrls {
                    success_url: item.request.router_return_url.clone(),
                    cancel_url: item.request.router_return_url.clone(),
                    error_url: item.request.router_return_url.clone(),
                }),
            }),
            _ => Err(errors::ConnectorError::NotImplemented(
                utils::get_unimplemented_payment_method_error_message("Datatrans"),
            ))?,
        }
    }
}

// Authorize TryFrom implementation
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<
        DatatransRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            T,
        >,
    > for DatatransPaymentsRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: DatatransRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        match item.router_data.request.payment_method_data.clone() {
            PaymentMethodData::Card(req_card) => {
                let is_mandate_payment = item.router_data.request.is_mandate_payment();
                let option =
                    is_mandate_payment.then_some(DataTransCreateAlias { create_alias: true });
                // provides return url for only mandate payment(CIT) or 3ds through datatrans
                let redirect = if is_mandate_payment
                    || (item.router_data.resource_common_data.is_three_ds()
                        && item.router_data.request.authentication_data.is_none())
                {
                    Some(RedirectUrls {
                        success_url: item.router_data.request.router_return_url.clone(),
                        cancel_url: item.router_data.request.router_return_url.clone(),
                        error_url: item.router_data.request.router_return_url.clone(),
                    })
                } else {
                    None
                };
                Ok(Self {
                    amount: Some(item.amount),
                    currency: item.router_data.request.currency,
                    card: create_card_details(&item, &req_card)?,
                    refno: item.router_data.resource_common_data.connector_request_reference_id.clone(),
                    auto_settle: item.router_data.request.is_auto_capture()?,
                    option,
                    redirect,
                })
            }
            PaymentMethodData::MandatePayment => {
                Ok(Self {
                    amount: Some(item.amount),
                    currency: item.router_data.request.currency,
                    card: create_mandate_details(&item)?,
                    refno: item.router_data.resource_common_data.connector_request_reference_id.clone(),
                    auto_settle: item.router_data.request.is_auto_capture()?,
                    option: None,
                    redirect: None,
                })
            }
            _ => Err(errors::ConnectorError::NotImplemented(
                utils::get_unimplemented_payment_method_error_message("Datatrans"),
            ))?,
        }
    }
}

// Authorize Response TryFrom implementation
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<
        ResponseRouterData<
            DatatransResponse,
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        >,
    > for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<
            DatatransResponse,
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let status = get_status(&item.response, item.router_data.request.is_auto_capture()?);
        let response = match &item.response {
            DatatransResponse::ErrorResponse(error) => Err(ErrorResponse {
                code: error.code.clone(),
                message: error.message.clone(),
                reason: Some(error.message.clone()),
                attempt_status: None,
                connector_transaction_id: None,
                status_code: item.http_code,
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
            }),
            DatatransResponse::TransactionResponse(response) => {
                Ok(PaymentsResponseData::TransactionResponse {
                    resource_id: ResponseId::ConnectorTransactionId(
                        response.transaction_id.clone(),
                    ),
                    redirection_data: None,
                    mandate_reference: None,
                    connector_metadata: None,
                    network_txn_id: None,
                    connector_response_reference_id: None,
                    incremental_authorization_allowed: None,
                    status_code: item.http_code,
                })
            }
            DatatransResponse::ThreeDSResponse(response) => {
                let redirection_link = match item.router_data.resource_common_data.test_mode {
                    Some(true) => format!("{REDIRECTION_SBX_URL}/v1/start"),
                    Some(false) | None => format!("{REDIRECTION_PROD_URL}/v1/start"),
                };
                Ok(PaymentsResponseData::TransactionResponse {
                    resource_id: ResponseId::ConnectorTransactionId(
                        response.transaction_id.clone(),
                    ),
                    redirection_data: Some(Box::new(RedirectForm::Form {
                        endpoint: format!("{}/{}", redirection_link, response.transaction_id),
                        method: Method::Get,
                        form_fields: HashMap::new(),
                    })),
                    mandate_reference: None,
                    connector_metadata: None,
                    network_txn_id: None,
                    connector_response_reference_id: None,
                    incremental_authorization_allowed: None,
                    status_code: item.http_code,
                })
            }
        };
        Ok(Self {
            response,
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

// SetupMandate Response TryFrom implementation
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<
        ResponseRouterData<
            DatatransResponse,
            RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>,
        >,
    > for RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<
            DatatransResponse,
            RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        // zero auth doesn't support manual capture
        let status = get_status(&item.response, true);
        let response = match &item.response {
            DatatransResponse::ErrorResponse(error) => Err(ErrorResponse {
                code: error.code.clone(),
                message: error.message.clone(),
                reason: Some(error.message.clone()),
                attempt_status: None,
                connector_transaction_id: None,
                status_code: item.http_code,
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
            }),
            DatatransResponse::TransactionResponse(response) => {
                Ok(PaymentsResponseData::TransactionResponse {
                    resource_id: ResponseId::ConnectorTransactionId(
                        response.transaction_id.clone(),
                    ),
                    redirection_data: None,
                    mandate_reference: None,
                    connector_metadata: None,
                    network_txn_id: None,
                    connector_response_reference_id: None,
                    incremental_authorization_allowed: None,
                    status_code: item.http_code,
                })
            }
            DatatransResponse::ThreeDSResponse(response) => {
                let redirection_link = match item.router_data.resource_common_data.test_mode {
                    Some(true) => format!("{REDIRECTION_SBX_URL}/v1/start"),
                    Some(false) | None => format!("{REDIRECTION_PROD_URL}/v1/start"),
                };
                Ok(PaymentsResponseData::TransactionResponse {
                    resource_id: ResponseId::ConnectorTransactionId(
                        response.transaction_id.clone(),
                    ),
                    redirection_data: Some(Box::new(RedirectForm::Form {
                        endpoint: format!("{}/{}", redirection_link, response.transaction_id),
                        method: Method::Get,
                        form_fields: HashMap::new(),
                    })),
                    mandate_reference: None,
                    connector_metadata: None,
                    network_txn_id: None,
                    connector_response_reference_id: None,
                    incremental_authorization_allowed: None,
                    status_code: item.http_code,
                })
            }
        };
        Ok(Self {
            response,
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

// Refund Request TryFrom implementation
impl<F, T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<
        DatatransRouterData<RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>, T>,
    > for DatatransRefundRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: DatatransRouterData<
            RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            amount: item.amount.to_owned(),
            currency: item.router_data.request.currency,
            refno: item.router_data.request.refund_id.clone(),
        })
    }
}

// Refund Response TryFrom implementation
impl<F> TryFrom<ResponseRouterData<DatatransRefundsResponse, Self>>
    for RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<DatatransRefundsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        match item.response {
            DatatransRefundsResponse::Error(error) => Ok(Self {
                response: Err(ErrorResponse {
                    code: error.code.clone(),
                    message: error.message.clone(),
                    reason: Some(error.message),
                    attempt_status: None,
                    connector_transaction_id: None,
                    status_code: item.http_code,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }),
                ..item.router_data
            }),
            DatatransRefundsResponse::Success(response) => Ok(Self {
                response: Ok(RefundsResponseData {
                    connector_refund_id: response.transaction_id,
                    refund_status: common_enums::RefundStatus::Success,
                    status_code: item.http_code,
                }),
                ..item.router_data
            }),
        }
    }
}

// RSync Response TryFrom implementation
impl<F> TryFrom<ResponseRouterData<DatatransRSyncResponse, Self>>
    for RouterDataV2<F, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<DatatransRSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let response = match item.response {
            DatatransRSyncResponse::Error(error) => Err(ErrorResponse {
                code: error.code.clone(),
                message: error.message.clone(),
                reason: Some(error.message),
                attempt_status: None,
                connector_transaction_id: None,
                status_code: item.http_code,
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
            }),
            DatatransRSyncResponse::Response(response) => Ok(RefundsResponseData {
                connector_refund_id: response.transaction_id.to_string(),
                refund_status: common_enums::RefundStatus::from(response),
                status_code: item.http_code,
            }),
        };
        Ok(Self {
            response,
            ..item.router_data
        })
    }
}

// PSync Response TryFrom implementation
impl<F> TryFrom<ResponseRouterData<DatatransSyncResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<DatatransSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        match item.response {
            DatatransSyncResponse::Error(error) => {
                let response = Err(ErrorResponse {
                    code: error.code.clone(),
                    message: error.message.clone(),
                    reason: Some(error.message),
                    attempt_status: None,
                    connector_transaction_id: None,
                    status_code: item.http_code,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                });
                Ok(Self {
                    response,
                    ..item.router_data
                })
            }
            DatatransSyncResponse::Response(sync_response) => {
                let status = common_enums::AttemptStatus::from(sync_response.clone());
                let response = if status == common_enums::AttemptStatus::Failure {
                    let (code, message) = match sync_response.detail.fail {
                        Some(fail_details) => (
                            fail_details.reason.unwrap_or(common_utils::consts::NO_ERROR_CODE.to_string()),
                            fail_details.message.unwrap_or(common_utils::consts::NO_ERROR_MESSAGE.to_string()),
                        ),
                        None => (common_utils::consts::NO_ERROR_CODE.to_string(), common_utils::consts::NO_ERROR_MESSAGE.to_string()),
                    };
                    Err(ErrorResponse {
                        code,
                        message: message.clone(),
                        reason: Some(message),
                        status_code: item.http_code,
                        attempt_status: None,
                        connector_transaction_id: None,
                        network_advice_code: None,
                        network_decline_code: None,
                        network_error_message: None,
                    })
                } else {
                    let mandate_reference = sync_response
                        .card
                        .as_ref()
                        .and_then(|card| card.alias.as_ref())
                        .map(|alias| MandateReference {
                            connector_mandate_id: Some(alias.clone()),
                            payment_method_id: None,
                        });
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(
                            sync_response.transaction_id.to_string(),
                        ),
                        redirection_data: None,
                        mandate_reference: mandate_reference.map(Box::new),
                        connector_metadata: None,
                        network_txn_id: None,
                        connector_response_reference_id: None,
                        incremental_authorization_allowed: None,
                        status_code: item.http_code,
                    })
                };
                Ok(Self {
                    response,
                    resource_common_data: PaymentFlowData {
                        status,
                        ..item.router_data.resource_common_data
                    },
                    ..item.router_data
                })
            }
        }
    }
}

// Capture Request TryFrom implementation
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<
        DatatransRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    > for DataPaymentCaptureRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: DatatransRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            amount: item.amount,
            currency: item.router_data.request.currency,
            refno: item.router_data.resource_common_data.connector_request_reference_id.clone(),
        })
    }
}

// Capture Response TryFrom implementation
impl<F> TryFrom<ResponseRouterData<DataTransCaptureResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<DataTransCaptureResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let status = match item.response {
            DataTransCaptureResponse::Error(error) => {
                if error.message == *TRANSACTION_ALREADY_SETTLED {
                    common_enums::AttemptStatus::Charged
                } else {
                    common_enums::AttemptStatus::Failure
                }
            }
            // Datatrans http code 204 implies Successful Capture
            //https://api-reference.datatrans.ch/#tag/v1transactions/operation/settle
            DataTransCaptureResponse::Empty => {
                if item.http_code == 204 {
                    common_enums::AttemptStatus::Charged
                } else {
                    common_enums::AttemptStatus::Failure
                }
            }
        };
        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

// Void Response TryFrom implementation
impl<F> TryFrom<ResponseRouterData<DataTransCancelResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<DataTransCancelResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let status = match item.response {
            // Datatrans http code 204 implies Successful Cancellation
            //https://api-reference.datatrans.ch/#tag/v1transactions/operation/cancel
            DataTransCancelResponse::Empty => {
                if item.http_code == 204 {
                    common_enums::AttemptStatus::Voided
                } else {
                    common_enums::AttemptStatus::Failure
                }
            }
            DataTransCancelResponse::Error(error) => {
                if error.message == *TRANSACTION_ALREADY_CANCELLED {
                    common_enums::AttemptStatus::Voided
                } else {
                    common_enums::AttemptStatus::Failure
                }
            }
        };
        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}