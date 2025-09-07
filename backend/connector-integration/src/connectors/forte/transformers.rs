use std::fmt::Debug;

use cards::CardNumber;
use common_enums::enums;
use common_utils::types::MinorUnit;
use domain_types::{
    connector_flow::{Authorize, Capture, PSync, Refund, RSync, Void},
    connector_types::*,
    errors::ConnectorError,
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes},
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
    router_request_types::ResponseId,
    router_response_types::{PaymentsResponseData, RefundsResponseData},
};
use error_stack::ResultExt;
use hyperswitch_masking::{PeekInterface, Secret};
use serde::{Deserialize, Serialize};

use crate::{
    types::{PaymentFlowData, RefundFlowData, ResponseRouterData},
    utils::{self, AddressDetailsData, CardData as _PaymentsAuthorizeRequestData},
};

// Auth type
#[derive(Debug, Clone)]
pub struct ForteAuthType {
    pub api_access_id: Secret<String>,
    pub organization_id: Secret<String>,
    pub location_id: Secret<String>,
    pub api_secret_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for ForteAuthType {
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::MultiAuthKey {
                api_key,
                key1,
                api_secret,
                key2,
            } => Ok(Self {
                api_access_id: api_key.to_owned(),
                organization_id: Secret::new(format!("org_{}", key1.peek())),
                location_id: Secret::new(format!("loc_{}", key2.peek())),
                api_secret_key: api_secret.to_owned(),
            }),
            _ => Err(ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

// Request structures
#[derive(Debug, Serialize)]
pub struct FortePaymentsRequest<T: PaymentMethodDataTypes + Serialize> {
    action: ForteAction,
    authorization_amount: MinorUnit,
    billing_address: BillingAddress,
    card: Card,
    #[serde(skip)]
    _phantom: std::marker::PhantomData<T>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BillingAddress {
    first_name: Secret<String>,
    last_name: Secret<String>,
}

#[derive(Debug, Serialize)]
pub struct Card {
    card_type: ForteCardType,
    name_on_card: Secret<String>,
    account_number: CardNumber,
    expire_month: Secret<String>,
    expire_year: Secret<String>,
    card_verification_value: Secret<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForteCardType {
    Visa,
    MasterCard,
    Amex,
    Discover,
    DinersClub,
    Jcb,
}

impl TryFrom<utils::CardIssuer> for ForteCardType {
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(issuer: utils::CardIssuer) -> Result<Self, Self::Error> {
        match issuer {
            utils::CardIssuer::AmericanExpress => Ok(Self::Amex),
            utils::CardIssuer::Master => Ok(Self::MasterCard),
            utils::CardIssuer::Discover => Ok(Self::Discover),
            utils::CardIssuer::Visa => Ok(Self::Visa),
            utils::CardIssuer::DinersClub => Ok(Self::DinersClub),
            utils::CardIssuer::JCB => Ok(Self::Jcb),
            _ => Err(ConnectorError::NotImplemented(
                utils::get_unimplemented_payment_method_error_message("Forte"),
            )
            .into()),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ForteAction {
    Sale,
    Authorize,
    Verify,
    Capture,
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<&RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>
    for FortePaymentsRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        if item.request.currency != enums::Currency::USD {
            return Err(ConnectorError::NotImplemented(
                utils::get_unimplemented_payment_method_error_message("Forte"),
            )
            .into());
        }
        
        match &item.request.payment_method_data {
            PaymentMethodData::Card(ref ccard) => {
                let action = match item.request.is_auto_capture()? {
                    true => ForteAction::Sale,
                    false => ForteAction::Authorize,
                };
                let card_type = ForteCardType::try_from(ccard.get_card_issuer()?)?;
                let address = item.get_billing_address()?;
                let card = Card {
                    card_type,
                    name_on_card: item
                        .get_optional_billing_full_name()
                        .unwrap_or(Secret::new("".to_string())),
                    account_number: ccard.card_number.clone(),
                    expire_month: ccard.card_exp_month.clone(),
                    expire_year: ccard.card_exp_year.clone(),
                    card_verification_value: ccard.card_cvc.clone(),
                };
                let first_name = address.get_first_name()?;
                let billing_address = BillingAddress {
                    first_name: first_name.clone(),
                    last_name: address.get_last_name().unwrap_or(first_name).clone(),
                };
                let authorization_amount = item.request.minor_amount;
                Ok(Self {
                    action,
                    authorization_amount,
                    billing_address,
                    card,
                    _phantom: std::marker::PhantomData,
                })
            }
            _ => Err(ConnectorError::NotImplemented(
                utils::get_unimplemented_payment_method_error_message("Forte"),
            )
            .into()),
        }
    }
}

// Response structures
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FortePaymentStatus {
    Complete,
    Failed,
    Authorized,
    Ready,
    Voided,
    Settled,
}

impl From<FortePaymentStatus> for enums::AttemptStatus {
    fn from(item: FortePaymentStatus) -> Self {
        match item {
            FortePaymentStatus::Complete | FortePaymentStatus::Settled => Self::Charged,
            FortePaymentStatus::Failed => Self::Failure,
            FortePaymentStatus::Ready => Self::Pending,
            FortePaymentStatus::Authorized => Self::Authorized,
            FortePaymentStatus::Voided => Self::Voided,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub enum ForteResponseCode {
    A01,
    A05,
    A06,
    U13,
    U14,
    U18,
    U20,
}

fn get_status(response_code: ForteResponseCode, action: ForteAction) -> enums::AttemptStatus {
    match response_code {
        ForteResponseCode::A01 => match action {
            ForteAction::Authorize => enums::AttemptStatus::Authorized,
            ForteAction::Sale => enums::AttemptStatus::Pending,
            ForteAction::Verify | ForteAction::Capture => enums::AttemptStatus::Charged,
        },
        ForteResponseCode::A05 | ForteResponseCode::A06 => enums::AttemptStatus::Authorizing,
        _ => enums::AttemptStatus::Failure,
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CardResponse {
    pub name_on_card: Option<Secret<String>>,
    pub last_4_account_number: String,
    pub masked_account_number: String,
    pub card_type: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ResponseStatus {
    pub environment: String,
    pub response_type: String,
    pub response_code: ForteResponseCode,
    pub response_desc: String,
    pub authorization_code: String,
    pub avs_result: Option<String>,
    pub cvv_result: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FortePaymentsResponse {
    pub transaction_id: String,
    pub location_id: Secret<String>,
    pub action: ForteAction,
    pub authorization_amount: Option<MinorUnit>,
    pub authorization_code: String,
    pub entered_by: String,
    pub billing_address: Option<BillingAddress>,
    pub card: Option<CardResponse>,
    pub response: ResponseStatus,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ForteMeta {
    pub auth_id: String,
}

impl<F, T> TryFrom<ResponseRouterData<FortePaymentsResponse, RouterDataV2<F, PaymentFlowData, T, PaymentsResponseData>>>
    for RouterDataV2<F, PaymentFlowData, T, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<FortePaymentsResponse, RouterDataV2<F, PaymentFlowData, T, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let response_code = item.response.response.response_code;
        let action = item.response.action;
        let transaction_id = &item.response.transaction_id;
        
        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(transaction_id.to_string()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: Some(serde_json::json!(ForteMeta {
                    auth_id: item.response.authorization_code,
                })),
                network_txn_id: None,
                connector_response_reference_id: Some(transaction_id.to_string()),
                incremental_authorization_allowed: None,
                charges: None,
            }),
            resource_common_data: PaymentFlowData {
                status: get_status(response_code, action),
                ..item.data.resource_common_data
            },
            ..item.data
        })
    }
}

// Error response structure
#[derive(Debug, Deserialize, Serialize)]
pub struct ErrorResponseStatus {
    pub environment: String,
    pub response_type: Option<String>,
    pub response_code: Option<String>,
    pub response_desc: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ForteErrorResponse {
    pub response: ErrorResponseStatus,
}

// Payment Sync Response
#[derive(Debug, Deserialize, Serialize)]
pub struct FortePaymentsSyncResponse {
    pub transaction_id: String,
    pub organization_id: Secret<String>,
    pub location_id: Secret<String>,
    pub original_transaction_id: Option<String>,
    pub status: FortePaymentStatus,
    pub action: ForteAction,
    pub authorization_code: String,
    pub authorization_amount: Option<MinorUnit>,
    pub billing_address: Option<BillingAddress>,
    pub entered_by: String,
    pub received_date: String,
    pub origination_date: Option<String>,
    pub card: Option<CardResponse>,
    pub attempt_number: i64,
    pub response: ResponseStatus,
}

impl<F, T> TryFrom<ResponseRouterData<FortePaymentsSyncResponse, RouterDataV2<F, PaymentFlowData, T, PaymentsResponseData>>>
    for RouterDataV2<F, PaymentFlowData, T, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<FortePaymentsSyncResponse, RouterDataV2<F, PaymentFlowData, T, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let transaction_id = &item.response.transaction_id;
        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(transaction_id.to_string()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: Some(serde_json::json!(ForteMeta {
                    auth_id: item.response.authorization_code,
                })),
                network_txn_id: None,
                connector_response_reference_id: Some(transaction_id.to_string()),
                incremental_authorization_allowed: None,
                charges: None,
            }),
            resource_common_data: PaymentFlowData {
                status: enums::AttemptStatus::from(item.response.status),
                ..item.data.resource_common_data
            },
            ..item.data
        })
    }
}

// Capture Request
#[derive(Debug, Serialize)]
pub struct ForteCaptureRequest {
    action: String,
    transaction_id: String,
    authorization_code: String,
}

impl TryFrom<&RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>> for ForteCaptureRequest {
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(item: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>) -> Result<Self, Self::Error> {
        let trn_id = item.request.connector_transaction_id.clone();
        let connector_auth_id: ForteMeta =
            utils::to_connector_meta(item.request.connector_meta.clone())?;
        let auth_code = connector_auth_id.auth_id;
        Ok(Self {
            action: "capture".to_string(),
            transaction_id: trn_id,
            authorization_code: auth_code,
        })
    }
}

// Capture Response
#[derive(Debug, Deserialize, Serialize)]
pub struct CaptureResponseStatus {
    pub environment: String,
    pub response_type: String,
    pub response_code: ForteResponseCode,
    pub response_desc: String,
    pub authorization_code: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ForteCaptureResponse {
    pub transaction_id: String,
    pub original_transaction_id: String,
    pub entered_by: String,
    pub authorization_code: String,
    pub response: CaptureResponseStatus,
}

impl<F, T> TryFrom<ResponseRouterData<ForteCaptureResponse, RouterDataV2<F, PaymentFlowData, T, PaymentsResponseData>>>
    for RouterDataV2<F, PaymentFlowData, T, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<ForteCaptureResponse, RouterDataV2<F, PaymentFlowData, T, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let transaction_id = &item.response.transaction_id;
        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(transaction_id.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: Some(serde_json::json!(ForteMeta {
                    auth_id: item.response.authorization_code,
                })),
                network_txn_id: None,
                connector_response_reference_id: Some(item.response.transaction_id.to_string()),
                incremental_authorization_allowed: None,
                charges: None,
            }),
            resource_common_data: PaymentFlowData {
                status: enums::AttemptStatus::from(item.response.response.response_code),
                ..item.data.resource_common_data
            },
            ..item.data
        })
    }
}

// Void/Cancel Request
#[derive(Debug, Serialize)]
pub struct ForteCancelRequest {
    action: String,
    authorization_code: String,
}

impl TryFrom<&RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>> for ForteCancelRequest {
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(item: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>) -> Result<Self, Self::Error> {
        let action = "void".to_string();
        let connector_auth_id: ForteMeta =
            utils::to_connector_meta(item.request.connector_meta.clone())?;
        let authorization_code = connector_auth_id.auth_id;
        Ok(Self {
            action,
            authorization_code,
        })
    }
}

// Void/Cancel Response
#[derive(Debug, Deserialize, Serialize)]
pub struct CancelResponseStatus {
    pub response_type: String,
    pub response_code: ForteResponseCode,
    pub response_desc: String,
    pub authorization_code: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ForteCancelResponse {
    pub transaction_id: String,
    pub location_id: Secret<String>,
    pub action: String,
    pub authorization_code: String,
    pub entered_by: String,
    pub response: CancelResponseStatus,
}

impl<F, T> TryFrom<ResponseRouterData<ForteCancelResponse, RouterDataV2<F, PaymentFlowData, T, PaymentsResponseData>>>
    for RouterDataV2<F, PaymentFlowData, T, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<ForteCancelResponse, RouterDataV2<F, PaymentFlowData, T, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let transaction_id = &item.response.transaction_id;
        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(transaction_id.to_string()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: Some(serde_json::json!(ForteMeta {
                    auth_id: item.response.authorization_code,
                })),
                network_txn_id: None,
                connector_response_reference_id: Some(transaction_id.to_string()),
                incremental_authorization_allowed: None,
                charges: None,
            }),
            resource_common_data: PaymentFlowData {
                status: enums::AttemptStatus::from(item.response.response.response_code),
                ..item.data.resource_common_data
            },
            ..item.data
        })
    }
}

// Refund Request
#[derive(Default, Debug, Serialize)]
pub struct ForteRefundRequest {
    action: String,
    authorization_amount: MinorUnit,
    original_transaction_id: String,
    authorization_code: String,
}

impl<F> TryFrom<&RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>> for ForteRefundRequest {
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: &RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> Result<Self, Self::Error> {
        let trn_id = item.request.connector_transaction_id.clone();
        let connector_auth_id: ForteMeta =
            utils::to_connector_meta(item.request.connector_metadata.clone())?;
        let auth_code = connector_auth_id.auth_id;
        let authorization_amount = item.request.minor_refund_amount;
        Ok(Self {
            action: "reverse".to_string(),
            authorization_amount,
            original_transaction_id: trn_id,
            authorization_code: auth_code,
        })
    }
}

// Refund Response
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RefundStatus {
    Complete,
    Ready,
    Failed,
}

impl From<RefundStatus> for enums::RefundStatus {
    fn from(item: RefundStatus) -> Self {
        match item {
            RefundStatus::Complete => Self::Success,
            RefundStatus::Ready => Self::Pending,
            RefundStatus::Failed => Self::Failure,
        }
    }
}

impl From<ForteResponseCode> for enums::RefundStatus {
    fn from(item: ForteResponseCode) -> Self {
        match item {
            ForteResponseCode::A01 | ForteResponseCode::A05 | ForteResponseCode::A06 => {
                Self::Pending
            }
            _ => Self::Failure,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RefundResponse {
    pub transaction_id: String,
    pub original_transaction_id: String,
    pub action: String,
    pub authorization_amount: Option<MinorUnit>,
    pub authorization_code: String,
    pub response: ResponseStatus,
}

impl<F> TryFrom<ResponseRouterData<RefundResponse, RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>>>
    for RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<RefundResponse, RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.transaction_id,
                refund_status: enums::RefundStatus::from(item.response.response.response_code),
            }),
            ..item.data
        })
    }
}

// Refund Sync Response
#[derive(Debug, Deserialize, Serialize)]
pub struct RefundSyncResponse {
    status: RefundStatus,
    transaction_id: String,
}

impl<F> TryFrom<ResponseRouterData<RefundSyncResponse, RouterDataV2<F, RefundFlowData, RefundSyncData, RefundsResponseData>>>
    for RouterDataV2<F, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<RefundSyncResponse, RouterDataV2<F, RefundFlowData, RefundSyncData, RefundsResponseData>>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.transaction_id,
                refund_status: enums::RefundStatus::from(item.response.status),
            }),
            ..item.data
        })
    }
}