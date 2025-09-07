use std::fmt::Debug;

use cards::CardNumber;
use common_enums::enums;
use common_utils::types::MinorUnit;
use domain_types::{
    connector_flow::{Authorize, Capture, PSync, RSync, Refund, Void},
    connector_types::*,
    errors::ConnectorError,
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes},
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
    router_request_types::ResponseId,
    router_response_types::{PaymentsResponseData, RefundsResponseData},
    types::{PaymentFlowData, RefundFlowData},
};
use error_stack::{report, ResultExt};
use hyperswitch_masking::{PeekInterface, Secret};
use serde::{Deserialize, Serialize};

use crate::types::ResponseRouterData;
use crate::utils::{AddressDetailsData, CardData, PaymentsAuthorizeRequestData, RouterData as _};

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
            _ => Err(report!(ConnectorError::FailedToObtainAuthType)),
        }
    }
}

// Helper function to convert MinorUnit to FloatMajorUnit for Forte API
fn minor_unit_to_float_major(amount: MinorUnit, currency: enums::Currency) -> Result<f64, ConnectorError> {
    match currency {
        enums::Currency::USD => {
            let amount_f64 = amount.get_amount_as_f64();
            Ok(amount_f64 / 100.0) // Convert cents to dollars
        }
        _ => Err(ConnectorError::NotImplemented(
            "Currency not supported by Forte".into(),
        )),
    }
}

// Request structures
#[derive(Debug, Serialize)]
pub struct FortePaymentsRequest<T: PaymentMethodDataTypes + Serialize> {
    action: ForteAction,
    authorization_amount: f64,
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

impl TryFrom<common_enums::CardNetwork> for ForteCardType {
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(card_network: common_enums::CardNetwork) -> Result<Self, Self::Error> {
        match card_network {
            common_enums::CardNetwork::AmericanExpress => Ok(Self::Amex),
            common_enums::CardNetwork::Mastercard => Ok(Self::MasterCard),
            common_enums::CardNetwork::Discover => Ok(Self::Discover),
            common_enums::CardNetwork::Visa => Ok(Self::Visa),
            common_enums::CardNetwork::DinersClub => Ok(Self::DinersClub),
            common_enums::CardNetwork::JCB => Ok(Self::Jcb),
            _ => Err(report!(ConnectorError::NotImplemented(
                "Card network not supported by Forte".into(),
            ))),
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

// Request transformation for Authorize
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<&RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>
    for FortePaymentsRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        // Validate currency
        if item.request.currency != enums::Currency::USD {
            return Err(report!(ConnectorError::NotImplemented(
                "Forte only supports USD currency".into(),
            )));
        }

        match &item.request.payment_method_data {
            PaymentMethodData::Card(card_data) => {
                let action = match item.request.capture_method {
                    Some(enums::CaptureMethod::Automatic) => ForteAction::Sale,
                    Some(enums::CaptureMethod::Manual) => ForteAction::Authorize,
                    _ => ForteAction::Sale, // Default to sale
                };

                let card_type = ForteCardType::try_from(card_data.card_network.clone())?;
                
                let authorization_amount = minor_unit_to_float_major(item.request.minor_amount, item.request.currency)?;

                let billing_address = item.get_billing_address()
                    .change_context(ConnectorError::MissingRequiredField {
                        field_name: "billing_address",
                    })?;

                let card = Card {
                    card_type,
                    name_on_card: item
                        .get_optional_billing_full_name()
                        .unwrap_or_else(|| Secret::new("".to_string())),
                    account_number: card_data.card_number.clone(),
                    expire_month: card_data.card_exp_month.clone(),
                    expire_year: card_data.card_exp_year.clone(),
                    card_verification_value: card_data.card_cvc.clone(),
                };

                let first_name = billing_address.get_first_name()
                    .change_context(ConnectorError::MissingRequiredField {
                        field_name: "billing_address.first_name",
                    })?;

                let billing_address = BillingAddress {
                    first_name: first_name.clone(),
                    last_name: billing_address.get_last_name().unwrap_or(first_name).clone(),
                };

                Ok(Self {
                    action,
                    authorization_amount,
                    billing_address,
                    card,
                    _phantom: std::marker::PhantomData,
                })
            }
            _ => Err(report!(ConnectorError::NotImplemented(
                "Payment method not supported by Forte".into(),
            ))),
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

impl From<ForteResponseCode> for enums::AttemptStatus {
    fn from(item: ForteResponseCode) -> Self {
        match item {
            ForteResponseCode::A01 | ForteResponseCode::A05 | ForteResponseCode::A06 => {
                Self::Pending
            }
            _ => Self::Failure,
        }
    }
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
    pub authorization_amount: Option<f64>,
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

// Response transformation for Authorize
impl<F> TryFrom<ResponseRouterData<FortePaymentsResponse, RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>>
    for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
where
    T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize,
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<FortePaymentsResponse, RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData { response, router_data, http_code } = item;
        
        let response_code = response.response.response_code;
        let action = response.action;
        let transaction_id = &response.transaction_id;
        let status = get_status(response_code, action);

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(transaction_id.to_string()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: Some(serde_json::json!(ForteMeta {
                    auth_id: response.authorization_code,
                })),
                network_txn_id: None,
                connector_response_reference_id: Some(transaction_id.to_string()),
                incremental_authorization_allowed: None,
                status_code: http_code,
            }),
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            ..router_data
        })
    }
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
    pub authorization_amount: Option<f64>,
    pub billing_address: Option<BillingAddress>,
    pub entered_by: String,
    pub received_date: String,
    pub origination_date: Option<String>,
    pub card: Option<CardResponse>,
    pub attempt_number: i64,
    pub response: ResponseStatus,
    pub links: ForteLink,
    pub biller_name: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ForteLink {
    pub disputes: String,
    pub settlements: String,
    #[serde(rename = "self")]
    pub self_url: String,
}

// Response transformation for Payment Sync
impl<F> TryFrom<ResponseRouterData<FortePaymentsSyncResponse, RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>>
    for RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<FortePaymentsSyncResponse, RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData { response, router_data, http_code } = item;
        
        let transaction_id = &response.transaction_id;
        let status = enums::AttemptStatus::from(response.status);

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(transaction_id.to_string()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: Some(serde_json::json!(ForteMeta {
                    auth_id: response.authorization_code,
                })),
                network_txn_id: None,
                connector_response_reference_id: Some(transaction_id.to_string()),
                incremental_authorization_allowed: None,
                status_code: http_code,
            }),
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            ..router_data
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

impl TryFrom<&RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>>
    for ForteCaptureRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let trn_id = item.request.connector_transaction_id.clone();
        let connector_auth_id: ForteMeta = item.request.connector_meta
            .as_ref()
            .ok_or(ConnectorError::MissingConnectorTransactionID)?
            .parse_value("ForteMeta")
            .change_context(ConnectorError::InvalidConnectorConfig {
                config: "connector_meta",
            })?;
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

// Response transformation for Capture
impl<F> TryFrom<ResponseRouterData<ForteCaptureResponse, RouterDataV2<F, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>>>
    for RouterDataV2<F, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<ForteCaptureResponse, RouterDataV2<F, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData { response, router_data, http_code } = item;
        
        let transaction_id = &response.transaction_id;
        let status = enums::AttemptStatus::from(response.response.response_code);

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(transaction_id.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: Some(serde_json::json!(ForteMeta {
                    auth_id: response.authorization_code,
                })),
                network_txn_id: None,
                connector_response_reference_id: Some(response.transaction_id.to_string()),
                incremental_authorization_allowed: None,
                status_code: http_code,
            }),
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            ..router_data
        })
    }
}

// Cancel/Void Request
#[derive(Debug, Serialize)]
pub struct ForteCancelRequest {
    action: String,
    authorization_code: String,
}

impl TryFrom<&RouterDataV2<Void, PaymentFlowData, PaymentsCancelData, PaymentsResponseData>>
    for ForteCancelRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: &RouterDataV2<Void, PaymentFlowData, PaymentsCancelData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let action = "void".to_string();
        let connector_auth_id: ForteMeta = item.request.connector_meta
            .as_ref()
            .ok_or(ConnectorError::MissingConnectorTransactionID)?
            .parse_value("ForteMeta")
            .change_context(ConnectorError::InvalidConnectorConfig {
                config: "connector_meta",
            })?;
        let authorization_code = connector_auth_id.auth_id;
        
        Ok(Self {
            action,
            authorization_code,
        })
    }
}

// Cancel Response
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

// Response transformation for Cancel/Void
impl<F> TryFrom<ResponseRouterData<ForteCancelResponse, RouterDataV2<F, PaymentFlowData, PaymentsCancelData, PaymentsResponseData>>>
    for RouterDataV2<F, PaymentFlowData, PaymentsCancelData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<ForteCancelResponse, RouterDataV2<F, PaymentFlowData, PaymentsCancelData, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData { response, router_data, http_code } = item;
        
        let transaction_id = &response.transaction_id;
        let status = enums::AttemptStatus::from(response.response.response_code);

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(transaction_id.to_string()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: Some(serde_json::json!(ForteMeta {
                    auth_id: response.authorization_code,
                })),
                network_txn_id: None,
                connector_response_reference_id: Some(transaction_id.to_string()),
                incremental_authorization_allowed: None,
                status_code: http_code,
            }),
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            ..router_data
        })
    }
}

// Refund Request
#[derive(Default, Debug, Serialize)]
pub struct ForteRefundRequest {
    action: String,
    authorization_amount: f64,
    original_transaction_id: String,
    authorization_code: String,
}

impl TryFrom<&RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>>
    for ForteRefundRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> Result<Self, Self::Error> {
        let trn_id = item.request.connector_transaction_id.clone();
        let connector_auth_id: ForteMeta = item.request.connector_metadata
            .as_ref()
            .ok_or(ConnectorError::MissingConnectorTransactionID)?
            .parse_value("ForteMeta")
            .change_context(ConnectorError::InvalidConnectorConfig {
                config: "connector_metadata",
            })?;
        let auth_code = connector_auth_id.auth_id;
        let authorization_amount = minor_unit_to_float_major(item.request.minor_refund_amount, item.request.currency)?;
        
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
    pub authorization_amount: Option<f64>,
    pub authorization_code: String,
    pub response: ResponseStatus,
}

// Response transformation for Refund
impl<F> TryFrom<ResponseRouterData<RefundResponse, RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>>>
    for RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<RefundResponse, RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData { response, router_data, http_code: _ } = item;
        
        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: response.transaction_id,
                refund_status: enums::RefundStatus::from(response.response.response_code),
            }),
            ..router_data
        })
    }
}

// Refund Sync Response
#[derive(Debug, Deserialize, Serialize)]
pub struct RefundSyncResponse {
    status: RefundStatus,
    transaction_id: String,
}

// Response transformation for Refund Sync
impl<F> TryFrom<ResponseRouterData<RefundSyncResponse, RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>>>
    for RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<RefundSyncResponse, RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData { response, router_data, http_code: _ } = item;
        
        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: response.transaction_id,
                refund_status: enums::RefundStatus::from(response.status),
            }),
            ..router_data
        })
    }
}

// Error Response
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