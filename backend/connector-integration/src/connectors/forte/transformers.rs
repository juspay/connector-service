use common_enums::enums;
use common_utils::types::MinorUnit;
use domain_types::{
    connector_flow::{Authorize, Capture, PSync, Refund, RSync, Void},
    connector_types::*,
    errors::ConnectorError,
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes},
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
    types::*,
};
use error_stack::ResultExt;
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

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
pub struct FortePaymentRequest<T: PaymentMethodDataTypes + Serialize> {
    pub action: ForteAction,
    pub authorization_amount: MinorUnit,
    pub billing_address: BillingAddress,
    pub card: Card,
    #[serde(skip)]
    pub _phantom: std::marker::PhantomData<T>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BillingAddress {
    pub first_name: Secret<String>,
    pub last_name: Secret<String>,
}

#[derive(Debug, Serialize)]
pub struct Card {
    pub card_type: ForteCardType,
    pub name_on_card: Secret<String>,
    pub account_number: Secret<String>,
    pub expire_month: Secret<String>,
    pub expire_year: Secret<String>,
    pub card_verification_value: Secret<String>,
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

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ForteAction {
    Sale,
    Authorize,
    Verify,
    Capture,
    Reverse,
    Void,
}

// Response structures
#[derive(Debug, Deserialize, Serialize)]
pub struct FortePaymentResponse {
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
pub enum ForteResponseCode {
    A01,
    A05,
    A06,
    U13,
    U14,
    U18,
    U20,
}

// Status mapping
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

impl From<ForteResponseCode> for enums::AttemptStatus {
    fn from(item: ForteResponseCode) -> Self {
        match item {
            ForteResponseCode::A01 => Self::Charged,
            ForteResponseCode::A05 | ForteResponseCode::A06 => Self::Pending,
            _ => Self::Failure,
        }
    }
}

// Capture request/response
#[derive(Debug, Serialize)]
pub struct ForteCaptureRequest {
    pub action: String,
    pub transaction_id: String,
    pub authorization_code: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ForteCaptureResponse {
    pub transaction_id: String,
    pub original_transaction_id: String,
    pub entered_by: String,
    pub authorization_code: String,
    pub response: ResponseStatus,
}

// Void request/response
#[derive(Debug, Serialize)]
pub struct ForteVoidRequest {
    pub action: String,
    pub authorization_code: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ForteVoidResponse {
    pub transaction_id: String,
    pub location_id: Secret<String>,
    pub action: String,
    pub authorization_code: String,
    pub entered_by: String,
    pub response: ResponseStatus,
}

// Sync response
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

// Refund request/response
#[derive(Debug, Serialize)]
pub struct ForteRefundRequest {
    pub action: String,
    pub authorization_amount: MinorUnit,
    pub original_transaction_id: String,
    pub authorization_code: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ForteRefundResponse {
    pub transaction_id: String,
    pub original_transaction_id: String,
    pub action: String,
    pub authorization_amount: Option<MinorUnit>,
    pub authorization_code: String,
    pub response: ResponseStatus,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ForteRefundSyncResponse {
    pub status: RefundStatus,
    pub transaction_id: String,
}

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

// Error response
#[derive(Debug, Deserialize, Serialize)]
pub struct ForteErrorResponse {
    pub response: ErrorResponseStatus,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ErrorResponseStatus {
    pub environment: String,
    pub response_type: Option<String>,
    pub response_code: Option<String>,
    pub response_desc: String,
}

// Metadata structure
#[derive(Debug, Serialize, Deserialize)]
pub struct ForteMeta {
    pub auth_id: String,
}

// Request transformation implementations
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<&RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>
    for FortePaymentRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
    ) -> Result<Self, Self::Error> {
        // Check currency support
        if item.request.currency != enums::Currency::USD {
            return Err(ConnectorError::NotImplemented(
                "Forte only supports USD currency".to_string()
            ).into());
        }

        match &item.request.payment_method_data {
            PaymentMethodData::Card(card_data) => {
                let action = match item.request.capture_method {
                    Some(enums::CaptureMethod::Automatic) => ForteAction::Sale,
                    _ => ForteAction::Authorize,
                };

                let card_type = match card_data.card_network {
                    Some(enums::CardNetwork::Visa) => ForteCardType::Visa,
                    Some(enums::CardNetwork::Mastercard) => ForteCardType::MasterCard,
                    Some(enums::CardNetwork::AmericanExpress) => ForteCardType::Amex,
                    Some(enums::CardNetwork::Discover) => ForteCardType::Discover,
                    Some(enums::CardNetwork::DinersClub) => ForteCardType::DinersClub,
                    Some(enums::CardNetwork::JCB) => ForteCardType::Jcb,
                    _ => return Err(ConnectorError::NotImplemented(
                        "Unsupported card network for Forte".to_string()
                    ).into()),
                };

                let billing_address = item.address.billing.as_ref()
                    .ok_or(ConnectorError::MissingRequiredField { field_name: "billing_address" })?;

                let card = Card {
                    card_type,
                    name_on_card: card_data.card_holder_name.clone()
                        .unwrap_or_else(|| Secret::new("".to_string())),
                    account_number: card_data.card_number.clone(),
                    expire_month: card_data.card_exp_month.clone(),
                    expire_year: card_data.card_exp_year.clone(),
                    card_verification_value: card_data.card_cvc.clone(),
                };

                let billing_addr = BillingAddress {
                    first_name: billing_address.first_name.clone()
                        .unwrap_or_else(|| Secret::new("".to_string())),
                    last_name: billing_address.last_name.clone()
                        .unwrap_or_else(|| Secret::new("".to_string())),
                };

                Ok(Self {
                    action,
                    authorization_amount: item.request.minor_amount,
                    billing_address: billing_addr,
                    card,
                    _phantom: std::marker::PhantomData,
                })
            }
            _ => Err(ConnectorError::NotImplemented(
                "Payment method not supported by Forte".to_string()
            ).into()),
        }
    }
}

// Response transformation implementations
impl<F> TryFrom<ResponseRouterData<FortePaymentResponse, RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>>
    for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
where
    T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize,
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: ResponseRouterData<FortePaymentResponse, RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData { response, router_data, http_code } = item;
        
        let status = enums::AttemptStatus::from(response.response.response_code);
        
        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(response.transaction_id.clone()),
                redirection_data: None,
                connector_metadata: Some(serde_json::json!(ForteMeta {
                    auth_id: response.authorization_code,
                })),
                network_txn_id: None,
                connector_response_reference_id: Some(response.transaction_id),
                incremental_authorization_allowed: None,
                mandate_reference: None,
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

// Additional transformation implementations for other flows would go here...
// (Capture, Void, PSync, Refund, RSync)

impl TryFrom<&RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>>
    for ForteCaptureRequest
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
    ) -> Result<Self, Self::Error> {
        let connector_meta: ForteMeta = item.request.connector_metadata
            .as_ref()
            .ok_or(ConnectorError::MissingConnectorMetaData)?
            .parse_value("ForteMeta")
            .change_context(ConnectorError::InvalidConnectorConfig { config: "connector_metadata" })?;

        Ok(Self {
            action: "capture".to_string(),
            transaction_id: item.request.connector_transaction_id.clone(),
            authorization_code: connector_meta.auth_id,
        })
    }
}

impl TryFrom<&RouterDataV2<Void, PaymentFlowData, PaymentsCancelData, PaymentsResponseData>>
    for ForteVoidRequest
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: &RouterDataV2<Void, PaymentFlowData, PaymentsCancelData, PaymentsResponseData>
    ) -> Result<Self, Self::Error> {
        let connector_meta: ForteMeta = item.request.connector_metadata
            .as_ref()
            .ok_or(ConnectorError::MissingConnectorMetaData)?
            .parse_value("ForteMeta")
            .change_context(ConnectorError::InvalidConnectorConfig { config: "connector_metadata" })?;

        Ok(Self {
            action: "void".to_string(),
            authorization_code: connector_meta.auth_id,
        })
    }
}

impl TryFrom<&RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>>
    for ForteRefundRequest
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
    ) -> Result<Self, Self::Error> {
        let connector_meta: ForteMeta = item.request.connector_metadata
            .as_ref()
            .ok_or(ConnectorError::MissingConnectorMetaData)?
            .parse_value("ForteMeta")
            .change_context(ConnectorError::InvalidConnectorConfig { config: "connector_metadata" })?;

        Ok(Self {
            action: "reverse".to_string(),
            authorization_amount: item.request.minor_refund_amount,
            original_transaction_id: item.request.connector_transaction_id.clone(),
            authorization_code: connector_meta.auth_id,
        })
    }
}