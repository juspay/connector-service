use std::fmt::Debug;
use std::marker::{Send, Sync};
use std::time::{SystemTime, UNIX_EPOCH};

use common_enums::{AttemptStatus, Currency, RefundStatus};
use common_utils::{errors::CustomResult, types::MinorUnit};
use domain_types::{
    connector_flow::*,
    connector_types::*,
    errors,
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes},
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
};
use error_stack::ResultExt;
use hyperswitch_masking::{PeekInterface, Secret};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::types::ResponseRouterData;
use crate::utils;

// Import the connector's RouterData wrapper type created by the macro
use super::PayboxRouterData;

// ============================================================================
// RESPONSE TYPE ALIASES
// ============================================================================
pub type PayboxAuthorizeResponse = PayboxPaymentResponse;
pub type PayboxCaptureResponse = PayboxPaymentResponse;
pub type PayboxVoidResponse = PayboxPaymentResponse;

// ============================================================================
// AUTHENTICATION
// ============================================================================

#[derive(Debug, Clone)]
pub struct PayboxAuthType {
    pub site: Secret<String>,
    pub rank: Secret<String>,
    pub key: Secret<String>,
    pub merchant_id: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for PayboxAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::MultiAuthKey {
                api_key,
                key1,
                api_secret,
                key2,
            } => Ok(Self {
                site: api_key.to_owned(),
                rank: key1.to_owned(),
                key: api_secret.to_owned(),
                merchant_id: key2.to_owned(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

// ============================================================================
// COMMON ENUMS AND TYPES
// ============================================================================

const VERSION_PAYBOX: &str = "00104";
const AUTH_REQUEST: &str = "00001";
const CAPTURE_REQUEST: &str = "00002";
const AUTH_AND_CAPTURE_REQUEST: &str = "00003";
const CANCEL_REQUEST: &str = "00005";
const REFUND_REQUEST: &str = "00014";
const SYNC_REQUEST: &str = "00017";
const SUCCESS_CODE: &str = "00000";
const PAY_ORIGIN_INTERNET: &str = "024";

#[derive(Debug, Serialize, Deserialize)]
pub struct PayboxMeta {
    pub connector_request_id: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PayboxStatus {
    #[serde(rename = "Remboursé")]
    Refunded,
    #[serde(rename = "Annulé")]
    Cancelled,
    #[serde(rename = "Autorisé")]
    Authorised,
    #[serde(rename = "Capturé")]
    Captured,
    #[serde(rename = "Refusé")]
    Rejected,
}

impl From<PayboxStatus> for AttemptStatus {
    fn from(item: PayboxStatus) -> Self {
        match item {
            PayboxStatus::Cancelled => Self::Voided,
            PayboxStatus::Authorised => Self::Authorized,
            PayboxStatus::Captured | PayboxStatus::Refunded => Self::Charged,
            PayboxStatus::Rejected => Self::Failure,
        }
    }
}

impl From<PayboxStatus> for RefundStatus {
    fn from(item: PayboxStatus) -> Self {
        match item {
            PayboxStatus::Refunded => Self::Success,
            PayboxStatus::Cancelled
            | PayboxStatus::Authorised
            | PayboxStatus::Captured
            | PayboxStatus::Rejected => Self::Failure,
        }
    }
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

fn get_transaction_type(capture_method: Option<common_enums::CaptureMethod>) -> &'static str {
    match capture_method {
        Some(common_enums::CaptureMethod::Automatic) => AUTH_AND_CAPTURE_REQUEST,
        Some(common_enums::CaptureMethod::Manual) => AUTH_REQUEST,
        _ => AUTH_REQUEST,
    }
}

fn generate_request_id() -> CustomResult<String, errors::ConnectorError> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .change_context(errors::ConnectorError::RequestEncodingFailed)?
        .as_millis()
        .to_string();

    timestamp
        .get(4..)
        .map(|s| s.to_string())
        .ok_or(errors::ConnectorError::ParsingFailed.into())
}

fn generate_date_time() -> String {
    let now = OffsetDateTime::now_utc();
    format!(
        "{:02}{:02}{:04}{:02}{:02}{:02}",
        now.day(),
        now.month() as u8,
        now.year(),
        now.hour(),
        now.minute(),
        now.second()
    )
}

fn get_currency_code(currency: Currency) -> CustomResult<String, errors::ConnectorError> {
    let code = match currency {
        Currency::EUR => "978",
        Currency::USD => "840",
        Currency::GBP => "826",
        Currency::CHF => "756",
        Currency::CAD => "124",
        _ => {
            return Err(errors::ConnectorError::NotSupported {
                message: format!("Currency {} not supported by Paybox", currency),
                connector: "Paybox",
            }
            .into())
        }
    };
    Ok(code.to_string())
}


fn get_transaction_id(numappel: Option<String>, numtrans: Option<String>) -> String {
    numappel.or(numtrans).unwrap_or_default()
}

// ============================================================================
// AUTHORIZE FLOW
// ============================================================================

#[derive(Debug, Serialize)]
pub struct PayboxPaymentRequest<T> {
    #[serde(rename = "VERSION")]
    pub version: String,
    #[serde(rename = "TYPE")]
    pub transaction_type: String,
    #[serde(rename = "SITE")]
    pub site: Secret<String>,
    #[serde(rename = "RANG")]
    pub rank: Secret<String>,
    #[serde(rename = "CLE")]
    pub key: Secret<String>,
    #[serde(rename = "NUMQUESTION")]
    pub paybox_request_number: String,
    #[serde(rename = "MONTANT")]
    pub amount: MinorUnit,
    #[serde(rename = "DEVISE")]
    pub currency: String,
    #[serde(rename = "REFERENCE")]
    pub reference: String,
    #[serde(rename = "DATEQ")]
    pub date: String,
    #[serde(rename = "PORTEUR")]
    pub card_number: Secret<String>,
    #[serde(rename = "DATEVAL")]
    pub expiration_date: Secret<String>,
    #[serde(rename = "CVV")]
    pub cvv: Secret<String>,
    #[serde(rename = "ACTIVITE")]
    pub activity: String,
    #[serde(skip)]
    _phantom: std::marker::PhantomData<T>,
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> TryFrom<PayboxRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>>
    for PayboxPaymentRequest<T>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: PayboxRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let router_data = item.router_data;
        let connector = item.connector;

        let auth = PayboxAuthType::try_from(&router_data.connector_auth_type)?;

        let amount = connector
            .amount_converter
            .convert(router_data.request.minor_amount, router_data.request.currency)
            .change_context(errors::ConnectorError::ParsingFailed)?;

        let card = match &router_data.request.payment_method_data {
            PaymentMethodData::Card(card_data) => card_data,
            _ => {
                return Err(errors::ConnectorError::NotSupported {
                    message: "Only card payments are supported".to_string(),
                    connector: "Paybox",
                }
                .into())
            }
        };

        let expiry_month = card.card_exp_month.peek();
        let expiry_year = card.card_exp_year.peek();
        let year_last_two = if expiry_year.len() >= 2 {
            &expiry_year[expiry_year.len() - 2..]
        } else {
            expiry_year.as_str()
        };

        let dateval = Secret::new(format!("{}{}", expiry_month, year_last_two));
        let transaction_type = get_transaction_type(router_data.request.capture_method);

        Ok(Self {
            version: VERSION_PAYBOX.to_string(),
            transaction_type: transaction_type.to_string(),
            site: auth.site,
            rank: auth.rank,
            key: auth.key,
            paybox_request_number: generate_request_id()?,
            amount,
            currency: get_currency_code(router_data.request.currency)?,
            reference: router_data.resource_common_data.connector_request_reference_id.clone(),
            date: generate_date_time(),
            card_number: Secret::new(card.card_number.peek().to_string()),
            expiration_date: dateval,
            cvv: card.card_cvc.clone(),
            activity: PAY_ORIGIN_INTERNET.to_string(),
            _phantom: std::marker::PhantomData,
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PayboxPaymentResponse {
    #[serde(rename = "NUMTRANS")]
    pub transaction_number: Option<String>,
    #[serde(rename = "NUMAPPEL")]
    pub paybox_order_id: Option<String>,
    #[serde(rename = "NUMQUESTION")]
    pub paybox_request_number: Option<String>,
    #[serde(rename = "SITE")]
    pub site: Option<String>,
    #[serde(rename = "RANG")]
    pub rank: Option<String>,
    #[serde(rename = "AUTORISATION")]
    pub authorization: Option<String>,
    #[serde(rename = "CODEREPONSE")]
    pub response_code: String,
    #[serde(rename = "COMMENTAIRE")]
    pub response_message: Option<String>,
}

impl<T: PaymentMethodDataTypes>
    TryFrom<
        ResponseRouterData<
            PayboxAuthorizeResponse,
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        >,
    > for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            PayboxAuthorizeResponse,
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let is_auto_capture = matches!(
            item.router_data.request.capture_method,
            Some(common_enums::CaptureMethod::Automatic)
        );

        let connector_transaction_id = get_transaction_id(
            item.response.paybox_order_id.clone(),
            item.response.transaction_number.clone(),
        );

        if item.response.response_code == SUCCESS_CODE {
            let status = if is_auto_capture {
                AttemptStatus::Charged
            } else {
                AttemptStatus::Authorized
            };

            let connector_metadata = item.response.transaction_number.as_ref().map(|transaction_number| {
                serde_json::json!({
                    "connector_request_id": transaction_number
                })
            });

            Ok(Self {
                response: Ok(PaymentsResponseData::TransactionResponse {
                    resource_id: ResponseId::ConnectorTransactionId(connector_transaction_id.clone()),
                    redirection_data: None,
                    mandate_reference: None,
                    connector_metadata,
                    network_txn_id: None,
                    connector_response_reference_id: Some(connector_transaction_id),
                    incremental_authorization_allowed: None,
                    status_code: item.http_code,
                }),
                resource_common_data: PaymentFlowData {
                    status,
                    ..item.router_data.resource_common_data
                },
                ..item.router_data
            })
        } else {
            Err(errors::ConnectorError::ResponseHandlingFailed.into())
        }
    }
}

// ============================================================================
// PSYNC FLOW
// ============================================================================

#[derive(Debug, Serialize)]
pub struct PayboxSyncRequest {
    #[serde(rename = "VERSION")]
    pub version: String,
    #[serde(rename = "TYPE")]
    pub transaction_type: String,
    #[serde(rename = "SITE")]
    pub site: Secret<String>,
    #[serde(rename = "RANG")]
    pub rank: Secret<String>,
    #[serde(rename = "CLE")]
    pub key: Secret<String>,
    #[serde(rename = "NUMQUESTION")]
    pub paybox_request_number: String,
    #[serde(rename = "REFERENCE")]
    pub reference: String,
    #[serde(rename = "DATEQ")]
    pub date: String,
    #[serde(rename = "NUMTRANS")]
    pub transaction_number: String,
    #[serde(rename = "NUMAPPEL")]
    pub paybox_order_id: String,
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> TryFrom<PayboxRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>>
    for PayboxSyncRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: PayboxRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let router_data = item.router_data;
        let auth = PayboxAuthType::try_from(&router_data.connector_auth_type)?;

        let numappel = match &router_data.request.connector_transaction_id {
            ResponseId::ConnectorTransactionId(id) => id.clone(),
            _ => return Err(errors::ConnectorError::MissingConnectorTransactionID.into()),
        };

        let paybox_meta: PayboxMeta = utils::to_connector_meta(router_data.request.connector_meta.clone())?;
        let numtrans = paybox_meta.connector_request_id;

        Ok(Self {
            version: VERSION_PAYBOX.to_string(),
            transaction_type: SYNC_REQUEST.to_string(),
            site: auth.site,
            rank: auth.rank,
            key: auth.key,
            paybox_request_number: generate_request_id()?,
            reference: router_data.resource_common_data.connector_request_reference_id.clone(),
            date: generate_date_time(),
            transaction_number: numtrans,
            paybox_order_id: numappel,
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PayboxPSyncResponse {
    #[serde(rename = "NUMTRANS")]
    pub transaction_number: Option<String>,
    #[serde(rename = "NUMAPPEL")]
    pub paybox_order_id: Option<String>,
    #[serde(rename = "NUMQUESTION")]
    pub paybox_request_number: Option<String>,
    #[serde(rename = "SITE")]
    pub site: Option<String>,
    #[serde(rename = "RANG")]
    pub rank: Option<String>,
    #[serde(rename = "AUTORISATION")]
    pub authorization: Option<String>,
    #[serde(rename = "CODEREPONSE")]
    pub response_code: String,
    #[serde(rename = "COMMENTAIRE")]
    pub response_message: Option<String>,
    #[serde(rename = "STATUS")]
    pub status: PayboxStatus,
}

impl TryFrom<
        ResponseRouterData<
            PayboxPSyncResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    > for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            PayboxPSyncResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let connector_payment_status = item.response.status;
        let status = AttemptStatus::from(connector_payment_status);

        let connector_transaction_id = get_transaction_id(
            item.response.paybox_order_id.clone(),
            item.response.transaction_number.clone(),
        );

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(connector_transaction_id.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(connector_transaction_id),
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

// ============================================================================
// CAPTURE FLOW
// ============================================================================

#[derive(Debug, Serialize)]
pub struct PayboxCaptureRequest {
    #[serde(rename = "VERSION")]
    pub version: String,
    #[serde(rename = "TYPE")]
    pub transaction_type: String,
    #[serde(rename = "SITE")]
    pub site: Secret<String>,
    #[serde(rename = "RANG")]
    pub rank: Secret<String>,
    #[serde(rename = "CLE")]
    pub key: Secret<String>,
    #[serde(rename = "NUMQUESTION")]
    pub paybox_request_number: String,
    #[serde(rename = "MONTANT")]
    pub amount: MinorUnit,
    #[serde(rename = "DEVISE")]
    pub currency: String,
    #[serde(rename = "REFERENCE")]
    pub reference: String,
    #[serde(rename = "DATEQ")]
    pub date: String,
    #[serde(rename = "NUMTRANS")]
    pub transaction_number: String,
    #[serde(rename = "NUMAPPEL")]
    pub paybox_order_id: String,
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> TryFrom<PayboxRouterData<RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>, T>>
    for PayboxCaptureRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: PayboxRouterData<RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let router_data = item.router_data;
        let connector = item.connector;
        let auth = PayboxAuthType::try_from(&router_data.connector_auth_type)?;

        let numappel = match &router_data.request.connector_transaction_id {
            ResponseId::ConnectorTransactionId(id) => id.clone(),
            _ => return Err(errors::ConnectorError::MissingConnectorTransactionID.into()),
        };

        let paybox_meta: PayboxMeta = utils::to_connector_meta_from_secret(
            router_data
                .resource_common_data
                .connector_meta_data
                .clone(),
        )?;
        let numtrans = paybox_meta.connector_request_id;

        let amount = connector
            .amount_converter
            .convert(
                router_data.request.minor_amount_to_capture,
                router_data.request.currency,
            )
            .change_context(errors::ConnectorError::ParsingFailed)?;

        Ok(Self {
            version: VERSION_PAYBOX.to_string(),
            transaction_type: CAPTURE_REQUEST.to_string(),
            site: auth.site,
            rank: auth.rank,
            key: auth.key,
            paybox_request_number: generate_request_id()?,
            amount,
            currency: get_currency_code(router_data.request.currency)?,
            reference: router_data.resource_common_data.connector_request_reference_id.clone(),
            date: generate_date_time(),
            transaction_number: numtrans,
            paybox_order_id: numappel,
        })
    }
}

impl TryFrom<
        ResponseRouterData<
            PayboxCaptureResponse,
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    > for RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            PayboxCaptureResponse,
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let connector_transaction_id = get_transaction_id(
            item.response.paybox_order_id.clone(),
            item.response.transaction_number.clone(),
        );

        if item.response.response_code == SUCCESS_CODE {
            Ok(Self {
                response: Ok(PaymentsResponseData::TransactionResponse {
                    resource_id: ResponseId::ConnectorTransactionId(connector_transaction_id.clone()),
                    redirection_data: None,
                    mandate_reference: None,
                    connector_metadata: None,
                    network_txn_id: None,
                    connector_response_reference_id: Some(connector_transaction_id),
                    incremental_authorization_allowed: None,
                    status_code: item.http_code,
                }),
                resource_common_data: PaymentFlowData {
                    status: AttemptStatus::Charged,
                    ..item.router_data.resource_common_data
                },
                ..item.router_data
            })
        } else {
            Err(errors::ConnectorError::ResponseHandlingFailed.into())
        }
    }
}

// ============================================================================
// VOID FLOW
// ============================================================================

#[derive(Debug, Serialize)]
pub struct PayboxVoidRequest {
    #[serde(rename = "VERSION")]
    pub version: String,
    #[serde(rename = "TYPE")]
    pub transaction_type: String,
    #[serde(rename = "SITE")]
    pub site: Secret<String>,
    #[serde(rename = "RANG")]
    pub rank: Secret<String>,
    #[serde(rename = "CLE")]
    pub key: Secret<String>,
    #[serde(rename = "NUMQUESTION")]
    pub paybox_request_number: String,
    #[serde(rename = "MONTANT")]
    pub amount: MinorUnit,
    #[serde(rename = "DEVISE")]
    pub currency: String,
    #[serde(rename = "REFERENCE")]
    pub reference: String,
    #[serde(rename = "DATEQ")]
    pub date: String,
    #[serde(rename = "NUMTRANS")]
    pub transaction_number: String,
    #[serde(rename = "NUMAPPEL")]
    pub paybox_order_id: String,
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> TryFrom<PayboxRouterData<RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>, T>>
    for PayboxVoidRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: PayboxRouterData<RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let router_data = item.router_data;
        let connector = item.connector;
        let auth = PayboxAuthType::try_from(&router_data.connector_auth_type)?;

        let numappel = router_data.request.connector_transaction_id.clone();

        // Try to get NUMTRANS from stored metadata, fallback to NUMAPPEL if not available
        // Note: connector_metadata in request may contain merchant custom data
        let numtrans = router_data.request.connector_metadata
            .clone()
            .and_then(|meta| utils::to_connector_meta_from_secret::<PayboxMeta>(Some(meta)).ok())
            .map(|meta| meta.connector_request_id)
            .unwrap_or_else(|| numappel.clone());

        let amount = router_data
            .request
            .amount
            .ok_or(errors::ConnectorError::MissingRequiredField {
                field_name: "amount",
            })?;

        let currency = router_data
            .request
            .currency
            .ok_or(errors::ConnectorError::MissingRequiredField {
                field_name: "currency",
            })?;

        let amount = connector
            .amount_converter
            .convert(amount, currency)
            .change_context(errors::ConnectorError::ParsingFailed)?;

        Ok(Self {
            version: VERSION_PAYBOX.to_string(),
            transaction_type: CANCEL_REQUEST.to_string(),
            site: auth.site,
            rank: auth.rank,
            key: auth.key,
            paybox_request_number: generate_request_id()?,
            amount,
            currency: get_currency_code(currency)?,
            reference: router_data.resource_common_data.connector_request_reference_id.clone(),
            date: generate_date_time(),
            transaction_number: numtrans,
            paybox_order_id: numappel,
        })
    }
}

impl TryFrom<
        ResponseRouterData<
            PayboxVoidResponse,
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        >,
    > for RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            PayboxVoidResponse,
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let connector_transaction_id = get_transaction_id(
            item.response.paybox_order_id.clone(),
            item.response.transaction_number.clone(),
        );

        if item.response.response_code == SUCCESS_CODE {
            Ok(Self {
                response: Ok(PaymentsResponseData::TransactionResponse {
                    resource_id: ResponseId::ConnectorTransactionId(connector_transaction_id.clone()),
                    redirection_data: None,
                    mandate_reference: None,
                    connector_metadata: None,
                    network_txn_id: None,
                    connector_response_reference_id: Some(connector_transaction_id),
                    incremental_authorization_allowed: None,
                    status_code: item.http_code,
                }),
                resource_common_data: PaymentFlowData {
                    status: AttemptStatus::Voided,
                    ..item.router_data.resource_common_data
                },
                ..item.router_data
            })
        } else {
            Err(errors::ConnectorError::ResponseHandlingFailed.into())
        }
    }
}

// ============================================================================
// REFUND FLOW
// ============================================================================

#[derive(Debug, Serialize)]
pub struct PayboxRefundRequest {
    #[serde(rename = "VERSION")]
    pub version: String,
    #[serde(rename = "TYPE")]
    pub transaction_type: String,
    #[serde(rename = "SITE")]
    pub site: Secret<String>,
    #[serde(rename = "RANG")]
    pub rank: Secret<String>,
    #[serde(rename = "CLE")]
    pub key: Secret<String>,
    #[serde(rename = "NUMQUESTION")]
    pub paybox_request_number: String,
    #[serde(rename = "MONTANT")]
    pub amount: MinorUnit,
    #[serde(rename = "DEVISE")]
    pub currency: String,
    #[serde(rename = "REFERENCE")]
    pub reference: String,
    #[serde(rename = "DATEQ")]
    pub date: String,
    #[serde(rename = "NUMTRANS")]
    pub transaction_number: String,
    #[serde(rename = "NUMAPPEL")]
    pub paybox_order_id: String,
    #[serde(rename = "ACTIVITE")]
    pub activity: String,
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> TryFrom<PayboxRouterData<RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>, T>>
    for PayboxRefundRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: PayboxRouterData<RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let router_data = item.router_data;
        let connector = item.connector;
        let auth = PayboxAuthType::try_from(&router_data.connector_auth_type)?;

        let numappel = router_data.request.connector_transaction_id.clone();

        // Try to get NUMTRANS from stored metadata, fallback to NUMAPPEL if not available
        // Note: connector_metadata in request may contain merchant custom data
        let numtrans = router_data.request.connector_metadata
            .clone()
            .and_then(|meta| utils::to_connector_meta::<PayboxMeta>(Some(meta)).ok())
            .map(|meta| meta.connector_request_id)
            .unwrap_or_else(|| numappel.clone());

        let amount = connector
            .amount_converter
            .convert(router_data.request.minor_refund_amount, router_data.request.currency)
            .change_context(errors::ConnectorError::ParsingFailed)?;

        Ok(Self {
            version: VERSION_PAYBOX.to_string(),
            transaction_type: REFUND_REQUEST.to_string(),
            site: auth.site,
            rank: auth.rank,
            key: auth.key,
            paybox_request_number: generate_request_id()?,
            amount,
            currency: get_currency_code(router_data.request.currency)?,
            reference: router_data.resource_common_data.connector_request_reference_id.clone(),
            date: generate_date_time(),
            transaction_number: numtrans,
            paybox_order_id: numappel,
            activity: PAY_ORIGIN_INTERNET.to_string(),
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PayboxRefundResponse {
    #[serde(rename = "NUMTRANS")]
    pub transaction_number: Option<String>,
    #[serde(rename = "NUMAPPEL")]
    pub paybox_order_id: Option<String>,
    #[serde(rename = "NUMQUESTION")]
    pub paybox_request_number: Option<String>,
    #[serde(rename = "SITE")]
    pub site: Option<String>,
    #[serde(rename = "RANG")]
    pub rank: Option<String>,
    #[serde(rename = "AUTORISATION")]
    pub authorization: Option<String>,
    #[serde(rename = "CODEREPONSE")]
    pub response_code: String,
    #[serde(rename = "COMMENTAIRE")]
    pub response_message: Option<String>,
}

impl TryFrom<
        ResponseRouterData<
            PayboxRefundResponse,
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    > for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            PayboxRefundResponse,
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let connector_refund_id = get_transaction_id(
            item.response.paybox_order_id.clone(),
            item.response.transaction_number.clone(),
        );

        if item.response.response_code == SUCCESS_CODE {
            Ok(Self {
                response: Ok(RefundsResponseData {
                    connector_refund_id,
                    refund_status: RefundStatus::Pending,
                    status_code: item.http_code,
                }),
                resource_common_data: RefundFlowData {
                    status: RefundStatus::Pending,
                    ..item.router_data.resource_common_data
                },
                ..item.router_data
            })
        } else {
            Err(errors::ConnectorError::ResponseHandlingFailed.into())
        }
    }
}

// ============================================================================
// RSYNC FLOW
// ============================================================================

#[derive(Debug, Serialize)]
pub struct PayboxRefundSyncRequest {
    #[serde(rename = "VERSION")]
    pub version: String,
    #[serde(rename = "TYPE")]
    pub transaction_type: String,
    #[serde(rename = "SITE")]
    pub site: Secret<String>,
    #[serde(rename = "RANG")]
    pub rank: Secret<String>,
    #[serde(rename = "CLE")]
    pub key: Secret<String>,
    #[serde(rename = "NUMQUESTION")]
    pub paybox_request_number: String,
    #[serde(rename = "DATEQ")]
    pub date: String,
    #[serde(rename = "NUMTRANS")]
    pub transaction_number: String,
    #[serde(rename = "NUMAPPEL")]
    pub paybox_order_id: String,
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> TryFrom<PayboxRouterData<RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>, T>>
    for PayboxRefundSyncRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: PayboxRouterData<RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let router_data = item.router_data;
        let auth = PayboxAuthType::try_from(&router_data.connector_auth_type)?;

        let connector_refund_id = router_data.request.connector_refund_id.clone();

        Ok(Self {
            version: VERSION_PAYBOX.to_string(),
            transaction_type: SYNC_REQUEST.to_string(),
            site: auth.site,
            rank: auth.rank,
            key: auth.key,
            paybox_request_number: generate_request_id()?,
            date: generate_date_time(),
            transaction_number: connector_refund_id.clone(),
            paybox_order_id: connector_refund_id,
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PayboxRSyncResponse {
    #[serde(rename = "NUMTRANS")]
    pub transaction_number: Option<String>,
    #[serde(rename = "NUMAPPEL")]
    pub paybox_order_id: Option<String>,
    #[serde(rename = "NUMQUESTION")]
    pub paybox_request_number: Option<String>,
    #[serde(rename = "SITE")]
    pub site: Option<String>,
    #[serde(rename = "RANG")]
    pub rank: Option<String>,
    #[serde(rename = "AUTORISATION")]
    pub authorization: Option<String>,
    #[serde(rename = "CODEREPONSE")]
    pub response_code: String,
    #[serde(rename = "COMMENTAIRE")]
    pub response_message: Option<String>,
    #[serde(rename = "STATUS")]
    pub status: PayboxStatus,
}

impl TryFrom<
        ResponseRouterData<
            PayboxRSyncResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    > for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            PayboxRSyncResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let connector_refund_status = item.response.status;
        let refund_status = RefundStatus::from(connector_refund_status);

        let connector_refund_id = get_transaction_id(
            item.response.paybox_order_id.clone(),
            item.response.transaction_number.clone(),
        );

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id,
                refund_status,
                status_code: item.http_code,
            }),
            resource_common_data: RefundFlowData {
                status: refund_status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

// ============================================================================
// ERROR RESPONSE
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayboxErrorResponse {
    #[serde(rename = "CODEREPONSE")]
    pub code: String,
    #[serde(rename = "COMMENTAIRE")]
    pub message: String,
    #[serde(rename = "NUMTRANS")]
    pub transaction_number: Option<String>,
}
