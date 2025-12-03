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

// Import the connector's RouterData wrapper type created by the macro
use super::PayboxRouterData;

// ============================================================================
// RESPONSE TYPE ALIASES
// ============================================================================
// Create type aliases to avoid duplicate templating in macro expansion
pub type PayboxAuthorizeResponse = PayboxPaymentResponse;
pub type PayboxCaptureResponse = PayboxPaymentResponse;
pub type PayboxVoidResponse = PayboxPaymentResponse;
// Note: PayboxPSyncResponse and PayboxRSyncResponse are defined separately below because they have STATUS field

// ============================================================================
// AUTHENTICATION
// ============================================================================

#[derive(Debug, Clone)]
pub struct PayboxAuthType {
    pub site: Secret<String>,
    pub rang: Secret<String>,
    pub cle: Secret<String>,
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
                rang: key1.to_owned(),
                cle: api_secret.to_owned(),
                merchant_id: key2.to_owned(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

// ============================================================================
// COMMON ENUMS AND TYPES
// ============================================================================

// Transaction type constants (matching Hyperswitch implementation)
const AUTH_REQUEST: &str = "00001";          // Authorization only
const CAPTURE_REQUEST: &str = "00002";       // Capture
const AUTH_AND_CAPTURE_REQUEST: &str = "00003"; // Auth + Capture in one request
const CANCEL_REQUEST: &str = "00005";        // Void/Cancel
const REFUND_REQUEST: &str = "00014";        // Refund
const SYNC_REQUEST: &str = "00017";          // Inquiry/Sync

// PayboxStatus enum for STATUS field in inquiry responses (TYPE=00017)
// These are French text values returned by Paybox
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
    // Determines the Paybox transaction type based on capture method
    // Following Hyperswitch implementation logic
    match capture_method {
        Some(common_enums::CaptureMethod::Automatic) => AUTH_AND_CAPTURE_REQUEST,
        Some(common_enums::CaptureMethod::Manual) => AUTH_REQUEST,
        _ => AUTH_REQUEST, // Default to authorization only
    }
}

fn generate_request_id() -> CustomResult<String, errors::ConnectorError> {
    // Generate a unique request ID using timestamp
    // Taking substring from position 4 to avoid collisions (matches Hyperswitch implementation)
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
    // Format: DDMMYYYYHHMMSS
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
    // ISO 4217 numeric codes
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

fn map_paybox_status_to_attempt_status(code: &str, transaction_type: &str) -> AttemptStatus {
    match code {
        "00000" => {
            // For authorization-only requests (manual capture), return Authorized
            // For capture/auth+capture requests, return Charged
            match transaction_type {
                AUTH_REQUEST => AttemptStatus::Authorized,  // Type 00001: Authorization only
                CAPTURE_REQUEST | AUTH_AND_CAPTURE_REQUEST => AttemptStatus::Charged,  // Type 00002, 00003
                _ => AttemptStatus::Charged,
            }
        }
        "00001" | "00003" => AttemptStatus::Failure,
        code if code.starts_with("001") => AttemptStatus::Failure,
        _ => AttemptStatus::Failure,
    }
}

fn map_paybox_status_to_refund_status(code: &str) -> RefundStatus {
    match code {
        "00000" => RefundStatus::Success,
        "00001" | "00003" => RefundStatus::Failure,
        code if code.starts_with("001") => RefundStatus::Failure,
        _ => RefundStatus::Failure,
    }
}

// ============================================================================
// AUTHORIZE FLOW
// ============================================================================

#[derive(Debug, Serialize)]
pub struct PayboxPaymentRequest<T> {
    #[serde(rename = "VERSION")]
    pub version: String,
    #[serde(rename = "TYPE")]
    pub request_type: String,
    #[serde(rename = "SITE")]
    pub site: Secret<String>,
    #[serde(rename = "RANG")]
    pub rang: Secret<String>,
    #[serde(rename = "CLE")]
    pub cle: Secret<String>,
    #[serde(rename = "NUMQUESTION")]
    pub numquestion: String,
    #[serde(rename = "MONTANT")]
    pub montant: MinorUnit,
    #[serde(rename = "DEVISE")]
    pub devise: String,
    #[serde(rename = "REFERENCE")]
    pub reference: String,
    #[serde(rename = "DATEQ")]
    pub dateq: String,
    #[serde(rename = "PORTEUR")]
    pub porteur: Secret<String>,
    #[serde(rename = "DATEVAL")]
    pub dateval: Secret<String>,
    #[serde(rename = "CVV")]
    pub cvv: Secret<String>,
    #[serde(rename = "ACTIVITE")]
    pub activite: String,
    // #[serde(rename = "IDENTIFIANT")]
    // pub identifiant: Secret<String>,
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

        let montant = connector
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

        // Paybox expects MMYY format (4 digits)
        // Take last 2 digits of year to handle both "2025" and "25" formats
        let year_last_two = if expiry_year.len() >= 2 {
            &expiry_year[expiry_year.len() - 2..]
        } else {
            expiry_year.as_str()
        };

        let dateval = Secret::new(format!("{}{}", expiry_month, year_last_two));

        // Determine transaction type based on capture method (following Hyperswitch)
        let transaction_type = get_transaction_type(router_data.request.capture_method);

        Ok(Self {
            version: "00104".to_string(),
            request_type: transaction_type.to_string(),
            site: auth.site,
            rang: auth.rang,
            cle: auth.cle,
            numquestion: generate_request_id()?,
            montant,
            devise: get_currency_code(router_data.request.currency)?,
            reference: router_data.resource_common_data.connector_request_reference_id.clone(),
            dateq: generate_date_time(),
            porteur: Secret::new(card.card_number.peek().to_string()),
            dateval,
            cvv: card.card_cvc.clone(),
            activite: "024".to_string(),
            // identifiant: auth.merchant_id,
            _phantom: std::marker::PhantomData,
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PayboxPaymentResponse {
    #[serde(rename = "NUMTRANS")]
    pub numtrans: Option<String>,
    #[serde(rename = "NUMAPPEL")]
    pub numappel: Option<String>,
    #[serde(rename = "NUMQUESTION")]
    pub numquestion: Option<String>,
    #[serde(rename = "SITE")]
    pub site: Option<String>,
    #[serde(rename = "RANG")]
    pub rang: Option<String>,
    #[serde(rename = "AUTORISATION")]
    pub autorisation: Option<String>,
    #[serde(rename = "CODEREPONSE")]
    pub codereponse: String,
    #[serde(rename = "COMMENTAIRE")]
    pub commentaire: Option<String>,
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
        // Determine status based on capture method and response code
        // Match Hyperswitch logic: Manual capture returns Authorized, Auto capture returns Charged
        let is_auto_capture = matches!(
            item.router_data.request.capture_method,
            Some(common_enums::CaptureMethod::Automatic)
        );

        let status = if item.response.codereponse == "00000" {
            // Success response - differentiate based on capture method
            if is_auto_capture {
                AttemptStatus::Charged
            } else {
                AttemptStatus::Authorized
            }
        } else {
            // Error response
            map_paybox_status_to_attempt_status(&item.response.codereponse, AUTH_REQUEST)
        };

        // Store NUMTRANS in connector_metadata for future operations (void, capture, refund)
        // NUMAPPEL is used as the main connector_transaction_id
        // This matches Hyperswitch implementation exactly
        let connector_metadata = item.response.numtrans.as_ref().map(|numtrans| {
            serde_json::json!({
                "connector_request_id": numtrans
            })
        });

        let connector_transaction_id = item
            .response
            .numappel
            .or(item.response.numtrans.clone())
            .unwrap_or_default();

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
    pub request_type: String,
    #[serde(rename = "SITE")]
    pub site: Secret<String>,
    #[serde(rename = "RANG")]
    pub rang: Secret<String>,
    #[serde(rename = "CLE")]
    pub cle: Secret<String>,
    #[serde(rename = "NUMQUESTION")]
    pub numquestion: String,
    #[serde(rename = "DATEQ")]
    pub dateq: String,
    #[serde(rename = "NUMTRANS")]
    pub numtrans: String,
    #[serde(rename = "NUMAPPEL")]
    pub numappel: String,
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

        // NUMAPPEL is the connector_transaction_id
        let numappel = match &router_data.request.connector_transaction_id {
            ResponseId::ConnectorTransactionId(id) => id.clone(),
            _ => return Err(errors::ConnectorError::MissingConnectorTransactionID.into()),
        };

        // Extract NUMTRANS from connector_metadata stored during authorization
        let numtrans = router_data
            .resource_common_data
            .connector_meta_data
            .as_ref()
            .and_then(|metadata| metadata.peek().get("connector_request_id"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| numappel.clone());

        Ok(Self {
            version: "00104".to_string(),
            request_type: SYNC_REQUEST.to_string(),
            site: auth.site,
            rang: auth.rang,
            cle: auth.cle,
            numquestion: generate_request_id()?,
            dateq: generate_date_time(),
            numtrans,
            numappel,
        })
    }
}

// PayboxPSyncResponse has a STATUS field unlike other payment responses
#[derive(Debug, Deserialize, Serialize)]
pub struct PayboxPSyncResponse {
    #[serde(rename = "NUMTRANS")]
    pub numtrans: Option<String>,
    #[serde(rename = "NUMAPPEL")]
    pub numappel: Option<String>,
    #[serde(rename = "NUMQUESTION")]
    pub numquestion: Option<String>,
    #[serde(rename = "SITE")]
    pub site: Option<String>,
    #[serde(rename = "RANG")]
    pub rang: Option<String>,
    #[serde(rename = "AUTORISATION")]
    pub autorisation: Option<String>,
    #[serde(rename = "CODEREPONSE")]
    pub codereponse: String,
    #[serde(rename = "COMMENTAIRE")]
    pub commentaire: Option<String>,
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
        // Convert PayboxStatus directly to AttemptStatus (matching Hyperswitch)
        let connector_payment_status = item.response.status;
        let status = AttemptStatus::from(connector_payment_status);

        let connector_transaction_id = item
            .response
            .numtrans
            .or(item.response.numappel)
            .unwrap_or_default();

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
    pub request_type: String,
    #[serde(rename = "SITE")]
    pub site: Secret<String>,
    #[serde(rename = "RANG")]
    pub rang: Secret<String>,
    #[serde(rename = "CLE")]
    pub cle: Secret<String>,
    #[serde(rename = "NUMQUESTION")]
    pub numquestion: String,
    #[serde(rename = "MONTANT")]
    pub montant: MinorUnit,
    #[serde(rename = "DEVISE")]
    pub devise: String,
    #[serde(rename = "REFERENCE")]
    pub reference: String,
    #[serde(rename = "DATEQ")]
    pub dateq: String,
    #[serde(rename = "NUMTRANS")]
    pub numtrans: String,
    #[serde(rename = "NUMAPPEL")]
    pub numappel: String,
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

        // NUMAPPEL is the connector_transaction_id
        let numappel = match &router_data.request.connector_transaction_id {
            ResponseId::ConnectorTransactionId(id) => id.clone(),
            _ => return Err(errors::ConnectorError::MissingConnectorTransactionID.into()),
        };

        // Extract NUMTRANS from connector_metadata stored during authorization
        let numtrans = router_data
            .request
            .connector_metadata
            .as_ref()
            .and_then(|metadata| metadata.get("connector_request_id"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| numappel.clone());

        let montant = connector
            .amount_converter
            .convert(
                router_data.request.minor_amount_to_capture,
                router_data.request.currency,
            )
            .change_context(errors::ConnectorError::ParsingFailed)?;

        Ok(Self {
            version: "00104".to_string(),
            request_type: CAPTURE_REQUEST.to_string(),
            site: auth.site,
            rang: auth.rang,
            cle: auth.cle,
            numquestion: generate_request_id()?,
            montant,
            devise: get_currency_code(router_data.request.currency)?,
            reference: router_data.resource_common_data.connector_request_reference_id.clone(),
            dateq: generate_date_time(),
            numtrans,
            numappel,
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
        // Capture always uses CAPTURE_REQUEST type
        let status = map_paybox_status_to_attempt_status(&item.response.codereponse, CAPTURE_REQUEST);
        let connector_transaction_id = item
            .response
            .numtrans
            .or(item.response.numappel)
            .unwrap_or_default();

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
// VOID FLOW
// ============================================================================

#[derive(Debug, Serialize)]
pub struct PayboxVoidRequest {
    #[serde(rename = "VERSION")]
    pub version: String,
    #[serde(rename = "TYPE")]
    pub request_type: String,
    #[serde(rename = "SITE")]
    pub site: Secret<String>,
    #[serde(rename = "RANG")]
    pub rang: Secret<String>,
    #[serde(rename = "CLE")]
    pub cle: Secret<String>,
    #[serde(rename = "NUMQUESTION")]
    pub numquestion: String,
    #[serde(rename = "MONTANT")]
    pub montant: MinorUnit,
    #[serde(rename = "DEVISE")]
    pub devise: String,
    #[serde(rename = "REFERENCE")]
    pub reference: String,
    #[serde(rename = "DATEQ")]
    pub dateq: String,
    #[serde(rename = "NUMTRANS")]
    pub numtrans: String,
    #[serde(rename = "NUMAPPEL")]
    pub numappel: String,
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

        // NUMAPPEL is the connector_transaction_id
        let numappel = router_data.request.connector_transaction_id.clone();

        // Extract NUMTRANS from connector_metadata stored during authorization
        let numtrans = router_data
            .request
            .connector_metadata
            .as_ref()
            .and_then(|metadata| metadata.peek().get("connector_request_id"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
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

        let montant = connector
            .amount_converter
            .convert(amount, currency)
            .change_context(errors::ConnectorError::ParsingFailed)?;

        Ok(Self {
            version: "00104".to_string(),
            request_type: CANCEL_REQUEST.to_string(),
            site: auth.site,
            rang: auth.rang,
            cle: auth.cle,
            numquestion: generate_request_id()?,
            montant,
            devise: get_currency_code(currency)?,
            reference: router_data.resource_common_data.connector_request_reference_id.clone(),
            dateq: generate_date_time(),
            numtrans,
            numappel,
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
        let status = if item.response.codereponse == "00000" {
            AttemptStatus::Voided
        } else {
            AttemptStatus::VoidFailed
        };

        let connector_transaction_id = item
            .response
            .numtrans
            .or(item.response.numappel)
            .unwrap_or_default();

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
// REFUND FLOW
// ============================================================================

#[derive(Debug, Serialize)]
pub struct PayboxRefundRequest {
    #[serde(rename = "VERSION")]
    pub version: String,
    #[serde(rename = "TYPE")]
    pub request_type: String,
    #[serde(rename = "SITE")]
    pub site: Secret<String>,
    #[serde(rename = "RANG")]
    pub rang: Secret<String>,
    #[serde(rename = "CLE")]
    pub cle: Secret<String>,
    #[serde(rename = "NUMQUESTION")]
    pub numquestion: String,
    #[serde(rename = "MONTANT")]
    pub montant: MinorUnit,
    #[serde(rename = "DEVISE")]
    pub devise: String,
    #[serde(rename = "REFERENCE")]
    pub reference: String,
    #[serde(rename = "DATEQ")]
    pub dateq: String,
    #[serde(rename = "NUMTRANS")]
    pub numtrans: String,
    #[serde(rename = "NUMAPPEL")]
    pub numappel: String,
    #[serde(rename = "ACTIVITE")]
    pub activite: String,
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

        // NUMAPPEL is the connector_transaction_id
        let numappel = router_data
            .request
            .connector_transaction_id
            .clone();

        // Extract NUMTRANS from connector_metadata stored during authorization
        let numtrans = router_data
            .request
            .connector_metadata
            .as_ref()
            .and_then(|metadata| metadata.get("connector_request_id"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| numappel.clone());

        let amount = connector
            .amount_converter
            .convert(router_data.request.minor_refund_amount, router_data.request.currency)
            .change_context(errors::ConnectorError::ParsingFailed)?;

        let montant = amount;

        Ok(Self {
            version: "00104".to_string(),
            request_type: REFUND_REQUEST.to_string(),
            site: auth.site,
            rang: auth.rang,
            cle: auth.cle,
            numquestion: generate_request_id()?,
            montant,
            devise: get_currency_code(router_data.request.currency)?,
            reference: router_data.resource_common_data.connector_request_reference_id.clone(),
            dateq: generate_date_time(),
            numtrans,
            numappel,
            activite: "024".to_string(),
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PayboxRefundResponse {
    #[serde(rename = "NUMTRANS")]
    pub numtrans: Option<String>,
    #[serde(rename = "NUMAPPEL")]
    pub numappel: Option<String>,
    #[serde(rename = "NUMQUESTION")]
    pub numquestion: Option<String>,
    #[serde(rename = "SITE")]
    pub site: Option<String>,
    #[serde(rename = "RANG")]
    pub rang: Option<String>,
    #[serde(rename = "AUTORISATION")]
    pub autorisation: Option<String>,
    #[serde(rename = "CODEREPONSE")]
    pub codereponse: String,
    #[serde(rename = "COMMENTAIRE")]
    pub commentaire: Option<String>,
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
        // For refund execute, always return Pending on success (matching Hyperswitch)
        // The actual status is determined by refund sync
        let refund_status = if item.response.codereponse == "00000" {
            RefundStatus::Pending
        } else {
            map_paybox_status_to_refund_status(&item.response.codereponse)
        };

        let connector_refund_id = item
            .response
            .numtrans
            .or(item.response.numappel)
            .unwrap_or_default();

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
// RSYNC FLOW
// ============================================================================

#[derive(Debug, Serialize)]
pub struct PayboxRefundSyncRequest {
    #[serde(rename = "VERSION")]
    pub version: String,
    #[serde(rename = "TYPE")]
    pub request_type: String,
    #[serde(rename = "SITE")]
    pub site: Secret<String>,
    #[serde(rename = "RANG")]
    pub rang: Secret<String>,
    #[serde(rename = "CLE")]
    pub cle: Secret<String>,
    #[serde(rename = "NUMQUESTION")]
    pub numquestion: String,
    #[serde(rename = "DATEQ")]
    pub dateq: String,
    #[serde(rename = "NUMTRANS")]
    pub numtrans: String,
    #[serde(rename = "NUMAPPEL")]
    pub numappel: String,
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
            version: "00104".to_string(),
            request_type: SYNC_REQUEST.to_string(),
            site: auth.site,
            rang: auth.rang,
            cle: auth.cle,
            numquestion: generate_request_id()?,
            dateq: generate_date_time(),
            numtrans: connector_refund_id.clone(),
            numappel: connector_refund_id,
        })
    }
}

// PayboxRSyncResponse has a STATUS field for inquiry responses (TYPE=00017)
#[derive(Debug, Deserialize, Serialize)]
pub struct PayboxRSyncResponse {
    #[serde(rename = "NUMTRANS")]
    pub numtrans: Option<String>,
    #[serde(rename = "NUMAPPEL")]
    pub numappel: Option<String>,
    #[serde(rename = "NUMQUESTION")]
    pub numquestion: Option<String>,
    #[serde(rename = "SITE")]
    pub site: Option<String>,
    #[serde(rename = "RANG")]
    pub rang: Option<String>,
    #[serde(rename = "AUTORISATION")]
    pub autorisation: Option<String>,
    #[serde(rename = "CODEREPONSE")]
    pub codereponse: String,
    #[serde(rename = "COMMENTAIRE")]
    pub commentaire: Option<String>,
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
        // Convert PayboxStatus directly to RefundStatus (matching Hyperswitch)
        let connector_refund_status = item.response.status;
        let refund_status = RefundStatus::from(connector_refund_status);

        let connector_refund_id = item
            .response
            .numtrans
            .or(item.response.numappel)
            .unwrap_or_default();

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
    pub numtrans: Option<String>,
}
