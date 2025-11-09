use bytes::Bytes;
use common_enums::{
    self, AttemptStatus, CaptureMethod, Currency, FutureUsage,
};
use common_utils::{consts,
    CustomResult,
    date_time, ext_traits::Encode,
    types::MinorUnit,
};
use domain_types::{
    payment_address::AddressDetails,
    connector_flow::Authorize,
    connector_types::{
        PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData,
        PaymentsSyncData,ResponseId,
    },
    errors::{self, ConnectorError},
    payment_method_data::{
        Card, PaymentMethodData, PaymentMethodDataTypes, RawCardNumber,
    },
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_request_types::AuthenticationData,
    utils::CardIssuer,
};
use error_stack::{ report};
use hyperswitch_masking::{Secret};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    types::ResponseRouterData,
    utils::{
        self,
    },
};

use super::ArchipelRouterData;

const THREE_DS_MAX_SUPPORTED_VERSION: &str = "2.2.0";

#[derive(Debug, Deserialize, Serialize, Eq, PartialEq, Clone)]
#[serde(transparent)]
pub struct ArchipelTenantId(pub String);

impl From<String> for ArchipelTenantId {
    fn from(value: String) -> Self {
        Self(value)
    }
}

pub struct ArchipelAuthType {
    pub(super) ca_certificate: Option<Secret<String>>,
}

impl TryFrom<&ConnectorAuthType> for ArchipelAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::HeaderKey { api_key } => Ok(Self {
                ca_certificate: Some(api_key.to_owned()),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct ArchipelConfigData {
    pub tenant_id: ArchipelTenantId,
    pub platform_url: String,
}

impl TryFrom<&Option<Value>> for ArchipelConfigData {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(connector_metadata: &Option<Value>) -> Result<Self, Self::Error> {
        let config_data = to_connector_meta(connector_metadata.clone())?;
        Ok(config_data)
    }
}

fn to_connector_meta(
    connector_meta: Option<Value>,
) -> CustomResult<ArchipelConfigData, ConnectorError> {
    print!("this is the meta data{:?}",connector_meta);
    let meta_obj = connector_meta
        .ok_or_else(|| ConnectorError::NoConnectorMetaData)?;

    // Extract the inner string first
    let connector_meta_str = meta_obj
        .get("connector_meta_data")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ConnectorError::InvalidDataFormat { field_name: "connector_meta_data" })?;
    print!("this is the connector_meta_str{:?}",connector_meta_str);

    // Now parse that string as JSON
    let inner_json: Value = serde_json::from_str(connector_meta_str)
        .map_err(|_| report!(ConnectorError::InvalidDataFormat { field_name: "connector_meta_data inner json" }))?;

    // Finally, deserialize into your target struct
    let config_data: ArchipelConfigData = serde_json::from_value(inner_json)
        .map_err(|_| report!(ConnectorError::InvalidDataFormat { field_name: "ArchipelConfigData" }))?;

    Ok(config_data)
}

#[derive(Debug, Default, Serialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "UPPERCASE")]
pub enum ArchipelPaymentInitiator {
    #[default]
    Customer,
    Merchant,
}

#[derive(Debug, Default, Serialize, Eq, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum ArchipelPaymentCertainty {
    #[default]
    Final,
    Estimated,
}

#[derive(Debug, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ArchipelOrderRequest {
    amount: MinorUnit,
    currency: String,
    certainty: ArchipelPaymentCertainty,
    initiator: ArchipelPaymentInitiator,
}

#[derive(Debug, Serialize, Eq, PartialEq, Clone)]
pub struct CardExpiryDate {
    month: Secret<String>,
    year: Secret<String>,
}

#[derive(Debug, Serialize, Default, Eq, PartialEq, Clone)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ApplicationSelectionIndicator {
    #[default]
    ByDefault,
    CustomerChoice,
}

#[derive(Debug, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Archipel3DS {
    #[serde(rename = "acsTransID")]
    acs_trans_id: Option<Secret<String>>,
    #[serde(rename = "dsTransID")]
    ds_trans_id: Option<Secret<String>>,
    #[serde(rename = "3DSRequestorName")]
    three_ds_requestor_name: Option<Secret<String>>,
    #[serde(rename = "3DSAuthDate")]
    three_ds_auth_date: Option<String>,
    #[serde(rename = "3DSAuthAmt")]
    three_ds_auth_amt: Option<MinorUnit>,
    #[serde(rename = "3DSAuthStatus")]
    three_ds_auth_status: Option<String>,
    #[serde(rename = "3DSMaxSupportedVersion")]
    three_ds_max_supported_version: String,
    #[serde(rename = "3DSVersion")]
    three_ds_version: Option<common_utils::types::SemanticVersion>,
    authentication_value: Secret<String>,
    authentication_method: Option<Secret<String>>,
    eci: Option<String>,
}

impl From<AuthenticationData> for Archipel3DS {
    fn from(three_ds_data: AuthenticationData) -> Self {
        let now = date_time::date_as_yyyymmddthhmmssmmmz().ok();
        Self {
            acs_trans_id: None,
            ds_trans_id: three_ds_data.ds_trans_id.map(Secret::new),
            three_ds_requestor_name: None,
            three_ds_auth_date: now,
            three_ds_auth_amt: None,
            three_ds_auth_status: None,
            three_ds_max_supported_version: THREE_DS_MAX_SUPPORTED_VERSION.into(),
            three_ds_version: three_ds_data.message_version,
            authentication_value: three_ds_data.cavv,
            authentication_method: None,
            eci: three_ds_data.eci,
        }
    }
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ArchipelCardHolder {
    billing_address: Option<ArchipelBillingAddress>,
}

impl From<Option<ArchipelBillingAddress>> for ArchipelCardHolder {
    fn from(value: Option<ArchipelBillingAddress>) -> Self {
        Self {
            billing_address: value,
        }
    }
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ArchipelBillingAddress {
    address: Option<Secret<String>>,
    postal_code: Option<Secret<String>>,
}

pub trait ToArchipelBillingAddress {
    fn to_archipel_billing_address(&self) -> Option<ArchipelBillingAddress>;
}

impl ToArchipelBillingAddress for AddressDetails {
    fn to_archipel_billing_address(&self) -> Option<ArchipelBillingAddress> {
        let address = self.get_combined_address_line().ok();
        let postal_code = self.get_optional_zip();

        match (address, postal_code) {
            (None, None) => None,
            (addr, zip) => Some(ArchipelBillingAddress {
                address: addr,
                postal_code: zip,
            }),
        }
    }
}

#[derive(Debug, Serialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "UPPERCASE")]
pub enum ArchipelCredentialIndicatorStatus {
    Initial,
    Subsequent,
}

#[derive(Debug, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ArchipelCredentialIndicator {
    status: ArchipelCredentialIndicatorStatus,
    recurring: Option<bool>,
    transaction_id: Option<String>,
}

#[derive(Debug, Serialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TokenizedCardData<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    card_data: ArchipelTokenizedCard<T>,
}

#[derive(Debug, Serialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ArchipelTokenizedCard<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    number: RawCardNumber<T>,
    expiry: CardExpiryDate,
    scheme: ArchipelCardScheme,
}

#[derive(Debug, Serialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ArchipelCard<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    number: RawCardNumber<T>,
    expiry: CardExpiryDate,
    security_code: Option<Secret<String>>,
    card_holder_name: Option<Secret<String>>,
    application_selection_indicator: ApplicationSelectionIndicator,
    scheme: ArchipelCardScheme,
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static
  + Serialize>
      TryFrom<(Option<Secret<String>>, Option<ArchipelCardHolder>, &Card<T>)>
      for ArchipelCard<T> {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        (card_holder_name, card_holder_billing, ccard): (
            Option<Secret<String>>,
            Option<ArchipelCardHolder>,
            &Card<T>,
        ),
    ) -> Result<Self, Self::Error> {
        // NOTE: Archipel does not accept `card.card_holder_name` field without `cardholder` field.
        // So if `card_holder` is None, `card.card_holder_name` must also be None.
        // However, the reverse is allowed — the `cardholder` field can exist without `card.card_holder_name`.
        let card_holder_name = card_holder_billing
            .as_ref()
            .and_then(|_| ccard.card_holder_name.clone().or(card_holder_name.clone()));

        let raw_card = serde_json::to_string(&ccard.card_number.0)
                    .unwrap_or_default()
                    .trim_matches('"')
                    .to_string();
        let card_issuer = domain_types::utils::get_card_issuer(&raw_card).ok();
        let scheme = ArchipelCardScheme::from(card_issuer);
        
        Ok(Self {
            number: ccard.card_number.clone(),
            expiry: CardExpiryDate {
                month: ccard.card_exp_month.clone(),
                year: ccard.get_card_expiry_year_2_digit()?,
            },
            security_code: Some(ccard.card_cvc.clone()),
            application_selection_indicator: ApplicationSelectionIndicator::ByDefault,
            card_holder_name,
            scheme,
        })
    }
}

#[derive(Debug, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ArchipelPaymentInformation {
    order: ArchipelOrderRequest,
    cardholder: Option<ArchipelCardHolder>,
    card_holder_name: Option<Secret<String>>,
    credential_indicator: Option<ArchipelCredentialIndicator>,
    stored_on_file: bool,
}

#[derive(Debug, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ArchipelCardAuthorizationRequest<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    order: ArchipelOrderRequest,
    card: ArchipelCard<T>,
    cardholder: Option<ArchipelCardHolder>,
    #[serde(rename = "3DS")]
    three_ds: Option<Archipel3DS>,
    credential_indicator: Option<ArchipelCredentialIndicator>,
    stored_on_file: bool,
    tenant_id: ArchipelTenantId,
}

// PaymentsResponse

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum ArchipelCardScheme {
    Amex,
    Mastercard,
    Visa,
    Discover,
    Diners,
    Unknown,
}

impl From<Option<CardIssuer>> for ArchipelCardScheme {
    fn from(card_issuer: Option<CardIssuer>) -> Self {
        match card_issuer {
            Some(CardIssuer::Visa) => Self::Visa,
            Some(CardIssuer::Master | CardIssuer::Maestro) => Self::Mastercard,
            Some(CardIssuer::AmericanExpress) => Self::Amex,
            Some(CardIssuer::Discover) => Self::Discover,
            Some(CardIssuer::DinersClub) => Self::Diners,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ArchipelPaymentStatus {
    #[default]
    Succeeded,
    Failed,
}

impl TryFrom<(AttemptStatus, CaptureMethod)> for ArchipelPaymentFlow {
    type Error = errors::ConnectorError;

    fn try_from(
        (status, capture_method): (AttemptStatus, CaptureMethod),
    ) -> Result<Self, Self::Error> {
        let is_auto_capture = matches!(capture_method, CaptureMethod::Automatic);

        match status {
            AttemptStatus::AuthenticationFailed => Ok(Self::Verify),
            AttemptStatus::Authorizing
            | AttemptStatus::Authorized
            | AttemptStatus::AuthorizationFailed => Ok(Self::Authorize),
            AttemptStatus::Voided | AttemptStatus::VoidInitiated | AttemptStatus::VoidFailed => {
                Ok(Self::Cancel)
            }
            AttemptStatus::CaptureInitiated | AttemptStatus::CaptureFailed => {
                if is_auto_capture {
                    Ok(Self::Pay)
                } else {
                    Ok(Self::Capture)
                }
            }
            AttemptStatus::PaymentMethodAwaited | AttemptStatus::ConfirmationAwaited => {
                if is_auto_capture {
                    Ok(Self::Pay)
                } else {
                    Ok(Self::Authorize)
                }
            }
            _ => Err(errors::ConnectorError::ProcessingStepFailed(Some(
                Bytes::from_static(
                    "Impossible to determine Archipel flow from AttemptStatus".as_bytes(),
                ),
            ))),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ArchipelPaymentFlow {
    Verify,
    Authorize,
    Pay,
    Capture,
    Cancel,
}

struct ArchipelFlowStatus {
    status: ArchipelPaymentStatus,
    flow: ArchipelPaymentFlow,
}
impl ArchipelFlowStatus {
    fn new(status: ArchipelPaymentStatus, flow: ArchipelPaymentFlow) -> Self {
        Self { status, flow }
    }
}

impl From<ArchipelFlowStatus> for AttemptStatus {
    fn from(ArchipelFlowStatus { status, flow }: ArchipelFlowStatus) -> Self {
        match status {
            ArchipelPaymentStatus::Succeeded => match flow {
                ArchipelPaymentFlow::Authorize => Self::Authorized,
                ArchipelPaymentFlow::Pay
                | ArchipelPaymentFlow::Verify
                | ArchipelPaymentFlow::Capture => Self::Charged,
                ArchipelPaymentFlow::Cancel => Self::Voided,
            },
            ArchipelPaymentStatus::Failed => match flow {
                ArchipelPaymentFlow::Authorize | ArchipelPaymentFlow::Pay => {
                    Self::AuthorizationFailed
                }
                ArchipelPaymentFlow::Verify => Self::AuthenticationFailed,
                ArchipelPaymentFlow::Capture => Self::CaptureFailed,
                ArchipelPaymentFlow::Cancel => Self::VoidFailed,
            },
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ArchipelOrderResponse {
    id: String,
    amount: Option<i64>,
    currency: Option<Currency>,
    captured_amount: Option<i64>,
    authorized_amount: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ArchipelErrorMessage {
    pub code: String,
    pub description: Option<String>,
}

impl Default for ArchipelErrorMessage {
    fn default() -> Self {
        Self {
            code: consts::NO_ERROR_CODE.to_string(),
            description: Some(consts::NO_ERROR_MESSAGE.to_string()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct ArchipelErrorMessageWithHttpCode {
    error_message: ArchipelErrorMessage,
    http_code: u16,
}
impl ArchipelErrorMessageWithHttpCode {
    fn new(error_message: ArchipelErrorMessage, http_code: u16) -> Self {
        Self {
            error_message,
            http_code,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct ArchipelTransactionMetadata {
    #[serde(alias = "transaction_id")]
    pub transaction_id: String,
    #[serde(alias = "transaction_date")]
    pub transaction_date: String,
    #[serde(alias = "financial_network_code")]
    pub financial_network_code: Option<String>,
    #[serde(alias = "issuer_transaction_id")]
    pub issuer_transaction_id: Option<String>,
    #[serde(alias = "response_code")]
    pub response_code: Option<String>,
    #[serde(alias = "authorization_code")]
    pub authorization_code: Option<String>,
    #[serde(alias = "payment_account_reference")]
    pub payment_account_reference: Option<Secret<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ArchipelPaymentsResponse {
    order: ArchipelOrderResponse,
    transaction_id: String,
    transaction_date: String,
    transaction_result: ArchipelPaymentStatus,
    error: Option<ArchipelErrorMessage>,
    financial_network_code: Option<String>,
    issuer_transaction_id: Option<String>,
    response_code: Option<String>,
    authorization_code: Option<String>,
    payment_account_reference: Option<Secret<String>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(transparent)]
pub struct ArchipelPSyncResponse(ArchipelPaymentsResponse);

impl std::ops::Deref for ArchipelPSyncResponse {
    type Target = ArchipelPaymentsResponse;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<&ArchipelPaymentsResponse> for ArchipelTransactionMetadata {
    fn from(payment_response: &ArchipelPaymentsResponse) -> Self {
        Self {
            transaction_id: payment_response.transaction_id.clone(),
            transaction_date: payment_response.transaction_date.clone(),
            financial_network_code: payment_response.financial_network_code.clone(),
            issuer_transaction_id: payment_response.issuer_transaction_id.clone(),
            response_code: payment_response.response_code.clone(),
            authorization_code: payment_response.authorization_code.clone(),
            payment_account_reference: payment_response.payment_account_reference.clone(),
        }
    }
}

// AUTHORIZATION FLOW
impl<T: PaymentMethodDataTypes> TryFrom<(
    MinorUnit,
    &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
)> for ArchipelPaymentInformation {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        (amount, router_data): (
            MinorUnit,
            &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
    ) -> Result<Self, Self::Error> {

        let is_recurring_payment = router_data
            .request
            .mandate_id
            .as_ref()
            .and_then(|mandate_ids| mandate_ids.mandate_id.as_ref())
            .is_some();

        let is_subsequent_trx = router_data
            .request
            .mandate_id
            .as_ref()
            .and_then(|mandate_ids| mandate_ids.mandate_reference_id.as_ref())
            .is_some();

        let is_saved_card_payment = (router_data.request.is_mandate_payment())
            | (router_data.request.setup_future_usage == Some(FutureUsage::OnSession));

        let certainty = if router_data.request.request_incremental_authorization {
            if is_recurring_payment {
                ArchipelPaymentCertainty::Final
            } else {
                ArchipelPaymentCertainty::Estimated
            }
        } else {
            ArchipelPaymentCertainty::Final
        };

        let transaction_initiator = if is_recurring_payment {
            ArchipelPaymentInitiator::Merchant
        } else {
            ArchipelPaymentInitiator::Customer
        };

        let order = ArchipelOrderRequest {
            amount,
            currency: router_data.request.currency.to_string(),
            certainty,
            initiator: transaction_initiator.clone(),
        };

        let cardholder = router_data
            .resource_common_data
            .get_billing_address()
            .ok()
            .and_then(|address| address.to_archipel_billing_address())
            .map(|billing_address| ArchipelCardHolder {
                billing_address: Some(billing_address),
            });

        // NOTE: Archipel does not accept `card.card_holder_name` field without `cardholder` field.
        // So if `card_holder` is None, `card.card_holder_name` must also be None.
        // However, the reverse is allowed — the `cardholder` field can exist without `card.card_holder_name`.
        let card_holder_name = cardholder.as_ref().and_then(|_| {
            router_data
                .resource_common_data
                .get_billing()
                .ok()
                .and_then(|billing| billing.get_optional_full_name())
        });

        let indicator_status = if is_subsequent_trx {
            ArchipelCredentialIndicatorStatus::Subsequent
        } else {
            ArchipelCredentialIndicatorStatus::Initial
        };

        let stored_on_file =
            is_saved_card_payment | router_data.request.is_customer_initiated_mandate_payment();

        let credential_indicator = stored_on_file.then(|| ArchipelCredentialIndicator {
            status: indicator_status.clone(),
            recurring: Some(is_recurring_payment),
            transaction_id: match indicator_status {
                ArchipelCredentialIndicatorStatus::Initial => None,
                ArchipelCredentialIndicatorStatus::Subsequent => {
                    router_data.request.get_optional_network_transaction_id()
                }
            },
        });

        Ok(Self {
            order,
            cardholder,
            card_holder_name,
            credential_indicator,
            stored_on_file,
        })
    }
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
        ArchipelRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for ArchipelCardAuthorizationRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ArchipelRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let payment_information: ArchipelPaymentInformation =
            ArchipelPaymentInformation::try_from((MinorUnit::new(item.router_data.request.amount), &item.router_data))?;
        let payment_method_data = match &item.router_data.request.payment_method_data {
            PaymentMethodData::Card(ccard) => ArchipelCard::try_from((
                payment_information.card_holder_name,
                payment_information.cardholder.clone(),
                ccard,
            ))?,
            PaymentMethodData::CardDetailsForNetworkTransactionId(..) 
            | PaymentMethodData::CardRedirect(..)
            | PaymentMethodData::Wallet(..)
            | PaymentMethodData::PayLater(..)
            | PaymentMethodData::BankRedirect(..)
            | PaymentMethodData::BankDebit(..)
            | PaymentMethodData::BankTransfer(..)
            | PaymentMethodData::Crypto(..)
            | PaymentMethodData::MandatePayment
            | PaymentMethodData::Reward
            | PaymentMethodData::RealTimePayment(..)
            | PaymentMethodData::Upi(..)
            | PaymentMethodData::Voucher(..)
            | PaymentMethodData::GiftCard(..)
            | PaymentMethodData::CardToken(..)
            | PaymentMethodData::OpenBanking(..)
            | PaymentMethodData::NetworkToken(..)
            | PaymentMethodData::MobilePayment(..) => Err(errors::ConnectorError::NotImplemented(
                utils::get_unimplemented_payment_method_error_message("Archipel"),
            ))?,
        };
        let three_ds: Option<Archipel3DS> = None;

        let connector_metadata = ArchipelConfigData::try_from(&item.router_data.request.metadata)?;

        Ok(Self {
            order: payment_information.order,
            cardholder: payment_information.cardholder,
            card: payment_method_data,
            three_ds,
            credential_indicator: payment_information.credential_indicator,
            stored_on_file: payment_information.stored_on_file,
            tenant_id: connector_metadata.tenant_id,
        })
    }
}

// Responses for AUTHORIZATION FLOW
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        ResponseRouterData<
            ArchipelPaymentsResponse,
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
            ArchipelPaymentsResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        if let Some(error) = item.response.error {
            return Ok(Self {
                response: Err(ArchipelErrorMessageWithHttpCode::new(error, item.http_code).into()),
                ..item.router_data
            });
        };

        let capture_method = item
            .router_data
            .request
            .capture_method
            .ok_or_else(|| errors::ConnectorError::CaptureMethodNotSupported)?;

        let (archipel_flow, is_incremental_allowed) = match capture_method {
            CaptureMethod::Automatic => (ArchipelPaymentFlow::Pay, false),
            _ => (
                ArchipelPaymentFlow::Authorize,
                item.router_data.request.request_incremental_authorization,
            ),
        };

        let connector_metadata: Option<serde_json::Value> =
            ArchipelTransactionMetadata::from(&item.response)
                .encode_to_value()
                .ok();

        let status: AttemptStatus =
            ArchipelFlowStatus::new(item.response.transaction_result, archipel_flow).into();

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.order.id),
                status_code: item.http_code,
                redirection_data: None,
                mandate_reference: None,
                connector_metadata,
                // Save archipel initial transaction uuid for network transaction mit/cit
                network_txn_id: item
                    .router_data
                    .request
                    .is_customer_initiated_mandate_payment()
                    .then_some(item.response.transaction_id),
                connector_response_reference_id: None,
                incremental_authorization_allowed: Some(is_incremental_allowed),
            }),
            ..item.router_data
        })
    }
}

// PSYNC FLOW
impl<F> TryFrom<ResponseRouterData<ArchipelPSyncResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<ArchipelPSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        if let Some(error) = item.response.0.error {
            return Ok(Self {
                response: Err(ArchipelErrorMessageWithHttpCode::new(error, item.http_code).into()),
                ..item.router_data
            });
        };

        let connector_metadata: Option<serde_json::Value> =
            ArchipelTransactionMetadata::from(&item.response.0)
                .encode_to_value()
                .ok();


        let capture_method = item
        .router_data
        .request
        .capture_method
        .ok_or(errors::ConnectorError::MissingRequiredField {
                    field_name: "capture_method",
                })?;

        let archipel_flow = match capture_method {
            CaptureMethod::Automatic => ArchipelPaymentFlow::Pay,
            _ => ArchipelPaymentFlow::Authorize,
        };

        let status: AttemptStatus =
            ArchipelFlowStatus::new(item.response.0.transaction_result.clone(), archipel_flow).into();

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.0.order.id.clone()),
                status_code: item.http_code,
                redirection_data: None,
                mandate_reference: None,
                connector_metadata,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
            }),
            ..item.router_data
        })
    }
}

impl From<ArchipelErrorMessageWithHttpCode> for ErrorResponse {
    fn from(
        ArchipelErrorMessageWithHttpCode {
            error_message,
            http_code,
        }: ArchipelErrorMessageWithHttpCode,
    ) -> Self {
        Self {
            status_code: http_code,
            code: error_message.code,
            attempt_status: None,
            connector_transaction_id: None,
            message: error_message
                .description
                .clone()
                .unwrap_or(consts::NO_ERROR_MESSAGE.to_string()),
            reason: error_message.description,
            network_decline_code: None,
            network_advice_code: None,
            network_error_message: None,
        }
    }
}