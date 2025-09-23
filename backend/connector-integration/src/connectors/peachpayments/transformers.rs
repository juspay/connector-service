use crate::utils;
use common_utils::{
    consts::{NO_ERROR_CODE, NO_ERROR_MESSAGE},
    pii,
    types::MinorUnit,
};
use domain_types::{
    connector_flow::{Authorize, Capture, PSync, Void},
    connector_types::{
        PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData,
        PaymentsResponseData, PaymentsSyncData, ResponseId,
    },
    errors::{self, ConnectorError},
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes, RawCardNumber},
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
};
use error_stack::ResultExt;
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use time::OffsetDateTime;

use super::PeachpaymentsRouterData;
use crate::types::ResponseRouterData;

impl TryFrom<&Option<pii::SecretSerdeValue>> for PeachPaymentsConnectorMetadataObject {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(meta_data: &Option<pii::SecretSerdeValue>) -> Result<Self, Self::Error> {
        let metadata = utils::to_connector_meta_from_secret::<Self>(meta_data.clone())
            .change_context(errors::ConnectorError::InvalidConnectorConfig {
                config: "metadata",
            })?;
        Ok(metadata)
    }
}

// Card Gateway API Transaction Request
#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PeachpaymentsPaymentsRequest<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    pub charge_method: String,
    pub reference_id: String,
    pub ecommerce_card_payment_only_transaction_data: EcommerceCardPaymentOnlyTransactionData<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pos_data: Option<serde_json::Value>,
    pub send_date_time: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde[rename_all = "camelCase"]]
pub struct EcommerceCardPaymentOnlyTransactionData<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    pub merchant_information: MerchantInformation,
    pub routing: Routing,
    pub card: CardDetails<T>,
    pub amount: AmountDetails,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MerchantInformation {
    pub client_merchant_reference_id: Secret<String>,
    pub name: Secret<String>,
    pub mcc: Secret<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<pii::Email>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mobile: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub postal_code: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region_code: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merchant_type: Option<MerchantType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub website_url: Option<url::Url>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum MerchantType {
    Standard,
    Sub,
    Iso,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Routing {
    pub route: Route,
    pub mid: Secret<String>,
    pub tid: Secret<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub visa_payment_facilitator_id: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub master_card_payment_facilitator_id: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub_mid: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amex_id: Option<Secret<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
pub enum Route {
    #[default]
    ExipayEmulator,
    AbsaBase24,
    NedbankPostbridge,
    AbsaPostbridgeEcentric,
    PostbridgeDirecttransact,
    PostbridgeEfficacy,
    FiservLloyds,
    NfsIzwe,
    AbsaHpsZambia,
    EcentricEcommerce,
    UnitTestEmptyConfig,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CardDetails<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    pub pan: RawCardNumber<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cardholder_name: Option<Secret<String>>,
    pub expiry_year: Secret<String>,
    pub expiry_month: Secret<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cvv: Option<Secret<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AmountDetails {
    pub amount: MinorUnit,
    pub currency_code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_amount: Option<String>,
}

// Confirm Transaction Request (for capture)
#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PeachpaymentsConfirmRequest {
    pub ecommerce_card_payment_only_confirmation_data: EcommerceCardPaymentOnlyConfirmationData,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct EcommerceCardPaymentOnlyConfirmationData {
    pub amount: AmountDetails,
}

// Void Transaction Request
#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PeachpaymentsVoidRequest {
    pub payment_method: PaymentMethod,
    pub send_date_time: String,
    pub failure_reason: FailureReason,
}

#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PaymentMethod {
    EcommerceCardPaymentOnly,
}

#[derive(Default, Debug, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum FailureReason {
    UnableToSend,
    #[default]
    Timeout,
    SecurityError,
    IssuerUnavailable,
    TooLateResponse,
    Malfunction,
    UnableToComplete,
    OnlineDeclined,
    SuspectedFraud,
    CardDeclined,
    Partial,
    OfflineDeclined,
    CustomerCancel,
}

impl FromStr for FailureReason {
    type Err = error_stack::Report<errors::ConnectorError>;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_lowercase().as_str() {
            "unable_to_send" => Ok(Self::UnableToSend),
            "timeout" => Ok(Self::Timeout),
            "security_error" => Ok(Self::SecurityError),
            "issuer_unavailable" => Ok(Self::IssuerUnavailable),
            "too_late_response" => Ok(Self::TooLateResponse),
            "malfunction" => Ok(Self::Malfunction),
            "unable_to_complete" => Ok(Self::UnableToComplete),
            "online_declined" => Ok(Self::OnlineDeclined),
            "suspected_fraud" => Ok(Self::SuspectedFraud),
            "card_declined" => Ok(Self::CardDeclined),
            "partial" => Ok(Self::Partial),
            "offline_declined" => Ok(Self::OfflineDeclined),
            "customer_cancel" => Ok(Self::CustomerCancel),
            _ => Ok(Self::Timeout),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct PeachPaymentsConnectorMetadataObject {
    pub client_merchant_reference_id: Secret<String>,
    pub name: Secret<String>,
    pub mcc: Secret<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<pii::Email>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mobile: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub postal_code: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region_code: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merchant_type: Option<MerchantType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub website_url: Option<url::Url>,
    pub route: Route,
    pub mid: Secret<String>,
    pub tid: Secret<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub visa_payment_facilitator_id: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub master_card_payment_facilitator_id: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub_mid: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amex_id: Option<Secret<String>>,
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
        PeachpaymentsRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for PeachpaymentsPaymentsRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: PeachpaymentsRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        match item.router_data.request.payment_method_data.clone() {
            PaymentMethodData::Card(req_card) => {
                let amount_in_cents = item.router_data.request.minor_amount;

                let connector_merchant_config = PeachPaymentsConnectorMetadataObject::try_from(
                    &item.router_data.resource_common_data.connector_meta_data,
                )?;

                let merchant_information = MerchantInformation {
                    client_merchant_reference_id: connector_merchant_config
                        .client_merchant_reference_id,
                    name: connector_merchant_config.name,
                    mcc: connector_merchant_config.mcc,
                    phone: connector_merchant_config.phone,
                    email: connector_merchant_config.email,
                    mobile: connector_merchant_config.mobile,
                    address: connector_merchant_config.address,
                    city: connector_merchant_config.city,
                    postal_code: connector_merchant_config.postal_code,
                    region_code: connector_merchant_config.region_code,
                    merchant_type: connector_merchant_config.merchant_type,
                    website_url: connector_merchant_config.website_url,
                };

                // Get routing configuration from metadata
                let routing = Routing {
                    route: connector_merchant_config.route,
                    mid: connector_merchant_config.mid,
                    tid: connector_merchant_config.tid,
                    visa_payment_facilitator_id: connector_merchant_config
                        .visa_payment_facilitator_id,
                    master_card_payment_facilitator_id: connector_merchant_config
                        .master_card_payment_facilitator_id,
                    sub_mid: connector_merchant_config.sub_mid,
                    amex_id: connector_merchant_config.amex_id,
                };

                let card = CardDetails {
                    pan: req_card.card_number.clone(),
                    cardholder_name: req_card.card_holder_name.clone(),
                    expiry_year: req_card.card_exp_year.clone(),
                    expiry_month: req_card.card_exp_month.clone(),
                    cvv: Some(req_card.card_cvc.clone()),
                };

                let amount = AmountDetails {
                    amount: amount_in_cents,
                    currency_code: item.router_data.request.currency.to_string(),
                    display_amount: None,
                };

                let ecommerce_data = EcommerceCardPaymentOnlyTransactionData {
                    merchant_information,
                    routing,
                    card,
                    amount,
                };

                // Generate current timestamp for sendDateTime (ISO 8601 format: YYYY-MM-DDTHH:MM:SSZ)
                let send_date_time = OffsetDateTime::now_utc()
                    .format(&time::format_description::well_known::Iso8601::DEFAULT)
                    .map_err(|_| errors::ConnectorError::RequestEncodingFailed)?;

                Ok(Self {
                    charge_method: "ecommerce_card_payment_only".to_string(),
                    reference_id: item
                        .router_data
                        .resource_common_data
                        .connector_request_reference_id,
                    ecommerce_card_payment_only_transaction_data: ecommerce_data,
                    pos_data: None,
                    send_date_time,
                })
            }
            _ => Err(errors::ConnectorError::NotImplemented("Payment method".to_string()).into()),
        }
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
        PeachpaymentsRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    > for PeachpaymentsVoidRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: PeachpaymentsRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let send_date_time = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Iso8601::DEFAULT)
            .map_err(|_| errors::ConnectorError::RequestEncodingFailed)?;
        Ok(Self {
            payment_method: PaymentMethod::EcommerceCardPaymentOnly,
            send_date_time,
            failure_reason: item
                .router_data
                .request
                .cancellation_reason
                .as_ref()
                .map(|reason| FailureReason::from_str(reason))
                .transpose()?
                .unwrap_or(FailureReason::Timeout),
        })
    }
}

// Auth Struct for Card Gateway API
pub struct PeachpaymentsAuthType {
    pub(crate) api_key: Secret<String>,
    pub(crate) tenant_id: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for PeachpaymentsAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        if let ConnectorAuthType::BodyKey { api_key, key1 } = auth_type {
            Ok(Self {
                api_key: api_key.clone(),
                tenant_id: key1.clone(),
            })
        } else {
            Err(errors::ConnectorError::FailedToObtainAuthType)?
        }
    }
}
// Card Gateway API Response
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PeachpaymentsPaymentStatus {
    Successful,
    Pending,
    Authorized,
    Approved,
    ApprovedConfirmed,
    Declined,
    Failed,
    Reversed,
    ThreedsRequired,
    Voided,
}

impl From<PeachpaymentsPaymentStatus> for common_enums::AttemptStatus {
    fn from(item: PeachpaymentsPaymentStatus) -> Self {
        match item {
            // PENDING means authorized but not yet captured - requires confirmation
            PeachpaymentsPaymentStatus::Pending
            | PeachpaymentsPaymentStatus::Authorized
            | PeachpaymentsPaymentStatus::Approved => Self::Authorized,
            PeachpaymentsPaymentStatus::Declined | PeachpaymentsPaymentStatus::Failed => {
                Self::Failure
            }
            PeachpaymentsPaymentStatus::Voided | PeachpaymentsPaymentStatus::Reversed => {
                Self::Voided
            }
            PeachpaymentsPaymentStatus::ThreedsRequired => Self::AuthenticationPending,
            PeachpaymentsPaymentStatus::ApprovedConfirmed
            | PeachpaymentsPaymentStatus::Successful => Self::Charged,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PeachpaymentsPaymentsResponse {
    pub transaction_id: String,
    pub response_code: Option<ResponseCode>,
    pub transaction_result: PeachpaymentsPaymentStatus,
    pub ecommerce_card_payment_only_transaction_data: Option<EcommerceCardPaymentOnlyResponseData>,
}

// Confirm Transaction Response
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde[rename_all = "camelCase"]]
pub struct PeachpaymentsConfirmResponse {
    pub transaction_id: String,
    pub response_code: Option<ResponseCode>,
    pub transaction_result: PeachpaymentsPaymentStatus,
    pub authorization_code: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde[rename_all = "camelCase"]]
#[serde(untagged)]
pub enum ResponseCode {
    Text(String),
    Structured {
        value: String,
        description: String,
        terminal_outcome_string: Option<String>,
        receipt_string: Option<String>,
    },
}

impl ResponseCode {
    pub fn value(&self) -> Option<&String> {
        match self {
            Self::Structured { value, .. } => Some(value),
            _ => None,
        }
    }

    pub fn description(&self) -> Option<&String> {
        match self {
            Self::Structured { description, .. } => Some(description),
            _ => None,
        }
    }

    pub fn as_text(&self) -> Option<&String> {
        match self {
            Self::Text(s) => Some(s),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EcommerceCardPaymentOnlyResponseData {
    pub amount: Option<AmountDetails>,
    pub stan: Option<Secret<String>>,
    pub rrn: Option<Secret<String>>,
    pub approval_code: Option<String>,
    pub merchant_advice_code: Option<String>,
    pub description: Option<String>,
    pub trace_id: Option<String>,
}

fn is_payment_success(value: Option<&String>) -> bool {
    if let Some(val) = value {
        val == "00" || val == "08" || val == "X94"
    } else {
        false
    }
}

fn get_error_code(response_code: Option<&ResponseCode>) -> String {
    response_code
        .and_then(|code| code.value())
        .map(|val| val.to_string())
        .unwrap_or(
            response_code
                .and_then(|code| code.as_text())
                .map(|text| text.to_string())
                .unwrap_or(NO_ERROR_CODE.to_string()),
        )
}

fn get_error_message(response_code: Option<&ResponseCode>) -> String {
    response_code
        .and_then(|code| code.description())
        .map(|desc| desc.to_string())
        .unwrap_or(
            response_code
                .and_then(|code| code.as_text())
                .map(|text| text.to_string())
                .unwrap_or(NO_ERROR_MESSAGE.to_string()),
        )
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
        ResponseRouterData<
            PeachpaymentsPaymentsResponse,
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
            PeachpaymentsPaymentsResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        let status = common_enums::AttemptStatus::from(item.response.transaction_result);

        // Check if it's an error response
        let response = if !is_payment_success(
            item.response
                .response_code
                .as_ref()
                .and_then(|code| code.value()),
        ) {
            Err(ErrorResponse {
                code: get_error_code(item.response.response_code.as_ref()),
                message: get_error_message(item.response.response_code.as_ref()),
                reason: item
                    .response
                    .ecommerce_card_payment_only_transaction_data
                    .and_then(|data| data.description),
                status_code: item.http_code,
                attempt_status: Some(status),
                connector_transaction_id: Some(item.response.transaction_id.clone()),
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
            })
        } else {
            Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    item.response.transaction_id.clone(),
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(item.response.transaction_id),
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            })
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            response,
            ..item.router_data
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
        PeachpaymentsRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    > for PeachpaymentsConfirmRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: PeachpaymentsRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let amount_in_cents = item.router_data.request.minor_amount_to_capture;

        let amount = AmountDetails {
            amount: amount_in_cents,
            currency_code: item.router_data.request.currency.to_string(),
            display_amount: None,
        };

        let confirmation_data = EcommerceCardPaymentOnlyConfirmationData { amount };

        Ok(Self {
            ecommerce_card_payment_only_confirmation_data: confirmation_data,
        })
    }
}

impl<F, T> TryFrom<ResponseRouterData<PeachpaymentsConfirmResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, T, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<PeachpaymentsConfirmResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let status = common_enums::AttemptStatus::from(item.response.transaction_result);

        // Check if it's an error response
        let response = if !is_payment_success(
            item.response
                .response_code
                .as_ref()
                .and_then(|code| code.value()),
        ) {
            Err(ErrorResponse {
                code: get_error_code(item.response.response_code.as_ref()),
                message: get_error_message(item.response.response_code.as_ref()),
                reason: None,
                status_code: item.http_code,
                attempt_status: Some(status),
                connector_transaction_id: Some(item.response.transaction_id.clone()),
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
            })
        } else {
            Ok(PaymentsResponseData::TransactionResponse {
                status_code: item.http_code,
                resource_id: ResponseId::ConnectorTransactionId(
                    item.response.transaction_id.clone(),
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: item.response.authorization_code.map(|auth_code| {
                    serde_json::json!({
                        "authorization_code": auth_code
                    })
                }),
                network_txn_id: None,
                connector_response_reference_id: Some(item.response.transaction_id),
                incremental_authorization_allowed: None,
            })
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            response,
            ..item.router_data
        })
    }
}

impl
    TryFrom<
        ResponseRouterData<
            PeachpaymentsPaymentsResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    > for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<
            PeachpaymentsPaymentsResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let status = common_enums::AttemptStatus::from(item.response.transaction_result);

        // Check if it's an error response
        let response = if !is_payment_success(
            item.response
                .response_code
                .as_ref()
                .and_then(|code| code.value()),
        ) {
            Err(ErrorResponse {
                code: get_error_code(item.response.response_code.as_ref()),
                message: get_error_message(item.response.response_code.as_ref()),
                reason: item
                    .response
                    .ecommerce_card_payment_only_transaction_data
                    .and_then(|data| data.description),
                status_code: item.http_code,
                attempt_status: Some(status),
                connector_transaction_id: Some(item.response.transaction_id.clone()),
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
            })
        } else {
            Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    item.response.transaction_id.clone(),
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(item.response.transaction_id),
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            })
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            response,
            ..item.router_data
        })
    }
}

impl
    TryFrom<
        ResponseRouterData<
            PeachpaymentsPaymentsResponse,
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        >,
    > for RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<
            PeachpaymentsPaymentsResponse,
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let status = common_enums::AttemptStatus::from(item.response.transaction_result);

        // Check if it's an error response
        let response = if !is_payment_success(
            item.response
                .response_code
                .as_ref()
                .and_then(|code| code.value()),
        ) {
            Err(ErrorResponse {
                code: get_error_code(item.response.response_code.as_ref()),
                message: get_error_message(item.response.response_code.as_ref()),
                reason: item
                    .response
                    .ecommerce_card_payment_only_transaction_data
                    .and_then(|data| data.description),
                status_code: item.http_code,
                attempt_status: Some(status),
                connector_transaction_id: Some(item.response.transaction_id.clone()),
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
            })
        } else {
            Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    item.response.transaction_id.clone(),
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(item.response.transaction_id),
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            })
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            response,
            ..item.router_data
        })
    }
}

// Error Response
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeachpaymentsErrorResponse {
    pub error_ref: String,
    pub message: String,
}

impl TryFrom<ErrorResponse> for PeachpaymentsErrorResponse {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(error_response: ErrorResponse) -> Result<Self, Self::Error> {
        Ok(Self {
            error_ref: error_response.code,
            message: error_response.message,
        })
    }
}
