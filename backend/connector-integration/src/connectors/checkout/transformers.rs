use std::{collections::HashMap, str::FromStr};
use hyperswitch_domain_models::payment_method_data::PaymentMethodData;
use domain_types::{
    connector_types::{PaymentsResponseData, PaymentFlowData, PaymentsAuthorizeData},
    connector_flow::Authorize,
    utils::ForeignTryFrom as DomainForeignTryFrom,
};
use hyperswitch_domain_models::{
    router_data_v2::RouterDataV2,
    router_data::ErrorResponse,
    router_request_types::{self as router_req_types, ResponseId},
    router_response_types::{RedirectForm as BaseRedirectForm, MandateReference as BaseMandateReference}
};
use hyperswitch_common_enums::{AttemptStatus, CaptureMethod, PaymentMethodType};
use hyperswitch_interfaces::errors;
use serde::{Deserialize, Serialize};
use hyperswitch_common_utils::types::MinorUnit;
use hyperswitch_common_utils::request::Method as ReqMethod;
use hyperswitch_masking::{Secret, ExposeInterface};
use hyperswitch_cards::CardNumberStrategy;
use hyperswitch_cards::CardNumber;

// Local trait definition to bypass orphan rule
pub trait ForeignTryFrom<F>: Sized {
    type Error;
    fn foreign_try_from(from: F) -> Result<Self, Self::Error>;
}

// === Request Structs ===

#[derive(Debug, Serialize)]
pub struct CheckoutPaymentRequest {
    source: CheckoutSource,
    amount: MinorUnit,
    currency: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    capture: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reference: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(rename = "3ds", skip_serializing_if = "Option::is_none")]
    three_ds: Option<CheckoutThreeDSRequest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    success_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    failure_url: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "type")]
#[serde(rename_all = "lowercase")]
pub enum CheckoutSource {
    Card(Box<CheckoutCardSource>),
}

#[derive(Debug, Serialize)]
pub struct CheckoutCardSource {
    number: Secret<String, CardNumberStrategy>,
    expiry_month: Secret<String>,
    expiry_year: Secret<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cvv: Option<Secret<String>>,
}

#[derive(Debug, Serialize)]
pub struct CheckoutThreeDSRequest {
    enabled: bool,
}

// === Response Structs ===

#[derive(Debug, Deserialize, Clone)]
pub struct CheckoutPaymentsResponse {
    id: String,
    action_id: Option<String>,
    amount: MinorUnit,
    currency: String,
    approved: bool,
    status: CheckoutPaymentStatus,
    auth_code: Option<String>,
    response_code: Option<String>,
    response_summary: Option<String>,
    #[serde(rename = "3ds")]
    three_ds: Option<CheckoutThreeDSResponse>,
    source: Option<CheckoutSourceResponse>,
    processed_on: Option<String>,
    reference: Option<String>,
    _links: Option<CheckoutLinks>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub enum CheckoutPaymentStatus {
    Authorized,
    Captured,
    CardVerified,
    Declined,
    Pending,
    Expired,
    Voided,
    PartiallyCaptured,
    PartiallyRefunded,
    Refunded,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CheckoutThreeDSResponse {
    #[serde(rename = "redirectUrl")]
    redirect_url: Option<String>,
    #[serde(rename = " downgraded")]
    downgraded: Option<bool>,
    enrolled: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CheckoutSourceResponse {
    #[serde(rename = "type")]
    source_type: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CheckoutLinks {
    #[serde(rename = "self")]
    _self: Option<CheckoutLink>,
    redirect: Option<CheckoutLink>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CheckoutLink {
    href: String,
}

// === Error Struct ===
#[derive(Debug, Deserialize, Clone)]
pub struct CheckoutErrorResponse {
    pub request_id: Option<String>,
    pub error_type: String,
    pub error_codes: Option<Vec<String>>,
}

// === Transformers (Placeholders - will be implemented next) ===

// Converts connector response to domain_types::PaymentsResponseData
impl TryFrom<CheckoutPaymentsResponse> for PaymentsResponseData {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: CheckoutPaymentsResponse) -> Result<Self, Self::Error> {
        let redirection_data: Option<BaseRedirectForm> = item._links.and_then(|links| links.redirect).map(|link| {
            BaseRedirectForm::Form {
                endpoint: link.href,
                method: ReqMethod::Get,
                form_fields: HashMap::new(),
            }
        });

        Ok(PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(item.id.clone()),
            redirection_data: Box::new(redirection_data),
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: item.reference,
            incremental_authorization_allowed: None,
        })
    }
}

// Map connector status to Hyperswitch status
impl ForeignTryFrom<CheckoutPaymentStatus> for AttemptStatus {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn foreign_try_from(item: CheckoutPaymentStatus) -> Result<Self, Self::Error> {
        match item {
            CheckoutPaymentStatus::Authorized => Ok(AttemptStatus::Authorized),
            CheckoutPaymentStatus::Captured => Ok(AttemptStatus::Charged),
            CheckoutPaymentStatus::Pending => Ok(AttemptStatus::AuthenticationPending),
            CheckoutPaymentStatus::CardVerified => Ok(AttemptStatus::Pending),
            CheckoutPaymentStatus::Declined => Ok(AttemptStatus::Failure),
            CheckoutPaymentStatus::Expired => Ok(AttemptStatus::Failure),
            CheckoutPaymentStatus::Voided => Ok(AttemptStatus::Voided),
            CheckoutPaymentStatus::PartiallyCaptured => Ok(AttemptStatus::PartialCharged),
            CheckoutPaymentStatus::PartiallyRefunded => Ok(AttemptStatus::Pending),
            CheckoutPaymentStatus::Refunded => Ok(AttemptStatus::Pending),
        }
    }
}

// Implements how RouterDataV2<_, _, _, domain_types::PaymentsResponseData> is constructed
impl<F, Req> ForeignTryFrom<(
    CheckoutPaymentsResponse,
    RouterDataV2<F, PaymentFlowData, Req, PaymentsResponseData>,
    u16,
    Option<CaptureMethod>,
    bool,
    Option<PaymentMethodType>,
)> for RouterDataV2<F, PaymentFlowData, Req, PaymentsResponseData> {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn foreign_try_from(
        (connector_response, data, http_code, _capture_method, _bool_flag, _pmt): (
            CheckoutPaymentsResponse,
            RouterDataV2<F, PaymentFlowData, Req, PaymentsResponseData>,
            u16,
            Option<CaptureMethod>,
            bool,
            Option<PaymentMethodType>,
        ),
    ) -> Result<Self, Self::Error> {
        let status = AttemptStatus::foreign_try_from(connector_response.status.clone())?;
        let error_response: Option<ErrorResponse> = if status == AttemptStatus::Failure {
            Some(ErrorResponse {
                code: connector_response.response_code.clone().unwrap_or_else(|| "CKO_DECLINED".to_string()),
                message: connector_response.response_summary.clone().unwrap_or_else(|| "Payment Declined by Checkout".to_string()),
                reason: connector_response.response_summary.clone(),
                status_code: http_code,
                attempt_status: Some(status),
                connector_transaction_id: Some(connector_response.id.clone()),
            })
        } else {
            None
        };
        let payments_response_data: PaymentsResponseData = connector_response.try_into()?;

        Ok(Self {
            response: error_response.map_or_else(|| Ok(payments_response_data), Err),
            resource_common_data: PaymentFlowData {
                status,
                ..data.resource_common_data
            },
            ..data
        })
    }
}

// Implement Request Transformer: RouterData -> CheckoutPaymentRequest
impl TryFrom<&RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>> for CheckoutPaymentRequest {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>) -> Result<Self, Self::Error> {
        let source = match item.request.payment_method_data.clone() {
            PaymentMethodData::Card(card) => {
                let number_str = card.card_number.to_string();
                let card_source = CheckoutCardSource {
                    number: Secret::<String, CardNumberStrategy>::new(card.card_number.to_string()),
                    expiry_month: card.card_exp_month,
                    expiry_year: card.card_exp_year,
                    name: card.nick_name,
                    cvv: Some(card.card_cvc),
                };
                Ok(CheckoutSource::Card(Box::new(card_source)))
            }
            // Add other payment methods like Token if needed
            _ => Err(errors::ConnectorError::NotImplemented(
                "Payment method not supported by Checkout".to_string(),
            )),
        }?;

        let capture = match item.request.capture_method {
            Some(CaptureMethod::Automatic) => Some(true),
            Some(CaptureMethod::Manual) => Some(false),
            Some(CaptureMethod::ManualMultiple) => Some(false), // Treat as Manual for Checkout
            Some(CaptureMethod::Scheduled) => None, // Checkout capture_on might be needed
            None => Some(true), // Default to capture if not specified? Check connector behavior.
        };

        let three_ds = CheckoutThreeDSRequest {
            enabled: item.request.enrolled_for_3ds, // Assuming direct mapping
        };

        Ok(Self {
            source,
            amount: item.request.minor_amount.clone(),
            currency: item.request.currency.to_string().to_uppercase(),
            capture,
            reference: Some(item.connector_request_reference_id.clone()),
            description: item.description.clone(),
            three_ds: Some(three_ds),
            success_url: item.request.router_return_url.clone(), // Or complete_authorize_url?
            failure_url: item.request.router_return_url.clone(), // Checkout uses separate urls
        })
    }
} 