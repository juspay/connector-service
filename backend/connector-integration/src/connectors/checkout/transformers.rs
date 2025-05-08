use hyperswitch_common_utils::{
    errors::CustomResult,
    ext_traits::ByteSliceExt,
    request::Method,
    types::MinorUnit,
};
use error_stack::ResultExt;
use hyperswitch_domain_models::{
    payment_method_data::PaymentMethodData,
    router_data::{ConnectorAuthType, PaymentMethodToken, RouterData, ErrorResponse},
    router_data_v2::{RouterDataV2, PaymentFlowData},
    router_request_types::{ResponseId, PaymentsAuthorizeData},
    router_response_types::{PaymentsResponseData, RedirectForm},
    router_flow_types::Authorize,
};
use hyperswitch_interfaces::errors;
use hyperswitch_masking::{ExposeInterface, Secret};
use serde::{Deserialize, Serialize};
use hyperswitch_common_enums::enums::{self, AttemptStatus};
use uuid;

#[derive(Debug)]
pub struct CheckoutRouterDataWrapper<T> {
    pub inner: T,
}

#[derive(Debug, Serialize)]
pub struct CheckoutRouterData<T> {
    pub amount: MinorUnit,
    pub router_data: T,
}

impl<T> From<(MinorUnit, T)> for CheckoutRouterData<T> {
    fn from((amount, item): (MinorUnit, T)) -> Self {
        Self {
            amount,
            router_data: item,
        }
    }
}

pub struct CheckoutAuthType {
    pub(super) api_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for CheckoutAuthType {
    type Error = errors::ConnectorError;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::HeaderKey { api_key } => Ok(Self {
                api_key: api_key.to_owned(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum CheckoutPaymentStatus {
    Succeeded,
    Failed,
    Processing,
    RequiresCustomerAction,
}

impl std::fmt::Display for CheckoutPaymentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Processing => "processing",
            Self::RequiresCustomerAction => "requires_customer_action",
        };
        write!(f, "{}", s)
    }
}

#[derive(Debug, Serialize)]
pub struct Card {
    number: Secret<String>,
    expiry_month: Secret<String>,
    expiry_year: Secret<String>,
    cvv: Secret<String>,
}

#[derive(Debug, Serialize)]
pub struct PaymentSource {
    card: Card,
}

#[derive(Debug, Serialize)]
pub struct CustomerRequest {
    email: String,
    name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CheckoutPaymentRequest {
    source: PaymentSource,
    amount: MinorUnit,
    currency: String,
    processing_channel_id: String,
    reference: String,
    capture: bool,
    customer: Option<CustomerRequest>,
    success_url: Option<String>,
    failure_url: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ThreeDsRequest {
    pub enabled: bool,
    pub attempt_n3d: bool,
}

impl TryFrom<&CheckoutRouterData<&RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>>> for CheckoutPaymentRequest {
    type Error = errors::ConnectorError;

    fn try_from(
        item: &CheckoutRouterData<&RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let payment_method_data = item.router_data.request.payment_method_data.clone();
        let card = match payment_method_data {
            PaymentMethodData::Card(card) => Ok(Card {
                number: Secret::new(card.card_number.expose()),
                expiry_month: card.card_exp_month,
                expiry_year: card.card_exp_year,
                cvv: card.card_cvc,
            }),
            _ => Err(errors::ConnectorError::NotImplemented("Payment method not supported".to_string())),
        }?;

        let email = item.router_data.request.email.clone()
            .ok_or(errors::ConnectorError::MissingRequiredField { field_name: "email" })?;

        Ok(Self {
            source: PaymentSource { card },
            customer: Some(CustomerRequest {
                email: email.expose(),
                name: item.router_data.request.customer_name.clone().map(|name| name.expose()),
            }),
            amount: item.amount,
            currency: item.router_data.request.currency.to_string(),
            processing_channel_id: format!("pc_{}", uuid::Uuid::new_v4()),
            capture: item.router_data.request.capture_method == Some(enums::CaptureMethod::Automatic),
            reference: item.router_data.connector_request_reference_id.clone(),
            success_url: item.router_data.request.complete_authorize_url.clone(),
            failure_url: item.router_data.request.complete_authorize_url.clone(),
        })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CheckoutPaymentResponse {
    pub id: String,
    pub status: CheckoutPaymentStatus,
    pub reference: String,
}

impl From<CheckoutPaymentStatus> for enums::AttemptStatus {
    fn from(status: CheckoutPaymentStatus) -> Self {
        match status {
            CheckoutPaymentStatus::Succeeded => Self::Charged,
            CheckoutPaymentStatus::Failed => Self::Failure,
            CheckoutPaymentStatus::Processing => Self::Pending,
            CheckoutPaymentStatus::RequiresCustomerAction => Self::AuthenticationPending,
        }
    }
}

impl<F, Req> TryFrom<(
    CheckoutPaymentResponse,
    RouterDataV2<F, PaymentFlowData, Req, PaymentsResponseData>,
    u16,
    Option<enums::CaptureMethod>,
    bool,
    Option<enums::PaymentMethodType>,
)> for CheckoutRouterDataWrapper<RouterDataV2<F, PaymentFlowData, Req, PaymentsResponseData>>
{
    type Error = errors::ConnectorError;

    fn try_from(
        (
            response,
            data,
            status_code,
            capture_method,
            _should_mask,
            payment_method_type,
        ): (
            CheckoutPaymentResponse,
            RouterDataV2<F, PaymentFlowData, Req, PaymentsResponseData>,
            u16,
            Option<enums::CaptureMethod>,
            bool,
            Option<enums::PaymentMethodType>,
        ),
    ) -> Result<Self, Self::Error> {
        let redirection_data = None;

        let response_data = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(response.id.clone()),
            redirection_data,
            mandate_reference: None,
            connector_metadata: None,
            charge_id: Some(response.id.clone()),
            network_txn_id: None,
            connector_response_reference_id: Some(response.reference.clone()),
            incremental_authorization_allowed: None,
        };

        Ok(Self {
            inner: RouterDataV2 {
                flow: data.flow,
                resource_common_data: data.resource_common_data,
                connector_auth_type: data.connector_auth_type,
                request: data.request,
                response: Ok(response_data),
            },
        })
    }
} 