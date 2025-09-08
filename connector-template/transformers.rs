use std::collections::HashMap;

use common_enums;
use common_utils::{
    request::Method,
    types::MinorUnit,
};
use domain_types::{
    connector_flow::Authorize,
    connector_types::{
        PaymentFlowData,
        PaymentsAuthorizeData, PaymentsResponseData,
        ResponseId,
    },
    errors::{self, ConnectorError},
    payment_method_data::{
        PaymentMethodData, PaymentMethodDataTypes, RawCardNumber,
    },
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
};
use hyperswitch_masking::{Secret, PeekInterface};
use serde::{Deserialize, Serialize};

use crate::types::ResponseRouterData;

pub struct {{connector_camel}}RouterData<T, U> {
    pub router_data: T,
    pub phantom_data: std::marker::PhantomData<U>,
}

impl<T, U> {{connector_camel}}RouterData<T, U> {
    pub fn new(router_data: T) -> Self {
        Self {
            router_data,
            phantom_data: std::marker::PhantomData,
        }
    }
}

// Auth Types
#[derive(Debug, Clone, Deserialize)]
pub struct {{connector_camel}}AuthType {
    pub api_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for {{connector_camel}}AuthType {
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::HeaderKey { api_key } => Ok(Self {
                api_key: api_key.to_owned(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

// Request Types
#[derive(Debug, Serialize)]
pub struct {{connector_camel}}PaymentsRequest<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    pub amount: MinorUnit,
    pub currency: String,
    pub payment_method: {{connector_camel}}PaymentMethod<T>,
    pub return_url: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct {{connector_camel}}PaymentMethod<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    #[serde(rename = "type")]
    pub method_type: String,
    pub card: Option<{{connector_camel}}Card<T>>,
}

#[derive(Debug, Serialize)]
pub struct {{connector_camel}}Card<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    pub number: RawCardNumber<T>,
    pub exp_month: Secret<String>,
    pub exp_year: Secret<String>,
    pub cvc: Option<Secret<String>>,
    pub holder_name: Option<Secret<String>>,
}

#[derive(Debug, Serialize)]
pub struct {{connector_camel}}SyncRequest {
    pub transaction_id: String,
}

#[derive(Debug, Serialize)]
pub struct {{connector_camel}}RefundRequest {
    pub amount: MinorUnit,
    pub currency: String,
    pub transaction_id: String,
    pub reason: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct {{connector_camel}}RefundSyncRequest {
    pub refund_id: String,
}

#[derive(Debug, Serialize)]
pub struct {{connector_camel}}CaptureRequest {
    pub amount: MinorUnit,
    pub currency: String,
    pub transaction_id: String,
}

#[derive(Debug, Serialize)]
pub struct {{connector_camel}}VoidRequest {
    pub transaction_id: String,
    pub reason: Option<String>,
}

// Response Types
#[derive(Debug, Clone, Default, Deserialize)]
pub struct {{connector_camel}}PaymentsResponse {
    pub id: String,
    pub status: String,
    pub amount: Option<MinorUnit>,
    pub currency: Option<String>,
    pub redirect_url: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct {{connector_camel}}SyncResponse {
    pub id: String,
    pub status: String,
    pub amount: Option<MinorUnit>,
    pub currency: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct {{connector_camel}}RefundResponse {
    pub id: String,
    pub status: String,
    pub amount: Option<MinorUnit>,
    pub currency: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct {{connector_camel}}RefundSyncResponse {
    pub id: String,
    pub status: String,
    pub amount: Option<MinorUnit>,
    pub currency: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct {{connector_camel}}CaptureResponse {
    pub id: String,
    pub status: String,
    pub amount: Option<MinorUnit>,
    pub currency: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct {{connector_camel}}VoidResponse {
    pub id: String,
    pub status: String,
}

#[derive(Debug, Deserialize)]
pub struct {{connector_camel}}ErrorResponse {
    pub code: Option<String>,
    pub message: Option<String>,
    pub reason: Option<String>,
}

// Request Conversion Implementations
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        {{connector_camel}}RouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for {{connector_camel}}PaymentsRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: {{connector_camel}}RouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let payment_method = match &item.router_data.request.payment_method_data {
            PaymentMethodData::Card(card) => {{connector_camel}}PaymentMethod {
                method_type: "card".to_string(),
                card: Some({{connector_camel}}Card {
                    number: card.card_number.clone(),
                    exp_month: card.card_exp_month.clone(),
                    exp_year: card.card_exp_year.clone(),
                    cvc: card.card_cvc.clone(),
                    holder_name: card.card_holder_name.clone(),
                }),
            },
            _ => return Err(ConnectorError::NotSupported { message: "Payment method not supported".to_string(), connector: "{{connector_name}}" }.into()),
        };

        Ok(Self {
            amount: item.router_data.request.minor_amount,
            currency: item.router_data.request.currency.to_string(),
            payment_method,
            return_url: item.router_data.resource_common_data.get_return_url(),
            description: item.router_data.resource_common_data.get_optional_description(),
        })
    }
}

// Response Conversion Implementations
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
            {{connector_camel}}PaymentsResponse,
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
            {{connector_camel}}PaymentsResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        let status = match item.response.status.as_str() {
            "succeeded" => common_enums::AttemptStatus::Charged,
            "pending" => common_enums::AttemptStatus::Pending,
            "failed" => common_enums::AttemptStatus::Failure,
            _ => common_enums::AttemptStatus::Pending,
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id),
                redirection_data: item.response.redirect_url.map(|url| {
                    Box::new(RedirectForm::Form {
                        endpoint: url,
                        method: Method::Get,
                        form_fields: HashMap::new(),
                    })
                }),
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                raw_connector_response: None,
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

// TODO: Implement similar patterns for other flows (PSync, Refund, RSync, Capture, Void)
// This is a basic template - you would need to implement the remaining conversions
// following the same pattern as shown above for Authorize flow.