use crate::connectors::fiservema::FiservemaRouterData;
use common_enums::AttemptStatus;
use common_utils::{
    consts::{NO_ERROR_CODE, NO_ERROR_MESSAGE},
    ext_traits::ValueExt,
    types::MinorUnit,
};
use domain_types::{
    connector_flow::Authorize,
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData},
    errors::ConnectorError,
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes, RawCardNumber},
    router_data_v2::RouterDataV2,
};
use error_stack::{report, ResultExt};
use hyperswitch_masking::{ExposeInterface, Secret};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemaAuthorizeRequest<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize> {
    pub amount: MinorUnit,
    pub currency: String,
    pub payment_method: FiservemaPaymentMethod<T>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemaPaymentMethod<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize> {
    #[serde(flatten)]
    pub payment_method_data: PaymentMethodData<T>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemaAuthorizeResponse {
    pub id: String,
    pub status: FiservemaStatus,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FiservemaStatus {
    Approved,
    Declined,
    Pending,
    Processing,
    Failed,
    Cancelled,
    Voided,
    Authorized,
    Captured,
    Refunded,
    PartiallyRefunded,
    Chargeback,
    Expired,
}

pub fn map_fiservema_status_to_attempt_status(status: &FiservemaStatus) -> AttemptStatus {
    match status {
        FiservemaStatus::Approved | FiservemaStatus::Captured => AttemptStatus::Charged,
        FiservemaStatus::Authorized => AttemptStatus::Authorized,
        FiservemaStatus::Pending | FiservemaStatus::Processing => AttemptStatus::Pending,
        FiservemaStatus::Declined | FiservemaStatus::Failed => AttemptStatus::Failure,
        FiservemaStatus::Cancelled | FiservemaStatus::Voided => AttemptStatus::Voided,
        FiservemaStatus::Refunded | FiservemaStatus::PartiallyRefunded => AttemptStatus::AutoRefunded,
        FiservemaStatus::Chargeback => AttemptStatus::Failure,
        FiservemaStatus::Expired => AttemptStatus::Failure,
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<FiservemaRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>>
    for FiservemaAuthorizeRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: FiservemaRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = item.router_data;
        let amount = router_data.request.amount;
        let currency = router_data.request.currency.to_string();
        let payment_method_data = router_data
            .request
            .payment_method_data
            .clone()
            .ok_or(ConnectorError::MissingRequiredField {
                field_name: "payment_method_data",
            })
            .attach_printable("payment_method_data is required for Fiservema authorize request")?;

        Ok(Self {
            amount,
            currency,
            payment_method: FiservemaPaymentMethod {
                payment_method_data,
            },
        })
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        crate::types::ResponseRouterData<
            FiservemaAuthorizeResponse,
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        >,
    > for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: crate::types::ResponseRouterData<
            FiservemaAuthorizeResponse,
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let response = item.response;
        let router_data = item.router_data;

        Ok(Self {
            response: Ok(PaymentsResponseData {
                connector_transaction_id: Some(response.id),
                status: map_fiservema_status_to_attempt_status(&response.status),
                ..Default::default()
            }),
            ..router_data
        })
    }
}