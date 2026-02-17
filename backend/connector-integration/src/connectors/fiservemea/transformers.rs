use crate::types::ResponseRouterData;
use common_enums::{enums, AttemptStatus};
use common_utils::types::FloatMajorUnit;
use domain_types::{
    connector_flow::Authorize,
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, ResponseId},
    errors,
    payment_method_data::{PaymentMethodDataTypes, RawCardNumber},
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, Secret};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct FiservemeaAuthType {
    pub api_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for FiservemeaAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::HeaderKey { api_key } => Ok(Self {
                api_key: api_key.to_owned(),
            }),
            _ => Err(error_stack::report!(
                errors::ConnectorError::FailedToObtainAuthType
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FiservemeaErrorResponse {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct FiservemeaPreAuthRequest<T: PaymentMethodDataTypes> {
    pub request_type: String,
    pub transaction_amount: FiservemeaAmount,
    pub payment_method: FiservemeaPaymentMethod<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order: Option<FiservemeaOrder>,
}

#[derive(Debug, Serialize)]
pub struct FiservemeaAmount {
    pub total: FloatMajorUnit,
    pub currency: enums::Currency,
}

#[derive(Debug, Serialize)]
pub struct FiservemeaPaymentMethod<T: PaymentMethodDataTypes> {
    pub payment_card: FiservemeaPaymentCard<T>,
}

#[derive(Debug, Serialize)]
pub struct FiservemeaPaymentCard<T: PaymentMethodDataTypes> {
    pub number: RawCardNumber<T>,
    pub security_code: Secret<String>,
    pub expiry_date: FiservemeaExpiryDate,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FiservemeaExpiryDate {
    pub month: String,
    pub year: String,
}

#[derive(Debug, Serialize)]
pub struct FiservemeaOrder {
    pub order_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub billing: Option<FiservemeaAddress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shipping: Option<FiservemeaAddress>,
}

#[derive(Debug, Serialize)]
pub struct FiservemeaAddress {
    pub name: String,
    pub address_line1: String,
    pub address_line2: Option<String>,
    pub city: String,
    pub state: Option<String>,
    pub postal_code: String,
    pub country: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FiservemeaTransactionResponse {
    pub client_request_id: String,
    pub api_trace_id: String,
    pub response_type: String,
    pub type: String,
    pub ipg_transaction_id: String,
    pub order_id: String,
    pub transaction_type: String,
    pub transaction_result: String,
    pub transaction_state: FiservemeaStatus,
    pub approved_amount: Option<FiservemeaAmount>,
    pub transaction_amount: Option<FiservemeaAmount>,
    pub processor: Option<FiservemeaProcessor>,
    pub payment_method_details: Option<FiservemeaPaymentMethodDetails>,
    pub error: Option<FiservemeaError>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FiservemeaStatus {
    Authorized,
    Captured,
    Declined,
    Settled,
    Voided,
    Waiting,
    Initialized,
    Pending,
    Ready,
    Template,
    Checked,
    CompletedGet,
    FAILED,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FiservemeaProcessor {
    pub reference_number: String,
    pub authorization_code: Option<String>,
    pub response_code: String,
    pub response_message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FiservemeaPaymentMethodDetails {
    pub payment_card: Option<FiservemeaPaymentCardDetails>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FiservemeaPaymentCardDetails {
    pub number: Option<Secret<String>>,
    pub expiry_date: Option<FiservemeaExpiryDate>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FiservemeaError {
    pub code: String,
    pub message: String,
}

impl<T: PaymentMethodDataTypes>
    TryFrom<
        &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    > for FiservemeaPreAuthRequest<T>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData<T>,
            PaymentsResponseData,
        >,
    ) -> Result<Self, Self::Error> {
        let amount = item.request.minor_amount.get_amount_as_float();
        let currency = item.request.currency;
        
        let payment_card = FiservemeaPaymentCard {
            number: item.request.payment_method.card_number.clone(),
            security_code: item.request.payment_method.cvv.clone(),
            expiry_date: FiservemeaExpiryDate {
                month: item.request.payment_method.expiry_month.clone(),
                year: item.request.payment_method.expiry_year.clone(),
            },
        };

        Ok(FiservemeaPreAuthRequest {
            request_type: "PaymentCardPreAuthTransaction".to_string(),
            transaction_amount: FiservemeaAmount {
                total: amount,
                currency,
            },
            payment_method: FiservemeaPaymentMethod { payment_card },
            order: None,
        })
    }
}

impl<T: PaymentMethodDataTypes>
    TryFrom<
        ResponseRouterData<
            FiservemeaTransactionResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    > for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            FiservemeaTransactionResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        let status = map_fiservemea_status_to_attempt_status(&item.response.transaction_state);
        
        let network_txn_id = item
            .response
            .processor
            .as_ref()
            .and_then(|p| p.reference_number.clone())
            .or_else(|| Some(item.response.ipg_transaction_id.clone()));

        let connector_txn_id = Some(item.response.ipg_transaction_id.clone());

        let approval_code = item
            .response
            .processor
            .as_ref()
            .and_then(|p| p.authorization_code.clone());

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(connector_txn_id.unwrap_or_default()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id,
                connector_response_reference_id: None,
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

pub fn map_fiservemea_status_to_attempt_status(status: &FiservemeaStatus) -> AttemptStatus {
    match status {
        FiservemeaStatus::Authorized => AttemptStatus::Authorized,
        FiservemeaStatus::Captured => AttemptStatus::Charged,
        FiservemeaStatus::Declined => AttemptStatus::Failure,
        FiservemeaStatus::Settled => AttemptStatus::Charged,
        FiservemeaStatus::Voided => AttemptStatus::Voided,
        FiservemeaStatus::Waiting => AttemptStatus::Pending,
        FiservemeaStatus::Initialized => AttemptStatus::Pending,
        FiservemeaStatus::Pending => AttemptStatus::Pending,
        FiservemeaStatus::Ready => AttemptStatus::Pending,
        FiservemeaStatus::Template => AttemptStatus::Pending,
        FiservemeaStatus::Checked => AttemptStatus::Pending,
        FiservemeaStatus::CompletedGet => AttemptStatus::Charged,
        FiservemeaStatus::FAILED => AttemptStatus::Failure,
    }
}
