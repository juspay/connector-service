use std::fmt::Debug;

use crate::types::ResponseRouterData;
use common_enums::AttemptStatus;
use common_utils::types::{MinorUnit, StringMinorUnit};
use domain_types::{
    connector_flow::{Authorize, Capture, RSync, Refund, Void},
    connector_types::{
        PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData,
        RefundsResponseData, ResponseId,
    },
    errors,
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes, RawCardNumber},
    router_data::{ConnectorAuthType, ConnectorSpecificAuth},
    router_data_v2::RouterDataV2,
};
use hyperswitch_masking::{PeekInterface, Secret};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MpgsApiOperation {
    Authorize,
    Capture,
    Refund,
    Void,
}

impl MpgsApiOperation {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Authorize => "AUTHORIZE",
            Self::Capture => "CAPTURE",
            Self::Refund => "REFUND",
            Self::Void => "VOID",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MpgsSourceType {
    Card,
}

impl MpgsSourceType {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Card => "CARD",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MpgsGatewayCode {
    Approved,
    ApprovedAuto,
    ApprovedPendingSettlement,
    PartiallyApproved,
    Pending,
    AuthenticationInProgress,
    Submitted,
    Declined,
    DeclinedAvs,
    DeclinedAvsCsc,
    DeclinedCsc,
    DeclinedDoNotContact,
    DeclinedInvalidPin,
    DeclinedPaymentPlan,
    DeclinedPinRequired,
    ExpiredCard,
    InsufficientFunds,
    Referred,
    UnspecifiedFailure,
    AuthenticationFailed,
    Blocked,
    Cancelled,
    Aborted,
    TimedOut,
    Unknown,
    SystemError,
    AcquirerSystemError,
}

#[derive(Debug, Clone)]
pub struct MpgsAuthType {
    pub api_key: Secret<String>,
    pub api_secret: Option<Secret<String>>,
}

impl MpgsAuthType {
    pub fn generate_basic_auth(&self) -> String {
        let mut credentials = Vec::new();
        credentials.extend_from_slice(self.api_key.peek().as_bytes());
        credentials.push(b':');
        if let Some(secret) = &self.api_secret {
            credentials.extend_from_slice(secret.peek().as_bytes());
        }
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, credentials)
    }
}

impl TryFrom<&ConnectorAuthType> for MpgsAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey {
                api_key,
                api_secret,
                ..
            } => Ok(Self {
                api_key: api_key.to_owned(),
                api_secret: Some(api_secret.to_owned()),
            }),
            _ => Err(error_stack::report!(
                errors::ConnectorError::FailedToObtainAuthType
            )),
        }
    }
}

impl TryFrom<&ConnectorSpecificAuth> for MpgsAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorSpecificAuth) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorSpecificAuth::Mpgs {
                api_key,
                api_secret,
            } => Ok(Self {
                api_key: api_key.clone(),
                api_secret: api_secret.clone(),
            }),
            _ => Err(error_stack::report!(
                errors::ConnectorError::FailedToObtainAuthType
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MpgsErrorResponse {
    pub error: Option<MpgsError>,
    pub result: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MpgsError {
    pub cause: Option<String>,
    pub explanation: Option<String>,
    pub field: Option<String>,
    pub support_code: Option<String>,
    pub validation_type: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct MpgsAuthorizeRequest<T: PaymentMethodDataTypes> {
    #[serde(rename = "apiOperation")]
    pub api_operation: MpgsApiOperation,
    pub order: MpgsOrder,
    #[serde(rename = "sourceOfFunds")]
    pub source_of_funds: MpgsSourceOfFunds<T>,
}

#[derive(Debug, Serialize)]
pub struct MpgsOrder {
    pub amount: StringMinorUnit,
    pub currency: common_enums::Currency,
}

#[derive(Debug, Serialize)]
pub struct MpgsSourceOfFunds<T: PaymentMethodDataTypes> {
    #[serde(rename = "type")]
    pub source_type: MpgsSourceType,
    pub provided: MpgsProvidedSource<T>,
}

#[derive(Debug, Serialize)]
pub struct MpgsProvidedSource<T: PaymentMethodDataTypes> {
    pub card: MpgsCard<T>,
}

#[derive(Debug, Serialize)]
pub struct MpgsCard<T: PaymentMethodDataTypes> {
    pub number: RawCardNumber<T>,
    #[serde(rename = "expiry")]
    pub expiry: MpgsExpiry,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "securityCode")]
    pub security_code: Option<Secret<String>>,
}

#[derive(Debug, Serialize)]
pub struct MpgsExpiry {
    pub month: Secret<String>,
    pub year: Secret<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MpgsAuthorizeResponse {
    #[serde(rename = "response")]
    pub response: MpgsGatewayResponse,
    #[serde(rename = "transaction")]
    pub transaction: MpgsTransactionResponse,
    #[serde(rename = "order")]
    pub order: MpgsOrderResponse,
    pub merchant: String,
    pub result: String,
}

pub type MpgsPSyncResponse = MpgsAuthorizeResponse;

#[derive(Debug, Serialize)]
pub struct MpgsCaptureRequest {
    #[serde(rename = "apiOperation")]
    pub api_operation: MpgsApiOperation,
    pub transaction: MpgsCaptureTransaction,
}

#[derive(Debug, Serialize)]
pub struct MpgsCaptureTransaction {
    pub amount: StringMinorUnit,
    pub currency: common_enums::Currency,
}

pub type MpgsCaptureResponse = MpgsAuthorizeResponse;

#[derive(Debug, Serialize)]
pub struct MpgsRefundRequest {
    #[serde(rename = "apiOperation")]
    pub api_operation: MpgsApiOperation,
    pub transaction: MpgsRefundTransaction,
}

#[derive(Debug, Serialize)]
pub struct MpgsRefundTransaction {
    pub amount: StringMinorUnit,
    pub currency: common_enums::Currency,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MpgsRefundResponse {
    #[serde(rename = "response")]
    pub response: MpgsGatewayResponse,
    #[serde(rename = "transaction")]
    pub transaction: MpgsTransactionResponse,
}

pub type MpgsRSyncResponse = MpgsRefundResponse;

#[derive(Debug, Serialize)]
pub struct MpgsVoidRequest {
    #[serde(rename = "apiOperation")]
    pub api_operation: MpgsApiOperation,
    pub transaction: MpgsVoidTransaction,
}

#[derive(Debug, Serialize)]
pub struct MpgsVoidTransaction {
    #[serde(rename = "targetTransactionId")]
    pub target_transaction_id: String,
}

pub type MpgsVoidResponse = MpgsAuthorizeResponse;

#[derive(Debug, Deserialize, Serialize)]
pub struct MpgsGatewayResponse {
    #[serde(rename = "gatewayCode")]
    pub gateway_code: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MpgsTransactionResponse {
    pub amount: MinorUnit,
    pub currency: common_enums::Currency,
    pub id: String,
    #[serde(rename = "type")]
    pub transaction_type: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MpgsOrderResponse {
    pub amount: MinorUnit,
    #[serde(rename = "creationTime")]
    pub creation_time: String,
    pub currency: common_enums::Currency,
    pub id: String,
    #[serde(rename = "lastUpdatedTime")]
    pub last_updated_time: String,
    #[serde(rename = "merchantAmount")]
    pub merchant_amount: MinorUnit,
    #[serde(rename = "merchantCurrency")]
    pub merchant_currency: common_enums::Currency,
    #[serde(rename = "totalAuthorizedAmount")]
    pub total_authorized_amount: MinorUnit,
}

fn map_mpgs_gateway_code_to_status(gateway_code: &str) -> AttemptStatus {
    // Try to deserialize the gateway code into the enum
    let gateway_code_enum: Result<MpgsGatewayCode, _> =
        serde_json::from_value(serde_json::Value::String(gateway_code.to_uppercase()));

    match gateway_code_enum {
        Ok(code) => match code {
            MpgsGatewayCode::Approved
            | MpgsGatewayCode::ApprovedAuto
            | MpgsGatewayCode::ApprovedPendingSettlement => AttemptStatus::Charged,
            MpgsGatewayCode::PartiallyApproved => AttemptStatus::PartialCharged,
            MpgsGatewayCode::Pending
            | MpgsGatewayCode::AuthenticationInProgress
            | MpgsGatewayCode::Submitted => AttemptStatus::Pending,
            MpgsGatewayCode::Declined
            | MpgsGatewayCode::DeclinedAvs
            | MpgsGatewayCode::DeclinedAvsCsc
            | MpgsGatewayCode::DeclinedCsc
            | MpgsGatewayCode::DeclinedDoNotContact
            | MpgsGatewayCode::DeclinedInvalidPin
            | MpgsGatewayCode::DeclinedPaymentPlan
            | MpgsGatewayCode::DeclinedPinRequired
            | MpgsGatewayCode::ExpiredCard
            | MpgsGatewayCode::InsufficientFunds
            | MpgsGatewayCode::Referred
            | MpgsGatewayCode::UnspecifiedFailure => AttemptStatus::Failure,
            MpgsGatewayCode::AuthenticationFailed => AttemptStatus::AuthenticationFailed,
            MpgsGatewayCode::Blocked | MpgsGatewayCode::Cancelled | MpgsGatewayCode::Aborted => {
                AttemptStatus::Voided
            }
            MpgsGatewayCode::TimedOut
            | MpgsGatewayCode::Unknown
            | MpgsGatewayCode::SystemError
            | MpgsGatewayCode::AcquirerSystemError => AttemptStatus::Pending,
        },
        // If we can't parse the gateway code, default to Pending
        Err(_) => AttemptStatus::Pending,
    }
}

fn build_payment_response_data(
    response: &MpgsAuthorizeResponse,
    http_code: u16,
) -> PaymentsResponseData {
    let transaction_id = response.transaction.id.clone();

    PaymentsResponseData::TransactionResponse {
        resource_id: ResponseId::ConnectorTransactionId(transaction_id),
        redirection_data: None,
        mandate_reference: None,
        connector_metadata: None,
        network_txn_id: None,
        connector_response_reference_id: Some(response.order.id.clone()),
        incremental_authorization_allowed: None,
        status_code: http_code,
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        super::MpgsRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for MpgsAuthorizeRequest<T>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: super::MpgsRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = item.router_data;

        let card_data = match &router_data.request.payment_method_data {
            PaymentMethodData::Card(card) => card,
            other => {
                return Err(error_stack::report!(errors::ConnectorError::NotSupported {
                    message: format!("Payment method type {:?}", std::mem::discriminant(other)),
                    connector: "MPGS",
                }))
            }
        };

        let request = Self {
            api_operation: MpgsApiOperation::Authorize,
            order: MpgsOrder {
                amount: crate::connectors::mpgs::MpgsAmountConvertor::convert(
                    router_data.request.minor_amount,
                    router_data.request.currency,
                )?,
                currency: router_data.request.currency,
            },
            source_of_funds: MpgsSourceOfFunds {
                source_type: MpgsSourceType::Card,
                provided: MpgsProvidedSource {
                    card: MpgsCard {
                        number: card_data.card_number.clone(),
                        expiry: MpgsExpiry {
                            month: card_data.card_exp_month.clone(),
                            year: card_data.card_exp_year.clone(),
                        },
                        security_code: Some(card_data.card_cvc.clone()),
                    },
                },
            },
        };

        Ok(request)
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<ResponseRouterData<MpgsAuthorizeResponse, Self>>
    for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<MpgsAuthorizeResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let response = item.response;
        let router_data = item.router_data;

        let status = map_mpgs_gateway_code_to_status(&response.response.gateway_code);
        let payments_response_data = build_payment_response_data(&response, item.http_code);

        Ok(Self {
            response: Ok(payments_response_data),
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            ..router_data
        })
    }
}

impl<F> TryFrom<ResponseRouterData<MpgsPSyncResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: ResponseRouterData<MpgsPSyncResponse, Self>) -> Result<Self, Self::Error> {
        let response = item.response;
        let router_data = item.router_data;

        let status = map_mpgs_gateway_code_to_status(&response.response.gateway_code);
        let payments_response_data = build_payment_response_data(&response, item.http_code);

        Ok(Self {
            response: Ok(payments_response_data),
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            ..router_data
        })
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        super::MpgsRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    > for MpgsCaptureRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: super::MpgsRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = item.router_data;

        Ok(Self {
            api_operation: MpgsApiOperation::Capture,
            transaction: MpgsCaptureTransaction {
                amount: crate::connectors::mpgs::MpgsAmountConvertor::convert(
                    router_data.request.minor_amount_to_capture,
                    router_data.request.currency,
                )?,
                currency: router_data.request.currency,
            },
        })
    }
}

impl TryFrom<ResponseRouterData<MpgsCaptureResponse, Self>>
    for RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: ResponseRouterData<MpgsCaptureResponse, Self>) -> Result<Self, Self::Error> {
        let response = item.response;
        let router_data = item.router_data;

        let status = map_mpgs_gateway_code_to_status(&response.response.gateway_code);
        let payments_response_data = build_payment_response_data(&response, item.http_code);

        Ok(Self {
            response: Ok(payments_response_data),
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            ..router_data
        })
    }
}

fn map_mpgs_gateway_code_to_refund_status(gateway_code: &str) -> common_enums::RefundStatus {
    let gateway_code_enum: Result<MpgsGatewayCode, _> =
        serde_json::from_value(serde_json::Value::String(gateway_code.to_uppercase()));

    match gateway_code_enum {
        Ok(code) => match code {
            MpgsGatewayCode::Approved
            | MpgsGatewayCode::ApprovedAuto
            | MpgsGatewayCode::ApprovedPendingSettlement => common_enums::RefundStatus::Success,
            MpgsGatewayCode::Pending | MpgsGatewayCode::Submitted => {
                common_enums::RefundStatus::Pending
            }
            _ => common_enums::RefundStatus::Failure,
        },
        Err(_) => common_enums::RefundStatus::Failure,
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        super::MpgsRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    > for MpgsRefundRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: super::MpgsRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = item.router_data;

        Ok(Self {
            api_operation: MpgsApiOperation::Refund,
            transaction: MpgsRefundTransaction {
                amount: crate::connectors::mpgs::MpgsAmountConvertor::convert(
                    router_data.request.minor_refund_amount,
                    router_data.request.currency,
                )?,
                currency: router_data.request.currency,
            },
        })
    }
}

impl TryFrom<ResponseRouterData<MpgsRefundResponse, Self>>
    for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: ResponseRouterData<MpgsRefundResponse, Self>) -> Result<Self, Self::Error> {
        let response = item.response;
        let router_data = item.router_data;

        let refund_status = map_mpgs_gateway_code_to_refund_status(&response.response.gateway_code);

        let connector_refund_id = response.transaction.id.clone();

        let refunds_response_data = RefundsResponseData {
            connector_refund_id,
            refund_status,
            status_code: item.http_code,
        };

        Ok(Self {
            response: Ok(refunds_response_data),
            resource_common_data: RefundFlowData {
                status: refund_status,
                ..router_data.resource_common_data
            },
            ..router_data
        })
    }
}

impl TryFrom<ResponseRouterData<MpgsRSyncResponse, Self>>
    for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: ResponseRouterData<MpgsRSyncResponse, Self>) -> Result<Self, Self::Error> {
        let response = item.response;
        let router_data = item.router_data;

        let refund_status = map_mpgs_gateway_code_to_refund_status(&response.response.gateway_code);

        let connector_refund_id = response.transaction.id.clone();

        let refunds_response_data = RefundsResponseData {
            connector_refund_id,
            refund_status,
            status_code: item.http_code,
        };

        Ok(Self {
            response: Ok(refunds_response_data),
            resource_common_data: RefundFlowData {
                status: refund_status,
                ..router_data.resource_common_data
            },
            ..router_data
        })
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        super::MpgsRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    > for MpgsVoidRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: super::MpgsRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = item.router_data;

        Ok(Self {
            api_operation: MpgsApiOperation::Void,
            transaction: MpgsVoidTransaction {
                target_transaction_id: router_data.request.connector_transaction_id.clone(),
            },
        })
    }
}

impl<F> TryFrom<ResponseRouterData<MpgsVoidResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: ResponseRouterData<MpgsVoidResponse, Self>) -> Result<Self, Self::Error> {
        let response = item.response;
        let router_data = item.router_data;

        let status = map_mpgs_gateway_code_to_status(&response.response.gateway_code);
        let payments_response_data = build_payment_response_data(&response, item.http_code);

        Ok(Self {
            response: Ok(payments_response_data),
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            ..router_data
        })
    }
}
