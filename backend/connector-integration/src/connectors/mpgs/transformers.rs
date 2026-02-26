use std::fmt::Debug;

use crate::types::ResponseRouterData;
use common_enums::AttemptStatus;
use domain_types::{
    connector_flow::{Authorize, Capture, RSync, Refund, Void},
    connector_types::{
        PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData,
        RefundsResponseData, ResponseId,
    },
    errors,
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes, RawCardNumber},
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
};
use hyperswitch_masking::{PeekInterface, Secret};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct MpgsAuthType {
    pub api_key: Secret<String>,
    pub api_secret: Option<Secret<String>>,
}

impl MpgsAuthType {
    pub fn generate_basic_auth(&self) -> String {
        let credentials = format!(
            "{}:{}",
            self.api_key.peek(),
            self.api_secret
                .as_ref()
                .map(|s| s.peek())
                .unwrap_or(&String::new())
        );
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
            ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self {
                api_key: api_key.to_owned(),
                api_secret: Some(key1.to_owned()),
            }),
            ConnectorAuthType::HeaderKey { api_key } => Ok(Self {
                api_key: api_key.to_owned(),
                api_secret: None,
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
    pub api_operation: String,
    pub order: MpgsOrder,
    #[serde(rename = "sourceOfFunds")]
    pub source_of_funds: MpgsSourceOfFunds<T>,
}

#[derive(Debug, Serialize)]
pub struct MpgsOrder {
    pub amount: String,
    pub currency: String,
}

#[derive(Debug, Serialize)]
pub struct MpgsSourceOfFunds<T: PaymentMethodDataTypes> {
    #[serde(rename = "type")]
    pub source_type: String,
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
    pub transaction: Option<MpgsTransactionResponse>,
    #[serde(rename = "order")]
    pub order: Option<MpgsOrderResponse>,
    pub result: Option<String>,
}

pub type MpgsPSyncResponse = MpgsAuthorizeResponse;

#[derive(Debug, Serialize)]
pub struct MpgsCaptureRequest {
    #[serde(rename = "apiOperation")]
    pub api_operation: String,
    pub transaction: MpgsCaptureTransaction,
}

#[derive(Debug, Serialize)]
pub struct MpgsCaptureTransaction {
    pub amount: String,
    pub currency: String,
}

pub type MpgsCaptureResponse = MpgsAuthorizeResponse;

#[derive(Debug, Serialize)]
pub struct MpgsRefundRequest {
    #[serde(rename = "apiOperation")]
    pub api_operation: String,
    pub transaction: MpgsRefundTransaction,
}

#[derive(Debug, Serialize)]
pub struct MpgsRefundTransaction {
    pub amount: String,
    pub currency: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MpgsRefundResponse {
    #[serde(rename = "response")]
    pub response: MpgsGatewayResponse,
    #[serde(rename = "transaction")]
    pub transaction: Option<MpgsTransactionResponse>,
}

pub type MpgsRSyncResponse = MpgsRefundResponse;

#[derive(Debug, Serialize)]
pub struct MpgsVoidRequest {
    #[serde(rename = "apiOperation")]
    pub api_operation: String,
}

pub type MpgsVoidResponse = MpgsAuthorizeResponse;

#[derive(Debug, Deserialize, Serialize)]
pub struct MpgsGatewayResponse {
    #[serde(rename = "gatewayCode")]
    pub gateway_code: String,
    #[serde(rename = "acquirerCode")]
    pub acquirer_code: Option<String>,
    #[serde(rename = "acquirerMessage")]
    pub acquirer_message: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MpgsTransactionResponse {
    #[serde(rename = "type")]
    pub transaction_type: Option<String>,
    #[serde(rename = "amount")]
    pub amount: Option<f64>,
    #[serde(rename = "currency")]
    pub currency: Option<String>,
    #[serde(rename = "authorizationCode")]
    pub authorization_code: Option<String>,
    #[serde(rename = "receipt")]
    pub receipt: Option<String>,
    #[serde(rename = "id")]
    pub id: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MpgsOrderResponse {
    #[serde(rename = "id")]
    pub id: Option<String>,
    #[serde(rename = "status")]
    pub status: Option<String>,
}

fn map_mpgs_gateway_code_to_status(gateway_code: &str) -> AttemptStatus {
    match gateway_code.to_uppercase().as_str() {
        "APPROVED" | "APPROVED_AUTO" | "APPROVED_PENDING_SETTLEMENT" => AttemptStatus::Charged,
        "PARTIALLY_APPROVED" => AttemptStatus::PartialCharged,
        "PENDING" | "AUTHENTICATION_IN_PROGRESS" | "SUBMITTED" => AttemptStatus::Pending,
        "DECLINED"
        | "DECLINED_AVS"
        | "DECLINED_AVS_CSC"
        | "DECLINED_CSC"
        | "DECLINED_DO_NOT_CONTACT"
        | "DECLINED_INVALID_PIN"
        | "DECLINED_PAYMENT_PLAN"
        | "DECLINED_PIN_REQUIRED"
        | "EXPIRED_CARD"
        | "INSUFFICIENT_FUNDS"
        | "REFERRED"
        | "UNSPECIFIED_FAILURE" => AttemptStatus::Failure,
        "AUTHENTICATION_FAILED" => AttemptStatus::AuthenticationFailed,
        "BLOCKED" | "CANCELLED" | "ABORTED" => AttemptStatus::Voided,
        "TIMED_OUT" | "UNKNOWN" | "SYSTEM_ERROR" | "ACQUIRER_SYSTEM_ERROR" => {
            AttemptStatus::Pending
        }
        _ => AttemptStatus::Pending,
    }
}

fn build_payment_response_data(
    response: &MpgsAuthorizeResponse,
    http_code: u16,
) -> PaymentsResponseData {
    let transaction_id = response
        .transaction
        .as_ref()
        .and_then(|t| t.id.clone())
        .or_else(|| response.order.as_ref().and_then(|o| o.id.clone()));

    PaymentsResponseData::TransactionResponse {
        resource_id: ResponseId::ConnectorTransactionId(
            transaction_id.unwrap_or_else(|| "unknown".to_string()),
        ),
        redirection_data: None,
        mandate_reference: None,
        connector_metadata: None,
        network_txn_id: response
            .transaction
            .as_ref()
            .and_then(|t| t.authorization_code.clone()),
        connector_response_reference_id: response.order.as_ref().and_then(|o| o.id.clone()),
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
                    message: format!(
                        "Payment method type {:?} is not supported",
                        std::mem::discriminant(other)
                    ),
                    connector: "MPGS",
                }))
            }
        };

        let amount = router_data
            .request
            .minor_amount
            .get_amount_as_i64()
            .to_string();

        let request = Self {
            api_operation: "AUTHORIZE".to_string(),
            order: MpgsOrder {
                amount,
                currency: router_data.request.currency.to_string(),
            },
            source_of_funds: MpgsSourceOfFunds {
                source_type: "CARD".to_string(),
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

        let amount = router_data
            .request
            .minor_amount_to_capture
            .get_amount_as_i64()
            .to_string();

        Ok(Self {
            api_operation: "CAPTURE".to_string(),
            transaction: MpgsCaptureTransaction {
                amount,
                currency: router_data.request.currency.to_string(),
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
    match gateway_code.to_uppercase().as_str() {
        "APPROVED" | "APPROVED_AUTO" | "APPROVED_PENDING_SETTLEMENT" => {
            common_enums::RefundStatus::Success
        }
        "PENDING" | "SUBMITTED" => common_enums::RefundStatus::Pending,
        _ => common_enums::RefundStatus::Failure,
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

        let amount = router_data
            .request
            .minor_refund_amount
            .get_amount_as_i64()
            .to_string();

        Ok(Self {
            api_operation: "REFUND".to_string(),
            transaction: MpgsRefundTransaction {
                amount,
                currency: router_data.request.currency.to_string(),
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

        let connector_refund_id = response
            .transaction
            .as_ref()
            .and_then(|t| t.id.clone())
            .unwrap_or_else(|| router_data.request.refund_id.clone());

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

        let connector_refund_id = response
            .transaction
            .as_ref()
            .and_then(|t| t.id.clone())
            .unwrap_or_else(|| router_data.request.connector_refund_id.clone());

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
        _item: super::MpgsRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            api_operation: "VOID".to_string(),
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
