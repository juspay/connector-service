use base64::{engine::general_purpose::STANDARD, Engine};
use common_enums::{AttemptStatus, RefundStatus};
use domain_types::{
    connector_flow::{Authorize, Capture, PSync, RSync, Refund, Void},
    connector_types::{
        PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData,
        RefundsResponseData, ResponseId,
    },
    errors::{self, ConnectorError},
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes},
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, PeekInterface, Secret};
use serde::{Deserialize, Serialize};

use crate::types::ResponseRouterData;

// =============================================================================
// AUTHENTICATION TYPE
// =============================================================================
#[derive(Debug, Clone)]
pub struct WorldpayAuthType {
    pub api_key: Secret<String>,
    pub api_secret: Secret<String>,
}

impl WorldpayAuthType {
    pub fn generate_basic_auth(&self) -> String {
        let credentials = format!("{}:{}", self.api_key.peek(), self.api_secret.peek());
        let encoded = STANDARD.encode(credentials);
        format!("Basic {encoded}")
    }
}

impl TryFrom<&ConnectorAuthType> for WorldpayAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey {
                api_key,
                api_secret,
                ..
            } => Ok(Self {
                api_key: api_key.to_owned(),
                api_secret: api_secret.to_owned(),
            }),
            ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self {
                api_key: api_key.to_owned(),
                api_secret: key1.to_owned(),
            }),
            _ => Err(error_stack::report!(
                errors::ConnectorError::FailedToObtainAuthType
            )),
        }
    }
}

// =============================================================================
// ERROR RESPONSE
// =============================================================================
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WorldpayErrorResponse {
    pub code: String,
    pub message: String,
}

// =============================================================================
// AUTHORIZE FLOW
// =============================================================================
#[derive(Debug, Serialize)]
pub struct WorldpayAuthorizeRequest {
    pub transaction_reference: String,
    pub merchant: WorldpayMerchant,
    pub instruction: WorldpayInstruction,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct WorldpayMerchant {
    pub entity: String,
}

#[derive(Debug, Serialize)]
pub struct WorldpayInstruction {
    pub method: String,
    pub payment_instrument: WorldpayPaymentInstrument,
    pub narrative: WorldpayNarrative,
    pub value: WorldpayValue,
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum WorldpayPaymentInstrument {
    #[serde(rename = "plain")]
    Plain(WorldpayCard),
}

#[derive(Debug, Serialize)]
pub struct WorldpayCard {
    pub card_holder_name: Secret<String>,
    pub card_number: Secret<String>,
    pub expiry_date: WorldpayExpiryDate,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cvc: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub billing_address: Option<WorldpayBillingAddress>,
}

#[derive(Debug, Serialize)]
pub struct WorldpayExpiryDate {
    pub month: u8,
    pub year: u16,
}

#[derive(Debug, Serialize)]
pub struct WorldpayBillingAddress {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address1: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address2: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address3: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub postal_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country_code: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct WorldpayNarrative {
    pub line1: String,
}

#[derive(Debug, Serialize)]
pub struct WorldpayValue {
    pub currency: String,
    pub amount: i64,
}

#[derive(Debug, Deserialize)]
pub struct WorldpayAuthorizeResponse {
    pub outcome: String,
    pub payment_id: String,
    pub transaction_reference: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scheme_reference: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<WorldpayIssuer>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_instrument: Option<WorldpayPaymentInstrumentResponse>,
}

#[derive(Debug, Deserialize)]
pub struct WorldpayIssuer {
    #[serde(rename = "authorizationCode")]
    pub authorization_code: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct WorldpayPaymentInstrumentResponse {
    #[serde(rename = "type")]
    pub instrument_type: String,
    #[serde(rename = "cardBin")]
    pub card_bin: Option<String>,
    #[serde(rename = "lastFour")]
    pub last_four: Option<String>,
    #[serde(rename = "countryCode")]
    pub country_code: Option<String>,
    #[serde(rename = "expiryDate")]
    pub expiry_date: Option<WorldpayExpiryDateResponse>,
    #[serde(rename = "cardBrand")]
    pub card_brand: Option<String>,
    #[serde(rename = "fundingType")]
    pub funding_type: Option<String>,
    pub category: Option<String>,
    #[serde(rename = "issuerName")]
    pub issuer_name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct WorldpayExpiryDateResponse {
    pub month: u8,
    pub year: u16,
}

// Status mapping for authorize outcome
fn map_worldpay_outcome_to_attempt_status(outcome: &str) -> AttemptStatus {
    match outcome {
        "authorized" => AttemptStatus::Charged,
        "refused" => AttemptStatus::Failure,
        "fraudHighRisk" => AttemptStatus::Failure,
        "3dsDeviceDataRequired" => AttemptStatus::AuthenticationPending,
        _ => AttemptStatus::Pending,
    }
}

// Request transformer for Authorize flow
impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        super::WorldpayRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    > for WorldpayAuthorizeRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: super::WorldpayRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;

        let payment_instrument = match &router_data.request.payment_method_data {
            PaymentMethodData::Card(card_data) => {
                let card_number = Secret::new(
                    serde_json::to_string(&card_data.card_number.clone().0)
                        .change_context(errors::ConnectorError::RequestEncodingFailed)?
                        .trim_matches('"')
                        .to_string(),
                );

                let card_holder_name = card_data
                    .card_holder_name
                    .clone()
                    .unwrap_or_else(|| Secret::new("".to_string()));

                let billing_address = router_data
                    .resource_common_data
                    .address
                    .get_payment_billing()
                    .and_then(|addr| addr.address.as_ref())
                    .map(|details| WorldpayBillingAddress {
                        address1: details.line1.clone(),
                        address2: details.line2.clone(),
                        address3: details.line3.clone(),
                        postal_code: details.zip.clone(),
                        city: details.city.clone(),
                        state: details.state.clone(),
                        country_code: details.country.as_ref().map(|c: &common_enums::CountryAlpha2| c.to_string()),
                    });

                WorldpayPaymentInstrument::Plain(WorldpayCard {
                    card_holder_name,
                    card_number,
                    expiry_date: WorldpayExpiryDate {
                        month: card_data
                            .card_exp_month
                            .expose()
                            .parse()
                            .unwrap_or(1),
                        year: card_data
                            .card_exp_year
                            .expose()
                            .parse()
                            .unwrap_or(2030),
                    },
                    cvc: Some(card_data.card_cvc.clone()),
                    billing_address,
                })
            }
            _ => {
                return Err(ConnectorError::NotImplemented(
                    "Only card payments are supported for Worldpay".to_string(),
                )
                .into())
            }
        };

        let narrative_line1 = router_data
            .request
            .description
            .clone()
            .unwrap_or_else(|| "Payment".to_string());

        Ok(Self {
            transaction_reference: router_data
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            merchant: WorldpayMerchant {
                entity: "default".to_string(),
            },
            instruction: WorldpayInstruction {
                method: "card".to_string(),
                payment_instrument,
                narrative: WorldpayNarrative { line1: narrative_line1 },
                value: WorldpayValue {
                    currency: router_data.request.currency.to_string(),
                    amount: router_data.request.minor_amount.get_amount_as_i64(),
                },
            },
            channel: Some("ecom".to_string()),
        })
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        ResponseRouterData<
            WorldpayAuthorizeResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    >
    for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            WorldpayAuthorizeResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let router_data = &item.router_data;

        let status = map_worldpay_outcome_to_attempt_status(&response.outcome);

        let payments_response_data = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(response.payment_id.clone()),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: Some(response.transaction_reference.clone()),
            incremental_authorization_allowed: None,
            status_code: item.http_code,
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data.clone()
            },
            response: Ok(payments_response_data),
            ..router_data.clone()
        })
    }
}

// =============================================================================
// PAYMENT SYNC (PSync) FLOW
// =============================================================================
#[derive(Debug, Deserialize)]
pub struct WorldpaySyncResponse {
    #[serde(rename = "lastEvent")]
    pub last_event: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_id: Option<String>,
}

fn map_worldpay_last_event_to_attempt_status(last_event: &str) -> AttemptStatus {
    match last_event {
        "authorizationSucceeded" => AttemptStatus::Charged,
        "authorizationRefused" => AttemptStatus::Failure,
        "authorizationRequested" => AttemptStatus::Pending,
        "settlementRequested" => AttemptStatus::Pending,
        "settlementSucceeded" => AttemptStatus::Charged,
        "refundRequested" => AttemptStatus::Pending,
        "refundSucceeded" => AttemptStatus::Charged,
        "cancellationRequested" => AttemptStatus::Pending,
        "cancellationSucceeded" => AttemptStatus::Voided,
        "reversalRequested" => AttemptStatus::Pending,
        "reversalSucceeded" => AttemptStatus::Voided,
        _ => AttemptStatus::Pending,
    }
}

impl TryFrom<
        ResponseRouterData<
            WorldpaySyncResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    > for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            WorldpaySyncResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let router_data = &item.router_data;

        let status = map_worldpay_last_event_to_attempt_status(&response.last_event);

        let connector_transaction_id = response
            .payment_id
            .clone()
            .or_else(|| match &router_data.request.connector_transaction_id {
                ResponseId::ConnectorTransactionId(id) => Some(id.clone()),
                _ => None,
            });

        let payments_response_data = PaymentsResponseData::TransactionResponse {
            resource_id: connector_transaction_id
                .map(ResponseId::ConnectorTransactionId)
                .unwrap_or(ResponseId::NoResponseId),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: None,
            incremental_authorization_allowed: None,
            status_code: item.http_code,
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data.clone()
            },
            response: Ok(payments_response_data),
            ..router_data.clone()
        })
    }
}

// =============================================================================
// CAPTURE FLOW
// =============================================================================
#[derive(Debug, Serialize)]
pub struct WorldpayCaptureRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct WorldpayCaptureResponse {
    pub outcome: String,
    #[serde(rename = "paymentId")]
    pub payment_id: String,
}

// Request transformer for Capture flow
impl TryFrom<
        super::WorldpayRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    > for WorldpayCaptureRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: super::WorldpayRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            reference: Some(
                item.router_data
                    .resource_common_data
                    .connector_request_reference_id
                    .clone(),
            ),
        })
    }
}

impl TryFrom<
        ResponseRouterData<
            WorldpayCaptureResponse,
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    > for RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            WorldpayCaptureResponse,
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let router_data = &item.router_data;

        let status = match response.outcome.as_str() {
            "sentForSettlement" => AttemptStatus::Charged,
            _ => AttemptStatus::Pending,
        };

        let payments_response_data = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(response.payment_id.clone()),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: None,
            incremental_authorization_allowed: None,
            status_code: item.http_code,
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data.clone()
            },
            response: Ok(payments_response_data),
            ..router_data.clone()
        })
    }
}

// =============================================================================
// VOID FLOW
// =============================================================================
#[derive(Debug, Deserialize)]
pub struct WorldpayVoidResponse {
    pub outcome: String,
    #[serde(rename = "paymentId")]
    pub payment_id: String,
    #[serde(rename = "transactionReference")]
    pub transaction_reference: String,
}

impl TryFrom<
        ResponseRouterData<
            WorldpayVoidResponse,
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        >,
    > for RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            WorldpayVoidResponse,
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let router_data = &item.router_data;

        let status = match response.outcome.as_str() {
            "sentForCancellation" => AttemptStatus::Voided,
            _ => AttemptStatus::Pending,
        };

        let payments_response_data = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(response.payment_id.clone()),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: Some(response.transaction_reference.clone()),
            incremental_authorization_allowed: None,
            status_code: item.http_code,
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data.clone()
            },
            response: Ok(payments_response_data),
            ..router_data.clone()
        })
    }
}

// =============================================================================
// REFUND FLOW
// =============================================================================
#[derive(Debug, Serialize)]
pub struct WorldpayRefundRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<WorldpayValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct WorldpayRefundResponse {
    pub outcome: String,
    #[serde(rename = "paymentId")]
    pub payment_id: String,
}

fn map_worldpay_refund_outcome_to_refund_status(outcome: &str) -> RefundStatus {
    match outcome {
        "sentForRefund" | "sentForPartialRefund" => RefundStatus::Pending,
        _ => RefundStatus::Pending,
    }
}

// Request transformer for Refund flow
impl TryFrom<
        super::WorldpayRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    > for WorldpayRefundRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: super::WorldpayRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;

        // For partial refunds, include the value
        let value = if router_data.request.minor_amount.get_amount_as_i64()
            < router_data.request.total_amount.get_amount_as_i64()
        {
            Some(WorldpayValue {
                currency: router_data.request.currency.to_string(),
                amount: router_data.request.minor_amount.get_amount_as_i64(),
            })
        } else {
            None
        };

        Ok(Self {
            value,
            reference: Some(
                router_data
                    .resource_common_data
                    .connector_request_reference_id
                    .clone(),
            ),
        })
    }
}

impl TryFrom<
        ResponseRouterData<
            WorldpayRefundResponse,
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    > for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            WorldpayRefundResponse,
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let router_data = &item.router_data;

        let refund_status = map_worldpay_refund_outcome_to_refund_status(&response.outcome);

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: response.payment_id.clone(),
                refund_status,
                status_code: item.http_code,
            }),
            ..router_data.clone()
        })
    }
}

// =============================================================================
// REFUND SYNC (RSync) FLOW
// =============================================================================
#[derive(Debug, Deserialize)]
pub struct WorldpayRefundSyncResponse {
    #[serde(rename = "lastEvent")]
    pub last_event: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_id: Option<String>,
}

fn map_worldpay_refund_event_to_refund_status(last_event: &str) -> RefundStatus {
    match last_event {
        "refundSucceeded" => RefundStatus::Success,
        "refundRequested" => RefundStatus::Pending,
        "refundRefused" => RefundStatus::Failure,
        _ => RefundStatus::Pending,
    }
}

impl TryFrom<
        ResponseRouterData<
            WorldpayRefundSyncResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    > for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            WorldpayRefundSyncResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let router_data = &item.router_data;

        let refund_status = map_worldpay_refund_event_to_refund_status(&response.last_event);

        let connector_refund_id = response
            .payment_id
            .clone()
            .or_else(|| Some(router_data.request.connector_refund_id.clone()));

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: connector_refund_id.unwrap_or_default(),
                refund_status,
                status_code: item.http_code,
            }),
            ..router_data.clone()
        })
    }
}
