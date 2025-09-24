use base64::{engine::general_purpose::STANDARD, Engine};
use common_enums::{AttemptStatus, RefundStatus};
use common_utils::types::MinorUnit;
use domain_types::{
    connector_flow::{Authorize, Capture, PSync, Void, Refund, RSync},
    connector_types::{
        PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundsData, RefundsResponseData,
        RefundSyncData, ResponseId,
    },
    errors,
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes, RawCardNumber},
    router_data::{ConnectorAuthType},
    router_data_v2::RouterDataV2,
};
use hyperswitch_masking::{PeekInterface, Secret};
use serde::{Deserialize, Serialize};

use crate::types::ResponseRouterData;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayAuthType {
    pub basic_auth: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for WorldpayAuthType {
    type Error = error_stack::Report<domain_types::errors::ConnectorError>;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::BodyKey { api_key, key1 } => {
                let credentials = format!("{}:{}", key1.peek(), api_key.peek());
                let encoded = STANDARD.encode(credentials.as_bytes());
                Ok(Self {
                    basic_auth: Secret::new(format!("Basic {}", encoded)),
                })
            }
            ConnectorAuthType::SignatureKey { api_key, key1, api_secret: _ } => {
                // For WorldPay, we use api_key and key1 for basic auth
                let credentials = format!("{}:{}", key1.peek(), api_key.peek());
                let encoded = STANDARD.encode(credentials.as_bytes());
                Ok(Self {
                    basic_auth: Secret::new(format!("Basic {}", encoded)),
                })
            }
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayExpiryDate {
    pub month: u8,
    pub year: u16,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayBillingAddress {
    pub address1: Option<Secret<String>>,
    pub city: Option<Secret<String>>,
    pub postal_code: Option<Secret<String>>,
    pub country_code: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayPaymentInstrument<T: PaymentMethodDataTypes> {
    #[serde(rename = "type")]
    pub instrument_type: String,
    pub card_number: RawCardNumber<T>,
    pub expiry_date: WorldpayExpiryDate,
    pub cvc: Option<Secret<String>>,
    pub card_holder_name: Option<Secret<String>>,
    pub billing_address: Option<WorldpayBillingAddress>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayMerchant {
    pub entity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayValue {
    pub currency: String,
    pub amount: MinorUnit,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayNarrative {
    pub line1: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayInstruction<T: PaymentMethodDataTypes> {
    pub method: String,
    pub payment_instrument: WorldpayPaymentInstrument<T>,
    pub narrative: WorldpayNarrative,
    pub value: WorldpayValue,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayPaymentRequest<T: PaymentMethodDataTypes> {
    pub transaction_reference: String,
    pub merchant: WorldpayMerchant,
    pub channel: String,
    pub instruction: WorldpayInstruction<T>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayHref {
    pub href: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayActionLink {
    pub href: String,
    pub method: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayLinks {
    #[serde(rename = "self")]
    pub self_link: WorldpayHref,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayActions {
    pub settle_payment: Option<WorldpayActionLink>,
    pub cancel_payment: Option<WorldpayActionLink>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayPaymentResponse {
    pub outcome: String,
    pub transaction_reference: String,
    #[serde(rename = "_links")]
    pub links: WorldpayLinks,
    #[serde(rename = "_actions")]
    pub actions: Option<WorldpayActions>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WorldpayCaptureRequest {
    pub value: Option<WorldpayValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayCaptureResponse {
    pub outcome: String,
    pub transaction_reference: String,
    #[serde(rename = "_links")]
    pub links: WorldpayLinks,
}

#[derive(Debug, Clone, Serialize)]
pub struct WorldpayVoidRequest {}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayVoidResponse {
    pub outcome: String,
    pub transaction_reference: String,
    #[serde(rename = "_links")]
    pub links: WorldpayLinks,
}


#[derive(Debug, Clone, Serialize)]
pub struct WorldpaySyncRequest {}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpaySyncResponse {
    pub outcome: String,
    pub transaction_reference: String,
    #[serde(rename = "_links")]
    pub links: WorldpayLinks,
    #[serde(rename = "_actions")]
    pub actions: Option<WorldpayActions>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WorldpayRefundRequest {}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayRefundResponse {
    pub outcome: String,
    #[serde(rename = "_links")]
    pub links: WorldpayLinks,
}

#[derive(Debug, Clone, Serialize)]
pub struct WorldpayRefundSyncRequest {}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayRefundSyncResponse {
    pub outcome: String,
    #[serde(rename = "_links")]
    pub links: WorldpayLinks,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayErrorResponse {
    pub error_name: String,
    pub message: String,
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize> TryFrom<super::WorldpayRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>>
    for WorldpayPaymentRequest<T>
{
    type Error = error_stack::Report<domain_types::errors::ConnectorError>;
    fn try_from(
        item: super::WorldpayRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let item = &item.router_data;
        match &item.request.payment_method_data {
            PaymentMethodData::Card(card_data) => {
                let payment_instrument = WorldpayPaymentInstrument {
                    instrument_type: "plain".to_string(),
                    card_number: card_data.card_number.clone(),
                    expiry_date: WorldpayExpiryDate {
                        month: card_data.card_exp_month.peek().parse().map_err(|_| errors::ConnectorError::RequestEncodingFailed)?,
                        year: card_data.card_exp_year.peek().parse().map_err(|_| errors::ConnectorError::RequestEncodingFailed)?,
                    },
                    cvc: Some(card_data.card_cvc.clone()),
                    card_holder_name: card_data.card_holder_name.clone(),
                    billing_address: item.resource_common_data.get_billing_address().ok().map(|addr| WorldpayBillingAddress {
                        address1: addr.line1.clone(),
                        city: addr.city.clone().map(|c| Secret::new(c)),
                        postal_code: addr.zip.clone(),
                        country_code: addr.country.map(|c| c.to_string()),
                    }),
                };

                Ok(Self {
                    transaction_reference: item.resource_common_data.connector_request_reference_id.clone(),
                    merchant: WorldpayMerchant {
                        entity: "default".to_string(),
                    },
                    channel: "ecom".to_string(),
                    instruction: WorldpayInstruction {
                        method: "card".to_string(),
                        payment_instrument,
                        narrative: WorldpayNarrative {
                            line1: "Payment".to_string(),
                        },
                        value: WorldpayValue {
                            currency: item.request.currency.to_string(),
                            amount: item.request.minor_amount,
                        },
                    },
                })
            }
            _ => Err(errors::ConnectorError::NotSupported {
                message: "Payment method not supported".to_string(),
                connector: "Worldpay",
            }
            .into()),
        }
    }
}

impl<T: PaymentMethodDataTypes>
    TryFrom<
        ResponseRouterData<
            WorldpayPaymentResponse,
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        >,
    > for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<domain_types::errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<
            WorldpayPaymentResponse,
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let status = match item.response.outcome.as_str() {
            "authorized" => AttemptStatus::Charged,
            "sentForSettlement" => AttemptStatus::Charged,
            "refused" => AttemptStatus::Failure,
            "3dsDeviceDataRequired" | "3dsChallenged" => AttemptStatus::AuthenticationPending,
            _ => AttemptStatus::Pending,
        };

        let connector_transaction_id = extract_transaction_id(&item.response.links.self_link.href)
            .unwrap_or_else(|| item.response.transaction_reference.clone());

        let mut router_data = item.router_data;
        router_data.resource_common_data.status = status;
        router_data.response = Ok(PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(connector_transaction_id),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: Some(item.response.transaction_reference),
            incremental_authorization_allowed: None,
            status_code: item.http_code,
        });
        Ok(router_data)
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize> TryFrom<super::WorldpayRouterData<RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>, T>>
    for WorldpayCaptureRequest
{
    type Error = error_stack::Report<domain_types::errors::ConnectorError>;
    fn try_from(
        item: super::WorldpayRouterData<RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let item = &item.router_data;
        Ok(Self {
            value: Some(WorldpayValue {
                currency: item.request.currency.to_string(),
                amount: item.request.minor_amount_to_capture,
            }),
        })
    }
}

impl
    TryFrom<
        ResponseRouterData<WorldpayCaptureResponse, RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>>,
    > for RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<domain_types::errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<WorldpayCaptureResponse, RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let status = match item.response.outcome.as_str() {
            "sentForSettlement" => AttemptStatus::Charged,
            _ => AttemptStatus::Pending,
        };

        let connector_transaction_id = extract_transaction_id(&item.response.links.self_link.href)
            .unwrap_or_else(|| item.response.transaction_reference.clone());

        let mut router_data = item.router_data;
        router_data.resource_common_data.status = status;
        router_data.response = Ok(PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(connector_transaction_id),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: Some(item.response.transaction_reference),
            incremental_authorization_allowed: None,
            status_code: item.http_code,
        });
        Ok(router_data)
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize> TryFrom<super::WorldpayRouterData<RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>, T>>
    for WorldpayVoidRequest
{
    type Error = error_stack::Report<domain_types::errors::ConnectorError>;
    fn try_from(
        _item: super::WorldpayRouterData<RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {})
    }
}

impl
    TryFrom<
        ResponseRouterData<WorldpayVoidResponse, RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>>,
    > for RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = error_stack::Report<domain_types::errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<WorldpayVoidResponse, RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let status = match item.response.outcome.as_str() {
            "sentForCancellation" => AttemptStatus::Voided,
            _ => AttemptStatus::VoidFailed,
        };

        let connector_transaction_id = extract_transaction_id(&item.response.links.self_link.href)
            .unwrap_or_else(|| item.response.transaction_reference.clone());

        let mut router_data = item.router_data;
        router_data.resource_common_data.status = status;
        router_data.response = Ok(PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(connector_transaction_id),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: Some(item.response.transaction_reference),
            incremental_authorization_allowed: None,
            status_code: item.http_code,
        });
        Ok(router_data)
    }
}


impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize> TryFrom<super::WorldpayRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>>
    for WorldpaySyncRequest
{
    type Error = error_stack::Report<domain_types::errors::ConnectorError>;
    fn try_from(
        _item: super::WorldpayRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {})
    }
}

impl
    TryFrom<
        ResponseRouterData<WorldpaySyncResponse, RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>,
    > for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<domain_types::errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<WorldpaySyncResponse, RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let status = match item.response.outcome.as_str() {
            "authorized" => AttemptStatus::Charged,
            "sentForSettlement" => AttemptStatus::Charged,
            "refused" => AttemptStatus::Failure,
            "sentForCancellation" => AttemptStatus::Voided,
            _ => AttemptStatus::Pending,
        };

        let connector_transaction_id = extract_transaction_id(&item.response.links.self_link.href)
            .unwrap_or_else(|| item.response.transaction_reference.clone());

        let mut router_data = item.router_data;
        router_data.resource_common_data.status = status;
        router_data.response = Ok(PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(connector_transaction_id),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: Some(item.response.transaction_reference),
            incremental_authorization_allowed: None,
            status_code: item.http_code,
        });
        Ok(router_data)
    }
}




// Refund Request Transformer
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize> TryFrom<super::WorldpayRouterData<RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>, T>>
    for WorldpayRefundRequest
{
    type Error = error_stack::Report<domain_types::errors::ConnectorError>;
    fn try_from(
        _item: super::WorldpayRouterData<RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        // Worldpay uses empty body for full refunds
        Ok(Self {})
    }
}

// Refund Response Transformer
impl
    TryFrom<
        ResponseRouterData<
            WorldpayRefundResponse,
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    > for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<domain_types::errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<
            WorldpayRefundResponse,
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let refund_status = match item.response.outcome.as_str() {
            "sentForRefund" | "sentForPartialRefund" => RefundStatus::Pending,
            "refunded" => RefundStatus::Success,
            "refused" | "failed" => RefundStatus::Failure,
            _ => RefundStatus::Pending,
        };

        let connector_refund_id = extract_transaction_id(&item.response.links.self_link.href)
            .unwrap_or_else(|| "unknown".to_string());

        let mut router_data = item.router_data;
        router_data.response = Ok(RefundsResponseData {
            connector_refund_id,
            refund_status,
            status_code: item.http_code,
        });
        Ok(router_data)
    }
}

// Refund Sync Request Transformer
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize> TryFrom<super::WorldpayRouterData<RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>, T>>
    for WorldpayRefundSyncRequest
{
    type Error = error_stack::Report<domain_types::errors::ConnectorError>;
    fn try_from(
        _item: super::WorldpayRouterData<RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {})
    }
}

// Refund Sync Response Transformer
impl
    TryFrom<
        ResponseRouterData<
            WorldpayRefundSyncResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    > for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<domain_types::errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<
            WorldpayRefundSyncResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let refund_status = match item.response.outcome.as_str() {
            "sentForRefund" | "sentForPartialRefund" => RefundStatus::Pending,
            "refunded" => RefundStatus::Success,
            "refused" | "failed" => RefundStatus::Failure,
            _ => RefundStatus::Pending,
        };

        let connector_refund_id = extract_transaction_id(&item.response.links.self_link.href)
            .unwrap_or_else(|| "unknown".to_string());

        let mut router_data = item.router_data;
        router_data.response = Ok(RefundsResponseData {
            connector_refund_id,
            refund_status,
            status_code: item.http_code,
        });
        Ok(router_data)
    }
}

fn extract_transaction_id(href: &str) -> Option<String> {
    href.split('/').last().map(|s| s.to_string())
}
