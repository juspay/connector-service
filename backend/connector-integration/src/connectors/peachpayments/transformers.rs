use super::{requests, responses, PeachpaymentsRouterData};

use crate::types::ResponseRouterData;
use common_enums::{AttemptStatus, Currency};
use common_utils::{
    errors::CustomResult,
    types::{MinorUnit, StringMinorUnitForConnector},
    AmountConvertor,
};
use domain_types::{
    connector_flow::{Authorize, Capture, PSync, RSync, Refund, Void},
    connector_types::{
        PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData,
        RefundsResponseData, ResponseId,
    },
    errors,
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes},
    router_data::{ConnectorSpecificAuth, ErrorResponse},
    router_data_v2::RouterDataV2,
};
use error_stack::ResultExt;
use hyperswitch_masking::{PeekInterface, Secret};
use serde::Serialize;
use std::fmt::Debug;

fn get_error_code(response_code: Option<&responses::PeachpaymentsResponseCode>) -> String {
    match response_code {
        Some(responses::PeachpaymentsResponseCode::Text(code)) => code.clone(),
        Some(responses::PeachpaymentsResponseCode::Structured { value, .. }) => value.clone(),
        None => "UNKNOWN".to_string(),
    }
}

fn get_error_message(response_code: Option<&responses::PeachpaymentsResponseCode>) -> String {
    match response_code {
        Some(responses::PeachpaymentsResponseCode::Text(msg)) => msg.clone(),
        Some(responses::PeachpaymentsResponseCode::Structured { description, .. }) => {
            description.clone()
        }
        None => "Unknown error".to_string(),
    }
}

fn get_webhook_response(
    response: responses::PeachpaymentsIncomingWebhook,
    status_code: u16,
) -> CustomResult<
    (AttemptStatus, Result<PaymentsResponseData, ErrorResponse>),
    errors::ConnectorError,
> {
    let transaction = response
        .transaction
        .ok_or(errors::ConnectorError::WebhookBodyDecodingFailed)?;

    let status: AttemptStatus = transaction.transaction_result.clone().into();

    let response_data = if status == AttemptStatus::Failure {
        Err(ErrorResponse {
            code: get_error_code(transaction.response_code.as_ref()),
            message: transaction
                .error_message
                .clone()
                .unwrap_or_else(|| get_error_message(transaction.response_code.as_ref())),
            reason: transaction.error_message.clone(),
            status_code,
            attempt_status: Some(status),
            connector_transaction_id: Some(transaction.transaction_id.clone()),
            network_decline_code: None,
            network_advice_code: None,
            network_error_message: None,
        })
    } else {
        Ok(PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(transaction.transaction_id.clone()),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: Some(transaction.reference_id.clone()),
            incremental_authorization_allowed: None,
            status_code,
        })
    };

    Ok((status, response_data))
}

#[derive(Debug, Clone)]
pub struct PeachpaymentsAuthType {
    pub api_key: Secret<String>,
    pub tenant_id: Secret<String>,
}

impl TryFrom<&ConnectorSpecificAuth> for PeachpaymentsAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorSpecificAuth) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorSpecificAuth::Peachpayments { api_key, tenant_id } => Ok(Self {
                api_key: api_key.to_owned(),
                tenant_id: tenant_id.to_owned(),
            }),
            _ => Err(error_stack::report!(
                errors::ConnectorError::FailedToObtainAuthType
            )),
        }
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
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
    > for requests::PeachpaymentsAuthorizeRequest<T>
{
    type Error = error_stack::Report<errors::ConnectorError>;

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
        let card_data = match item.router_data.request.payment_method_data.clone() {
            PaymentMethodData::Card(card_info) => {
                requests::PeachpaymentsCardData::Card(requests::PeachpaymentsCard {
                    card: requests::PeachpaymentsCardDetails {
                        pan: card_info.card_number,
                        cvv: card_info.card_cvc,
                        cardholder_name: card_info.card_holder_name,
                        expiry_year: Some(card_info.card_exp_year),
                        expiry_month: Some(card_info.card_exp_month),
                        eci: None,
                    },
                })
            }
            PaymentMethodData::NetworkToken(token_data) => {
                requests::PeachpaymentsCardData::NetworkToken(requests::PeachpaymentsNetworkToken {
                    payment_method: "ecommerce_card_payment_only".to_string(),
                    routing: requests::PeachpaymentsRoutingInfo {
                        merchant_payment_method_route_id: Secret::new(
                            "default_route_id".to_string(),
                        ),
                    },
                    network_token: requests::PeachpaymentsNetworkTokenDetails {
                        token: Secret::new(token_data.token_number.peek().clone()),
                        expiry_year: token_data.token_exp_year,
                        expiry_month: token_data.token_exp_month,
                        cryptogram: token_data.token_cryptogram,
                        eci: token_data.eci,
                        scheme: token_data
                            .card_network
                            .map(|n| format!("{:?}", n).to_lowercase()),
                    },
                    cof_data: requests::PeachpaymentsCofData {
                        cof_type: "adhoc".to_string(),
                        source: "cit".to_string(),
                        mode: "initial".to_string(),
                    },
                    _phantom: std::marker::PhantomData,
                })
            }
            _ => {
                return Err(errors::ConnectorError::NotSupported {
                    message: "Payment method not supported".to_string(),
                    connector: "peachpayments",
                }
                .into());
            }
        };

        Ok(Self {
            charge_method: "ecommerce_card_payment_only".to_string(),
            reference_id: item
                .router_data
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            card_data,
            pos_data: None,
            send_date_time: common_utils::date_time::now().to_string(),
            _phantom: std::marker::PhantomData,
        })
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<ResponseRouterData<responses::PeachpaymentsPaymentsResponse, Self>>
    for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<responses::PeachpaymentsPaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let (status, response) = match item.response {
            responses::PeachpaymentsPaymentsResponse::Response(data) => {
                let status: AttemptStatus = data.transaction_result.clone().into();
                let response = if status == AttemptStatus::Failure {
                    Err(ErrorResponse {
                        code: get_error_code(data.response_code.as_ref()),
                        message: get_error_message(data.response_code.as_ref()),
                        reason: Some(get_error_message(data.response_code.as_ref())),
                        status_code: item.http_code,
                        attempt_status: Some(status),
                        connector_transaction_id: Some(data.transaction_id.clone()),
                        network_decline_code: None,
                        network_advice_code: None,
                        network_error_message: None,
                    })
                } else {
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(data.transaction_id),
                        redirection_data: None,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: None,
                        connector_response_reference_id: None,
                        incremental_authorization_allowed: None,
                        status_code: item.http_code,
                    })
                };
                (status, response)
            }
            responses::PeachpaymentsPaymentsResponse::WebhookResponse(webhook) => {
                get_webhook_response(*webhook, item.http_code)?
            }
        };

        Ok(Self {
            response,
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

impl TryFrom<ResponseRouterData<responses::PeachpaymentsSyncResponse, Self>>
    for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<responses::PeachpaymentsSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let status: AttemptStatus = item.response.transaction_result.into();

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.transaction_id),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
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

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        PeachpaymentsRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    > for requests::PeachpaymentsCaptureRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: PeachpaymentsRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let amount = StringMinorUnitForConnector
            .convert(
                item.router_data.request.minor_amount_to_capture,
                item.router_data.request.currency,
            )
            .change_context(errors::ConnectorError::ParsingFailed)?;

        Ok(Self {
            amount: requests::PeachpaymentsAmount {
                amount: amount.to_string(),
                currency_code: item.router_data.request.currency,
            },
        })
    }
}

impl TryFrom<ResponseRouterData<responses::PeachpaymentsCaptureResponse, Self>>
    for RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<responses::PeachpaymentsCaptureResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let status: AttemptStatus = item.response.transaction_result.into();

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.transaction_id),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
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

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        PeachpaymentsRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    > for requests::PeachpaymentsVoidRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: PeachpaymentsRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let amount = item.router_data.request.amount.unwrap_or_default();
        let currency = item.router_data.request.currency.unwrap_or(Currency::ZAR);

        let amount_converted = StringMinorUnitForConnector
            .convert(amount, currency)
            .change_context(errors::ConnectorError::ParsingFailed)?;

        Ok(Self {
            amount: requests::PeachpaymentsAmount {
                amount: amount_converted.to_string(),
                currency_code: currency,
            },
        })
    }
}

impl TryFrom<ResponseRouterData<responses::PeachpaymentsVoidResponse, Self>>
    for RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<responses::PeachpaymentsVoidResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let status: AttemptStatus = item.response.transaction_result.into();

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.transaction_id),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
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

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        PeachpaymentsRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    > for requests::PeachpaymentsRefundRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: PeachpaymentsRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let refund_amount = StringMinorUnitForConnector
            .convert(
                MinorUnit::new(item.router_data.request.refund_amount),
                item.router_data.request.currency,
            )
            .change_context(errors::ConnectorError::ParsingFailed)?;

        Ok(Self {
            reference_id: item
                .router_data
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            card_data: requests::PeachpaymentsRefundTransactionData {
                amount: requests::PeachpaymentsAmount {
                    amount: refund_amount.to_string(),
                    currency_code: item.router_data.request.currency,
                },
            },
        })
    }
}

impl TryFrom<ResponseRouterData<responses::PeachpaymentsRefundResponse, Self>>
    for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<responses::PeachpaymentsRefundResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let refund_status = item.response.transaction_result.into();

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.transaction_id.clone(),
                refund_status,
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

impl TryFrom<ResponseRouterData<responses::PeachpaymentsRefundSyncResponse, Self>>
    for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<responses::PeachpaymentsRefundSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let refund_status = item.response.transaction_result.into();

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.transaction_id.clone(),
                refund_status,
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}
