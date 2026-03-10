use super::{requests, responses, PeachpaymentsRouterData};

use crate::types::ResponseRouterData;
use common_enums::{AttemptStatus, Currency, RefundStatus};
use common_utils::{
    errors::CustomResult,
    types::{MinorUnit, StringMinorUnitForConnector},
    AmountConvertor, SecretSerdeValue,
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
use time::format_description::well_known::Iso8601;
use time::OffsetDateTime;

pub fn get_error_code(response_code: Option<&responses::PeachpaymentsResponseCode>) -> String {
    match response_code {
        Some(responses::PeachpaymentsResponseCode::Text(code)) => code.clone(),
        Some(responses::PeachpaymentsResponseCode::Structured { value, .. }) => value.clone(),
        None => "UNKNOWN".to_string(),
    }
}

pub fn get_error_message(response_code: Option<&responses::PeachpaymentsResponseCode>) -> String {
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

#[derive(Debug, Clone)]
pub struct PeachpaymentsConnectorMetadataObject {
    pub client_merchant_reference_id: Secret<String>,
    pub merchant_payment_method_route_id: Secret<String>,
}

impl TryFrom<&Option<SecretSerdeValue>> for PeachpaymentsConnectorMetadataObject {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(meta_data: &Option<SecretSerdeValue>) -> Result<Self, Self::Error> {
        let metadata = meta_data
            .as_ref()
            .ok_or(errors::ConnectorError::MissingRequiredField {
                field_name: "connector_meta_data",
            })?;

        let metadata_obj =
            metadata
                .peek()
                .as_object()
                .ok_or(errors::ConnectorError::MissingRequiredField {
                    field_name: "connector_meta_data",
                })?;

        let client_merchant_reference_id = metadata_obj
            .get("client_merchant_reference_id")
            .and_then(|v: &serde_json::Value| v.as_str())
            .ok_or(errors::ConnectorError::MissingRequiredField {
                field_name: "connector_meta_data.client_merchant_reference_id",
            })?;

        let merchant_payment_method_route_id = metadata_obj
            .get("merchant_payment_method_route_id")
            .and_then(|v: &serde_json::Value| v.as_str())
            .ok_or(errors::ConnectorError::MissingRequiredField {
                field_name: "connector_meta_data.merchant_payment_method_route_id",
            })?;

        Ok(Self {
            client_merchant_reference_id: Secret::new(client_merchant_reference_id.to_string()),
            merchant_payment_method_route_id: Secret::new(
                merchant_payment_method_route_id.to_string(),
            ),
        })
    }
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
        if item.router_data.resource_common_data.is_three_ds() {
            return Err(errors::ConnectorError::NotSupported {
                message: "3DS payments are not supported by PeachPayments".to_string(),
                connector: "peachpayments",
            }
            .into());
        }

        let connector_meta_data = PeachpaymentsConnectorMetadataObject::try_from(
            &item.router_data.resource_common_data.connector_meta_data,
        )?;

        let amount = StringMinorUnitForConnector
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(errors::ConnectorError::ParsingFailed)?;

        let transaction_data = match item.router_data.request.payment_method_data.clone() {
            PaymentMethodData::Card(card_info) => {
                requests::PeachpaymentsTransactionData::Card(requests::PeachpaymentsCardData {
                    merchant_information: requests::PeachpaymentsMerchantInformation {
                        client_merchant_reference_id: connector_meta_data
                            .client_merchant_reference_id,
                    },
                    routing_reference: requests::PeachpaymentsRoutingReference {
                        merchant_payment_method_route_id: connector_meta_data
                            .merchant_payment_method_route_id,
                    },
                    card: requests::PeachpaymentsCardDetails {
                        pan: card_info.card_number,
                        cardholder_name: card_info.card_holder_name,
                        expiry_year: Some({
                            let year_str = card_info.card_exp_year.peek();
                            if year_str.len() == 4 {
                                Secret::new(year_str[2..].to_string())
                            } else {
                                Secret::new(year_str.to_string())
                            }
                        }),
                        expiry_month: Some(card_info.card_exp_month),
                        cvv: Some(card_info.card_cvc),
                        eci: None,
                    },
                    amount: requests::PeachpaymentsAmount {
                        amount: amount.to_string(),
                        currency_code: item.router_data.request.currency,
                        display_amount: None,
                    },
                    rrn: item.router_data.request.merchant_order_id.clone(),
                    pre_auth_inc_ext_capture_flow: item
                        .router_data
                        .request
                        .capture_method
                        .map(|cm| {
                            if cm == common_enums::CaptureMethod::Manual {
                                Some(requests::PeachpaymentsPreAuthFlow {
                                    dcc_mode: requests::DccMode::NoDcc,
                                    txn_ref_nr: item
                                        .router_data
                                        .resource_common_data
                                        .connector_request_reference_id
                                        .clone(),
                                })
                            } else {
                                None
                            }
                        })
                        .flatten(),
                    cof_data: None,
                })
            }
            PaymentMethodData::NetworkToken(token_data) => {
                requests::PeachpaymentsTransactionData::NetworkToken(
                    requests::PeachpaymentsNetworkTokenData {
                        merchant_information: requests::PeachpaymentsMerchantInformation {
                            client_merchant_reference_id: connector_meta_data
                                .client_merchant_reference_id,
                        },
                        routing_reference: requests::PeachpaymentsRoutingReference {
                            merchant_payment_method_route_id: connector_meta_data
                                .merchant_payment_method_route_id,
                        },
                        network_token: requests::PeachpaymentsNetworkTokenDetails {
                            token: Secret::new(token_data.token_number.peek().clone()),
                            expiry_year: token_data.token_exp_year,
                            expiry_month: token_data.token_exp_month,
                            cryptogram: token_data.token_cryptogram,
                            eci: token_data.eci,
                            scheme: token_data.card_network.map(|n| format!("{:?}", n)),
                        },
                        amount: requests::PeachpaymentsAmount {
                            amount: amount.to_string(),
                            currency_code: item.router_data.request.currency,
                            display_amount: None,
                        },
                        cof_data: requests::PeachpaymentsCofData::default(),
                        rrn: item.router_data.request.merchant_order_id.clone(),
                        pre_auth_inc_ext_capture_flow: None,
                        _phantom: std::marker::PhantomData,
                    },
                )
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
            transaction_data,
            pos_data: None,
            send_date_time: OffsetDateTime::now_utc()
                .format(&Iso8601::DEFAULT)
                .map_err(|_| errors::ConnectorError::RequestEncodingFailed)?,
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
                display_amount: None,
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
                display_amount: None,
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
                    display_amount: None,
                },
            },
            pos_data: None,
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

impl From<responses::PeachpaymentsPaymentStatus> for AttemptStatus {
    fn from(item: responses::PeachpaymentsPaymentStatus) -> Self {
        match item {
            responses::PeachpaymentsPaymentStatus::Pending
            | responses::PeachpaymentsPaymentStatus::Authorized
            | responses::PeachpaymentsPaymentStatus::Approved => Self::Authorized,
            responses::PeachpaymentsPaymentStatus::Declined
            | responses::PeachpaymentsPaymentStatus::Failed => Self::Failure,
            responses::PeachpaymentsPaymentStatus::Voided
            | responses::PeachpaymentsPaymentStatus::Reversed => Self::Voided,
            responses::PeachpaymentsPaymentStatus::ThreedsRequired => Self::AuthenticationPending,
            responses::PeachpaymentsPaymentStatus::ApprovedConfirmed
            | responses::PeachpaymentsPaymentStatus::Successful => Self::Charged,
        }
    }
}

impl From<responses::PeachpaymentsRefundStatus> for RefundStatus {
    fn from(item: responses::PeachpaymentsRefundStatus) -> Self {
        match item {
            responses::PeachpaymentsRefundStatus::ApprovedConfirmed => Self::Success,
            responses::PeachpaymentsRefundStatus::Failed
            | responses::PeachpaymentsRefundStatus::Declined => Self::Failure,
        }
    }
}

impl TryFrom<requests::CardNetworkLowercase> for common_enums::CardNetwork {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(card_network: requests::CardNetworkLowercase) -> Result<Self, Self::Error> {
        match card_network {
            requests::CardNetworkLowercase::Visa => Ok(Self::Visa),
            requests::CardNetworkLowercase::Mastercard => Ok(Self::Mastercard),
            requests::CardNetworkLowercase::Amex => Ok(Self::AmericanExpress),
            requests::CardNetworkLowercase::Discover => Ok(Self::Discover),
            requests::CardNetworkLowercase::Jcb => Ok(Self::JCB),
            requests::CardNetworkLowercase::Diners => Ok(Self::DinersClub),
            requests::CardNetworkLowercase::CartesBancaires => Ok(Self::CartesBancaires),
            requests::CardNetworkLowercase::UnionPay => Ok(Self::UnionPay),
            requests::CardNetworkLowercase::Interac => Ok(Self::Interac),
            requests::CardNetworkLowercase::RuPay => Ok(Self::RuPay),
            requests::CardNetworkLowercase::Maestro => Ok(Self::Maestro),
            requests::CardNetworkLowercase::Star => Ok(Self::Star),
            requests::CardNetworkLowercase::Pulse => Ok(Self::Pulse),
            requests::CardNetworkLowercase::Accel => Ok(Self::Accel),
            requests::CardNetworkLowercase::Nyce => Ok(Self::Nyce),
        }
    }
}

impl Default for requests::CardOnFileData {
    fn default() -> Self {
        Self {
            _type: requests::CofType::Adhoc,
            source: requests::CofSource::Cit,
            mode: requests::CofMode::Initial,
        }
    }
}

impl Default for requests::PeachpaymentsCofData {
    fn default() -> Self {
        Self {
            cof_type: requests::CofType::Adhoc,
            source: requests::CofSource::Cit,
            mode: requests::CofMode::Initial,
        }
    }
}
