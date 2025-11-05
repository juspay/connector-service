use std::collections::HashMap;

use common_enums::enums;
use common_utils::{
    consts::{NO_ERROR_CODE, NO_ERROR_MESSAGE},
    ext_traits::ValueExt,
    types::StringMajorUnit,
};
use domain_types::{
    connector_flow::{Authorize, Capture, RSync, Refund, SetupMandate, Void},
    connector_types::{
        MandateReference, PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData,
        PaymentsCaptureData, PaymentsResponseData, RefundFlowData, RefundSyncData, RefundsData,
        RefundsResponseData, ResponseId, SetupMandateRequestData,
    },
    errors,
    payment_method_data::{Card, PaymentMethodData, PaymentMethodDataTypes},
    router_data::{
        AdditionalPaymentMethodConnectorResponse, ConnectorAuthType, ConnectorResponseData,
        ErrorResponse,
    },
    router_data_v2::RouterDataV2,
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeOptionInterface, PeekInterface, Secret};
use serde::{Deserialize, Serialize};

use super::{requests, responses};
use crate::connectors::payload::{PayloadAmountConvertor, PayloadRouterData};
use crate::types::ResponseRouterData;

// Re-export types for use in main connector file
pub use super::requests::{
    PayloadCancelRequest, PayloadCaptureRequest, PayloadCardsRequestData, PayloadPaymentsRequest,
    PayloadRefundRequest,
};
pub use super::responses::{
    PayloadAuthorizeResponse, PayloadCaptureResponse, PayloadErrorResponse, PayloadEventDetails,
    PayloadPSyncResponse, PayloadPaymentsResponse, PayloadRSyncResponse, PayloadRefundResponse,
    PayloadSetupMandateResponse, PayloadVoidResponse, PayloadWebhookEvent, PayloadWebhooksTrigger,
};

type Error = error_stack::Report<errors::ConnectorError>;

// Helper function to check if capture method is manual
fn is_manual_capture(capture_method: Option<enums::CaptureMethod>) -> bool {
    matches!(capture_method, Some(enums::CaptureMethod::Manual))
}

// Helper function to get card expiry in format "MM/YY"
fn get_card_expiry<T: PaymentMethodDataTypes>(card: &Card<T>) -> Result<Secret<String>, Error> {
    let month = card.card_exp_month.peek();
    let year = card.card_exp_year.peek();

    // Get last 2 digits of year
    let year_2_digit = if year.len() >= 2 {
        &year[year.len() - 2..]
    } else {
        year
    };

    Ok(Secret::new(format!("{}/{}", month, year_2_digit)))
}

// Auth Struct
#[derive(Debug, Clone, Deserialize)]
pub struct PayloadAuth {
    pub api_key: Secret<String>,
    pub processing_account_id: Option<Secret<String>>,
}

#[derive(Debug, Clone)]
pub struct PayloadAuthType {
    pub auths: HashMap<enums::Currency, PayloadAuth>,
}

impl TryFrom<(&ConnectorAuthType, enums::Currency)> for PayloadAuth {
    type Error = Error;
    fn try_from(value: (&ConnectorAuthType, enums::Currency)) -> Result<Self, Self::Error> {
        let (auth_type, currency) = value;
        match auth_type {
            ConnectorAuthType::CurrencyAuthKey { auth_key_map } => {
                let auth_key = auth_key_map.get(&currency).ok_or(
                    errors::ConnectorError::CurrencyNotSupported {
                        message: currency.to_string(),
                        connector: "Payload",
                    },
                )?;

                auth_key
                    .to_owned()
                    .parse_value("PayloadAuth")
                    .change_context(errors::ConnectorError::FailedToObtainAuthType)
            }
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

impl TryFrom<&ConnectorAuthType> for PayloadAuthType {
    type Error = Error;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::CurrencyAuthKey { auth_key_map } => {
                let auths = auth_key_map
                    .iter()
                    .map(|(currency, auth_key)| {
                        let auth: PayloadAuth = auth_key
                            .to_owned()
                            .parse_value("PayloadAuth")
                            .change_context(errors::ConnectorError::InvalidDataFormat {
                                field_name: "auth_key_map",
                            })?;
                        Ok((*currency, auth))
                    })
                    .collect::<Result<_, Self::Error>>()?;
                Ok(Self { auths })
            }
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

// Helper function to build card request data
fn build_payload_cards_request_data<T: PaymentMethodDataTypes>(
    payment_method_data: &PaymentMethodData<T>,
    connector_auth_type: &ConnectorAuthType,
    currency: enums::Currency,
    amount: StringMajorUnit,
    resource_common_data: &PaymentFlowData,
    capture_method: Option<enums::CaptureMethod>,
    is_mandate: bool,
) -> Result<requests::PayloadCardsRequestData<T>, Error> {
    if let PaymentMethodData::Card(req_card) = payment_method_data {
        let payload_auth = PayloadAuth::try_from((connector_auth_type, currency))?;

        let card = requests::PayloadCard {
            number: req_card.card_number.clone(),
            expiry: get_card_expiry(req_card)?,
            cvc: req_card.card_cvc.clone(),
        };

        // Get billing address to access zip and state
        let billing_addr = resource_common_data.get_billing_address()?;

        let billing_address = requests::BillingAddress {
            city: resource_common_data.get_billing_city()?,
            country: resource_common_data.get_billing_country()?,
            postal_code: billing_addr.zip.clone().ok_or(
                errors::ConnectorError::MissingRequiredField {
                    field_name: "billing.address.zip",
                },
            )?,
            state_province: billing_addr.state.clone().ok_or(
                errors::ConnectorError::MissingRequiredField {
                    field_name: "billing.address.state",
                },
            )?,
            street_address: resource_common_data.get_billing_line1()?,
        };

        // For manual capture, set status to "authorized"
        let status = if is_manual_capture(capture_method) {
            Some(responses::PayloadPaymentStatus::Authorized)
        } else {
            None
        };

        Ok(requests::PayloadCardsRequestData {
            amount,
            card,
            transaction_types: requests::TransactionTypes::Payment,
            payment_method_type: "card".to_string(),
            status,
            billing_address,
            processing_id: payload_auth.processing_account_id,
            keep_active: is_mandate,
        })
    } else {
        Err(errors::ConnectorError::NotImplemented(
            "Payment method not implemented for Payload".to_string(),
        )
        .into())
    }
}

// TryFrom implementations for request bodies

// SetupMandate request
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        PayloadRouterData<
            RouterDataV2<
                SetupMandate,
                PaymentFlowData,
                SetupMandateRequestData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for requests::PayloadCardsRequestData<T>
{
    type Error = Error;

    fn try_from(
        item: PayloadRouterData<
            RouterDataV2<
                SetupMandate,
                PaymentFlowData,
                SetupMandateRequestData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;

        match router_data.request.amount {
            Some(amount) if amount > 0 => Err(errors::ConnectorError::FlowNotSupported {
                flow: "Setup mandate with non zero amount".to_string(),
                connector: "Payload".to_string(),
            }
            .into()),
            _ => {
                // For SetupMandate, is_mandate is always true
                build_payload_cards_request_data(
                    &router_data.request.payment_method_data,
                    &router_data.connector_auth_type,
                    router_data.request.currency,
                    StringMajorUnit::zero(),
                    &router_data.resource_common_data,
                    None, // No capture_method for SetupMandate
                    true,
                )
            }
        }
    }
}

// Authorize request
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        PayloadRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for requests::PayloadPaymentsRequest<T>
{
    type Error = Error;

    fn try_from(
        item: PayloadRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;

        // Convert amount using PayloadAmountConvertor
        let amount = PayloadAmountConvertor::convert(
            router_data.request.minor_amount,
            router_data.request.currency,
        )?;

        match &router_data.request.payment_method_data {
            PaymentMethodData::Card(_) => {
                let is_mandate = router_data.request.is_mandate_payment();

                let cards_data = build_payload_cards_request_data(
                    &router_data.request.payment_method_data,
                    &router_data.connector_auth_type,
                    router_data.request.currency,
                    amount.clone(),
                    &router_data.resource_common_data,
                    router_data.request.capture_method,
                    is_mandate,
                )?;

                Ok(Self::PayloadCardsRequest(Box::new(cards_data)))
            }
            PaymentMethodData::MandatePayment => {
                // For manual capture, set status to "authorized"
                let status = if is_manual_capture(router_data.request.capture_method) {
                    Some(responses::PayloadPaymentStatus::Authorized)
                } else {
                    None
                };

                let mandate_id = router_data
                    .request
                    .get_connector_mandate_id()
                    .change_context(errors::ConnectorError::MissingRequiredField {
                        field_name: "connector_mandate_id",
                    })?;

                Ok(Self::PayloadMandateRequest(Box::new(
                    requests::PayloadMandateRequestData {
                        amount: amount.clone(),
                        transaction_types: requests::TransactionTypes::Payment,
                        payment_method_id: Secret::new(mandate_id),
                        status,
                    },
                )))
            }
            _ => Err(errors::ConnectorError::NotImplemented("Payment method".to_string()).into()),
        }
    }
}

// Capture request
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        PayloadRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    > for requests::PayloadCaptureRequest
{
    type Error = Error;

    fn try_from(
        _item: PayloadRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            status: responses::PayloadPaymentStatus::Processed,
        })
    }
}

// Void request
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        PayloadRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    > for requests::PayloadCancelRequest
{
    type Error = Error;

    fn try_from(
        _item: PayloadRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            status: responses::PayloadPaymentStatus::Voided,
        })
    }
}

// Refund request
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        PayloadRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    > for requests::PayloadRefundRequest
{
    type Error = Error;

    fn try_from(
        item: PayloadRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let connector_transaction_id = router_data.request.connector_transaction_id.clone();

        // Convert amount using PayloadAmountConvertor
        let amount = PayloadAmountConvertor::convert(
            router_data.request.minor_refund_amount,
            router_data.request.currency,
        )?;

        Ok(Self {
            transaction_type: requests::TransactionTypes::Refund,
            amount,
            ledger_assoc_transaction_id: connector_transaction_id,
        })
    }
}

// TryFrom implementations for response bodies

impl From<responses::PayloadPaymentStatus> for common_enums::AttemptStatus {
    fn from(item: responses::PayloadPaymentStatus) -> Self {
        match item {
            responses::PayloadPaymentStatus::Authorized => Self::Authorized,
            responses::PayloadPaymentStatus::Processed => Self::Charged,
            responses::PayloadPaymentStatus::Processing => Self::Pending,
            responses::PayloadPaymentStatus::Rejected
            | responses::PayloadPaymentStatus::Declined => Self::Failure,
            responses::PayloadPaymentStatus::Voided => Self::Voided,
        }
    }
}

// Common function to handle PayloadPaymentsResponse
fn handle_payment_response<F, T>(
    response: responses::PayloadPaymentsResponse,
    router_data: RouterDataV2<F, PaymentFlowData, T, PaymentsResponseData>,
    http_code: u16,
    is_mandate_payment: bool,
) -> Result<RouterDataV2<F, PaymentFlowData, T, PaymentsResponseData>, Error> {
    match response {
        responses::PayloadPaymentsResponse::PayloadCardsResponse(card_response) => {
            let status = common_enums::AttemptStatus::from(card_response.status);

            let mandate_reference = if is_mandate_payment {
                let connector_payment_method_id = card_response
                    .connector_payment_method_id
                    .clone()
                    .expose_option();
                connector_payment_method_id.map(|id| MandateReference {
                    connector_mandate_id: Some(id),
                    payment_method_id: None,
                })
            } else {
                None
            };

            let _connector_response = card_response
                .avs
                .map(|avs_response| {
                    let payment_checks = serde_json::json!({
                        "avs_result": avs_response
                    });
                    AdditionalPaymentMethodConnectorResponse::Card {
                        authentication_data: None,
                        payment_checks: Some(payment_checks),
                        card_network: None,
                        domestic_network: None,
                    }
                })
                .map(ConnectorResponseData::with_additional_payment_method_data);

            let response_result = if status == common_enums::AttemptStatus::Failure {
                Err(ErrorResponse {
                    attempt_status: None,
                    code: card_response
                        .status_code
                        .clone()
                        .unwrap_or_else(|| NO_ERROR_CODE.to_string()),
                    message: card_response
                        .status_message
                        .clone()
                        .unwrap_or_else(|| NO_ERROR_MESSAGE.to_string()),
                    reason: card_response.status_message,
                    status_code: http_code,
                    connector_transaction_id: Some(card_response.transaction_id.clone()),
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                })
            } else {
                Ok(PaymentsResponseData::TransactionResponse {
                    resource_id: ResponseId::ConnectorTransactionId(card_response.transaction_id),
                    redirection_data: None,
                    mandate_reference: mandate_reference.map(Box::new),
                    connector_metadata: None,
                    network_txn_id: None,
                    connector_response_reference_id: card_response.ref_number,
                    incremental_authorization_allowed: None,
                    status_code: http_code,
                })
            };

            // Create a mutable copy to set the status
            let mut router_data_with_status = router_data;
            router_data_with_status
                .resource_common_data
                .set_status(status);

            Ok(RouterDataV2 {
                response: response_result,
                ..router_data_with_status
            })
        }
    }
}

// Authorize response
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
            responses::PayloadPaymentsResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    > for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = Error;

    fn try_from(
        item: ResponseRouterData<
            responses::PayloadPaymentsResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        let is_mandate_payment = item.router_data.request.is_mandate_payment();
        handle_payment_response(
            item.response,
            item.router_data,
            item.http_code,
            is_mandate_payment,
        )
    }
}

// SetupMandate response
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
            responses::PayloadPaymentsResponse,
            RouterDataV2<
                SetupMandate,
                PaymentFlowData,
                SetupMandateRequestData<T>,
                PaymentsResponseData,
            >,
        >,
    >
    for RouterDataV2<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData<T>,
        PaymentsResponseData,
    >
{
    type Error = Error;

    fn try_from(
        item: ResponseRouterData<
            responses::PayloadPaymentsResponse,
            RouterDataV2<
                SetupMandate,
                PaymentFlowData,
                SetupMandateRequestData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        // SetupMandate is always a mandate payment
        handle_payment_response(item.response, item.router_data, item.http_code, true)
    }
}

// PSync response
impl
    TryFrom<
        ResponseRouterData<
            responses::PayloadPaymentsResponse,
            RouterDataV2<
                domain_types::connector_flow::PSync,
                PaymentFlowData,
                domain_types::connector_types::PaymentsSyncData,
                PaymentsResponseData,
            >,
        >,
    >
    for RouterDataV2<
        domain_types::connector_flow::PSync,
        PaymentFlowData,
        domain_types::connector_types::PaymentsSyncData,
        PaymentsResponseData,
    >
{
    type Error = Error;

    fn try_from(
        item: ResponseRouterData<
            responses::PayloadPaymentsResponse,
            RouterDataV2<
                domain_types::connector_flow::PSync,
                PaymentFlowData,
                domain_types::connector_types::PaymentsSyncData,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        handle_payment_response(item.response, item.router_data, item.http_code, false)
    }
}

// Capture response
impl
    TryFrom<
        ResponseRouterData<
            responses::PayloadPaymentsResponse,
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    > for RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = Error;

    fn try_from(
        item: ResponseRouterData<
            responses::PayloadPaymentsResponse,
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        handle_payment_response(item.response, item.router_data, item.http_code, false)
    }
}

// Void response
impl
    TryFrom<
        ResponseRouterData<
            responses::PayloadPaymentsResponse,
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        >,
    > for RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = Error;

    fn try_from(
        item: ResponseRouterData<
            responses::PayloadPaymentsResponse,
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        handle_payment_response(item.response, item.router_data, item.http_code, false)
    }
}

// Refund status conversion
impl From<responses::RefundStatus> for enums::RefundStatus {
    fn from(item: responses::RefundStatus) -> Self {
        match item {
            responses::RefundStatus::Processed => Self::Success,
            responses::RefundStatus::Processing => Self::Pending,
            responses::RefundStatus::Declined | responses::RefundStatus::Rejected => Self::Failure,
        }
    }
}

// Refund response
impl
    TryFrom<
        ResponseRouterData<
            responses::PayloadRefundResponse,
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    > for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = Error;

    fn try_from(
        item: ResponseRouterData<
            responses::PayloadRefundResponse,
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.transaction_id.to_string(),
                refund_status: enums::RefundStatus::from(item.response.status),
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

// Webhook helper function to parse incoming webhook events
pub fn parse_webhook_event(
    body: &[u8],
) -> Result<PayloadWebhookEvent, error_stack::Report<errors::ConnectorError>> {
    serde_json::from_slice::<PayloadWebhookEvent>(body)
        .change_context(errors::ConnectorError::WebhookBodyDecodingFailed)
}

// RSync response
impl
    TryFrom<
        ResponseRouterData<
            responses::PayloadRefundResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    > for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = Error;

    fn try_from(
        item: ResponseRouterData<
            responses::PayloadRefundResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.transaction_id.to_string(),
                refund_status: enums::RefundStatus::from(item.response.status),
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

// Webhook event transformation
pub fn get_event_type_from_trigger(
    trigger: responses::PayloadWebhooksTrigger,
) -> domain_types::connector_types::EventType {
    match trigger {
        // Payment Success Events
        responses::PayloadWebhooksTrigger::Processed => {
            domain_types::connector_types::EventType::PaymentIntentSuccess
        }
        responses::PayloadWebhooksTrigger::Authorized => {
            domain_types::connector_types::EventType::PaymentIntentAuthorizationSuccess
        }
        // Payment Processing Events
        responses::PayloadWebhooksTrigger::Payment
        | responses::PayloadWebhooksTrigger::AutomaticPayment => {
            domain_types::connector_types::EventType::PaymentIntentProcessing
        }
        // Payment Failure Events
        responses::PayloadWebhooksTrigger::Decline
        | responses::PayloadWebhooksTrigger::Reject
        | responses::PayloadWebhooksTrigger::BankAccountReject => {
            domain_types::connector_types::EventType::PaymentIntentFailure
        }
        responses::PayloadWebhooksTrigger::Void | responses::PayloadWebhooksTrigger::Reversal => {
            domain_types::connector_types::EventType::PaymentIntentCancelled
        }
        // Refund Events
        responses::PayloadWebhooksTrigger::Refund => {
            domain_types::connector_types::EventType::RefundSuccess
        }
        // Dispute Events
        responses::PayloadWebhooksTrigger::Chargeback => {
            domain_types::connector_types::EventType::DisputeOpened
        }
        responses::PayloadWebhooksTrigger::ChargebackReversal => {
            domain_types::connector_types::EventType::DisputeWon
        }
        // Other payment-related events - treat as generic payment processing
        responses::PayloadWebhooksTrigger::PaymentActivationStatus
        | responses::PayloadWebhooksTrigger::Credit
        | responses::PayloadWebhooksTrigger::Deposit
        | responses::PayloadWebhooksTrigger::PaymentLinkStatus
        | responses::PayloadWebhooksTrigger::ProcessingStatus
        | responses::PayloadWebhooksTrigger::TransactionOperation
        | responses::PayloadWebhooksTrigger::TransactionOperationClear => {
            domain_types::connector_types::EventType::PaymentIntentProcessing
        }
    }
}
