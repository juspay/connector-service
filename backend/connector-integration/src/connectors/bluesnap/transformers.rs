use base64::{engine::general_purpose::STANDARD, Engine};
use common_enums::AttemptStatus;
use common_utils::{
    errors::CustomResult,
    types::{StringMajorUnit, StringMajorUnitForConnector},
    AmountConvertor, MinorUnit,
};
use domain_types::{
    connector_flow::{Authorize, Capture, PSync, RSync, Refund},
    connector_types::{
        PaymentFlowData, PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData,
        PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData,
        ResponseId,
    },
    errors,
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes},
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
};
use error_stack::ResultExt;
use hyperswitch_masking::{PeekInterface, Secret};
use serde::Serialize;

use super::{requests, responses};
use crate::types::ResponseRouterData;

// Re-export request types
pub use requests::{
    BluesnapCaptureRequest, BluesnapCardHolderInfo, BluesnapCompletePaymentsRequest,
    BluesnapCreditCard, BluesnapMetadata, BluesnapPaymentMethodDetails, BluesnapPaymentsRequest,
    BluesnapPaymentsTokenRequest, BluesnapRefundRequest, BluesnapRefundSyncRequest,
    BluesnapSyncRequest, BluesnapThreeDSecureInfo, BluesnapTxnType, BluesnapVoidRequest,
    BluesnapWallet, RequestMetadata, TransactionFraudInfo,
};

// Re-export response types
pub use responses::{
    BluesnapAuthorizeResponse, BluesnapCaptureResponse, BluesnapChargebackStatus,
    BluesnapCreditCardResponse, BluesnapDisputeWebhookBody, BluesnapErrorResponse,
    BluesnapPSyncResponse, BluesnapPaymentsResponse, BluesnapProcessingInfo,
    BluesnapProcessingStatus, BluesnapRedirectionResponse, BluesnapRefundResponse,
    BluesnapRefundStatus, BluesnapRefundSyncResponse, BluesnapThreeDsReference,
    BluesnapThreeDsResult, BluesnapVoidResponse, BluesnapWebhookBody, BluesnapWebhookEvent,
    BluesnapWebhookObjectResource, RedirectErrorMessage,
};

// Helper function to convert MinorUnit to StringMajorUnit
fn convert_minor_to_major_unit(
    minor_amount: MinorUnit,
    currency: common_enums::Currency,
) -> CustomResult<StringMajorUnit, errors::ConnectorError> {
    StringMajorUnitForConnector
        .convert(minor_amount, currency)
        .change_context(errors::ConnectorError::RequestEncodingFailed)
}

// Auth Type
#[derive(Debug, Clone)]
pub struct BluesnapAuthType {
    pub username: Secret<String>,
    pub password: Secret<String>,
}

impl BluesnapAuthType {
    pub fn generate_basic_auth(&self) -> String {
        let credentials = format!("{}:{}", self.username.peek(), self.password.peek());
        let encoded = STANDARD.encode(credentials);
        format!("Basic {encoded}")
    }
}

impl TryFrom<&ConnectorAuthType> for BluesnapAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self {
                username: key1.to_owned(),
                password: api_key.to_owned(),
            }),
            _ => Err(error_stack::report!(
                errors::ConnectorError::FailedToObtainAuthType
            )),
        }
    }
}

// Status mapping function - mimics Hyperswitch's ForeignTryFrom pattern
fn get_attempt_status_from_bluesnap_status(
    txn_type: BluesnapTxnType,
    processing_status: BluesnapProcessingStatus,
) -> AttemptStatus {
    match processing_status {
        BluesnapProcessingStatus::Success => match txn_type {
            BluesnapTxnType::AuthOnly => AttemptStatus::Authorized,
            BluesnapTxnType::AuthReversal => AttemptStatus::Voided,
            BluesnapTxnType::AuthCapture | BluesnapTxnType::Capture => AttemptStatus::Charged,
            BluesnapTxnType::Refund => AttemptStatus::Charged,
        },
        BluesnapProcessingStatus::Pending | BluesnapProcessingStatus::PendingMerchantReview => {
            AttemptStatus::Pending
        }
        BluesnapProcessingStatus::Fail => AttemptStatus::Failure,
    }
}

// Status mapping for refunds
fn map_bluesnap_refund_status(status: &BluesnapRefundStatus) -> common_enums::RefundStatus {
    match status {
        BluesnapRefundStatus::Success => common_enums::RefundStatus::Success,
        BluesnapRefundStatus::Pending => common_enums::RefundStatus::Pending,
    }
}

// ===== REQUEST TRANSFORMERS =====

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        super::BluesnapRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for BluesnapPaymentsRequest<T>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: super::BluesnapRouterData<
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

        // Determine card_transaction_type based on capture_method
        let card_transaction_type = match router_data.request.capture_method {
            Some(common_enums::CaptureMethod::Manual) => BluesnapTxnType::AuthOnly,
            _ => BluesnapTxnType::AuthCapture,
        };

        // Extract billing address from resource_common_data
        let billing_address = router_data
            .resource_common_data
            .address
            .get_payment_method_billing();

        let card_holder_info = billing_address.as_ref().and_then(|addr| {
            addr.address.as_ref().map(|details| BluesnapCardHolderInfo {
                first_name: details.first_name.clone(),
                last_name: details.last_name.clone(),
                zip: details.zip.clone(),
            })
        });

        // Build payment method details based on payment method type
        let payment_method_details = match &router_data.request.payment_method_data {
            PaymentMethodData::Card(card_data) => {
                // Convert card number to Secret<String>
                let card_number = Secret::new(
                    serde_json::to_string(&card_data.card_number.clone().0)
                        .change_context(errors::ConnectorError::RequestEncodingFailed)?
                        .trim_matches('"')
                        .to_string(),
                );
                BluesnapPaymentMethodDetails::Card {
                    credit_card: BluesnapCreditCard {
                        card_number,
                        security_code: card_data.card_cvc.clone(),
                        expiration_month: card_data.card_exp_month.clone(),
                        expiration_year: card_data.get_expiry_year_4_digit(),
                    },
                }
            }
            PaymentMethodData::Wallet(wallet_data) => match wallet_data {
                domain_types::payment_method_data::WalletData::ApplePay(apple_pay_data) => {
                    let encoded_payment_token = Secret::new(
                        serde_json::to_string(&apple_pay_data.payment_data)
                            .change_context(errors::ConnectorError::RequestEncodingFailed)?,
                    );
                    BluesnapPaymentMethodDetails::Wallet {
                        wallet: BluesnapWallet {
                            apple_pay: Some(requests::BluesnapApplePayWallet {
                                encoded_payment_token,
                            }),
                            google_pay: None,
                            wallet_type: "APPLE_PAY".to_string(),
                        },
                    }
                }
                domain_types::payment_method_data::WalletData::GooglePay(google_pay_data) => {
                    let encoded_payment_token = Secret::new(
                        serde_json::to_string(&google_pay_data.tokenization_data)
                            .change_context(errors::ConnectorError::RequestEncodingFailed)?,
                    );
                    BluesnapPaymentMethodDetails::Wallet {
                        wallet: BluesnapWallet {
                            apple_pay: None,
                            google_pay: Some(requests::BluesnapGooglePayWallet {
                                encoded_payment_token,
                            }),
                            wallet_type: "GOOGLE_PAY".to_string(),
                        },
                    }
                }
                _ => Err(errors::ConnectorError::NotImplemented(
                    "Selected wallet type is not supported".to_string(),
                ))?,
            },
            _ => Err(errors::ConnectorError::NotImplemented(
                "Selected payment method is not supported".to_string(),
            ))?,
        };

        // Convert MinorUnit to StringMajorUnit
        let amount = convert_minor_to_major_unit(
            router_data.request.minor_amount,
            router_data.request.currency,
        )?;

        Ok(Self {
            amount,
            currency: router_data.request.currency.to_string(),
            card_transaction_type,
            payment_method_details,
            card_holder_info,
            transaction_fraud_info: None,
            merchant_transaction_id: None,
            transaction_meta_data: None,
            _phantom: std::marker::PhantomData,
        })
    }
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        super::BluesnapRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    > for BluesnapCaptureRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: super::BluesnapRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;

        let connector_transaction_id = match router_data.request.connector_transaction_id {
            ResponseId::ConnectorTransactionId(ref id) => id.clone(),
            _ => return Err(errors::ConnectorError::MissingConnectorTransactionID.into()),
        };

        // Convert amount for capture - use minor_amount_to_capture
        let amount = Some(convert_minor_to_major_unit(
            router_data.request.minor_amount_to_capture,
            router_data.request.currency,
        )?);

        Ok(Self {
            card_transaction_type: BluesnapTxnType::Capture,
            transaction_id: connector_transaction_id,
            amount,
        })
    }
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        super::BluesnapRouterData<
            RouterDataV2<
                domain_types::connector_flow::Void,
                PaymentFlowData,
                domain_types::connector_types::PaymentVoidData,
                PaymentsResponseData,
            >,
            T,
        >,
    > for BluesnapVoidRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: super::BluesnapRouterData<
            RouterDataV2<
                domain_types::connector_flow::Void,
                PaymentFlowData,
                domain_types::connector_types::PaymentVoidData,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;

        Ok(Self {
            card_transaction_type: BluesnapTxnType::AuthReversal,
            transaction_id: router_data.request.connector_transaction_id.clone(),
        })
    }
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        super::BluesnapRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    > for BluesnapSyncRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        _item: super::BluesnapRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        // Empty request for GET-based sync
        Ok(Self {})
    }
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        super::BluesnapRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    > for BluesnapRefundRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: super::BluesnapRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;

        // Convert amount for partial refund support
        let amount = Some(convert_minor_to_major_unit(
            router_data.request.minor_refund_amount,
            router_data.request.currency,
        )?);

        Ok(Self {
            amount,
            reason: router_data.request.reason.clone(),
        })
    }
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        super::BluesnapRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    > for BluesnapRefundSyncRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        _item: super::BluesnapRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        // Empty request for GET-based sync
        Ok(Self {})
    }
}

// ===== RESPONSE TRANSFORMERS =====

impl<T: PaymentMethodDataTypes>
    TryFrom<
        ResponseRouterData<
            BluesnapAuthorizeResponse,
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
            BluesnapAuthorizeResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        let status = get_attempt_status_from_bluesnap_status(
            item.response.card_transaction_type.clone(),
            item.response.processing_info.processing_status.clone(),
        );

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    item.response.transaction_id.clone(),
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(item.response.transaction_id.clone()),
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

impl
    TryFrom<
        ResponseRouterData<
            BluesnapCaptureResponse,
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    > for RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            BluesnapCaptureResponse,
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let status = get_attempt_status_from_bluesnap_status(
            item.response.card_transaction_type.clone(),
            item.response.processing_info.processing_status.clone(),
        );

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    item.response.transaction_id.clone(),
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(item.response.transaction_id.clone()),
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

impl
    TryFrom<
        ResponseRouterData<
            BluesnapVoidResponse,
            RouterDataV2<
                domain_types::connector_flow::Void,
                PaymentFlowData,
                domain_types::connector_types::PaymentVoidData,
                PaymentsResponseData,
            >,
        >,
    >
    for RouterDataV2<
        domain_types::connector_flow::Void,
        PaymentFlowData,
        domain_types::connector_types::PaymentVoidData,
        PaymentsResponseData,
    >
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            BluesnapVoidResponse,
            RouterDataV2<
                domain_types::connector_flow::Void,
                PaymentFlowData,
                domain_types::connector_types::PaymentVoidData,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        let status = get_attempt_status_from_bluesnap_status(
            item.response.card_transaction_type.clone(),
            item.response.processing_info.processing_status.clone(),
        );

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    item.response.transaction_id.clone(),
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(item.response.transaction_id.clone()),
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

impl
    TryFrom<
        ResponseRouterData<
            BluesnapPSyncResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    > for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            BluesnapPSyncResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let status = get_attempt_status_from_bluesnap_status(
            item.response.card_transaction_type.clone(),
            item.response.processing_info.processing_status.clone(),
        );

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    item.response.transaction_id.clone(),
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(item.response.transaction_id.clone()),
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

impl
    TryFrom<
        ResponseRouterData<
            BluesnapRefundResponse,
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    > for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            BluesnapRefundResponse,
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let refund_status = map_bluesnap_refund_status(&item.response.refund_status);

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.refund_transaction_id.to_string(),
                refund_status,
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

pub fn map_chargeback_status_to_event_type(
    cb_status: &str,
) -> CustomResult<domain_types::connector_types::EventType, errors::ConnectorError> {
    use domain_types::connector_types::EventType;

    let status: BluesnapChargebackStatus =
        serde_json::from_value(serde_json::Value::String(cb_status.to_string()))
            .change_context(errors::ConnectorError::WebhookEventTypeNotFound)?;

    Ok(match status {
        BluesnapChargebackStatus::New | BluesnapChargebackStatus::Working => {
            EventType::DisputeOpened
        }
        BluesnapChargebackStatus::Closed => EventType::DisputeExpired,
        BluesnapChargebackStatus::CompletedLost => EventType::DisputeLost,
        BluesnapChargebackStatus::CompletedPending => EventType::DisputeChallenged,
        BluesnapChargebackStatus::CompletedWon => EventType::DisputeWon,
    })
}

pub fn map_webhook_event_to_incoming_webhook_event(
    webhook_event: &BluesnapWebhookEvent,
) -> domain_types::connector_types::EventType {
    use domain_types::connector_types::EventType;

    match webhook_event {
        BluesnapWebhookEvent::Decline | BluesnapWebhookEvent::CcChargeFailed => {
            EventType::PaymentIntentFailure
        }
        BluesnapWebhookEvent::Charge => EventType::PaymentIntentSuccess,
        BluesnapWebhookEvent::Refund => EventType::RefundSuccess,
        BluesnapWebhookEvent::Chargeback | BluesnapWebhookEvent::ChargebackStatusChanged => {
            EventType::DisputeOpened
        }
        BluesnapWebhookEvent::Unknown => EventType::PaymentIntentFailure,
    }
}

impl
    TryFrom<
        ResponseRouterData<
            BluesnapRefundSyncResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    > for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            BluesnapRefundSyncResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let refund_status = map_bluesnap_refund_status(&item.response.refund_status);

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.refund_transaction_id.to_string(),
                refund_status,
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}
