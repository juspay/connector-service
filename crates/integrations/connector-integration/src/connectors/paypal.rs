pub mod transformers;

use base64::Engine;
use common_enums::{AttemptStatus, CurrencyUnit};
use common_utils::{
    consts::{NO_ERROR_CODE, NO_ERROR_MESSAGE},
    errors::CustomResult,
    events,
    ext_traits::ByteSliceExt,
    StringMajorUnit,
};
#[allow(unused_imports)]
use domain_types::{
    connector_flow::{
        Accept, Authenticate, Authorize, Capture, ClientAuthenticationToken,
        CreateConnectorCustomer, CreateOrder, DefendDispute, IncrementalAuthorization,
        MandateRevoke, PSync, PaymentMethodToken, PostAuthenticate, PreAuthenticate, RSync, Refund,
        RepeatPayment, ServerAuthenticationToken, ServerSessionAuthenticationToken, SetupMandate,
        SubmitEvidence, VerifyWebhookSource, Void, VoidPC,
    },
    connector_types::{
        ClientAuthenticationTokenRequestData, EventContext, PaymentCreateOrderData,
        PaymentCreateOrderResponse, PaymentFlowData, PaymentMethodTokenResponse,
        PaymentMethodTokenizationData, PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData,
        PaymentsPostAuthenticateData, PaymentsResponseData, PaymentsSyncData, RefundFlowData,
        RefundSyncData, RefundsData, RefundsResponseData, RepeatPaymentData, RequestDetails,
        ServerAuthenticationTokenRequestData, ServerAuthenticationTokenResponseData,
        SetupMandateRequestData, VerifyWebhookSourceFlowData,
    },
    merchant_authentication_flow_data::MerchantAuthenticationFlowData,
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes, WalletData},
    router_data::{ConnectorSpecificConfig, ErrorResponse, FlowStatus},
    router_data_v2::RouterDataV2,
    router_request_types::VerifyWebhookSourceRequestData,
    router_response_types::{Response, VerifyWebhookSourceResponseData},
    types::Connectors,
};
use error_stack::{report, ResultExt};
use hyperswitch_masking::{ExposeInterface, ExposeOptionInterface, Mask, Maskable, Secret};
use interfaces::{
    api::ConnectorCommon, connector_integration_v2::ConnectorIntegrationV2, connector_types,
    decode::BodyDecoding, verification::SourceVerification,
};
use serde::Serialize;
use std::fmt::{Debug, Write};

use super::macros;
use crate::{
    connectors::paypal::transformers::{
        self as paypal, auth_headers, constants as paypal_constants, PaypalAuthResponse,
        PaypalAuthUpdateRequest, PaypalAuthUpdateResponse, PaypalCaptureResponse,
        PaypalClientAuthTokenRequest, PaypalClientAuthTokenResponse, PaypalOrderCreateRequest,
        PaypalOrderCreateResponse, PaypalPaymentsCancelResponse, PaypalPaymentsCaptureRequest,
        PaypalPaymentsRequest, PaypalPostAuthenticateResponse, PaypalRefundRequest,
        PaypalRepeatPaymentRequest, PaypalRepeatPaymentResponse, PaypalSetupMandatesResponse,
        PaypalSetupTokenRequest, PaypalSetupTokenResponse, PaypalSyncResponse,
        PaypalZeroMandateRequest, RefundResponse, RefundSyncResponse,
    },
    finalize_connector_response,
    types::ResponseRouterData,
    utils::{self, ConnectorErrorType, ConnectorErrorTypeMapping},
    with_error_response_body,
};
use domain_types::errors::{ConnectorError, IntegrationError, WebhookError};

pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const AUTHORIZATION: &str = "Authorization";
}

pub const BASE64_ENGINE: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentPostAuthenticateV2<T> for Paypal<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ConnectorServiceTrait<T> for Paypal<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAuthorizeV2<T> for Paypal<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentSyncV2 for Paypal<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ClientAuthentication for Paypal<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentVoidV2 for Paypal<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundSyncV2 for Paypal<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundV2 for Paypal<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentCapture for Paypal<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ValidationTrait for Paypal<T>
{
    fn should_do_access_token(&self, _payment_method: Option<common_enums::PaymentMethod>) -> bool {
        true
    }

    /// PayPal-hosted card 3DS uses only the PostAuthenticate leg: the initial Authorize
    /// creates the SCA order and returns the payer-action redirect; once the payer is back,
    /// PostAuthenticate reads `authentication_result` (outcome guard) and the completion
    /// Authorize (`orders/{id}/capture|authorize`) moves the money. Terminates in at most
    /// two steps: PostAuthenticate is always followed by Authorize, which ends the loop.
    /// doc: https://developer.paypal.com/docs/checkout/advanced/customize/3d-secure/api/
    fn next_authentication_step(
        &self,
        auth_type: common_enums::AuthenticationType,
        payment_method: common_enums::PaymentMethod,
        redirect_state: connector_types::RedirectState,
        completed_step: Option<connector_types::AuthenticationStep>,
    ) -> connector_types::AuthenticationStep {
        use connector_types::{AuthenticationStep, RedirectState};

        if auth_type == common_enums::AuthenticationType::ThreeDs
            && payment_method == common_enums::PaymentMethod::Card
        {
            match (redirect_state, completed_step) {
                (_, Some(AuthenticationStep::PostAuthenticate)) => AuthenticationStep::Authorize,
                (
                    RedirectState::RedirectWithParams | RedirectState::RedirectWithoutParams,
                    None,
                ) => AuthenticationStep::PostAuthenticate,
                _ => AuthenticationStep::Authorize,
            }
        } else {
            AuthenticationStep::Authorize
        }
    }
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::SetupMandateV2<T> for Paypal<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RepeatPaymentV2<T> for Paypal<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentTokenV2<T> for Paypal<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::IncomingWebhook for Paypal<T>
{
    fn verify_webhook_source(
        &self,
        _request: RequestDetails,
        _connector_webhook_secret: Option<domain_types::connector_types::ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorSpecificConfig>,
    ) -> Result<bool, error_stack::Report<WebhookError>> {
        // This is a fallback for connectors that don't require external verification
        // For PayPal, this should never be called due to requires_external_verification check
        Err::<bool, _>(
            error_stack::report!(WebhookError::WebhookSourceVerificationFailed)
                .attach_printable(
                    "PayPal requires external API call for webhook verification, not internal verification",
                ),
        )
    }

    fn sample_webhook_body(&self) -> &'static [u8] {
        br#"{"event_type":"PAYMENT.CAPTURE.COMPLETED","resource":{"id":"probe_capture_001","status":"COMPLETED","amount":{"value":"10.00","currency_code":"USD"}}}"#
    }

    fn get_event_type(
        &self,
        request: RequestDetails,
    ) -> Result<domain_types::connector_types::EventType, error_stack::Report<WebhookError>> {
        let details = parse_paypal_webhook(&request.body)?;
        get_paypal_event_type(&details)
    }

    fn get_webhook_event_reference(
        &self,
        request: RequestDetails,
    ) -> Result<
        Option<domain_types::connector_types::WebhookResourceReference>,
        error_stack::Report<WebhookError>,
    > {
        use domain_types::connector_types::{
            DisputeWebhookReference, PaymentWebhookReference, RefundWebhookReference,
            WebhookResourceReference,
        };

        let details = parse_paypal_webhook(&request.body)?;

        // Disputes are read leniently (the deprecated RISK.DISPUTE.CREATED payload need not carry
        // the full dispute object). A dispute references the payment by the PayPal capture id
        // (`seller_transaction_id`) its disputed transactions agree on, else none
        // (techspec UNDECIDED #4).
        // doc: https://developer.paypal.com/docs/api/customer-disputes/v1/#disputes_get
        if details.event_type.resource_kind() == paypal::PaypalWebhookResourceKind::Dispute {
            let dispute = details
                .dispute_fields()
                .change_context(WebhookError::WebhookReferenceIdNotFound)?;
            return Ok(Some(WebhookResourceReference::Dispute(
                DisputeWebhookReference {
                    connector_dispute_id: dispute.dispute_id,
                    connector_transaction_id: dispute
                        .disputed_transactions
                        .as_deref()
                        .and_then(paypal::paypal_dispute_transaction_id),
                },
            )));
        }

        let resource = details
            .resource()
            .change_context(WebhookError::WebhookReferenceIdNotFound)?;
        Ok(match resource {
            // `connector_transaction_id` is the order id on every payment flow of this connector.
            paypal::PaypalResource::Payment(resource) => {
                Some(WebhookResourceReference::Payment(PaymentWebhookReference {
                    connector_transaction_id: resource.order_id(),
                    merchant_transaction_id: resource.invoice_id.clone(),
                    connector_preprocessing_id: None,
                }))
            }
            paypal::PaypalResource::Order(resource) => {
                Some(WebhookResourceReference::Payment(PaymentWebhookReference {
                    connector_transaction_id: Some(resource.id),
                    merchant_transaction_id: None,
                    connector_preprocessing_id: None,
                }))
            }
            paypal::PaypalResource::Refund(resource) => {
                Some(WebhookResourceReference::Refund(RefundWebhookReference {
                    connector_refund_id: Some(resource.id),
                    merchant_refund_id: None,
                    connector_transaction_id: None,
                    merchant_transaction_id: None,
                }))
            }
            paypal::PaypalResource::Dispute(dispute) => {
                Some(WebhookResourceReference::Dispute(DisputeWebhookReference {
                    connector_dispute_id: Some(dispute.dispute_id),
                    connector_transaction_id: paypal::paypal_dispute_transaction_id(
                        &dispute.disputed_transactions,
                    ),
                }))
            }
            paypal::PaypalResource::Unsupported => None,
        })
    }

    fn process_payment_webhook(
        &self,
        request: RequestDetails,
        _connector_webhook_secret: Option<domain_types::connector_types::ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorSpecificConfig>,
        _event_context: Option<EventContext>,
    ) -> Result<
        domain_types::connector_types::WebhookDetailsResponse,
        error_stack::Report<WebhookError>,
    > {
        let details = parse_paypal_webhook(&request.body)?;
        let mut status = get_paypal_payment_webhook_status(details.event_type);

        let (order_id, failure_reason) = match details.event_type.resource_kind() {
            paypal::PaypalWebhookResourceKind::Payment
            | paypal::PaypalWebhookResourceKind::Order => match details
                .resource()
                .change_context(WebhookError::WebhookResourceObjectNotFound)?
            {
                paypal::PaypalResource::Payment(resource) => (
                    resource.order_id(),
                    resource
                        .status_details
                        .as_ref()
                        .and_then(|status_details| status_details.reason.clone()),
                ),
                paypal::PaypalResource::Order(resource) => {
                    // CHECKOUT.ORDER.COMPLETED is read from the order's payments, never
                    // assumed captured (an AUTHORIZE-intent order completes once authorized).
                    if matches!(
                        details.event_type,
                        paypal::PaypalWebhookEventType::CheckoutOrderCompleted
                    ) {
                        status = resource
                            .completed_payment_status()
                            .map(AttemptStatus::from)
                            .unwrap_or(AttemptStatus::Pending);
                    }
                    (Some(resource.id), None)
                }
                paypal::PaypalResource::Refund(_)
                | paypal::PaypalResource::Dispute(_)
                | paypal::PaypalResource::Unsupported => (None, None),
            },
            paypal::PaypalWebhookResourceKind::Refund
            | paypal::PaypalWebhookResourceKind::Dispute
            | paypal::PaypalWebhookResourceKind::Unsupported => (None, None),
        };

        let (error_code, error_message) = if status == AttemptStatus::Failure {
            (
                Some(
                    failure_reason
                        .clone()
                        .unwrap_or_else(|| NO_ERROR_CODE.to_string()),
                ),
                Some(failure_reason.unwrap_or_else(|| NO_ERROR_MESSAGE.to_string())),
            )
        } else {
            (None, None)
        };

        Ok(domain_types::connector_types::WebhookDetailsResponse {
            connector_returned_payment_method_details: None,
            resource_id: order_id
                .map(domain_types::connector_types::ResponseId::ConnectorTransactionId),
            status,
            connector_response_reference_id: None,
            connector_request_reference_id: None,
            mandate_reference: None,
            error_code,
            error_message,
            error_reason: None,
            raw_connector_response: String::from_utf8(request.body).ok(),
            status_code: 200,
            response_headers: None,
            amount_captured: None,
            network_txn_id: None,
            payment_method_update: None,
            sender_payment_instrument_id: None,
        })
    }

    fn process_refund_webhook(
        &self,
        request: RequestDetails,
        _connector_webhook_secret: Option<domain_types::connector_types::ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorSpecificConfig>,
    ) -> Result<
        domain_types::connector_types::RefundWebhookDetailsResponse,
        error_stack::Report<WebhookError>,
    > {
        let details = parse_paypal_webhook(&request.body)?;

        let refund_status =
            get_paypal_refund_webhook_status(details.event_type).ok_or_else(|| {
                report!(WebhookError::WebhookEventTypeNotFound).attach_printable(format!(
                    "{} is not a PayPal refund event",
                    details.event_type
                ))
            })?;

        let refund = match details
            .resource()
            .change_context(WebhookError::WebhookResourceObjectNotFound)?
        {
            paypal::PaypalResource::Refund(refund) => refund,
            paypal::PaypalResource::Payment(_)
            | paypal::PaypalResource::Order(_)
            | paypal::PaypalResource::Dispute(_)
            | paypal::PaypalResource::Unsupported => {
                return Err(report!(WebhookError::WebhookResourceObjectNotFound)
                    .attach_printable("Expected PayPal refund webhook resource"));
            }
        };

        // A refund carries no `processor_response`; its failure reason is `status_details.reason`.
        // doc: https://developer.paypal.com/docs/api/payments/v2/#refunds_get
        let (error_code, error_message) = if refund_status == common_enums::RefundStatus::Failure {
            let reason = refund
                .status_details
                .as_ref()
                .and_then(|status_details| status_details.reason.clone());
            (
                Some(reason.clone().unwrap_or_else(|| NO_ERROR_CODE.to_string())),
                Some(reason.unwrap_or_else(|| NO_ERROR_MESSAGE.to_string())),
            )
        } else {
            (None, None)
        };

        Ok(
            domain_types::connector_types::RefundWebhookDetailsResponse {
                connector_refund_id: Some(refund.id),
                merchant_transaction_id: None,
                status: refund_status,
                connector_response_reference_id: None,
                error_code,
                error_message,
                raw_connector_response: String::from_utf8(request.body).ok(),
                status_code: 200,
                response_headers: None,
            },
        )
    }

    fn process_dispute_webhook(
        &self,
        request: RequestDetails,
        _connector_webhook_secret: Option<domain_types::connector_types::ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorSpecificConfig>,
    ) -> Result<
        domain_types::connector_types::DisputeWebhookDetailsResponse,
        error_stack::Report<WebhookError>,
    > {
        let details = parse_paypal_webhook(&request.body)?;

        let status = match get_paypal_event_type(&details)? {
            domain_types::connector_types::EventType::DisputeOpened => {
                common_enums::DisputeStatus::DisputeOpened
            }
            domain_types::connector_types::EventType::DisputeChallenged => {
                common_enums::DisputeStatus::DisputeChallenged
            }
            domain_types::connector_types::EventType::DisputeWon => {
                common_enums::DisputeStatus::DisputeWon
            }
            domain_types::connector_types::EventType::DisputeLost => {
                common_enums::DisputeStatus::DisputeLost
            }
            domain_types::connector_types::EventType::DisputeCancelled => {
                common_enums::DisputeStatus::DisputeCancelled
            }
            domain_types::connector_types::EventType::DisputeAccepted => {
                common_enums::DisputeStatus::DisputeAccepted
            }
            domain_types::connector_types::EventType::DisputeExpired => {
                common_enums::DisputeStatus::DisputeExpired
            }
            other => {
                return Err(
                    report!(WebhookError::WebhookEventTypeNotFound).attach_printable(format!(
                        "PayPal event {other:?} does not carry a dispute state"
                    )),
                );
            }
        };

        let dispute = match details
            .resource()
            .change_context(WebhookError::WebhookResourceObjectNotFound)?
        {
            paypal::PaypalResource::Dispute(payload) => payload,
            paypal::PaypalResource::Payment(_)
            | paypal::PaypalResource::Order(_)
            | paypal::PaypalResource::Refund(_)
            | paypal::PaypalResource::Unsupported => {
                return Err(report!(WebhookError::WebhookResourceObjectNotFound)
                    .attach_printable("Expected PayPal dispute webhook resource"));
            }
        };

        let amount_minor = domain_types::utils::convert_back_amount_to_minor_units_for_webhook(
            &common_utils::types::StringMajorUnitForConnector,
            dispute.dispute_amount.value,
            dispute.dispute_amount.currency_code,
        )?;
        let amount = domain_types::utils::convert_amount_for_webhook(
            &common_utils::types::StringMinorUnitForConnector,
            amount_minor,
            dispute.dispute_amount.currency_code,
        )?;

        let stage = match dispute.dispute_life_cycle_stage {
            paypal::DisputeLifeCycleStage::Inquiry => common_enums::DisputeStage::PreDispute,
            paypal::DisputeLifeCycleStage::Chargeback => common_enums::DisputeStage::Dispute,
            paypal::DisputeLifeCycleStage::PreArbitration
            | paypal::DisputeLifeCycleStage::Arbitration => {
                common_enums::DisputeStage::PreArbitration
            }
        };

        Ok(
            domain_types::connector_types::DisputeWebhookDetailsResponse {
                amount,
                currency: dispute.dispute_amount.currency_code,
                dispute_id: dispute.dispute_id,
                status,
                stage,
                connector_response_reference_id: None,
                dispute_message: dispute.reason,
                raw_connector_response: String::from_utf8(request.body).ok(),
                status_code: 200,
                response_headers: None,
                connector_reason_code: None,
                additional_details: None,
            },
        )
    }

    fn get_webhook_resource_object(
        &self,
        request: RequestDetails,
    ) -> Result<Box<dyn hyperswitch_masking::ErasedMaskSerialize>, error_stack::Report<WebhookError>>
    {
        let details = parse_paypal_webhook(&request.body)?;
        let resource: Box<dyn hyperswitch_masking::ErasedMaskSerialize> = Box::new(details);
        Ok(resource)
    }
}

fn parse_paypal_webhook(
    body: &[u8],
) -> Result<paypal::PaypalWebhooksBody, error_stack::Report<WebhookError>> {
    body.parse_struct("PaypalWebhooksBody")
        .change_context(WebhookError::WebhookBodyDecodingFailed)
}

/// doc: https://developer.paypal.com/api/rest/webhooks/event-names/
fn get_paypal_event_type(
    details: &paypal::PaypalWebhooksBody,
) -> Result<domain_types::connector_types::EventType, error_stack::Report<WebhookError>> {
    use domain_types::connector_types::EventType as E;
    use paypal::PaypalWebhookEventType as P;
    Ok(match details.event_type {
        P::PaymentCaptureCompleted => E::PaymentIntentSuccess,
        // COMPLETED says the intent finished, not that money moved: read the order's payments
        // the way PSync does. doc: https://developer.paypal.com/docs/api/orders/v2/#orders_get
        P::CheckoutOrderCompleted => {
            let order = match details
                .resource()
                .change_context(WebhookError::WebhookEventTypeNotFound)?
            {
                paypal::PaypalResource::Order(order) => order,
                paypal::PaypalResource::Payment(_)
                | paypal::PaypalResource::Refund(_)
                | paypal::PaypalResource::Dispute(_)
                | paypal::PaypalResource::Unsupported => {
                    return Err(report!(WebhookError::WebhookEventTypeNotFound)
                        .attach_printable("Expected PayPal checkout-order webhook resource"));
                }
            };
            // Same buckets as the shared `From<PaypalPaymentStatus> for AttemptStatus` map.
            use paypal::PaypalPaymentStatus as S;
            match order.completed_payment_status() {
                Some(S::Completed | S::Captured | S::Refunded | S::PartiallyRefunded) => {
                    E::PaymentIntentSuccess
                }
                Some(S::Created) => E::PaymentIntentAuthorizationSuccess,
                Some(S::Declined | S::Failed | S::Denied | S::Expired) => E::PaymentIntentFailure,
                Some(S::Voided) => E::PaymentIntentCancelled,
                Some(S::Pending | S::PartiallyCaptured | S::Unknown) => E::PaymentIntentProcessing,
                None => E::IncomingWebhookEventUnspecified,
            }
        }
        P::PaymentCapturePending | P::CheckoutOrderProcessed => E::PaymentIntentProcessing,
        P::PaymentCaptureDeclined | P::PaymentCaptureDenied => E::PaymentIntentFailure,
        P::PaymentAuthorizationCreated => E::PaymentIntentAuthorizationSuccess,
        P::PaymentAuthorizationVoided => E::PaymentIntentCancelled,
        P::PaymentCaptureRefunded | P::PaymentRefundCompleted => E::RefundSuccess,
        P::PaymentRefundFailed => E::RefundFailure,
        P::PaymentRefundPending => E::RefundProcessing,
        // A reversal is a chargeback signal; the chargeback itself arrives as CUSTOMER.DISPUTE.*.
        P::PaymentCaptureReversed | P::CheckoutOrderApproved | P::Unknown => {
            E::IncomingWebhookEventUnspecified
        }
        // RISK.DISPUTE.CREATED is the deprecated form of CUSTOMER.DISPUTE.CREATED.
        P::CustomerDisputeCreated | P::RiskDisputeCreated => E::DisputeOpened,
        P::CustomerDisputedUpdated => {
            match details
                .dispute_fields()
                .change_context(WebhookError::WebhookEventTypeNotFound)?
                .status
            {
                Some(paypal::DisputeStatus::UnderReview) => E::DisputeChallenged,
                Some(
                    paypal::DisputeStatus::Open
                    | paypal::DisputeStatus::WaitingForBuyerResponse
                    | paypal::DisputeStatus::WaitingForSellerResponse
                    | paypal::DisputeStatus::Resolved
                    | paypal::DisputeStatus::Other
                    | paypal::DisputeStatus::Unknown,
                )
                | None => E::DisputeOpened,
            }
        }
        // The outcome is nested at `resource.dispute_outcome.outcome_code`.
        // doc: https://developer.paypal.com/docs/api/customer-disputes/v1/#disputes_get
        P::CustomerDisputeResolved => match details
            .dispute_fields()
            .change_context(WebhookError::WebhookEventTypeNotFound)?
            .dispute_outcome
            .map(|outcome| outcome.outcome_code)
        {
            Some(paypal::OutcomeCode::ResolvedSellerFavour) => E::DisputeWon,
            Some(
                paypal::OutcomeCode::ResolvedBuyerFavour | paypal::OutcomeCode::ResolvedWithPayout,
            ) => E::DisputeLost,
            Some(paypal::OutcomeCode::CanceledByBuyer | paypal::OutcomeCode::NONE) => {
                E::DisputeCancelled
            }
            // Deprecated outcome codes.
            Some(paypal::OutcomeCode::ACCEPTED) => E::DisputeAccepted,
            Some(paypal::OutcomeCode::DENIED) => E::DisputeCancelled,
            Some(paypal::OutcomeCode::Unknown) | None => E::IncomingWebhookEventUnspecified,
        },
    })
}

fn get_paypal_payment_webhook_status(event: paypal::PaypalWebhookEventType) -> AttemptStatus {
    use paypal::PaypalWebhookEventType as P;
    match event {
        P::PaymentCaptureCompleted => AttemptStatus::Charged,
        // CHECKOUT.ORDER.COMPLETED: process_payment_webhook reads the status from the order.
        P::PaymentCapturePending | P::CheckoutOrderProcessed | P::CheckoutOrderCompleted => {
            AttemptStatus::Pending
        }
        P::PaymentCaptureDeclined | P::PaymentCaptureDenied => AttemptStatus::Failure,
        P::PaymentAuthorizationCreated => AttemptStatus::Authorized,
        P::PaymentAuthorizationVoided => AttemptStatus::Voided,
        // No payment-state change: refund and dispute events are handled by their own
        // processors, and a reversal, an approved order or an unknown event moves no attempt.
        P::PaymentCaptureReversed
        | P::CheckoutOrderApproved
        | P::PaymentCaptureRefunded
        | P::PaymentRefundCompleted
        | P::PaymentRefundPending
        | P::PaymentRefundFailed
        | P::CustomerDisputeCreated
        | P::CustomerDisputeResolved
        | P::CustomerDisputedUpdated
        | P::RiskDisputeCreated
        | P::Unknown => AttemptStatus::Pending,
    }
}

/// doc: https://developer.paypal.com/api/rest/webhooks/event-names/#link-refunds
fn get_paypal_refund_webhook_status(
    event: paypal::PaypalWebhookEventType,
) -> Option<common_enums::RefundStatus> {
    use paypal::PaypalWebhookEventType as P;
    match event {
        P::PaymentCaptureRefunded | P::PaymentRefundCompleted => {
            Some(common_enums::RefundStatus::Success)
        }
        P::PaymentRefundPending => Some(common_enums::RefundStatus::Pending),
        P::PaymentRefundFailed => Some(common_enums::RefundStatus::Failure),
        P::PaymentAuthorizationCreated
        | P::PaymentAuthorizationVoided
        | P::PaymentCaptureCompleted
        | P::PaymentCapturePending
        | P::PaymentCaptureDeclined
        | P::PaymentCaptureDenied
        | P::PaymentCaptureReversed
        | P::CheckoutOrderCompleted
        | P::CheckoutOrderProcessed
        | P::CheckoutOrderApproved
        | P::CustomerDisputeCreated
        | P::CustomerDisputeResolved
        | P::CustomerDisputedUpdated
        | P::RiskDisputeCreated
        | P::Unknown => None,
    }
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::VerifyRedirectResponse for Paypal<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> SourceVerification
    for Paypal<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> BodyDecoding
    for Paypal<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentOrderCreate for Paypal<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ServerAuthentication for Paypal<T>
{
}
macros::create_all_prerequisites!(
    connector_name: Paypal,
    generic_type: T,
    api: [
        (
            flow: CreateOrder,
            request_body: PaypalOrderCreateRequest,
            response_body: PaypalOrderCreateResponse,
            router_data: RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>,
        ),
        (
            flow: Authorize,
            request_body: PaypalPaymentsRequest<T>,
            response_body: PaypalAuthResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: PSync,
            response_body: PaypalSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ),
        (
            flow: PostAuthenticate,
            response_body: PaypalPostAuthenticateResponse,
            router_data: RouterDataV2<PostAuthenticate, PaymentFlowData, PaymentsPostAuthenticateData<T>, PaymentsResponseData>,
        ),
        (
            flow: Capture,
            request_body: PaypalPaymentsCaptureRequest,
            response_body: PaypalCaptureResponse,
            response_router_data: connector,
            router_data: RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ),
        (
            flow: Void,
            response_body: PaypalPaymentsCancelResponse,
            router_data: RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ),
        (
            flow: ServerAuthenticationToken,
            request_body: PaypalAuthUpdateRequest,
            response_body: PaypalAuthUpdateResponse,
            router_data: RouterDataV2<ServerAuthenticationToken, MerchantAuthenticationFlowData, ServerAuthenticationTokenRequestData, ServerAuthenticationTokenResponseData>,
        ),
        (
            flow: Refund,
            request_body: PaypalRefundRequest,
            response_body: RefundResponse,
            router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ),
        (
            flow: RSync,
            response_body: RefundSyncResponse,
            router_data: RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ),
        (
            flow: SetupMandate,
            request_body: PaypalZeroMandateRequest,
            response_body: PaypalSetupMandatesResponse,
            router_data: RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>,
        ),
        (
            flow: RepeatPayment,
            request_body: PaypalRepeatPaymentRequest<T>,
            response_body: PaypalRepeatPaymentResponse,
            router_data: RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData<T>, PaymentsResponseData>,
        ),
        (
            flow: PaymentMethodToken,
            request_body: PaypalSetupTokenRequest<T>,
            response_body: PaypalSetupTokenResponse,
            router_data: RouterDataV2<PaymentMethodToken, PaymentFlowData, PaymentMethodTokenizationData<T>, PaymentMethodTokenResponse>,
        ),
        (
            flow: ClientAuthenticationToken,
            request_body: PaypalClientAuthTokenRequest,
            response_body: PaypalClientAuthTokenResponse,
            router_data: RouterDataV2<ClientAuthenticationToken, MerchantAuthenticationFlowData, ClientAuthenticationTokenRequestData, PaymentsResponseData>,
        )
    ],
    amount_converters: [
        amount_converter: StringMajorUnit
    ],
    member_functions: {
        /// Common Bearer-token headers. `idempotency_key` is the `PayPal-Request-Id`
        /// for a POST (derive it with `paypal::paypal_idempotency_key`, one per API
        /// call type); pass `None` for GET calls, which carry no idempotency key.
        pub fn build_headers(
            &self,
            access_token: &str,
            idempotency_key: Option<&str>,
            connector_config: &ConnectorSpecificConfig,
            connector_metadata: Option<&serde_json::Value>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, IntegrationError> {
            let auth = paypal::PaypalAuthType::try_from(connector_config)?;
            let mut headers = vec![
                (
                    headers::CONTENT_TYPE.to_string(),
                    self.common_get_content_type().to_string().into(),
                ),
                (
                    headers::AUTHORIZATION.to_string(),
                    format!("Bearer {access_token}").into_masked(),
                ),
                (
                    auth_headers::PREFER.to_string(),
                    "return=representation".to_string().into(),
                ),
            ];
            if let Some(idempotency_key) = idempotency_key {
                headers.push((
                    auth_headers::PAYPAL_REQUEST_ID.to_string(),
                    idempotency_key.to_string().into_masked(),
                ));
            }
            if let Ok(paypal::PaypalConnectorCredentials::PartnerIntegration(credentials)) =
                auth.get_credentials()
            {
                let auth_assertion_header =
                    construct_auth_assertion_header(&credentials.payer_id, &credentials.client_id);

                let partner_attribution_id = connector_metadata
                    .and_then(|metadata| metadata.get("paypal_partner_attribution_id"))
                    .and_then(|value| value.as_str())
                    .unwrap_or(paypal_constants::DEFAULT_PARTNER_ATTRIBUTION_ID);

                headers.extend(vec![
                    (
                        auth_headers::PAYPAL_AUTH_ASSERTION.to_string(),
                        auth_assertion_header.to_string().into_masked(),
                    ),
                    (
                        auth_headers::PAYPAL_PARTNER_ATTRIBUTION_ID.to_string(),
                        partner_attribution_id.to_string().into(),
                    ),
                ])
            } else {
                let legacy_attribution_id = connector_metadata
                    .and_then(|metadata| metadata.get("paypal_legacy_partner_attribution_id"))
                    .and_then(|value| value.as_str())
                    .unwrap_or(paypal_constants::DEFAULT_LEGACY_PARTNER_ATTRIBUTION_ID);

                headers.extend(vec![(
                    auth_headers::PAYPAL_PARTNER_ATTRIBUTION_ID.to_string(),
                    legacy_attribution_id.to_string().into(),
                )])
            }
            Ok(headers)
        }

        pub fn connector_base_url_payments<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.paypal.base_url
        }

        pub fn connector_base_url_refunds<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, RefundFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.paypal.base_url
        }

        pub fn connector_base_url_merchant_auth<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, MerchantAuthenticationFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.paypal.base_url
        }

     /// Orders v2 error body -> `ErrorResponse`. `error_flow` selects the issue -> attempt
     /// status table (`paypal::paypal_error_attempt_status`); `None` keeps the
     /// constant `Failure` used by CreateOrder.
     pub fn get_order_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut events::Event>,
        error_flow: Option<paypal::PaypalErrorFlow>,
    ) -> CustomResult<ErrorResponse, ConnectorError> {
        //Handled error response separately for Orders as the end point is different for Orders - (Authorize) and Payments - (Capture, void, refund, rsync).
        //Error response have different fields for Orders and Payments.
        let parsed: Result<paypal::PaypalOrderErrorResponse, _> =
            res.response.parse_struct("Paypal ErrorResponse");
        let response = match parsed {
            Ok(response) => response,
            // A 5xx whose body is not PayPal JSON is still an unknown outcome:
            // keep the flow's Pending mapping instead of RESPONSE_HANDLING_FAILED (B025).
            Err(parse_error) if res.status_code >= 500 => {
                let attempt_status = match error_flow {
                    Some(error_flow) => {
                        paypal::paypal_error_attempt_status(error_flow, res.status_code, &[])
                    }
                    None => Some(FlowStatus::Payment(AttemptStatus::Failure)),
                };
                return Ok(paypal_5xx_unparsed_error_response(
                    res.status_code,
                    attempt_status,
                    &res.response,
                    &parse_error,
                ));
            }
            Err(err) => {
                return Err(err.change_context(utils::response_handling_fail_for_connector(
                    res.status_code,
                    "paypal",
                )))
            }
        };

        with_error_response_body!(event_builder, response);

        let typed = macros::serialize_typed_connector_payload(&response, "typed_connector_response");
        let error_reason = response.details.clone().map(|order_errors| {
            order_errors
                .iter()
                .map(|error| {
                    let mut reason = format!(
                        "description - {}",
                        error.description.as_deref().unwrap_or(error.issue.as_str())
                    );
                    if let Some(value) = &error.value {
                        reason.push_str(&format!(", value - {value}"));
                    }
                    if let Some(field) = error
                        .field
                        .as_ref()
                        .and_then(|field| field.split('/').next_back())
                    {
                        reason.push_str(&format!(", field - {field}"));
                    }
                    reason.push(';');
                    reason
                })
                .collect::<String>()
        });
        let errors_list = response.details.unwrap_or_default();
        let attempt_status = match error_flow {
            Some(error_flow) => {
                let issues: Vec<paypal::PaypalErrorIssue> = errors_list
                    .iter()
                    .map(|error| paypal::PaypalErrorIssue::from_issue(&error.issue))
                    .collect();
                paypal::paypal_error_attempt_status(error_flow, res.status_code, &issues)
            }
            None => Some(FlowStatus::Payment(AttemptStatus::Failure)),
        };
        let option_error_code_message =
            utils::get_error_code_error_message_based_on_priority(
                self.clone(),
                errors_list
                    .into_iter()
                    .map(|errors| errors.into())
                    .collect(),
            );
        Ok(ErrorResponse {
            status_code: res.status_code,
            code: option_error_code_message
                .clone()
                .map(|error_code_message| error_code_message.error_code)
                .unwrap_or(NO_ERROR_CODE.to_string()),
            message: option_error_code_message
                .map(|error_code_message| error_code_message.error_message)
                .unwrap_or(NO_ERROR_MESSAGE.to_string()),
            reason: error_reason.or(Some(response.message)),
            attempt_status,
            // debug_id is PayPal's correlation id, not a resource id (B022)
            connector_transaction_id: None,
            network_advice_code: None,
            network_decline_code: None,
            network_error_message: None,
            typed_connector_response: typed,
            raw_connector_response: None,
            raw_connector_request: None,
            typed_connector_request: None,
        })
    }
    }
);

/// Completion intent for an Authorize that completes an existing order: the intent
/// recorded in `connector_feature_data` (PaypalMeta.order_intent) when present, else the
/// payment's capture method.
fn paypal_completion_intent<T: PaymentMethodDataTypes>(
    req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
) -> paypal::PaypalPaymentIntent {
    let recorded = [
        req.resource_common_data.connector_feature_data.as_ref(),
        req.request.connector_feature_data.as_ref(),
    ]
    .into_iter()
    .flatten()
    .map(|secret| secret.clone().expose())
    .find(|data| data.get("order_intent").is_some());
    paypal::paypal_completion_intent(recorded.as_ref(), req.request.is_auto_capture())
}

// Manual implementation for Authorize with conditional request body
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        Authorize,
        PaymentFlowData,
        PaymentsAuthorizeData<T>,
        PaymentsResponseData,
    > for Paypal<T>
{
    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Post
    }

    fn get_headers(
        &self,
        req: &RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData<T>,
            PaymentsResponseData,
        >,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, IntegrationError> {
        let access_token = req.resource_common_data.access_token.clone().ok_or(
            IntegrationError::FailedToObtainAuthType {
                context: Default::default(),
            },
        )?;
        let connector_metadata = req
            .resource_common_data
            .connector_feature_data
            .as_ref()
            .map(|secret| secret.clone().expose());
        let reference = &req.resource_common_data.connector_request_reference_id;
        // Creating the order and completing an approved order are different PayPal API
        // call types, so they must not share a PayPal-Request-Id.
        let completes_existing_order = matches!(
            req.request.payment_method_data,
            PaymentMethodData::Wallet(WalletData::PaypalSdk(_))
        ) || req.resource_common_data.connector_order_id.is_some();
        let intent = if completes_existing_order {
            paypal_completion_intent(req)
        } else {
            paypal::paypal_order_intent(req.request.is_auto_capture())
        };
        // The completion key is anchored on the order id in the URL (SDK token or
        // connector_order_id), so two orders completed with an empty reference never
        // share a key (b4-02).
        let order_id = match &req.request.payment_method_data {
            PaymentMethodData::Wallet(WalletData::PaypalSdk(paypal_wallet_data)) => {
                Some(paypal_wallet_data.token.as_str())
            }
            _ => req.resource_common_data.connector_order_id.as_deref(),
        };
        let kind = if completes_existing_order {
            paypal::PaypalRequestIdKind::CompleteOrder {
                order_id,
                intent: &intent,
            }
        } else {
            paypal::PaypalRequestIdKind::CreateOrder
        };
        let idempotency_key = paypal::paypal_idempotency_key(reference, kind);
        self.build_headers(
            &access_token.access_token.expose(),
            Some(&idempotency_key),
            &req.connector_config,
            connector_metadata.as_ref(),
        )
    }

    fn get_url(
        &self,
        req: &RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData<T>,
            PaymentsResponseData,
        >,
    ) -> CustomResult<String, IntegrationError> {
        // Completing an order must use the action matching the order's intent
        // (ACTION_DOES_NOT_MATCH_INTENT); see `paypal::paypal_completion_intent`.
        let action = match paypal_completion_intent(req) {
            paypal::PaypalPaymentIntent::Capture => "capture",
            paypal::PaypalPaymentIntent::Authorize | paypal::PaypalPaymentIntent::Authenticate => {
                "authorize"
            }
        };

        let base = self.connector_base_url_payments(req);

        let path = if let PaymentMethodData::Wallet(WalletData::PaypalSdk(paypal_wallet_data)) =
            &req.request.payment_method_data
        {
            // Case 1: PaypalSdk wallet - complete order using SDK token
            format!("v2/checkout/orders/{}/{}", paypal_wallet_data.token, action)
        } else if let Some(order_id) = &req.resource_common_data.connector_order_id {
            // Case 2: Completing an existing/redirect-approved order (order_id set on the order)
            format!("v2/checkout/orders/{order_id}/{action}")
        } else {
            // Case 3: Creating new order
            "v2/checkout/orders".to_owned()
        };

        Ok(format!("{base}{path}"))
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData<T>,
            PaymentsResponseData,
        >,
    ) -> CustomResult<Option<common_utils::request::ConnectorRequestData>, IntegrationError> {
        let body = if matches!(
            req.request.payment_method_data,
            PaymentMethodData::Wallet(WalletData::PaypalSdk(_))
        ) {
            // PaypalSdk wallet: no body needed, buyer approved via SDK
            None
        } else if let Some(order_id) = &req.resource_common_data.connector_order_id {
            // G-ThreeDS-02 (deny by default): completing an order moves money and PayPal does
            // not refuse an order whose payer never authenticated. Only approval flows (payer
            // approves on PayPal, the wallet, or the bank) are exempt; every other arm needs the
            // outcome PostAuthenticate accepted for this same order.
            if !paypal::paypal_completion_exempt_from_3ds(&req.request.payment_method_data)
                && !paypal::paypal_completion_has_accepted_3ds(
                    req.request.authentication_data.as_ref(),
                    order_id,
                )
            {
                return Err(report!(IntegrationError::MissingRequiredField {
                    field_name: "authentication_data",
                    context: domain_types::errors::IntegrationErrorContext {
                        suggested_action: Some(
                            "Run PostAuthenticate for this PayPal order first and pass its \
                             authentication_data (connector_transaction_id = connector_order_id, \
                             trans_status SUCCESS, NOT_VERIFIED or VERIFICATION_NOT_PERFORMED)"
                                .to_string(),
                        ),
                        doc_url: Some(
                            "https://developer.paypal.com/docs/checkout/advanced/customize/3d-secure/response-parameters/"
                                .to_string(),
                        ),
                        additional_context: Some(format!(
                            "{} 3DS completion refused before any call: no accepted 3DS \
                             outcome for this order",
                            domain_types::types::PaymentMethodDataType::from(
                                req.request.payment_method_data.clone()
                            )
                        )),
                    },
                }));
            }
            None
        } else {
            // Build full request body for creating new order (like HS Authorize)
            let connector_router_data = PaypalRouterData {
                connector: self.to_owned(),
                router_data: req.to_owned(),
            };
            let connector_req = PaypalPaymentsRequest::try_from(connector_router_data)?;
            let typed = events::MaskedSerdeValue::from_masked_optional(
                &connector_req,
                "typed_connector_request",
            );

            Some(common_utils::request::ConnectorRequestData::new(
                common_utils::request::RequestContent::Json(Box::new(connector_req)),
                typed,
            ))
        };

        Ok(body)
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData<T>,
            PaymentsResponseData,
        >,
        event_builder: Option<&mut events::Event>,
        res: Response,
    ) -> CustomResult<
        RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ConnectorError,
    > {
        let response: PaypalAuthResponse = res
            .response
            .parse_struct("PaypalAuthResponse")
            .change_context(utils::response_handling_fail_for_connector(
                res.status_code,
                "paypal",
            ))?;

        finalize_connector_response!(event_builder, response, data, res.status_code)
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut events::Event>,
        _connector_config: &ConnectorSpecificConfig,
    ) -> CustomResult<ErrorResponse, ConnectorError> {
        self.get_order_error_response(res, event_builder, Some(paypal::PaypalErrorFlow::Authorize))
    }

    // 5xx: outcome unknown (the resource may exist) -> the flow's PayPal error table
    // (P-foundation-04: 5xx -> Pending), never the framework default's None (B025).
    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut events::Event>,
        connector_config: &ConnectorSpecificConfig,
    ) -> CustomResult<ErrorResponse, ConnectorError> {
        <Self as ConnectorIntegrationV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData<T>,
            PaymentsResponseData,
        >>::get_error_response_v2(self, res, event_builder, connector_config)
    }
}

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type],
    connector: Paypal,
    curl_request: FormUrlEncoded(PaypalAuthUpdateRequest),
    curl_response: PaypalAuthUpdateResponse,
    flow_name: ServerAuthenticationToken,
    resource_common_data: MerchantAuthenticationFlowData,
    flow_request: ServerAuthenticationTokenRequestData,
    flow_response: ServerAuthenticationTokenResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<ServerAuthenticationToken, MerchantAuthenticationFlowData, ServerAuthenticationTokenRequestData, ServerAuthenticationTokenResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, IntegrationError> {
            let auth = paypal::PaypalAuthType::try_from(&req.connector_config)?;
            let credentials = auth.get_credentials()?;
            let auth_val = credentials.generate_authorization_value();

            Ok(vec![
                (
                    headers::CONTENT_TYPE.to_string(),
                    "application/x-www-form-urlencoded".to_string().into(),
                ),
                (headers::AUTHORIZATION.to_string(), auth_val.into_masked()),
            ])
        }
        fn get_url(
            &self,
            req: &RouterDataV2<ServerAuthenticationToken, MerchantAuthenticationFlowData, ServerAuthenticationTokenRequestData, ServerAuthenticationTokenResponseData>,
        ) -> CustomResult<String, IntegrationError> {
            Ok(format!("{}v1/oauth2/token", self.connector_base_url_merchant_auth(req)))
        }
        fn get_error_response_v2(
                &self,
                res: Response,
                event_builder: Option<&mut events::Event>,
                _connector_config: &ConnectorSpecificConfig,
    ) -> CustomResult<ErrorResponse, ConnectorError> {
                let response: paypal::PaypalAccessTokenErrorResponse = res
                .response
                .parse_struct("Paypal AccessTokenErrorResponse")
                .change_context(utils::response_handling_fail_for_connector(res.status_code, "paypal"))?;

        with_error_response_body!(event_builder, response);

        let typed = macros::serialize_typed_connector_payload(&response, "typed_connector_response");
        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response.error.clone(),
            message: response.error.clone(),
            reason: Some(response.error_description),
            attempt_status: None,
            connector_transaction_id: None,
            network_advice_code: None,
            network_decline_code: None,
            network_error_message: None,
            typed_connector_response: typed,
            raw_connector_response: None,
            raw_connector_request: None,
            typed_connector_request: None,
        })
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Paypal,
    curl_response: PaypalSyncResponse,
    flow_name: PSync,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsSyncData,
    flow_response: PaymentsResponseData,
    http_method: Get,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, IntegrationError> {
            let access_token = req.resource_common_data
                .access_token
                .clone()
                .ok_or(IntegrationError::FailedToObtainAuthType { context: Default::default() })?;
            let connector_metadata = req.resource_common_data.connector_feature_data
                .as_ref()
                .map(|secret| secret.clone().expose());
            self.build_headers(
                &access_token.access_token.expose(),
                // GET: no PayPal-Request-Id.
                None,
                &req.connector_config,
                connector_metadata.as_ref(),
            )
        }
        fn get_url(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<String, IntegrationError> {
            let paypal_meta: paypal::PaypalMeta = utils::to_connector_meta(req.request.connector_feature_data.clone().map(|m| m.expose()))?;
        match req.resource_common_data.payment_method {
            common_enums::PaymentMethod::Wallet | common_enums::PaymentMethod::BankRedirect => Ok(format!(
                "{}v2/checkout/orders/{}",
                self.connector_base_url_payments(req),
                req.request
                    .connector_transaction_id
                    .get_connector_transaction_id()
                    .change_context(IntegrationError::MissingConnectorTransactionID { context: Default::default() })?
            )),
            _ => {
                let psync_url = match paypal_meta.psync_flow {
                    // G-PSync-01: for a card payment the PayPal resource to read is the
                    // authorization or capture, not the order; refuse before any call when the
                    // id recorded by the previous flow is missing.
                    transformers::PaypalPaymentIntent::Authorize => {
                        let authorize_id = paypal_meta.authorize_id.ok_or_else(|| {
                            IntegrationError::MissingRequiredField {
                                field_name: "connector_feature_data.authorize_id",
                                context: domain_types::errors::IntegrationErrorContext {
                                    suggested_action: Some(
                                        "Pass the connector_feature_data returned by the PayPal \
                                         Authorize response; it carries the authorization id"
                                            .to_string(),
                                    ),
                                    doc_url: Some(
                                        "https://developer.paypal.com/docs/api/payments/v2/#authorizations_get"
                                            .to_string(),
                                    ),
                                    additional_context: Some(
                                        "psync_flow is AUTHORIZE but authorize_id is absent".to_string(),
                                    ),
                                },
                            }
                        })?;
                        format!("v2/payments/authorizations/{authorize_id}")
                    }
                    transformers::PaypalPaymentIntent::Capture => {
                        let capture_id = paypal_meta.capture_id.ok_or_else(|| {
                            IntegrationError::MissingRequiredField {
                                field_name: "connector_feature_data.capture_id",
                                context: domain_types::errors::IntegrationErrorContext {
                                    suggested_action: Some(
                                        "Pass the connector_feature_data returned by the PayPal \
                                         Authorize or Capture response; it carries the capture id"
                                            .to_string(),
                                    ),
                                    doc_url: Some(
                                        "https://developer.paypal.com/docs/api/payments/v2/#captures_get"
                                            .to_string(),
                                    ),
                                    additional_context: Some(
                                        "psync_flow is CAPTURE but capture_id is absent".to_string(),
                                    ),
                                },
                            }
                        })?;
                        format!("v2/payments/captures/{capture_id}")
                    }
                    // only set when payment is done through card 3DS
                    //because no authorize or capture id is generated during payment authorize call for card 3DS
                    transformers::PaypalPaymentIntent::Authenticate => {
                        format!(
                            "v2/checkout/orders/{}",
                            req.request
                                .connector_transaction_id
                                .get_connector_transaction_id()
                                .change_context(
                                    IntegrationError::MissingConnectorTransactionID { context: Default::default() }
                                )?
                        )
                    }
                };
                Ok(format!("{}{psync_url}", self.connector_base_url_payments(req)))
            }
        }
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type],
    connector: Paypal,
    curl_request: Json(PaypalPaymentsCaptureRequest),
    curl_response: PaypalCaptureResponse,
    flow_name: Capture,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsCaptureData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, IntegrationError> {
            let access_token = req.resource_common_data
                .access_token
                .clone()
                .ok_or(IntegrationError::FailedToObtainAuthType { context: Default::default() })?;
            let connector_metadata = req.resource_common_data.connector_feature_data
                .as_ref()
                .map(|secret| secret.clone().expose());
            // One PayPal-Request-Id per (authorization, call type): a retried capture
            // replays rather than duplicates, and two payments never share a key even
            // when merchant_capture_id is omitted (b4-02). A missing authorize_id is
            // refused by get_url before any call.
            let authorization_id = utils::to_connector_meta::<paypal::PaypalMeta>(
                req.request.connector_feature_data.clone().map(|m| m.expose()),
            )
            .ok()
            .and_then(|meta| meta.authorize_id);
            let idempotency_key = paypal::paypal_idempotency_key(
                &req.resource_common_data.connector_request_reference_id,
                paypal::PaypalRequestIdKind::Capture {
                    authorization_id: authorization_id.as_deref(),
                },
            );
            self.build_headers(
                &access_token.access_token.expose(),
                Some(&idempotency_key),
                &req.connector_config,
                connector_metadata.as_ref(),
            )
        }
        fn get_url(
            &self,
            req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ) -> CustomResult<String, IntegrationError> {
            let paypal_meta: paypal::PaypalMeta = utils::to_connector_meta(req.request.connector_feature_data.clone().map(|m| m.expose()))?;
            // G-Capture-01: capture acts on the authorization id, not the order id;
            // refuse before any call when the Authorize response did not record it.
            let authorize_id = paypal_meta.authorize_id.ok_or_else(|| {
                IntegrationError::MissingRequiredField {
                    field_name: "connector_feature_data.authorize_id",
                    context: domain_types::errors::IntegrationErrorContext {
                        suggested_action: Some(
                            "Pass the connector_feature_data returned by the PayPal \
                             Authorize response (capture_method MANUAL); it carries the \
                             authorization id"
                                .to_string(),
                        ),
                        doc_url: Some(
                            "https://developer.paypal.com/docs/api/payments/v2/#authorizations_capture"
                                .to_string(),
                        ),
                        additional_context: Some(
                            "Capture requires authorize_id in connector_feature_data".to_string(),
                        ),
                    },
                }
            })?;
            Ok(format!(
                "{}v2/payments/authorizations/{}/capture",
                self.connector_base_url_payments(req),
                authorize_id
            ))
        }
        fn get_error_response_v2(
            &self,
            res: Response,
            event_builder: Option<&mut events::Event>,
            connector_config: &ConnectorSpecificConfig,
        ) -> CustomResult<ErrorResponse, ConnectorError> {
            let status_code = res.status_code;
            // Every details[].issue, not only the priority one carried in `code`, so an
            // AUTHORIZATION_ALREADY_CAPTURED replay is never reported as a failure.
            let issues: Vec<paypal::PaypalErrorIssue> =
                serde_json::from_slice::<paypal::PaypalPaymentErrorResponse>(&res.response)
                    .ok()
                    .and_then(|response| response.details)
                    .into_iter()
                    .flatten()
                    .map(|detail| paypal::PaypalErrorIssue::from_issue(&detail.issue))
                    .collect();
            let mut error = self.build_error_response(res, event_builder, connector_config)?;
            error.attempt_status = paypal::paypal_error_attempt_status(
                paypal::PaypalErrorFlow::Capture,
                status_code,
                &issues,
            );
            Ok(error)
        }

        // 5xx: outcome unknown (the resource may exist) -> the flow's PayPal error table
        // (P-foundation-04: 5xx -> Pending), never the framework default's None (B025).
        fn get_5xx_error_response(
            &self,
            res: Response,
            event_builder: Option<&mut events::Event>,
            connector_config: &ConnectorSpecificConfig,
        ) -> CustomResult<ErrorResponse, ConnectorError> {
            <Self as ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>>::get_error_response_v2(
                self,
                res,
                event_builder,
                connector_config,
            )
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type],
    connector: Paypal,
    curl_response: PaypalPaymentsCancelResponse,
    flow_name: Void,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentVoidData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, IntegrationError> {
            let access_token = req.resource_common_data
                .access_token
                .clone()
                .ok_or(IntegrationError::FailedToObtainAuthType { context: Default::default() })?;
            let connector_metadata = req.resource_common_data.connector_feature_data
                .as_ref()
                .map(|secret| secret.clone().expose());
            // One PayPal-Request-Id per (authorization, call type): a retried void
            // replays, and two payments never share a key even when merchant_void_id is
            // omitted (b4-02). A missing authorize_id is refused by get_url.
            let authorization_id = utils::to_connector_meta::<paypal::PaypalMeta>(
                req.request.connector_feature_data.clone().map(|secret| secret.expose()),
            )
            .ok()
            .and_then(|meta| meta.authorize_id);
            let idempotency_key = paypal::paypal_idempotency_key(
                &req.resource_common_data.connector_request_reference_id,
                paypal::PaypalRequestIdKind::Void {
                    authorization_id: authorization_id.as_deref(),
                },
            );
            self.build_headers(
                &access_token.access_token.expose(),
                Some(&idempotency_key),
                &req.connector_config,
                connector_metadata.as_ref(),
            )
        }

        fn get_url(
            &self,
            req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ) -> CustomResult<String, IntegrationError> {
            let connector_metadata_value = req.request.connector_feature_data.clone().map(|secret| secret.expose());
            let paypal_meta: paypal::PaypalMeta = utils::to_connector_meta(connector_metadata_value)?;
            // G-Void-01: void acts on the authorization id, not the order id; refuse
            // before any call when the Authorize response did not record it.
            let authorize_id = paypal_meta.authorize_id.ok_or_else(|| {
                IntegrationError::MissingRequiredField {
                    field_name: "connector_feature_data.authorize_id",
                    context: domain_types::errors::IntegrationErrorContext {
                        suggested_action: Some(
                            "Pass the connector_feature_data returned by the PayPal \
                             Authorize response (capture_method MANUAL); it carries the \
                             authorization id"
                                .to_string(),
                        ),
                        doc_url: Some(
                            "https://developer.paypal.com/docs/api/payments/v2/#authorizations_void"
                                .to_string(),
                        ),
                        additional_context: Some(
                            "Void requires authorize_id in connector_feature_data".to_string(),
                        ),
                    },
                }
            })?;
            Ok(format!(
                "{}v2/payments/authorizations/{}/void",
                self.connector_base_url_payments(req),
                authorize_id,
            ))
        }
        fn get_error_response_v2(
            &self,
            res: Response,
            event_builder: Option<&mut events::Event>,
            connector_config: &ConnectorSpecificConfig,
        ) -> CustomResult<ErrorResponse, ConnectorError> {
            let status_code = res.status_code;
            // Every details[].issue, not only the priority one carried in `code`, so a
            // PREVIOUSLY_VOIDED replay is reported as Voided rather than a failure.
            let issues: Vec<paypal::PaypalErrorIssue> =
                serde_json::from_slice::<paypal::PaypalPaymentErrorResponse>(&res.response)
                    .ok()
                    .and_then(|response| response.details)
                    .into_iter()
                    .flatten()
                    .map(|detail| paypal::PaypalErrorIssue::from_issue(&detail.issue))
                    .collect();
            let mut error = self.build_error_response(res, event_builder, connector_config)?;
            error.attempt_status = paypal::paypal_error_attempt_status(
                paypal::PaypalErrorFlow::Void,
                status_code,
                &issues,
            );
            Ok(error)
        }

        // 5xx: outcome unknown (the resource may exist) -> the flow's PayPal error table
        // (P-foundation-04: 5xx -> Pending), never the framework default's None (B025).
        fn get_5xx_error_response(
            &self,
            res: Response,
            event_builder: Option<&mut events::Event>,
            connector_config: &ConnectorSpecificConfig,
        ) -> CustomResult<ErrorResponse, ConnectorError> {
            <Self as ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>>::get_error_response_v2(
                self,
                res,
                event_builder,
                connector_config,
            )
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type],
    connector: Paypal,
    curl_request: Json(PaypalRefundRequest),
    curl_response: RefundResponse,
    flow_name: Refund,
    resource_common_data: RefundFlowData,
    flow_request: RefundsData,
    flow_response: RefundsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, IntegrationError> {
            let access_token = req.resource_common_data
                .access_token
                .clone()
                .ok_or(IntegrationError::FailedToObtainAuthType { context: Default::default() })?;
            let connector_metadata = req.resource_common_data.connector_feature_data
                .as_ref()
                .map(|secret| secret.clone().expose());
            // PayPal-Request-Id is unique per refund (the refund's own id): two partial
            // refunds of one capture must not share a key, or the second replays the first.
            let capture_id = utils::to_connector_meta::<paypal::PaypalMeta>(
                req.request.connector_feature_data.clone().expose_option(),
            )
            .ok()
            .and_then(|meta| meta.capture_id);
            let idempotency_key = paypal::paypal_idempotency_key(
                &req.resource_common_data.connector_request_reference_id,
                paypal::PaypalRequestIdKind::Refund {
                    capture_id: capture_id.as_deref(),
                    refund_id: &req.request.refund_id,
                },
            );
            self.build_headers(
                &access_token.access_token.expose(),
                Some(&idempotency_key),
                &req.connector_config,
                connector_metadata.as_ref(),
            )
        }
        fn get_url(
            &self,
            req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ) -> CustomResult<String, IntegrationError> {
            let paypal_meta: paypal::PaypalMeta = utils::to_connector_meta(req.request.connector_feature_data.clone().expose_option())?;
            // G-Refund-01: a refund acts on the capture id; refuse before any call when
            // the Authorize/Capture response did not record it.
            let capture_id = paypal_meta.capture_id.ok_or_else(|| {
                IntegrationError::MissingRequiredField {
                    field_name: "connector_feature_data.capture_id",
                    context: domain_types::errors::IntegrationErrorContext {
                        suggested_action: Some(
                            "Pass the connector_feature_data returned by the PayPal \
                             Authorize (capture_method AUTOMATIC) or Capture response; \
                             it carries the capture id"
                                .to_string(),
                        ),
                        doc_url: Some(
                            "https://developer.paypal.com/docs/api/payments/v2/#captures_refund"
                                .to_string(),
                        ),
                        additional_context: Some(
                            "Refund requires capture_id in connector_feature_data".to_string(),
                        ),
                    },
                }
            })?;
            Ok(format!(
                "{}v2/payments/captures/{}/refund",
                self.connector_base_url_refunds(req),
                capture_id,
            ))
        }
        fn get_error_response_v2(
            &self,
            res: Response,
            event_builder: Option<&mut events::Event>,
            connector_config: &ConnectorSpecificConfig,
        ) -> CustomResult<ErrorResponse, ConnectorError> {
            let status_code = res.status_code;
            // Every details[].issue is read so the refund table sees the whole error;
            // 409 PREVIOUS_REQUEST_IN_PROGRESS / 5xx stay Pending, the rest is Failure.
            let issues: Vec<paypal::PaypalErrorIssue> =
                serde_json::from_slice::<paypal::PaypalPaymentErrorResponse>(&res.response)
                    .ok()
                    .and_then(|response| response.details)
                    .into_iter()
                    .flatten()
                    .map(|detail| paypal::PaypalErrorIssue::from_issue(&detail.issue))
                    .collect();
            let mut error = self.build_error_response(res, event_builder, connector_config)?;
            error.attempt_status = paypal::paypal_error_attempt_status(
                paypal::PaypalErrorFlow::Refund,
                status_code,
                &issues,
            );
            Ok(error)
        }

        // 5xx: outcome unknown (the resource may exist) -> the flow's PayPal error table
        // (P-foundation-04: 5xx -> Pending), never the framework default's None (B025).
        fn get_5xx_error_response(
            &self,
            res: Response,
            event_builder: Option<&mut events::Event>,
            connector_config: &ConnectorSpecificConfig,
        ) -> CustomResult<ErrorResponse, ConnectorError> {
            <Self as ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>>::get_error_response_v2(
                self,
                res,
                event_builder,
                connector_config,
            )
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Paypal,
    curl_response: RefundSyncResponse,
    flow_name: RSync,
    resource_common_data: RefundFlowData,
    flow_request: RefundSyncData,
    flow_response: RefundsResponseData,
    http_method: Get,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, IntegrationError> {
            let access_token = req.resource_common_data
                .access_token
                .clone()
                .ok_or(IntegrationError::FailedToObtainAuthType { context: Default::default() })?;
            let connector_metadata = req.resource_common_data.connector_feature_data
                .as_ref()
                .map(|secret| secret.clone().expose());
            self.build_headers(
                &access_token.access_token.expose(),
                // GET: no PayPal-Request-Id.
                None,
                &req.connector_config,
                connector_metadata.as_ref(),
            )
        }
        fn get_url(
            &self,
            req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ) -> CustomResult<String, IntegrationError> {
            Ok(format!(
                "{}v2/payments/refunds/{}",
                self.connector_base_url_refunds(req),
                req.request.connector_refund_id
            ))
        }
    }
);

// SetupMandate: POST v3/vault/payment-tokens with a raw card or with
// payment_source.token{SETUP_TOKEN} from PaymentMethodService/Tokenize.
// Doc: https://developer.paypal.com/docs/api/payment-tokens/v3/#payment-tokens_create
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type],
    connector: Paypal,
    curl_request: Json(PaypalZeroMandateRequest),
    curl_response: PaypalSetupMandatesResponse,
    flow_name: SetupMandate,
    resource_common_data: PaymentFlowData,
    flow_request: SetupMandateRequestData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, IntegrationError> {
            let access_token = req.resource_common_data
                .access_token
                .clone()
                .ok_or(IntegrationError::FailedToObtainAuthType {
                    context: domain_types::errors::IntegrationErrorContext {
                        suggested_action: Some(
                            "Obtain a PayPal access token (CreateServerAuthenticationToken) \
                             before PaymentService/SetupRecurring"
                                .to_string(),
                        ),
                        doc_url: Some(
                            "https://developer.paypal.com/api/rest/authentication/".to_string(),
                        ),
                        additional_context: None,
                    },
                })?;
            let connector_metadata = req.resource_common_data.connector_feature_data
                .as_ref()
                .map(|secret| secret.clone().expose());
            // Vault v3 limits PayPal-Request-Id to 108 characters. A setup-token
            // exchange is keyed on the setup token id, so two Tokenize chains never
            // share a key when merchant_payment_method_id is omitted (b4-02).
            let setup_token_id = match &req.request.payment_method_data {
                PaymentMethodData::PaymentMethodToken(setup_token) => {
                    Some(hyperswitch_masking::PeekInterface::peek(&setup_token.token).as_str())
                }
                _ => None,
            };
            let idempotency_key = paypal::paypal_idempotency_key(
                &req.resource_common_data.connector_request_reference_id,
                paypal::PaypalRequestIdKind::VaultPaymentToken { setup_token_id },
            );
            self.build_headers(
                &access_token.access_token.expose(),
                Some(&idempotency_key),
                &req.connector_config,
                connector_metadata.as_ref(),
            )
        }
        fn get_url(
            &self,
            req: &RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>,
        ) -> CustomResult<String, IntegrationError> {
            Ok(format!(
                "{}v3/vault/payment-tokens/",
                self.connector_base_url_payments(req)
            ))
        }
        fn get_error_response_v2(
            &self,
            res: Response,
            event_builder: Option<&mut events::Event>,
            connector_config: &ConnectorSpecificConfig,
        ) -> CustomResult<ErrorResponse, ConnectorError> {
            let status_code = res.status_code;
            let mut error = self.build_error_response(res, event_builder, connector_config)?;
            error.attempt_status = paypal::paypal_error_attempt_status(
                paypal::PaypalErrorFlow::SetupMandate,
                status_code,
                &[paypal::PaypalErrorIssue::from_issue(&error.code)],
            );
            Ok(error)
        }

        // 5xx: outcome unknown (the resource may exist) -> the flow's PayPal error table
        // (P-foundation-04: 5xx -> Pending), never the framework default's None (B025).
        fn get_5xx_error_response(
            &self,
            res: Response,
            event_builder: Option<&mut events::Event>,
            connector_config: &ConnectorSpecificConfig,
        ) -> CustomResult<ErrorResponse, ConnectorError> {
            <Self as ConnectorIntegrationV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>>::get_error_response_v2(
                self,
                res,
                event_builder,
                connector_config,
            )
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type],
    connector: Paypal,
    curl_request: Json(PaypalRepeatPaymentRequest<T>),
    curl_response: PaypalRepeatPaymentResponse,
    flow_name: RepeatPayment,
    resource_common_data: PaymentFlowData,
    flow_request: RepeatPaymentData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData<T>, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, IntegrationError> {
            let access_token = req.resource_common_data
                .access_token
                .clone()
                .ok_or(IntegrationError::FailedToObtainAuthType {
                    context: domain_types::errors::IntegrationErrorContext {
                        suggested_action: Some(
                            "Obtain a PayPal access token (CreateServerAuthenticationToken) \
                             before RecurringPaymentService/Charge"
                                .to_string(),
                        ),
                        doc_url: Some(
                            "https://developer.paypal.com/api/rest/authentication/".to_string(),
                        ),
                        additional_context: None,
                    },
                })?;
            let connector_metadata = req.resource_common_data.connector_feature_data
                .as_ref()
                .map(|secret| secret.clone().expose());
            // A MIT is an Orders v2 create-order call.
            let idempotency_key = paypal::paypal_idempotency_key(
                &req.resource_common_data.connector_request_reference_id,
                paypal::PaypalRequestIdKind::CreateOrder,
            );
            self.build_headers(
                &access_token.access_token.expose(),
                Some(&idempotency_key),
                &req.connector_config,
                connector_metadata.as_ref(),
            )
        }
        fn get_url(
            &self,
            req: &RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData<T>, PaymentsResponseData>,
        ) -> CustomResult<String, IntegrationError> {
            Ok(format!("{}v2/checkout/orders", self.connector_base_url_payments(req)))
        }
        // RepeatPayment calls the Orders API, whose error body differs from the
        // Payments API one parsed by `build_error_response`.
        fn get_error_response_v2(
            &self,
            res: Response,
            event_builder: Option<&mut events::Event>,
            _connector_config: &ConnectorSpecificConfig,
        ) -> CustomResult<ErrorResponse, ConnectorError> {
            self.get_order_error_response(res, event_builder, Some(paypal::PaypalErrorFlow::Authorize))
        }

        // 5xx: outcome unknown (the resource may exist) -> the flow's PayPal error table
        // (P-foundation-04: 5xx -> Pending), never the framework default's None (B025).
        fn get_5xx_error_response(
            &self,
            res: Response,
            event_builder: Option<&mut events::Event>,
            connector_config: &ConnectorSpecificConfig,
        ) -> CustomResult<ErrorResponse, ConnectorError> {
            <Self as ConnectorIntegrationV2<RepeatPayment, PaymentFlowData, RepeatPaymentData<T>, PaymentsResponseData>>::get_error_response_v2(
                self,
                res,
                event_builder,
                connector_config,
            )
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type],
    connector: Paypal,
    curl_request: Json(PaypalOrderCreateRequest),
    curl_response: PaypalOrderCreateResponse,
    flow_name: CreateOrder,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentCreateOrderData,
    flow_response: PaymentCreateOrderResponse,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, IntegrationError> {
            let access_token = req.resource_common_data.access_token.clone().ok_or(
                IntegrationError::FailedToObtainAuthType {
                    context: Default::default(),
                },
            )?;
            let connector_metadata = req
                .resource_common_data
                .connector_feature_data
                .as_ref()
                .map(|secret| secret.clone().expose());
            self.build_headers(
                &access_token.access_token.expose(),
                Some(&req.resource_common_data.connector_request_reference_id),
                &req.connector_config,
                connector_metadata.as_ref(),
            )
        }

        fn get_url(
            &self,
            req: &RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>,
        ) -> CustomResult<String, IntegrationError> {
            Ok(format!("{}v2/checkout/orders", self.connector_base_url_payments(req)))
        }

        fn get_error_response_v2(
            &self,
            res: Response,
            event_builder: Option<&mut events::Event>,
            _connector_config: &ConnectorSpecificConfig,
    ) -> CustomResult<ErrorResponse, ConnectorError> {
            self.get_order_error_response(res, event_builder, None)
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Paypal,
    curl_request: Json(PaypalClientAuthTokenRequest),
    curl_response: PaypalClientAuthTokenResponse,
    flow_name: ClientAuthenticationToken,
    resource_common_data: MerchantAuthenticationFlowData,
    flow_request: ClientAuthenticationTokenRequestData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<ClientAuthenticationToken, MerchantAuthenticationFlowData, ClientAuthenticationTokenRequestData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, IntegrationError> {
            // Use Basic auth (client_id:client_secret) for v1/identity/generate-token
            // since the ClientAuthenticationToken gRPC request does not carry a pre-obtained access token.
            let auth = paypal::PaypalAuthType::try_from(&req.connector_config)?;
            let credentials = auth.get_credentials()?;
            let auth_val = credentials.generate_authorization_value();

            Ok(vec![
                (
                    headers::CONTENT_TYPE.to_string(),
                    "application/json".to_string().into(),
                ),
                (headers::AUTHORIZATION.to_string(), auth_val.into_masked()),
            ])
        }
        fn get_url(
            &self,
            req: &RouterDataV2<ClientAuthenticationToken, MerchantAuthenticationFlowData, ClientAuthenticationTokenRequestData, PaymentsResponseData>,
        ) -> CustomResult<String, IntegrationError> {
            Ok(format!("{}v1/identity/generate-token", self.connector_base_url_merchant_auth(req)))
        }
    }
);

// Vault v3 setup token: the server-side entry point for card $0 verification and for an
// encrypted (PSP-decrypted) Apple Pay token, which Orders v2 cannot accept. Served by
// PaymentMethodService/Tokenize; the token is then vaulted by TokenSetupRecurring.
// Doc: https://developer.paypal.com/docs/api/payment-tokens/v3/#setup-tokens_create
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type],
    connector: Paypal,
    curl_request: Json(PaypalSetupTokenRequest<T>),
    curl_response: PaypalSetupTokenResponse,
    flow_name: PaymentMethodToken,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentMethodTokenizationData<T>,
    flow_response: PaymentMethodTokenResponse,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<PaymentMethodToken, PaymentFlowData, PaymentMethodTokenizationData<T>, PaymentMethodTokenResponse>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, IntegrationError> {
            let access_token = req.resource_common_data
                .access_token
                .clone()
                .ok_or(IntegrationError::FailedToObtainAuthType {
                    context: domain_types::errors::IntegrationErrorContext {
                        suggested_action: Some(
                            "Obtain a PayPal access token (CreateServerAuthenticationToken) \
                             before PaymentMethodService/Tokenize"
                                .to_string(),
                        ),
                        doc_url: Some(
                            "https://developer.paypal.com/api/rest/authentication/".to_string(),
                        ),
                        additional_context: None,
                    },
                })?;
            let connector_metadata = req.resource_common_data.connector_feature_data
                .as_ref()
                .map(|secret| secret.clone().expose());
            let idempotency_key = paypal::paypal_idempotency_key(
                &req.resource_common_data.connector_request_reference_id,
                paypal::PaypalRequestIdKind::VaultSetupToken,
            );
            self.build_headers(
                &access_token.access_token.expose(),
                Some(&idempotency_key),
                &req.connector_config,
                connector_metadata.as_ref(),
            )
        }
        fn get_url(
            &self,
            req: &RouterDataV2<PaymentMethodToken, PaymentFlowData, PaymentMethodTokenizationData<T>, PaymentMethodTokenResponse>,
        ) -> CustomResult<String, IntegrationError> {
            Ok(format!("{}v3/vault/setup-tokens", self.connector_base_url_payments(req)))
        }
        fn get_error_response_v2(
            &self,
            res: Response,
            event_builder: Option<&mut events::Event>,
            connector_config: &ConnectorSpecificConfig,
        ) -> CustomResult<ErrorResponse, ConnectorError> {
            let status_code = res.status_code;
            let mut error = self.build_error_response(res, event_builder, connector_config)?;
            error.attempt_status = paypal::paypal_error_attempt_status(
                paypal::PaypalErrorFlow::PaymentMethodToken,
                status_code,
                &[paypal::PaypalErrorIssue::from_issue(&error.code)],
            );
            Ok(error)
        }

        // 5xx: outcome unknown (the resource may exist) -> the flow's PayPal error table
        // (P-foundation-04: 5xx -> Pending), never the framework default's None (B025).
        fn get_5xx_error_response(
            &self,
            res: Response,
            event_builder: Option<&mut events::Event>,
            connector_config: &ConnectorSpecificConfig,
        ) -> CustomResult<ErrorResponse, ConnectorError> {
            <Self as ConnectorIntegrationV2<PaymentMethodToken, PaymentFlowData, PaymentMethodTokenizationData<T>, PaymentMethodTokenResponse>>::get_error_response_v2(
                self,
                res,
                event_builder,
                connector_config,
            )
        }
    }
);

// PostAuthenticate: read the payer's 3DS outcome from the order
// (`GET v2/checkout/orders/{id}?fields=payment_source`). Read-only; never moves money.
// doc: https://developer.paypal.com/docs/checkout/advanced/customize/3d-secure/api/
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Paypal,
    curl_response: PaypalPostAuthenticateResponse,
    flow_name: PostAuthenticate,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsPostAuthenticateData<T>,
    flow_response: PaymentsResponseData,
    http_method: Get,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<PostAuthenticate, PaymentFlowData, PaymentsPostAuthenticateData<T>, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, IntegrationError> {
            let access_token = req.resource_common_data
                .access_token
                .clone()
                .ok_or(IntegrationError::FailedToObtainAuthType {
                    context: domain_types::errors::IntegrationErrorContext {
                        suggested_action: Some(
                            "Pass the access token from CreateServerAuthenticationToken in state.access_token"
                                .to_string(),
                        ),
                        doc_url: Some(
                            "https://developer.paypal.com/api/rest/authentication/".to_string(),
                        ),
                        additional_context: None,
                    },
                })?;
            let connector_metadata = req.resource_common_data.connector_feature_data
                .as_ref()
                .map(|secret| secret.clone().expose());
            self.build_headers(
                &access_token.access_token.expose(),
                // GET: no PayPal-Request-Id.
                None,
                &req.connector_config,
                connector_metadata.as_ref(),
            )
        }
        fn get_url(
            &self,
            req: &RouterDataV2<PostAuthenticate, PaymentFlowData, PaymentsPostAuthenticateData<T>, PaymentsResponseData>,
        ) -> CustomResult<String, IntegrationError> {
            // G-ThreeDS-01: the GET target is the order created by the 3DS Authorize.
            let order_id = paypal::paypal_post_auth_order_id(req)
                .ok_or(IntegrationError::MissingRequiredField {
                    field_name: "connector_order_reference_id",
                    context: domain_types::errors::IntegrationErrorContext {
                        suggested_action: Some(
                            "Pass the PayPal order id returned by the 3DS Authorize \
                             (connector_transaction_id) as connector_order_reference_id"
                                .to_string(),
                        ),
                        doc_url: Some(
                            "https://developer.paypal.com/docs/api/orders/v2/#orders_get"
                                .to_string(),
                        ),
                        additional_context: None,
                    },
                })?;

            Ok(format!(
                "{}v2/checkout/orders/{}?fields=payment_source",
                self.connector_base_url_payments(req),
                order_id
            ))
        }
    }
);

// VerifyWebhookSource implementation using ConnectorIntegrationV2
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        VerifyWebhookSource,
        VerifyWebhookSourceFlowData,
        VerifyWebhookSourceRequestData,
        VerifyWebhookSourceResponseData,
    > for Paypal<T>
{
    fn get_url(
        &self,
        req: &RouterDataV2<
            VerifyWebhookSource,
            VerifyWebhookSourceFlowData,
            VerifyWebhookSourceRequestData,
            VerifyWebhookSourceResponseData,
        >,
    ) -> CustomResult<String, IntegrationError> {
        let base_url = self.base_url(&req.resource_common_data.connectors);
        Ok(format!(
            "{}v1/notifications/verify-webhook-signature",
            base_url
        ))
    }

    fn get_headers(
        &self,
        req: &RouterDataV2<
            VerifyWebhookSource,
            VerifyWebhookSourceFlowData,
            VerifyWebhookSourceRequestData,
            VerifyWebhookSourceResponseData,
        >,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, IntegrationError> {
        // PayPal verify-webhook-signature uses Basic Auth (client_id:client_secret), not Bearer token
        let auth = transformers::PaypalAuthType::try_from(&req.connector_config).change_context(
            IntegrationError::FailedToObtainAuthType {
                context: Default::default(),
            },
        )?;
        let credentials = auth.get_credentials()?;
        let auth_val = credentials.generate_authorization_value();

        Ok(vec![
            (
                headers::CONTENT_TYPE.to_string(),
                "application/json".to_string().into(),
            ),
            (headers::AUTHORIZATION.to_string(), auth_val.into_masked()),
        ])
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<
            VerifyWebhookSource,
            VerifyWebhookSourceFlowData,
            VerifyWebhookSourceRequestData,
            VerifyWebhookSourceResponseData,
        >,
    ) -> CustomResult<Option<common_utils::request::ConnectorRequestData>, IntegrationError> {
        let verification_request = paypal::PaypalSourceVerificationRequest::try_from(&req.request)?;
        let typed = events::MaskedSerdeValue::from_masked_optional(
            &verification_request,
            "typed_connector_request",
        );
        Ok(Some(common_utils::request::ConnectorRequestData::new(
            common_utils::request::RequestContent::Json(Box::new(verification_request)),
            typed,
        )))
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<
            VerifyWebhookSource,
            VerifyWebhookSourceFlowData,
            VerifyWebhookSourceRequestData,
            VerifyWebhookSourceResponseData,
        >,
        event_builder: Option<&mut events::Event>,
        res: Response,
    ) -> CustomResult<
        RouterDataV2<
            VerifyWebhookSource,
            VerifyWebhookSourceFlowData,
            VerifyWebhookSourceRequestData,
            VerifyWebhookSourceResponseData,
        >,
        ConnectorError,
    > {
        let verification_response: paypal::PaypalSourceVerificationResponse = res
            .response
            .parse_struct("PaypalSourceVerificationResponse")
            .change_context(utils::response_handling_fail_for_connector(
                res.status_code,
                "paypal",
            ))?;
        finalize_connector_response!(event_builder, verification_response, data, res.status_code)
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut events::Event>,
        _connector_config: &ConnectorSpecificConfig,
    ) -> CustomResult<ErrorResponse, ConnectorError> {
        self.build_error_response(res, event_builder, _connector_config)
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::VerifyWebhookSourceV2 for Paypal<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorErrorTypeMapping for Paypal<T>
{
    fn get_connector_error_type(
        &self,
        error_code: String,
        _error_message: String,
    ) -> ConnectorErrorType {
        match error_code.as_str() {
            "CANNOT_BE_NEGATIVE" => ConnectorErrorType::UserError,
            "CANNOT_BE_ZERO_OR_NEGATIVE" => ConnectorErrorType::UserError,
            "CARD_EXPIRED" => ConnectorErrorType::UserError,
            "DECIMAL_PRECISION" => ConnectorErrorType::UserError,
            "DUPLICATE_INVOICE_ID" => ConnectorErrorType::UserError,
            "INSTRUMENT_DECLINED" => ConnectorErrorType::BusinessError,
            "INTERNAL_SERVER_ERROR" => ConnectorErrorType::TechnicalError,
            "INVALID_ACCOUNT_STATUS" => ConnectorErrorType::BusinessError,
            "INVALID_CURRENCY_CODE" => ConnectorErrorType::UserError,
            "INVALID_PARAMETER_SYNTAX" => ConnectorErrorType::UserError,
            "INVALID_PARAMETER_VALUE" => ConnectorErrorType::UserError,
            "INVALID_RESOURCE_ID" => ConnectorErrorType::UserError,
            "INVALID_STRING_LENGTH" => ConnectorErrorType::UserError,
            "MISSING_REQUIRED_PARAMETER" => ConnectorErrorType::UserError,
            "PAYER_ACCOUNT_LOCKED_OR_CLOSED" => ConnectorErrorType::BusinessError,
            "PAYER_ACCOUNT_RESTRICTED" => ConnectorErrorType::BusinessError,
            "PAYER_CANNOT_PAY" => ConnectorErrorType::BusinessError,
            "PERMISSION_DENIED" => ConnectorErrorType::BusinessError,
            "INVALID_ARRAY_MAX_ITEMS" => ConnectorErrorType::UserError,
            "INVALID_ARRAY_MIN_ITEMS" => ConnectorErrorType::UserError,
            "INVALID_COUNTRY_CODE" => ConnectorErrorType::UserError,
            "NOT_SUPPORTED" => ConnectorErrorType::BusinessError,
            "PAYPAL_REQUEST_ID_REQUIRED" => ConnectorErrorType::UserError,
            "MALFORMED_REQUEST_JSON" => ConnectorErrorType::UserError,
            "PERMISSION_DENIED_FOR_DONATION_ITEMS" => ConnectorErrorType::BusinessError,
            "MALFORMED_REQUEST" => ConnectorErrorType::TechnicalError,
            "AMOUNT_MISMATCH" => ConnectorErrorType::UserError,
            "BILLING_ADDRESS_INVALID" => ConnectorErrorType::UserError,
            "CITY_REQUIRED" => ConnectorErrorType::UserError,
            "DONATION_ITEMS_NOT_SUPPORTED" => ConnectorErrorType::BusinessError,
            "DUPLICATE_REFERENCE_ID" => ConnectorErrorType::UserError,
            "INVALID_PAYER_ID" => ConnectorErrorType::UserError,
            "ITEM_TOTAL_REQUIRED" => ConnectorErrorType::UserError,
            "MAX_VALUE_EXCEEDED" => ConnectorErrorType::UserError,
            "MISSING_PICKUP_ADDRESS" => ConnectorErrorType::UserError,
            "MULTI_CURRENCY_ORDER" => ConnectorErrorType::BusinessError,
            "MULTIPLE_ITEM_CATEGORIES" => ConnectorErrorType::UserError,
            "MULTIPLE_SHIPPING_ADDRESS_NOT_SUPPORTED" => ConnectorErrorType::UserError,
            "MULTIPLE_SHIPPING_TYPE_NOT_SUPPORTED" => ConnectorErrorType::BusinessError,
            "PAYEE_ACCOUNT_INVALID" => ConnectorErrorType::UserError,
            "PAYEE_ACCOUNT_LOCKED_OR_CLOSED" => ConnectorErrorType::UserError,
            "REFERENCE_ID_REQUIRED" => ConnectorErrorType::UserError,
            "PAYMENT_SOURCE_CANNOT_BE_USED" => ConnectorErrorType::BusinessError,
            "PAYMENT_SOURCE_DECLINED_BY_PROCESSOR" => ConnectorErrorType::BusinessError,
            "PAYMENT_SOURCE_INFO_CANNOT_BE_VERIFIED" => ConnectorErrorType::BusinessError,
            "POSTAL_CODE_REQUIRED" => ConnectorErrorType::UserError,
            "SHIPPING_ADDRESS_INVALID" => ConnectorErrorType::UserError,
            "TAX_TOTAL_MISMATCH" => ConnectorErrorType::UserError,
            "TAX_TOTAL_REQUIRED" => ConnectorErrorType::UserError,
            "UNSUPPORTED_INTENT" => ConnectorErrorType::BusinessError,
            "UNSUPPORTED_PAYMENT_INSTRUCTION" => ConnectorErrorType::UserError,
            "SHIPPING_TYPE_NOT_SUPPORTED_FOR_CLIENT" => ConnectorErrorType::BusinessError,
            "UNSUPPORTED_SHIPPING_TYPE" => ConnectorErrorType::BusinessError,
            "PREFERRED_SHIPPING_OPTION_AMOUNT_MISMATCH" => ConnectorErrorType::UserError,
            "CARD_CLOSED" => ConnectorErrorType::BusinessError,
            "ORDER_CANNOT_BE_SAVED" => ConnectorErrorType::BusinessError,
            "SAVE_ORDER_NOT_SUPPORTED" => ConnectorErrorType::BusinessError,
            "FIELD_NOT_PATCHABLE" => ConnectorErrorType::UserError,
            "AMOUNT_NOT_PATCHABLE" => ConnectorErrorType::UserError,
            "INVALID_PATCH_OPERATION" => ConnectorErrorType::UserError,
            "PAYEE_ACCOUNT_NOT_SUPPORTED" => ConnectorErrorType::UserError,
            "PAYEE_ACCOUNT_NOT_VERIFIED" => ConnectorErrorType::UserError,
            "PAYEE_NOT_CONSENTED" => ConnectorErrorType::UserError,
            "INVALID_JSON_POINTER_FORMAT" => ConnectorErrorType::BusinessError,
            "INVALID_PARAMETER" => ConnectorErrorType::UserError,
            "NOT_PATCHABLE" => ConnectorErrorType::BusinessError,
            "PATCH_VALUE_REQUIRED" => ConnectorErrorType::UserError,
            "PATCH_PATH_REQUIRED" => ConnectorErrorType::UserError,
            "REFERENCE_ID_NOT_FOUND" => ConnectorErrorType::UserError,
            "SHIPPING_OPTION_NOT_SELECTED" => ConnectorErrorType::UserError,
            "SHIPPING_OPTIONS_NOT_SUPPORTED" => ConnectorErrorType::BusinessError,
            "MULTIPLE_SHIPPING_OPTION_SELECTED" => ConnectorErrorType::UserError,
            "ORDER_ALREADY_COMPLETED" => ConnectorErrorType::BusinessError,
            "ACTION_DOES_NOT_MATCH_INTENT" => ConnectorErrorType::BusinessError,
            "AGREEMENT_ALREADY_CANCELLED" => ConnectorErrorType::BusinessError,
            "BILLING_AGREEMENT_NOT_FOUND" => ConnectorErrorType::BusinessError,
            "DOMESTIC_TRANSACTION_REQUIRED" => ConnectorErrorType::BusinessError,
            "ORDER_NOT_APPROVED" => ConnectorErrorType::UserError,
            "MAX_NUMBER_OF_PAYMENT_ATTEMPTS_EXCEEDED" => ConnectorErrorType::TechnicalError,
            "PAYEE_BLOCKED_TRANSACTION" => ConnectorErrorType::BusinessError,
            "TRANSACTION_LIMIT_EXCEEDED" => ConnectorErrorType::UserError,
            "TRANSACTION_RECEIVING_LIMIT_EXCEEDED" => ConnectorErrorType::BusinessError,
            "TRANSACTION_REFUSED" => ConnectorErrorType::TechnicalError,
            "ORDER_ALREADY_AUTHORIZED" => ConnectorErrorType::BusinessError,
            "AUTH_CAPTURE_NOT_ENABLED" => ConnectorErrorType::BusinessError,
            "AMOUNT_CANNOT_BE_SPECIFIED" => ConnectorErrorType::BusinessError,
            "AUTHORIZATION_AMOUNT_EXCEEDED" => ConnectorErrorType::UserError,
            "AUTHORIZATION_CURRENCY_MISMATCH" => ConnectorErrorType::UserError,
            "MAX_AUTHORIZATION_COUNT_EXCEEDED" => ConnectorErrorType::BusinessError,
            "ORDER_COMPLETED_OR_VOIDED" => ConnectorErrorType::BusinessError,
            "ORDER_EXPIRED" => ConnectorErrorType::BusinessError,
            "INVALID_PICKUP_ADDRESS" => ConnectorErrorType::UserError,
            "CONSENT_NEEDED" => ConnectorErrorType::UserError,
            "COMPLIANCE_VIOLATION" => ConnectorErrorType::BusinessError,
            "REDIRECT_PAYER_FOR_ALTERNATE_FUNDING" => ConnectorErrorType::TechnicalError,
            "ORDER_ALREADY_CAPTURED" => ConnectorErrorType::UserError,
            "TRANSACTION_BLOCKED_BY_PAYEE" => ConnectorErrorType::BusinessError,
            "NOT_ENABLED_FOR_CARD_PROCESSING" => ConnectorErrorType::BusinessError,
            "PAYEE_NOT_ENABLED_FOR_CARD_PROCESSING" => ConnectorErrorType::BusinessError,
            _ => ConnectorErrorType::UnknownError,
        }
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> ConnectorCommon
    for Paypal<T>
{
    fn id(&self) -> &'static str {
        "paypal"
    }

    fn get_currency_unit(&self) -> CurrencyUnit {
        CurrencyUnit::Base
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.paypal.base_url.as_ref()
    }

    fn get_auth_header(
        &self,
        auth_type: &ConnectorSpecificConfig,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, IntegrationError> {
        let auth = paypal::PaypalAuthType::try_from(auth_type)?;
        let credentials = auth.get_credentials()?;

        Ok(vec![(
            headers::AUTHORIZATION.to_string(),
            credentials.get_client_secret().into_masked(),
        )])
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut events::Event>,
        _connector_config: &ConnectorSpecificConfig,
    ) -> CustomResult<ErrorResponse, ConnectorError> {
        let parsed: Result<paypal::PaypalPaymentErrorResponse, _> =
            res.response.parse_struct("Paypal ErrorResponse");
        let response = match parsed {
            Ok(response) => response,
            // A 5xx whose body is not PayPal JSON: the flow wrappers set attempt_status
            // from paypal_error_attempt_status (5xx -> Pending) (B025).
            Err(parse_error) if res.status_code >= 500 => {
                return Ok(paypal_5xx_unparsed_error_response(
                    res.status_code,
                    None,
                    &res.response,
                    &parse_error,
                ));
            }
            Err(err) => {
                return Err(
                    err.change_context(utils::response_handling_fail_for_connector(
                        res.status_code,
                        "paypal",
                    )),
                )
            }
        };

        with_error_response_body!(event_builder, response);

        let typed =
            macros::serialize_typed_connector_payload(&response, "typed_connector_response");
        let error_reason = response
            .details
            .clone()
            .map(|error_details| {
                error_details
                    .iter()
                    .try_fold(String::new(), |mut acc, error| {
                        if let Some(description) = &error.description {
                            write!(acc, "description - {description} ;")
                                .change_context(utils::response_handling_fail_for_connector(
                                    res.status_code,
                                    "paypal",
                                ))
                                .attach_printable("Failed to concatenate error details")
                                .map(|_| acc)
                        } else {
                            Ok(acc)
                        }
                    })
            })
            .transpose()?;
        let reason = match error_reason {
            Some(err_reason) => err_reason
                .is_empty()
                .then(|| response.message.to_owned())
                .or(Some(err_reason)),
            None => Some(response.message.to_owned()),
        };
        let errors_list = response.details.unwrap_or_default();
        let option_error_code_message = utils::get_error_code_error_message_based_on_priority(
            self.clone(),
            errors_list
                .into_iter()
                .map(|errors| errors.into())
                .collect(),
        );

        Ok(ErrorResponse {
            status_code: res.status_code,
            code: option_error_code_message
                .clone()
                .map(|error_code_message| error_code_message.error_code)
                .unwrap_or(NO_ERROR_CODE.to_string()),
            message: option_error_code_message
                .map(|error_code_message| error_code_message.error_message)
                .unwrap_or(NO_ERROR_MESSAGE.to_string()),
            reason,
            attempt_status: None,
            // debug_id is PayPal's correlation id, not a resource id (B022)
            connector_transaction_id: None,
            network_advice_code: None,
            network_decline_code: None,
            network_error_message: None,
            typed_connector_response: typed,
            raw_connector_response: None,
            raw_connector_request: None,
            typed_connector_request: None,
        })
    }
}

/// ErrorResponse for a PayPal 5xx whose body is not a PayPal error document.
/// A 5xx whose body is not PayPal JSON. The outcome stays unknown (the caller's
/// attempt_status), but the parse error and a bounded body excerpt are kept in
/// `reason` so the failure is diagnosable (b4-06). The body is only displayed, never
/// verified, so a lossy UTF-8 decode is fine here.
fn paypal_5xx_unparsed_error_response(
    status_code: u16,
    attempt_status: Option<FlowStatus>,
    body: &[u8],
    parse_error: &dyn std::fmt::Display,
) -> ErrorResponse {
    let excerpt: String = String::from_utf8_lossy(body).chars().take(256).collect();
    tracing::warn!(status_code, %parse_error, "PayPal 5xx with a non-JSON body");
    ErrorResponse {
        status_code,
        code: NO_ERROR_CODE.to_string(),
        message: NO_ERROR_MESSAGE.to_string(),
        reason: Some(format!(
            "PayPal HTTP {status_code}, unparsable body ({parse_error}): {excerpt}"
        )),
        attempt_status,
        connector_transaction_id: None,
        network_advice_code: None,
        network_decline_code: None,
        network_error_message: None,
        typed_connector_response: None,
        raw_connector_response: None,
        raw_connector_request: None,
        typed_connector_request: None,
    }
}

fn construct_auth_assertion_header(
    payer_id: &Secret<String>,
    client_id: &Secret<String>,
) -> String {
    let algorithm = BASE64_ENGINE.encode("{\"alg\":\"none\"}").to_string();
    let merchant_credentials = format!(
        "{{\"iss\":\"{}\",\"payer_id\":\"{}\"}}",
        client_id.clone().expose(),
        payer_id.clone().expose()
    );
    let encoded_credentials = BASE64_ENGINE.encode(merchant_credentials).to_string();
    format!("{algorithm}.{encoded_credentials}.")
}

macros::macro_connector_flow_status_impls!(
    connector: Paypal,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    not_implemented: [
        IncrementalAuthorization,
        Accept,
        SubmitEvidence,
        DefendDispute,
        CreateConnectorCustomer,
        GetConnectorCustomer,
        PreAuthenticate,
        Authenticate,
        MandateRevoke,
    ],
    not_supported: [
        VoidPostRefund,
        ServerSessionAuthenticationToken,
        VoidPC,
    ],
);
