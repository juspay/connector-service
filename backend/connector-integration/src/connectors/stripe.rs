pub mod transformers;
use std::{
    fmt::Debug,
    marker::{Send, Sync},
};

use common_utils::{
    consts::{NO_ERROR_CODE, NO_ERROR_MESSAGE},
    errors::CustomResult,
    events,
    ext_traits::ByteSliceExt,
    types::StringMinorUnit,
};
use domain_types::{
    connector_flow::{
        Accept, Authenticate, Authorize, Capture, CreateAccessToken, CreateConnectorCustomer,
        CreateOrder, CreateSessionToken, DefendDispute, IncrementalAuthorization, MandateRevoke,
        PSync, PaymentMethodToken, PostAuthenticate, PreAuthenticate, RSync, Refund, RepeatPayment,
        SdkSessionToken, SetupMandate, SubmitEvidence, Void, VoidPC,
    },
    connector_types::{
        AcceptDisputeData, AccessTokenRequestData, AccessTokenResponseData, ConnectorCustomerData,
        ConnectorCustomerResponse, ConnectorWebhookSecrets, DisputeDefendData, DisputeFlowData,
        DisputeResponseData, DisputeWebhookDetailsResponse, EventType, MandateRevokeRequestData,
        MandateRevokeResponseData, PaymentCreateOrderData, PaymentCreateOrderResponse,
        PaymentFlowData, PaymentMethodTokenResponse, PaymentMethodTokenizationData,
        PaymentVoidData, PaymentsAuthenticateData, PaymentsAuthorizeData,
        PaymentsCancelPostCaptureData, PaymentsCaptureData, PaymentsIncrementalAuthorizationData,
        PaymentsPostAuthenticateData, PaymentsPreAuthenticateData, PaymentsResponseData,
        PaymentsSdkSessionTokenData, PaymentsSyncData, RefundFlowData, RefundSyncData,
        RefundWebhookDetailsResponse, RefundsData, RefundsResponseData, RepeatPaymentData,
        RequestDetails, ResponseId, SessionTokenRequestData, SessionTokenResponseData,
        SetupMandateRequestData, SubmitEvidenceData, WebhookDetailsResponse,
    },
    errors::{self, ConnectorError},
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorSpecificAuth, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
    utils,
};

use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, Mask, Maskable, PeekInterface, Secret};
use interfaces::{
    api::ConnectorCommon, connector_integration_v2::ConnectorIntegrationV2, connector_types,
    decode::BodyDecoding, verification::SourceVerification,
};
use serde::Serialize;
use transformers::{
    self as stripe, CancelRequest, CaptureRequest, CreateConnectorCustomerRequest,
    CreateConnectorCustomerResponse, PaymentIncrementalAuthRequest, PaymentIntentRequest,
    PaymentIntentRequest as RepeatPaymentRequest,
    PaymentIntentResponse as PaymentIncrementalAuthResponse, PaymentSyncResponse,
    PaymentsAuthorizeResponse, PaymentsAuthorizeResponse as RepeatPaymentResponse,
    PaymentsCaptureResponse, PaymentsVoidResponse, RefundResponse,
    RefundResponse as RefundSyncResponse, SetupMandateRequest, SetupMandateResponse,
    StripeRefundRequest, StripeTokenResponse, TokenRequest, WebhookEvent, WebhookEventObjectType,
    WebhookEventStatus, WebhookEventType, WebhookEventTypeBody, WebhookPaymentMethodDetails,
    WebhookPaymentMethodType,
};

use super::macros;
use crate::{types::ResponseRouterData, with_error_response_body};

pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const AUTHORIZATION: &str = "Authorization";
    pub(crate) const STRIPE_COMPATIBLE_CONNECT_ACCOUNT: &str = "Stripe-Account";
}
use stripe::auth_headers;

// Webhook helper functions

/// Parses the Stripe-Signature header and extracts key-value pairs
fn get_signature_elements_from_header(
    headers: &std::collections::HashMap<String, String>,
) -> Result<std::collections::HashMap<String, Vec<u8>>, ConnectorError> {
    let security_header = headers
        .get("Stripe-Signature")
        .or_else(|| headers.get("stripe-signature"))
        .ok_or(ConnectorError::WebhookSignatureNotFound)?;

    let props = security_header.split(',').collect::<Vec<&str>>();
    let mut security_header_kvs: std::collections::HashMap<String, Vec<u8>> =
        std::collections::HashMap::with_capacity(props.len());

    for prop_str in &props {
        let (prop_key, prop_value) = prop_str
            .split_once('=')
            .ok_or(ConnectorError::WebhookSourceVerificationFailed)?;

        security_header_kvs.insert(prop_key.to_string(), prop_value.bytes().collect());
    }

    Ok(security_header_kvs)
}

/// Get the transaction ID from a Stripe webhook event
fn get_stripe_transaction_id(details: &WebhookEvent) -> Result<String, ConnectorError> {
    match details.event_data.event_object.object {
        WebhookEventObjectType::PaymentIntent => Ok(details.event_data.event_object.id.clone()),
        WebhookEventObjectType::Charge => details
            .event_data
            .event_object
            .payment_intent
            .clone()
            .ok_or(ConnectorError::WebhookReferenceIdNotFound),
        WebhookEventObjectType::Dispute => details
            .event_data
            .event_object
            .payment_intent
            .clone()
            .ok_or(ConnectorError::WebhookReferenceIdNotFound),
        WebhookEventObjectType::Source => Ok(details.event_data.event_object.id.clone()),
        WebhookEventObjectType::Refund => Ok(details.event_data.event_object.id.clone()),
    }
}

/// Map webhook event to payment attempt status
fn get_payment_status_from_webhook(details: &WebhookEvent) -> common_enums::AttemptStatus {
    match &details.event_type {
        WebhookEventType::PaymentIntentSucceed => common_enums::AttemptStatus::Charged,
        WebhookEventType::PaymentIntentFailed => common_enums::AttemptStatus::Failure,
        WebhookEventType::PaymentIntentCanceled => common_enums::AttemptStatus::Voided,
        WebhookEventType::PaymentIntentProcessing => common_enums::AttemptStatus::Pending,
        WebhookEventType::PaymentIntentAmountCapturableUpdated => {
            common_enums::AttemptStatus::Authorized
        }
        WebhookEventType::PaymentIntentRequiresAction => {
            common_enums::AttemptStatus::AuthenticationPending
        }
        WebhookEventType::PaymentIntentPartiallyFunded => {
            common_enums::AttemptStatus::PartialCharged
        }
        WebhookEventType::ChargeCaptured => common_enums::AttemptStatus::Charged,
        WebhookEventType::ChargeSucceeded => common_enums::AttemptStatus::Pending,
        WebhookEventType::ChargeFailed => common_enums::AttemptStatus::Failure,
        WebhookEventType::ChargeExpired => common_enums::AttemptStatus::Failure,
        _ => {
            // Map based on status field if available
            details
                .event_data
                .event_object
                .status
                .as_ref()
                .map(|status| match status {
                    WebhookEventStatus::Succeeded => common_enums::AttemptStatus::Charged,
                    WebhookEventStatus::Failed => common_enums::AttemptStatus::Failure,
                    WebhookEventStatus::Processing => common_enums::AttemptStatus::Pending,
                    WebhookEventStatus::RequiresCapture => common_enums::AttemptStatus::Authorized,
                    WebhookEventStatus::RequiresAction => {
                        common_enums::AttemptStatus::AuthenticationPending
                    }
                    WebhookEventStatus::RequiresConfirmation => {
                        common_enums::AttemptStatus::ConfirmationAwaited
                    }
                    WebhookEventStatus::RequiresPaymentMethod => {
                        common_enums::AttemptStatus::PaymentMethodAwaited
                    }
                    WebhookEventStatus::Canceled => common_enums::AttemptStatus::Voided,
                    _ => common_enums::AttemptStatus::Pending,
                })
                .unwrap_or(common_enums::AttemptStatus::Pending)
        }
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::SdkSessionTokenV2 for Stripe<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ConnectorServiceTrait<T> for Stripe<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAuthorizeV2<T> for Stripe<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentSessionToken for Stripe<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAccessToken for Stripe<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::CreateConnectorCustomer for Stripe<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentSyncV2 for Stripe<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentVoidV2 for Stripe<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentVoidPostCaptureV2 for Stripe<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        VoidPC,
        PaymentFlowData,
        PaymentsCancelPostCaptureData,
        PaymentsResponseData,
    > for Stripe<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundSyncV2 for Stripe<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundV2 for Stripe<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentCapture for Stripe<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::SetupMandateV2<T> for Stripe<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::AcceptDispute for Stripe<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentIncrementalAuthorization for Stripe<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::SubmitEvidenceV2 for Stripe<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::DisputeDefend for Stripe<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RepeatPaymentV2<T> for Stripe<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentTokenV2<T> for Stripe<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentPreAuthenticateV2<T> for Stripe<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentOrderCreate for Stripe<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAuthenticateV2<T> for Stripe<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentPostAuthenticateV2<T> for Stripe<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::IncomingWebhook for Stripe<T>
{
    fn verify_webhook_source(
        &self,
        request: RequestDetails,
        connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorAuthType>,
    ) -> Result<bool, error_stack::Report<ConnectorError>> {
        // If no webhook secret is provided, cannot verify
        let webhook_secret = match connector_webhook_secret {
            Some(secrets) => secrets.secret,
            None => return Ok(false),
        };

        // Get signature and message
        let signature = self.get_webhook_source_verification_signature(
            &request,
            &ConnectorWebhookSecrets {
                secret: webhook_secret.clone(),
                additional_secret: None,
            },
        )?;

        let message = self.get_webhook_source_verification_message(
            &request,
            &ConnectorWebhookSecrets {
                secret: webhook_secret.clone(),
                additional_secret: None,
            },
        )?;

        // Compute HMAC-SHA256 and verify
        use common_utils::crypto::{HmacSha256, VerifySignature};
        let crypto_algorithm = HmacSha256;
        crypto_algorithm
            .verify_signature(&webhook_secret, &signature, &message)
            .map_err(|_| {
                error_stack::report!(ConnectorError::WebhookSourceVerificationFailed)
                    .attach_printable("Stripe webhook signature verification failed")
            })
    }

    fn get_webhook_source_verification_signature(
        &self,
        request: &RequestDetails,
        _connector_webhook_secret: &ConnectorWebhookSecrets,
    ) -> Result<Vec<u8>, error_stack::Report<ConnectorError>> {
        let mut security_header_kvs = get_signature_elements_from_header(&request.headers)?;

        let signature = security_header_kvs
            .remove("v1")
            .ok_or(ConnectorError::WebhookSignatureNotFound)?;

        hex::decode(signature).change_context(ConnectorError::WebhookSignatureNotFound)
    }

    fn get_webhook_source_verification_message(
        &self,
        request: &RequestDetails,
        _connector_webhook_secret: &ConnectorWebhookSecrets,
    ) -> Result<Vec<u8>, error_stack::Report<ConnectorError>> {
        let mut security_header_kvs = get_signature_elements_from_header(&request.headers)?;

        let timestamp = security_header_kvs
            .remove("t")
            .ok_or(ConnectorError::WebhookSignatureNotFound)?;

        Ok(format!(
            "{}.{}",
            String::from_utf8_lossy(&timestamp),
            String::from_utf8_lossy(&request.body)
        )
        .into_bytes())
    }

    fn get_event_type(
        &self,
        request: RequestDetails,
        _connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorAuthType>,
    ) -> Result<EventType, error_stack::Report<ConnectorError>> {
        let details: WebhookEventTypeBody = request
            .body
            .parse_struct("WebhookEventTypeBody")
            .change_context(ConnectorError::WebhookEventTypeNotFound)?;

        Ok(match details.event_type {
            WebhookEventType::PaymentIntentFailed => EventType::PaymentIntentFailure,
            WebhookEventType::PaymentIntentSucceed => EventType::PaymentIntentSuccess,
            WebhookEventType::PaymentIntentCanceled => EventType::PaymentIntentCancelled,
            WebhookEventType::PaymentIntentAmountCapturableUpdated => {
                EventType::PaymentIntentAuthorizationSuccess
            }
            WebhookEventType::ChargeSucceeded => {
                if let Some(WebhookPaymentMethodDetails {
                    payment_method:
                        WebhookPaymentMethodType::AchCreditTransfer
                        | WebhookPaymentMethodType::MultibancoBankTransfers,
                }) = details.event_data.event_object.payment_method_details
                {
                    EventType::PaymentIntentSuccess
                } else {
                    EventType::IncomingWebhookEventUnspecified
                }
            }
            WebhookEventType::ChargeRefundUpdated => details
                .event_data
                .event_object
                .status
                .map(|status| match status {
                    WebhookEventStatus::Succeeded => EventType::RefundSuccess,
                    WebhookEventStatus::Failed => EventType::RefundFailure,
                    _ => EventType::IncomingWebhookEventUnspecified,
                })
                .unwrap_or(EventType::IncomingWebhookEventUnspecified),
            WebhookEventType::SourceChargeable => EventType::SourceChargeable,
            WebhookEventType::DisputeCreated => EventType::DisputeOpened,
            WebhookEventType::DisputeClosed => EventType::DisputeCancelled,
            WebhookEventType::DisputeUpdated => details
                .event_data
                .event_object
                .status
                .map(|status| match status {
                    WebhookEventStatus::Won => EventType::DisputeWon,
                    WebhookEventStatus::Lost => EventType::DisputeLost,
                    WebhookEventStatus::NeedsResponse
                    | WebhookEventStatus::WarningNeedsResponse => EventType::DisputeOpened,
                    WebhookEventStatus::UnderReview | WebhookEventStatus::WarningUnderReview => {
                        EventType::DisputeChallenged
                    }
                    WebhookEventStatus::WarningClosed => EventType::DisputeCancelled,
                    _ => EventType::IncomingWebhookEventUnspecified,
                })
                .unwrap_or(EventType::IncomingWebhookEventUnspecified),
            WebhookEventType::PaymentIntentPartiallyFunded => {
                EventType::PaymentIntentPartiallyFunded
            }
            WebhookEventType::PaymentIntentRequiresAction => EventType::PaymentActionRequired,
            WebhookEventType::ChargeDisputeFundsWithdrawn => EventType::DisputeLost,
            WebhookEventType::ChargeDisputeFundsReinstated => EventType::DisputeWon,
            WebhookEventType::Unknown
            | WebhookEventType::ChargeCaptured
            | WebhookEventType::ChargeExpired
            | WebhookEventType::ChargeFailed
            | WebhookEventType::ChargePending
            | WebhookEventType::ChargeUpdated
            | WebhookEventType::ChargeRefunded
            | WebhookEventType::PaymentIntentCreated
            | WebhookEventType::PaymentIntentProcessing
            | WebhookEventType::SourceTransactionCreated => {
                EventType::IncomingWebhookEventUnspecified
            }
        })
    }

    fn process_payment_webhook(
        &self,
        request: RequestDetails,
        _connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorAuthType>,
    ) -> Result<WebhookDetailsResponse, error_stack::Report<ConnectorError>> {
        let request_body_copy = request.body.clone();
        let details: WebhookEvent = request
            .body
            .parse_struct("WebhookEvent")
            .change_context(ConnectorError::WebhookResourceObjectNotFound)?;

        let connector_transaction_id = get_stripe_transaction_id(&details)?;
        let status = get_payment_status_from_webhook(&details);

        Ok(WebhookDetailsResponse {
            resource_id: Some(ResponseId::ConnectorTransactionId(
                connector_transaction_id.clone(),
            )),
            status,
            status_code: 200,
            mandate_reference: None,
            connector_response_reference_id: Some(connector_transaction_id),
            error_code: details
                .event_data
                .event_object
                .last_payment_error
                .as_ref()
                .and_then(|e| e.code.clone()),
            error_message: details
                .event_data
                .event_object
                .last_payment_error
                .as_ref()
                .and_then(|e| e.message.clone()),
            raw_connector_response: Some(String::from_utf8_lossy(&request_body_copy).to_string()),
            response_headers: None,
            minor_amount_captured: None,
            amount_captured: None,
            error_reason: None,
            network_txn_id: None,
            transformation_status: common_enums::WebhookTransformationStatus::Complete,
        })
    }

    fn process_refund_webhook(
        &self,
        request: RequestDetails,
        _connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorAuthType>,
    ) -> Result<RefundWebhookDetailsResponse, error_stack::Report<ConnectorError>> {
        let request_body_copy = request.body.clone();
        let details: WebhookEvent = request
            .body
            .parse_struct("WebhookEvent")
            .change_context(ConnectorError::WebhookResourceObjectNotFound)?;

        let refund_status = details
            .event_data
            .event_object
            .status
            .as_ref()
            .map(|status| match status {
                WebhookEventStatus::Succeeded => common_enums::RefundStatus::Success,
                WebhookEventStatus::Failed => common_enums::RefundStatus::Failure,
                WebhookEventStatus::Processing => common_enums::RefundStatus::Pending,
                _ => common_enums::RefundStatus::Pending,
            })
            .unwrap_or(common_enums::RefundStatus::Pending);

        Ok(RefundWebhookDetailsResponse {
            connector_refund_id: Some(details.event_data.event_object.id.clone()),
            status: refund_status,
            status_code: 200,
            connector_response_reference_id: Some(details.event_data.event_object.id),
            error_code: None,
            error_message: None,
            raw_connector_response: Some(String::from_utf8_lossy(&request_body_copy).to_string()),
            response_headers: None,
        })
    }

    fn process_dispute_webhook(
        &self,
        request: RequestDetails,
        _connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorAuthType>,
    ) -> Result<DisputeWebhookDetailsResponse, error_stack::Report<ConnectorError>> {
        let request_body_copy = request.body.clone();
        let details: WebhookEvent = request
            .body
            .parse_struct("WebhookEvent")
            .change_context(ConnectorError::WebhookResourceObjectNotFound)?;

        let dispute_status = details
            .event_data
            .event_object
            .status
            .as_ref()
            .map(|status| match status {
                WebhookEventStatus::Won => common_enums::DisputeStatus::DisputeWon,
                WebhookEventStatus::Lost => common_enums::DisputeStatus::DisputeLost,
                WebhookEventStatus::NeedsResponse | WebhookEventStatus::WarningNeedsResponse => {
                    common_enums::DisputeStatus::DisputeOpened
                }
                WebhookEventStatus::UnderReview | WebhookEventStatus::WarningUnderReview => {
                    common_enums::DisputeStatus::DisputeChallenged
                }
                WebhookEventStatus::WarningClosed => common_enums::DisputeStatus::DisputeCancelled,
                _ => common_enums::DisputeStatus::DisputeOpened,
            })
            .unwrap_or(common_enums::DisputeStatus::DisputeOpened);

        let amount = utils::convert_amount(
            self.amount_converter,
            details
                .event_data
                .event_object
                .amount
                .unwrap_or(common_utils::types::MinorUnit::new(0)),
            details.event_data.event_object.currency,
        )
        .unwrap_or_else(|_| StringMinorUnit::default());

        Ok(DisputeWebhookDetailsResponse {
            amount,
            currency: details.event_data.event_object.currency,
            dispute_id: details.event_data.event_object.id.clone(),
            stage: common_enums::DisputeStage::Dispute,
            status: dispute_status,
            connector_response_reference_id: details.event_data.event_object.payment_intent.clone(),
            dispute_message: details.event_data.event_object.reason.clone(),
            connector_reason_code: None,
            raw_connector_response: Some(String::from_utf8_lossy(&request_body_copy).to_string()),
            status_code: 200,
            response_headers: None,
        })
    }

    fn get_webhook_resource_object(
        &self,
        request: RequestDetails,
    ) -> Result<
        Box<dyn hyperswitch_masking::ErasedMaskSerialize>,
        error_stack::Report<ConnectorError>,
    > {
        let details: WebhookEvent = request
            .body
            .parse_struct("WebhookEvent")
            .change_context(ConnectorError::WebhookBodyDecodingFailed)?;

        Ok(Box::new(details.event_data.event_object))
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::VerifyRedirectResponse for Stripe<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> SourceVerification
    for Stripe<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> BodyDecoding
    for Stripe<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ValidationTrait for Stripe<T>
{
    fn should_create_connector_customer(&self) -> bool {
        true
    }
    fn should_do_payment_method_token(
        &self,
        payment_method: common_enums::PaymentMethod,
        payment_method_type: Option<common_enums::PaymentMethodType>,
    ) -> bool {
        matches!(payment_method, common_enums::PaymentMethod::Wallet)
            && !matches!(
                payment_method_type,
                Some(common_enums::PaymentMethodType::GooglePay)
            )
    }
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::MandateRevokeV2 for Stripe<T>
{
}

macros::create_amount_converter_wrapper!(connector_name: Stripe, amount_type: MinorUnit);
macros::create_all_prerequisites!(
    connector_name: Stripe,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: PaymentIntentRequest<T>,
            response_body: PaymentsAuthorizeResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: RepeatPayment,
            request_body: RepeatPaymentRequest<T>,
            response_body: RepeatPaymentResponse,
            router_data: RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData<T>, PaymentsResponseData>,
        ),
        (
            flow: PSync,
            response_body: PaymentSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ),
        (
            flow: Capture,
            request_body: CaptureRequest,
            response_body: PaymentsCaptureResponse,
            router_data: RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ),
        (
            flow: Void,
            request_body: CancelRequest,
            response_body: PaymentsVoidResponse,
            router_data: RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ),
        (
            flow: Refund,
            request_body: StripeRefundRequest,
            response_body: RefundResponse,
            router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ),
        (
            flow: RSync,
            response_body: RefundSyncResponse,
            router_data: RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ),
        (
            flow: PaymentMethodToken,
            request_body: TokenRequest<T>,
            response_body: StripeTokenResponse,
            router_data: RouterDataV2<PaymentMethodToken, PaymentFlowData, PaymentMethodTokenizationData<T>, PaymentMethodTokenResponse>,
        ),
        (
            flow: SetupMandate,
            request_body: SetupMandateRequest<T>,
            response_body: SetupMandateResponse,
            router_data: RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>,
        ),
        (
            flow: CreateConnectorCustomer,
            request_body: CreateConnectorCustomerRequest,
            response_body: CreateConnectorCustomerResponse,
            router_data: RouterDataV2<CreateConnectorCustomer, PaymentFlowData, ConnectorCustomerData, ConnectorCustomerResponse>,
        ),
        (
            flow: IncrementalAuthorization,
            request_body: PaymentIncrementalAuthRequest,
            response_body: PaymentIncrementalAuthResponse,
            router_data: RouterDataV2<IncrementalAuthorization, PaymentFlowData, PaymentsIncrementalAuthorizationData, PaymentsResponseData>,
        )
    ],
    amount_converters: [
        amount_converter: StringMinorUnit
    ],
    member_functions: {
        pub fn build_headers<F, FCD, Req, Res>(
            &self,
            req: &RouterDataV2<F, FCD, Req, Res>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
            let mut header = vec![(
                headers::CONTENT_TYPE.to_string(),
                Self::common_get_content_type(self).to_string().into(),
            )];
            let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
            header.append(&mut api_key);
            Ok(header)
        }

        pub fn connector_base_url_payments<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.stripe.base_url
        }

        pub fn connector_base_url_refunds<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, RefundFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.stripe.base_url
        }
    }
);

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> ConnectorCommon
    for Stripe<T>
{
    fn id(&self) -> &'static str {
        "stripe"
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/x-www-form-urlencoded"
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        // &self.base_url
        connectors.stripe.base_url.as_ref()
    }

    fn get_auth_header(
        &self,
        auth_type: &ConnectorSpecificAuth,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        let auth = stripe::StripeAuthType::try_from(auth_type)
            .change_context(ConnectorError::FailedToObtainAuthType)?;
        Ok(vec![
            (
                headers::AUTHORIZATION.to_string(),
                format!("Bearer {}", auth.api_key.peek()).into_masked(),
            ),
            (
                auth_headers::STRIPE_API_VERSION.to_string(),
                auth_headers::STRIPE_VERSION.to_string().into_masked(),
            ),
        ])
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut events::Event>,
    ) -> CustomResult<ErrorResponse, ConnectorError> {
        let response: stripe::ErrorResponse = res
            .response
            .parse_struct("ErrorResponse")
            .change_context(ConnectorError::ResponseDeserializationFailed)?;

        with_error_response_body!(event_builder, response);

        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response
                .error
                .code
                .unwrap_or_else(|| NO_ERROR_CODE.to_string()),
            message: response
                .error
                .message
                .clone()
                .unwrap_or_else(|| NO_ERROR_MESSAGE.to_string()),
            reason: response.error.message.map(|message| {
                response
                    .error
                    .decline_code
                    .clone()
                    .map(|decline_code| {
                        format!("message - {message}, decline_code - {decline_code}")
                    })
                    .unwrap_or(message)
            }),
            attempt_status: None,
            connector_transaction_id: response.error.payment_intent.map(|pi| pi.id),
            network_advice_code: response.error.network_advice_code,
            network_decline_code: response.error.network_decline_code,
            network_error_message: response.error.decline_code.or(response.error.advice_code),
        })
    }
}

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Stripe,
    curl_request: FormUrlEncoded(PaymentIntentRequest),
    curl_response: PaymentsAuthorizeResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
            let mut header = vec![(
                headers::CONTENT_TYPE.to_string(),
                self.common_get_content_type()
                    .to_string()
                    .into(),
            )];

            let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
            header.append(&mut api_key);

            let stripe_split_payment_metadata = stripe::StripeSplitPaymentRequest::try_from(req)?;

            // if the request has split payment object, then append the transfer account id in headers in charge_type is Direct
            if let Some(domain_types::connector_types::SplitPaymentsRequest::StripeSplitPayment(
                stripe_split_payment,
            )) = &req.request.split_payments
            {
                if stripe_split_payment.charge_type
                    ==common_enums::PaymentChargeType::Stripe(common_enums::StripeChargeType::Direct)
                {
                    let mut customer_account_header = vec![(
                        headers::STRIPE_COMPATIBLE_CONNECT_ACCOUNT.to_string(),
                        stripe_split_payment
                            .transfer_account_id
                            .clone()
                            .into_masked(),
                    )];
                    header.append(&mut customer_account_header);
                }
            }
            // if request doesn't have transfer_account_id, but stripe_split_payment_metadata has it, append it
            else if let Some(transfer_account_id) =
                stripe_split_payment_metadata.transfer_account_id.clone()
            {
                let mut customer_account_header = vec![(
                    headers::STRIPE_COMPATIBLE_CONNECT_ACCOUNT.to_string(),
                    transfer_account_id.into_masked(),
                )];
                header.append(&mut customer_account_header);
            }
            Ok(header)
        }

        fn get_url(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<String, ConnectorError> {
            Ok(format!(
                "{}{}",
                self.connector_base_url_payments(req),
                "v1/payment_intents"
            ))
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Stripe,
    curl_request: FormUrlEncoded(RepeatPaymentRequest),
    curl_response: RepeatPaymentResponse,
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
        ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
            let mut header = vec![(
                headers::CONTENT_TYPE.to_string(),
                self.common_get_content_type()
                    .to_string()
                    .into(),
            )];

            let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
            header.append(&mut api_key);

            let stripe_split_payment_metadata = stripe::StripeSplitPaymentRequest::try_from(req)?;

            let transfer_account_id = req
                .request
                .split_payments
                .as_ref()
                .map(|split_payments| {
                    let domain_types::connector_types::SplitPaymentsRequest::StripeSplitPayment(stripe_split_payment) =
                        split_payments;
                    stripe_split_payment
                })
                .filter(|stripe_split_payment| {
                    matches!(stripe_split_payment.charge_type, common_enums::PaymentChargeType::Stripe(common_enums::StripeChargeType::Direct))
                })
                .map(|stripe_split_payment| stripe_split_payment.transfer_account_id.clone())
                .or_else(|| stripe_split_payment_metadata.transfer_account_id.clone().map(|s| s.expose()));

            if let Some(transfer_account_id) = transfer_account_id {
                let mut customer_account_header = vec![(
                    headers::STRIPE_COMPATIBLE_CONNECT_ACCOUNT.to_string(),
                    transfer_account_id.clone().into_masked(),
                )];
                header.append(&mut customer_account_header);
            };
            Ok(header)
        }

        fn get_url(
            &self,
            req: &RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData<T>, PaymentsResponseData>,
        ) -> CustomResult<String, ConnectorError> {
            Ok(format!(
                "{}{}",
                self.connector_base_url_payments(req),
                "v1/payment_intents"
            ))
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Stripe,
    curl_request: FormUrlEncoded(TokenRequest),
    curl_response: StripeTokenResponse,
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
        ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
            let mut header = vec![(
                headers::CONTENT_TYPE.to_string(),
                self.common_get_content_type().to_string().into(),
            )];
            let transfer_account_id = req
                .request
                .split_payments
                .as_ref()
                .map(|split_payments| {
                    let domain_types::connector_types::SplitPaymentsRequest::StripeSplitPayment(stripe_split_payment) =
                        split_payments;
                    stripe_split_payment
                })
                .filter(|stripe_split_payment| {
                    matches!(stripe_split_payment.charge_type, common_enums::PaymentChargeType::Stripe(common_enums::StripeChargeType::Direct))
                })
                .map(|stripe_split_payment| stripe_split_payment.transfer_account_id.clone());

            if let Some(transfer_account_id) = transfer_account_id {
                let mut customer_account_header = vec![(
                    headers::STRIPE_COMPATIBLE_CONNECT_ACCOUNT.to_string(),
                    transfer_account_id.clone().into_masked(),
                )];
                header.append(&mut customer_account_header);
            };

            let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
            header.append(&mut api_key);
            Ok(header)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<PaymentMethodToken, PaymentFlowData, PaymentMethodTokenizationData<T>, PaymentMethodTokenResponse>,
        ) -> CustomResult<String, ConnectorError> {
            if matches!(
                req.request.split_payments,
                Some(domain_types::connector_types::SplitPaymentsRequest::StripeSplitPayment(_))
            ) {
                Ok(format!(
                    "{}{}",
                    self.connector_base_url_payments(req),
                    "v1/payment_methods"
                ))
            }
            else {
                Ok(format!("{}{}", self.connector_base_url_payments(req), "v1/tokens"))
            }
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Stripe,
    curl_request: FormUrlEncoded(SetupMandateRequest),
    curl_response: SetupMandateResponse,
    flow_name: SetupMandate,
    resource_common_data: PaymentFlowData,
    flow_request: SetupMandateRequestData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
            let mut header = vec![(
                headers::CONTENT_TYPE.to_string(),
                self.common_get_content_type().to_string().into(),
            )];
            let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
            header.append(&mut api_key);
            Ok(header)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>,
        ) -> CustomResult<String, ConnectorError> {
            Ok(format!(
                "{}{}",
                self.connector_base_url_payments(req),
                "v1/setup_intents"
            ))
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Stripe,
    curl_request: FormUrlEncoded(CreateConnectorCustomerRequest),
    curl_response: CreateConnectorCustomerResponse,
    flow_name: CreateConnectorCustomer,
    resource_common_data: PaymentFlowData,
    flow_request: ConnectorCustomerData,
    flow_response: ConnectorCustomerResponse,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<CreateConnectorCustomer, PaymentFlowData, ConnectorCustomerData, ConnectorCustomerResponse>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
            let mut header = vec![(
                headers::CONTENT_TYPE.to_string(),
                self.common_get_content_type()
                    .to_string()
                    .into(),
            )];
            let transfer_account_id = req
                .request
                .split_payments
                .as_ref()
                .map(|split_payments| {
                    let domain_types::connector_types::SplitPaymentsRequest::StripeSplitPayment(stripe_split_payment) =
                        split_payments;
                    stripe_split_payment
                })
                .filter(|stripe_split_payment| {
                    matches!(stripe_split_payment.charge_type, common_enums::PaymentChargeType::Stripe(common_enums::StripeChargeType::Direct))
                })
                .map(|stripe_split_payment| stripe_split_payment.transfer_account_id.clone());

            if let Some(transfer_account_id) = transfer_account_id {
                let mut customer_account_header = vec![(
                    headers::STRIPE_COMPATIBLE_CONNECT_ACCOUNT.to_string(),
                    transfer_account_id.clone().into_masked(),
                )];
                header.append(&mut customer_account_header);
            };

            let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
            header.append(&mut api_key);
            Ok(header)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<CreateConnectorCustomer, PaymentFlowData, ConnectorCustomerData, ConnectorCustomerResponse>,
        ) -> CustomResult<String, ConnectorError> {
            Ok(format!("{}{}", self.connector_base_url_payments(req), "v1/customers"))
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Stripe,
    curl_response: PaymentSyncResponse,
    flow_name: PSync,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsSyncData,
    flow_response: PaymentsResponseData,
    http_method: Get,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
            let mut header = vec![(
                headers::CONTENT_TYPE.to_string(),
                self.common_get_content_type().to_string().into(),
            )];
            let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
            header.append(&mut api_key);

            if let Some(domain_types::connector_types::SplitPaymentsRequest::StripeSplitPayment(
                stripe_split_payment,
            )) = &req.request.split_payments
            {
                transformers::transform_headers_for_connect_platform(
                    stripe_split_payment.charge_type.clone(),
                    Secret::new(stripe_split_payment.transfer_account_id.clone()),
                    &mut header,
                );
            }
            Ok(header)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<String, ConnectorError> {
            let id = req.request.connector_transaction_id.clone();

            match id.get_connector_transaction_id() {
                Ok(x) if x.starts_with("set") => Ok(format!(
                    "{}{}/{}?expand[0]=latest_attempt", // expand latest attempt to extract payment checks and three_d_secure data
                    self.connector_base_url_payments(req),
                    "v1/setup_intents",
                    x,
                )),
                Ok(x) => Ok(format!(
                    "{}{}/{}{}",
                    self.connector_base_url_payments(req),
                    "v1/payment_intents",
                    x,
                    "?expand[0]=latest_charge" //updated payment_id(if present) reside inside latest_charge field
                )),
                x => x.change_context(ConnectorError::MissingConnectorTransactionID),
            }
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Stripe,
    curl_request: FormUrlEncoded(CaptureRequest),
    curl_response: PaymentsCaptureResponse,
    flow_name: Capture,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsCaptureData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
            let mut header = vec![(
                headers::CONTENT_TYPE.to_string(),
                Self::common_get_content_type(self).to_string().into(),
            )];
            let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
            header.append(&mut api_key);
            Ok(header)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ) -> CustomResult<String, ConnectorError> {
            let id = req.request.connector_transaction_id.get_connector_transaction_id()
                .change_context(ConnectorError::MissingConnectorTransactionID)?;
            Ok(format!(
                "{}{}/{}/capture",
                self.connector_base_url_payments(req),
                "v1/payment_intents",
                id
            ))
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Stripe,
    curl_request: FormUrlEncoded(CancelRequest),
    curl_response: PaymentsVoidResponse,
    flow_name: Void,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentVoidData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
            let mut header = vec![(
                headers::CONTENT_TYPE.to_string(),
                self.common_get_content_type().to_string().into(),
            )];
            let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
            header.append(&mut api_key);
            Ok(header)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ) -> CustomResult<String, ConnectorError> {
            let payment_id = &req.request.connector_transaction_id;
            Ok(format!(
                "{}v1/payment_intents/{}/cancel",
                self.connector_base_url_payments(req),
                payment_id
            ))
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Stripe,
    curl_request: FormUrlEncoded(PaymentIncrementalAuthRequest),
    curl_response: PaymentIncrementalAuthResponse,
    flow_name: IncrementalAuthorization,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsIncrementalAuthorizationData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<IncrementalAuthorization, PaymentFlowData, PaymentsIncrementalAuthorizationData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
            self.build_headers(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<IncrementalAuthorization, PaymentFlowData, PaymentsIncrementalAuthorizationData, PaymentsResponseData>,
        ) -> CustomResult<String, ConnectorError> {
            let payment_id = &req.request.connector_transaction_id.get_connector_transaction_id()
                .change_context(ConnectorError::MissingConnectorTransactionID)?;
            Ok(format!(
                "{}v1/payment_intents/{}/increment_authorization",
                self.connector_base_url_payments(req),
                payment_id
            ))
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Stripe,
    curl_request: FormUrlEncoded(StripeRefundRequest),
    curl_response: RefundResponse,
    flow_name: Refund,
    resource_common_data: RefundFlowData,
    flow_request: RefundsData,
    flow_response: RefundsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
            let mut header = vec![(
                headers::CONTENT_TYPE.to_string(),
                self.common_get_content_type().to_string().into(),
            )];
            let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
            header.append(&mut api_key);

            if let Some(domain_types::connector_types::SplitRefundsRequest::StripeSplitRefund(ref stripe_split_refund)) =
                req.request.split_refunds.as_ref()
            {
                match &stripe_split_refund.charge_type {
                    common_enums::PaymentChargeType::Stripe(stripe_charge) => {
                        if stripe_charge == &common_enums::StripeChargeType::Direct {
                            let mut customer_account_header = vec![(
                                headers::STRIPE_COMPATIBLE_CONNECT_ACCOUNT.to_string(),
                                stripe_split_refund
                                    .transfer_account_id
                                    .clone()
                                    .into_masked(),
                            )];
                            header.append(&mut customer_account_header);
                        }
                    }
                }
            }
            Ok(header)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ) -> CustomResult<String, ConnectorError> {
            Ok(format!("{}{}", self.connector_base_url_refunds(req), "v1/refunds"))
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Stripe,
    curl_response: RefundSyncResponse,
    flow_name: RSync,
    resource_common_data: RefundFlowData,
    flow_request: RefundSyncData,
    flow_response: RefundsResponseData,
    http_method: Get,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
            let mut header = vec![(
                headers::CONTENT_TYPE.to_string(),
                self.common_get_content_type().to_string().into(),
            )];
            let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
            header.append(&mut api_key);

            if let Some(domain_types::connector_types::SplitRefundsRequest::StripeSplitRefund(ref stripe_refund)) =
                req.request.split_refunds.as_ref()
            {
                transformers::transform_headers_for_connect_platform(
                    stripe_refund.charge_type.clone(),
                    Secret::new(stripe_refund.transfer_account_id.clone()),
                    &mut header,
                );
            }
            Ok(header)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ) -> CustomResult<String, ConnectorError> {
            let id = req.request.connector_refund_id.clone();
            Ok(format!("{}v1/refunds/{}", self.connector_base_url_refunds(req), id))
        }
    }
);

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    for Stripe<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
    for Stripe<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
    for Stripe<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for Stripe<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        CreateSessionToken,
        PaymentFlowData,
        SessionTokenRequestData,
        SessionTokenResponseData,
    > for Stripe<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        CreateAccessToken,
        PaymentFlowData,
        AccessTokenRequestData,
        AccessTokenResponseData,
    > for Stripe<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        PreAuthenticate,
        PaymentFlowData,
        PaymentsPreAuthenticateData<T>,
        PaymentsResponseData,
    > for Stripe<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        Authenticate,
        PaymentFlowData,
        PaymentsAuthenticateData<T>,
        PaymentsResponseData,
    > for Stripe<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        PostAuthenticate,
        PaymentFlowData,
        PaymentsPostAuthenticateData<T>,
        PaymentsResponseData,
    > for Stripe<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        MandateRevoke,
        PaymentFlowData,
        MandateRevokeRequestData,
        MandateRevokeResponseData,
    > for Stripe<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        SdkSessionToken,
        PaymentFlowData,
        PaymentsSdkSessionTokenData,
        PaymentsResponseData,
    > for Stripe<T>
{
}

// SourceVerification implementations for all flows
