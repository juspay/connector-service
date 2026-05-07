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
};
use domain_types::{
    connector_flow::{
        Accept, Authenticate, Authorize, Capture, ClientAuthenticationToken,
        CreateConnectorCustomer, CreateOrder, DefendDispute, IncrementalAuthorization,
        MandateRevoke, PSync, PaymentMethodToken, PostAuthenticate, PreAuthenticate, RSync, Refund,
        RepeatPayment, ServerAuthenticationToken, ServerSessionAuthenticationToken, SetupMandate,
        SubmitEvidence, Void, VoidPC,
    },
    connector_types::{
        AcceptDisputeData, ClientAuthenticationTokenRequestData, ConnectorCustomerData,
        ConnectorCustomerResponse, DisputeDefendData, DisputeFlowData, DisputeResponseData,
        MandateRevokeRequestData, MandateRevokeResponseData, PaymentCreateOrderData,
        PaymentCreateOrderResponse, PaymentFlowData, PaymentMethodTokenResponse,
        PaymentMethodTokenizationData, PaymentVoidData, PaymentsAuthenticateData,
        PaymentsAuthorizeData, PaymentsCancelPostCaptureData, PaymentsCaptureData,
        PaymentsIncrementalAuthorizationData, PaymentsPostAuthenticateData,
        PaymentsPreAuthenticateData, PaymentsResponseData, PaymentsSyncData, RefundFlowData,
        RefundSyncData, RefundsData, RefundsResponseData, RepeatPaymentData,
        ServerAuthenticationTokenRequestData, ServerAuthenticationTokenResponseData,
        ServerSessionAuthenticationTokenRequestData, ServerSessionAuthenticationTokenResponseData,
        SetupMandateRequestData, SubmitEvidenceData,
    },
    errors::{ConnectorError, IntegrationError},
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorSpecificConfig, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
};

use common_utils::types::AmountConvertor;
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
    StripeAcceptDisputeResponse, StripeClientAuthRequest, StripeClientAuthResponse,
    StripeDefendDisputeRequest, StripeDefendDisputeResponse, StripeRefundRequest,
    StripeSubmitEvidenceRequest, StripeSubmitEvidenceResponse, StripeTokenResponse, TokenRequest,
};

use super::macros;
use crate::{types::ResponseRouterData, with_error_response_body};

pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const AUTHORIZATION: &str = "Authorization";
    pub(crate) const STRIPE_COMPATIBLE_CONNECT_ACCOUNT: &str = "Stripe-Account";
}
use stripe::auth_headers;

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ClientAuthentication for Stripe<T>
{
}

macros::macro_connector_payout_implementation!(
    connector: Stripe,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize]
);

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ConnectorServiceTrait<T> for Stripe<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAuthorizeV2<T> for Stripe<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ServerSessionAuthentication for Stripe<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ServerAuthentication for Stripe<T>
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
        request: domain_types::connector_types::RequestDetails,
        connector_webhook_secret: Option<domain_types::connector_types::ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorSpecificConfig>,
    ) -> Result<bool, error_stack::Report<domain_types::errors::WebhookError>> {
        use common_utils::crypto::VerifySignature;

        let connector_webhook_secrets = connector_webhook_secret
            .ok_or(domain_types::errors::WebhookError::WebhookVerificationSecretNotFound)
            .attach_printable("Stripe webhook signing secret not configured")?;

        let signature_header = request
            .headers
            .get("stripe-signature")
            .ok_or(domain_types::errors::WebhookError::WebhookSignatureNotFound)
            .attach_printable("Missing Stripe-Signature header")?;

        let mut timestamp = None;
        let mut v1_signatures: Vec<String> = Vec::new();
        for part in signature_header.split(',') {
            if let Some((key, value)) = part.split_once('=') {
                match key.trim() {
                    "t" => timestamp = Some(value.to_string()),
                    "v1" => v1_signatures.push(value.to_string()),
                    _ => {}
                }
            }
        }

        let timestamp = timestamp
            .ok_or(domain_types::errors::WebhookError::WebhookSignatureNotFound)
            .attach_printable("Missing timestamp in Stripe-Signature header")?;

        let timestamp_secs: i64 = timestamp
            .parse()
            .map_err(|_| domain_types::errors::WebhookError::WebhookSourceVerificationFailed)
            .attach_printable("Invalid timestamp in Stripe-Signature header")?;
        let now_secs = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| domain_types::errors::WebhookError::WebhookSourceVerificationFailed)
                .attach_printable("System clock is before UNIX epoch")?
                .as_secs(),
        )
        .map_err(|_| domain_types::errors::WebhookError::WebhookSourceVerificationFailed)
        .attach_printable("System time value out of range")?;
        if (now_secs - timestamp_secs).abs() > 300 {
            return Err(error_stack::Report::new(
                domain_types::errors::WebhookError::WebhookSourceVerificationFailed,
            )
            .attach_printable("Webhook timestamp outside 5-minute tolerance window"));
        }

        if v1_signatures.is_empty() {
            return Err(domain_types::errors::WebhookError::WebhookSignatureNotFound.into());
        }

        let body_str = String::from_utf8_lossy(&request.body);
        let signed_payload = format!("{timestamp}.{body_str}");

        let is_valid = v1_signatures.iter().any(|sig| {
            hex::decode(sig)
                .ok()
                .and_then(|decoded| {
                    common_utils::crypto::HmacSha256
                        .verify_signature(
                            &connector_webhook_secrets.secret,
                            &decoded,
                            signed_payload.as_bytes(),
                        )
                        .ok()
                })
                .unwrap_or(false)
        });

        Ok(is_valid)
    }

    fn get_webhook_source_verification_signature(
        &self,
        request: &domain_types::connector_types::RequestDetails,
        _connector_webhook_secret: &domain_types::connector_types::ConnectorWebhookSecrets,
    ) -> Result<Vec<u8>, error_stack::Report<domain_types::errors::WebhookError>> {
        let signature_header = request
            .headers
            .get("stripe-signature")
            .ok_or(domain_types::errors::WebhookError::WebhookSignatureNotFound)?;

        for part in signature_header.split(',') {
            if let Some((key, value)) = part.split_once('=') {
                if key.trim() == "v1" {
                    return hex::decode(value)
                        .change_context(
                            domain_types::errors::WebhookError::WebhookSignatureNotFound,
                        )
                        .attach_printable("Failed to decode v1 hex signature");
                }
            }
        }

        Err(domain_types::errors::WebhookError::WebhookSignatureNotFound.into())
    }

    fn get_webhook_source_verification_message(
        &self,
        request: &domain_types::connector_types::RequestDetails,
        _connector_webhook_secret: &domain_types::connector_types::ConnectorWebhookSecrets,
    ) -> Result<Vec<u8>, error_stack::Report<domain_types::errors::WebhookError>> {
        let signature_header = request
            .headers
            .get("stripe-signature")
            .ok_or(domain_types::errors::WebhookError::WebhookSignatureNotFound)?;

        let timestamp = signature_header
            .split(',')
            .find_map(|part| {
                part.split_once('=').and_then(|(key, value)| {
                    if key.trim() == "t" {
                        Some(value.to_string())
                    } else {
                        None
                    }
                })
            })
            .ok_or(domain_types::errors::WebhookError::WebhookSignatureNotFound)
            .attach_printable("Missing timestamp in Stripe-Signature header")?;

        let body_str = String::from_utf8_lossy(&request.body);
        Ok(format!("{timestamp}.{body_str}").into_bytes())
    }

    fn sample_webhook_body(&self) -> &'static [u8] {
        br#"{"id":"evt_test_001","object":"event","type":"payment_intent.succeeded","data":{"object":{"id":"pi_test_001","object":"payment_intent","amount":2000,"currency":"usd","status":"succeeded","created":1686089970,"metadata":{}}},"livemode":false,"created":1686089970,"pending_webhooks":0}"#
    }

    fn get_event_type(
        &self,
        request: domain_types::connector_types::RequestDetails,
    ) -> Result<
        domain_types::connector_types::EventType,
        error_stack::Report<domain_types::errors::WebhookError>,
    > {
        let event: stripe::WebhookEventTypeBody = serde_json::from_slice(&request.body)
            .change_context(domain_types::errors::WebhookError::WebhookBodyDecodingFailed)
            .attach_printable("Failed to deserialize Stripe webhook event")?;

        Ok(stripe::map_webhook_event_to_event_type(
            &event.event_type,
            &event.event_data.event_object.status,
        ))
    }

    fn get_webhook_event_reference(
        &self,
        request: domain_types::connector_types::RequestDetails,
    ) -> Result<
        Option<domain_types::connector_types::WebhookResourceReference>,
        error_stack::Report<domain_types::errors::WebhookError>,
    > {
        let event: stripe::WebhookEvent = serde_json::from_slice(&request.body)
            .change_context(domain_types::errors::WebhookError::WebhookBodyDecodingFailed)?;

        let obj = &event.event_data.event_object;

        match obj.object {
            stripe::WebhookEventObjectType::PaymentIntent => Ok(Some(
                domain_types::connector_types::WebhookResourceReference::Payment(
                    domain_types::connector_types::PaymentWebhookReference {
                        connector_transaction_id: Some(obj.id.clone()),
                        merchant_transaction_id: obj
                            .metadata
                            .as_ref()
                            .and_then(|m| m.order_id.clone()),
                    },
                ),
            )),
            stripe::WebhookEventObjectType::Charge | stripe::WebhookEventObjectType::Source => {
                let connector_transaction_id =
                    obj.payment_intent.clone().unwrap_or_else(|| obj.id.clone());
                Ok(Some(
                    domain_types::connector_types::WebhookResourceReference::Payment(
                        domain_types::connector_types::PaymentWebhookReference {
                            connector_transaction_id: Some(connector_transaction_id),
                            merchant_transaction_id: obj
                                .metadata
                                .as_ref()
                                .and_then(|m| m.order_id.clone()),
                        },
                    ),
                ))
            }
            stripe::WebhookEventObjectType::Refund => Ok(Some(
                domain_types::connector_types::WebhookResourceReference::Refund(
                    domain_types::connector_types::RefundWebhookReference {
                        connector_refund_id: Some(obj.id.clone()),
                        merchant_refund_id: None,
                        connector_transaction_id: obj.payment_intent.clone(),
                    },
                ),
            )),
            stripe::WebhookEventObjectType::Dispute => Ok(Some(
                domain_types::connector_types::WebhookResourceReference::Dispute(
                    domain_types::connector_types::DisputeWebhookReference {
                        connector_dispute_id: Some(obj.id.clone()),
                        connector_transaction_id: obj.payment_intent.clone(),
                    },
                ),
            )),
        }
    }

    fn process_payment_webhook(
        &self,
        request: domain_types::connector_types::RequestDetails,
        _connector_webhook_secret: Option<domain_types::connector_types::ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorSpecificConfig>,
        event_context: Option<domain_types::connector_types::EventContext>,
    ) -> Result<
        domain_types::connector_types::WebhookDetailsResponse,
        error_stack::Report<domain_types::errors::WebhookError>,
    > {
        let raw_body = String::from_utf8_lossy(&request.body).to_string();
        let event_type_body: stripe::WebhookEventTypeBody =
            serde_json::from_slice(&request.body)
                .change_context(domain_types::errors::WebhookError::WebhookBodyDecodingFailed)?;
        let event: stripe::WebhookEvent = serde_json::from_slice(&request.body)
            .change_context(domain_types::errors::WebhookError::WebhookBodyDecodingFailed)?;

        let status = stripe::get_payment_attempt_status_from_webhook(
            &event_type_body.event_type,
            &event_type_body.event_data.event_object.status,
            &event_context,
        );

        let obj = &event.event_data.event_object;

        let connector_transaction_id = match obj.object {
            stripe::WebhookEventObjectType::PaymentIntent => Some(obj.id.clone()),
            stripe::WebhookEventObjectType::Charge | stripe::WebhookEventObjectType::Source => {
                obj.payment_intent.clone().or_else(|| Some(obj.id.clone()))
            }
            _ => None,
        };

        let resource_id = connector_transaction_id
            .map(domain_types::connector_types::ResponseId::ConnectorTransactionId);

        let (error_code, error_message, error_reason) =
            if status == common_enums::AttemptStatus::Failure {
                let err = obj.last_payment_error.as_ref();
                (
                    err.and_then(|e| e.code.clone()),
                    err.and_then(|e| e.message.clone()),
                    err.and_then(|e| e.message.clone()),
                )
            } else {
                (None, None, None)
            };

        Ok(domain_types::connector_types::WebhookDetailsResponse {
            resource_id,
            status,
            connector_response_reference_id: obj.metadata.as_ref().and_then(|m| m.order_id.clone()),
            mandate_reference: None,
            error_code,
            error_message,
            error_reason,
            raw_connector_response: Some(raw_body),
            status_code: 200,
            response_headers: None,
            amount_captured: None,
            minor_amount_captured: None,
            network_txn_id: None,
            payment_method_update: None,
        })
    }

    fn process_refund_webhook(
        &self,
        request: domain_types::connector_types::RequestDetails,
        _connector_webhook_secret: Option<domain_types::connector_types::ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorSpecificConfig>,
    ) -> Result<
        domain_types::connector_types::RefundWebhookDetailsResponse,
        error_stack::Report<domain_types::errors::WebhookError>,
    > {
        let raw_body = String::from_utf8_lossy(&request.body).to_string();
        let event_type_body: stripe::WebhookEventTypeBody =
            serde_json::from_slice(&request.body)
                .change_context(domain_types::errors::WebhookError::WebhookBodyDecodingFailed)?;
        let event: stripe::WebhookEvent = serde_json::from_slice(&request.body)
            .change_context(domain_types::errors::WebhookError::WebhookBodyDecodingFailed)?;

        let status =
            stripe::get_refund_status_from_webhook(&event_type_body.event_data.event_object.status);

        Ok(
            domain_types::connector_types::RefundWebhookDetailsResponse {
                connector_refund_id: Some(event.event_data.event_object.id.clone()),
                status,
                connector_response_reference_id: None,
                error_code: None,
                error_message: None,
                raw_connector_response: Some(raw_body),
                status_code: 200,
                response_headers: None,
            },
        )
    }

    fn process_dispute_webhook(
        &self,
        request: domain_types::connector_types::RequestDetails,
        _connector_webhook_secret: Option<domain_types::connector_types::ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorSpecificConfig>,
    ) -> Result<
        domain_types::connector_types::DisputeWebhookDetailsResponse,
        error_stack::Report<domain_types::errors::WebhookError>,
    > {
        let raw_body = String::from_utf8_lossy(&request.body).to_string();
        let event_type_body: stripe::WebhookEventTypeBody =
            serde_json::from_slice(&request.body)
                .change_context(domain_types::errors::WebhookError::WebhookBodyDecodingFailed)?;
        let event: stripe::WebhookEvent = serde_json::from_slice(&request.body)
            .change_context(domain_types::errors::WebhookError::WebhookBodyDecodingFailed)?;

        let obj = &event.event_data.event_object;
        let (stage, dispute_status) = stripe::get_dispute_stage_and_status(
            &event_type_body.event_type,
            &event_type_body.event_data.event_object.status,
        );

        let amount = obj
            .amount
            .ok_or(domain_types::errors::WebhookError::WebhookProcessingFailed)
            .attach_printable("Missing amount in Stripe dispute webhook")?;

        let amount_string = common_utils::types::StringMinorUnitForConnector
            .convert(amount, obj.currency)
            .change_context(
                domain_types::errors::WebhookError::WebhookAmountConversionFailed {
                    reason: format!(
                        "Failed to convert dispute amount: {}",
                        amount.get_amount_as_i64()
                    ),
                },
            )?;

        Ok(
            domain_types::connector_types::DisputeWebhookDetailsResponse {
                amount: amount_string,
                currency: obj.currency,
                dispute_id: obj.id.clone(),
                status: dispute_status,
                stage,
                connector_response_reference_id: obj.payment_intent.clone(),
                dispute_message: obj.reason.clone(),
                raw_connector_response: Some(raw_body),
                status_code: 200,
                response_headers: None,
                connector_reason_code: None,
            },
        )
    }

    fn get_webhook_resource_object(
        &self,
        request: domain_types::connector_types::RequestDetails,
    ) -> Result<
        Box<dyn hyperswitch_masking::ErasedMaskSerialize>,
        error_stack::Report<domain_types::errors::WebhookError>,
    > {
        let event: stripe::WebhookEventObjectResource = serde_json::from_slice(&request.body)
            .change_context(domain_types::errors::WebhookError::WebhookBodyDecodingFailed)?;

        Ok(Box::new(event.data.object))
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
    ConnectorIntegrationV2<
        MandateRevoke,
        PaymentFlowData,
        MandateRevokeRequestData,
        MandateRevokeResponseData,
    > for Stripe<T>
{
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
        ),
        (
            flow: ClientAuthenticationToken,
            request_body: StripeClientAuthRequest,
            response_body: StripeClientAuthResponse,
            router_data: RouterDataV2<ClientAuthenticationToken, PaymentFlowData, ClientAuthenticationTokenRequestData, PaymentsResponseData>,
        ),
        (
            flow: Accept,
            response_body: StripeAcceptDisputeResponse,
            router_data: RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>,
        ),
        (
            flow: SubmitEvidence,
            request_body: StripeSubmitEvidenceRequest,
            response_body: StripeSubmitEvidenceResponse,
            router_data: RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>,
        ),
        (
            flow: DefendDispute,
            request_body: StripeDefendDisputeRequest,
            response_body: StripeDefendDisputeResponse,
            router_data: RouterDataV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>,
        )
    ],
    amount_converters: [],
    member_functions: {
        pub fn build_headers<F, FCD, Req, Res>(
            &self,
            req: &RouterDataV2<F, FCD, Req, Res>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, IntegrationError> {
            let mut header = vec![(
                headers::CONTENT_TYPE.to_string(),
                Self::common_get_content_type(self).to_string().into(),
            )];
            let mut api_key = self.get_auth_header(&req.connector_config)?;
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

        pub fn connector_base_url_disputes<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, DisputeFlowData, Req, Res>,
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
        auth_type: &ConnectorSpecificConfig,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, IntegrationError> {
        let auth = stripe::StripeAuthType::try_from(auth_type).change_context(
            IntegrationError::FailedToObtainAuthType {
                context: Default::default(),
            },
        )?;
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
        let response: stripe::ErrorResponse =
            res.response.parse_struct("ErrorResponse").change_context(
                crate::utils::response_handling_fail_for_connector(res.status_code, "stripe"),
            )?;

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
        ) -> CustomResult<Vec<(String, Maskable<String>)>, IntegrationError> {
            let mut header = vec![(
                headers::CONTENT_TYPE.to_string(),
                self.common_get_content_type()
                    .to_string()
                    .into(),
            )];

            let mut api_key = self.get_auth_header(&req.connector_config)?;
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
        ) -> CustomResult<String, IntegrationError> {
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
        ) -> CustomResult<Vec<(String, Maskable<String>)>, IntegrationError> {
            let mut header = vec![(
                headers::CONTENT_TYPE.to_string(),
                self.common_get_content_type()
                    .to_string()
                    .into(),
            )];

            let mut api_key = self.get_auth_header(&req.connector_config)?;
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
        ) -> CustomResult<String, IntegrationError> {
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
        ) -> CustomResult<Vec<(String, Maskable<String>)>, IntegrationError> {
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

            let mut api_key = self.get_auth_header(&req.connector_config)?;
            header.append(&mut api_key);
            Ok(header)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<PaymentMethodToken, PaymentFlowData, PaymentMethodTokenizationData<T>, PaymentMethodTokenResponse>,
        ) -> CustomResult<String, IntegrationError> {
            Ok(format!(
                "{}{}",
                self.connector_base_url_payments(req),
                "v1/payment_methods"
            ))
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
        ) -> CustomResult<Vec<(String, Maskable<String>)>, IntegrationError> {
            let mut header = vec![(
                headers::CONTENT_TYPE.to_string(),
                self.common_get_content_type().to_string().into(),
            )];
            let mut api_key = self.get_auth_header(&req.connector_config)?;
            header.append(&mut api_key);
            Ok(header)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>,
        ) -> CustomResult<String, IntegrationError> {
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
        ) -> CustomResult<Vec<(String, Maskable<String>)>, IntegrationError> {
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

            let mut api_key = self.get_auth_header(&req.connector_config)?;
            header.append(&mut api_key);
            Ok(header)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<CreateConnectorCustomer, PaymentFlowData, ConnectorCustomerData, ConnectorCustomerResponse>,
        ) -> CustomResult<String, IntegrationError> {
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
        ) -> CustomResult<Vec<(String, Maskable<String>)>, IntegrationError> {
            let mut header = vec![(
                headers::CONTENT_TYPE.to_string(),
                self.common_get_content_type().to_string().into(),
            )];
            let mut api_key = self.get_auth_header(&req.connector_config)?;
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
        ) -> CustomResult<String, IntegrationError> {
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
                x => x.change_context(IntegrationError::MissingConnectorTransactionID { context: Default::default() })
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
        ) -> CustomResult<Vec<(String, Maskable<String>)>, IntegrationError> {
            let mut header = vec![(
                headers::CONTENT_TYPE.to_string(),
                Self::common_get_content_type(self).to_string().into(),
            )];
            let mut api_key = self.get_auth_header(&req.connector_config)?;
            header.append(&mut api_key);
            Ok(header)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ) -> CustomResult<String, IntegrationError> {
            let id = req.request.connector_transaction_id.get_connector_transaction_id()
                .change_context(IntegrationError::MissingConnectorTransactionID { context: Default::default() })?;
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
        ) -> CustomResult<Vec<(String, Maskable<String>)>, IntegrationError> {
            let mut header = vec![(
                headers::CONTENT_TYPE.to_string(),
                self.common_get_content_type().to_string().into(),
            )];
            let mut api_key = self.get_auth_header(&req.connector_config)?;
            header.append(&mut api_key);
            Ok(header)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ) -> CustomResult<String, IntegrationError> {
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
        ) -> CustomResult<Vec<(String, Maskable<String>)>, IntegrationError> {
            self.build_headers(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<IncrementalAuthorization, PaymentFlowData, PaymentsIncrementalAuthorizationData, PaymentsResponseData>,
        ) -> CustomResult<String, IntegrationError> {
            let payment_id = &req.request.connector_transaction_id.get_connector_transaction_id()
                .change_context(IntegrationError::MissingConnectorTransactionID { context: Default::default() })?;
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
        ) -> CustomResult<Vec<(String, Maskable<String>)>, IntegrationError> {
            let mut header = vec![(
                headers::CONTENT_TYPE.to_string(),
                self.common_get_content_type().to_string().into(),
            )];
            let mut api_key = self.get_auth_header(&req.connector_config)?;
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
        ) -> CustomResult<String, IntegrationError> {
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
        ) -> CustomResult<Vec<(String, Maskable<String>)>, IntegrationError> {
            let mut header = vec![(
                headers::CONTENT_TYPE.to_string(),
                self.common_get_content_type().to_string().into(),
            )];
            let mut api_key = self.get_auth_header(&req.connector_config)?;
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
        ) -> CustomResult<String, IntegrationError> {
            let id = req.request.connector_refund_id.clone();
            Ok(format!("{}v1/refunds/{}", self.connector_base_url_refunds(req), id))
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Stripe,
    curl_request: FormUrlEncoded(StripeClientAuthRequest),
    curl_response: StripeClientAuthResponse,
    flow_name: ClientAuthenticationToken,
    resource_common_data: PaymentFlowData,
    flow_request: ClientAuthenticationTokenRequestData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<ClientAuthenticationToken, PaymentFlowData, ClientAuthenticationTokenRequestData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, IntegrationError> {
            self.build_headers(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<ClientAuthenticationToken, PaymentFlowData, ClientAuthenticationTokenRequestData, PaymentsResponseData>,
        ) -> CustomResult<String, IntegrationError> {
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
    curl_response: StripeAcceptDisputeResponse,
    flow_name: Accept,
    resource_common_data: DisputeFlowData,
    flow_request: AcceptDisputeData,
    flow_response: DisputeResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, IntegrationError> {
            self.build_headers(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>,
        ) -> CustomResult<String, IntegrationError> {
            let dispute_id = &req.resource_common_data.connector_dispute_id;
            Ok(format!(
                "{}v1/disputes/{}/close",
                self.connector_base_url_disputes(req),
                dispute_id
            ))
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Stripe,
    curl_request: FormUrlEncoded(StripeSubmitEvidenceRequest),
    curl_response: StripeSubmitEvidenceResponse,
    flow_name: SubmitEvidence,
    resource_common_data: DisputeFlowData,
    flow_request: SubmitEvidenceData,
    flow_response: DisputeResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, IntegrationError> {
            self.build_headers(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>,
        ) -> CustomResult<String, IntegrationError> {
            let dispute_id = &req.resource_common_data.connector_dispute_id;
            Ok(format!(
                "{}v1/disputes/{}",
                self.connector_base_url_disputes(req),
                dispute_id
            ))
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Stripe,
    curl_request: FormUrlEncoded(StripeDefendDisputeRequest),
    curl_response: StripeDefendDisputeResponse,
    flow_name: DefendDispute,
    resource_common_data: DisputeFlowData,
    flow_request: DisputeDefendData,
    flow_response: DisputeResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, IntegrationError> {
            self.build_headers(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>,
        ) -> CustomResult<String, IntegrationError> {
            let dispute_id = &req.resource_common_data.connector_dispute_id;
            Ok(format!(
                "{}v1/disputes/{}",
                self.connector_base_url_disputes(req),
                dispute_id
            ))
        }
    }
);
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
        ServerSessionAuthenticationToken,
        PaymentFlowData,
        ServerSessionAuthenticationTokenRequestData,
        ServerSessionAuthenticationTokenResponseData,
    > for Stripe<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        ServerAuthenticationToken,
        PaymentFlowData,
        ServerAuthenticationTokenRequestData,
        ServerAuthenticationTokenResponseData,
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

// SourceVerification implementations for all flows
