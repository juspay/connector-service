use common_utils::{
    consts, crypto::VerifySignature, errors::CustomResult, events, ext_traits::BytesExt,
    types::StringMajorUnit,
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
        ConnectorCustomerResponse, ConnectorSpecifications, DisputeDefendData, DisputeFlowData,
        DisputeResponseData, MandateRevokeRequestData, MandateRevokeResponseData,
        PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData,
        PaymentMethodTokenResponse, PaymentMethodTokenizationData, PaymentVoidData,
        PaymentsAuthenticateData, PaymentsAuthorizeData, PaymentsCancelPostCaptureData,
        PaymentsCaptureData, PaymentsIncrementalAuthorizationData, PaymentsPostAuthenticateData,
        PaymentsPreAuthenticateData, PaymentsResponseData, PaymentsSdkSessionTokenData,
        PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData,
        RepeatPaymentData, SessionTokenRequestData, SessionTokenResponseData,
        SetupMandateRequestData, SubmitEvidenceData,
    },
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data::ErrorResponse,
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
};
use error_stack::{Report, ResultExt};
use hyperswitch_masking::Maskable;
use interfaces::{
    api::ConnectorCommon, connector_integration_v2::ConnectorIntegrationV2, connector_types,
    verification::SourceVerification,
};

use serde::Serialize;
use std::fmt::Debug;
pub mod transformers;

use transformers::{
    NuveiCaptureRequest, NuveiCaptureResponse, NuveiErrorResponse, NuveiPaymentRequest,
    NuveiPaymentResponse, NuveiRefundRequest, NuveiRefundResponse, NuveiRefundSyncRequest,
    NuveiRefundSyncResponse, NuveiSessionTokenRequest, NuveiSessionTokenResponse, NuveiSyncRequest,
    NuveiSyncResponse, NuveiVoidRequest, NuveiVoidResponse,
};

use super::macros;
use crate::types::ResponseRouterData;

// Local headers module
mod headers {
    pub const CONTENT_TYPE: &str = "Content-Type";
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        IncrementalAuthorization,
        PaymentFlowData,
        PaymentsIncrementalAuthorizationData,
        PaymentsResponseData,
    > for Nuvei<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::SdkSessionTokenV2 for Nuvei<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ConnectorServiceTrait<T> for Nuvei<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::MandateRevokeV2 for Nuvei<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAuthorizeV2<T> for Nuvei<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentSyncV2 for Nuvei<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentVoidV2 for Nuvei<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundSyncV2 for Nuvei<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundV2 for Nuvei<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentCapture for Nuvei<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ValidationTrait for Nuvei<T>
{
    fn should_do_session_token(&self) -> bool {
        true
    }
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentOrderCreate for Nuvei<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::SetupMandateV2<T> for Nuvei<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RepeatPaymentV2<T> for Nuvei<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::AcceptDispute for Nuvei<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentIncrementalAuthorization for Nuvei<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::SubmitEvidenceV2 for Nuvei<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::DisputeDefend for Nuvei<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::IncomingWebhook for Nuvei<T>
{
    fn get_webhook_source_verification_signature(
        &self,
        request: &domain_types::connector_types::RequestDetails,
        _connector_webhook_secret: &domain_types::connector_types::ConnectorWebhookSecrets,
    ) -> Result<Vec<u8>, Report<errors::ConnectorError>> {
        use transformers::{get_webhook_object_from_body, NuveiWebhook};

        let webhook = get_webhook_object_from_body(&request.body)
            .change_context(errors::ConnectorError::WebhookSourceVerificationFailed)
            .attach_printable("Failed to parse webhook body for signature verification")?;

        let nuvei_notification_signature = match webhook {
            NuveiWebhook::PaymentDmn(notification) => notification
                .advance_response_checksum
                .ok_or(errors::ConnectorError::WebhookSignatureNotFound)?,
            NuveiWebhook::Chargeback(_) => request
                .headers
                .get("Checksum")
                .ok_or(errors::ConnectorError::WebhookSignatureNotFound)?
                .clone(),
        };

        hex::decode(nuvei_notification_signature)
            .change_context(errors::ConnectorError::WebhookSignatureNotFound)
    }

    fn get_webhook_source_verification_message(
        &self,
        request: &domain_types::connector_types::RequestDetails,
        connector_webhook_secrets: &domain_types::connector_types::ConnectorWebhookSecrets,
    ) -> Result<Vec<u8>, Report<errors::ConnectorError>> {
        use crate::utils::concat_strings;
        use transformers::{get_webhook_object_from_body, NuveiWebhook};

        let webhook = get_webhook_object_from_body(&request.body)
            .change_context(errors::ConnectorError::WebhookSourceVerificationFailed)
            .attach_printable("Failed to parse webhook body for message construction")?;

        let secret_str = std::str::from_utf8(&connector_webhook_secrets.secret)
            .change_context(errors::ConnectorError::WebhookBodyDecodingFailed)?;

        match webhook {
            NuveiWebhook::PaymentDmn(notification) => {
                let status = notification
                    .status
                    .as_ref()
                    .map(|s| format!("{s:?}").to_uppercase())
                    .unwrap_or_default();

                let to_sign = concat_strings(&[
                    secret_str.to_string(),
                    notification.total_amount,
                    notification.currency,
                    notification.response_time_stamp,
                    notification.ppp_transaction_id,
                    status,
                    notification.product_id.unwrap_or("NA".to_string()),
                ]);
                Ok(to_sign.into_bytes())
            }
            NuveiWebhook::Chargeback(notification) => {
                let response = serde_json::to_string(&notification)
                    .change_context(errors::ConnectorError::WebhookBodyDecodingFailed)?;

                let to_sign = format!("{secret_str}{response}");
                Ok(to_sign.into_bytes())
            }
        }
    }

    fn verify_webhook_source(
        &self,
        request: domain_types::connector_types::RequestDetails,
        connector_webhook_secret: Option<domain_types::connector_types::ConnectorWebhookSecrets>,
        _connector_account_details: Option<domain_types::router_data::ConnectorAuthType>,
    ) -> Result<bool, Report<errors::ConnectorError>> {
        use common_utils::crypto;

        let connector_webhook_secrets = match connector_webhook_secret {
            Some(secrets) => secrets,
            None => {
                tracing::warn!(
                    target: "nuvei_webhook",
                    "Missing webhook secret for Nuvei webhook verification - verification failed but continuing processing"
                );
                return Ok(false);
            }
        };

        let signature = match self
            .get_webhook_source_verification_signature(&request, &connector_webhook_secrets)
        {
            Ok(sig) => sig,
            Err(error) => {
                tracing::warn!(
                    target: "nuvei_webhook",
                    "Failed to get webhook source verification signature for Nuvei: {} - verification failed but continuing processing",
                    error
                );
                return Ok(false);
            }
        };

        let message = match self
            .get_webhook_source_verification_message(&request, &connector_webhook_secrets)
        {
            Ok(msg) => msg,
            Err(error) => {
                tracing::warn!(
                    target: "nuvei_webhook",
                    "Failed to get webhook source verification message for Nuvei: {} - verification failed but continuing processing",
                    error
                );
                return Ok(false);
            }
        };

        match crypto::Sha256.verify_signature(
            &connector_webhook_secrets.secret,
            &signature,
            &message,
        ) {
            Ok(is_verified) => Ok(is_verified),
            Err(error) => {
                tracing::warn!(
                    target: "nuvei_webhook",
                    "Failed to verify webhook signature for Nuvei: {} - verification failed but continuing processing",
                    error
                );
                Ok(false)
            }
        }
    }

    fn get_event_type(
        &self,
        request: domain_types::connector_types::RequestDetails,
        _connector_webhook_secret: Option<domain_types::connector_types::ConnectorWebhookSecrets>,
        _connector_account_details: Option<domain_types::router_data::ConnectorAuthType>,
    ) -> Result<domain_types::connector_types::EventType, Report<errors::ConnectorError>> {
        use transformers::{
            get_webhook_object_from_body, map_dispute_notification_to_event,
            map_notification_to_event, NuveiWebhook,
        };

        let webhook = get_webhook_object_from_body(&request.body)
            .change_context(errors::ConnectorError::WebhookEventTypeNotFound)
            .attach_printable("Failed to parse webhook body to determine event type")?;

        match webhook {
            NuveiWebhook::PaymentDmn(notification) => {
                if let Some((status, transaction_type)) =
                    notification.status.zip(notification.transaction_type)
                {
                    map_notification_to_event(status, transaction_type)
                } else {
                    Err(errors::ConnectorError::WebhookEventTypeNotFound.into())
                }
            }
            NuveiWebhook::Chargeback(notification) => {
                map_dispute_notification_to_event(&notification.chargeback)
            }
        }
    }

    fn process_payment_webhook(
        &self,
        request: domain_types::connector_types::RequestDetails,
        _connector_webhook_secret: Option<domain_types::connector_types::ConnectorWebhookSecrets>,
        _connector_account_details: Option<domain_types::router_data::ConnectorAuthType>,
    ) -> Result<domain_types::connector_types::WebhookDetailsResponse, Report<errors::ConnectorError>>
    {
        use transformers::{get_webhook_object_from_body, NuveiWebhook};

        let webhook = get_webhook_object_from_body(&request.body)
            .change_context(errors::ConnectorError::WebhookReferenceIdNotFound)
            .attach_printable("Failed to parse webhook body for payment webhook processing")?;

        match webhook {
            NuveiWebhook::PaymentDmn(notification) => {
                let response =
                    domain_types::connector_types::WebhookDetailsResponse::try_from(notification)
                        .change_context(errors::ConnectorError::WebhookBodyDecodingFailed)?;

                Ok(domain_types::connector_types::WebhookDetailsResponse {
                    raw_connector_response: Some(
                        String::from_utf8_lossy(&request.body).to_string(),
                    ),
                    ..response
                })
            }
            NuveiWebhook::Chargeback(_) => {
                Err(errors::ConnectorError::WebhookEventTypeNotFound.into())
            }
        }
    }

    fn process_refund_webhook(
        &self,
        request: domain_types::connector_types::RequestDetails,
        _connector_webhook_secret: Option<domain_types::connector_types::ConnectorWebhookSecrets>,
        _connector_account_details: Option<domain_types::router_data::ConnectorAuthType>,
    ) -> Result<
        domain_types::connector_types::RefundWebhookDetailsResponse,
        Report<errors::ConnectorError>,
    > {
        use transformers::{get_webhook_object_from_body, NuveiTransactionType, NuveiWebhook};

        let webhook = get_webhook_object_from_body(&request.body)
            .change_context(errors::ConnectorError::WebhookReferenceIdNotFound)
            .attach_printable("Failed to parse webhook body for refund webhook processing")?;

        match webhook {
            NuveiWebhook::PaymentDmn(notification) => {
                // Only process if it's a refund transaction
                if notification.transaction_type == Some(NuveiTransactionType::Credit) {
                    let response =
                        domain_types::connector_types::RefundWebhookDetailsResponse::try_from(
                            notification,
                        )
                        .change_context(errors::ConnectorError::WebhookBodyDecodingFailed)?;

                    Ok(
                        domain_types::connector_types::RefundWebhookDetailsResponse {
                            raw_connector_response: Some(
                                String::from_utf8_lossy(&request.body).to_string(),
                            ),
                            ..response
                        },
                    )
                } else {
                    Err(errors::ConnectorError::WebhookEventTypeNotFound.into())
                }
            }
            NuveiWebhook::Chargeback(_) => {
                Err(errors::ConnectorError::WebhookEventTypeNotFound.into())
            }
        }
    }

    fn process_dispute_webhook(
        &self,
        request: domain_types::connector_types::RequestDetails,
        _connector_webhook_secret: Option<domain_types::connector_types::ConnectorWebhookSecrets>,
        _connector_account_details: Option<domain_types::router_data::ConnectorAuthType>,
    ) -> Result<
        domain_types::connector_types::DisputeWebhookDetailsResponse,
        Report<errors::ConnectorError>,
    > {
        use common_enums::{Currency, DisputeStatus};
        use domain_types::connector_types::DisputeWebhookDetailsResponse;
        use transformers::{
            get_dispute_stage, get_webhook_object_from_body, map_dispute_notification_to_event,
            NuveiWebhook,
        };

        let webhook = get_webhook_object_from_body(&request.body)
            .change_context(errors::ConnectorError::WebhookBodyDecodingFailed)
            .attach_printable("Failed to parse webhook body for dispute webhook processing")?;

        match webhook {
            NuveiWebhook::Chargeback(notification) => {
                let currency = notification
                    .chargeback
                    .reported_currency
                    .to_uppercase()
                    .parse::<Currency>()
                    .map_err(|_| errors::ConnectorError::ResponseDeserializationFailed)?;

                // Convert FloatMajorUnit to MinorUnit using FloatMajorUnitForConnector
                use common_utils::types::StringMinorUnitForConnector;
                use common_utils::types::{AmountConvertor, FloatMajorUnitForConnector};
                let converter = FloatMajorUnitForConnector;
                let amount_minorunit = converter
                    .convert_back(notification.chargeback.reported_amount, currency)
                    .change_context(errors::ConnectorError::AmountConversionFailed)?;

                // Then convert to StringMinorUnit using StringMinorUnitForConnector
                let minor_unit_converter = StringMinorUnitForConnector;
                let amount = minor_unit_converter
                    .convert(amount_minorunit, currency)
                    .change_context(errors::ConnectorError::AmountConversionFailed)?;

                let connector_dispute_id = notification
                    .chargeback
                    .dispute_id
                    .clone()
                    .ok_or(errors::ConnectorError::WebhookReferenceIdNotFound)?;

                let dispute_stage = get_dispute_stage(&notification.chargeback)?;

                Ok(DisputeWebhookDetailsResponse {
                    amount,
                    currency,
                    dispute_id: connector_dispute_id,
                    status: {
                        // Map dispute status code to EventType first, then to DisputeStatus
                        let event_type =
                            map_dispute_notification_to_event(&notification.chargeback)?;
                        match event_type {
                            domain_types::connector_types::EventType::DisputeOpened => {
                                DisputeStatus::DisputeOpened
                            }
                            domain_types::connector_types::EventType::DisputeAccepted => {
                                DisputeStatus::DisputeAccepted
                            }
                            domain_types::connector_types::EventType::DisputeCancelled => {
                                DisputeStatus::DisputeCancelled
                            }
                            domain_types::connector_types::EventType::DisputeChallenged => {
                                DisputeStatus::DisputeChallenged
                            }
                            domain_types::connector_types::EventType::DisputeWon => {
                                DisputeStatus::DisputeWon
                            }
                            domain_types::connector_types::EventType::DisputeLost => {
                                DisputeStatus::DisputeLost
                            }
                            domain_types::connector_types::EventType::DisputeExpired => {
                                DisputeStatus::DisputeExpired
                            }
                            _ => DisputeStatus::DisputeOpened, // Default fallback
                        }
                    },
                    stage: dispute_stage,
                    connector_response_reference_id: None,
                    dispute_message: notification.chargeback.chargeback_reason.clone(),
                    raw_connector_response: Some(
                        String::from_utf8_lossy(&request.body).to_string(),
                    ),
                    status_code: 200,
                    response_headers: None,
                    connector_reason_code: notification
                        .chargeback
                        .chargeback_reason_category
                        .clone(),
                })
            }
            NuveiWebhook::PaymentDmn(_) => {
                Err(errors::ConnectorError::WebhookEventTypeNotFound.into())
            }
        }
    }
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::VerifyRedirectResponse for Nuvei<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> SourceVerification
    for Nuvei<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentSessionToken for Nuvei<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAccessToken for Nuvei<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::CreateConnectorCustomer for Nuvei<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentTokenV2<T> for Nuvei<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentPreAuthenticateV2<T> for Nuvei<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAuthenticateV2<T> for Nuvei<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentPostAuthenticateV2<T> for Nuvei<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentVoidPostCaptureV2 for Nuvei<T>
{
}

// Create all prerequisites using macros
macros::create_all_prerequisites!(
    connector_name: Nuvei,
    generic_type: T,
    api: [
        (
            flow: CreateSessionToken,
            request_body: NuveiSessionTokenRequest,
            response_body: NuveiSessionTokenResponse,
            router_data: RouterDataV2<CreateSessionToken, PaymentFlowData, SessionTokenRequestData, SessionTokenResponseData>,
        ),
        (
            flow: Authorize,
            request_body: NuveiPaymentRequest<T>,
            response_body: NuveiPaymentResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: PSync,
            request_body: NuveiSyncRequest,
            response_body: NuveiSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ),
        (
            flow: Capture,
            request_body: NuveiCaptureRequest,
            response_body: NuveiCaptureResponse,
            router_data: RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ),
        (
            flow: Refund,
            request_body: NuveiRefundRequest,
            response_body: NuveiRefundResponse,
            router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ),
        (
            flow: RSync,
            request_body: NuveiRefundSyncRequest,
            response_body: NuveiRefundSyncResponse,
            router_data: RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ),
        (
            flow: Void,
            request_body: NuveiVoidRequest,
            response_body: NuveiVoidResponse,
            router_data: RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        )
    ],
    amount_converters: [
        amount_converter_webhooks: StringMajorUnit
    ],
    member_functions: {
        pub fn build_headers<F, FCD, Req, Res>(
            &self,
            _req: &RouterDataV2<F, FCD, Req, Res>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            let header = vec![(
                headers::CONTENT_TYPE.to_string(),
                "application/json".to_string().into(),
            )];
            Ok(header)
        }

        pub fn connector_base_url_payments<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.nuvei.base_url
        }

        pub fn connector_base_url_refunds<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, RefundFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.nuvei.base_url
        }
    }
);

// Implement CreateSessionToken flow using macro
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Nuvei,
    curl_request: Json(NuveiSessionTokenRequest),
    curl_response: NuveiSessionTokenResponse,
    flow_name: CreateSessionToken,
    resource_common_data: PaymentFlowData,
    flow_request: SessionTokenRequestData,
    flow_response: SessionTokenResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<CreateSessionToken, PaymentFlowData, SessionTokenRequestData, SessionTokenResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<CreateSessionToken, PaymentFlowData, SessionTokenRequestData, SessionTokenResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            Ok(format!("{}/getSessionToken.do", self.connector_base_url_payments(req)))
        }
    }
);

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> ConnectorCommon
    for Nuvei<T>
{
    fn id(&self) -> &'static str {
        "nuvei"
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.nuvei.base_url.as_ref()
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut events::Event>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: Result<NuveiErrorResponse, Report<common_utils::errors::ParsingError>> =
            res.response.parse_struct("nuvei ErrorResponse");

        match response {
            Ok(response_data) => {
                if let Some(i) = event_builder {
                    i.set_connector_response(&response_data);
                }
                Ok(ErrorResponse {
                    status_code: res.status_code,
                    code: response_data
                        .err_code
                        .unwrap_or(consts::NO_ERROR_CODE.to_string()),
                    message: response_data
                        .reason
                        .clone()
                        .unwrap_or(consts::NO_ERROR_MESSAGE.to_string()),
                    reason: response_data.reason,
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                })
            }
            Err(error_msg) => {
                if let Some(event) = event_builder {
                    event.set_connector_response(&serde_json::json!({"error": "Error response parsing failed", "status_code": res.status_code}))
                };
                tracing::error!(deserialization_error =? error_msg);
                domain_types::utils::handle_json_response_deserialization_failure(res, "nuvei")
            }
        }
    }
}

// Implement Authorize flow using macro
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Nuvei,
    curl_request: Json(NuveiPaymentRequest),
    curl_response: NuveiPaymentResponse,
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
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            Ok(format!("{}/payment.do", self.connector_base_url_payments(req)))
        }
    }
);

// Implement PSync flow using macro
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Nuvei,
    curl_request: Json(NuveiSyncRequest),
    curl_response: NuveiSyncResponse,
    flow_name: PSync,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsSyncData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            Ok(format!("{}/getTransactionDetails.do", self.connector_base_url_payments(req)))
        }
    }
);

// Implement Capture flow using macro
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Nuvei,
    curl_request: Json(NuveiCaptureRequest),
    curl_response: NuveiCaptureResponse,
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
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            Ok(format!("{}/settleTransaction.do", self.connector_base_url_payments(req)))
        }
    }
);

// Implement Refund flow using macro
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Nuvei,
    curl_request: Json(NuveiRefundRequest),
    curl_response: NuveiRefundResponse,
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
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            Ok(format!("{}/refundTransaction.do", self.connector_base_url_refunds(req)))
        }
    }
);

// Implement RSync flow using macro
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Nuvei,
    curl_request: Json(NuveiRefundSyncRequest),
    curl_response: NuveiRefundSyncResponse,
    flow_name: RSync,
    resource_common_data: RefundFlowData,
    flow_request: RefundSyncData,
    flow_response: RefundsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            Ok(format!("{}/getTransactionDetails.do", self.connector_base_url_refunds(req)))
        }
    }
);

// Implement Void flow using macro
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Nuvei,
    curl_request: Json(NuveiVoidRequest),
    curl_response: NuveiVoidResponse,
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
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            Ok(format!("{}/voidTransaction.do", self.connector_base_url_payments(req)))
        }
    }
);

// Implementation for empty stubs - these will need to be properly implemented later

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for Nuvei<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        CreateConnectorCustomer,
        PaymentFlowData,
        ConnectorCustomerData,
        ConnectorCustomerResponse,
    > for Nuvei<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    for Nuvei<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
    for Nuvei<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
    for Nuvei<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData<T>,
        PaymentsResponseData,
    > for Nuvei<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        VoidPC,
        PaymentFlowData,
        PaymentsCancelPostCaptureData,
        PaymentsResponseData,
    > for Nuvei<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        PaymentMethodToken,
        PaymentFlowData,
        PaymentMethodTokenizationData<T>,
        PaymentMethodTokenResponse,
    > for Nuvei<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        PreAuthenticate,
        PaymentFlowData,
        PaymentsPreAuthenticateData<T>,
        PaymentsResponseData,
    > for Nuvei<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        Authenticate,
        PaymentFlowData,
        PaymentsAuthenticateData<T>,
        PaymentsResponseData,
    > for Nuvei<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        PostAuthenticate,
        PaymentFlowData,
        PaymentsPostAuthenticateData<T>,
        PaymentsResponseData,
    > for Nuvei<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        CreateAccessToken,
        PaymentFlowData,
        AccessTokenRequestData,
        AccessTokenResponseData,
    > for Nuvei<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        SdkSessionToken,
        PaymentFlowData,
        PaymentsSdkSessionTokenData,
        PaymentsResponseData,
    > for Nuvei<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        MandateRevoke,
        PaymentFlowData,
        MandateRevokeRequestData,
        MandateRevokeResponseData,
    > for Nuvei<T>
{
}

// SourceVerification implementations for all flows

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> ConnectorSpecifications
    for Nuvei<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        RepeatPayment,
        PaymentFlowData,
        RepeatPaymentData<T>,
        PaymentsResponseData,
    > for Nuvei<T>
{
}
