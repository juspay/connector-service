pub mod transformers;

use common_enums;
use common_utils::{
    consts, errors::CustomResult, ext_traits::ByteSliceExt, request::RequestContent,
    types::FloatMajorUnit,
};
use domain_types::{
    connector_flow::{
        Accept, Authorize, Capture, CreateAccessToken, CreateOrder, CreateSessionToken,
        DefendDispute, PSync, RSync, Refund, RepeatPayment, SetupMandate, SubmitEvidence, Void,
    },
    connector_types::{
        AcceptDisputeData, AccessTokenRequestData, AccessTokenResponseData,
        ConnectorSpecifications, ConnectorWebhookSecrets, DisputeDefendData, DisputeFlowData,
        DisputeResponseData, EventType, PaymentCreateOrderData, PaymentCreateOrderResponse,
        PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundSyncData,
        RefundWebhookDetailsResponse, RefundsData, RefundsResponseData, RepeatPaymentData,
        RequestDetails, ResponseId, SessionTokenRequestData, SessionTokenResponseData,
        SetupMandateRequestData, SubmitEvidenceData, WebhookDetailsResponse,
    },
    errors::{self, ConnectorError},
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
};
use error_stack::ResultExt;
use hyperswitch_masking::Maskable;
use interfaces::{
    api::ConnectorCommon,
    connector_integration_v2::ConnectorIntegrationV2,
    connector_types::{
        AcceptDispute, ConnectorServiceTrait, DisputeDefend, IncomingWebhook, PaymentAuthorizeV2,
        PaymentCapture, PaymentOrderCreate, PaymentSessionToken, PaymentSyncV2, PaymentVoidV2,
        RefundSyncV2, RefundV2, RepeatPaymentV2, SetupMandateV2, SubmitEvidenceV2, ValidationTrait,
    },
    events::connector_api_logs::ConnectorEvent,
    verification::SourceVerification,
};
use serde::Serialize;

use self::transformers::{
    get_trans_id, AuthorizedotnetAuthorizeResponse, AuthorizedotnetCaptureRequest,
    AuthorizedotnetCaptureResponse, AuthorizedotnetCreateSyncRequest, AuthorizedotnetPSyncResponse,
    AuthorizedotnetPaymentsRequest, AuthorizedotnetRSyncRequest, AuthorizedotnetRSyncResponse,
    AuthorizedotnetRefundRequest, AuthorizedotnetRefundResponse,
    AuthorizedotnetRepeatPaymentRequest, AuthorizedotnetRepeatPaymentResponse,
    AuthorizedotnetVoidRequest, AuthorizedotnetVoidResponse, AuthorizedotnetWebhookEventType,
    AuthorizedotnetWebhookObjectId, CreateCustomerProfileRequest, CreateCustomerProfileResponse,
};
use super::macros;
use crate::{types::ResponseRouterData, with_response_body};

pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > ConnectorServiceTrait<T> for Authorizedotnet<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > PaymentSessionToken for Authorizedotnet<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > SetupMandateV2<T> for Authorizedotnet<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > ValidationTrait for Authorizedotnet<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > IncomingWebhook for Authorizedotnet<T>
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

        // Extract X-ANET-Signature header (case-insensitive)
        let signature_header = match request
            .headers
            .get("X-ANET-Signature")
            .or_else(|| request.headers.get("x-anet-signature"))
        {
            Some(header) => header,
            None => {
                tracing::warn!(
                    target: "authorizedotnet_webhook",
                    "Missing X-ANET-Signature header in webhook request from Authorize.Net - verification failed but continuing processing"
                );
                return Ok(false); // Missing signature -> verification fails but continue processing
            }
        };

        // Parse "sha512=<hex>" format
        let signature_hex = match signature_header.strip_prefix("sha512=") {
            Some(hex) => hex,
            None => {
                tracing::warn!(
                    target: "authorizedotnet_webhook",
                    "Invalid signature format in X-ANET-Signature header, expected 'sha512=<hex>' but got: '{}' - verification failed but continuing processing",
                    signature_header
                );
                return Ok(false); // Invalid format -> verification fails but continue processing
            }
        };

        // Decode hex signature
        let expected_signature = match hex::decode(signature_hex) {
            Ok(sig) => sig,
            Err(hex_error) => {
                tracing::warn!(
                    target: "authorizedotnet_webhook",
                    "Failed to decode hex signature from X-ANET-Signature header: '{}', error: {} - verification failed but continuing processing",
                    signature_hex,
                    hex_error
                );
                return Ok(false); // Invalid hex -> verification fails but continue processing
            }
        };

        // Compute HMAC-SHA512 of request body
        use common_utils::crypto::{HmacSha512, SignMessage};
        let crypto_algorithm = HmacSha512;
        let computed_signature = match crypto_algorithm.sign_message(&webhook_secret, &request.body)
        {
            Ok(sig) => sig,
            Err(crypto_error) => {
                tracing::error!(
                    target: "authorizedotnet_webhook",
                    "Failed to compute HMAC-SHA512 signature for webhook verification, error: {:?} - verification failed but continuing processing",
                    crypto_error
                );
                return Ok(false); // Crypto error -> verification fails but continue processing
            }
        };

        // Constant-time comparison to prevent timing attacks
        Ok(computed_signature == expected_signature)
    }

    fn get_event_type(
        &self,
        request: RequestDetails,
        _connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorAuthType>,
    ) -> Result<EventType, error_stack::Report<ConnectorError>> {
        let webhook_body: AuthorizedotnetWebhookEventType = request
            .body
            .parse_struct("AuthorizedotnetWebhookEventType")
            .change_context(ConnectorError::WebhookEventTypeNotFound)
            .attach_printable_lazy(|| {
                "Failed to parse webhook event type from Authorize.Net webhook body"
            })?;

        Ok(match webhook_body.event_type {
            transformers::AuthorizedotnetIncomingWebhookEventType::AuthorizationCreated => {
                EventType::PaymentIntentAuthorizationSuccess
            }
            transformers::AuthorizedotnetIncomingWebhookEventType::PriorAuthCapture
            | transformers::AuthorizedotnetIncomingWebhookEventType::CaptureCreated => {
                EventType::PaymentIntentCaptureSuccess
            }
            transformers::AuthorizedotnetIncomingWebhookEventType::AuthCapCreated => {
                EventType::PaymentIntentSuccess // Combined auth+capture
            }
            transformers::AuthorizedotnetIncomingWebhookEventType::VoidCreated => {
                EventType::PaymentIntentCancelled
            }
            transformers::AuthorizedotnetIncomingWebhookEventType::RefundCreated => {
                EventType::RefundSuccess
            }
            transformers::AuthorizedotnetIncomingWebhookEventType::CustomerCreated
            | transformers::AuthorizedotnetIncomingWebhookEventType::CustomerPaymentProfileCreated => {
                EventType::MandateActive
            }
            transformers::AuthorizedotnetIncomingWebhookEventType::Unknown => {
                tracing::warn!(
                    target: "authorizedotnet_webhook",
                    "Received unknown webhook event type from Authorize.Net - rejecting webhook"
                );
                return Err(
                    error_stack::report!(ConnectorError::WebhookEventTypeNotFound)
                        .attach_printable("Unknown webhook event type"),
                )
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
        let webhook_body: AuthorizedotnetWebhookObjectId = request
            .body
            .parse_struct("AuthorizedotnetWebhookObjectId")
            .change_context(ConnectorError::WebhookResourceObjectNotFound)
            .attach_printable_lazy(|| {
                "Failed to parse Authorize.Net payment webhook body structure"
            })?;

        let transaction_id = get_trans_id(&webhook_body).attach_printable_lazy(|| {
            format!(
                "Failed to extract transaction ID from payment webhook for event: {:?}",
                webhook_body.event_type
            )
        })?;
        let status = transformers::SyncStatus::from(webhook_body.event_type.clone());

        Ok(WebhookDetailsResponse {
            resource_id: Some(ResponseId::ConnectorTransactionId(transaction_id.clone())),
            status: common_enums::AttemptStatus::from(status),
            status_code: 200,
            mandate_reference: None,
            connector_response_reference_id: Some(transaction_id),
            error_code: None,
            error_message: None,
            raw_connector_response: Some(String::from_utf8_lossy(&request_body_copy).to_string()),
            response_headers: None,
        })
    }

    fn process_refund_webhook(
        &self,
        request: RequestDetails,
        _connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorAuthType>,
    ) -> Result<RefundWebhookDetailsResponse, error_stack::Report<ConnectorError>> {
        let request_body_copy = request.body.clone();
        let webhook_body: AuthorizedotnetWebhookObjectId = request
            .body
            .parse_struct("AuthorizedotnetWebhookObjectId")
            .change_context(ConnectorError::WebhookResourceObjectNotFound)
            .attach_printable_lazy(|| {
                "Failed to parse Authorize.Net refund webhook body structure"
            })?;

        let transaction_id = get_trans_id(&webhook_body).attach_printable_lazy(|| {
            format!(
                "Failed to extract transaction ID from refund webhook for event: {:?}",
                webhook_body.event_type
            )
        })?;

        Ok(RefundWebhookDetailsResponse {
            connector_refund_id: Some(transaction_id.clone()),
            status: common_enums::RefundStatus::Success, // Authorize.Net only sends successful refund webhooks
            status_code: 200,
            connector_response_reference_id: Some(transaction_id),
            error_code: None,
            error_message: None,
            raw_connector_response: Some(String::from_utf8_lossy(&request_body_copy).to_string()),
            response_headers: None,
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
    > SubmitEvidenceV2 for Authorizedotnet<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > DisputeDefend for Authorizedotnet<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > RefundSyncV2 for Authorizedotnet<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > AcceptDispute for Authorizedotnet<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > RepeatPaymentV2 for Authorizedotnet<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > PaymentOrderCreate for Authorizedotnet<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > PaymentAuthorizeV2<T> for Authorizedotnet<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > PaymentSyncV2 for Authorizedotnet<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > PaymentVoidV2 for Authorizedotnet<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > RefundV2 for Authorizedotnet<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > PaymentCapture for Authorizedotnet<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > interfaces::connector_types::PaymentAccessToken for Authorizedotnet<T>
{
}

// Basic connector implementation
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > ConnectorCommon for Authorizedotnet<T>
{
    fn id(&self) -> &'static str {
        "authorizedotnet"
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.authorizedotnet.base_url.as_ref()
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: transformers::ResponseMessages = res
            .response
            .parse_struct("ResponseMessages")
            .map_err(|_| ConnectorError::ResponseDeserializationFailed)?;

        with_response_body!(event_builder, response);

        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response
                .message
                .first()
                .map(|m| m.code.clone())
                .unwrap_or_else(|| consts::NO_ERROR_CODE.to_string()),
            message: response
                .message
                .first()
                .map(|m| m.text.clone())
                .unwrap_or_else(|| consts::NO_ERROR_MESSAGE.to_string()),
            reason: None,
            attempt_status: None,
            connector_transaction_id: None,
            network_decline_code: None,
            network_advice_code: None,
            network_error_message: None,
        })
    }

    fn get_currency_unit(&self) -> common_enums::CurrencyUnit {
        common_enums::CurrencyUnit::Base
    }
}

// Define connector prerequisites
macros::create_all_prerequisites!(
    connector_name: Authorizedotnet,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: AuthorizedotnetPaymentsRequest<T>,
            response_body: AuthorizedotnetAuthorizeResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: PSync,
            request_body: AuthorizedotnetCreateSyncRequest,
            response_body: AuthorizedotnetPSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ),
        (
            flow: Capture,
            request_body: AuthorizedotnetCaptureRequest,
            response_body: AuthorizedotnetCaptureResponse,
            router_data: RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ),
        (
            flow: Void,
            request_body: AuthorizedotnetVoidRequest,
            response_body: AuthorizedotnetVoidResponse,
            router_data: RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ),
        (
            flow: Refund,
            request_body: AuthorizedotnetRefundRequest<T>,
            response_body: AuthorizedotnetRefundResponse,
            router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ),
        (
            flow: RSync,
            request_body: AuthorizedotnetRSyncRequest,
            response_body: AuthorizedotnetRSyncResponse,
            router_data: RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ),
        (
            flow: RepeatPayment,
            request_body: AuthorizedotnetRepeatPaymentRequest,
            response_body: AuthorizedotnetRepeatPaymentResponse,
            router_data: RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>,
        ),
        (
            flow: SetupMandate,
            request_body: CreateCustomerProfileRequest<T>,
            response_body: CreateCustomerProfileResponse,
            router_data: RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>,
        )
    ],
    amount_converters: [
        amount_converter: FloatMajorUnit
    ],
    member_functions: {
        fn preprocess_response_bytes<F, FCD, Req, Res>(
            &self,
            _req: &RouterDataV2<F, FCD, Req, Res>,
            bytes: bytes::Bytes,
        ) -> CustomResult<bytes::Bytes, errors::ConnectorError> {
            // Check if the bytes begin with UTF-8 BOM (EF BB BF)
            let encoding = encoding_rs::UTF_8;
            let intermediate_response_bytes = encoding.decode_with_bom_removal(&bytes);
            let processed_bytes = bytes::Bytes::copy_from_slice(intermediate_response_bytes.0.as_bytes());

            Ok(processed_bytes)
        }
        pub fn build_headers<F, FCD, Req, Res>(
            &self,
            req: &RouterDataV2<F, FCD, Req, Res>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
            let mut header = vec![(
                headers::CONTENT_TYPE.to_string(),
                "application/json".to_string().into(),
            )];
            let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
            header.append(&mut api_key);
            Ok(header)
        }

        pub fn connector_base_url_payments<F, Req, Res>(
            &self,
            req: &RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> String {
            let base_url = &req.resource_common_data.connectors.authorizedotnet.base_url;
            base_url.to_string()
        }

        pub fn connector_base_url_refunds<F, Req, Res>(
            &self,
            req: &RouterDataV2<F, RefundFlowData, Req, Res>,
        ) -> String {
            req.resource_common_data.connectors.authorizedotnet.base_url.to_string()
        }
    }
);

// Implement the specific flows
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Authorizedotnet,
    curl_request: Json(AuthorizedotnetPaymentsRequest),
    curl_response: AuthorizedotnetAuthorizeResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    preprocess_response: true,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
            self.build_headers(req)
        }

        fn get_url(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<String, ConnectorError> {
            Ok(self.connector_base_url_payments(req).to_string())
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Authorizedotnet,
    curl_request: Json(AuthorizedotnetCreateSyncRequest),
    curl_response: AuthorizedotnetPSyncResponse,
    flow_name: PSync,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsSyncData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    preprocess_response: true,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
            self.build_headers(req)
        }

        fn get_url(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<String, ConnectorError> {
            Ok(self.connector_base_url_payments(req).to_string())
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Authorizedotnet,
    curl_request: Json(AuthorizedotnetCaptureRequest),
    curl_response: AuthorizedotnetCaptureResponse,
    flow_name: Capture,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsCaptureData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    preprocess_response: true,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
            self.build_headers(req)
        }

        fn get_url(
            &self,
            req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ) -> CustomResult<String, ConnectorError> {
            Ok(self.connector_base_url_payments(req).to_string())
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Authorizedotnet,
    curl_request: Json(AuthorizedotnetVoidRequest),
    curl_response: AuthorizedotnetVoidResponse,
    flow_name: Void,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentVoidData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    preprocess_response: true,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
            self.build_headers(req)
        }

        fn get_url(
            &self,
            req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ) -> CustomResult<String, ConnectorError> {
            Ok(self.connector_base_url_payments(req).to_string())
        }
    }
);

// Empty implementation for Refund flow to satisfy trait bounds
// The actual refund logic is handled by the specific implementations in transformers.rs
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
    for Authorizedotnet<T>
{
    fn get_headers(
        &self,
        req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        self.build_headers(req)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> CustomResult<String, ConnectorError> {
        Ok(self.connector_base_url_refunds(req).to_string())
    }

    fn get_request_body(
        &self,
        _req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> CustomResult<Option<RequestContent>, ConnectorError> {
        // This is a placeholder implementation
        // The actual refund logic should be handled by specific implementations
        Err(ConnectorError::NotImplemented("Refund not implemented for generic type".into()).into())
    }
}

// Implement RSync flow
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Authorizedotnet,
    curl_request: Json(AuthorizedotnetRSyncRequest),
    curl_response: AuthorizedotnetRSyncResponse,
    flow_name: RSync,
    resource_common_data: RefundFlowData,
    flow_request: RefundSyncData,
    flow_response: RefundsResponseData,
    http_method: Post,
    preprocess_response: true,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
            self.build_headers(req)
        }

        fn get_url(
            &self,
            req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ) -> CustomResult<String, ConnectorError> {
            Ok(self.connector_base_url_refunds(req).to_string())
        }

    }
);

// Use macro implementation for SetupMandate
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Authorizedotnet,
    curl_request: Json(CreateCustomerProfileRequest),
    curl_response: CreateCustomerProfileResponse,
    flow_name: SetupMandate,
    resource_common_data: PaymentFlowData,
    flow_request: SetupMandateRequestData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    preprocess_response: true,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
            self.build_headers(req)
        }

        fn get_url(
            &self,
            req: &RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>,
        ) -> CustomResult<String, ConnectorError> {
            Ok(self.connector_base_url_payments(req).to_string())
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Authorizedotnet,
    curl_request: Json(AuthorizedotnetRepeatPaymentRequest),
    curl_response: AuthorizedotnetRepeatPaymentResponse,
    flow_name: RepeatPayment,
    resource_common_data: PaymentFlowData,
    flow_request: RepeatPaymentData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    preprocess_response: true, // Keeping true for Authorize.net which needs BOM handling
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
            self.build_headers(req)
        }

        fn get_url(
            &self,
            req: &RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>,
        ) -> CustomResult<String, ConnectorError> {
            Ok(self.connector_base_url_payments(req).to_string())
        }
    }
);

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    ConnectorIntegrationV2<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for Authorizedotnet<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    ConnectorIntegrationV2<
        CreateSessionToken,
        PaymentFlowData,
        SessionTokenRequestData,
        SessionTokenResponseData,
    > for Authorizedotnet<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    ConnectorIntegrationV2<
        CreateAccessToken,
        PaymentFlowData,
        AccessTokenRequestData,
        AccessTokenResponseData,
    > for Authorizedotnet<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    for Authorizedotnet<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
    for Authorizedotnet<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
    for Authorizedotnet<T>
{
}

// SourceVerification implementations for all flows
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > SourceVerification<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
    for Authorizedotnet<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    SourceVerification<
        CreateSessionToken,
        PaymentFlowData,
        SessionTokenRequestData,
        SessionTokenResponseData,
    > for Authorizedotnet<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    SourceVerification<
        CreateAccessToken,
        PaymentFlowData,
        AccessTokenRequestData,
        AccessTokenResponseData,
    > for Authorizedotnet<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > SourceVerification<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    for Authorizedotnet<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > SourceVerification<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
    for Authorizedotnet<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > SourceVerification<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
    for Authorizedotnet<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > SourceVerification<Refund, RefundFlowData, RefundsData, RefundsResponseData>
    for Authorizedotnet<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > SourceVerification<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
    for Authorizedotnet<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    SourceVerification<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for Authorizedotnet<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    SourceVerification<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData<T>,
        PaymentsResponseData,
    > for Authorizedotnet<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > SourceVerification<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>
    for Authorizedotnet<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > SourceVerification<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    for Authorizedotnet<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > SourceVerification<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
    for Authorizedotnet<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > SourceVerification<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
    for Authorizedotnet<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > ConnectorSpecifications for Authorizedotnet<T>
{
}
