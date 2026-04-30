pub mod transformers;
pub use transformers as axisbank;

use self::transformers::{
    extract_merchant_identifiers_from_metadata, AxisbankAuthConfig, AxisbankPaymentsRequest,
    AxisbankPaymentsResponse, AxisbankRefundRequest, AxisbankRefundResponse,
    AxisbankRefundSyncRequest, AxisbankRefundSyncResponse, AxisbankSyncRequest,
    AxisbankSyncResponse, AxisbankWebhookTypeProbe,
};
use super::macros;
use crate::types::ResponseRouterData;
use common_enums as enums;
use common_utils::{
    errors::CustomResult,
    events,
    ext_traits::ByteSliceExt,
    types::StringMajorUnit,
};
use domain_types::connector_types::EventType;
use domain_types::errors::{ConnectorError, IntegrationError, IntegrationErrorContext, WebhookError};
use domain_types::{
    connector_flow::{
        Accept, Authenticate, Authorize, Capture, ClientAuthenticationToken,
        CreateConnectorCustomer, CreateOrder, DefendDispute, IncrementalAuthorization,
        MandateRevoke, PSync, PaymentMethodToken, PostAuthenticate, PreAuthenticate, RSync, Refund,
        RepeatPayment, ServerAuthenticationToken, ServerSessionAuthenticationToken, SetupMandate,
        SubmitEvidence, VerifyWebhookSource, Void, VoidPC,
    },
    connector_types::{
        AcceptDisputeData, ClientAuthenticationTokenRequestData, ConnectorCustomerData,
        ConnectorCustomerResponse, ConnectorSpecifications, ConnectorWebhookSecrets,
        DisputeDefendData, DisputeFlowData,
        DisputeResponseData, MandateRevokeRequestData, MandateRevokeResponseData,
        PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData,
        PaymentMethodTokenResponse, PaymentMethodTokenizationData, PaymentVoidData,
        PaymentsAuthenticateData, PaymentsAuthorizeData, PaymentsCancelPostCaptureData,
        PaymentsCaptureData, PaymentsIncrementalAuthorizationData, PaymentsPostAuthenticateData,
        PaymentsPreAuthenticateData, PaymentsResponseData, PaymentsSyncData, RefundFlowData,
        RefundSyncData, RefundsData, RefundsResponseData, RepeatPaymentData,
        RequestDetails, ResponseId, RefundWebhookDetailsResponse, WebhookDetailsResponse,
        ServerAuthenticationTokenRequestData, ServerAuthenticationTokenResponseData,
        ServerSessionAuthenticationTokenRequestData, ServerSessionAuthenticationTokenResponseData,
        SetupMandateRequestData, SubmitEvidenceData, VerifyWebhookSourceFlowData,
    },
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorSpecificConfig, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_request_types::VerifyWebhookSourceRequestData,
    router_response_types::Response,
    router_response_types::VerifyWebhookSourceResponseData,
    types::Connectors,
};
use error_stack::ResultExt;
use base64::Engine as _;
use hyperswitch_masking::Maskable;
use interfaces::{
    api::ConnectorCommon, connector_integration_v2::ConnectorIntegrationV2, connector_types,
    decode::BodyDecoding, verification::SourceVerification,
};
use serde::Serialize;
use tracing::error;

/// Recursively sort all JSON object keys alphabetically.
///
/// Required for Axis Bank webhook signature verification: the spec states that
/// the callback JSON body keys must be alphabetically sorted before signing.
fn sort_json_keys_alphabetically(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut sorted: serde_json::Map<String, serde_json::Value> =
                serde_json::Map::new();
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for key in keys {
                sorted.insert(key.clone(), sort_json_keys_alphabetically(&map[key]));
            }
            serde_json::Value::Object(sorted)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(sort_json_keys_alphabetically).collect())
        }
        other => other.clone(),
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    connector_types::ConnectorServiceTrait<T> for Axisbank<T>
{
}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    SourceVerification for Axisbank<T>
{
}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize> BodyDecoding
    for Axisbank<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAuthorizeV2<T> for Axisbank<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentSyncV2 for Axisbank<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentVoidV2 for Axisbank<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundV2 for Axisbank<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundSyncV2 for Axisbank<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentCapture for Axisbank<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    connector_types::SetupMandateV2<T> for Axisbank<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    connector_types::CreateConnectorCustomer for Axisbank<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentOrderCreate for Axisbank<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    connector_types::ValidationTrait for Axisbank<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    connector_types::VerifyRedirectResponse for Axisbank<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    connector_types::AcceptDispute for Axisbank<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    connector_types::DisputeDefend for Axisbank<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    connector_types::SubmitEvidenceV2 for Axisbank<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    connector_types::MandateRevokeV2 for Axisbank<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentTokenV2<T> for Axisbank<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentPreAuthenticateV2<T> for Axisbank<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentPostAuthenticateV2<T> for Axisbank<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAuthenticateV2<T> for Axisbank<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    connector_types::RepeatPaymentV2<T> for Axisbank<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentVoidPostCaptureV2 for Axisbank<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    connector_types::ClientAuthentication for Axisbank<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    connector_types::ServerSessionAuthentication for Axisbank<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    connector_types::ServerAuthentication for Axisbank<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentIncrementalAuthorization for Axisbank<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    connector_types::IncomingWebhook for Axisbank<T>
{
    /// Extract the RSA-PSS-SHA256 signature from the `x-merchant-payload-signature` header.
    fn get_webhook_source_verification_signature(
        &self,
        request: &RequestDetails,
        _connector_webhook_secret: &ConnectorWebhookSecrets,
    ) -> Result<Vec<u8>, error_stack::Report<WebhookError>> {
        use crate::connectors::juspay_upi_stack::constants::X_MERCHANT_PAYLOAD_SIGNATURE;

        let signature_b64 = request
            .headers
            .get(X_MERCHANT_PAYLOAD_SIGNATURE)
            .ok_or(WebhookError::WebhookSignatureNotFound)
            .attach_printable("Missing x-merchant-payload-signature header in Axis Bank callback")?;

        base64::engine::general_purpose::STANDARD
            .decode(signature_b64)
            .or_else(|_| {
                common_utils::consts::BASE64_ENGINE_URL_SAFE_NO_PAD.decode(signature_b64)
            })
            .change_context(WebhookError::WebhookSignatureNotFound)
            .attach_printable("Failed to base64-decode Axis Bank webhook signature")
    }

    /// Construct the signing message: alphabetically-sorted JSON body bytes.
    ///
    /// Per Axis Bank spec, the callback signature is computed over the JSON body
    /// with keys sorted alphabetically.
    fn get_webhook_source_verification_message(
        &self,
        request: &RequestDetails,
        _connector_webhook_secret: &ConnectorWebhookSecrets,
    ) -> Result<Vec<u8>, error_stack::Report<WebhookError>> {
        let body_value: serde_json::Value = serde_json::from_slice(&request.body)
            .change_context(WebhookError::WebhookBodyDecodingFailed)
            .attach_printable("Failed to parse Axis Bank webhook body as JSON")?;

        // Sort JSON keys alphabetically (as required by Axis Bank spec)
        let sorted_json = sort_json_keys_alphabetically(&body_value);

        serde_json::to_vec(&sorted_json)
            .change_context(WebhookError::WebhookBodyDecodingFailed)
            .attach_printable("Failed to serialize sorted Axis Bank webhook body")
    }

    /// Verify the webhook signature using RSA-PSS-SHA256 and Juspay's public key.
    fn verify_webhook_source(
        &self,
        request: RequestDetails,
        _connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        connector_account_details: Option<ConnectorSpecificConfig>,
    ) -> Result<bool, error_stack::Report<WebhookError>> {
        let connector_config = connector_account_details
            .ok_or(WebhookError::WebhookVerificationSecretNotFound)
            .attach_printable("Axis Bank connector_account_details missing for webhook verification")?;

        let auth = AxisbankAuthConfig::try_from(&connector_config)
            .change_context(WebhookError::WebhookSourceVerificationFailed)
            .attach_printable("Failed to extract AxisbankAuthConfig for webhook verification")?;

        let dummy_secret = ConnectorWebhookSecrets {
            secret: Vec::new(),
            additional_secret: None,
        };

        let signature = self.get_webhook_source_verification_signature(&request, &dummy_secret)?;
        let message = self.get_webhook_source_verification_message(&request, &dummy_secret)?;

        let signature_b64 =
            common_utils::consts::BASE64_ENGINE_URL_SAFE_NO_PAD.encode(&signature);
        let message_str = String::from_utf8_lossy(&message);
        crate::connectors::juspay_upi_stack::crypto::verify_jws_signature_pss(
            &signature_b64,
            &message_str,
            &auth.juspay_public_key,
        )
        .change_context(WebhookError::WebhookSourceVerificationFailed)
        .attach_printable("RSA-PSS-SHA256 verification failed for Axis Bank webhook")
    }

    /// Determine the event type from the webhook body.
    ///
    /// Axis Bank sends two callback types:
    /// - Payment callback: has `merchantRequestId`, `gatewayResponseCode`, `type`
    /// - Refund callback: has `refundRequestId`
    fn get_event_type(
        &self,
        request: RequestDetails,
    ) -> Result<EventType, error_stack::Report<WebhookError>> {
        use transformers::webhook_gateway_code_to_attempt_status;

        let probe: AxisbankWebhookTypeProbe = serde_json::from_slice(&request.body)
            .change_context(WebhookError::WebhookEventTypeNotFound)
            .attach_printable("Failed to probe Axis Bank webhook type")?;

        if probe.refund_request_id.is_some() {
            // Refund callback
            let callback: axisbank::RefundCallbackPayload = serde_json::from_slice(&request.body)
                .change_context(WebhookError::WebhookEventTypeNotFound)
                .attach_printable("Failed to parse Axis Bank refund callback")?;

            let status = transformers::webhook_gateway_code_to_refund_status(
                &callback.refund_type,
                &callback.gateway_response_code,
                &callback.gateway_response_status,
            );

            match status {
                common_enums::RefundStatus::Success => Ok(EventType::RefundSuccess),
                common_enums::RefundStatus::Failure
                | common_enums::RefundStatus::TransactionFailure => Ok(EventType::RefundFailure),
                common_enums::RefundStatus::Pending
                | common_enums::RefundStatus::ManualReview => Ok(EventType::RefundFailure),
            }
        } else {
            // Payment callback
            let callback: axisbank::PayCallbackPayload = serde_json::from_slice(&request.body)
                .change_context(WebhookError::WebhookEventTypeNotFound)
                .attach_printable("Failed to parse Axis Bank payment callback")?;

            let attempt_status =
                webhook_gateway_code_to_attempt_status(&callback.gateway_response_code);

            match attempt_status {
                common_enums::AttemptStatus::Charged => Ok(EventType::PaymentIntentSuccess),
                common_enums::AttemptStatus::Failure
                | common_enums::AttemptStatus::AuthorizationFailed
                | common_enums::AttemptStatus::AuthenticationFailed => {
                    Ok(EventType::PaymentIntentFailure)
                }
                _ => Ok(EventType::PaymentIntentProcessing),
            }
        }
    }

    /// Process a payment webhook and return standardised `WebhookDetailsResponse`.
    fn process_payment_webhook(
        &self,
        request: RequestDetails,
        _connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorSpecificConfig>,
        _event_context: Option<domain_types::connector_types::EventContext>,
    ) -> Result<WebhookDetailsResponse, error_stack::Report<WebhookError>> {
        use transformers::webhook_gateway_code_to_attempt_status;

        let callback: axisbank::PayCallbackPayload = serde_json::from_slice(&request.body)
            .change_context(WebhookError::WebhookBodyDecodingFailed)
            .attach_printable("Failed to parse Axis Bank payment callback body")?;

        let status = webhook_gateway_code_to_attempt_status(&callback.gateway_response_code);

        let resource_id = if !callback.gateway_transaction_id.is_empty() {
            Some(ResponseId::ConnectorTransactionId(
                callback.gateway_transaction_id.clone(),
            ))
        } else {
            Some(ResponseId::EncodedData(
                callback.merchant_request_id.clone(),
            ))
        };

        Ok(WebhookDetailsResponse {
            resource_id,
            status,
            connector_response_reference_id: callback.gateway_reference_id.clone(),
            mandate_reference: None,
            error_code: None,
            error_message: None,
            error_reason: None,
            raw_connector_response: Some(String::from_utf8_lossy(&request.body).to_string()),
            status_code: 200,
            response_headers: None,
            amount_captured: None,
            minor_amount_captured: None,
            network_txn_id: None,
            payment_method_update: None,
        })
    }

    /// Process a refund webhook and return standardised `RefundWebhookDetailsResponse`.
    fn process_refund_webhook(
        &self,
        request: RequestDetails,
        _connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorSpecificConfig>,
    ) -> Result<RefundWebhookDetailsResponse, error_stack::Report<WebhookError>> {
        let callback: axisbank::RefundCallbackPayload = serde_json::from_slice(&request.body)
            .change_context(WebhookError::WebhookBodyDecodingFailed)
            .attach_printable("Failed to parse Axis Bank refund callback body")?;

        let status = transformers::webhook_gateway_code_to_refund_status(
            &callback.refund_type,
            &callback.gateway_response_code,
            &callback.gateway_response_status,
        );

        Ok(RefundWebhookDetailsResponse {
            connector_refund_id: Some(callback.refund_request_id.clone()),
            status,
            connector_response_reference_id: Some(callback.original_merchant_request_id.clone()),
            error_code: None,
            error_message: None,
            raw_connector_response: Some(String::from_utf8_lossy(&request.body).to_string()),
            status_code: 200,
            response_headers: None,
        })
    }

    /// Return the raw webhook body as the resource object (for logging/debugging).
    fn get_webhook_resource_object(
        &self,
        request: RequestDetails,
    ) -> Result<Box<dyn hyperswitch_masking::ErasedMaskSerialize>, error_stack::Report<WebhookError>>
    {
        let body: serde_json::Value = serde_json::from_slice(&request.body)
            .change_context(WebhookError::WebhookResourceObjectNotFound)
            .attach_printable("Failed to parse Axis Bank webhook body as resource object")?;

        Ok(Box::new(body))
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    connector_types::VerifyWebhookSourceV2 for Axisbank<T>
{
}

macros::macro_connector_payout_implementation!(
    connector: Axisbank,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize]
);

macros::create_amount_converter_wrapper!(
    connector_name: Axisbank,
    amount_type: StringMajorUnit
);

macros::create_all_prerequisites!(
    connector_name: Axisbank,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: AxisbankPaymentsRequest,
            response_body: AxisbankPaymentsResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: PSync,
            request_body: AxisbankSyncRequest,
            response_body: AxisbankSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ),
        (
            flow: Refund,
            request_body: AxisbankRefundRequest,
            response_body: AxisbankRefundResponse,
            router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ),
        (
            flow: RSync,
            request_body: AxisbankRefundSyncRequest,
            response_body: AxisbankRefundSyncResponse,
            router_data: RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        )
    ],
    amount_converters: [
        amount_converter: StringMajorUnit
    ],
    member_functions: {
        /// Preprocess JWE-encrypted responses from Axis Bank.
        ///
        /// Delegates to the shared Juspay UPI Stack preprocessing function.
        /// All banks in the Juspay UPI Merchant Stack family (Axis, YES, Kotak, RBL, AU)
        /// share the same JWE/JWS handling pipeline.
        pub fn preprocess_response_bytes<F, FCD, Req, Res>(
            &self,
            req: &RouterDataV2<F, FCD, Req, Res>,
            response_bytes: bytes::Bytes,
            _status_code: u16,
        ) -> Result<bytes::Bytes, ConnectorError>
        where
            Self: ConnectorIntegrationV2<F, FCD, Req, Res>,
        {
            use domain_types::errors::ResponseTransformationErrorContext;

            let auth_config = AxisbankAuthConfig::try_from(&req.connector_config)
                .map_err(|e| {
                    error!(error = %e, "Could not extract Axisbank auth config");
                    ConnectorError::ResponseDeserializationFailed {
                        context: ResponseTransformationErrorContext {
                            http_status_code: None,
                            additional_context: Some(format!("Failed to extract AxisbankAuthConfig from connector_config. Verify all required fields are present: merchant_id, merchant_channel_id, merchant_kid, juspay_kid, merchant_private_key, juspay_public_key. See documentation: {}/docs/transactions", crate::connectors::juspay_upi_stack::constants::DOC_URL_BASE)),
                        },
                    }
                })?;

            crate::connectors::juspay_upi_stack::crypto::preprocess_jwe_response(
                response_bytes,
                &auth_config.merchant_private_key,
            )
        }

        pub fn connector_base_url<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.axisbank.base_url
        }

        pub fn connector_base_url_refunds<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, RefundFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.axisbank.base_url
        }

        pub fn build_headers<F, FCD, Req, Res>(
            &self,
            _req: &RouterDataV2<F, FCD, Req, Res>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, IntegrationError>
        where
            Self: ConnectorIntegrationV2<F, FCD, Req, Res>,
        {
            Ok(vec![
                ("content-type".to_string(), "application/json".to_string().into()),
            ])
        }
    }
);

// Authorize Flow - Register Intent
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Axisbank,
    curl_request: Json(AxisbankPaymentsRequest),
    curl_response: AxisbankPaymentsResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    preprocess_response: true,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, IntegrationError> {
            let (merchant_id, merchant_channel_id) =
                extract_merchant_identifiers_from_metadata(&req.request.metadata)?;
            let merchant_request_id = req.resource_common_data.connector_request_reference_id.clone();
            crate::connectors::juspay_upi_stack::transformers::build_request_headers(
                &merchant_id,
                &merchant_channel_id,
                &merchant_request_id,
            )
        }

        fn get_url(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<String, IntegrationError> {
            let base_url = self.connector_base_url(req);
            Ok(format!("{}merchants/transactions/registerIntent", base_url))
        }
    }
);

// PSync Flow - Status 360
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Axisbank,
    curl_request: Json(AxisbankSyncRequest),
    curl_response: AxisbankSyncResponse,
    flow_name: PSync,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsSyncData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    preprocess_response: true,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, IntegrationError> {
            let (merchant_id, merchant_channel_id) =
                extract_merchant_identifiers_from_metadata(&req.resource_common_data.connector_feature_data)?;
            let merchant_request_id = req
                .request
                .connector_transaction_id
                .get_connector_transaction_id()
                .map_err(|_| IntegrationError::MissingRequiredField {
                    field_name: "connector_transaction_id",
                    context: IntegrationErrorContext {
                        suggested_action: Some("connector_transaction_id must be set before calling PSync".to_string()),
                        doc_url: Some(crate::connectors::juspay_upi_stack::constants::DOC_URL_TRANSACTION_STATUS_360.to_string()),
                        additional_context: Some("PSync requires the merchantRequestId returned from Register Intent. Ensure the payment was initialized successfully before querying status.".to_string()),
                    },
                })?;

            crate::connectors::juspay_upi_stack::transformers::build_request_headers(
                &merchant_id,
                &merchant_channel_id,
                &merchant_request_id,
            )
        }

        fn get_url(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<String, IntegrationError> {
            let base_url = self.connector_base_url(req);
            Ok(format!("{}merchants/transactions/status360", base_url))
        }
    }
);

// Refund Flow - Refund 360
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Axisbank,
    curl_request: Json(AxisbankRefundRequest),
    curl_response: AxisbankRefundResponse,
    flow_name: Refund,
    resource_common_data: RefundFlowData,
    flow_request: RefundsData,
    flow_response: RefundsResponseData,
    http_method: Post,
    preprocess_response: true,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, IntegrationError> {
            let (merchant_id, merchant_channel_id) =
                extract_merchant_identifiers_from_metadata(&req.resource_common_data.connector_feature_data)?;

            let refund_request_id = req.request.refund_id.clone();

            crate::connectors::juspay_upi_stack::transformers::build_request_headers(
                &merchant_id,
                &merchant_channel_id,
                &refund_request_id,
            )
        }

        fn get_url(
            &self,
            req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ) -> CustomResult<String, IntegrationError> {
            let base_url = self.connector_base_url_refunds(req);
            Ok(format!("{}merchants/transactions/refund360", base_url))
        }
    }
);

// RSync Flow - Refund Status (uses same endpoint as Refund)
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Axisbank,
    curl_request: Json(AxisbankRefundSyncRequest),
    curl_response: AxisbankRefundSyncResponse,
    flow_name: RSync,
    resource_common_data: RefundFlowData,
    flow_request: RefundSyncData,
    flow_response: RefundsResponseData,
    http_method: Post,
    preprocess_response: true,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, IntegrationError> {
            let (merchant_id, merchant_channel_id) =
                extract_merchant_identifiers_from_metadata(&req.resource_common_data.connector_feature_data)?;

            let refund_request_id = req.request.connector_refund_id.clone();

            crate::connectors::juspay_upi_stack::transformers::build_request_headers(
                &merchant_id,
                &merchant_channel_id,
                &refund_request_id,
            )
        }

        fn get_url(
            &self,
            req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ) -> CustomResult<String, IntegrationError> {
            let base_url = self.connector_base_url_refunds(req);
            Ok(format!("{}merchants/transactions/refund360", base_url))
        }
    }
);

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    ConnectorCommon for Axisbank<T>
{
    fn id(&self) -> &'static str {
        "axisbank"
    }

    fn get_currency_unit(&self) -> enums::CurrencyUnit {
        enums::CurrencyUnit::Minor
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn get_auth_header(
        &self,
        _auth_type: &ConnectorSpecificConfig,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, IntegrationError> {
        Ok(vec![])
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.axisbank.base_url.as_ref()
    }

    fn build_error_response(
        &self,
        res: Response,
        _event_builder: Option<&mut events::Event>,
    ) -> CustomResult<ErrorResponse, ConnectorError> {
        let error_response = if let Ok(error) = res
            .response
            .parse_struct::<axisbank::AxisbankErrorResponse>("Axisbank ErrorResponse")
        {
            axisbank::build_error_response(
                res.status_code,
                &error.response_code,
                &error.response_message,
            )
        } else {
            let raw_response = String::from_utf8_lossy(&res.response);
            axisbank::build_error_response(res.status_code, "UNKNOWN", &raw_response)
        };

        Ok(error_response)
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    ConnectorSpecifications for Axisbank<T>
{
    fn get_supported_payment_methods(
        &self,
    ) -> Option<&'static domain_types::types::SupportedPaymentMethods> {
        None
    }

    fn get_supported_webhook_flows(&self) -> Option<&'static [enums::EventClass]> {
        static SUPPORTED: &[enums::EventClass] = &[
            enums::EventClass::Payments,
            enums::EventClass::Refunds,
        ];
        Some(SUPPORTED)
    }
}

// Stub implementations for unsupported flows
impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
    for Axisbank<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
    for Axisbank<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData<T>,
        PaymentsResponseData,
    > for Axisbank<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        PreAuthenticate,
        PaymentFlowData,
        PaymentsPreAuthenticateData<T>,
        PaymentsResponseData,
    > for Axisbank<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        Authenticate,
        PaymentFlowData,
        PaymentsAuthenticateData<T>,
        PaymentsResponseData,
    > for Axisbank<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        PostAuthenticate,
        PaymentFlowData,
        PaymentsPostAuthenticateData<T>,
        PaymentsResponseData,
    > for Axisbank<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        RepeatPayment,
        PaymentFlowData,
        RepeatPaymentData<T>,
        PaymentsResponseData,
    > for Axisbank<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        CreateConnectorCustomer,
        PaymentFlowData,
        ConnectorCustomerData,
        ConnectorCustomerResponse,
    > for Axisbank<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for Axisbank<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        PaymentMethodToken,
        PaymentFlowData,
        PaymentMethodTokenizationData<T>,
        PaymentMethodTokenResponse,
    > for Axisbank<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    for Axisbank<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
    for Axisbank<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
    for Axisbank<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        MandateRevoke,
        PaymentFlowData,
        MandateRevokeRequestData,
        MandateRevokeResponseData,
    > for Axisbank<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        ServerAuthenticationToken,
        PaymentFlowData,
        ServerAuthenticationTokenRequestData,
        ServerAuthenticationTokenResponseData,
    > for Axisbank<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        ServerSessionAuthenticationToken,
        PaymentFlowData,
        ServerSessionAuthenticationTokenRequestData,
        ServerSessionAuthenticationTokenResponseData,
    > for Axisbank<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        ClientAuthenticationToken,
        PaymentFlowData,
        ClientAuthenticationTokenRequestData,
        PaymentsResponseData,
    > for Axisbank<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        VoidPC,
        PaymentFlowData,
        PaymentsCancelPostCaptureData,
        PaymentsResponseData,
    > for Axisbank<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        IncrementalAuthorization,
        PaymentFlowData,
        PaymentsIncrementalAuthorizationData,
        PaymentsResponseData,
    > for Axisbank<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        VerifyWebhookSource,
        VerifyWebhookSourceFlowData,
        VerifyWebhookSourceRequestData,
        VerifyWebhookSourceResponseData,
    > for Axisbank<T>
{
}
