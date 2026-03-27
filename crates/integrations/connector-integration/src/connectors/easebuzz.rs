pub mod transformers;

use std::fmt::Debug;

use common_enums::CurrencyUnit;
use common_utils::{
    errors::CustomResult, events, ext_traits::ByteSliceExt, types::StringMajorUnit,
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
        ConnectorCustomerResponse, DisputeDefendData, DisputeFlowData, DisputeResponseData,
        MandateRevokeRequestData, MandateRevokeResponseData, PaymentCreateOrderData,
        PaymentCreateOrderResponse, PaymentFlowData, PaymentMethodTokenResponse,
        PaymentMethodTokenizationData, PaymentVoidData, PaymentsAuthenticateData,
        PaymentsAuthorizeData, PaymentsCancelPostCaptureData, PaymentsCaptureData,
        PaymentsIncrementalAuthorizationData, PaymentsPostAuthenticateData,
        PaymentsPreAuthenticateData, PaymentsResponseData, PaymentsSdkSessionTokenData,
        PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData,
        RepeatPaymentData, SessionTokenRequestData, SessionTokenResponseData,
        SetupMandateRequestData, SubmitEvidenceData, VerifyWebhookSourceFlowData,
    },
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorSpecificConfig, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_request_types::VerifyWebhookSourceRequestData,
    router_response_types::{Response, VerifyWebhookSourceResponseData},
    types::Connectors,
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, Maskable, PeekInterface};
use interfaces::{
    api::ConnectorCommon, connector_integration_v2::ConnectorIntegrationV2, connector_types,
    decode::BodyDecoding,
};
use serde::Serialize;
use transformers as easebuzz;
use transformers::{
    EasebuzzAuthorizeRequest, EasebuzzAuthorizeResponse, EasebuzzCreateOrderRequest,
    EasebuzzCreateOrderResponse, EasebuzzRefundRequest, EasebuzzRefundResponse,
    EasebuzzRefundSyncRequest, EasebuzzRefundSyncResponse, EasebuzzRepeatPaymentRequest,
    EasebuzzRepeatPaymentResponse, EasebuzzRevokeMandateRequest, EasebuzzRevokeMandateResponse,
    EasebuzzSetupMandateRequest, EasebuzzSetupMandateResponse, EasebuzzSyncRequest,
    EasebuzzSyncResponse,
};

use super::macros;
use crate::{types::ResponseRouterData, with_error_response_body};

pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
}

// =============================================================================
// CONNECTOR COMMON IMPLEMENTATION
// =============================================================================
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> ConnectorCommon
    for Easebuzz<T>
{
    fn id(&self) -> &'static str {
        "easebuzz"
    }

    fn get_currency_unit(&self) -> CurrencyUnit {
        CurrencyUnit::Base
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/x-www-form-urlencoded"
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.easebuzz.base_url.as_ref()
    }

    fn get_auth_header(
        &self,
        _auth_type: &ConnectorSpecificConfig,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        // Easebuzz uses hash-based auth in request body, not headers
        Ok(vec![])
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut events::Event>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: easebuzz::EasebuzzErrorResponse = res
            .response
            .parse_struct("EasebuzzErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        with_error_response_body!(event_builder, response);

        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response.code,
            message: response.message.clone(),
            reason: Some(response.message),
            attempt_status: None,
            connector_transaction_id: None,
            network_decline_code: None,
            network_advice_code: None,
            network_error_message: None,
        })
    }
}

// =============================================================================
// BODY DECODING IMPLEMENTATION
// =============================================================================
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> BodyDecoding
    for Easebuzz<T>
{
}

// =============================================================================
// CONNECTOR SERVICE TRAIT IMPLEMENTATIONS
// =============================================================================
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ConnectorServiceTrait<T> for Easebuzz<T>
{
}

// ===== FLOW TRAIT IMPLEMENTATIONS =====
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::AcceptDispute for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::CreateConnectorCustomer for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::DisputeDefend for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::IncomingWebhook for Easebuzz<T>
{
    fn verify_webhook_source(
        &self,
        request: domain_types::connector_types::RequestDetails,
        connector_webhook_secret: Option<domain_types::connector_types::ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorSpecificConfig>,
    ) -> Result<bool, error_stack::Report<errors::ConnectorError>> {
        let connector_webhook_secret = connector_webhook_secret
            .ok_or(errors::ConnectorError::WebhookSourceVerificationFailed)
            .attach_printable("Connector webhook secret not configured")?;

        let signature =
            self.get_webhook_source_verification_signature(&request, &connector_webhook_secret)?;
        let message =
            self.get_webhook_source_verification_message(&request, &connector_webhook_secret)?;

        // Easebuzz uses SHA-512 for webhook verification
        // Compute SHA-512 hash of the message using the secret as key
        use common_utils::crypto::{GenerateDigest, Sha512};
        let expected_signature = Sha512
            .generate_digest(&message)
            .change_context(errors::ConnectorError::WebhookSourceVerificationFailed)
            .attach_printable("Failed to generate SHA-512 digest for webhook verification")?;

        Ok(expected_signature.eq(&signature))
    }

    fn get_webhook_source_verification_signature(
        &self,
        request: &domain_types::connector_types::RequestDetails,
        _connector_webhook_secret: &domain_types::connector_types::ConnectorWebhookSecrets,
    ) -> Result<Vec<u8>, error_stack::Report<errors::ConnectorError>> {
        // Easebuzz transaction webhooks include a `hash` field in the body
        // Try to parse as transaction webhook to extract the hash
        let body: serde_json::Value = request
            .body
            .parse_struct("WebhookBody")
            .change_context(errors::ConnectorError::WebhookSignatureNotFound)?;

        let hash_str = body
            .get("hash")
            .and_then(|h| h.as_str())
            .ok_or(errors::ConnectorError::WebhookSignatureNotFound)?;

        hex::decode(hash_str).change_context(errors::ConnectorError::WebhookSignatureNotFound)
    }

    fn get_webhook_source_verification_message(
        &self,
        request: &domain_types::connector_types::RequestDetails,
        connector_webhook_secret: &domain_types::connector_types::ConnectorWebhookSecrets,
    ) -> Result<Vec<u8>, error_stack::Report<errors::ConnectorError>> {
        // Easebuzz webhook hash verification uses reverse hash formula:
        // sha512(salt|status|||||||||||email|firstname|productinfo|amount|txnid|key)
        // (reverse of the initiate payment hash)
        let body: serde_json::Value = request
            .body
            .parse_struct("WebhookBody")
            .change_context(errors::ConnectorError::WebhookSourceVerificationFailed)?;

        let salt = String::from_utf8_lossy(&connector_webhook_secret.secret).to_string();
        let status = body.get("status").and_then(|v| v.as_str()).unwrap_or("");
        let email = body.get("email").and_then(|v| v.as_str()).unwrap_or("");
        let firstname = body.get("firstname").and_then(|v| v.as_str()).unwrap_or("");
        let productinfo = body
            .get("productinfo")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let amount = body.get("amount").and_then(|v| v.as_str()).unwrap_or("");
        let txnid = body.get("txnid").and_then(|v| v.as_str()).unwrap_or("");
        let key = body.get("key").and_then(|v| v.as_str()).unwrap_or("");

        // Reverse hash formula: salt|status|udf10|...|udf1|email|firstname|productinfo|amount|txnid|key
        let hash_input = format!(
            "{salt}|{status}|||||||||||{email}|{firstname}|{productinfo}|{amount}|{txnid}|{key}"
        );

        Ok(hash_input.into_bytes())
    }

    fn get_event_type(
        &self,
        request: domain_types::connector_types::RequestDetails,
        _connector_webhook_secret: Option<domain_types::connector_types::ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorSpecificConfig>,
    ) -> Result<domain_types::connector_types::EventType, error_stack::Report<errors::ConnectorError>>
    {
        let webhook_body: easebuzz::EasebuzzWebhookBody = request
            .body
            .parse_struct("EasebuzzWebhookBody")
            .change_context(errors::ConnectorError::WebhookEventTypeNotFound)?;

        easebuzz::get_easebuzz_webhook_event_type(&webhook_body)
    }

    fn process_payment_webhook(
        &self,
        request: domain_types::connector_types::RequestDetails,
        _connector_webhook_secret: Option<domain_types::connector_types::ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorSpecificConfig>,
    ) -> Result<
        domain_types::connector_types::WebhookDetailsResponse,
        error_stack::Report<errors::ConnectorError>,
    > {
        let webhook_body: easebuzz::EasebuzzWebhookBody = request
            .body
            .parse_struct("EasebuzzWebhookBody")
            .change_context(errors::ConnectorError::WebhookBodyDecodingFailed)?;

        match webhook_body {
            easebuzz::EasebuzzWebhookBody::Transaction(txn) => {
                let status = easebuzz::map_easebuzz_webhook_txn_status(&txn.status);

                let error_code = txn
                    .error
                    .as_deref()
                    .filter(|e| !e.is_empty() && *e != "NA")
                    .map(|e| e.to_string());
                let error_message = txn
                    .error_message
                    .as_deref()
                    .filter(|e| !e.is_empty())
                    .map(|e| e.to_string());

                Ok(domain_types::connector_types::WebhookDetailsResponse {
                    resource_id: Some(
                        domain_types::connector_types::ResponseId::ConnectorTransactionId(
                            txn.easepayid.clone(),
                        ),
                    ),
                    status,
                    connector_response_reference_id: Some(txn.txnid),
                    mandate_reference: None,
                    error_code,
                    error_message: error_message.clone(),
                    error_reason: error_message,
                    raw_connector_response: Some(
                        String::from_utf8_lossy(&request.body).to_string(),
                    ),
                    status_code: 200,
                    response_headers: None,
                    transformation_status: common_enums::WebhookTransformationStatus::Complete,
                    amount_captured: None,
                    minor_amount_captured: None,
                    network_txn_id: None,
                    payment_method_update: None,
                })
            }
            easebuzz::EasebuzzWebhookBody::PresentmentStatus(presentment) => {
                let status = easebuzz::map_easebuzz_webhook_presentment_status(&presentment.status);

                let connector_transaction_id = presentment
                    .pg_transaction_id
                    .clone()
                    .unwrap_or_else(|| presentment.id.clone());

                Ok(domain_types::connector_types::WebhookDetailsResponse {
                    resource_id: Some(
                        domain_types::connector_types::ResponseId::ConnectorTransactionId(
                            connector_transaction_id,
                        ),
                    ),
                    status,
                    connector_response_reference_id: presentment.merchant_request_number,
                    mandate_reference: None,
                    error_code: None,
                    error_message: None,
                    error_reason: None,
                    raw_connector_response: Some(
                        String::from_utf8_lossy(&request.body).to_string(),
                    ),
                    status_code: 200,
                    response_headers: None,
                    transformation_status: common_enums::WebhookTransformationStatus::Complete,
                    amount_captured: None,
                    minor_amount_captured: None,
                    network_txn_id: None,
                    payment_method_update: None,
                })
            }
            easebuzz::EasebuzzWebhookBody::MandateStatus(_mandate) => {
                // Mandate status webhooks don't have a dedicated process_mandate_webhook.
                // They are dispatched via get_event_type returning MandateActive/MandateRevoked/MandateFailed.
                Err(errors::ConnectorError::WebhooksNotImplemented.into())
            }
            easebuzz::EasebuzzWebhookBody::Refund(_) => {
                // Refund webhooks are handled by process_refund_webhook
                Err(errors::ConnectorError::WebhooksNotImplemented.into())
            }
        }
    }

    fn process_refund_webhook(
        &self,
        request: domain_types::connector_types::RequestDetails,
        _connector_webhook_secret: Option<domain_types::connector_types::ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorSpecificConfig>,
    ) -> Result<
        domain_types::connector_types::RefundWebhookDetailsResponse,
        error_stack::Report<errors::ConnectorError>,
    > {
        let webhook_body: easebuzz::EasebuzzWebhookBody = request
            .body
            .parse_struct("EasebuzzWebhookBody")
            .change_context(errors::ConnectorError::WebhookBodyDecodingFailed)?;

        match webhook_body {
            easebuzz::EasebuzzWebhookBody::Refund(refund) => {
                let status = easebuzz::map_easebuzz_webhook_refund_status(&refund.refund_status);

                Ok(
                    domain_types::connector_types::RefundWebhookDetailsResponse {
                        connector_refund_id: Some(refund.refund_id),
                        status,
                        connector_response_reference_id: refund.merchant_refund_id,
                        error_code: None,
                        error_message: None,
                        raw_connector_response: Some(
                            String::from_utf8_lossy(&request.body).to_string(),
                        ),
                        status_code: 200,
                        response_headers: None,
                    },
                )
            }
            _ => Err(errors::ConnectorError::WebhooksNotImplemented.into()),
        }
    }

    fn get_webhook_resource_object(
        &self,
        request: domain_types::connector_types::RequestDetails,
    ) -> Result<
        Box<dyn hyperswitch_masking::ErasedMaskSerialize>,
        error_stack::Report<errors::ConnectorError>,
    > {
        let webhook_body: easebuzz::EasebuzzWebhookBody = request
            .body
            .parse_struct("EasebuzzWebhookBody")
            .change_context(errors::ConnectorError::WebhookResourceObjectNotFound)
            .attach_printable("Failed to parse Easebuzz webhook resource object")?;

        Ok(Box::new(webhook_body))
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::MandateRevokeV2 for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAccessToken for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAuthenticateV2<T> for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAuthorizeV2<T> for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentCapture for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentIncrementalAuthorization for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentOrderCreate for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentPostAuthenticateV2<T> for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentPreAuthenticateV2<T> for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentSessionToken for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentSyncV2 for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentTokenV2<T> for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentVoidPostCaptureV2 for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentVoidV2 for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundSyncV2 for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundV2 for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RepeatPaymentV2<T> for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::SdkSessionTokenV2 for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::SetupMandateV2<T> for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::SubmitEvidenceV2 for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ValidationTrait for Easebuzz<T>
{
    fn should_do_order_create(&self) -> bool {
        true
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::VerifyRedirectResponse for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::VerifyWebhookSourceV2 for Easebuzz<T>
{
}

// =============================================================================
// MACRO-BASED CONNECTOR SETUP
// =============================================================================
macros::create_all_prerequisites!(
    connector_name: Easebuzz,
    generic_type: T,
    api: [
        (
            flow: CreateOrder,
            request_body: EasebuzzCreateOrderRequest,
            response_body: EasebuzzCreateOrderResponse,
            router_data: RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>,
        ),
        (
            flow: Authorize,
            request_body: EasebuzzAuthorizeRequest,
            response_body: EasebuzzAuthorizeResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: PSync,
            request_body: EasebuzzSyncRequest,
            response_body: EasebuzzSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ),
        (
            flow: Refund,
            request_body: EasebuzzRefundRequest,
            response_body: EasebuzzRefundResponse,
            router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ),
        (
            flow: RSync,
            request_body: EasebuzzRefundSyncRequest,
            response_body: EasebuzzRefundSyncResponse,
            router_data: RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ),
        (
            flow: SetupMandate,
            request_body: EasebuzzSetupMandateRequest,
            response_body: EasebuzzSetupMandateResponse,
            router_data: RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>,
        ),
        (
            flow: RepeatPayment,
            request_body: EasebuzzRepeatPaymentRequest,
            response_body: EasebuzzRepeatPaymentResponse,
            router_data: RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData<T>, PaymentsResponseData>,
        ),
        (
            flow: MandateRevoke,
            request_body: EasebuzzRevokeMandateRequest,
            response_body: EasebuzzRevokeMandateResponse,
            router_data: RouterDataV2<MandateRevoke, PaymentFlowData, MandateRevokeRequestData, MandateRevokeResponseData>,
        )
    ],
    amount_converters: [
        amount_converter: StringMajorUnit
    ],
    member_functions: {
        pub fn build_headers<F, FCD, Req, Res>(
            &self,
            _req: &RouterDataV2<F, FCD, Req, Res>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError>
        where
            Self: ConnectorIntegrationV2<F, FCD, Req, Res>,
        {
            Ok(vec![
                (headers::CONTENT_TYPE.to_string(), "application/x-www-form-urlencoded".into()),
            ])
        }

        pub fn connector_base_url<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.easebuzz.base_url
        }

        pub fn connector_secondary_base_url<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> CustomResult<&'a str, errors::ConnectorError> {
            let base_url = req
                .resource_common_data
                .connectors
                .easebuzz
                .secondary_base_url
                .as_deref()
                .ok_or(errors::ConnectorError::InvalidConnectorConfig {
                    config: "secondary_base_url",
                })?;
            Ok(base_url)
        }
    }
);

// =============================================================================
// CreateOrder FLOW IMPLEMENTATION
// =============================================================================
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Easebuzz,
    curl_request: FormUrlEncoded(EasebuzzCreateOrderRequest),
    curl_response: EasebuzzCreateOrderResponse,
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
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req)
        }

        fn get_url(
            &self,
            req: &RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>,
        ) -> CustomResult<String, errors::ConnectorError> {
            Ok(format!(
                "{}/payment/initiateLink",
                self.connector_base_url(req)
            ))
        }
    }
);

// =============================================================================
// AUTHORIZE FLOW IMPLEMENTATION
// =============================================================================
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Easebuzz,
    curl_request: FormUrlEncoded(EasebuzzAuthorizeRequest),
    curl_response: EasebuzzAuthorizeResponse,
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
            Ok(format!(
                "{}/initiate_seamless_payment/",
                self.connector_base_url(req)
            ))
        }
    }
);

// =============================================================================
// PSync FLOW IMPLEMENTATION
// =============================================================================
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Easebuzz,
    curl_request: FormUrlEncoded(EasebuzzSyncRequest),
    curl_response: EasebuzzSyncResponse,
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
            // PSync uses a different base URL (dashboard.easebuzz.in vs pay.easebuzz.in)
            let base_url = self.connector_secondary_base_url(req)?;
            Ok(format!("{}/transaction/v1/retrieve", base_url))
        }
    }
);

// =============================================================================
// REFUND FLOW IMPLEMENTATION
// =============================================================================
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Easebuzz,
    curl_request: FormUrlEncoded(EasebuzzRefundRequest),
    curl_response: EasebuzzRefundResponse,
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
            // Refund uses the DASHBOARD base URL (secondary_base_url = dashboard.easebuzz.in)
            let base_url = req
                .resource_common_data
                .connectors
                .easebuzz
                .secondary_base_url
                .as_deref()
                .ok_or(errors::ConnectorError::InvalidConnectorConfig {
                    config: "secondary_base_url",
                })?;
            Ok(format!("{}/transaction/v2/refund", base_url))
        }
    }
);

// =============================================================================
// RSync FLOW IMPLEMENTATION
// =============================================================================
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Easebuzz,
    curl_request: FormUrlEncoded(EasebuzzRefundSyncRequest),
    curl_response: EasebuzzRefundSyncResponse,
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
            // RSync uses the DASHBOARD base URL (secondary_base_url = dashboard.easebuzz.in)
            let base_url = req
                .resource_common_data
                .connectors
                .easebuzz
                .secondary_base_url
                .as_deref()
                .ok_or(errors::ConnectorError::InvalidConnectorConfig {
                    config: "secondary_base_url",
                })?;
            Ok(format!("{}/refund/v1/retrieve", base_url))
        }
    }
);

// =============================================================================
// SetupMandate FLOW IMPLEMENTATION
// =============================================================================
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Easebuzz,
    curl_request: Json(EasebuzzSetupMandateRequest),
    curl_response: EasebuzzSetupMandateResponse,
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
            _req: &RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            // Mandate API uses application/json content type.
            // Auth is included in the request body (key field + hash).
            Ok(vec![
                (headers::CONTENT_TYPE.to_string(), "application/json".into()),
            ])
        }

        fn get_url(
            &self,
            req: &RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            // Mandate flow uses api.easebuzz.in base URL
            // Step 1: Generate access key via /autocollect/v1/access-key/generate/
            // We use the secondary_base_url or hardcode the mandate API base URL
            let base_url = req
                .resource_common_data
                .connectors
                .easebuzz
                .secondary_base_url
                .as_deref()
                .ok_or(errors::ConnectorError::InvalidConnectorConfig {
                    config: "secondary_base_url",
                })?;
            Ok(format!("{}/autocollect/v1/access-key/generate/", base_url))
        }
    }
);

// =============================================================================
// RepeatPayment FLOW IMPLEMENTATION
// =============================================================================
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Easebuzz,
    curl_request: Json(EasebuzzRepeatPaymentRequest),
    curl_response: EasebuzzRepeatPaymentResponse,
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
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            // RepeatPayment (mandate execute) uses application/json content type
            // and Authorization header with SHA-512 hash + X-EB-MERCHANT-KEY header
            let auth = easebuzz::EasebuzzAuthType::try_from(&req.connector_config)
                .map_err(|_| errors::ConnectorError::FailedToObtainAuthType)?;
            let key = auth.api_key.expose();

            // Compute SHA-512 authorization hash: sha512(key|accNo|ifsc|upihandle|salt)
            // For mandate execute, account details are empty
            let auth_hash = easebuzz::compute_mandate_auth_hash_pub(&key, "", "", "", &key);

            Ok(vec![
                (headers::CONTENT_TYPE.to_string(), "application/json".into()),
                ("Authorization".to_string(), auth_hash.into()),
                ("X-EB-MERCHANT-KEY".to_string(), key.into()),
            ])
        }

        fn get_url(
            &self,
            req: &RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData<T>, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            // Mandate execute uses api.easebuzz.in base URL (secondary_base_url)
            let base_url = req
                .resource_common_data
                .connectors
                .easebuzz
                .secondary_base_url
                .as_deref()
                .ok_or(errors::ConnectorError::InvalidConnectorConfig {
                    config: "secondary_base_url",
                })?;

            // Determine endpoint based on payment method
            // UPI and Wallet use /autocollect/v1/mandate/execute/
            // Netbanking (eNACH) uses /autocollect/v1/mandate/presentment/
            let endpoint = match &req.request.payment_method_data {
                domain_types::payment_method_data::PaymentMethodData::Netbanking(_) => {
                    format!("{}/autocollect/v1/mandate/presentment/", base_url)
                }
                _ => {
                    format!("{}/autocollect/v1/mandate/execute/", base_url)
                }
            };

            Ok(endpoint)
        }
    }
);

// =============================================================================
// MandateRevoke FLOW IMPLEMENTATION
// =============================================================================
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Easebuzz,
    curl_request: Json(EasebuzzRevokeMandateRequest),
    curl_response: EasebuzzRevokeMandateResponse,
    flow_name: MandateRevoke,
    resource_common_data: PaymentFlowData,
    flow_request: MandateRevokeRequestData,
    flow_response: MandateRevokeResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<MandateRevoke, PaymentFlowData, MandateRevokeRequestData, MandateRevokeResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            // MandateRevoke uses application/json content type
            // and Authorization header with SHA-512 hash + X-EB-MERCHANT-KEY header
            let auth = easebuzz::EasebuzzAuthType::try_from(&req.connector_config)
                .map_err(|_| errors::ConnectorError::FailedToObtainAuthType)?;
            let key = auth.api_key.expose();

            // Compute SHA-512 authorization hash: sha512(key|accNo|ifsc|upihandle|salt)
            // For mandate revoke, account details are empty
            let auth_hash = easebuzz::compute_mandate_auth_hash_pub(&key, "", "", "", &key);

            Ok(vec![
                (headers::CONTENT_TYPE.to_string(), "application/json".into()),
                ("Authorization".to_string(), auth_hash.into()),
                ("X-EB-MERCHANT-KEY".to_string(), key.into()),
            ])
        }

        fn get_url(
            &self,
            req: &RouterDataV2<MandateRevoke, PaymentFlowData, MandateRevokeRequestData, MandateRevokeResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            // MandateRevoke uses api.easebuzz.in base URL (secondary_base_url)
            let base_url = req
                .resource_common_data
                .connectors
                .easebuzz
                .secondary_base_url
                .as_deref()
                .ok_or(errors::ConnectorError::InvalidConnectorConfig {
                    config: "secondary_base_url",
                })?;

            // Extract mandate ID from connector_mandate_id, falling back to mandate_id
            let mandate_id = req
                .request
                .connector_mandate_id
                .as_ref()
                .map(|id| id.peek().to_string())
                .unwrap_or_else(|| req.request.mandate_id.peek().to_string());

            Ok(format!(
                "{}/autocollect/v1/mandate/{}/status_update/",
                base_url, mandate_id
            ))
        }
    }
);

// =============================================================================
// SUPPORTED PAYMENT METHODS
// =============================================================================
use std::sync::LazyLock;

use common_enums::{CaptureMethod, PaymentMethod, PaymentMethodType};
use domain_types::{
    connector_types::{ConnectorSpecifications, SupportedPaymentMethodsExt},
    types::{FeatureStatus, PaymentMethodDetails, SupportedPaymentMethods},
};

static EASEBUZZ_SUPPORTED_PAYMENT_METHODS: LazyLock<SupportedPaymentMethods> =
    LazyLock::new(|| {
        let mut supported = SupportedPaymentMethods::new();

        // UPI payment methods
        for pmt in [
            PaymentMethodType::UpiIntent,
            PaymentMethodType::UpiCollect,
            PaymentMethodType::UpiQr,
        ] {
            supported.add(
                PaymentMethod::Upi,
                pmt,
                PaymentMethodDetails {
                    mandates: FeatureStatus::Supported,
                    refunds: FeatureStatus::NotSupported,
                    supported_capture_methods: vec![CaptureMethod::Automatic],
                    specific_features: None,
                },
            );
        }

        // Wallet payment method (redirect-based)
        supported.add(
            PaymentMethod::Wallet,
            PaymentMethodType::Mifinity,
            PaymentMethodDetails {
                mandates: FeatureStatus::Supported,
                refunds: FeatureStatus::NotSupported,
                supported_capture_methods: vec![CaptureMethod::Automatic],
                specific_features: None,
            },
        );

        // Net Banking
        supported.add(
            PaymentMethod::Netbanking,
            PaymentMethodType::Netbanking,
            PaymentMethodDetails {
                mandates: FeatureStatus::Supported,
                refunds: FeatureStatus::NotSupported,
                supported_capture_methods: vec![CaptureMethod::Automatic],
                specific_features: None,
            },
        );

        supported
    });

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> ConnectorSpecifications
    for Easebuzz<T>
{
    fn get_supported_payment_methods(&self) -> Option<&'static SupportedPaymentMethods> {
        Some(&EASEBUZZ_SUPPORTED_PAYMENT_METHODS)
    }
}

// ===== REMAINING EMPTY CONNECTOR INTEGRATION V2 IMPLEMENTATIONS =====
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        CreateConnectorCustomer,
        PaymentFlowData,
        ConnectorCustomerData,
        ConnectorCustomerResponse,
    > for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
    for Easebuzz<T>
{
}

// MandateRevoke ConnectorIntegrationV2 is generated by macro_connector_implementation! below

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        CreateAccessToken,
        PaymentFlowData,
        AccessTokenRequestData,
        AccessTokenResponseData,
    > for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        Authenticate,
        PaymentFlowData,
        PaymentsAuthenticateData<T>,
        PaymentsResponseData,
    > for Easebuzz<T>
{
}

// Authorize ConnectorIntegrationV2 is generated by macro_connector_implementation! below

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
    for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        IncrementalAuthorization,
        PaymentFlowData,
        PaymentsIncrementalAuthorizationData,
        PaymentsResponseData,
    > for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        PostAuthenticate,
        PaymentFlowData,
        PaymentsPostAuthenticateData<T>,
        PaymentsResponseData,
    > for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        PreAuthenticate,
        PaymentFlowData,
        PaymentsPreAuthenticateData<T>,
        PaymentsResponseData,
    > for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        CreateSessionToken,
        PaymentFlowData,
        SessionTokenRequestData,
        SessionTokenResponseData,
    > for Easebuzz<T>
{
}

// PSync ConnectorIntegrationV2 is generated by macro_connector_implementation! below

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        PaymentMethodToken,
        PaymentFlowData,
        PaymentMethodTokenizationData<T>,
        PaymentMethodTokenResponse,
    > for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        VoidPC,
        PaymentFlowData,
        PaymentsCancelPostCaptureData,
        PaymentsResponseData,
    > for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
    for Easebuzz<T>
{
}

// RSync ConnectorIntegrationV2 is generated by macro_connector_implementation! below

// Refund ConnectorIntegrationV2 is generated by macro_connector_implementation! below

// RepeatPayment ConnectorIntegrationV2 is generated by macro_connector_implementation! below

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        SdkSessionToken,
        PaymentFlowData,
        PaymentsSdkSessionTokenData,
        PaymentsResponseData,
    > for Easebuzz<T>
{
}

// SetupMandate ConnectorIntegrationV2 is generated by macro_connector_implementation! below

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
    for Easebuzz<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        domain_types::connector_flow::VerifyWebhookSource,
        VerifyWebhookSourceFlowData,
        VerifyWebhookSourceRequestData,
        VerifyWebhookSourceResponseData,
    > for Easebuzz<T>
{
}

// ===== SOURCE VERIFICATION IMPLEMENTATION =====
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification for Easebuzz<T>
{
}
