pub mod transformers;
use common_utils::Maskable;

use std::fmt::Debug;
use common_enums::CurrencyUnit;
use transformers::{
    self as cryptopay, CryptopayPaymentsRequest, CryptopayPaymentsResponse,
    CryptopayPaymentsResponse as CryptopayPaymentsSyncResponse,
};
use super::macros;
use crate::types::ResponseRouterData;
use hex::encode;
use domain_types::{
    connector_flow::{
        Accept, Authenticate, Authorize, Capture, CreateAccessToken, CreateConnectorCustomer,
        CreateOrder, CreateSessionToken, DefendDispute, PSync, PaymentMethodToken,
        PostAuthenticate, PreAuthenticate, RSync, Refund, RepeatPayment, SetupMandate,
        SubmitEvidence, Void, VoidPC,
    },
    connector_types::{
        AcceptDisputeData, AccessTokenRequestData, AccessTokenResponseData, ConnectorCustomerData,
        ConnectorCustomerResponse, ConnectorWebhookSecrets, DisputeDefendData, DisputeFlowData,
        DisputeResponseData, EventType, PaymentCreateOrderData, PaymentCreateOrderResponse,
        PaymentFlowData, PaymentMethodTokenResponse, PaymentMethodTokenizationData,
        PaymentVoidData, PaymentsAuthenticateData, PaymentsAuthorizeData,
        PaymentsCancelPostCaptureData, PaymentsCaptureData, PaymentsPostAuthenticateData,
        PaymentsPreAuthenticateData, PaymentsResponseData, PaymentsSyncData, RefundFlowData,
        RefundSyncData, RefundsData, RefundsResponseData, RepeatPaymentData, RequestDetails,
        SessionTokenRequestData, SessionTokenResponseData, SetupMandateRequestData,
        SubmitEvidenceData, WebhookDetailsResponse,
    payment_method_data::PaymentMethodDataTypes,
    types::Connectors,
use common_utils::{
    crypto::{self, GenerateDigest, SignMessage, VerifySignature},
    date_time,
    errors::CustomResult,
    ext_traits::ByteSliceExt,
    request::Method,
use serde::Serialize;
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
use domain_types::errors;
use domain_types::router_response_types::Response;
use interfaces::{
    api::ConnectorCommon, connector_integration_v2::ConnectorIntegrationV2, connector_types,
    events::connector_api_logs::ConnectorEvent, verification::SourceVerification,
// use crate::masking::{Mask, Maskable, PeekInterface};
use crate::with_error_response_body;
use base64::Engine;
pub const BASE64_ENGINE: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
use error_stack::ResultExt;
pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const AUTHORIZATION: &str = "Authorization";
    pub(crate) const DATE: &str = "Date";
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > ConnectorCommon for Cryptopay<T>
{
    fn id(&self) -> &'static str {
        "cryptopay"
    }
    fn get_currency_unit(&self) -> CurrencyUnit {
        CurrencyUnit::Base
    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth = cryptopay::CryptopayAuthType::try_from(auth_type)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        Ok(vec![(
            headers::AUTHORIZATION.to_string(),
            auth.api_key.peek().to_owned().into_masked(),
        )])
    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.cryptopay.base_url.as_ref()
    fn build_error_response(
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: cryptopay::CryptopayErrorResponse = res
            .response
            .parse_struct("CryptopayErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        with_error_response_body!(event_builder, response);
        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response.error.code,
            message: response.error.message,
            reason: response.error.reason,
            attempt_status: None,
            connector_transaction_id: None,
            network_advice_code: None,
            network_decline_code: None,
            network_error_message: None,
        })
// Trait implementations with generic type parameters
    > connector_types::ConnectorServiceTrait<T> for Cryptopay<T>
    > connector_types::PaymentAuthorizeV2<T> for Cryptopay<T>
    > connector_types::PaymentSyncV2 for Cryptopay<T>
    > connector_types::PaymentAccessToken for Cryptopay<T>
    > connector_types::CreateConnectorCustomer for Cryptopay<T>
    > connector_types::PaymentSessionToken for Cryptopay<T>
    > connector_types::PaymentVoidPostCaptureV2 for Cryptopay<T>
    >
    ConnectorIntegrationV2<
        VoidPC,
        PaymentFlowData,
        PaymentsCancelPostCaptureData,
        PaymentsResponseData,
    > for Cryptopay<T>
    SourceVerification<VoidPC, PaymentFlowData, PaymentsCancelPostCaptureData, PaymentsResponseData>
    for Cryptopay<T>
    > connector_types::PaymentVoidV2 for Cryptopay<T>
    > connector_types::RefundSyncV2 for Cryptopay<T>
    > connector_types::RefundV2 for Cryptopay<T>
    > connector_types::PaymentCapture for Cryptopay<T>
    > connector_types::SetupMandateV2<T> for Cryptopay<T>
    > connector_types::AcceptDispute for Cryptopay<T>
    > connector_types::SubmitEvidenceV2 for Cryptopay<T>
    > connector_types::DisputeDefend for Cryptopay<T>
    > connector_types::PaymentOrderCreate for Cryptopay<T>
    > connector_types::ValidationTrait for Cryptopay<T>
    > connector_types::RepeatPaymentV2 for Cryptopay<T>
    > connector_types::PaymentTokenV2<T> for Cryptopay<T>
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentPreAuthenticateV2<T> for Cryptopay<T>
    connector_types::PaymentAuthenticateV2<T> for Cryptopay<T>
    connector_types::PaymentPostAuthenticateV2<T> for Cryptopay<T>
macros::create_amount_converter_wrapper!(connector_name: Cryptopay, amount_type: StringMajorUnit);
macros::create_all_prerequisites!(
    connector_name: Cryptopay,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: CryptopayPaymentsRequest,
            response_body: CryptopayPaymentsResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
            flow: PSync,
            response_body: CryptopayPaymentsSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        )
    ],
    amount_converters: [],
    member_functions: {
        pub fn build_headers<F, Req, Res>(
            &self,
            req: &RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError>
        where
            Self: ConnectorIntegrationV2<F, PaymentFlowData, Req, Res>,
        {
            let method = self.get_http_method();
            let payload = match method {
                Method::Get => String::default(),
                Method::Post | Method::Put | Method::Delete | Method::Patch => {
                    let body = self
                        .get_request_body(req)?
                        .map(|content| content.get_inner_value().peek().to_owned())
                        .unwrap_or_default();
                    let md5_payload = crypto::Md5
                        .generate_digest(body.as_bytes())
                        .change_context(errors::ConnectorError::RequestEncodingFailed)?;
                    encode(md5_payload)
                }
            };
            let api_method = method.to_string();
            let now = date_time::date_as_yyyymmddthhmmssmmmz()
                .change_context(errors::ConnectorError::RequestEncodingFailed)?;
            let date = format!("{}+00:00", now.split_at(now.len() - 5).0);
            let content_type = self.get_content_type().to_string();
            let api = (self.get_url(req)?).replace(self.connector_base_url_payments(req), "");
            let auth = cryptopay::CryptopayAuthType::try_from(&req.connector_auth_type)?;
            let sign_req: String = format!("{api_method}\n{payload}\n{content_type}\n{date}\n{api}");
            let authz = crypto::HmacSha1::sign_message(
                &crypto::HmacSha1,
                auth.api_secret.peek().as_bytes(),
                sign_req.as_bytes(),
            )
            .change_context(errors::ConnectorError::RequestEncodingFailed)
            .attach_printable("Failed to sign the message")?;
            let authz = BASE64_ENGINE.encode(authz);
            let auth_string: String = format!("HMAC {}:{}", auth.api_key.peek(), authz);
            let headers = vec![
                (
                    headers::AUTHORIZATION.to_string(),
                    auth_string.into_masked(),
                ),
                (headers::DATE.to_string(), date.into()),
                    headers::CONTENT_TYPE.to_string(),
                    self.get_content_type().to_string().into(),
            ];
            Ok(headers)
        }
        pub fn connector_base_url_payments<'a, F, Req, Res>(
            req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.cryptopay.base_url
);
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Cryptopay,
    curl_request: Json(CryptopayPaymentsRequest),
    curl_response: CryptopayResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req)
        fn get_url(
        ) -> CustomResult<String, errors::ConnectorError> {
            Ok(format!("{}/api/invoices", self.connector_base_url_payments(req)))
    curl_response: CryptopayPaymentResponse,
    flow_name: PSync,
    flow_request: PaymentsSyncData,
    http_method: Get,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            let custom_id = req.resource_common_data.connector_request_reference_id.clone();
            Ok(format!(
                "{}/api/invoices/custom_id/{custom_id}",
                self.connector_base_url_payments(req),
            ))
    connector_types::IncomingWebhook for Cryptopay<T>
    fn get_webhook_source_verification_signature(
        request: &RequestDetails,
        _connector_webhook_secret: &ConnectorWebhookSecrets,
    ) -> Result<Vec<u8>, error_stack::Report<domain_types::errors::ConnectorError>> {
        let base64_signature = request
            .headers
            .get("x-cryptopay-signature")
            .ok_or(errors::ConnectorError::WebhookSourceVerificationFailed)
            .attach_printable("Missing incoming webhook signature for Cryptopay")?;
        hex::decode(base64_signature)
            .change_context(errors::ConnectorError::WebhookSourceVerificationFailed)
    fn get_webhook_source_verification_message(
        _connector_webhook_secrets: &ConnectorWebhookSecrets,
        let message = std::str::from_utf8(&request.body)
            .attach_printable("Webhook source verification message parsing failed for Cryptopay")?;
        Ok(message.to_string().into_bytes())
    fn verify_webhook_source(
        request: RequestDetails,
        connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorAuthType>,
    ) -> Result<bool, error_stack::Report<domain_types::errors::ConnectorError>> {
        let algorithm = crypto::HmacSha256;
        let connector_webhook_secrets = match connector_webhook_secret {
            Some(secrets) => secrets,
            None => Err(domain_types::errors::ConnectorError::WebhookSourceVerificationFailed)?,
        };
        let signature =
            self.get_webhook_source_verification_signature(&request, &connector_webhook_secrets)?;
        let message =
            self.get_webhook_source_verification_message(&request, &connector_webhook_secrets)?;
        algorithm
            .verify_signature(&connector_webhook_secrets.secret, &signature, &message)
            .attach_printable("Webhook source verification failed for Cryptopay")
    fn get_event_type(
        _connector_webhook_secret: Option<ConnectorWebhookSecrets>,
    ) -> Result<EventType, error_stack::Report<domain_types::errors::ConnectorError>> {
        let notif: cryptopay::CryptopayWebhookDetails = request
            .body
            .parse_struct("CryptopayWebhookDetails")
            .change_context(errors::ConnectorError::WebhookEventTypeNotFound)?;
        match notif.data.status {
            cryptopay::CryptopayPaymentStatus::Completed => Ok(EventType::PaymentIntentSuccess),
            cryptopay::CryptopayPaymentStatus::Unresolved => Ok(EventType::PaymentActionRequired),
            cryptopay::CryptopayPaymentStatus::Cancelled => Ok(EventType::PaymentIntentFailure),
            _ => Ok(EventType::IncomingWebhookEventUnspecified),
    fn process_payment_webhook(
    ) -> Result<WebhookDetailsResponse, error_stack::Report<domain_types::errors::ConnectorError>>
    {
        let response = WebhookDetailsResponse::try_from(notif)
            .change_context(errors::ConnectorError::WebhookBodyDecodingFailed);
        response.map(|mut response| {
            response.raw_connector_response =
                Some(String::from_utf8_lossy(&request.body).to_string());
            response
    ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
    ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
    ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
    ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
        SetupMandate,
        SetupMandateRequestData<T>,
    ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
    ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
        CreateOrder,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
        CreateSessionToken,
        SessionTokenRequestData,
        SessionTokenResponseData,
        CreateAccessToken,
        AccessTokenRequestData,
        AccessTokenResponseData,
        PaymentMethodToken,
        PaymentMethodTokenizationData<T>,
        PaymentMethodTokenResponse,
        PreAuthenticate,
        PaymentsPreAuthenticateData<T>,
        Authenticate,
        PaymentsAuthenticateData<T>,
        PostAuthenticate,
        PaymentsPostAuthenticateData<T>,
        CreateConnectorCustomer,
        ConnectorCustomerData,
        ConnectorCustomerResponse,
// SourceVerification implementations for all flows
    interfaces::verification::SourceVerification<
        Authorize,
        PaymentsAuthorizeData<T>,
        PSync,
        PaymentsSyncData,
        Capture,
        PaymentsCaptureData,
        Void,
        PaymentVoidData,
        Refund,
        RefundFlowData,
        RefundsData,
        RefundsResponseData,
        RSync,
        RefundSyncData,
        Accept,
        DisputeFlowData,
        AcceptDisputeData,
        DisputeResponseData,
        SubmitEvidence,
        SubmitEvidenceData,
        DefendDispute,
        DisputeDefendData,
        RepeatPayment,
        RepeatPaymentData,
    ConnectorIntegrationV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>
