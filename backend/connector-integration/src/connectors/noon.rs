use std::fmt::Debug;
use common_utils::Maskable;

use base64::Engine;
use common_enums::AttemptStatus;
use common_utils::{
    crypto::{self, VerifySignature},
    errors::CustomResult,
    ext_traits::ByteSliceExt,
    types::StringMajorUnit,
};
use domain_types::{
    connector_flow::{
        Accept, Authenticate, Authorize, Capture, CreateAccessToken, CreateConnectorCustomer,
        CreateOrder, CreateSessionToken, DefendDispute, PSync, PaymentMethodToken,
        PostAuthenticate, PreAuthenticate, RSync, Refund, RepeatPayment, SetupMandate,
        SubmitEvidence, Void, VoidPC,
    },
    connector_types::{
        AcceptDisputeData, AccessTokenRequestData, AccessTokenResponseData, ConnectorCustomerData,
        ConnectorCustomerResponse, ConnectorSpecifications, ConnectorWebhookSecrets,
        DisputeDefendData, DisputeFlowData, DisputeResponseData, EventType, PaymentCreateOrderData,
        PaymentCreateOrderResponse, PaymentFlowData, PaymentMethodTokenResponse,
        PaymentMethodTokenizationData, PaymentVoidData, PaymentsAuthenticateData,
        PaymentsAuthorizeData, PaymentsCancelPostCaptureData, PaymentsCaptureData,
        PaymentsPostAuthenticateData, PaymentsPreAuthenticateData, PaymentsResponseData,
        PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData,
        RepeatPaymentData, RequestDetails, SessionTokenRequestData, SessionTokenResponseData,
        SetupMandateRequestData, SubmitEvidenceData,
    },
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
};
// use crate::masking::{Mask, Maskable, PeekInterface};
use interfaces::{
    api::ConnectorCommon, connector_integration_v2::ConnectorIntegrationV2, connector_types,
    events::connector_api_logs::ConnectorEvent,
};
use serde::Serialize;
pub mod transformers;
use error_stack::ResultExt;
pub const BASE64_ENGINE: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
use transformers::{
    self as noon, NoonAuthType, NoonErrorResponse, NoonPaymentsActionRequest,
    NoonPaymentsActionRequest as NoonPaymentsRefundActionRequest, NoonPaymentsCancelRequest,
    NoonPaymentsRequest, NoonPaymentsResponse, NoonPaymentsResponse as NoonPaymentsSyncResponse,
    NoonPaymentsResponse as NoonPaymentsCaptureResponse,
    NoonPaymentsResponse as NoonPaymentsVoidResponse, RefundResponse, RefundSyncResponse,
    SetupMandateRequest, SetupMandateResponse,
use super::macros;
use crate::{types::ResponseRouterData, with_error_response_body};
// Local headers module
mod headers {
    pub const CONTENT_TYPE: &str = "Content-Type";
    pub const AUTHORIZATION: &str = "Authorization";
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ConnectorServiceTrait<T> for Noon<T>
{
    connector_types::PaymentAuthorizeV2<T> for Noon<T>
    connector_types::PaymentSyncV2 for Noon<T>
    connector_types::PaymentVoidV2 for Noon<T>
    connector_types::RefundSyncV2 for Noon<T>
    connector_types::RefundV2 for Noon<T>
    connector_types::PaymentCapture for Noon<T>
    connector_types::ValidationTrait for Noon<T>
    connector_types::PaymentOrderCreate for Noon<T>
    connector_types::SetupMandateV2<T> for Noon<T>
    connector_types::RepeatPaymentV2 for Noon<T>
    connector_types::PaymentVoidPostCaptureV2 for Noon<T>
    ConnectorIntegrationV2<
        VoidPC,
        PaymentFlowData,
        PaymentsCancelPostCaptureData,
        PaymentsResponseData,
    > for Noon<T>
    connector_types::AcceptDispute for Noon<T>
    connector_types::SubmitEvidenceV2 for Noon<T>
    connector_types::DisputeDefend for Noon<T>
    connector_types::IncomingWebhook for Noon<T>
    fn get_webhook_source_verification_signature(
        &self,
        request: &RequestDetails,
        _connector_webhook_secret: &ConnectorWebhookSecrets,
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        let webhook_body: noon::NoonWebhookSignature = request
            .body
            .parse_struct("NoonWebhookSignature")
            .change_context(errors::ConnectorError::WebhookSignatureNotFound)
            .attach_printable("Missing incoming webhook signature for noon")?;
        let signature = webhook_body.signature;
        BASE64_ENGINE
            .decode(signature)
            .attach_printable("Missing incoming webhook signature for noon")
    }
    fn get_webhook_source_verification_message(
        _connector_webhook_secrets: &ConnectorWebhookSecrets,
        let webhook_body: noon::NoonWebhookBody = request
            .parse_struct("NoonWebhookBody")
        let message = format!(
            "{},{},{},{},{}",
            webhook_body.order_id,
            webhook_body.order_status,
            webhook_body.event_id,
            webhook_body.event_type,
            webhook_body.time_stamp,
        );
        Ok(message.into_bytes())
    fn get_event_type(
        request: RequestDetails,
        _connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorAuthType>,
    ) -> Result<EventType, error_stack::Report<domain_types::errors::ConnectorError>> {
        let details: noon::NoonWebhookEvent = request
            .parse_struct("NoonWebhookEvent")
            .change_context(errors::ConnectorError::WebhookEventTypeNotFound)
            .attach_printable("Failed to parse webhook event type from Noon webhook body")?;
        Ok(match &details.event_type {
            noon::NoonWebhookEventTypes::Sale | noon::NoonWebhookEventTypes::Capture => {
                match &details.order_status {
                    noon::NoonPaymentStatus::Captured => EventType::PaymentIntentSuccess,
                    _ => Err(errors::ConnectorError::WebhookEventTypeNotFound)?,
                }
            }
            noon::NoonWebhookEventTypes::Fail => EventType::PaymentIntentFailure,
            noon::NoonWebhookEventTypes::Authorize
            | noon::NoonWebhookEventTypes::Authenticate
            | noon::NoonWebhookEventTypes::Refund
            | noon::NoonWebhookEventTypes::Unknown => EventType::IncomingWebhookEventUnspecified,
        })
    fn verify_webhook_source(
        connector_webhook_secret: Option<ConnectorWebhookSecrets>,
    ) -> Result<bool, error_stack::Report<domain_types::errors::ConnectorError>> {
        let algorithm = crypto::HmacSha512;
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
            .change_context(errors::ConnectorError::WebhookSourceVerificationFailed)
            .attach_printable("Noon webhook signature verification failed")
    fn process_payment_webhook(
        _request: RequestDetails,
    ) -> Result<
        domain_types::connector_types::WebhookDetailsResponse,
        error_stack::Report<domain_types::errors::ConnectorError>,
    > {
        Ok(domain_types::connector_types::WebhookDetailsResponse {
            resource_id: None,
            status: common_enums::AttemptStatus::Unknown,
            connector_response_reference_id: None,
            error_code: None,
            error_message: None,
            raw_connector_response: None,
            status_code: 200,
            response_headers: None,
            mandate_reference: None,
            amount_captured: None,
            minor_amount_captured: None,
            error_reason: None,
            network_txn_id: None,
            transformation_status: common_enums::WebhookTransformationStatus::Incomplete,
    fn get_webhook_resource_object(
    ) -> CustomResult<Box<dyn common_utils::ErasedMaskSerialize>, errors::ConnectorError>
    {
        let resource: noon::NoonWebhookObject = request
            .parse_struct("NoonWebhookObject")
            .change_context(errors::ConnectorError::WebhookResourceObjectNotFound)
            .attach_printable("Failed to parse webhook resource object from Noon webhook body")?;
        Ok(Box::new(noon::NoonPaymentsResponse::from(resource)))
    connector_types::PaymentSessionToken for Noon<T>
    connector_types::PaymentAccessToken for Noon<T>
    connector_types::CreateConnectorCustomer for Noon<T>
    connector_types::PaymentTokenV2<T> for Noon<T>
    connector_types::PaymentPreAuthenticateV2<T> for Noon<T>
    connector_types::PaymentAuthenticateV2<T> for Noon<T>
    connector_types::PaymentPostAuthenticateV2<T> for Noon<T>
macros::create_all_prerequisites!(
    connector_name: Noon,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: NoonPaymentsRequest<T>,
            response_body: NoonPaymentsResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
            flow: PSync,
            response_body: NoonPaymentsSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            flow: Capture,
            request_body: NoonPaymentsActionRequest,
            response_body: NoonPaymentsCaptureResponse,
            router_data: RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            flow: Void,
            request_body: NoonPaymentsCancelRequest,
            response_body: NoonPaymentsVoidResponse,
            router_data: RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            flow: Refund,
            request_body: NoonPaymentsRefundActionRequest,
            response_body: RefundResponse,
            router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            flow: SetupMandate,
            request_body: SetupMandateRequest<T>,
            response_body: SetupMandateResponse,
            router_data: RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>,
            flow: RSync,
            response_body: RefundSyncResponse,
            router_data: RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        )
    ],
    amount_converters: [
        amount_converter: StringMajorUnit
    member_functions: {
        pub fn build_headers<F, FCD, Req, Res>(
            &self,
            req: &RouterDataV2<F, FCD, Req, Res>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError>
        where
            Self: ConnectorIntegrationV2<F, FCD, Req, Res>,
        {
        let mut header = vec![(
            headers::CONTENT_TYPE.to_string(),
            self.get_content_type().to_string().into(),
        )];
        let mut auth_header = self.get_auth_header(&req.connector_auth_type)?;
        header.append(&mut auth_header);
        Ok(header)
        }
        pub fn connector_base_url_payments<'a, F, Req, Res>(
            req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.noon.base_url
        pub fn connector_base_url_refunds<'a, F, Req, Res>(
            req: &'a RouterDataV2<F, RefundFlowData, Req, Res>,
        pub fn get_auth_header(
            auth_type: &ConnectorAuthType,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            let auth = NoonAuthType::try_from(auth_type)?;
            let encoded_api_key = auth
                .business_identifier
                .zip(auth.application_identifier)
                .zip(auth.api_key)
                .map(|((business_identifier, application_identifier), api_key)| {
                    BASE64_ENGINE.encode(format!(
                        "{business_identifier}.{application_identifier}:{api_key}",
                    ))
                });
            Ok(vec![(
                headers::AUTHORIZATION.to_string(),
                format!("Key {}", encoded_api_key.peek()).into_masked(),
            )])
);
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> ConnectorCommon
    for Noon<T>
    fn id(&self) -> &'static str {
        "noon"
    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.noon.base_url.as_ref()
    fn build_error_response(
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: NoonErrorResponse = res
            .response
            .parse_struct("NoonErrorResponse")
            .map_err(|_| errors::ConnectorError::ResponseDeserializationFailed)?;
        with_error_response_body!(event_builder, response);
        // Adding in case of timeouts, if psync gives 4xx with this code, fail the payment
        let attempt_status = if response.result_code == 19001 {
            Some(AttemptStatus::Failure)
        } else {
            None
        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response.result_code.to_string(),
            message: response.class_description.clone(),
            reason: Some(response.message.clone()),
            attempt_status,
            connector_transaction_id: None,
            network_advice_code: None,
            network_decline_code: None,
            network_error_message: None,
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Noon,
    curl_request: Json(NoonPaymentsRequest),
    curl_response: NoonPaymentsResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            self.build_headers(req)
        fn get_url(
        ) -> CustomResult<String, errors::ConnectorError> {
            Ok(format!("{}payment/v1/order", self.connector_base_url_payments(req)))
    curl_request: Json(SetupMandateRequest<T>),
    curl_response: SetupMandateResponse,
    flow_name: SetupMandate,
    flow_request: SetupMandateRequestData<T>,
            req: &RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>,
    curl_response: NoonPaymentsSyncResponse,
    flow_name: PSync,
    flow_request: PaymentsSyncData,
    http_method: Get,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        Ok(format!(
            "{}payment/v1/order/getbyreference/{}",
            self.connector_base_url_payments(req),
            req.resource_common_data.connector_request_reference_id
        ))
    curl_request: Json(NoonPaymentsActionRequest),
    curl_response: NoonPaymentsCaptureResponse,
    flow_name: Capture,
    flow_request: PaymentsCaptureData,
            req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
// Add implementation for Void
    curl_request: Json(NoonPaymentsCancelRequest),
    curl_response: NoonPaymentsVoidResponse,
    flow_name: Void,
    flow_request: PaymentVoidData,
            req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
             Ok(format!("{}payment/v1/order", self.connector_base_url_payments(req),))
// Add implementation for Refund
    curl_request: Json(NoonPaymentsRefundActionRequest),
    curl_response: RefundResponse,
    flow_name: Refund,
    resource_common_data: RefundFlowData,
    flow_request: RefundsData,
    flow_response: RefundsResponseData,
            req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            Ok(format!("{}payment/v1/order", self.connector_base_url_refunds(req)))
// Implement RSync to fix the RefundSyncV2 trait requirement
    curl_response: RefundSyncResponse,
    flow_name: RSync,
    flow_request: RefundSyncData,
            req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            req: &RouterDataV2<domain_types::connector_flow::RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        let request_ref_id = req.request.connector_refund_id.clone();
        // Validate the refund ID to prevent injection attacks
        if request_ref_id.is_empty() {
           return Err(errors::ConnectorError::MissingRequiredField {
              field_name: "request_ref_id",
           }.into());
            self.connector_base_url_refunds(req),
            request_ref_id,
// Implementation for empty stubs - these will need to be properly implemented later
        CreateOrder,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
    ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
        CreateSessionToken,
        SessionTokenRequestData,
        SessionTokenResponseData,
        CreateAccessToken,
        AccessTokenRequestData,
        AccessTokenResponseData,
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
        SetupMandate,
        SetupMandateRequestData<T>,
        Accept,
        DisputeFlowData,
        AcceptDisputeData,
        DisputeResponseData,
        SubmitEvidence,
        SubmitEvidenceData,
        DefendDispute,
        DisputeDefendData,
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> ConnectorSpecifications
// We already have an implementation for ValidationTrait above
        RepeatPayment,
        RepeatPaymentData,
    ConnectorIntegrationV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
        PaymentMethodToken,
        PaymentMethodTokenizationData<T>,
        PaymentMethodTokenResponse,
// ConnectorIntegrationV2 implementations for authentication flows
        PreAuthenticate,
        PaymentsPreAuthenticateData<T>,
        Authenticate,
        PaymentsAuthenticateData<T>,
        PostAuthenticate,
        PaymentsPostAuthenticateData<T>,
// SourceVerification implementations for authentication flows
