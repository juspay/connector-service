#[cfg(test)]
use common_utils::Maskable;
mod test;
pub mod transformers;

use std::{
    fmt::Debug,
    marker::{Send, Sync},
    sync::LazyLock,
};
use common_enums::{enums, PaymentMethodType};
use common_utils::{
    consts,
    errors::CustomResult,
    ext_traits::{ByteSliceExt, BytesExt},
    types::FloatMajorUnit,
use domain_types::{
    connector_flow::{
        Accept, Authenticate, Authorize, Capture, CreateAccessToken, CreateConnectorCustomer,
        CreateOrder, CreateSessionToken, DefendDispute, PSync, PaymentMethodToken,
        PostAuthenticate, PreAuthenticate, RSync, Refund, RepeatPayment, SetupMandate,
        SubmitEvidence, Void,
    },
    connector_types::{
        AcceptDisputeData, AccessTokenRequestData, AccessTokenResponseData, ConnectorCustomerData,
        ConnectorCustomerResponse, ConnectorSpecifications, ConnectorWebhookSecrets,
        DisputeDefendData, DisputeFlowData, DisputeResponseData, EventType, PaymentCreateOrderData,
        PaymentCreateOrderResponse, PaymentFlowData, PaymentMethodTokenResponse,
        PaymentMethodTokenizationData, PaymentVoidData, PaymentsAuthenticateData,
        PaymentsAuthorizeData, PaymentsCaptureData, PaymentsPostAuthenticateData,
        PaymentsPreAuthenticateData, PaymentsResponseData, PaymentsSyncData, RefundFlowData,
        RefundSyncData, RefundsData, RefundsResponseData, RepeatPaymentData, RequestDetails,
        ResponseId, SessionTokenRequestData, SessionTokenResponseData, SetupMandateRequestData,
        SubmitEvidenceData, SupportedPaymentMethodsExt, WebhookDetailsResponse,
    errors::{self, ConnectorError},
    payment_method_data::{DefaultPCIHolder, PaymentMethodData, PaymentMethodDataTypes},
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::{
        self, ConnectorInfo, Connectors, FeatureStatus, PaymentMethodDetails,
        SupportedPaymentMethods,
use error_stack::ResultExt;
// use crate::masking::{ExposeInterface, Mask, Maskable};
use interfaces::{
    api::ConnectorCommon,
    connector_integration_v2::ConnectorIntegrationV2,
    connector_types::{self, ConnectorValidation},
    events::connector_api_logs::ConnectorEvent,
use serde::Serialize;
use transformers::*;
use super::macros;
use crate::{types::ResponseRouterData, with_error_response_body};
pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const AUTHORIZATION: &str = "Authorization";
}
const BLUECODE_API_VERSION: &str = "v1";
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::IncomingWebhook for Bluecode<T>
{
    fn verify_webhook_source(
        &self,
        request: RequestDetails,
        connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorAuthType>,
    ) -> CustomResult<bool, errors::ConnectorError> {
        let connector_webhook_secrets = match connector_webhook_secret {
            Some(secrets) => secrets.secret,
            None => return Ok(false),
        };
        let security_header = request
            .headers
            .get("x-eorder-webhook-signature")
            .ok_or(domain_types::errors::ConnectorError::WebhookSignatureNotFound)?
            .clone();
        let signature = hex::decode(security_header)
            .change_context(errors::ConnectorError::WebhookSignatureNotFound)?;
        let parsed: serde_json::Value = serde_json::from_slice(&request.body)
            .change_context(errors::ConnectorError::ParsingFailed)?;
        let sorted_payload = transformers::sort_and_minify_json(&parsed)?;
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA512, &connector_webhook_secrets);
        let verify = ring::hmac::verify(&key, sorted_payload.as_bytes(), &signature)
            .map(|_| true)
            .change_context(errors::ConnectorError::WebhookSourceVerificationFailed)?;
        Ok(verify)
    }
    fn process_payment_webhook(
        _connector_webhook_secret: Option<ConnectorWebhookSecrets>,
    ) -> Result<WebhookDetailsResponse, error_stack::Report<ConnectorError>> {
        let request_body_copy = request.body.clone();
        let webhook_body: transformers::BluecodeWebhookResponse = request
            .body
            .parse_struct("BluecodeWebhookResponse")
            .change_context(ConnectorError::WebhookResourceObjectNotFound)
            .attach_printable_lazy(|| "Failed to parse Bluecode payment webhook body structure")?;
        let transaction_id = webhook_body.order_id.clone();
        let status: common_enums::AttemptStatus = webhook_body.status.into();
        Ok(WebhookDetailsResponse {
            resource_id: Some(ResponseId::ConnectorTransactionId(transaction_id.clone())),
            status,
            status_code: 200,
            connector_response_reference_id: Some(transaction_id),
            error_code: None,
            error_message: None,
            raw_connector_response: Some(String::from_utf8_lossy(&request_body_copy).to_string()),
            response_headers: None,
            mandate_reference: None,
            minor_amount_captured: None,
            amount_captured: None,
            error_reason: None,
            network_txn_id: None,
            transformation_status: common_enums::WebhookTransformationStatus::Complete,
        })
    fn get_event_type(
        _request: RequestDetails,
    ) -> Result<EventType, error_stack::Report<ConnectorError>> {
        Ok(EventType::Payment)
    connector_types::ConnectorServiceTrait<T> for Bluecode<T>
    connector_types::PaymentTokenV2<T> for Bluecode<T>
    connector_types::PaymentAuthorizeV2<T> for Bluecode<T>
    connector_types::PaymentSessionToken for Bluecode<T>
    connector_types::PaymentSyncV2 for Bluecode<T>
    connector_types::PaymentVoidV2 for Bluecode<T>
    connector_types::PaymentVoidPostCaptureV2 for Bluecode<T>
    connector_types::RefundSyncV2 for Bluecode<T>
    connector_types::RefundV2 for Bluecode<T>
    connector_types::PaymentCapture for Bluecode<T>
    connector_types::SetupMandateV2<T> for Bluecode<T>
    connector_types::AcceptDispute for Bluecode<T>
    connector_types::SubmitEvidenceV2 for Bluecode<T>
    connector_types::DisputeDefend for Bluecode<T>
    connector_types::RepeatPaymentV2 for Bluecode<T>
    connector_types::ValidationTrait for Bluecode<T>
    connector_types::PaymentOrderCreate for Bluecode<T>
    connector_types::PaymentPreAuthenticateV2<T> for Bluecode<T>
    connector_types::PaymentAuthenticateV2<T> for Bluecode<T>
    connector_types::PaymentPostAuthenticateV2<T> for Bluecode<T>
    ConnectorIntegrationV2<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for Bluecode<T>
    ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
    for Bluecode<T>
    ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
    ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
        CreateSessionToken,
        SessionTokenRequestData,
        SessionTokenResponseData,
    ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
    ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
    ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
        SetupMandate,
        SetupMandateRequestData<T>,
        PaymentsResponseData,
    ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
        PreAuthenticate,
        PaymentsPreAuthenticateData<T>,
        Authenticate,
        PaymentsAuthenticateData<T>,
        PostAuthenticate,
        PaymentsPostAuthenticateData<T>,
        domain_types::connector_flow::VoidPC,
        domain_types::connector_types::PaymentsCancelPostCaptureData,
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
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
        CreateAccessToken,
        AccessTokenRequestData,
        AccessTokenResponseData,
        CreateConnectorCustomer,
        ConnectorCustomerData,
        ConnectorCustomerResponse,
        DefendDispute,
        DisputeDefendData,
        RepeatPayment,
        RepeatPaymentData,
    ConnectorIntegrationV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>
        PaymentMethodToken,
        PaymentMethodTokenizationData<T>,
        PaymentMethodTokenResponse,
    connector_types::PaymentAccessToken for Bluecode<T>
    connector_types::CreateConnectorCustomer for Bluecode<T>
macros::create_all_prerequisites!(
    connector_name: Bluecode,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: BluecodePaymentsRequest,
            response_body: BluecodePaymentsResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
            flow: PSync,
            response_body: BluecodeSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        )
    ],
    amount_converters: [
        amount_converter: FloatMajorUnit
    member_functions: {
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
        pub fn connector_base_url_payments<'a, F, Req, Res>(
            req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> &'a str {
            req.resource_common_data.connectors.bluecode.base_url.as_ref()
);
// present
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> ConnectorCommon
    fn id(&self) -> &'static str {
        "bluecode"
    fn get_currency_unit(&self) -> common_enums::CurrencyUnit {
        common_enums::CurrencyUnit::Base
    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.bluecode.base_url.as_ref()
    fn get_auth_header(
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth = BluecodeAuthType::try_from(auth_type)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        Ok(vec![(
            headers::AUTHORIZATION.to_string(),
            format!("token {}", auth.api_key.expose()).into_masked(),
        )])
    fn build_error_response(
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: BluecodeErrorResponse = res
            .response
            .parse_struct("BluecodeErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        with_error_response_body!(event_builder, response);
        Ok(ErrorResponse {
            status_code: res.status_code,
            code: consts::NO_ERROR_CODE.to_string(),
            message: response.message.clone(),
            reason: Some(response.message),
            attempt_status: None,
            connector_transaction_id: None,
            network_advice_code: None,
            network_decline_code: None,
            network_error_message: None,
impl ConnectorValidation for Bluecode<DefaultPCIHolder> {
    fn validate_mandate_payment(
        _pm_type: Option<PaymentMethodType>,
        pm_data: PaymentMethodData<DefaultPCIHolder>,
    ) -> CustomResult<(), errors::ConnectorError> {
        match pm_data {
            PaymentMethodData::Card(_) => Err(errors::ConnectorError::NotImplemented(
                "validate_mandate_payment does not support cards".to_string(),
            )
            .into()),
            _ => Ok(()),
    fn validate_psync_reference_id(
        _data: &PaymentsSyncData,
        _is_three_ds: bool,
        _status: enums::AttemptStatus,
        _connector_meta_data: Option<common_utils::pii::SecretSerdeValue>,
        Ok(())
    fn is_webhook_source_verification_mandatory(&self) -> bool {
        true
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Bluecode,
    curl_request: Json(BluecodePaymentsRequest),
    curl_response: BluecodePaymentsResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize ],
    other_functions: {
        fn get_headers(
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req)
        fn get_url(
        ) -> CustomResult<String, errors::ConnectorError> {
            Ok(format!(
                "{}api/{}/order/payin/start",
                self.connector_base_url_payments(req),
                BLUECODE_API_VERSION
            ))
    curl_response: BluecodeSyncResponse,
    flow_name: PSync,
    flow_request: PaymentsSyncData,
    http_method: Get,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            let connector_transaction_id = req
                .request
                .connector_transaction_id
                .get_connector_transaction_id()
                .change_context(errors::ConnectorError::MissingConnectorTransactionID)?;
                "{}api/{}/order/{}/status",
                BLUECODE_API_VERSION,
                connector_transaction_id
static BLUECODE_SUPPORTED_PAYMENT_METHODS: LazyLock<SupportedPaymentMethods> =
    LazyLock::new(|| {
        let supported_capture_methods = vec![enums::CaptureMethod::Automatic];
        let mut santander_supported_payment_methods = SupportedPaymentMethods::new();
        santander_supported_payment_methods.add(
            enums::PaymentMethod::Wallet,
            enums::PaymentMethodType::Bluecode,
            PaymentMethodDetails {
                mandates: FeatureStatus::NotSupported,
                refunds: FeatureStatus::NotSupported,
                supported_capture_methods,
                specific_features: None,
            },
        );
        santander_supported_payment_methods
    });
static BLUECODE_CONNECTOR_INFO: ConnectorInfo = ConnectorInfo {
    display_name: "Bluecode",
    description: "Bluecode is building a global payment network that combines Alipay+, Discover and EMPSA and enables seamless payments in 75 countries. With over 160 million acceptance points, payments are processed according to the highest European security and data protection standards to make Europe less dependent on international players.",
    connector_type: types::PaymentConnectorCategory::AlternativePaymentMethod,
static BLUECODE_SUPPORTED_WEBHOOK_FLOWS: [enums::EventClass; 1] = [enums::EventClass::Payments];
impl ConnectorSpecifications for Bluecode<DefaultPCIHolder> {
    fn get_connector_about(&self) -> Option<&'static ConnectorInfo> {
        Some(&BLUECODE_CONNECTOR_INFO)
    fn get_supported_payment_methods(&self) -> Option<&'static SupportedPaymentMethods> {
        Some(&*BLUECODE_SUPPORTED_PAYMENT_METHODS)
    fn get_supported_webhook_flows(&self) -> Option<&'static [enums::EventClass]> {
        Some(&BLUECODE_SUPPORTED_WEBHOOK_FLOWS)
