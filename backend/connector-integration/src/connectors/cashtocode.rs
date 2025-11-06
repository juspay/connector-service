pub mod transformers;
use common_utils::{Secret, Maskable};

use std::fmt::Debug;
use base64::Engine;
use common_enums::CurrencyUnit;
use common_utils::{errors::CustomResult, ext_traits::ByteSliceExt, types::FloatMajorUnit,
    Maskable,
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
        ConnectorCustomerResponse, ConnectorWebhookSecrets, DisputeDefendData, DisputeFlowData,
        DisputeResponseData, PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData,
        PaymentMethodTokenResponse, PaymentMethodTokenizationData, PaymentVoidData,
        PaymentsAuthenticateData, PaymentsAuthorizeData, PaymentsCancelPostCaptureData,
        PaymentsCaptureData, PaymentsPostAuthenticateData, PaymentsPreAuthenticateData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData,
        RefundsResponseData, RepeatPaymentData, RequestDetails, SessionTokenRequestData,
        SessionTokenResponseData, SetupMandateRequestData, SubmitEvidenceData,
    },
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
};
use error_stack::ResultExt;
// use crate::masking::{Mask, Maskable, PeekInterface, Secret};
use interfaces::{
    api::ConnectorCommon,
    connector_integration_v2::ConnectorIntegrationV2,
    connector_types,
    events::connector_api_logs::ConnectorEvent,
    verification::{ConnectorSourceVerificationSecrets, SourceVerification},
};
use serde::Serialize;
use transformers::{self as cashtocode, CashtocodePaymentsRequest, CashtocodePaymentsResponse};
use super::macros;
use crate::{types::ResponseRouterData, with_error_response_body};
pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const AUTHORIZATION: &str = "Authorization";
}
// Trait implementations with generic type parameters
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::ConnectorServiceTrait<T> for Cashtocode<T>
{
    > connector_types::PaymentAuthorizeV2<T> for Cashtocode<T>
    > connector_types::PaymentSyncV2 for Cashtocode<T>
    > connector_types::PaymentSessionToken for Cashtocode<T>
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAccessToken for Cashtocode<T>
    > connector_types::CreateConnectorCustomer for Cashtocode<T>
    > connector_types::PaymentVoidV2 for Cashtocode<T>
    > connector_types::RefundSyncV2 for Cashtocode<T>
    > connector_types::RefundV2 for Cashtocode<T>
    > connector_types::PaymentCapture for Cashtocode<T>
    > connector_types::SetupMandateV2<T> for Cashtocode<T>
    > connector_types::AcceptDispute for Cashtocode<T>
    > connector_types::SubmitEvidenceV2 for Cashtocode<T>
    > connector_types::DisputeDefend for Cashtocode<T>
    > connector_types::IncomingWebhook for Cashtocode<T>
    fn verify_webhook_source(
        &self,
        request: RequestDetails,
        connector_webhook_secrets: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorAuthType>,
    ) -> Result<bool, error_stack::Report<domain_types::errors::ConnectorError>> {
        let webhook_secret = match connector_webhook_secrets.clone() {
            Some(secrets) => secrets,
            None => return Ok(false),
        };
        let base64_signature = request
            .headers
            .get("authorization")
            .ok_or(errors::ConnectorError::WebhookSignatureNotFound)?;
        let signature = base64_signature.as_bytes();
        let secret_auth = String::from_utf8(webhook_secret.secret.to_vec())
            .change_context(errors::ConnectorError::WebhookSourceVerificationFailed)
            .attach_printable("Could not convert secret to UTF-8")?;
        let signature_auth = String::from_utf8(signature.to_vec())
        Ok(signature_auth == secret_auth)
    }
    fn get_event_type(
        _request: RequestDetails,
        _connector_webhook_secret: Option<ConnectorWebhookSecrets>,
    ) -> Result<
        domain_types::connector_types::EventType,
        error_stack::Report<domain_types::errors::ConnectorError>,
    > {
        Ok(domain_types::connector_types::EventType::PaymentIntentSuccess)
    fn process_payment_webhook(
        domain_types::connector_types::WebhookDetailsResponse,
        let webhook: transformers::CashtocodePaymentsSyncResponse = request
            .body
            .parse_struct("CashtocodePaymentsSyncResponse")
            .change_context(errors::ConnectorError::WebhookResourceObjectNotFound)?;
        Ok(domain_types::connector_types::WebhookDetailsResponse {
            resource_id: Some(
                domain_types::connector_types::ResponseId::ConnectorTransactionId(
                    webhook.transaction_id.clone(),
                ),
            ),
            status: common_enums::AttemptStatus::Charged,
            status_code: 200,
            mandate_reference: None,
            connector_response_reference_id: None,
            error_code: None,
            error_message: None,
            raw_connector_response: Some(String::from_utf8_lossy(&request.body).to_string()),
            response_headers: None,
            minor_amount_captured: None,
            amount_captured: None,
            error_reason: None,
            network_txn_id: None,
            transformation_status: common_enums::WebhookTransformationStatus::Complete,
        })
    > connector_types::PaymentOrderCreate for Cashtocode<T>
    > connector_types::ValidationTrait for Cashtocode<T>
    > connector_types::RepeatPaymentV2 for Cashtocode<T>
    > connector_types::PaymentTokenV2<T> for Cashtocode<T>
// Authentication trait implementations
    > connector_types::PaymentPreAuthenticateV2<T> for Cashtocode<T>
    > connector_types::PaymentAuthenticateV2<T> for Cashtocode<T>
    > connector_types::PaymentPostAuthenticateV2<T> for Cashtocode<T>
    > connector_types::PaymentVoidPostCaptureV2 for Cashtocode<T>
    >
    ConnectorIntegrationV2<
        VoidPC,
        PaymentFlowData,
        PaymentsCancelPostCaptureData,
        PaymentsResponseData,
    > for Cashtocode<T>
macros::create_all_prerequisites!(
    connector_name: Cashtocode,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: CashtocodePaymentsRequest,
            response_body: CashtocodePaymentsResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        )
    ],
    amount_converters: [
        amount_converter: FloatMajorUnit
    member_functions: {
        pub fn build_headers<F, FCD, Req, Res>(
            &self,
            _req: &RouterDataV2<F, FCD, Req, Res>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError>
        where
            Self: ConnectorIntegrationV2<F, FCD, Req, Res>,
        {
            Ok(vec![(
                headers::CONTENT_TYPE.to_string(),
                self.common_get_content_type().to_string().into(),
            )])
        }
        pub fn connector_base_url_payments<'a, F, Req, Res>(
            req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.cashtocode.base_url
        pub fn connector_base_url_refunds<'a, F, Req, Res>(
            req: &'a RouterDataV2<F, RefundFlowData, Req, Res>,
);
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Cashtocode,
    curl_request: Json(CashtocodePaymentsRequest),
    curl_response: CashtocodePaymentsResponse,
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
            let mut header = vec![(
            )];
            let auth_type = transformers::CashtocodeAuth::try_from((
                &req.connector_auth_type,
                &req.request.currency,
            ))?;
            let mut api_key = get_b64_auth_cashtocode(req.request.payment_method_type, &auth_type)?;
            header.append(&mut api_key);
            Ok(header)
        fn get_url(
        ) -> CustomResult<String, errors::ConnectorError> {
            Ok(format!("{}/merchant/paytokens", self.connector_base_url_payments(req)))
    > ConnectorCommon for Cashtocode<T>
    fn id(&self) -> &'static str {
        "cashtocode"
    fn get_currency_unit(&self) -> CurrencyUnit {
        CurrencyUnit::Base
    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.cashtocode.base_url.as_ref()
    fn get_auth_header(
        _auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        // Cashtocode uses custom auth in get_headers
        Ok(vec![])
    fn build_error_response(
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: cashtocode::CashtocodeErrorResponse = res
            .response
            .parse_struct("CashtocodeErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        with_error_response_body!(event_builder, response);
        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response.error.to_string(),
            message: response.error_description.clone(),
            reason: Some(response.error_description),
            attempt_status: None,
            connector_transaction_id: None,
            network_advice_code: None,
            network_decline_code: None,
            network_error_message: None,
// Stub implementations for unsupported flows
    > ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
    for Cashtocode<T>
    > ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    > ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
    > ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
    > ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
// Authentication flow implementations
        PreAuthenticate,
        PaymentsPreAuthenticateData<T>,
        Authenticate,
        PaymentsAuthenticateData<T>,
        PostAuthenticate,
        PaymentsPostAuthenticateData<T>,
//marker traits
// Duplicate create_all_prerequisites! call removed - already defined above
// Duplicate macro_connector_implementation! for Authorize flow removed - already defined above
        CreateOrder,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
    > ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
    > ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
        SetupMandate,
        SetupMandateRequestData<T>,
    ConnectorIntegrationV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>
        CreateSessionToken,
        SessionTokenRequestData,
        SessionTokenResponseData,
        CreateAccessToken,
        AccessTokenRequestData,
        AccessTokenResponseData,
        CreateConnectorCustomer,
        ConnectorCustomerData,
        ConnectorCustomerResponse,
        PaymentMethodToken,
        PaymentMethodTokenizationData<T>,
        PaymentMethodTokenResponse,
// SourceVerification implementations for all flows
macro_rules! impl_source_verification_stub {
    ($flow:ty, $common_data:ty, $req:ty, $resp:ty) => {
        impl<
                T: PaymentMethodDataTypes
                    + std::fmt::Debug
                    + std::marker::Sync
                    + std::marker::Send
                    + 'static
                    + Serialize,
            > SourceVerification<$flow, $common_data, $req, $resp> for Cashtocode<T>
            fn get_secrets(
                &self,
                _secrets: ConnectorSourceVerificationSecrets,
            ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
                Ok(Vec::new()) // STUB - will be implemented in Phase 10
            }
            fn get_algorithm(
            ) -> CustomResult<
                Box<dyn common_utils::crypto::VerifySignature + Send>,
                errors::ConnectorError,
            > {
                Ok(Box::new(common_utils::crypto::NoAlgorithm)) // STUB - will be implemented in Phase 10
            fn get_signature(
                _payload: &[u8],
                _router_data: &RouterDataV2<$flow, $common_data, $req, $resp>,
                _secrets: &[u8],
            fn get_message(
                payload: &[u8],
                Ok(payload.to_owned()) // STUB - will be implemented in Phase 10
    };
// Apply to all flows
impl_source_verification_stub!(
    Authorize,
    PaymentFlowData,
    PaymentsAuthorizeData<T>,
    PaymentsResponseData
    PSync,
    PaymentsSyncData,
    Capture,
    PaymentsCaptureData,
impl_source_verification_stub!(Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData);
impl_source_verification_stub!(Refund, RefundFlowData, RefundsData, RefundsResponseData);
impl_source_verification_stub!(RSync, RefundFlowData, RefundSyncData, RefundsResponseData);
    SetupMandate,
    SetupMandateRequestData<T>,
    RepeatPayment,
    RepeatPaymentData,
    Accept,
    DisputeFlowData,
    AcceptDisputeData,
    DisputeResponseData
    SubmitEvidence,
    SubmitEvidenceData,
    DefendDispute,
    DisputeDefendData,
    CreateOrder,
    PaymentCreateOrderData,
    PaymentCreateOrderResponse
    PreAuthenticate,
    PaymentsPreAuthenticateData<T>,
    Authenticate,
    PaymentsAuthenticateData<T>,
    PostAuthenticate,
    PaymentsPostAuthenticateData<T>,
    VoidPC,
    PaymentsCancelPostCaptureData,
    interfaces::verification::SourceVerification<
fn get_b64_auth_cashtocode(
    payment_method_type: Option<common_enums::PaymentMethodType>,
    auth_type: &transformers::CashtocodeAuth,
) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
    fn construct_basic_auth(
        username: Option<Secret<String>>,
        password: Option<Secret<String>>,
    ) -> Result<Maskable<String>, errors::ConnectorError> {
        let username = username.ok_or(errors::ConnectorError::FailedToObtainAuthType)?;
        let password = password.ok_or(errors::ConnectorError::FailedToObtainAuthType)?;
        Ok(format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!(
                "{}:{}",
                username.peek(),
                password.peek()
            ))
        .into_masked())
    let auth_header = match payment_method_type {
        Some(common_enums::PaymentMethodType::ClassicReward) => construct_basic_auth(
            auth_type.username_classic.to_owned(),
            auth_type.password_classic.to_owned(),
        ),
        Some(common_enums::PaymentMethodType::Evoucher) => construct_basic_auth(
            auth_type.username_evoucher.to_owned(),
            auth_type.password_evoucher.to_owned(),
        _ => return Err(errors::ConnectorError::MissingPaymentMethodType)?,
    }?;
    Ok(vec![(headers::AUTHORIZATION.to_string(), auth_header)])
