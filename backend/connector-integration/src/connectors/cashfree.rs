pub mod test;
use common_utils::Maskable;
pub mod transformers;

use std::fmt::Debug;
use cashfree::{
    CashfreeOrderCreateRequest, CashfreeOrderCreateResponse, CashfreePaymentRequest,
    CashfreePaymentResponse,
};
use common_enums::AttemptStatus;
use common_utils::{errors::CustomResult, ext_traits::ByteSliceExt,
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
        ConnectorCustomerResponse, DisputeDefendData, DisputeFlowData, DisputeResponseData,
        PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData,
        PaymentMethodTokenResponse, PaymentMethodTokenizationData, PaymentVoidData,
        PaymentsAuthenticateData, PaymentsAuthorizeData, PaymentsCancelPostCaptureData,
        PaymentsCaptureData, PaymentsPostAuthenticateData, PaymentsPreAuthenticateData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData,
        RefundsResponseData, RepeatPaymentData, SessionTokenRequestData, SessionTokenResponseData,
        SetupMandateRequestData, SubmitEvidenceData,
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
use error_stack::ResultExt;
// use crate::masking::{Mask, Maskable};
use interfaces::{
    api::ConnectorCommon,
    connector_integration_v2::ConnectorIntegrationV2,
    connector_types,
    events::connector_api_logs::ConnectorEvent,
    verification::{ConnectorSourceVerificationSecrets, SourceVerification},
use serde::Serialize;
use transformers as cashfree;
use super::macros;
use crate::{types::ResponseRouterData, with_response_body};
pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const X_CLIENT_ID: &str = "X-Client-Id";
    pub(crate) const X_CLIENT_SECRET: &str = "X-Client-Secret";
    pub(crate) const X_API_VERSION: &str = "x-api-version";
}
// Trait implementations will be added after the macro creates the struct
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::PaymentPreAuthenticateV2<T> for Cashfree<T>
{
    > connector_types::PaymentAuthenticateV2<T> for Cashfree<T>
    > connector_types::PaymentPostAuthenticateV2<T> for Cashfree<T>
    > connector_types::ConnectorServiceTrait<T> for Cashfree<T>
    > connector_types::PaymentAuthorizeV2<T> for Cashfree<T>
    > connector_types::PaymentSessionToken for Cashfree<T>
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAccessToken for Cashfree<T>
    > connector_types::CreateConnectorCustomer for Cashfree<T>
    > connector_types::PaymentOrderCreate for Cashfree<T>
// Trait implementations for all flows
    > connector_types::PaymentSyncV2 for Cashfree<T>
    > connector_types::PaymentVoidV2 for Cashfree<T>
    > connector_types::RefundSyncV2 for Cashfree<T>
    > connector_types::RefundV2 for Cashfree<T>
    > connector_types::PaymentCapture for Cashfree<T>
    > connector_types::SetupMandateV2<T> for Cashfree<T>
    > connector_types::RepeatPaymentV2 for Cashfree<T>
    > connector_types::PaymentVoidPostCaptureV2 for Cashfree<T>
    > connector_types::AcceptDispute for Cashfree<T>
    > connector_types::SubmitEvidenceV2 for Cashfree<T>
    > connector_types::DisputeDefend for Cashfree<T>
    > connector_types::IncomingWebhook for Cashfree<T>
    > connector_types::PaymentTokenV2<T> for Cashfree<T>
// Trait implementations after the macro creates the struct
    > connector_types::ValidationTrait for Cashfree<T>
    fn should_do_order_create(&self) -> bool {
        true // Cashfree V3 requires order creation
    }
// Define connector prerequisites
macros::create_all_prerequisites!(
    connector_name: Cashfree,
    generic_type: T,
    api: [
        (
            flow: CreateOrder,
            request_body: CashfreeOrderCreateRequest,
            response_body: CashfreeOrderCreateResponse,
            router_data: RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>,
        ),
            flow: Authorize,
            request_body: CashfreePaymentRequest,
            response_body: CashfreePaymentResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        )
    ],
    amount_converters: [],
    member_functions: {
        pub fn build_headers<F, FCD, Req, Res>(
            &self,
            req: &RouterDataV2<F, FCD, Req, Res>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            let mut headers = vec![(
                headers::CONTENT_TYPE.to_string(),
                "application/json".to_string().into(),
            )];
            let mut auth_headers = self.get_auth_header(&req.connector_auth_type)?;
            headers.append(&mut auth_headers);
            Ok(headers)
        }
        pub fn connector_base_url<F, Req, Res>(
            req: &RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> String {
            req.resource_common_data.connectors.cashfree.base_url.to_string()
);
// CreateOrder flow implementation using macros
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Cashfree,
    curl_request: Json(CashfreeOrderCreateRequest),
    curl_response: CashfreeOrderCreateResponse,
    flow_name: CreateOrder,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentCreateOrderData,
    flow_response: PaymentCreateOrderResponse,
    http_method: Post,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            req: &RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>,
            self.build_headers(req)
        fn get_url(
        ) -> CustomResult<String, errors::ConnectorError> {
            let base_url = self.connector_base_url(req);
            Ok(format!("{base_url}pg/orders"))
// Authorize flow implementation using macros
    curl_request: Json(CashfreePaymentRequest),
    curl_response: CashfreePaymentResponse,
    flow_name: Authorize,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            Ok(format!("{base_url}pg/orders/sessions"))
// Type alias for non-generic trait implementations
    > ConnectorCommon for Cashfree<T>
    fn id(&self) -> &'static str {
        "cashfree"
    fn get_currency_unit(&self) -> common_enums::CurrencyUnit {
        common_enums::CurrencyUnit::Base // For major units
    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        &connectors.cashfree.base_url
    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth = cashfree::CashfreeAuthType::try_from(auth_type)?;
        Ok(vec![
            (headers::X_CLIENT_ID.to_string(), auth.app_id.into_masked()),
            (
                headers::X_CLIENT_SECRET.to_string(),
                auth.secret_key.into_masked(),
            ),
                headers::X_API_VERSION.to_string(),
                "2022-09-01".to_string().into(),
        ])
    fn build_error_response(
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: cashfree::CashfreeErrorResponse = res
            .response
            .parse_struct("CashfreeErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        with_response_body!(event_builder, response);
        let attempt_status = match response.code.as_str() {
            "AUTHENTICATION_ERROR" => AttemptStatus::AuthenticationFailed,
            "AUTHORIZATION_ERROR" => AttemptStatus::AuthorizationFailed,
            "INVALID_REQUEST_ERROR" => AttemptStatus::Failure,
            "GATEWAY_ERROR" => AttemptStatus::Failure,
            "SERVER_ERROR" => AttemptStatus::Pending,
            _ => AttemptStatus::Failure,
        };
        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response.code.clone(),
            message: response.message.clone(),
            reason: Some(response.message),
            attempt_status: Some(attempt_status),
            connector_transaction_id: None,
            network_decline_code: None,
            network_advice_code: None,
            network_error_message: None,
        })
// Stub implementations for unsupported flows
    > ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    for Cashfree<T>
    > ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
    > ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
    > ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
    > ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
    >
    ConnectorIntegrationV2<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData<T>,
        PaymentsResponseData,
    > for Cashfree<T>
    > ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
        PaymentMethodToken,
        PaymentMethodTokenizationData<T>,
        PaymentMethodTokenResponse,
// CreateSessionToken stub implementation
        CreateSessionToken,
        SessionTokenRequestData,
        SessionTokenResponseData,
// CreateAccessToken stub implementation
        CreateAccessToken,
        AccessTokenRequestData,
        AccessTokenResponseData,
// CreateConnectorCustomer stub implementation
        CreateConnectorCustomer,
        ConnectorCustomerData,
        ConnectorCustomerResponse,
    > ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
// Default ConnectorIntegrationV2 implementations for unsupported flows
    ConnectorIntegrationV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>
        VoidPC,
        PaymentsCancelPostCaptureData,
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
            > SourceVerification<$flow, $common_data, $req, $resp> for Cashfree<T>
        {
            fn get_secrets(
                &self,
                _secrets: ConnectorSourceVerificationSecrets,
            ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
                Ok(Vec::new()) // Stub implementation
            }
            fn get_algorithm(
            ) -> CustomResult<
                Box<dyn common_utils::crypto::VerifySignature + Send>,
                errors::ConnectorError,
            > {
                Ok(Box::new(common_utils::crypto::NoAlgorithm)) // Stub implementation
            fn get_signature(
                _payload: &[u8],
                _router_data: &domain_types::router_data_v2::RouterDataV2<
                    $flow,
                    $common_data,
                    $req,
                    $resp,
                >,
                _secrets: &[u8],
            fn get_message(
                payload: &[u8],
                Ok(payload.to_owned()) // Stub implementation
    };
// Apply to all flows
impl_source_verification_stub!(
    Authorize,
    PaymentFlowData,
    PaymentsAuthorizeData<T>,
    PaymentsResponseData
    CreateOrder,
    PaymentCreateOrderData,
    PaymentCreateOrderResponse
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
    CreateSessionToken,
    SessionTokenRequestData,
    SessionTokenResponseData
    CreateAccessToken,
    AccessTokenRequestData,
    AccessTokenResponseData
    PaymentMethodToken,
    PaymentMethodTokenizationData<T>,
    PaymentMethodTokenResponse
// Authentication flow ConnectorIntegrationV2 implementations
        PreAuthenticate,
        PaymentsPreAuthenticateData<T>,
        Authenticate,
        PaymentsAuthenticateData<T>,
        PostAuthenticate,
        PaymentsPostAuthenticateData<T>,
// Authentication flow SourceVerification implementations
    PreAuthenticate,
    PaymentsPreAuthenticateData<T>,
    Authenticate,
    PaymentsAuthenticateData<T>,
    PostAuthenticate,
    PaymentsPostAuthenticateData<T>,
    CreateConnectorCustomer,
    ConnectorCustomerData,
    ConnectorCustomerResponse
    VoidPC,
    PaymentsCancelPostCaptureData,
