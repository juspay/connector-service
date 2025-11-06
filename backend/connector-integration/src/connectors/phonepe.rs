pub mod constants;
use common_utils::Maskable;
pub mod headers;
pub mod transformers;

use common_enums as enums;
use common_utils::{errors::CustomResult, ext_traits::BytesExt, types::MinorUnit,
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
        ConnectorCustomerResponse, ConnectorSpecifications, DisputeDefendData, DisputeFlowData,
        DisputeResponseData, PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData,
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
    types::{ConnectorInfo, Connectors},
use error_stack::ResultExt;
// use crate::masking::{Maskable, PeekInterface};
use interfaces::{
    api::ConnectorCommon,
    connector_integration_v2::ConnectorIntegrationV2,
    connector_types,
    events::connector_api_logs::ConnectorEvent,
    verification::{ConnectorSourceVerificationSecrets, SourceVerification},
use serde::Serialize;
use transformers as phonepe;
use self::transformers::{
    PhonepePaymentsRequest, PhonepePaymentsResponse, PhonepeSyncRequest, PhonepeSyncResponse,
use super::macros;
use crate::types::ResponseRouterData;
// Trait implementations with generic type parameters
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::PaymentPreAuthenticateV2<T> for Phonepe<T>
{
}
    > connector_types::PaymentAuthenticateV2<T> for Phonepe<T>
    > connector_types::PaymentPostAuthenticateV2<T> for Phonepe<T>
    > connector_types::ConnectorServiceTrait<T> for Phonepe<T>
    > connector_types::PaymentSessionToken for Phonepe<T>
impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAccessToken for Phonepe<T>
    > connector_types::CreateConnectorCustomer for Phonepe<T>
    > connector_types::PaymentAuthorizeV2<T> for Phonepe<T>
    > connector_types::PaymentSyncV2 for Phonepe<T>
    > connector_types::PaymentVoidV2 for Phonepe<T>
    > connector_types::RefundSyncV2 for Phonepe<T>
    > connector_types::RefundV2 for Phonepe<T>
    > connector_types::PaymentCapture for Phonepe<T>
    > connector_types::SetupMandateV2<T> for Phonepe<T>
    > connector_types::AcceptDispute for Phonepe<T>
    > connector_types::SubmitEvidenceV2 for Phonepe<T>
    > connector_types::DisputeDefend for Phonepe<T>
    > connector_types::IncomingWebhook for Phonepe<T>
    > connector_types::PaymentOrderCreate for Phonepe<T>
    > connector_types::ValidationTrait for Phonepe<T>
    > connector_types::RepeatPaymentV2 for Phonepe<T>
    > connector_types::PaymentVoidPostCaptureV2 for Phonepe<T>
    > connector_types::PaymentTokenV2<T> for Phonepe<T>
// Define connector prerequisites
macros::create_all_prerequisites!(
    connector_name: Phonepe,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: PhonepePaymentsRequest,
            response_body: PhonepePaymentsResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
            flow: PSync,
            request_body: PhonepeSyncRequest,
            response_body: PhonepeSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        )
    ],
    amount_converters: [
        amount_converter: MinorUnit
    member_functions: {
        pub fn connector_base_url<F, Req, Res>(
            &self,
            req: &RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> String {
            req.resource_common_data.connectors.phonepe.base_url.to_string()
        }
        pub fn connector_base_url_payments<'a, F, Req, Res>(
            req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.phonepe.base_url
        pub fn connector_base_url_refunds<'a, F, Req, Res>(
            req: &'a RouterDataV2<F, RefundFlowData, Req, Res>,
        pub fn build_headers<F, FCD, Req, Res>(
            _req: &RouterDataV2<F, FCD, Req, Res>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError>
        where
            Self: ConnectorIntegrationV2<F, FCD, Req, Res>,
        {
            Ok(vec![(
                headers::CONTENT_TYPE.to_string(),
                "application/json".to_string().into(),
            )])
    }
);
// Authorize flow implementation using macros
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Phonepe,
    curl_request: Json(PhonepePaymentsRequest),
    curl_response: PhonepePaymentsResponse,
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
            // Get base headers first
            let mut headers = vec![
                (
                    headers::CONTENT_TYPE.to_string(),
                    "application/json".to_string().into(),
                ),
            ];
            // Build the request to get the checksum for X-VERIFY header
            let connector_router_data = PhonepeRouterData {
                connector: self.clone(),
                router_data: req,
            };
            let connector_req = phonepe::PhonepePaymentsRequest::try_from(&connector_router_data)?;
            headers.push((headers::X_VERIFY.to_string(), connector_req.checksum.into()));
            Ok(headers)
        fn get_url(
        ) -> CustomResult<String, errors::ConnectorError> {
            let base_url = self.connector_base_url(req);
            Ok(format!("{}{}", base_url, constants::API_PAY_ENDPOINT))
// PSync flow implementation using macros
    curl_request: Json(PhonepeSyncRequest),
    curl_response: PhonepeSyncResponse,
    flow_name: PSync,
    flow_request: PaymentsSyncData,
    http_method: Get,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            let connector_req = phonepe::PhonepeSyncRequest::try_from(&connector_router_data)?;
            // Get merchant ID for X-MERCHANT-ID header
            let auth = phonepe::PhonepeAuthType::try_from(&req.connector_auth_type)?;
            headers.push((headers::X_MERCHANT_ID.to_string(), auth.merchant_id.peek().to_string().into()));
            let merchant_transaction_id = &req.resource_common_data.connector_request_reference_id;
            let api_endpoint = constants::API_STATUS_ENDPOINT;
            let merchant_id = auth.merchant_id.peek();
            Ok(format!("{base_url}{api_endpoint}/{merchant_id}/{merchant_transaction_id}"))
// Type alias for non-generic trait implementations
// Implement ConnectorServiceTrait by virtue of implementing all required traits
    > ConnectorCommon for Phonepe<T>
    fn id(&self) -> &'static str {
        "phonepe"
    fn get_currency_unit(&self) -> enums::CurrencyUnit {
        enums::CurrencyUnit::Minor
    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let _auth = phonepe::PhonepeAuthType::try_from(auth_type)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        Ok(vec![(
            "Content-Type".to_string(),
            "application/json".to_string().into(),
        )])
    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.phonepe.base_url.as_ref()
    fn build_error_response(
        res: Response,
        _event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        // Parse PhonePe error response (unified for both sync and payments)
        let (error_message, error_code, attempt_status) = if let Ok(error_response) =
            res.response
                .parse_struct::<phonepe::PhonepeErrorResponse>("PhonePe ErrorResponse")
            let attempt_status = phonepe::get_phonepe_error_status(&error_response.code);
            (error_response.message, error_response.code, attempt_status)
        } else {
            let raw_response = String::from_utf8_lossy(&res.response);
            (
                "Unknown PhonePe error".to_string(),
                raw_response.to_string(),
                None,
            )
        };
        Ok(ErrorResponse {
            status_code: res.status_code,
            code: error_code,
            message: error_message.clone(),
            reason: Some(error_message),
            attempt_status,
            connector_transaction_id: None,
            network_decline_code: None,
            network_advice_code: None,
            network_error_message: None,
        })
    >
    ConnectorIntegrationV2<
        VoidPC,
        PaymentFlowData,
        PaymentsCancelPostCaptureData,
        PaymentsResponseData,
    > for Phonepe<T>
    > ConnectorSpecifications for Phonepe<T>
    fn get_supported_payment_methods(
    ) -> Option<&'static domain_types::types::SupportedPaymentMethods> {
        None // TODO: Add UPI payment methods support
    fn get_supported_webhook_flows(&self) -> Option<&'static [enums::EventClass]> {
        None // TODO: Add webhook support
    fn get_connector_about(&self) -> Option<&'static ConnectorInfo> {
        None // TODO: Add connector info
// Default empty implementations for unsupported flows - the traits will use default implementations
        CreateOrder,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
    for Phonepe<T>
    > ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
    > ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
        SetupMandate,
        SetupMandateRequestData<T>,
    ConnectorIntegrationV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>
    > ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    > ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
    > ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
    ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
        PaymentMethodToken,
        PaymentMethodTokenizationData<T>,
        PaymentMethodTokenResponse,
        PreAuthenticate,
        PaymentsPreAuthenticateData<T>,
        Authenticate,
        PaymentsAuthenticateData<T>,
        PostAuthenticate,
        PaymentsPostAuthenticateData<T>,
// SourceVerification implementations for all flows - using macro to generate stubs
macro_rules! impl_source_verification_stub {
    ($flow:ty, $common_data:ty, $req:ty, $resp:ty) => {
        impl<
                T: PaymentMethodDataTypes
                    + std::fmt::Debug
                    + std::marker::Sync
                    + std::marker::Send
                    + 'static
                    + Serialize,
            > SourceVerification<$flow, $common_data, $req, $resp> for Phonepe<T>
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
                _router_data: &RouterDataV2<$flow, $common_data, $req, $resp>,
                _secrets: &[u8],
            fn get_message(
                payload: &[u8],
                Ok(payload.to_owned()) // Stub implementation
    };
// Stub implementations for missing flows
        CreateSessionToken,
        SessionTokenRequestData,
        SessionTokenResponseData,
        CreateAccessToken,
        AccessTokenRequestData,
        AccessTokenResponseData,
        CreateConnectorCustomer,
        ConnectorCustomerData,
        ConnectorCustomerResponse,
// Apply to all flows
impl_source_verification_stub!(
    CreateSessionToken,
    PaymentFlowData,
    SessionTokenRequestData,
    SessionTokenResponseData
    CreateAccessToken,
    AccessTokenRequestData,
    AccessTokenResponseData
    Authorize,
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
    PaymentMethodToken,
    PaymentMethodTokenizationData<T>,
    PaymentMethodTokenResponse
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
