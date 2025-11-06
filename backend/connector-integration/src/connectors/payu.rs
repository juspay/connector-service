pub mod transformers;
use common_utils::Maskable;

use std::fmt::Debug;
use base64::Engine;
use common_enums::{enums, CurrencyUnit};
use common_utils::{errors::CustomResult, ext_traits::ByteSliceExt, types::StringMajorUnit,
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
    },
    errors::{self, ConnectorError},
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
};
use error_stack::ResultExt;
// use crate::masking::Maskable;
use interfaces::{
    api::ConnectorCommon, connector_integration_v2::ConnectorIntegrationV2, connector_types,
    events::connector_api_logs::ConnectorEvent,
use serde::Serialize;
pub const BASE64_ENGINE: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
use transformers::{
    is_upi_collect_flow, PayuAuthType, PayuPaymentRequest, PayuPaymentResponse, PayuSyncRequest,
    PayuSyncResponse,
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
    > connector_types::ConnectorServiceTrait<T> for Payu<T>
{
}
    > connector_types::PaymentAuthorizeV2<T> for Payu<T>
    > connector_types::PaymentSyncV2 for Payu<T>
    > connector_types::PaymentSessionToken for Payu<T>
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAccessToken for Payu<T>
    > connector_types::CreateConnectorCustomer for Payu<T>
    > connector_types::PaymentVoidV2 for Payu<T>
    > connector_types::RefundSyncV2 for Payu<T>
    > connector_types::RefundV2 for Payu<T>
    > connector_types::PaymentCapture for Payu<T>
    > connector_types::SetupMandateV2<T> for Payu<T>
    > connector_types::AcceptDispute for Payu<T>
    > connector_types::SubmitEvidenceV2 for Payu<T>
    > connector_types::DisputeDefend for Payu<T>
    > connector_types::IncomingWebhook for Payu<T>
    > connector_types::PaymentOrderCreate for Payu<T>
    > connector_types::ValidationTrait for Payu<T>
    > connector_types::RepeatPaymentV2 for Payu<T>
    > connector_types::PaymentTokenV2<T> for Payu<T>
// Authentication trait implementations
    > connector_types::PaymentPreAuthenticateV2<T> for Payu<T>
    > connector_types::PaymentAuthenticateV2<T> for Payu<T>
    > connector_types::PaymentPostAuthenticateV2<T> for Payu<T>
    > connector_types::PaymentVoidPostCaptureV2 for Payu<T>
    >
    ConnectorIntegrationV2<
        VoidPC,
        PaymentFlowData,
        PaymentsCancelPostCaptureData,
        PaymentsResponseData,
    > for Payu<T>
// Set up connector using macros with all framework integrations
macros::create_all_prerequisites!(
    connector_name: Payu,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: PayuPaymentRequest,
            response_body: PayuPaymentResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
            flow: PSync,
            request_body: PayuSyncRequest,
            response_body: PayuSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        )
    ],
    amount_converters: [
        amount_converter: StringMajorUnit
    member_functions: {
        pub fn build_headers<F, FCD, Req, Res>(
            &self,
            _req: &RouterDataV2<F, FCD, Req, Res>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError>
        where
            Self: ConnectorIntegrationV2<F, FCD, Req, Res>,
        {
            Ok(vec![
                ("Content-Type".to_string(), "application/x-www-form-urlencoded".into()),
                ("Accept".to_string(), "application/json".into()),
            ])
        }
        pub fn connector_base_url_payments<'a, F, Req, Res>(
            req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.payu.base_url
        pub fn connector_base_url_refunds<'a, F, Req, Res>(
            req: &'a RouterDataV2<F, RefundFlowData, Req, Res>,
        pub fn preprocess_response_bytes<F, FCD, Res>(
            req: &RouterDataV2<F, FCD, PaymentsAuthorizeData<T>, Res>,
            bytes: bytes::Bytes,
        ) -> CustomResult<bytes::Bytes, ConnectorError> {
            if is_upi_collect_flow(&req.request) {
                // For UPI collect flows, we need to return base64 decoded response
                let decoded_value = BASE64_ENGINE.decode(bytes.clone());
                match decoded_value {
                    Ok(decoded_bytes) => Ok(decoded_bytes.into()),
                    Err(_) => Ok(bytes.clone())
                }
            } else {
                // For other flows, we can use the response itself
                Ok(bytes)
            }
    }
);
// Implement PSync flow using macro framework
macros::macro_connector_implementation!(
    connector_default_implementations: [],
    connector: Payu,
    curl_request: FormUrlEncoded(PayuSyncRequest),
    curl_response: PayuSyncResponse,
    flow_name: PSync,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsSyncData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            _req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        fn get_url(
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<String, ConnectorError> {
            // Based on Haskell implementation: uses /merchant/postservice.php?form=2 for verification
            // Test: https://test.payu.in/merchant/postservice.php?form=2
            let base_url = self.base_url(&req.resource_common_data.connectors);
            Ok(format!("{base_url}/merchant/postservice.php?form=2"))
        fn get_content_type(&self) -> &'static str {
            "application/x-www-form-urlencoded"
        fn get_error_response_v2(
            res: Response,
            _event_builder: Option<&mut ConnectorEvent>,
        ) -> CustomResult<ErrorResponse, ConnectorError> {
            // PayU sync may return error responses in different formats
            let response: PayuSyncResponse = res
                .response
                .parse_struct("PayU Sync ErrorResponse")
                .change_context(ConnectorError::ResponseDeserializationFailed)?;
            // Check if PayU returned error status (0 = error)
            if response.status == Some(0) {
                Ok(ErrorResponse {
                    status_code: res.status_code,
                    code: "PAYU_SYNC_ERROR".to_string(),
                    message: response.msg.unwrap_or_default(),
                    reason: None,
                    attempt_status: Some(enums::AttemptStatus::Failure),
                    connector_transaction_id: None,
                    network_error_message: None,
                    network_advice_code: None,
                    network_decline_code: None,
                })
                // Generic error response
                    code: "SYNC_UNKNOWN_ERROR".to_string(),
                    message: "Unknown PayU sync error".to_string(),
// Implement authorize flow using macro framework
    curl_request: FormUrlEncoded(PayuPaymentRequest),
    curl_response: PayuPaymentResponse,
    flow_name: Authorize,
    flow_request: PaymentsAuthorizeData<T>,
    preprocess_response: true,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            self.build_headers(req)
            // Based on Haskell Endpoints.hs: uses /_payment endpoint for UPI transactions
            // Test: https://test.payu.in/_payment
            // Prod: https://secure.payu.in/_payment
            Ok(format!("{base_url}/_payment"))
            // PayU returns error responses in the same JSON format as success responses
            // We need to parse the response and check for error fields
            let response: PayuPaymentResponse = res
                .parse_struct("PayU ErrorResponse")
                        .change_context(ConnectorError::ResponseDeserializationFailed)?;
            // Check if this is an error response
            if response.error.is_some() {
                    code: response.error.unwrap_or_default(),
                    message: response.message.unwrap_or_default(),
                    connector_transaction_id: response.reference_id,
                // This shouldn't happen as successful responses go through normal flow
                // But fallback to generic error
                    code: "UNKNOWN_ERROR".to_string(),
                    message: "Unknown PayU error".to_string(),
// Implement ConnectorCommon trait
    > ConnectorCommon for Payu<T>
    fn id(&self) -> &'static str {
        "payu"
    fn get_currency_unit(&self) -> common_enums::CurrencyUnit {
        CurrencyUnit::Minor
    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        &connectors.payu.base_url
    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        let _auth = PayuAuthType::try_from(auth_type)?;
        // Payu uses form-based authentication, not headers
        Ok(vec![])
// **STUB IMPLEMENTATIONS**: Source Verification Framework stubs for main development
// These will be replaced with actual implementations in Phase 10
use common_utils::crypto;
use interfaces::verification::{ConnectorSourceVerificationSecrets, SourceVerification};
            + Serialize
    > SourceVerification<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
    for Payu<T>
    fn get_secrets(
        _secrets: ConnectorSourceVerificationSecrets,
    ) -> CustomResult<Vec<u8>, ConnectorError> {
        // STUB: Return empty secrets - will be implemented in Phase 10
        Ok(Vec::new())
    fn get_algorithm(
    ) -> CustomResult<Box<dyn crypto::VerifySignature + Send>, ConnectorError> {
        // STUB: Use NoAlgorithm - will be replaced with actual algorithm in Phase 10
        Ok(Box::new(crypto::NoAlgorithm))
    fn get_signature(
        _payload: &[u8],
        _router_data: &RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData<T>,
            PaymentsResponseData,
        >,
        _secrets: &[u8],
        // STUB: Return empty signature - will extract actual signature in Phase 10
    fn get_message(
        payload: &[u8],
        // STUB: Return payload as-is - will implement gateway-specific message format in Phase 10
        Ok(payload.to_owned())
// Add Source Verification stubs for all other flows
macro_rules! impl_source_verification_stub {
    ($flow:ty, $common_data:ty, $req:ty, $resp:ty) => {
        impl<
                T: PaymentMethodDataTypes
                    + std::fmt::Debug
                    + std::marker::Sync
                    + std::marker::Send
                    + 'static
                    + Serialize,
            > SourceVerification<$flow, $common_data, $req, $resp> for Payu<T>
            fn get_secrets(
                &self,
                _secrets: ConnectorSourceVerificationSecrets,
            ) -> CustomResult<Vec<u8>, ConnectorError> {
                Ok(Vec::new()) // STUB - will be implemented in Phase 10
            fn get_algorithm(
            ) -> CustomResult<Box<dyn crypto::VerifySignature + Send>, ConnectorError> {
                Ok(Box::new(crypto::NoAlgorithm)) // STUB - will be implemented in Phase 10
            fn get_signature(
                _payload: &[u8],
                _router_data: &RouterDataV2<$flow, $common_data, $req, $resp>,
                _secrets: &[u8],
            fn get_message(
                payload: &[u8],
                Ok(payload.to_owned()) // STUB - will be implemented in Phase 10
    };
// Apply stub implementations to all flows
impl_source_verification_stub!(
    PSync,
    PaymentFlowData,
    PaymentsSyncData,
    PaymentsResponseData
    Capture,
    PaymentsCaptureData,
impl_source_verification_stub!(Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData);
impl_source_verification_stub!(Refund, RefundFlowData, RefundsData, RefundsResponseData);
impl_source_verification_stub!(RSync, RefundFlowData, RefundSyncData, RefundsResponseData);
    DefendDispute,
    DisputeFlowData,
    DisputeDefendData,
    DisputeResponseData
    CreateOrder,
    PaymentCreateOrderData,
    PaymentCreateOrderResponse
    SetupMandate,
    SetupMandateRequestData<T>,
    Accept,
    AcceptDisputeData,
    SubmitEvidence,
    SubmitEvidenceData,
    RepeatPayment,
    RepeatPaymentData,
// Connector integration implementations for unsupported flows (stubs)
    > ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData> for Payu<T>
    > ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
    > ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
    > ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
        SetupMandate,
        SetupMandateRequestData<T>,
    ConnectorIntegrationV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>
    > ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
    > ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
        CreateOrder,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
        PaymentMethodToken,
        PaymentMethodTokenizationData<T>,
        PaymentMethodTokenResponse,
// Add stub implementation for CreateSessionToken
        CreateSessionToken,
        SessionTokenRequestData,
        SessionTokenResponseData,
// Add stub implementation for CreateAccessToken
        CreateAccessToken,
        AccessTokenRequestData,
        AccessTokenResponseData,
// Add stub implementation for CreateConnectorCustomer
        CreateConnectorCustomer,
        ConnectorCustomerData,
        ConnectorCustomerResponse,
// Add source verification stub for CreateSessionToken
    CreateSessionToken,
    SessionTokenRequestData,
    SessionTokenResponseData
    CreateAccessToken,
    AccessTokenRequestData,
    AccessTokenResponseData
// Add source verification stub for PaymentMethodToken
    PaymentMethodToken,
    PaymentMethodTokenizationData<T>,
    PaymentMethodTokenResponse
    CreateConnectorCustomer,
    ConnectorCustomerData,
    ConnectorCustomerResponse
// Authentication flow implementations
        PreAuthenticate,
        PaymentsPreAuthenticateData<T>,
        Authenticate,
        PaymentsAuthenticateData<T>,
        PostAuthenticate,
        PaymentsPostAuthenticateData<T>,
// Authentication source verification stubs
    PreAuthenticate,
    PaymentsPreAuthenticateData<T>,
    Authenticate,
    PaymentsAuthenticateData<T>,
    PostAuthenticate,
    PaymentsPostAuthenticateData<T>,
    VoidPC,
    PaymentsCancelPostCaptureData,
