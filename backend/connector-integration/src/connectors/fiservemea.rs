pub mod transformers;

use std::fmt::Debug;

use common_enums::CurrencyUnit;
use common_utils::{errors::CustomResult, events, ext_traits::ByteSliceExt};
use domain_types::{
    connector_flow::{
        Accept, Authenticate, Authorize, Capture, CreateAccessToken, CreateOrder,
        CreateSessionToken, DefendDispute, IncrementalAuthorization, PSync, PaymentMethodToken,
        PostAuthenticate, PreAuthenticate, RSync, Refund, RepeatPayment, SetupMandate,
        SubmitEvidence, Void, VoidPC,
    },
    connector_types::{
        AcceptDisputeData, AccessTokenRequestData, AccessTokenResponseData, ConnectorCustomerData,
        ConnectorCustomerResponse, DisputeDefendData, DisputeFlowData, DisputeResponseData,
        PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData,
        PaymentMethodTokenResponse, PaymentMethodTokenizationData, PaymentVoidData,
        PaymentsAuthenticateData, PaymentsAuthorizeData, PaymentsCancelPostCaptureData,
        PaymentsCaptureData, PaymentsIncrementalAuthorizationData, PaymentsPostAuthenticateData,
        PaymentsPreAuthenticateData, PaymentsResponseData, PaymentsSyncData, RefundFlowData,
        RefundSyncData, RefundsData, RefundsResponseData, RepeatPaymentData,
        SessionTokenRequestData, SessionTokenResponseData, SetupMandateRequestData,
        SubmitEvidenceData,
    },
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, Maskable};
use interfaces::{
    api::ConnectorCommon, connector_integration_v2::ConnectorIntegrationV2, connector_types,
};
use serde::Serialize;
use transformers::{
    self as fiservemea, FiservemeaAuthorizeRequest, FiservemeaAuthorizeResponse,
};

use super::macros;
use crate::types::ResponseRouterData;
use crate::with_error_response_body;

pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const API_KEY: &str = "Api-Key";
    pub(crate) const CLIENT_REQUEST_ID: &str = "Client-Request-Id";
    pub(crate) const TIMESTAMP: &str = "Timestamp";
    pub(crate) const MESSAGE_SIGNATURE: &str = "Message-Signature";
}

// ============================================================================
// TRAIT IMPLEMENTATIONS
// ============================================================================

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ConnectorServiceTrait<T> for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAuthorizeV2<T> for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentSyncV2 for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentVoidV2 for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentVoidPostCaptureV2 for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentCapture for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentIncrementalAuthorization for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundV2 for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundSyncV2 for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::SetupMandateV2<T> for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::MandateRevokeV2 for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RepeatPaymentV2<T> for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentOrderCreate for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentSessionToken for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::SdkSessionTokenV2 for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAccessToken for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentTokenV2<T> for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentPreAuthenticateV2<T> for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAuthenticateV2<T> for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentPostAuthenticateV2<T> for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::AcceptDispute for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::DisputeDefend for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::SubmitEvidenceV2 for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::IncomingWebhook for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ValidationTrait for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::CreateConnectorCustomer for Fiservemea<T>
{
}

// ============================================================================
// MACRO-BASED IMPLEMENTATION
// ============================================================================

macros::create_amount_converter_wrapper!(connector_name: Fiservemea, amount_type: StringMajorUnit);
macros::create_all_prerequisites!(
    connector_name: Fiservemea,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: FiservemeaAuthorizeRequest,
            response_body: FiservemeaAuthorizeResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        )
    ],
    amount_converters: [
        amount_converter: StringMajorUnit
    ],
    member_functions: {
        /// Build authentication headers with message signature
        ///
        /// Generates all required headers for Fiserv EMEA API:
        /// - Content-Type: application/json
        /// - Api-Key: Merchant API key
        /// - Client-Request-Id: Unique UUID for request tracking
        /// - Timestamp: Current epoch milliseconds
        /// - Message-Signature: HMAC-SHA256 signature
        pub fn build_headers<F, FCD, Req, Res>(
            &self,
            req: &RouterDataV2<F, FCD, Req, Res>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            let auth = FiservemeaAuthType::try_from(&req.connector_auth_type)
                .change_context(errors::ConnectorError::FailedToObtainAuthType)?;

            // Generate unique client request ID
            let client_request_id = FiservemeaAuthType::generate_client_request_id();

            // Generate timestamp
            let timestamp = FiservemeaAuthType::generate_timestamp();

            // Build headers
            let mut header = vec![
                (
                    headers::CONTENT_TYPE.to_string(),
                    "application/json".to_string().into(),
                ),
                (
                    headers::API_KEY.to_string(),
                    auth.api_key.expose().to_string().into_masked(),
                ),
                (
                    headers::CLIENT_REQUEST_ID.to_string(),
                    client_request_id.clone().into_masked(),
                ),
                (
                    headers::TIMESTAMP.to_string(),
                    timestamp.to_string().into_masked(),
                ),
            ];

            // Note: Message-Signature will be generated in the request body serialization
            // and added to headers. For now, we store the auth data for later use.
            Ok(header)
        }

        /// Get base URL for payment operations
        pub fn connector_base_url_payments<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.fiservemea.base_url
        }

        /// Get base URL for refund operations
        pub fn connector_base_url_refunds<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, RefundFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.fiservemea.base_url
        }
    }
);

// ============================================================================
// AUTHORIZE FLOW IMPLEMENTATION
// ============================================================================

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Fiservemea,
    curl_request: Json(FiservemeaAuthorizeRequest),
    curl_response: FiservemeaAuthorizeResponse,
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
            let auth = FiservemeaAuthType::try_from(&req.connector_auth_type)
                .change_context(errors::ConnectorError::FailedToObtainAuthType)?;

            // Generate unique client request ID
            let client_request_id = FiservemeaAuthType::generate_client_request_id();

            // Generate timestamp
            let timestamp = FiservemeaAuthType::generate_timestamp();

            // Serialize request body for signature generation
            let request_obj = FiservemeaAuthorizeRequest::try_from(req)?;
            let request_body = serde_json::to_string(&request_obj)
                .map_err(|_| errors::ConnectorError::RequestEncodingFailed)?;

            // Generate message signature
            let signature = auth.generate_message_signature(&client_request_id, timestamp, &request_body)?;

            // Build headers
            let mut header = vec![
                (
                    headers::CONTENT_TYPE.to_string(),
                    "application/json".to_string().into(),
                ),
                (
                    headers::API_KEY.to_string(),
                    auth.api_key.expose().to_string().into_masked(),
                ),
                (
                    headers::CLIENT_REQUEST_ID.to_string(),
                    client_request_id.into_masked(),
                ),
                (
                    headers::TIMESTAMP.to_string(),
                    timestamp.to_string().into_masked(),
                ),
                (
                    headers::MESSAGE_SIGNATURE.to_string(),
                    signature.into_masked(),
                ),
            ];

            Ok(header)
        }

        fn get_url(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            let base_url = self.connector_base_url_payments(req);
            Ok(format!("{}/ipp/payments-gateway/v2/payments", base_url))
        }
    }
);

// ============================================================================
// STUB IMPLEMENTATIONS FOR OTHER FLOWS
// ============================================================================

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
    for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        VoidPC,
        PaymentFlowData,
        PaymentsCancelPostCaptureData,
        PaymentsResponseData,
    > for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
    for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        IncrementalAuthorization,
        PaymentFlowData,
        PaymentsIncrementalAuthorizationData,
        PaymentsResponseData,
    > for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
    for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
    for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData<T>,
        PaymentsResponseData,
    > for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        domain_types::connector_flow::MandateRevoke,
        PaymentFlowData,
        domain_types::connector_types::MandateRevokeRequestData,
        domain_types::connector_types::MandateRevokeResponseData,
    > for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        RepeatPayment,
        PaymentFlowData,
        RepeatPaymentData<T>,
        PaymentsResponseData,
    > for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        CreateSessionToken,
        PaymentFlowData,
        SessionTokenRequestData,
        SessionTokenResponseData,
    > for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
    for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
    for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        PaymentMethodToken,
        PaymentFlowData,
        PaymentMethodTokenizationData<T>,
        PaymentMethodTokenResponse,
    > for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        CreateAccessToken,
        PaymentFlowData,
        AccessTokenRequestData,
        AccessTokenResponseData,
    > for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        PreAuthenticate,
        PaymentFlowData,
        PaymentsPreAuthenticateData<T>,
        PaymentsResponseData,
    > for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        Authenticate,
        PaymentFlowData,
        PaymentsAuthenticateData<T>,
        PaymentsResponseData,
    > for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        PostAuthenticate,
        PaymentFlowData,
        PaymentsPostAuthenticateData<T>,
        PaymentsResponseData,
    > for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        domain_types::connector_flow::CreateConnectorCustomer,
        PaymentFlowData,
        ConnectorCustomerData,
        ConnectorCustomerResponse,
    > for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        domain_types::connector_flow::SdkSessionToken,
        PaymentFlowData,
        domain_types::connector_types::PaymentsSdkSessionTokenData,
        PaymentsResponseData,
    > for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::VerifyRedirectResponse for Fiservemea<T>
{
}

// ============================================================================
// CONNECTOR COMMON IMPLEMENTATION
// ============================================================================

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> ConnectorCommon
    for Fiservemea<T>
{
    fn id(&self) -> &'static str {
        "fiservemea"
    }

    fn get_currency_unit(&self) -> CurrencyUnit {
        CurrencyUnit::Minor
    }

    fn base_url<'a>(&self, _connectors: &'a Connectors) -> &'a str {
        "https://prod.emea.api.fiservapps.com/sandbox"
    }

    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth = FiservemeaAuthType::try_from(auth_type)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        Ok(vec![(
            headers::API_KEY.to_string(),
            auth.api_key.expose().to_string().into_masked(),
        )])
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut events::Event>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: FiservemeaErrorResponse = res
            .response
            .parse_struct("FiservemeaErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        with_error_response_body!(event_builder, response);

        // Map response type to attempt status
        let attempt_status = match response.response_type {
            FiservemeaResponseType::EndpointDeclined => Some(AttemptStatus::Failure),
            FiservemeaResponseType::GatewayDeclined => Some(AttemptStatus::Failure),
            FiservemeaResponseType::ServerError => Some(AttemptStatus::Pending),
            FiservemeaResponseType::EndpointCommunicationError => Some(AttemptStatus::Pending),
            _ => None,
        };

        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response.error.code,
            message: response.error.message,
            reason: response.error.decline_reason_code,
            attempt_status,
            connector_transaction_id: None,
            network_decline_code: None,
            network_advice_code: None,
            network_error_message: None,
        })
    }
}