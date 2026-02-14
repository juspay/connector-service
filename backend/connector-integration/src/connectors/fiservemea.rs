pub mod transformers;

use std::fmt::Debug;

use common_enums::CurrencyUnit;
use common_utils::{errors::CustomResult, events, ext_traits::ByteSliceExt};
use domain_types::{
    connector_flow::{
        Authorize,
    },
    connector_types::{
        PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData,
    },
    connector_types::*, errors, payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response, types::Connectors,
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, Mask, Maskable, Secret};
use interfaces::{
    api::ConnectorCommon, connector_integration_v2::ConnectorIntegrationV2, connector_types,
};
use serde::Serialize;
use transformers as fiservemea;
use transformers::{
    FiservemeaAuthorizeRequest,
    FiservemeaAuthorizeResponse,
};

use super::macros;

use crate::with_error_response_body;

pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const API_KEY: &str = "Api-Key";
    pub(crate) const CLIENT_REQUEST_ID: &str = "Client-Request-Id";
    pub(crate) const TIMESTAMP: &str = "Timestamp";
    pub(crate) const MESSAGE_SIGNATURE: &str = "Message-Signature";
}



// =============================================================================
// MACRO PREREQUISITES
// =============================================================================
// Define connector struct and bridge types for all flows
macros::create_all_prerequisites!(
    connector_name: Fiservemea,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: FiservemeaAuthorizeRequest<T>,
            response_body: FiservemeaAuthorizeResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        )
    ],
    amount_converters: [
        amount_converter: MinorUnit
    ],
    member_functions: {
        /// Build headers with HMAC-SHA256 signature
        fn build_headers_with_signature(
            &self,
            auth: &fiservemea::FiservemeaAuthType,
            request_body_str: &str,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            let client_request_id = fiservemea::FiservemeaAuthType::generate_client_request_id();
            let timestamp = fiservemea::FiservemeaAuthType::generate_timestamp();

            let api_key_value = auth.api_key.clone().expose();
            let message_signature = auth.generate_hmac_signature(
                &api_key_value,
                &client_request_id,
                &timestamp,
                request_body_str,
            )?;

            Ok(vec![
                (
                    headers::CONTENT_TYPE.to_string(),
                    "application/json".to_string().into(),
                ),
                (
                    headers::API_KEY.to_string(),
                    Secret::new(api_key_value).into_masked(),
                ),
                (
                    headers::CLIENT_REQUEST_ID.to_string(),
                    client_request_id.into(),
                ),
                (headers::TIMESTAMP.to_string(), timestamp.into()),
                (
                    headers::MESSAGE_SIGNATURE.to_string(),
                    message_signature.into(),
                ),
            ])
        }

        fn connector_base_url<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.fiservemea.base_url
        }
    }
);

// =============================================================================
// MAIN CONNECTOR INTEGRATION IMPLEMENTATIONS
// =============================================================================
// Authorize flow - Payment authorization with HMAC signature
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Fiservemea,
    curl_request: Json(FiservemeaAuthorizeRequest<T>),
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
            let auth = fiservemea::FiservemeaAuthType::try_from(&req.connector_auth_type)
                .change_context(errors::ConnectorError::FailedToObtainAuthType)?;

            let connector_req = fiservemea::FiservemeaAuthorizeRequest::try_from(req)?;
            let request_body_str = serde_json::to_string(&connector_req)
                .change_context(errors::ConnectorError::RequestEncodingFailed)?;

            self.build_headers_with_signature(
                &auth,
                &request_body_str,
            )
        }

        fn get_url(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            Ok(format!("{}/ipp/payments-gateway/v2/payments", self.connector_base_url(req)))
        }
    }
);

// =============================================================================
// CONNECTOR COMMON IMPLEMENTATION
// =============================================================================
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> ConnectorCommon
    for Fiservemea<T>
{
    fn id(&self) -> &'static str {
        "fiservemea"
    }

    fn get_currency_unit(&self) -> CurrencyUnit {
        CurrencyUnit::Minor
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn base_url<'a>(&self, _connectors: &'a Connectors) -> &'a str {
        "https://prod.emea.api.fiservapps.com/sandbox"
    }

    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth = fiservemea::FiservemeaAuthType::try_from(auth_type)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        Ok(vec![(
            headers::AUTHORIZATION.to_string(),
            format!("Bearer {}", auth.api_key.expose()).into(),
        )])
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut events::Event>,
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        let response: fiservemea::FiservemeaErrorResponse = res
            .response
            .parse_struct("FiservemeaErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        with_error_response_body!(event_builder, response);

        Ok(domain_types::router_data::ErrorResponse {
            status_code: res.status_code,
            code: response.code,
            message: response.message,
            reason: None,
            attempt_status: None,
            connector_transaction_id: None,
            network_decline_code: None,
            network_advice_code: None,
            network_error_message: None,
        })
    }
}
// =============================================================================
// DYNAMICALLY GENERATED IMPLEMENTATIONS
// =============================================================================
// The following implementations were auto-generated by add_connector.sh
// based on the flows detected in ConnectorServiceTrait.
//
// To customize a flow implementation:
// 1. Move the empty impl block above (before this comment section)
// 2. Add your custom logic inside the impl block
// 3. The script will not regenerate moved implementations
// =============================================================================

// ===== CONNECTOR SERVICE TRAIT IMPLEMENTATIONS =====
// Main service trait - aggregates all other traits
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ConnectorServiceTrait<T> for Fiservemea<T>
{
}

// ===== FLOW TRAIT IMPLEMENTATIONS =====
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::AcceptDispute for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::CreateConnectorCustomer for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::DisputeDefend for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::IncomingWebhook for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::MandateRevokeV2 for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAccessToken for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAuthenticateV2<T> for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAuthorizeV2<T> for Fiservemea<T>
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
    connector_types::PaymentOrderCreate for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentPostAuthenticateV2<T> for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentPreAuthenticateV2<T> for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentSessionToken for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentSyncV2 for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentTokenV2<T> for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentVoidPostCaptureV2 for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentVoidV2 for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundSyncV2 for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundV2 for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RepeatPaymentV2<T> for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::SdkSessionTokenV2 for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::SetupMandateV2<T> for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::SubmitEvidenceV2 for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ValidationTrait for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::VerifyRedirectResponse for Fiservemea<T>
{
}

// ===== CONNECTOR INTEGRATION V2 IMPLEMENTATIONS =====
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        connector_flow::Accept,
        DisputeFlowData,
        AcceptDisputeData,
        DisputeResponseData,
    > for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        connector_flow::CreateConnectorCustomer,
        PaymentFlowData,
        ConnectorCustomerData,
        ConnectorCustomerResponse,
    > for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        connector_flow::DefendDispute,
        DisputeFlowData,
        DisputeDefendData,
        DisputeResponseData,
    > for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        connector_flow::MandateRevoke,
        PaymentFlowData,
        MandateRevokeRequestData,
        MandateRevokeResponseData,
    > for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        connector_flow::CreateAccessToken,
        PaymentFlowData,
        AccessTokenRequestData,
        AccessTokenResponseData,
    > for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        connector_flow::Authenticate,
        PaymentFlowData,
        PaymentsAuthenticateData<T>,
        PaymentsResponseData,
    > for Fiservemea<T>
{
}



impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        connector_flow::Capture,
        PaymentFlowData,
        PaymentsCaptureData,
        PaymentsResponseData,
    > for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        connector_flow::IncrementalAuthorization,
        PaymentFlowData,
        PaymentsIncrementalAuthorizationData,
        PaymentsResponseData,
    > for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        connector_flow::CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        connector_flow::PostAuthenticate,
        PaymentFlowData,
        PaymentsPostAuthenticateData<T>,
        PaymentsResponseData,
    > for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        connector_flow::PreAuthenticate,
        PaymentFlowData,
        PaymentsPreAuthenticateData<T>,
        PaymentsResponseData,
    > for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        connector_flow::CreateSessionToken,
        PaymentFlowData,
        SessionTokenRequestData,
        SessionTokenResponseData,
    > for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        connector_flow::PSync,
        PaymentFlowData,
        PaymentsSyncData,
        PaymentsResponseData,
    > for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        connector_flow::PaymentMethodToken,
        PaymentFlowData,
        PaymentMethodTokenizationData<T>,
        PaymentMethodTokenResponse,
    > for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        connector_flow::VoidPC,
        PaymentFlowData,
        PaymentsCancelPostCaptureData,
        PaymentsResponseData,
    > for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        connector_flow::Void,
        PaymentFlowData,
        PaymentVoidData,
        PaymentsResponseData,
    > for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        connector_flow::RSync,
        RefundFlowData,
        RefundSyncData,
        RefundsResponseData,
    > for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<connector_flow::Refund, RefundFlowData, RefundsData, RefundsResponseData>
    for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        connector_flow::RepeatPayment,
        PaymentFlowData,
        RepeatPaymentData<T>,
        PaymentsResponseData,
    > for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        connector_flow::SdkSessionToken,
        PaymentFlowData,
        PaymentsSdkSessionTokenData,
        PaymentsResponseData,
    > for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        connector_flow::SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData<T>,
        PaymentsResponseData,
    > for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        connector_flow::SubmitEvidence,
        DisputeFlowData,
        SubmitEvidenceData,
        DisputeResponseData,
    > for Fiservemea<T>
{
}

// ===== SOURCE VERIFICATION IMPLEMENTATION =====
// Simple non-generic trait for webhook signature verification
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification for Fiservemea<T>
{
}
