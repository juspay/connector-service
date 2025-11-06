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
};
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
    > connector_types::PaymentPreAuthenticateV2<T> for Noon<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::PaymentAuthenticateV2<T> for Noon<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::PaymentPostAuthenticateV2<T> for Noon<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::ConnectorServiceTrait<T> for Noon<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::PaymentAuthorizeV2<T> for Noon<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::PaymentSessionToken for Noon<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAccessToken for Noon<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::CreateConnectorCustomer for Noon<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentOrderCreate for Noon<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentSyncV2 for Noon<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentVoidV2 for Noon<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundSyncV2 for Noon<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundV2 for Noon<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentCapture for Noon<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::SetupMandateV2<T> for Noon<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RepeatPaymentV2<T> for Noon<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentVoidPostCaptureV2<T> for Noon<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::AcceptDispute for Noon<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::SubmitEvidenceV2 for Noon<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::DisputeDefend for Noon<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::IncomingWebhook for Noon<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentTokenV2<T> for Noon<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ValidationTrait for Noon<T>
{
    fn should_do_order_create(&self) -> bool {
        false // Noon doesn't require separate order creation
    }
}

// ConnectorCommon implementation
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> ConnectorCommon for Noon<T> {
    fn id(&self) -> &'static str {
        "noon"
    }

    fn get_currency_unit(&self) -> common_enums::CurrencyUnit {
        common_enums::CurrencyUnit::Minor // For minor units
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        &connectors.noon.base_url
    }

    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth = noon::NoonAuthType::try_from(auth_type)?;
        Ok(vec![
            ("Content-Type".to_string(), "application/json".to_string().into()),
            ("Accept".to_string(), "application/json".to_string().into()),
            ("Authorization".to_string(), auth.auth_header.into_masked()),
        ])
    }

    fn build_error_response(
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: noon::NoonErrorResponse = res
            .response
            .parse_struct("NoonErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        
        // Set error response body for logging
        if let Some(event) = event_builder {
            event.set_error_response_body(&response);
        }

        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response.code.clone(),
            message: response.message.clone(),
            reason: Some(response.message),
            attempt_status: None,
            connector_transaction_id: None,
            network_decline_code: None,
            network_advice_code: None,
            network_error_message: None,
        })
    }

    fn get_webhook_source_verification_message(
        &self,
        _request: &domain_types::router_data_v2::RouterDataV2<
            domain_types::connector_flow::PSync,
            domain_types::connector_types::PaymentFlowData,
            domain_types::connector_types::PaymentsSyncData,
            domain_types::connector_types::PaymentsResponseData,
        >,
        _response_body: &str,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok("webhook_source_verification".to_string())
    }

    fn get_webhook_source_verification_algorithm(
        &self,
    ) -> CustomResult<Box<dyn crypto::VerifySignature + Send>, errors::ConnectorError> {
        Ok(Box::new(common_utils::crypto::NoAlgorithm))
    }

    fn get_webhook_source_verification_signature(
        &self,
        _request: &domain_types::router_data_v2::RouterDataV2<
            domain_types::connector_flow::PSync,
            domain_types::connector_types::PaymentFlowData,
            domain_types::connector_types::PaymentsSyncData,
            domain_types::connector_types::PaymentsResponseData,
        >,
        _response_body: &str,
        _secret: &[u8],
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(Vec::new())
    }

    fn get_webhook_source_verification_public_key(
        &self,
        _request: &domain_types::router_data_v2::RouterDataV2<
            domain_types::connector_flow::PSync,
            domain_types::connector_types::PaymentFlowData,
            domain_types::connector_types::PaymentsSyncData,
            domain_types::connector_types::PaymentsResponseData,
        >,
        _secrets: &interfaces::api::ConnectorWebhookSecrets,
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(Vec::new())
    }
}

// ConnectorIntegrationV2 implementations
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
    for Noon<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    for Noon<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
    for Noon<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
    for Noon<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
    for Noon<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
    for Noon<T>
{
}

// Additional ConnectorIntegrationV2 implementations for unsupported flows
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<CreateSessionToken, SessionTokenRequestData, SessionTokenResponseData>
    for Noon<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<CreateAccessToken, AccessTokenRequestData, AccessTokenResponseData>
    for Noon<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<CreateConnectorCustomer, ConnectorCustomerData, ConnectorCustomerResponse>
    for Noon<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>
    for Noon<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>
    for Noon<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<VoidPC, PaymentFlowData, PaymentsCancelPostCaptureData, PaymentsResponseData>
    for Noon<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    for Noon<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
    for Noon<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
    for Noon<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<PaymentMethodToken, PaymentMethodTokenizationData<T>, PaymentMethodTokenResponse>
    for Noon<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<PreAuthenticate, PaymentFlowData, PaymentsPreAuthenticateData<T>, PaymentsResponseData>
    for Noon<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Authenticate, PaymentFlowData, PaymentsAuthenticateData<T>, PaymentsResponseData>
    for Noon<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<PostAuthenticate, PaymentFlowData, PaymentsPostAuthenticateData<T>, PaymentsResponseData>
    for Noon<T>
{
}

// SourceVerification implementations for authentication flows
macro_rules! impl_source_verification_stub {
    ($flow:ty, $common_data:ty, $req:ty, $resp:ty) => {
        impl<
                T: PaymentMethodDataTypes
                    + std::fmt::Debug
                    + std::marker::Sync
                    + std::marker::Send
                    + 'static
                    + Serialize,
            > interfaces::verification::SourceVerification<$flow, $common_data, $req, $resp> for Noon<T>
        {
            fn get_secrets(
                &self,
                _secrets: interfaces::verification::ConnectorSourceVerificationSecrets,
            ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
                Ok(Vec::new()) // Stub implementation
            }

            fn get_algorithm(
                &self,
            ) -> CustomResult<Box<dyn crypto::VerifySignature + Send>, errors::ConnectorError> {
                Ok(Box::new(common_utils::crypto::NoAlgorithm)) // Stub implementation
            }

            fn get_signature(
                &self,
                _payload: &[u8],
                _router_data: &domain_types::router_data_v2::RouterDataV2<
                    $flow,
                    $common_data,
                    $req,
                    $resp,
                >,
                _secrets: &[u8],
            ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
                Ok(Vec::new()) // Stub implementation
            }

            fn get_message(
                &self,
                payload: &[u8],
            ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
                Ok(payload.to_owned()) // Stub implementation
            }
        }
    };
}

// Apply to all flows
impl_source_verification_stub!(
    Authorize,
    PaymentFlowData,
    PaymentsAuthorizeData<T>,
    PaymentsResponseData
);

impl_source_verification_stub!(
    PSync,
    PaymentFlowData,
    PaymentsSyncData,
    PaymentsResponseData
);

impl_source_verification_stub!(
    Capture,
    PaymentFlowData,
    PaymentsCaptureData,
    PaymentsResponseData
);

impl_source_verification_stub!(Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData);
impl_source_verification_stub!(Refund, RefundFlowData, RefundsData, RefundsResponseData);
impl_source_verification_stub!(RSync, RefundFlowData, RefundSyncData, RefundsResponseData);

impl_source_verification_stub!(
    SetupMandate,
    PaymentFlowData,
    SetupMandateRequestData<T>,
    PaymentsResponseData
);

impl_source_verification_stub!(
    RepeatPayment,
    PaymentFlowData,
    RepeatPaymentData,
    PaymentsResponseData
);

impl_source_verification_stub!(
    Accept,
    DisputeFlowData,
    AcceptDisputeData,
    DisputeResponseData
);

impl_source_verification_stub!(
    SubmitEvidence,
    DisputeFlowData,
    SubmitEvidenceData,
    DisputeResponseData
);

impl_source_verification_stub!(
    DefendDispute,
    DisputeFlowData,
    DisputeDefendData,
    DisputeResponseData
);

impl_source_verification_stub!(
    CreateSessionToken,
    SessionTokenRequestData,
    SessionTokenResponseData,
    PaymentsResponseData
);

impl_source_verification_stub!(
    CreateAccessToken,
    AccessTokenRequestData,
    AccessTokenResponseData,
    PaymentsResponseData
);

impl_source_verification_stub!(
    CreateConnectorCustomer,
    ConnectorCustomerData,
    ConnectorCustomerResponse,
    PaymentsResponseData
);

impl_source_verification_stub!(
    PaymentMethodToken,
    PaymentMethodTokenizationData<T>,
    PaymentMethodTokenResponse,
    PaymentsResponseData
);

impl_source_verification_stub!(
    PreAuthenticate,
    PaymentFlowData,
    PaymentsPreAuthenticateData<T>,
    PaymentsResponseData
);

impl_source_verification_stub!(
    Authenticate,
    PaymentFlowData,
    PaymentsAuthenticateData<T>,
    PaymentsResponseData
);

impl_source_verification_stub!(
    PostAuthenticate,
    PaymentFlowData,
    PaymentsPostAuthenticateData<T>,
    PaymentsResponseData
);

impl_source_verification_stub!(
    VoidPC,
    PaymentFlowData,
    PaymentsCancelPostCaptureData,
    PaymentsResponseData
);