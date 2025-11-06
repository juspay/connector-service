pub mod transformers;
use common_utils::Maskable;
use std::fmt::Debug;

use base64::Engine;
use common_enums::CurrencyUnit;
use common_utils::{
    consts::{NO_ERROR_CODE, NO_ERROR_MESSAGE},
    errors::CustomResult,
    ext_traits::ByteSliceExt,
    types::StringMajorUnit,
    ParsingError,
};
use domain_types::{
    connector_flow::{
        Accept, Authenticate, Authorize, Capture, CreateAccessToken, CreateConnectorCustomer,
        CreateOrder, CreateSessionToken, DefendDispute, PSync, PaymentMethodToken,
        PostAuthenticate, PreAuthenticate, RSync, Refund, RepeatPayment, SetupMandate,
        SubmitEvidence, Void,
    },
    connector_types::{
        AcceptDisputeData, AccessTokenRequestData, AccessTokenResponseData, ConnectorCustomerData,
        ConnectorCustomerResponse, DisputeDefendData, DisputeFlowData, DisputeResponseData,
        PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData,
        PaymentMethodTokenResponse, PaymentMethodTokenizationData, PaymentVoidData,
        PaymentsAuthenticateData, PaymentsAuthorizeData, PaymentsCaptureData,
        PaymentsPostAuthenticateData, PaymentsPreAuthenticateData, PaymentsResponseData,
        PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData,
        RepeatPaymentData, SessionTokenRequestData, SessionTokenResponseData,
        SetupMandateRequestData, SubmitEvidenceData,
    },
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
};
use error_stack::Report;
// use crate::masking::{Mask, Maskable, PeekInterface};
use interfaces::{
    api::ConnectorCommon, connector_integration_v2::ConnectorIntegrationV2, connector_types,
    events::connector_api_logs::ConnectorEvent,
};
use serde::Serialize;
use transformers::{
    self as braintree, BraintreeCancelRequest, BraintreeCancelResponse, BraintreeCaptureRequest,
    BraintreeCaptureResponse, BraintreePSyncRequest, BraintreePSyncResponse,
    BraintreePaymentsRequest, BraintreePaymentsResponse, BraintreeRSyncRequest,
    BraintreeRSyncResponse, BraintreeRefundRequest, BraintreeRefundResponse, BraintreeTokenRequest,
    BraintreeTokenResponse,
};
use super::macros;
use crate::{types::ResponseRouterData, with_error_response_body};

// Trait implementations with generic type parameters
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::PaymentPreAuthenticateV2<T> for Braintree<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::PaymentAuthenticateV2<T> for Braintree<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::PaymentPostAuthenticateV2<T> for Braintree<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::ConnectorServiceTrait<T> for Braintree<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::PaymentAuthorizeV2<T> for Braintree<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::PaymentSessionToken for Braintree<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAccessToken for Braintree<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::CreateConnectorCustomer for Braintree<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentOrderCreate for Braintree<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentSyncV2 for Braintree<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentVoidV2 for Braintree<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundSyncV2 for Braintree<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundV2 for Braintree<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentCapture for Braintree<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::SetupMandateV2<T> for Braintree<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RepeatPaymentV2<T> for Braintree<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentVoidPostCaptureV2<T> for Braintree<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::AcceptDispute for Braintree<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::SubmitEvidenceV2 for Braintree<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::DisputeDefend for Braintree<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::IncomingWebhook for Braintree<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentTokenV2<T> for Braintree<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ValidationTrait for Braintree<T>
{
    fn should_do_order_create(&self) -> bool {
        false // Braintree doesn't require separate order creation
    }

    fn should_do_payment_method_token(&self) -> bool {
        true // Braintree supports payment method tokenization
    }
}

// ConnectorCommon implementation
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> ConnectorCommon for Braintree<T> {
    fn id(&self) -> &'static str {
        "braintree"
    }

    fn get_currency_unit(&self) -> CurrencyUnit {
        CurrencyUnit::Minor // For minor units
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        &connectors.braintree.base_url
    }

    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth = braintree::BraintreeAuthType::try_from(auth_type)?;
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
        let response: braintree::BraintreeErrorResponse = res
            .response
            .parse_struct("BraintreeErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        
        with_error_response_body!(event_builder, response);

        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response.error_code.clone(),
            message: response.error_message.clone(),
            reason: Some(response.error_message),
            attempt_status: None,
            connector_transaction_id: None,
            network_decline_code: None,
            network_advice_code: None,
            network_error_message: None,
        })
    }
}

// ConnectorIntegrationV2 implementations
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
    for Braintree<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    for Braintree<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
    for Braintree<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
    for Braintree<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
    for Braintree<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
    for Braintree<T>
{
}

// Additional ConnectorIntegrationV2 implementations for unsupported flows
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<CreateSessionToken, SessionTokenRequestData, SessionTokenResponseData>
    for Braintree<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<CreateAccessToken, AccessTokenRequestData, AccessTokenResponseData>
    for Braintree<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<CreateConnectorCustomer, ConnectorCustomerData, ConnectorCustomerResponse>
    for Braintree<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>
    for Braintree<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>
    for Braintree<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<VoidPC, PaymentFlowData, PaymentsCancelPostCaptureData, PaymentsResponseData>
    for Braintree<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    for Braintree<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
    for Braintree<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
    for Braintree<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<PaymentMethodToken, PaymentMethodTokenizationData<T>, PaymentMethodTokenResponse>
    for Braintree<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<PreAuthenticate, PaymentFlowData, PaymentsPreAuthenticateData<T>, PaymentsResponseData>
    for Braintree<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Authenticate, PaymentFlowData, PaymentsAuthenticateData<T>, PaymentsResponseData>
    for Braintree<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<PostAuthenticate, PaymentFlowData, PaymentsPostAuthenticateData<T>, PaymentsResponseData>
    for Braintree<T>
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
            > interfaces::verification::SourceVerification<$flow, $common_data, $req, $resp> for Braintree<T>
        {
            fn get_secrets(
                &self,
                _secrets: interfaces::verification::ConnectorSourceVerificationSecrets,
            ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
                Ok(Vec::new()) // Stub implementation
            }

            fn get_algorithm(
                &self,
            ) -> CustomResult<Box<dyn common_utils::crypto::VerifySignature + Send>, errors::ConnectorError> {
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