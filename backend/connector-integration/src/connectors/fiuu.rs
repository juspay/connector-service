pub mod transformers;
use common_utils::{Secret, Maskable};

use std::{any::type_name, borrow::Cow, collections::HashMap, fmt::Debug};
use bytes::Bytes;
use common_enums::CurrencyUnit;
use common_utils::{
    crypto::{self, GenerateDigest, VerifySignature},
    errors::CustomResult,
    ext_traits::{ByteSliceExt, BytesExt},
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
        PaymentsSyncData, RefundFlowData, RefundSyncData, RefundWebhookDetailsResponse,
        RefundsData, RefundsResponseData, RepeatPaymentData, RequestDetails,
        SessionTokenRequestData, SessionTokenResponseData, SetupMandateRequestData,
        SubmitEvidenceData, WebhookDetailsResponse,
    },
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
    utils,
};
use error_stack::ResultExt;
// use crate::masking::{ExposeInterface, Maskable, PeekInterface, Secret};
use interfaces::{
    api::ConnectorCommon,
    connector_integration_v2::ConnectorIntegrationV2,
    connector_types::{self},
    events::connector_api_logs::ConnectorEvent,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{error, info, warn};
use transformers::{
    self as fiuu, FiuuPaymentCancelRequest, FiuuPaymentCancelResponse, FiuuPaymentResponse,
    FiuuPaymentSyncRequest, FiuuPaymentsRequest, FiuuPaymentsResponse, FiuuRefundRequest,
    FiuuRefundResponse, FiuuRefundSyncRequest, FiuuRefundSyncResponse, FiuuWebhooksResponse,
    PaymentCaptureRequest, PaymentCaptureResponse,
};
use super::macros;
use crate::{
    types::ResponseRouterData, utils::xml_utils::flatten_json_structure, with_error_response_body,
    with_response_body,
};

// Trait implementations with generic type parameters
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::PaymentPreAuthenticateV2<T> for Fiuu<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::PaymentAuthenticateV2<T> for Fiuu<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::PaymentPostAuthenticateV2<T> for Fiuu<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::ConnectorServiceTrait<T> for Fiuu<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::PaymentAuthorizeV2<T> for Fiuu<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::PaymentSessionToken for Fiuu<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAccessToken for Fiuu<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::CreateConnectorCustomer for Fiuu<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentOrderCreate for Fiuu<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentSyncV2 for Fiuu<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentVoidV2 for Fiuu<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundSyncV2 for Fiuu<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundV2 for Fiuu<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentCapture for Fiuu<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::SetupMandateV2<T> for Fiuu<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RepeatPaymentV2<T> for Fiuu<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentVoidPostCaptureV2<T> for Fiuu<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::AcceptDispute for Fiuu<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::SubmitEvidenceV2 for Fiuu<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::DisputeDefend for Fiuu<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::IncomingWebhook for Fiuu<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentTokenV2<T> for Fiuu<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ValidationTrait for Fiuu<T>
{
    fn should_do_order_create(&self) -> bool {
        false // Fiuu doesn't require separate order creation
    }
}

macros::create_all_prerequisites!(
    connector_name: Fiuu,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: FiuuPaymentsRequest<T>,
            response_body: FiuuPaymentsResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: PSync,
            request_body: FiuuPaymentSyncRequest,
            response_body: FiuuPaymentResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ),
        (
            flow: Capture,
            request_body: PaymentCaptureRequest,
            response_body: PaymentCaptureResponse,
            router_data: RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ),
        (
            flow: Void,
            request_body: FiuuPaymentCancelRequest,
            response_body: FiuuPaymentCancelResponse,
            router_data: RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ),
        (
            flow: Refund,
            request_body: FiuuRefundRequest,
            response_body: FiuuRefundResponse,
            router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ),
        (
            flow: RSync,
            request_body: FiuuRefundSyncRequest,
            response_body: FiuuRefundSyncResponse,
            router_data: RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        )
    ],
    amount_converters: [
        amount_converter: StringMajorUnit
    ],
    member_functions: {
        pub fn preprocess_response_bytes<F, FCD, Req, Res>(
            &self,
            _req: &RouterDataV2<F, FCD, Req, Res>,
            response_bytes: Bytes,
        ) -> Result<Bytes, errors::ConnectorError> {
                let response_str = String::from_utf8(response_bytes.to_vec()).map_err(|e| {
                error!("Error in Deserializing Response Data: {:?}", e);
                errors::ConnectorError::ResponseDeserializationFailed
            })?;
            
            // Process the response string as needed
            Ok(Bytes::from(response_str))
        }
        pub fn connector_base_url<F, Req, Res>(
            req: &RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> String {
            req.resource_common_data.connectors.fiuu.base_url.to_string()
        }
        pub fn connector_base_url_refunds<'a, F, Req, Res>(
            req: &'a RouterDataV2<F, RefundFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.fiuu.base_url
        }
    }
);

// ConnectorIntegrationV2 implementations
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
    for Fiuu<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    for Fiuu<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
    for Fiuu<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
    for Fiuu<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
    for Fiuu<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
    for Fiuu<T>
{
}

// Additional ConnectorIntegrationV2 implementations for unsupported flows
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<CreateSessionToken, SessionTokenRequestData, SessionTokenResponseData>
    for Fiuu<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<CreateAccessToken, AccessTokenRequestData, AccessTokenResponseData>
    for Fiuu<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<CreateConnectorCustomer, ConnectorCustomerData, ConnectorCustomerResponse>
    for Fiuu<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>
    for Fiuu<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>
    for Fiuu<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<VoidPC, PaymentFlowData, PaymentsCancelPostCaptureData, PaymentsResponseData>
    for Fiuu<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    for Fiuu<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
    for Fiuu<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
    for Fiuu<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<PaymentMethodToken, PaymentMethodTokenizationData<T>, PaymentMethodTokenResponse>
    for Fiuu<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<PreAuthenticate, PaymentFlowData, PaymentsPreAuthenticateData<T>, PaymentsResponseData>
    for Fiuu<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Authenticate, PaymentFlowData, PaymentsAuthenticateData<T>, PaymentsResponseData>
    for Fiuu<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<PostAuthenticate, PaymentFlowData, PaymentsPostAuthenticateData<T>, PaymentsResponseData>
    for Fiuu<T>
{
}

// SourceVerification implementations
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        Authorize,
        PaymentFlowData,
        PaymentsAuthorizeData<T>,
        PaymentsResponseData,
    > for Fiuu<T>
{
    fn get_secrets(
        &self,
        _secrets: interfaces::verification::ConnectorSourceVerificationSecrets,
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(Vec::new()) // Stub implementation
    }

    fn get_algorithm(
        &self,
    ) -> CustomResult<
        Box<dyn common_utils::crypto::VerifySignature + Send>,
        errors::ConnectorError,
    > {
        Ok(Box::new(common_utils::crypto::NoAlgorithm)) // Stub implementation
    }

    fn get_signature(
        &self,
        _payload: &[u8],
        _router_data: &domain_types::router_data_v2::RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData<T>,
            PaymentsResponseData,
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

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        PSync,
        PaymentFlowData,
        PaymentsSyncData,
        PaymentsResponseData,
    > for Fiuu<T>
{
    fn get_secrets(
        &self,
        _secrets: interfaces::verification::ConnectorSourceVerificationSecrets,
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(Vec::new()) // Stub implementation
    }

    fn get_algorithm(
        &self,
    ) -> CustomResult<
        Box<dyn common_utils::crypto::VerifySignature + Send>,
        errors::ConnectorError,
    > {
        Ok(Box::new(common_utils::crypto::NoAlgorithm)) // Stub implementation
    }

    fn get_signature(
        &self,
        _payload: &[u8],
        _router_data: &domain_types::router_data_v2::RouterDataV2<
            PSync,
            PaymentFlowData,
            PaymentsSyncData,
            PaymentsResponseData,
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

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        Refund,
        RefundFlowData,
        RefundsData,
        RefundsResponseData,
    > for Fiuu<T>
{
    fn get_secrets(
        &self,
        _secrets: interfaces::verification::ConnectorSourceVerificationSecrets,
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(Vec::new()) // Stub implementation
    }

    fn get_algorithm(
        &self,
    ) -> CustomResult<
        Box<dyn common_utils::crypto::VerifySignature + Send>,
        errors::ConnectorError,
    > {
        Ok(Box::new(common_utils::crypto::NoAlgorithm)) // Stub implementation
    }

    fn get_signature(
        &self,
        _payload: &[u8],
        _router_data: &domain_types::router_data_v2::RouterDataV2<
            Refund,
            RefundFlowData,
            RefundsData,
            RefundsResponseData,
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

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        RSync,
        RefundFlowData,
        RefundSyncData,
        RefundsResponseData,
    > for Fiuu<T>
{
    fn get_secrets(
        &self,
        _secrets: interfaces::verification::ConnectorSourceVerificationSecrets,
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(Vec::new()) // Stub implementation
    }

    fn get_algorithm(
        &self,
    ) -> CustomResult<
        Box<dyn common_utils::crypto::VerifySignature + Send>,
        errors::ConnectorError,
    > {
        Ok(Box::new(common_utils::crypto::NoAlgorithm)) // Stub implementation
    }

    fn get_signature(
        &self,
        _payload: &[u8],
        _router_data: &domain_types::router_data_v2::RouterDataV2<
            RSync,
            RefundFlowData,
            RefundSyncData,
            RefundsResponseData,
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

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        PreAuthenticate,
        PaymentFlowData,
        PaymentsPreAuthenticateData<T>,
        PaymentsResponseData,
    > for Fiuu<T>
{
    fn get_secrets(
        &self,
        _secrets: interfaces::verification::ConnectorSourceVerificationSecrets,
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(Vec::new()) // Stub implementation
    }

    fn get_algorithm(
        &self,
    ) -> CustomResult<
        Box<dyn common_utils::crypto::VerifySignature + Send>,
        errors::ConnectorError,
    > {
        Ok(Box::new(common_utils::crypto::NoAlgorithm)) // Stub implementation
    }

    fn get_signature(
        &self,
        _payload: &[u8],
        _router_data: &domain_types::router_data_v2::RouterDataV2<
            PreAuthenticate,
            PaymentFlowData,
            PaymentsPreAuthenticateData<T>,
            PaymentsResponseData,
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

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        Authenticate,
        PaymentFlowData,
        PaymentsAuthenticateData<T>,
        PaymentsResponseData,
    > for Fiuu<T>
{
    fn get_secrets(
        &self,
        _secrets: interfaces::verification::ConnectorSourceVerificationSecrets,
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(Vec::new()) // Stub implementation
    }

    fn get_algorithm(
        &self,
    ) -> CustomResult<
        Box<dyn common_utils::crypto::VerifySignature + Send>,
        errors::ConnectorError,
    > {
        Ok(Box::new(common_utils::crypto::NoAlgorithm)) // Stub implementation
    }

    fn get_signature(
        &self,
        _payload: &[u8],
        _router_data: &domain_types::router_data_v2::RouterDataV2<
            Authenticate,
            PaymentFlowData,
            PaymentsAuthenticateData<T>,
            PaymentsResponseData,
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

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        PostAuthenticate,
        PaymentFlowData,
        PaymentsPostAuthenticateData<T>,
        PaymentsResponseData,
    > for Fiuu<T>
{
    fn get_secrets(
        &self,
        _secrets: interfaces::verification::ConnectorSourceVerificationSecrets,
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(Vec::new()) // Stub implementation
    }

    fn get_algorithm(
        &self,
    ) -> CustomResult<
        Box<dyn common_utils::crypto::VerifySignature + Send>,
        errors::ConnectorError,
    > {
        Ok(Box::new(common_utils::crypto::NoAlgorithm)) // Stub implementation
    }

    fn get_signature(
        &self,
        _payload: &[u8],
        _router_data: &domain_types::router_data_v2::RouterDataV2<
            PostAuthenticate,
            PaymentFlowData,
            PaymentsPostAuthenticateData<T>,
            PaymentsResponseData,
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

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        CreateConnectorCustomer,
        ConnectorCustomerData,
        ConnectorCustomerResponse,
        PaymentsResponseData,
    > for Fiuu<T>
{
    fn get_secrets(
        &self,
        _secrets: interfaces::verification::ConnectorSourceVerificationSecrets,
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(Vec::new()) // Stub implementation
    }

    fn get_algorithm(
        &self,
    ) -> CustomResult<
        Box<dyn common_utils::crypto::VerifySignature + Send>,
        errors::ConnectorError,
    > {
        Ok(Box::new(common_utils::crypto::NoAlgorithm)) // Stub implementation
    }

    fn get_signature(
        &self,
        _payload: &[u8],
        _router_data: &domain_types::router_data_v2::RouterDataV2<
            CreateConnectorCustomer,
            ConnectorCustomerData,
            ConnectorCustomerResponse,
            PaymentsResponseData,
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

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        VoidPC,
        PaymentFlowData,
        PaymentsCancelPostCaptureData,
        PaymentsResponseData,
    > for Fiuu<T>
{
    fn get_secrets(
        &self,
        _secrets: interfaces::verification::ConnectorSourceVerificationSecrets,
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(Vec::new()) // Stub implementation
    }

    fn get_algorithm(
        &self,
    ) -> CustomResult<
        Box<dyn common_utils::crypto::VerifySignature + Send>,
        errors::ConnectorError,
    > {
        Ok(Box::new(common_utils::crypto::NoAlgorithm)) // Stub implementation
    }

    fn get_signature(
        &self,
        _payload: &[u8],
        _router_data: &domain_types::router_data_v2::RouterDataV2<
            VoidPC,
            PaymentFlowData,
            PaymentsCancelPostCaptureData,
            PaymentsResponseData,
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