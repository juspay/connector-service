// EaseBuzz Connector Implementation
pub mod transformers;

use common_enums::{AttemptStatus, PaymentMethodType};
use common_utils::{
    crypto,
    errors::CustomResult,
    ext_traits::BytesExt,
    request::RequestContent,
    types::{self, StringMinorUnit},
};
use domain_types::{
    connector_flow::{
        Accept, Authorize, Capture, CreateOrder, CreateSessionToken, DefendDispute, PSync, RSync,
        Refund, RepeatPayment, SetupMandate, SubmitEvidence, Void,
    },
    connector_types::{
        AcceptDisputeData, ConnectorWebhookSecrets, DisputeDefendData, DisputeFlowData,
        DisputeResponseData, PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData,
        PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData,
        PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData,
        RepeatPaymentData, ResponseId, SessionTokenRequestData, SessionTokenResponseData,
        SetupMandateRequestData, SubmitEvidenceData,
    },
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
};
use error_stack::ResultExt;
use hyperswitch_masking::{Mask, Maskable, PeekInterface, Secret};
use interfaces::{
    api::ConnectorCommon,
    connector_integration_v2::ConnectorIntegrationV2,
    connector_types,
    events::connector_api_logs::ConnectorEvent,
    verification::{ConnectorSourceVerificationSecrets, SourceVerification},
};
use serde::Serialize;

use self::transformers::{
    EaseBuzzPaymentsRequest, EaseBuzzPaymentsResponse, EaseBuzzPaymentsSyncRequest,
    EaseBuzzPaymentsSyncResponse, EaseBuzzRefundRequest, EaseBuzzRefundResponse,
    EaseBuzzRefundSyncRequest, EaseBuzzRefundSyncResponse,
};

use super::macros;
use crate::{types::ResponseRouterData, with_error_response_body};

// Source verification stub macro
macro_rules! impl_source_verification_stub {
    ($flow:ty, $common_data:ty, $req:ty, $resp:ty) => {
        impl<
                T: PaymentMethodDataTypes
                    + std::fmt::Debug
                    + std::marker::Sync
                    + std::marker::Send
                    + 'static
                    + Serialize,
            > SourceVerification<$flow, $common_data, $req, $resp> for EaseBuzz<T>
        {
            fn get_secrets(
                &self,
                _secrets: ConnectorSourceVerificationSecrets,
            ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
                Ok(Vec::new()) // STUB - will be implemented in Phase 10
            }
            fn get_algorithm(
                &self,
            ) -> CustomResult<String, errors::ConnectorError> {
                Ok("SHA256".to_string())
            }
        }
    };
}

// Create all prerequisites using UCS v2 macro framework
macros::create_all_prerequisites!(
    connector_name: EaseBuzz,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: EaseBuzzPaymentsRequest,
            response_body: EaseBuzzPaymentsResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: PSync,
            request_body: EaseBuzzPaymentsSyncRequest,
            response_body: EaseBuzzPaymentsSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ),
        (
            flow: RSync,
            request_body: EaseBuzzRefundSyncRequest,
            response_body: EaseBuzzRefundSyncResponse,
            router_data: RouterDataV2<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>,
        ),
        (
            flow: Refund,
            request_body: EaseBuzzRefundRequest,
            response_body: EaseBuzzRefundResponse,
            router_data: RouterDataV2<Refund, PaymentFlowData, RefundFlowData, RefundsResponseData>,
        )
    ],
    amount_converters: [
        amount_converter: StringMinorUnit
    ],
    member_functions: {
        fn get_api_tag(&self) -> &'static str {
            "EaseBuzz"
        }
    }
);

// Implement connector common traits
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    ConnectorCommon for EaseBuzz<T>
{
    fn id(&self) -> &'static str {
        "easebuzz"
    }

    fn base_url(&self) -> &'static str {
        "https://pay.easebuzz.in"
    }

    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<
        Vec<(String, hyperswitch_masking::Maskable<String>)>,
        domain_types::errors::ConnectorError,
    > {
        match auth_type {
            ConnectorAuthType::SignatureKey { api_key, key1 } => {
                Ok(vec![(
                    "Authorization".to_string(),
                    hyperswitch_masking::Maskable::new(format!("Basic {}:{}", api_key.expose(), key1.expose())),
                )])
            }
            _ => Err(domain_types::errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

// Implement Authorize flow using macro framework
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: EaseBuzz,
    curl_request: Json(EaseBuzzPaymentsRequest),
    curl_response: EaseBuzzPaymentsResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
    other_functions: {
        fn build_request_v2(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<Option<common_utils::request::Request>, errors::ConnectorError> {
            let is_test = req.resource_common_data.test_mode.unwrap_or(false);
            let base_url = if is_test {
                self.get_test_base_url()
            } else {
                self.get_base_url()
            };

            let endpoint = match req.request.payment_method_type {
                PaymentMethodType::Upi => "/payment/initiateLink",
                _ => return Err(errors::ConnectorError::NotImplemented("Payment method not supported".to_string()).into()),
            };

            let url = format!("{}{}", base_url, endpoint);
            let request = EaseBuzzPaymentsRequest::try_from(req)?;

            Ok(Some(common_utils::request::RequestBuilder::new()
                .method(common_utils::request::RequestMethod::Post)
                .url(&url)
                .attach_default_headers()
                .headers(vec![(
                    "Content-Type".to_string(),
                    "application/json".to_string(),
                )])
                .body(RequestContent::Json(request))
                .build()))
        }
    }
);

// Implement PSync flow using macro framework
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: EaseBuzz,
    curl_request: Json(EaseBuzzPaymentsSyncRequest),
    curl_response: EaseBuzzPaymentsSyncResponse,
    flow_name: PSync,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsSyncData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
    other_functions: {
        fn build_request_v2(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<Option<common_utils::request::Request>, errors::ConnectorError> {
            let is_test = req.resource_common_data.test_mode.unwrap_or(false);
            let base_url = if is_test {
                self.get_test_base_url()
            } else {
                self.get_base_url()
            };

            let url = format!("{}/payment/txnSync", base_url);
            let request = EaseBuzzPaymentsSyncRequest::try_from(req)?;

            Ok(Some(common_utils::request::RequestBuilder::new()
                .method(common_utils::request::RequestMethod::Post)
                .url(&url)
                .attach_default_headers()
                .headers(vec![(
                    "Content-Type".to_string(),
                    "application/json".to_string(),
                )])
                .body(RequestContent::Json(request))
                .build()))
        }
    }
);

// Implement Refund flow using macro framework
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: EaseBuzz,
    curl_request: Json(EaseBuzzRefundRequest),
    curl_response: EaseBuzzRefundResponse,
    flow_name: Refund,
    resource_common_data: PaymentFlowData,
    flow_request: RefundFlowData,
    flow_response: RefundsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
    other_functions: {
        fn build_request_v2(
            &self,
            req: &RouterDataV2<Refund, PaymentFlowData, RefundFlowData, RefundsResponseData>,
        ) -> CustomResult<Option<common_utils::request::Request>, errors::ConnectorError> {
            let is_test = req.resource_common_data.test_mode.unwrap_or(false);
            let base_url = if is_test {
                self.get_test_base_url()
            } else {
                self.get_base_url()
            };

            let url = format!("{}/transaction/refund", base_url);
            let request = EaseBuzzRefundRequest::try_from(req)?;

            Ok(Some(common_utils::request::RequestBuilder::new()
                .method(common_utils::request::RequestMethod::Post)
                .url(&url)
                .attach_default_headers()
                .headers(vec![(
                    "Content-Type".to_string(),
                    "application/json".to_string(),
                )])
                .body(RequestContent::Json(request))
                .build()))
        }
    }
);

// Implement RSync flow using macro framework
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: EaseBuzz,
    curl_request: Json(EaseBuzzRefundSyncRequest),
    curl_response: EaseBuzzRefundSyncResponse,
    flow_name: RSync,
    resource_common_data: PaymentFlowData,
    flow_request: RefundSyncData,
    flow_response: RefundsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
    other_functions: {
        fn build_request_v2(
            &self,
            req: &RouterDataV2<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>,
        ) -> CustomResult<Option<common_utils::request::Request>, errors::ConnectorError> {
            let is_test = req.resource_common_data.test_mode.unwrap_or(false);
            let base_url = if is_test {
                self.get_test_base_url()
            } else {
                self.get_base_url()
            };

            let url = format!("{}/transaction/refundSync", base_url);
            let request = EaseBuzzRefundSyncRequest::try_from(req)?;

            Ok(Some(common_utils::request::RequestBuilder::new()
                .method(common_utils::request::RequestMethod::Post)
                .url(&url)
                .attach_default_headers()
                .headers(vec![(
                    "Content-Type".to_string(),
                    "application/json".to_string(),
                )])
                .body(RequestContent::Json(request))
                .build()))
        }
    }
);

// Add source verification stubs for all flows
impl_source_verification_stub!(Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData);
impl_source_verification_stub!(PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData);
impl_source_verification_stub!(Refund, PaymentFlowData, RefundFlowData, RefundsResponseData);
impl_source_verification_stub!(RSync, PaymentFlowData, RefundSyncData, RefundsResponseData);

// Implement connector types traits
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::PaymentAuthorizeV2 for EaseBuzz<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::PaymentSyncV2 for EaseBuzz<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::PaymentRefundV2 for EaseBuzz<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::RefundSyncV2 for EaseBuzz<T>
{
}

// Stub implementations for unsupported flows
#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzVoidRequest;
#[derive(Debug, Clone)]
pub struct EaseBuzzVoidResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzCaptureRequest;
#[derive(Debug, Clone)]
pub struct EaseBuzzCaptureResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzCreateOrderRequest;
#[derive(Debug, Clone)]
pub struct EaseBuzzCreateOrderResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzSessionTokenRequest;
#[derive(Debug, Clone)]
pub struct EaseBuzzSessionTokenResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzSetupMandateRequest;
#[derive(Debug, Clone)]
pub struct EaseBuzzSetupMandateResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzAcceptDisputeRequest;
#[derive(Debug, Clone)]
pub struct EaseBuzzAcceptDisputeResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzDefendDisputeRequest;
#[derive(Debug, Clone)]
pub struct EaseBuzzDefendDisputeResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzSubmitEvidenceRequest;
#[derive(Debug, Clone)]
pub struct EaseBuzzSubmitEvidenceResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzRepeatPaymentRequest;
#[derive(Debug, Clone)]
pub struct EaseBuzzRepeatPaymentResponse;

// Implement all connector types traits (even for unsupported flows)
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::PaymentVoidV2 for EaseBuzz<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::PaymentCaptureV2 for EaseBuzz<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::PaymentOrderCreate for EaseBuzz<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::PaymentSessionToken for EaseBuzz<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::PaymentSetupMandate for EaseBuzz<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::DisputeAccept for EaseBuzz<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::DisputeDefend for EaseBuzz<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::DisputeSubmitEvidence for EaseBuzz<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::PaymentRepeatPayment for EaseBuzz<T>
{
}

// Macro for not implemented flows
macro_rules! impl_not_implemented_flow {
    ($flow:ty, $common_data:ty, $req:ty, $resp:ty) => {
        impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
            ConnectorIntegrationV2<$flow, $common_data, $req, $resp> for EaseBuzz<T>
        {
            fn build_request_v2(
                &self,
                _req: &RouterDataV2<$flow, $common_data, $req, $resp>,
            ) -> CustomResult<Option<common_utils::request::Request>, errors::ConnectorError> {
                let flow_name = stringify!($flow);
                Err(errors::ConnectorError::NotImplemented(flow_name.to_string()).into())
            }
        }
    };
}

// Apply not implemented macro to unsupported flows
impl_not_implemented_flow!(Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData);
impl_not_implemented_flow!(Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData);
impl_not_implemented_flow!(CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse);
impl_not_implemented_flow!(CreateSessionToken, PaymentFlowData, SessionTokenRequestData, SessionTokenResponseData);
impl_not_implemented_flow!(SetupMandate, PaymentFlowData, SetupMandateRequestData, SetupMandateResponseData);
impl_not_implemented_flow!(Accept, PaymentFlowData, AcceptDisputeData, DisputeResponseData);
impl_not_implemented_flow!(DefendDispute, PaymentFlowData, DisputeDefendData, DisputeResponseData);
impl_not_implemented_flow!(SubmitEvidence, PaymentFlowData, SubmitEvidenceData, DisputeResponseData);
impl_not_implemented_flow!(RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData);