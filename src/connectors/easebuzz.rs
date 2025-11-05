// EaseBuzz Connector Implementation
pub mod constants;
pub mod transformers;

use std::marker::PhantomData;

use common_enums::{AttemptStatus, PaymentMethodType};
use common_utils::{
    crypto,
    errors::CustomResult,
    ext_traits::BytesExt,
    request::RequestContent,
    types::{self, StringMinorUnit},
};
use domain_types::{
    connector_flow::{Authorize, PSync, RSync},
    connector_types::{
        ConnectorCommon, ConnectorCommonV2, ConnectorIntegrationV2, ConnectorSpecifications,
        ConnectorWebhookSecrets, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData,
        PaymentsSyncData, RefundFlowData, RefundsData, RefundsResponseData, RefundSyncData,
    },
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data_v2::RouterDataV2,
    types as domain_types,
};
use error_stack::ResultExt;
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};

use self::transformers::{
    EaseBuzzPaymentsRequest, EaseBuzzPaymentsResponse, EaseBuzzPaymentsSyncRequest,
    EaseBuzzPaymentsSyncResponse, EaseBuzzRefundRequest, EaseBuzzRefundResponse,
    EaseBuzzRefundSyncRequest, EaseBuzzRefundSyncResponse,
};
use crate::utils;

// Create all prerequisites using the mandatory macro framework
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
        fn get_auth_header(&self, auth_type: &domain_types::ConnectorAuthType) -> CustomResult<Vec<(String, String)>, errors::ConnectorError> {
            match auth_type {
                domain_types::ConnectorAuthType::HeaderKey { api_key, .. } => {
                    Ok(vec![("Authorization".to_string(), format!("Bearer {}", api_key.peek()))])
                }
                domain_types::ConnectorAuthType::SignatureKey { api_key, .. } => {
                    Ok(vec![("Authorization".to_string(), format!("Bearer {}", api_key.peek()))])
                }
                _ => Err(errors::ConnectorError::AuthenticationFailed.into()),
            }
        }

        fn build_hash(&self, data: &str, salt: &str) -> String {
            let combined = format!("{}|{}", data, salt);
            crypto::Sha512::hash_bytes(combined.as_bytes()).to_string()
        }
    }
);

// Implement the connector using the mandatory macro framework
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
        fn get_api_tag(&self) -> &'static str {
            "payments"
        }
    }
);

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
        fn get_api_tag(&self) -> &'static str {
            "sync"
        }
    }
);

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
        fn get_api_tag(&self) -> &'static str {
            "refund"
        }
    }
);

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
        fn get_api_tag(&self) -> &'static str {
            "refund_sync"
        }
    }
);

// Implement ConnectorCommon trait for custom logic
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    ConnectorCommon for EaseBuzz<T>
{
    fn get_connector_name(&self) -> &'static str {
        "EaseBuzz"
    }

    fn get_base_url(&self) -> &'static str {
        if self.test_mode.unwrap_or(false) {
            "https://testpay.easebuzz.in"
        } else {
            "https://pay.easebuzz.in"
        }
    }

    fn build_request(
        &self,
        req: &domain_types::RouterData,
        connectors: &domain_types::Connectors,
    ) -> CustomResult<domain_types::Request, errors::ConnectorError> {
        let auth = self.get_auth_header(&connectors.auth_type)?;
        Ok(domain_types::Request {
            url: self.base_url.to_string(),
            method: domain_types::Method::Post,
            headers: auth,
            body: RequestContent::Json("{}".to_string()),
            encoding: None,
        })
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    ConnectorCommonV2 for EaseBuzz<T>
{
    fn get_connector_name(&self) -> &'static str {
        "EaseBuzz"
    }

    fn get_base_url(&self) -> &'static str {
        if self.test_mode.unwrap_or(false) {
            "https://testpay.easebuzz.in"
        } else {
            "https://pay.easebuzz.in"
        }
    }

    fn get_content_type(&self) -> &'static str {
        "application/json"
    }
}

// Stub types for unimplemented flows
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

// Implement not-implemented flows
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

// Use macro for all unimplemented flows
impl_not_implemented_flow!(domain_types::connector_flow::Void, PaymentFlowData, domain_types::PaymentVoidData, PaymentsResponseData);
impl_not_implemented_flow!(domain_types::connector_flow::Capture, PaymentFlowData, domain_types::PaymentsCaptureData, PaymentsResponseData);
impl_not_implemented_flow!(domain_types::connector_flow::CreateOrder, PaymentFlowData, domain_types::PaymentCreateOrderData, domain_types::PaymentCreateOrderResponse);
impl_not_implemented_flow!(domain_types::connector_flow::CreateSessionToken, PaymentFlowData, domain_types::SessionTokenRequestData, domain_types::SessionTokenResponseData);
impl_not_implemented_flow!(domain_types::connector_flow::SetupMandate, PaymentFlowData, domain_types::SetupMandateRequestData, domain_types::SetupMandateRequestData);
impl_not_implemented_flow!(domain_types::connector_flow::Accept, PaymentFlowData, domain_types::AcceptDisputeData, domain_types::DisputeResponseData);
impl_not_implemented_flow!(domain_types::connector_flow::DefendDispute, PaymentFlowData, domain_types::DisputeDefendData, domain_types::DisputeResponseData);
impl_not_implemented_flow!(domain_types::connector_flow::SubmitEvidence, PaymentFlowData, domain_types::SubmitEvidenceData, domain_types::DisputeResponseData);
impl_not_implemented_flow!(domain_types::connector_flow::RepeatPayment, PaymentFlowData, domain_types::RepeatPaymentData, PaymentsResponseData);

// Source verification stubs
macros::impl_source_verification_stub!(Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData);
macros::impl_source_verification_stub!(PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData);
macros::impl_source_verification_stub!(RSync, PaymentFlowData, RefundSyncData, RefundsResponseData);
macros::impl_source_verification_stub!(Refund, PaymentFlowData, RefundFlowData, RefundsResponseData);
macros::impl_source_verification_stub!(domain_types::connector_flow::Void, PaymentFlowData, domain_types::PaymentVoidData, PaymentsResponseData);
macros::impl_source_verification_stub!(domain_types::connector_flow::Capture, PaymentFlowData, domain_types::PaymentsCaptureData, PaymentsResponseData);
macros::impl_source_verification_stub!(domain_types::connector_flow::CreateOrder, PaymentFlowData, domain_types::PaymentCreateOrderData, domain_types::PaymentCreateOrderResponse);
macros::impl_source_verification_stub!(domain_types::connector_flow::CreateSessionToken, PaymentFlowData, domain_types::SessionTokenRequestData, domain_types::SessionTokenResponseData);
macros::impl_source_verification_stub!(domain_types::connector_flow::SetupMandate, PaymentFlowData, domain_types::SetupMandateRequestData, domain_types::SetupMandateRequestData);
macros::impl_source_verification_stub!(domain_types::connector_flow::Accept, PaymentFlowData, domain_types::AcceptDisputeData, domain_types::DisputeResponseData);
macros::impl_source_verification_stub!(domain_types::connector_flow::DefendDispute, PaymentFlowData, domain_types::DisputeDefendData, domain_types::DisputeResponseData);
macros::impl_source_verification_stub!(domain_types::connector_flow::SubmitEvidence, PaymentFlowData, domain_types::SubmitEvidenceData, domain_types::DisputeResponseData);
macros::impl_source_verification_stub!(domain_types::connector_flow::RepeatPayment, PaymentFlowData, domain_types::RepeatPaymentData, PaymentsResponseData);

// Implement all connector types traits
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    domain_types::connector_types::PaymentOrderCreate for EaseBuzz<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    domain_types::connector_types::PaymentSessionToken for EaseBuzz<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    domain_types::connector_types::PaymentVoidV2 for EaseBuzz<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    domain_types::connector_types::PaymentCaptureV2 for EaseBuzz<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    domain_types::connector_types::MandateSetupV2 for EaseBuzz<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    domain_types::connector_types::DisputeAccept for EaseBuzz<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    domain_types::connector_types::DisputeDefend for EaseBuzz<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    domain_types::connector_types::DisputeSubmitEvidence for EaseBuzz<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    domain_types::connector_types::PaymentRepeatV2 for EaseBuzz<T> {}

// Connector specifications
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    ConnectorSpecifications for EaseBuzz<T>
{
    fn get_supported_payment_methods(&self) -> Vec<PaymentMethodType> {
        vec![PaymentMethodType::Upi, PaymentMethodType::UpiCollect, PaymentMethodType::UpiIntent]
    }

    fn get_supported_capture_methods(&self) -> Vec<domain_types::CaptureMethod> {
        vec![domain_types::CaptureMethod::Automatic]
    }

    fn get_webhook_secret(&self) -> Option<&ConnectorWebhookSecrets> {
        None
    }
}