pub mod transformers;

use std::fmt::Debug;

use common_utils::{
    errors::CustomResult,
    types::{StringMinorUnit},
};
use domain_types::{
    connector_flow::{Authorize, PSync, RSync},
    connector_types::{
        PaymentFlowData, PaymentsAuthorizeData,
        PaymentsResponseData, PaymentsSyncData, RefundSyncData, RefundsResponseData,
    },
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
};
use error_stack::ResultExt;
use hyperswitch_masking::{Maskable, Secret};
use interfaces::{
    api::ConnectorCommon,
    connector_integration_v2::ConnectorIntegrationV2,
    connector_types,
};
use serde::Serialize;
use transformers::{ZaakPayPaymentsRequest, ZaakPayPaymentsResponse, ZaakPayPaymentsSyncRequest, ZaakPayPaymentsSyncResponse, ZaakPayRefundSyncRequest, ZaakPayRefundSyncResponse};

use super::macros;

// Create all prerequisites using the mandatory macro framework
macros::create_all_prerequisites!(
    connector_name: ZaakPay,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: ZaakPayPaymentsRequest,
            response_body: ZaakPayPaymentsResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: PSync,
            request_body: ZaakPayPaymentsSyncRequest,
            response_body: ZaakPayPaymentsSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ),
        (
            flow: RSync,
            request_body: ZaakPayRefundSyncRequest,
            response_body: ZaakPayRefundSyncResponse,
            router_data: RouterDataV2<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>,
        )
    ],
    amount_converters: [
        amount_converter: StringMinorUnit
    ],
    member_functions: {
        get_content_type: || Some("application/json".to_string()),
        get_error_response_v2: |response: &[u8]| {
            let error_response: Result<transformers::ZaakPayErrorResponse, _> = serde_json::from_slice(response);
            error_response.map_err(|_| errors::ConnectorError::ResponseDeserializationFailed).map(|err| ErrorResponse {
                code: err.response_code,
                message: err.response_description,
                status_code: None,
                reason: None,
            })
        },
        get_api_tag: |flow| {
            match flow {
                domain_types::connector_flow::Flow::Authorize => "transact",
                domain_types::connector_flow::Flow::PSync => "check",
                domain_types::connector_flow::Flow::RSync => "check",
                _ => "unknown",
            }
        }
    }
);

// Implement the connector using the mandatory macro framework
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: ZaakPay,
    curl_request: Json(ZaakPayPaymentsRequest),
    curl_response: ZaakPayPaymentsResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
    other_functions: {}
);

// PSync flow implementation
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: ZaakPay,
    curl_request: Json(ZaakPayPaymentsSyncRequest),
    curl_response: ZaakPayPaymentsSyncResponse,
    flow_name: PSync,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsSyncData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
    other_functions: {}
);

// RSync flow implementation
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: ZaakPay,
    curl_request: Json(ZaakPayRefundSyncRequest),
    curl_response: ZaakPayRefundSyncResponse,
    flow_name: RSync,
    resource_common_data: PaymentFlowData,
    flow_request: RefundSyncData,
    flow_response: RefundsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
    other_functions: {}
);

// ConnectorCommon implementation for base URL and authentication
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    ConnectorCommon for ZaakPay<T>
{
    fn id(&self) -> &'static str {
        "zaakpay"
    }

    fn base_url<'a>(&self, _auth_type: &'a domain_types::types::Connectors) -> &'a str {
        "https://api.zaakpay.com"
    }

    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        match auth_type {
            ConnectorAuthType::HeaderKey { api_key } => {
                Ok(vec![("Authorization".to_string(), Maskable::new(api_key.clone()))])
            }
            _ => Err(errors::ConnectorError::AuthenticationFailed.into()),
        }
    }
}

// Implement source verification stubs for all flows
macros::impl_source_verification_stub!(Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData);
macros::impl_source_verification_stub!(PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData);
macros::impl_source_verification_stub!(RSync, PaymentFlowData, RefundSyncData, RefundsResponseData);

// Stub types for unimplemented flows
#[derive(Debug, Clone, Serialize)]
pub struct ZaakPayVoidRequest;
#[derive(Debug, Clone)]
pub struct ZaakPayVoidResponse;

#[derive(Debug, Clone, Serialize)]
pub struct ZaakPayCaptureRequest;
#[derive(Debug, Clone)]
pub struct ZaakPayCaptureResponse;

#[derive(Debug, Clone, Serialize)]
pub struct ZaakPayRefundRequest;
#[derive(Debug, Clone)]
pub struct ZaakPayRefundResponse;

#[derive(Debug, Clone, Serialize)]
pub struct ZaakPayCreateOrderRequest;
#[derive(Debug, Clone)]
pub struct ZaakPayCreateOrderResponse;

#[derive(Debug, Clone, Serialize)]
pub struct ZaakPaySessionTokenRequest;
#[derive(Debug, Clone)]
pub struct ZaakPaySessionTokenResponse;

#[derive(Debug, Clone, Serialize)]
pub struct ZaakPaySetupMandateRequest;
#[derive(Debug, Clone)]
pub struct ZaakPaySetupMandateResponse;

#[derive(Debug, Clone, Serialize)]
pub struct ZaakPayRepeatPaymentRequest;
#[derive(Debug, Clone)]
pub struct ZaakPayRepeatPaymentResponse;

#[derive(Debug, Clone, Serialize)]
pub struct ZaakPayAcceptDisputeRequest;
#[derive(Debug, Clone)]
pub struct ZaakPayAcceptDisputeResponse;

#[derive(Debug, Clone, Serialize)]
pub struct ZaakPayDefendDisputeRequest;
#[derive(Debug, Clone)]
pub struct ZaakPayDefendDisputeResponse;

#[derive(Debug, Clone, Serialize)]
pub struct ZaakPaySubmitEvidenceRequest;
#[derive(Debug, Clone)]
pub struct ZaakPaySubmitEvidenceResponse;

// Implement not-implemented flows
macro_rules! impl_not_implemented_flow {
    ($flow:ty, $common_data:ty, $req:ty, $resp:ty) => {
        impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
            ConnectorIntegrationV2<$flow, $common_data, $req, $resp> for ZaakPay<T>
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

// Apply not-implemented macro to all unsupported flows
impl_not_implemented_flow!(domain_types::connector_flow::Void, PaymentFlowData, domain_types::connector_types::PaymentVoidData, PaymentsResponseData);
impl_not_implemented_flow!(domain_types::connector_flow::Capture, PaymentFlowData, domain_types::connector_types::PaymentsCaptureData, PaymentsResponseData);
impl_not_implemented_flow!(domain_types::connector_flow::Refund, PaymentFlowData, domain_types::connector_types::RefundsData, RefundsResponseData);
impl_not_implemented_flow!(domain_types::connector_flow::CreateOrder, PaymentFlowData, domain_types::connector_types::PaymentCreateOrderData, domain_types::connector_types::PaymentCreateOrderResponse);
impl_not_implemented_flow!(domain_types::connector_flow::CreateSessionToken, PaymentFlowData, domain_types::connector_types::SessionTokenRequestData, domain_types::connector_types::SessionTokenResponseData);
impl_not_implemented_flow!(domain_types::connector_flow::SetupMandate, PaymentFlowData, domain_types::connector_types::SetupMandateRequestData<T>, domain_types::connector_types::SetupMandateRequestData<T>);
impl_not_implemented_flow!(domain_types::connector_flow::RepeatPayment, PaymentFlowData, domain_types::connector_types::RepeatPaymentData, domain_types::connector_types::RepeatPaymentData);
impl_not_implemented_flow!(domain_types::connector_flow::Accept, PaymentFlowData, domain_types::connector_types::AcceptDisputeData, domain_types::connector_types::DisputeResponseData);
impl_not_implemented_flow!(domain_types::connector_flow::DefendDispute, PaymentFlowData, domain_types::connector_types::DisputeDefendData, domain_types::connector_types::DisputeResponseData);
impl_not_implemented_flow!(domain_types::connector_flow::SubmitEvidence, PaymentFlowData, domain_types::connector_types::SubmitEvidenceData, domain_types::connector_types::DisputeResponseData);

// Implement all connector type traits
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::PaymentOrderCreate for ZaakPay<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::PaymentSessionToken for ZaakPay<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::PaymentVoidV2 for ZaakPay<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::PaymentCapture for ZaakPay<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::PaymentRefund for ZaakPay<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::RefundExecute for ZaakPay<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::RefundSyncV2 for ZaakPay<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::MandateSetup for ZaakPay<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::PaymentTokenV2<T> for ZaakPay<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::DisputeAccept for ZaakPay<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::DisputeDefend for ZaakPay<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::SubmitEvidenceV2 for ZaakPay<T> {}