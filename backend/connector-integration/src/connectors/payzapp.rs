pub mod transformers;

use common_enums::{Currency, PaymentMethodType};
use common_utils::{
    errors::CustomResult,
    ext_traits::BytesExt,
    request::Method,
    types::{StringMinorUnit},
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
use transformers::{self as payzapp, PayZappPaymentsRequest, PayZappPaymentsResponse, PayZappPaymentsSyncRequest, PayZappPaymentsSyncResponse, PayZappVoidRequest, PayZappVoidResponse, PayZappCaptureRequest, PayZappCaptureResponse, PayZappRefundRequest, PayZappRefundResponse, PayZappRefundSyncRequest, PayZappRefundSyncResponse, PayZappCreateOrderRequest, PayZappCreateOrderResponse, PayZappSessionTokenRequest, PayZappSessionTokenResponse, PayZappSetupMandateRequest, PayZappSetupMandateResponse, PayZappRepeatPaymentRequest, PayZappRepeatPaymentResponse, PayZappAcceptDisputeRequest, PayZappAcceptDisputeResponse, PayZappDefendDisputeRequest, PayZappDefendDisputeResponse, PayZappSubmitEvidenceRequest, PayZappSubmitEvidenceResponse};

use super::macros;
use crate::{types::ResponseRouterData, with_error_response_body};

pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const AUTHORIZATION: &str = "Authorization";
}

// Create all prerequisites using the mandatory macro framework
macros::create_all_prerequisites!(
    connector_name: PayZapp,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: PayZappPaymentsRequest,
            response_body: PayZappPaymentsResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: PSync,
            request_body: PayZappPaymentsSyncRequest,
            response_body: PayZappPaymentsSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ),
        // Stub types for unsupported flows - MANDATORY to avoid compilation errors
        (
            flow: Void,
            request_body: PayZappVoidRequest,
            response_body: PayZappVoidResponse,
            router_data: RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ),
        (
            flow: Capture,
            request_body: PayZappCaptureRequest,
            response_body: PayZappCaptureResponse,
            router_data: RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ),
        (
            flow: Refund,
            request_body: PayZappRefundRequest,
            response_body: PayZappRefundResponse,
            router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ),
        (
            flow: RSync,
            request_body: PayZappRefundSyncRequest,
            response_body: PayZappRefundSyncResponse,
            router_data: RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ),
        (
            flow: CreateOrder,
            request_body: PayZappCreateOrderRequest,
            response_body: PayZappCreateOrderResponse,
            router_data: RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>,
        ),
        (
            flow: CreateSessionToken,
            request_body: PayZappSessionTokenRequest,
            response_body: PayZappSessionTokenResponse,
            router_data: RouterDataV2<CreateSessionToken, PaymentFlowData, SessionTokenRequestData, SessionTokenResponseData>,
        ),
        (
            flow: SetupMandate,
            request_body: PayZappSetupMandateRequest,
            response_body: PayZappSetupMandateResponse,
            router_data: RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData>,
        ),
        (
            flow: RepeatPayment,
            request_body: PayZappRepeatPaymentRequest,
            response_body: PayZappRepeatPaymentResponse,
            router_data: RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>,
        ),
        (
            flow: Accept,
            request_body: PayZappAcceptDisputeRequest,
            response_body: PayZappAcceptDisputeResponse,
            router_data: RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>,
        ),
        (
            flow: DefendDispute,
            request_body: PayZappDefendDisputeRequest,
            response_body: PayZappDefendDisputeResponse,
            router_data: RouterDataV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>,
        ),
        (
            flow: SubmitEvidence,
            request_body: PayZappSubmitEvidenceRequest,
            response_body: PayZappSubmitEvidenceResponse,
            router_data: RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>,
        )
    ],
    amount_converters: [
        amount_converter: StringMinorUnit
    ],
    member_functions: {
        fn get_api_tag(&self) -> &'static str {
            "PayZapp"
        }

        fn get_base_url(&self, req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>) -> String {
            let is_test = req.resource_common_data.test_mode.unwrap_or(false);
            if is_test {
                "https://app.pc.enstage-sas.com".to_string()
            } else {
                "https://app.wibmo.com".to_string()
            }
        }

        fn get_charge_base_url(&self, req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>) -> String {
            let is_test = req.resource_common_data.test_mode.unwrap_or(false);
            if is_test {
                "https://api.pc.enstage-sas.com".to_string()
            } else {
                "https://api.wibmo.com".to_string()
            }
        }
    }
);

// MANDATORY: Use macro_connector_implementation for Authorize flow
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: PayZapp,
    curl_request: Json(PayZappPaymentsRequest),
    curl_response: PayZappPaymentsResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
    other_functions: {
        fn get_url(&self, req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>) -> CustomResult<String, errors::ConnectorError> {
            let base_url = self.get_base_url(req);
            Ok(format!("{}/payment/merchant/init", base_url))
        }
    }
);

// MANDATORY: Use macro_connector_implementation for PSync flow
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: PayZapp,
    curl_request: Json(PayZappPaymentsSyncRequest),
    curl_response: PayZappPaymentsSyncResponse,
    flow_name: PSync,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsSyncData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
    other_functions: {
        fn get_url(&self, req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>) -> CustomResult<String, errors::ConnectorError> {
            let is_test = req.resource_common_data.test_mode.unwrap_or(false);
            let base_url = if is_test {
                "https://api.pc.enstage-sas.com"
            } else {
                "https://api.wibmo.com"
            };
            Ok(format!("{}/v2/in/txn/iap/wpay/enquiry", base_url))
        }
    }
);

// MANDATORY: Implement all connector_types traits even for unused flows
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize> 
    connector_types::PaymentOrderCreate for PayZapp<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize> 
    connector_types::PaymentSessionToken for PayZapp<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize> 
    connector_types::PaymentVoidV2 for PayZapp<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize> 
    connector_types::PaymentCapture for PayZapp<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize> 
    connector_types::PaymentRefund for PayZapp<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize> 
    connector_types::RefundSyncV2 for PayZapp<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize> 
    connector_types::PaymentRepeat for PayZapp<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize> 
    connector_types::MandateSetup for PayZapp<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize> 
    connector_types::AcceptDispute for PayZapp<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize> 
    connector_types::DefendDispute for PayZapp<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize> 
    connector_types::SubmitEvidenceV2 for PayZapp<T> {}

// MANDATORY: Implement ConnectorCommon trait
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize> 
    ConnectorCommon for PayZapp<T> {
    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: payzapp::PayZappErrorResponse = res
            .response
            .parse_struct("PayZappErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        event_builder.map(|i| i.set_error_response(&response));

        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response.res_code,
            message: response.res_desc,
            reason: None,
            attempt_status: None,
        })
    }
}

// MANDATORY: Add not-implemented flow handlers for all unimplemented flows
macro_rules! impl_not_implemented_flow {
    ($flow:ty, $common_data:ty, $req:ty, $resp:ty) => {
        impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
            ConnectorIntegrationV2<$flow, $common_data, $req, $resp> for PayZapp<T>
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
impl_not_implemented_flow!(Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData);
impl_not_implemented_flow!(Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData);
impl_not_implemented_flow!(Refund, RefundFlowData, RefundsData, RefundsResponseData);
impl_not_implemented_flow!(RSync, RefundFlowData, RefundSyncData, RefundsResponseData);
impl_not_implemented_flow!(CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse);
impl_not_implemented_flow!(CreateSessionToken, PaymentFlowData, SessionTokenRequestData, SessionTokenResponseData);
impl_not_implemented_flow!(SetupMandate, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData);
impl_not_implemented_flow!(RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData);
impl_not_implemented_flow!(Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData);
impl_not_implemented_flow!(DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData);
impl_not_implemented_flow!(SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData);