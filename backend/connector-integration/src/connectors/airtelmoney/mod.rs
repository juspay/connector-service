// AirtelMoney Connector Implementation
pub mod constants;
pub mod transformers;

use common_utils::{
    errors::CustomResult,
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
use transformers::{self as airtelmoney, AirtelMoneyPaymentsRequest, AirtelMoneyPaymentsResponse};

use super::macros;
use crate::{types::ResponseRouterData, with_error_response_body};

macros::create_all_prerequisites!(
    connector_name: AirtelMoney,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: AirtelMoneyPaymentsRequest,
            response_body: AirtelMoneyPaymentsResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: PSync,
            request_body: AirtelMoneyPaymentsSyncRequest,
            response_body: AirtelMoneyPaymentsResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ),
        (
            flow: RSync,
            request_body: AirtelMoneyRefundSyncRequest,
            response_body: AirtelMoneyRefundResponse,
            router_data: RouterDataV2<RSync, RefundSyncData, RefundSyncData, RefundsResponseData>,
        ),
        (
            flow: Refund,
            request_body: AirtelMoneyRefundRequest,
            response_body: AirtelMoneyRefundResponse,
            router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ),
        (
            flow: Void,
            request_body: AirtelMoneyVoidRequest,
            response_body: AirtelMoneyVoidResponse,
            router_data: RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ),
        (
            flow: Capture,
            request_body: AirtelMoneyCaptureRequest,
            response_body: AirtelMoneyCaptureResponse,
            router_data: RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ),
        (
            flow: CreateOrder,
            request_body: AirtelMoneyCreateOrderRequest,
            response_body: AirtelMoneyCreateOrderResponse,
            router_data: RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>,
        ),
        (
            flow: CreateSessionToken,
            request_body: AirtelMoneySessionTokenRequest,
            response_body: AirtelMoneySessionTokenResponse,
            router_data: RouterDataV2<CreateSessionToken, PaymentFlowData, SessionTokenRequestData, SessionTokenResponseData>,
        ),
        (
            flow: SetupMandate,
            request_body: AirtelMoneySetupMandateRequest,
            response_body: AirtelMoneySetupMandateResponse,
            router_data: RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData>,
        ),
        (
            flow: RepeatPayment,
            request_body: AirtelMoneyRepeatPaymentRequest,
            response_body: AirtelMoneyRepeatPaymentResponse,
            router_data: RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>,
        ),
        (
            flow: Accept,
            request_body: AirtelMoneyAcceptDisputeRequest,
            response_body: AirtelMoneyAcceptDisputeResponse,
            router_data: RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>,
        ),
        (
            flow: DefendDispute,
            request_body: AirtelMoneyDefendDisputeRequest,
            response_body: AirtelMoneyDefendDisputeResponse,
            router_data: RouterDataV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>,
        ),
        (
            flow: SubmitEvidence,
            request_body: AirtelMoneySubmitEvidenceRequest,
            response_body: AirtelMoneySubmitEvidenceResponse,
            router_data: RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>,
        )
    ],
    amount_converters: [
        amount_converter: StringMinorUnit
    ],
    member_functions: {
        fn get_api_tag(&self) -> &'static str {
            "airtelmoney"
        }
    }
);

// Implement connector traits for all flows
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize> 
    connector_types::PaymentOrderCreate for AirtelMoney<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize> 
    connector_types::PaymentSessionToken for AirtelMoney<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize> 
    connector_types::PaymentVoidV2 for AirtelMoney<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize> 
    connector_types::PaymentCaptureV2 for AirtelMoney<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize> 
    connector_types::PaymentRefundV2 for AirtelMoney<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize> 
    connector_types::RefundSyncV2 for AirtelMoney<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize> 
    connector_types::PaymentSetupMandate for AirtelMoney<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize> 
    connector_types::PaymentRepeatPayment for AirtelMoney<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize> 
    connector_types::DisputeAccept for AirtelMoney<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize> 
    connector_types::DisputeDefend for AirtelMoney<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize> 
    connector_types::DisputeSubmitEvidence for AirtelMoney<T> {}

// Macro for not implemented flows
macro_rules! impl_not_implemented_flow {
    ($flow:ty, $common_data:ty, $req:ty, $resp:ty) => {
        impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
            ConnectorIntegrationV2<$flow, $common_data, $req, $resp> for AirtelMoney<T>
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

// Implement not implemented flows
impl_not_implemented_flow!(Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData);
impl_not_implemented_flow!(Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData);
impl_not_implemented_flow!(CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse);
impl_not_implemented_flow!(CreateSessionToken, PaymentFlowData, SessionTokenRequestData, SessionTokenResponseData);
impl_not_implemented_flow!(SetupMandate, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData);
impl_not_implemented_flow!(RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData);
impl_not_implemented_flow!(Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData);
impl_not_implemented_flow!(DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData);
impl_not_implemented_flow!(SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData);

// Main connector implementation using macros
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: AirtelMoney,
    curl_request: Json(AirtelMoneyPaymentsRequest),
    curl_response: AirtelMoneyPaymentsResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize],
    other_functions: {
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: AirtelMoney,
    curl_request: Json(AirtelMoneyPaymentsSyncRequest),
    curl_response: AirtelMoneyPaymentsResponse,
    flow_name: PSync,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsSyncData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize],
    other_functions: {
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: AirtelMoney,
    curl_request: Json(AirtelMoneyRefundRequest),
    curl_response: AirtelMoneyRefundResponse,
    flow_name: Refund,
    resource_common_data: RefundFlowData,
    flow_request: RefundsData,
    flow_response: RefundsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize],
    other_functions: {
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: AirtelMoney,
    curl_request: Json(AirtelMoneyRefundSyncRequest),
    curl_response: AirtelMoneyRefundResponse,
    flow_name: RSync,
    resource_common_data: RefundSyncData,
    flow_request: RefundSyncData,
    flow_response: RefundsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize],
    other_functions: {
    }
);

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize> 
    ConnectorCommon for AirtelMoney<T> {
    fn get_id(&self) -> &'static str {
        "airtelmoney"
    }

    fn get_base_url(&self) -> &'static str {
        constants::get_base_url()
    }

    fn get_auth_header(&self, _auth_type: &ConnectorAuthType) -> CustomResult<Vec<(String, String)>, errors::ConnectorError> {
        Ok(vec![])
    }
}