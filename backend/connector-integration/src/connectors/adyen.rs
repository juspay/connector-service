mod test;
pub mod transformers;
use std::sync::LazyLock;

use common_enums::{
    AttemptStatus, CaptureMethod, CardNetwork, EventClass, PaymentMethod, PaymentMethodType,
};
use common_utils::{
    errors::CustomResult, ext_traits::ByteSliceExt, pii::SecretSerdeValue, request::RequestContent,
};
use domain_types::{
    connector_flow::{
        Accept, Authorize, Capture, CreateOrder, DefendDispute, PSync, RSync, Refund, SetupMandate,
        SubmitEvidence, Void,
    },
    connector_types::{
        AcceptDisputeData, ConnectorSpecifications, ConnectorWebhookSecrets, DisputeDefendData,
        DisputeFlowData, DisputeResponseData, PaymentCreateOrderData, PaymentCreateOrderResponse,
        PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundSyncData,
        RefundWebhookDetailsResponse, RefundsData, RefundsResponseData, RequestDetails, ResponseId,
        SetupMandateRequestData, SubmitEvidenceData, SupportedPaymentMethodsExt,
        WebhookDetailsResponse,
    },
    errors,
    payment_method_data::{DefaultPCIHolder, PaymentMethodData, PaymentMethodDataTypes},
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::{
        self, CardSpecificFeatures, ConnectorInfo, Connectors, FeatureStatus,
        PaymentMethodDataType, PaymentMethodDetails, PaymentMethodSpecificFeatures,
        SupportedPaymentMethods,
    },
};
use error_stack::report;
use hyperswitch_masking::{Mask, Maskable};
use interfaces::{
    api::ConnectorCommon,
    connector_integration_v2::ConnectorIntegrationV2,
    connector_types::{self, is_mandate_supported, ConnectorValidation},
    events::connector_api_logs::ConnectorEvent,
};
use transformers::{
    self as adyen, AdyenCaptureRequest, AdyenCaptureResponse, AdyenDefendDisputeRequest,
    AdyenDefendDisputeResponse, AdyenDisputeAcceptRequest, AdyenDisputeAcceptResponse,
    AdyenDisputeSubmitEvidenceRequest, AdyenNotificationRequestItemWH, AdyenPSyncResponse,
    AdyenPaymentRequest, AdyenPaymentResponse, AdyenRedirectRequest, AdyenRefundRequest,
    AdyenRefundResponse, AdyenSubmitEvidenceResponse, AdyenVoidRequest, AdyenVoidResponse,
    SetupMandateRequest, SetupMandateResponse,
};

use super::macros;
use crate::{types::ResponseRouterData, with_error_response_body};

pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const X_API_KEY: &str = "X-Api-Key";
}

impl<T: PaymentMethodDataTypes> connector_types::ConnectorServiceTrait<T> for Adyen {}
impl<T: PaymentMethodDataTypes> connector_types::PaymentAuthorizeV2<T> for Adyen {}
impl connector_types::PaymentSyncV2 for Adyen {}
impl connector_types::PaymentVoidV2 for Adyen {}
impl connector_types::RefundSyncV2 for Adyen {}
impl connector_types::RefundV2 for Adyen {}
impl connector_types::PaymentCapture for Adyen {}
impl<T: PaymentMethodDataTypes> connector_types::SetupMandateV2<T> for Adyen {}
impl connector_types::AcceptDispute for Adyen {}
impl connector_types::SubmitEvidenceV2 for Adyen {}
impl connector_types::DisputeDefend for Adyen {}

// type AuthorizeRouterData<T> = RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>;
// type SetupMandateRouterData<T> = RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>;
// type PSyncRouterData = RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>;
// type CaptureRouterData = RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>;
// type VoidRouterData = RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>;
// type RefundRouterData = RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>;
// type AcceptRouterData = RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>;
// type SubmitEvidenceRouterData = RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>;
// type DefendDisputeRouterData = RouterDataV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>;


macros::create_all_prerequisites!(
    connector_name: Adyen,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static],
    api: [
        (
            flow: Authorize,
            request_body: AdyenPaymentRequest,
            response_body: AdyenPaymentResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: PSync,
            request_body: AdyenRedirectRequest,
            response_body: AdyenPSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ),
        (
            flow: Capture,
            request_body: AdyenCaptureRequest,
            response_body: AdyenCaptureResponse,
            router_data: RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ),
        (
            flow: Void,
            request_body: AdyenVoidRequest,
            response_body: AdyenVoidResponse,
            router_data: RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ),
        (
            flow: Refund,
            request_body: AdyenRefundRequest,
            response_body: AdyenRefundResponse,
            router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ),
        (
            flow: SetupMandate,
            request_body: SetupMandateRequest,
            response_body: SetupMandateResponse,
            router_data: RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>,
        ),
        (
            flow: Accept,
            request_body: AdyenDisputeAcceptRequest,
            response_body: AdyenDisputeAcceptResponse,
            router_data: RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>,

        ),
        (
            flow: SubmitEvidence,
            request_body: AdyenDisputeSubmitEvidenceRequest,
            response_body: AdyenSubmitEvidenceResponse,
            router_data: RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>,
    
        ),
        (
            flow: DefendDispute,
            request_body: AdyenDefendDisputeRequest,
            response_body: AdyenDefendDisputeResponse,
            router_data: RouterDataV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>,
        )
    ],
    amount_converters: [],
    member_functions: {
        pub fn build_headers<F, FCD, Req, Res>(
            &self,
            req: &RouterDataV2<F, FCD, Req, Res>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            let mut header = vec![(
                headers::CONTENT_TYPE.to_string(),
                "application/json".to_string().into(),
            )];
            let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
            header.append(&mut api_key);
            Ok(header)
        }

        pub fn connector_base_url_payments<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.adyen.base_url
        }

        pub fn connector_base_url_refunds<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, RefundFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.adyen.base_url
        }

        pub fn connector_base_url_disputes<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, DisputeFlowData, Req, Res>,
        ) -> Option<&'a str> {
            req.resource_common_data.connectors.adyen.dispute_base_url.as_deref()
        }
    }
);

// #[allow(unused_imports)]
// use crate::connectors::macros::{
//     Bridge, BridgeRequestResponse, FlowTypes, GetFormData, NoRequestBody, NoRequestBodyTemplating,
// };
// use std::marker::PhantomData;
// #[allow(unused_imports)]
// mod macro_types {
//     pub(super) use crate::types::*;
//     pub(super) use common_utils::{errors::CustomResult, request::RequestContent};
//     pub(super) use domain_types::{
//         errors::ConnectorError, router_data::ErrorResponse, router_data_v2::RouterDataV2,
//         router_response_types::Response,
//     };
//     pub(super) use hyperswitch_masking::Maskable;
//     pub(super) use interfaces::events::connector_api_logs::ConnectorEvent;
// }
// pub struct AdyenRouterData<RD: FlowTypes, T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static> {
//     pub connector: Adyen<T>,
//     pub router_data: RD,
// }
// impl<RD: FlowTypes, T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static> FlowTypes for AdyenRouterData<RD, T> {
//     type Flow = RD::Flow;
//     type FlowCommonData = RD::FlowCommonData;
//     type Request = RD::Request;
//     type Response = RD::Response;
// }
// pub struct AdyenPaymentRequestTemplating;

// pub struct AdyenPaymentResponseTemplating;

// impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static> BridgeRequestResponse
//     for Bridge<AdyenPaymentRequestTemplating, AdyenPaymentResponseTemplating, T>
// {
//     type RequestBody = AdyenPaymentRequest;
//     type ResponseBody = AdyenPaymentResponse;
//     type ConnectorInputData = AdyenRouterData<
//         RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T
//     >;
// }
// pub struct AdyenRedirectRequestTemplating;

// pub struct AdyenPSyncResponseTemplating;

// impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static> BridgeRequestResponse
//     for Bridge<AdyenRedirectRequestTemplating, AdyenPSyncResponseTemplating, T>
// {
//     type RequestBody = AdyenRedirectRequest;
//     type ResponseBody = AdyenPSyncResponse;
//     type ConnectorInputData = AdyenRouterData<
//         RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T
//     >;
// }
// pub struct AdyenCaptureRequestTemplating;

// pub struct AdyenCaptureResponseTemplating;

// impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static> BridgeRequestResponse
//     for Bridge<AdyenCaptureRequestTemplating, AdyenCaptureResponseTemplating, T>
// {
//     type RequestBody = AdyenCaptureRequest;
//     type ResponseBody = AdyenCaptureResponse;
//     type ConnectorInputData = AdyenRouterData<
//         RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>, T
//     >;
// }
// pub struct AdyenVoidRequestTemplating;

// pub struct AdyenVoidResponseTemplating;

// impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static> BridgeRequestResponse
//     for Bridge<AdyenVoidRequestTemplating, AdyenVoidResponseTemplating, T>
// {
//     type RequestBody = AdyenVoidRequest;
//     type ResponseBody = AdyenVoidResponse;
//     type ConnectorInputData =
//         AdyenRouterData<RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>, T>;
// }
// pub struct AdyenRefundRequestTemplating;

// pub struct AdyenRefundResponseTemplating;

// impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static> BridgeRequestResponse
//     for Bridge<AdyenRefundRequestTemplating, AdyenRefundResponseTemplating, T>
// {
//     type RequestBody = AdyenRefundRequest;
//     type ResponseBody = AdyenRefundResponse;
//     type ConnectorInputData =
//         AdyenRouterData<RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>, T>;
// }
// pub struct SetupMandateRequestTemplating;

// pub struct SetupMandateResponseTemplating;

// impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send+ 'static> BridgeRequestResponse
//     for Bridge<SetupMandateRequestTemplating, SetupMandateResponseTemplating, T>
// {
//     type RequestBody = SetupMandateRequest;
//     type ResponseBody = SetupMandateResponse;
//     type ConnectorInputData = AdyenRouterData<
//         RouterDataV2<
//             SetupMandate,
//             PaymentFlowData,
//             SetupMandateRequestData<T>,
//             PaymentsResponseData,
//         >,T
//     >;
// }
// pub struct AdyenDisputeAcceptRequestTemplating;

// pub struct AdyenDisputeAcceptResponseTemplating;

// impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static> BridgeRequestResponse
//     for Bridge<AdyenDisputeAcceptRequestTemplating, AdyenDisputeAcceptResponseTemplating, T>
// {
//     type RequestBody = AdyenDisputeAcceptRequest;
//     type ResponseBody = AdyenDisputeAcceptResponse;
//     type ConnectorInputData = AdyenRouterData<
//         RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>, T
//     >;
// }
// pub struct AdyenDisputeSubmitEvidenceRequestTemplating;

// pub struct AdyenSubmitEvidenceResponseTemplating;

// impl <T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static> BridgeRequestResponse
//     for Bridge<
//         AdyenDisputeSubmitEvidenceRequestTemplating,
//         AdyenSubmitEvidenceResponseTemplating,
//         T,
//     >
// {
//     type RequestBody = AdyenDisputeSubmitEvidenceRequest;
//     type ResponseBody = AdyenSubmitEvidenceResponse;
//     type ConnectorInputData = AdyenRouterData<
//         RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>, T
//     >;
// }
// pub struct AdyenDefendDisputeRequestTemplating;

// pub struct AdyenDefendDisputeResponseTemplating;

// impl <T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static> BridgeRequestResponse
//     for Bridge<AdyenDefendDisputeRequestTemplating, AdyenDefendDisputeResponseTemplating, T>
// {
//     type RequestBody = AdyenDefendDisputeRequest;
//     type ResponseBody = AdyenDefendDisputeResponse;
//     type ConnectorInputData = AdyenRouterData<
//         RouterDataV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>, T
//     >;
// }
// #[derive(Clone)]
// pub struct Adyen<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send+ 'static> {
//     authorize: &'static (dyn BridgeRequestResponse<
//         RequestBody = AdyenPaymentRequest,
//         ResponseBody = AdyenPaymentResponse,
//         ConnectorInputData = AdyenRouterData<
//             RouterDataV2<
//                 Authorize,
//                 PaymentFlowData,
//                 PaymentsAuthorizeData<T>,
//                 PaymentsResponseData,
//             >,
//             T
//         >,
//     >),
//     p_sync: &'static (dyn BridgeRequestResponse<
//         RequestBody = AdyenRedirectRequest,
//         ResponseBody = AdyenPSyncResponse,
//         ConnectorInputData = AdyenRouterData<
//             RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T
//         >,
//     >),
//     capture: &'static (dyn BridgeRequestResponse<
//         RequestBody = AdyenCaptureRequest,
//         ResponseBody = AdyenCaptureResponse,
//         ConnectorInputData = AdyenRouterData<
//             RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>, T
//         >,
//     >),
//     void: &'static (dyn BridgeRequestResponse<
//         RequestBody = AdyenVoidRequest,
//         ResponseBody = AdyenVoidResponse,
//         ConnectorInputData = AdyenRouterData<
//             RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>, T
//         >,
//     >),
//     refund: &'static (dyn BridgeRequestResponse<
//         RequestBody = AdyenRefundRequest,
//         ResponseBody = AdyenRefundResponse,
//         ConnectorInputData = AdyenRouterData<
//             RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>, T
//         >,
//     >),
//     setup_mandate: &'static (dyn BridgeRequestResponse<
//         RequestBody = SetupMandateRequest,
//         ResponseBody = SetupMandateResponse,
//         ConnectorInputData = AdyenRouterData<
//             RouterDataV2<
//                 SetupMandate,
//                 PaymentFlowData,
//                 SetupMandateRequestData<T>,
//                 PaymentsResponseData,
//             >,
//             T
//         >,
//     >),
//     accept: &'static (dyn BridgeRequestResponse<
//         RequestBody = AdyenDisputeAcceptRequest,
//         ResponseBody = AdyenDisputeAcceptResponse,
//         ConnectorInputData = AdyenRouterData<
//             RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>, T
//         >,
//     >),
//     submit_evidence: &'static (dyn BridgeRequestResponse<
//         RequestBody = AdyenDisputeSubmitEvidenceRequest,
//         ResponseBody = AdyenSubmitEvidenceResponse,
//         ConnectorInputData = AdyenRouterData<
//             RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>, T
//         >,
//     >),
//     defend_dispute: &'static (dyn BridgeRequestResponse<
//         RequestBody = AdyenDefendDisputeRequest,
//         ResponseBody = AdyenDefendDisputeResponse,
//         ConnectorInputData = AdyenRouterData<
//             RouterDataV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>, T
//         >,
//     >),
// }
// impl<T:PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static>  Adyen<T> {
//     pub const fn new() -> &'static Self {
//         &Self {
//             authorize: &Bridge::<AdyenPaymentRequestTemplating, AdyenPaymentResponseTemplating, T>(
//                 PhantomData,
//             ),
//             p_sync: &Bridge::<AdyenRedirectRequestTemplating, AdyenPSyncResponseTemplating, T>(
//                 PhantomData,
//             ),
//             capture: &Bridge::<AdyenCaptureRequestTemplating, AdyenCaptureResponseTemplating, T>(
//                 PhantomData,
//             ),
//             void: &Bridge::<AdyenVoidRequestTemplating, AdyenVoidResponseTemplating, T>(
//                 PhantomData,
//             ),
//             refund: &Bridge::<AdyenRefundRequestTemplating, AdyenRefundResponseTemplating, T>(
//                 PhantomData,
//             ),
//             setup_mandate: &Bridge::<SetupMandateRequestTemplating, SetupMandateResponseTemplating, T>(
//                 PhantomData,
//             ),
//             accept: &Bridge::<
//                 AdyenDisputeAcceptRequestTemplating,
//                 AdyenDisputeAcceptResponseTemplating,
//                 T
//             >(PhantomData),
//             submit_evidence: &Bridge::<
//                 AdyenDisputeSubmitEvidenceRequestTemplating,
//                 AdyenSubmitEvidenceResponseTemplating,
//                 T
//             >(PhantomData),
//             defend_dispute: &Bridge::<
//                 AdyenDefendDisputeRequestTemplating,
//                 AdyenDefendDisputeResponseTemplating,
//                 T
//             >(PhantomData),
//         }
//     }
//     pub fn build_headers<F, FCD, Req, Res>(
//         &self,
//         req: &RouterDataV2<F, FCD, Req, Res>,
//     ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
//         let mut header = <[_]>::into_vec(
//             #[rustc_box]
//             alloc::boxed::Box::new([(
//                 headers::CONTENT_TYPE.to_string(),
//                 "application/json".to_string().into(),
//             )]),
//         );
//         let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
//         header.append(&mut api_key);
//         Ok(header)
//     }
//     pub fn connector_base_url_payments<'a, F, Req, Res>(
//         &self,
//         req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
//     ) -> &'a str {
//         &req.resource_common_data.connectors.adyen.base_url
//     }
//     pub fn connector_base_url_refunds<'a, F, Req, Res>(
//         &self,
//         req: &'a RouterDataV2<F, RefundFlowData, Req, Res>,
//     ) -> &'a str {
//         &req.resource_common_data.connectors.adyen.base_url
//     }
//     pub fn connector_base_url_disputes<'a, F, Req, Res>(
//         &self,
//         req: &'a RouterDataV2<F, DisputeFlowData, Req, Res>,
//     ) -> Option<&'a str> {
//         req.resource_common_data
//             .connectors
//             .adyen
//             .dispute_base_url
//             .as_deref()
//     }
// }

impl ConnectorCommon for Adyen
{
    fn id(&self) -> &'static str {
        "adyen"
    }
    fn get_currency_unit(&self) -> common_enums::CurrencyUnit {
        common_enums::CurrencyUnit::Minor
    }
    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth = adyen::AdyenAuthType::try_from(auth_type)
            .map_err(|_| errors::ConnectorError::FailedToObtainAuthType)?;
        Ok(vec![(
            headers::X_API_KEY.to_string(),
            auth.api_key.into_masked(),
        )])
    }
    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.adyen.base_url.as_ref()
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: adyen::AdyenErrorResponse = res
            .response
            .parse_struct("ErrorResponse")
            .map_err(|_| errors::ConnectorError::ResponseDeserializationFailed)?;

        with_error_response_body!(event_builder, response);

        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response.error_code,
            message: response.message.to_owned(),
            reason: Some(response.message),
            attempt_status: None,
            connector_transaction_id: response.psp_reference,
            network_decline_code: None,
            network_advice_code: None,
            network_error_message: None,
            raw_connector_response: Some(String::from_utf8_lossy(&res.response).to_string()),
        })
    }
}

const ADYEN_API_VERSION: &str = "v68";

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Adyen,
    curl_request: Json(AdyenPaymentRequest),
    curl_response: AdyenPaymentResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static ],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            Ok(format!("{}{}/payments", self.connector_base_url_payments(req), ADYEN_API_VERSION))
        }
    }
);

// impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static> ConnectorIntegrationV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
//     for Adyen<T>
// {
//     fn get_http_method(&self) -> common_utils::request::Method {
//         common_utils::request::Method::Post
//     }
//     fn get_headers(
//         &self,
//         req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
//     ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
//         self.build_headers(req)
//     }
//     fn get_url(
//         &self,
//         req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
//     ) -> CustomResult<String, errors::ConnectorError> {
//         Ok(alloc::__export::must_use({
//             let res = alloc::fmt::format(alloc::__export::format_args!(
//                 "{}{}/payments",
//                 self.connector_base_url_payments(req),
//                 ADYEN_API_VERSION
//             ));
//             res
//         }))
//     }
//     fn get_content_type(&self) -> &'static str {
//         self.common_get_content_type()
//     }
//     fn get_error_response_v2(
//         &self,
//         res: Response,
//         event_builder: Option<&mut ConnectorEvent>,
//     ) -> CustomResult<ErrorResponse, macro_types::ConnectorError> {
//         self.build_error_response(res, event_builder)
//     }
//     fn get_request_body(
//         &self,
//         req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
//     ) -> CustomResult<Option<macro_types::RequestContent>, macro_types::ConnectorError> {
//         let bridge = self.authorize;
//         let input_data = AdyenRouterData {
//             connector: self.to_owned(),
//             router_data: req.clone(),
//         };
//         let request = bridge.request_body(input_data)?;
//         Ok(Some(RequestContent::Json(Box::new(request))))
//     }
//     fn handle_response_v2(
//         &self,
//         data: &RouterDataV2<
//             Authorize,
//             PaymentFlowData,
//             PaymentsAuthorizeData<T>,
//             PaymentsResponseData,
//         >,
//         event_builder: Option<&mut ConnectorEvent>,
//         res: Response,
//     ) -> CustomResult<
//         RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
//         macro_types::ConnectorError,
//     > {
//         let bridge = self.authorize;
//         let response_body = bridge.response(res.response)?;
//         event_builder.map(|i| i.set_response_body(&response_body));
//         let response_router_data = ResponseRouterData {
//             response: response_body,
//             router_data: data.clone(),
//             http_code: res.status_code,
//         };
//         let result = bridge.router_data(response_router_data)?;
//         Ok(result)
//     }
// }

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Adyen,
    curl_request: Json(AdyenRedirectRequest),
    curl_response: AdyenPSyncResponse,
    flow_name: PSync,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsSyncData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static ],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            Ok(format!("{}{}/payments/details", self.connector_base_url_payments(req), ADYEN_API_VERSION))
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Adyen,
    curl_request: Json(AdyenCaptureRequest),
    curl_response: AdyenCaptureResponse,
    flow_name: Capture,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsCaptureData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            let id = match &req.request.connector_transaction_id {
                ResponseId::ConnectorTransactionId(id) => id,
                _ => return Err(errors::ConnectorError::MissingConnectorTransactionID.into())
            };
            Ok(format!("{}{}/payments/{}/captures", self.connector_base_url_payments(req), ADYEN_API_VERSION, id))
        }
    }
);

impl connector_types::ValidationTrait for Adyen {}

impl connector_types::PaymentOrderCreate for Adyen {}

impl
    ConnectorIntegrationV2<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for Adyen
{
}

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Adyen,
    curl_request: Json(AdyenVoidRequest),
    curl_response: AdyenVoidResponse,
    flow_name: Void,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentVoidData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            let id = req.request.connector_transaction_id.clone();
            Ok(format!("{}{}/payments/{}/cancels", self.connector_base_url_payments(req), ADYEN_API_VERSION, id))
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Adyen,
    curl_request: Json(AdyenDefendDisputeRequest),
    curl_response: AdyenDefendDisputeResponse,
    flow_name: DefendDispute,
    resource_common_data: DisputeFlowData,
    flow_request: DisputeDefendData,
    flow_response: DisputeResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            let dispute_url = self.connector_base_url_disputes(req)
                .ok_or(errors::ConnectorError::FailedToObtainIntegrationUrl)?;
            Ok(format!("{dispute_url}ca/services/DisputeService/v30/defendDispute"))
        }
    }
);

impl ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData> for Adyen {}

// SourceVerification implementations for all flows
impl<
        T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static,
    >
    interfaces::verification::SourceVerification<
        Authorize,
        PaymentFlowData,
        PaymentsAuthorizeData<T>,
        PaymentsResponseData,
    > for Adyen
{
}

impl
    interfaces::verification::SourceVerification<
        PSync,
        PaymentFlowData,
        PaymentsSyncData,
        PaymentsResponseData,
    > for Adyen
{
}

impl
    interfaces::verification::SourceVerification<
        Capture,
        PaymentFlowData,
        PaymentsCaptureData,
        PaymentsResponseData,
    > for Adyen
{
}

impl
    interfaces::verification::SourceVerification<
        Void,
        PaymentFlowData,
        PaymentVoidData,
        PaymentsResponseData,
    > for Adyen
{
}

impl
    interfaces::verification::SourceVerification<
        Refund,
        RefundFlowData,
        RefundsData,
        RefundsResponseData,
    > for Adyen
{
}

impl
    interfaces::verification::SourceVerification<
        RSync,
        RefundFlowData,
        RefundSyncData,
        RefundsResponseData,
    > for Adyen
{
}

impl<
        T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static,
    >
    interfaces::verification::SourceVerification<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData<T>,
        PaymentsResponseData,
    > for Adyen
{
}

impl
    interfaces::verification::SourceVerification<
        Accept,
        DisputeFlowData,
        AcceptDisputeData,
        DisputeResponseData,
    > for Adyen
{
}

impl
    interfaces::verification::SourceVerification<
        SubmitEvidence,
        DisputeFlowData,
        SubmitEvidenceData,
        DisputeResponseData,
    > for Adyen
{
}

impl
    interfaces::verification::SourceVerification<
        DefendDispute,
        DisputeFlowData,
        DisputeDefendData,
        DisputeResponseData,
    > for Adyen
{
}

impl
    interfaces::verification::SourceVerification<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for Adyen
{
}

impl connector_types::IncomingWebhook for Adyen {
    fn get_event_type(
        &self,
        request: RequestDetails,
        _connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorAuthType>,
    ) -> Result<domain_types::connector_types::EventType, error_stack::Report<errors::ConnectorError>>
    {
        let notif: AdyenNotificationRequestItemWH =
            transformers::get_webhook_object_from_body(request.body).map_err(|err| {
                report!(errors::ConnectorError::WebhookBodyDecodingFailed)
                    .attach_printable(format!("error while decoding webhook body {err}"))
            })?;
        Ok(transformers::get_adyen_webhook_event_type(notif.event_code))
    }

    fn process_payment_webhook(
        &self,
        request: RequestDetails,
        _connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorAuthType>,
    ) -> Result<WebhookDetailsResponse, error_stack::Report<errors::ConnectorError>> {
        let request_body_copy = request.body.clone();
        let notif: AdyenNotificationRequestItemWH =
            transformers::get_webhook_object_from_body(request.body).map_err(|err| {
                report!(errors::ConnectorError::WebhookBodyDecodingFailed)
                    .attach_printable(format!("error while decoding webhook body {err}"))
            })?;
        Ok(WebhookDetailsResponse {
            resource_id: Some(ResponseId::ConnectorTransactionId(
                notif.psp_reference.clone(),
            )),
            status: transformers::get_adyen_payment_webhook_event(notif.event_code, notif.success)?,
            connector_response_reference_id: Some(notif.psp_reference),
            error_code: notif.reason.clone(),
            error_message: notif.reason,
            raw_connector_response: Some(String::from_utf8_lossy(&request_body_copy).to_string()),
        })
    }

    fn process_refund_webhook(
        &self,
        request: RequestDetails,
        _connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorAuthType>,
    ) -> Result<
        domain_types::connector_types::RefundWebhookDetailsResponse,
        error_stack::Report<errors::ConnectorError>,
    > {
        let request_body_copy = request.body.clone();
        let notif: AdyenNotificationRequestItemWH =
            transformers::get_webhook_object_from_body(request.body).map_err(|err| {
                report!(errors::ConnectorError::WebhookBodyDecodingFailed)
                    .attach_printable(format!("error while decoding webhook body {err}"))
            })?;

        Ok(RefundWebhookDetailsResponse {
            connector_refund_id: Some(notif.psp_reference.clone()),
            status: transformers::get_adyen_refund_webhook_event(notif.event_code, notif.success)?,
            connector_response_reference_id: Some(notif.psp_reference.clone()),
            error_code: notif.reason.clone(),
            error_message: notif.reason,
            raw_connector_response: Some(String::from_utf8_lossy(&request_body_copy).to_string()),
        })
    }

    fn process_dispute_webhook(
        &self,
        request: RequestDetails,
        _connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorAuthType>,
    ) -> Result<
        domain_types::connector_types::DisputeWebhookDetailsResponse,
        error_stack::Report<errors::ConnectorError>,
    > {
        let request_body_copy = request.body.clone();
        let notif: AdyenNotificationRequestItemWH =
            transformers::get_webhook_object_from_body(request.body).map_err(|err| {
                report!(errors::ConnectorError::WebhookBodyDecodingFailed)
                    .attach_printable(format!("error while decoding webhook body {err}"))
            })?;
        let (stage, status) = transformers::get_dispute_stage_and_status(
            notif.event_code,
            notif.additional_data.dispute_status,
        );
        Ok(
            domain_types::connector_types::DisputeWebhookDetailsResponse {
                dispute_id: notif.psp_reference.clone(),
                stage,
                status,
                connector_response_reference_id: Some(notif.psp_reference.clone()),
                dispute_message: notif.reason,
                raw_connector_response: Some(
                    String::from_utf8_lossy(&request_body_copy).to_string(),
                ),
            },
        )
    }
}

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Adyen,
    curl_request: Json(AdyenRefundRequest),
    curl_response: AdyenRefundResponse,
    flow_name: Refund,
    resource_common_data: RefundFlowData,
    flow_request: RefundsData,
    flow_response: RefundsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            let connector_payment_id = req.request.connector_transaction_id.clone();
            Ok(format!("{}{}/payments/{}/refunds", self.connector_base_url_refunds(req), ADYEN_API_VERSION, connector_payment_id))
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Adyen,
    curl_request: Json(SetupMandateRequest),
    curl_response: SetupMandateResponse,
    flow_name: SetupMandate,
    resource_common_data: PaymentFlowData,
    flow_request: SetupMandateRequestData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            Ok(format!("{}{}/payments", self.connector_base_url_payments(req), ADYEN_API_VERSION))
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Adyen,
    curl_request: Json(AdyenDisputeAcceptRequest),
    curl_response: AdyenDisputeAcceptResponse,
    flow_name: Accept,
    resource_common_data: DisputeFlowData,
    flow_request: AcceptDisputeData,
    flow_response: DisputeResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            let dispute_url = self.connector_base_url_disputes(req)
                                  .ok_or(errors::ConnectorError::FailedToObtainIntegrationUrl)?;
            Ok(format!("{dispute_url}ca/services/DisputeService/v30/acceptDispute"))
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Adyen,
    curl_request: Json(AdyenDisputeSubmitEvidenceRequest),
    curl_response: AdyenSubmitEvidenceResponse,
    flow_name: SubmitEvidence,
    resource_common_data: DisputeFlowData,
    flow_request: SubmitEvidenceData,
    flow_response: DisputeResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            let dispute_url = self.connector_base_url_disputes(req)
                                  .ok_or(errors::ConnectorError::FailedToObtainIntegrationUrl)?;
            Ok(format!("{dispute_url}ca/services/DisputeService/v30/supplyDefenseDocument"))
        }
    }
);

static ADYEN_SUPPORTED_PAYMENT_METHODS: LazyLock<SupportedPaymentMethods> = LazyLock::new(|| {
    let adyen_supported_capture_methods = vec![
        CaptureMethod::Automatic,
        CaptureMethod::Manual,
        CaptureMethod::ManualMultiple,
        // CaptureMethod::Scheduled,
    ];

    let adyen_supported_card_network = vec![
        CardNetwork::AmericanExpress,
        CardNetwork::CartesBancaires,
        CardNetwork::UnionPay,
        CardNetwork::DinersClub,
        CardNetwork::Discover,
        CardNetwork::Interac,
        CardNetwork::JCB,
        CardNetwork::Maestro,
        CardNetwork::Mastercard,
        CardNetwork::Visa,
    ];

    let mut adyen_supported_payment_methods = SupportedPaymentMethods::new();

    adyen_supported_payment_methods.add(
        PaymentMethod::Card,
        PaymentMethodType::Credit,
        PaymentMethodDetails {
            mandates: FeatureStatus::Supported,
            refunds: FeatureStatus::Supported,
            supported_capture_methods: adyen_supported_capture_methods.clone(),
            specific_features: Some(PaymentMethodSpecificFeatures::Card(CardSpecificFeatures {
                three_ds: FeatureStatus::Supported,
                no_three_ds: FeatureStatus::Supported,
                supported_card_networks: adyen_supported_card_network.clone(),
            })),
        },
    );

    adyen_supported_payment_methods.add(
        PaymentMethod::Card,
        PaymentMethodType::Debit,
        PaymentMethodDetails {
            mandates: FeatureStatus::Supported,
            refunds: FeatureStatus::Supported,
            supported_capture_methods: adyen_supported_capture_methods.clone(),
            specific_features: Some(PaymentMethodSpecificFeatures::Card(CardSpecificFeatures {
                three_ds: FeatureStatus::Supported,
                no_three_ds: FeatureStatus::Supported,
                supported_card_networks: adyen_supported_card_network.clone(),
            })),
        },
    );

    adyen_supported_payment_methods
});

static ADYEN_CONNECTOR_INFO: ConnectorInfo = ConnectorInfo {
    display_name: "Adyen", 
    description: "Adyen is a Dutch payment company with the status of an acquiring bank that allows businesses to accept e-commerce, mobile, and point-of-sale payments. It is listed on the stock exchange Euronext Amsterdam.",
    connector_type: types::PaymentConnectorCategory::PaymentGateway,
};

static ADYEN_SUPPORTED_WEBHOOK_FLOWS: &[EventClass] = &[EventClass::Payments, EventClass::Refunds];

impl ConnectorSpecifications for Adyen {
    fn get_connector_about(&self) -> Option<&'static ConnectorInfo> {
        Some(&ADYEN_CONNECTOR_INFO)
    }

    fn get_supported_payment_methods(&self) -> Option<&'static SupportedPaymentMethods> {
        Some(&ADYEN_SUPPORTED_PAYMENT_METHODS)
    }

    fn get_supported_webhook_flows(&self) -> Option<&'static [EventClass]> {
        Some(ADYEN_SUPPORTED_WEBHOOK_FLOWS)
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static > ConnectorValidation for Adyen
{
    fn validate_mandate_payment(
        &self,
        pm_type: Option<PaymentMethodType>,
        pm_data: PaymentMethodData<DefaultPCIHolder>,
    ) -> CustomResult<(), errors::ConnectorError> {
        let mandate_supported_pmd = std::collections::HashSet::from([PaymentMethodDataType::Card]);
        is_mandate_supported(pm_data, pm_type, mandate_supported_pmd, self.id())
    }

    fn validate_psync_reference_id(
        &self,
        data: &PaymentsSyncData,
        _is_three_ds: bool,
        _status: AttemptStatus,
        _connector_meta_data: Option<SecretSerdeValue>,
    ) -> CustomResult<(), errors::ConnectorError> {
        if data.encoded_data.is_some() {
            return Ok(());
        }
        Err(errors::ConnectorError::MissingRequiredField {
            field_name: "encoded_data",
        }
        .into())
    }
    fn is_webhook_source_verification_mandatory(&self) -> bool {
        false
    }
}
