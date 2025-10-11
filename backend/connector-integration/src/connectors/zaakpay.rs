pub mod transformers;

use common_enums::CurrencyUnit;
use common_utils::{
    errors::CustomResult,
    ext_traits::ByteSliceExt,
    types::{FloatMajorUnit, StringMinorUnit},
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
use transformers::{self as zaakpay, ZaakPayPaymentsRequest, ZaakPayPaymentsResponse};

use super::macros;
use crate::{types::ResponseRouterData, with_error_response_body};

pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const AUTHORIZATION: &str = "Authorization";
}

// Trait implementations with generic type parameters
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > ConnectorCommon for crate::types::ConnectorData<T>
{
    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, String)>, errors::ConnectorError> {
        match auth_type {
            ConnectorAuthType::HeaderKey { api_key } => Ok(vec![(
                headers::AUTHORIZATION.to_string(),
                format!("Bearer {}", api_key.peek()),
            )]),
            _ => Err(errors::ConnectorError::AuthenticationFailed.into()),
        }
    }

    fn get_base_url(&self) -> &'static str {
        match self.connector_name {
            Connectors::ZaakPay => "https://zaakpay.com",
            _ => "https://zaakpay.com",
        }
    }

    fn get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn get_api_tag(&self) -> &'static str {
        "default"
    }

    fn get_error_response(
        &self,
        response: &[u8],
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.handle_error_response(response)
    }
}

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
            router_data: RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ),
        // Stub types for unimplemented flows
        (
            flow: Void,
            request_body: ZaakPayVoidRequest,
            response_body: ZaakPayVoidResponse,
            router_data: RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ),
        (
            flow: Capture,
            request_body: ZaakPayCaptureRequest,
            response_body: ZaakPayCaptureResponse,
            router_data: RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ),
        (
            flow: Refund,
            request_body: ZaakPayRefundRequest,
            response_body: ZaakPayRefundResponse,
            router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ),
        (
            flow: CreateOrder,
            request_body: ZaakPayCreateOrderRequest,
            response_body: ZaakPayCreateOrderResponse,
            router_data: RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>,
        ),
        (
            flow: CreateSessionToken,
            request_body: ZaakPaySessionTokenRequest,
            response_body: ZaakPaySessionTokenResponse,
            router_data: RouterDataV2<CreateSessionToken, PaymentFlowData, SessionTokenRequestData, SessionTokenResponseData>,
        ),
        (
            flow: SetupMandate,
            request_body: ZaakPaySetupMandateRequest,
            response_body: ZaakPaySetupMandateResponse,
            router_data: RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData>,
        ),
        (
            flow: RepeatPayment,
            request_body: ZaakPayRepeatPaymentRequest,
            response_body: ZaakPayRepeatPaymentResponse,
            router_data: RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>,
        ),
        (
            flow: Accept,
            request_body: ZaakPayAcceptDisputeRequest,
            response_body: ZaakPayAcceptDisputeResponse,
            router_data: RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>,
        ),
        (
            flow: DefendDispute,
            request_body: ZaakPayDefendDisputeRequest,
            response_body: ZaakPayDefendDisputeResponse,
            router_data: RouterDataV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>,
        ),
        (
            flow: SubmitEvidence,
            request_body: ZaakPaySubmitEvidenceRequest,
            response_body: ZaakPaySubmitEvidenceResponse,
            router_data: RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>,
        )
    ],
    amount_converters: [
        amount_converter: StringMinorUnit
    ],
    member_functions: {
        fn build_checksum(&self, data: &str, salt: &str) -> String {
            use sha2::{Digest, Sha512};
            let mut hasher = Sha512::new();
            hasher.update(data);
            hasher.update(salt);
            hex::encode(hasher.finalize())
        }
    }
);

// Implement Authorize flow using macro framework
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
    other_functions: {
        fn build_request_v2(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<Option<interfaces::api::Request>, errors::ConnectorError> {
            let connector_request = ZaakPayPaymentsRequest::try_from(req)?;
            let auth_header = self.get_auth_header(&req.connector_auth_type)?;
            
            let request = interfaces::api::RequestBuilder::new()
                .method(interfaces::api::Method::Post)
                .url(&types::UrlType::get_url(
                    self.get_base_url(),
                    "transact",
                    &types::ConnectorAction::PaymentAuthorize,
                )?)
                .attach_default_headers()
                .headers(auth_header)
                .body(types::RequestBody::Json(connector_request))
                .build();

            Ok(Some(request))
        }

        fn handle_response_v2(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            res: interfaces::api::Response,
        ) -> CustomResult<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, errors::ConnectorError> {
            let response: ZaakPayPaymentsResponse = res
                .response
                .parse_struct("ZaakPayPaymentsResponse")
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

            let router_response = PaymentsResponseData::try_from(response)?;

            Ok(RouterDataV2::from_response(
                router_response,
                req.request.clone(),
                req.resource_common_data.clone(),
                req.connector_meta_data.clone(),
            ))
        }
    }
);

// Implement PSync flow using macro framework
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
    other_functions: {
        fn build_request_v2(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<Option<interfaces::api::Request>, errors::ConnectorError> {
            let connector_request = ZaakPayPaymentsSyncRequest::try_from(req)?;
            let auth_header = self.get_auth_header(&req.connector_auth_type)?;
            
            let request = interfaces::api::RequestBuilder::new()
                .method(interfaces::api::Method::Post)
                .url(&types::UrlType::get_url(
                    self.get_base_url(),
                    "check",
                    &types::ConnectorAction::PaymentSync,
                )?)
                .attach_default_headers()
                .headers(auth_header)
                .body(types::RequestBody::Json(connector_request))
                .build();

            Ok(Some(request))
        }

        fn handle_response_v2(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            res: interfaces::api::Response,
        ) -> CustomResult<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, errors::ConnectorError> {
            let response: ZaakPayPaymentsSyncResponse = res
                .response
                .parse_struct("ZaakPayPaymentsSyncResponse")
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

            let router_response = PaymentsResponseData::try_from(response)?;

            Ok(RouterDataV2::from_response(
                router_response,
                req.request.clone(),
                req.resource_common_data.clone(),
                req.connector_meta_data.clone(),
            ))
        }
    }
);

// Implement RSync flow using macro framework
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: ZaakPay,
    curl_request: Json(ZaakPayRefundSyncRequest),
    curl_response: ZaakPayRefundSyncResponse,
    flow_name: RSync,
    resource_common_data: RefundFlowData,
    flow_request: RefundSyncData,
    flow_response: RefundsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
    other_functions: {
        fn build_request_v2(
            &self,
            req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ) -> CustomResult<Option<interfaces::api::Request>, errors::ConnectorError> {
            let connector_request = ZaakPayRefundSyncRequest::try_from(req)?;
            let auth_header = self.get_auth_header(&req.connector_auth_type)?;
            
            let request = interfaces::api::RequestBuilder::new()
                .method(interfaces::api::Method::Post)
                .url(&types::UrlType::get_url(
                    self.get_base_url(),
                    "check",
                    &types::ConnectorAction::RefundSync,
                )?)
                .attach_default_headers()
                .headers(auth_header)
                .body(types::RequestBody::Json(connector_request))
                .build();

            Ok(Some(request))
        }

        fn handle_response_v2(
            &self,
            req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            res: interfaces::api::Response,
        ) -> CustomResult<RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>, errors::ConnectorError> {
            let response: ZaakPayRefundSyncResponse = res
                .response
                .parse_struct("ZaakPayRefundSyncResponse")
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

            let router_response = RefundsResponseData::try_from(response)?;

            Ok(RouterDataV2::from_response(
                router_response,
                req.request.clone(),
                req.resource_common_data.clone(),
                req.connector_meta_data.clone(),
            ))
        }
    }
);

// Implement not-implemented flows with proper error handling
macro_rules! impl_not_implemented_flow {
    ($flow:ty, $common_data:ty, $req:ty, $resp:ty) => {
        impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
            ConnectorIntegrationV2<$flow, $common_data, $req, $resp> for crate::types::ConnectorData<T>
        {
            fn build_request_v2(
                &self,
                _req: &RouterDataV2<$flow, $common_data, $req, $resp>,
            ) -> CustomResult<Option<interfaces::api::Request>, errors::ConnectorError> {
                let flow_name = stringify!($flow);
                Err(errors::ConnectorError::NotImplemented(flow_name.to_string()).into())
            }

            fn handle_response_v2(
                &self,
                _req: &RouterDataV2<$flow, $common_data, $req, $resp>,
                _res: interfaces::api::Response,
            ) -> CustomResult<RouterDataV2<$flow, $common_data, $req, $resp>, errors::ConnectorError> {
                let flow_name = stringify!($flow);
                Err(errors::ConnectorError::NotImplemented(flow_name.to_string()).into())
            }
        }
    };
}

// Apply not-implemented macro to all unimplemented flows
impl_not_implemented_flow!(Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData);
impl_not_implemented_flow!(Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData);
impl_not_implemented_flow!(Refund, RefundFlowData, RefundsData, RefundsResponseData);
impl_not_implemented_flow!(CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse);
impl_not_implemented_flow!(CreateSessionToken, PaymentFlowData, SessionTokenRequestData, SessionTokenResponseData);
impl_not_implemented_flow!(SetupMandate, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData);
impl_not_implemented_flow!(RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData);
impl_not_implemented_flow!(Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData);
impl_not_implemented_flow!(DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData);
impl_not_implemented_flow!(SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData);

// Implement source verification stubs for all flows
macro_rules! impl_source_verification_stub {
    ($flow:ty, $common_data:ty, $req:ty, $resp:ty) => {
        impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
            SourceVerification<$flow, $common_data, $req, $resp> for crate::types::ConnectorData<T>
        {
            fn verify_source(
                &self,
                _request: &RouterDataV2<$flow, $common_data, $req, $resp>,
                _secrets: &ConnectorSourceVerificationSecrets,
            ) -> CustomResult<bool, errors::ConnectorError> {
                Ok(true)
            }
        }
    };
}

// Apply source verification stubs to all flows
impl_source_verification_stub!(Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData);
impl_source_verification_stub!(PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData);
impl_source_verification_stub!(RSync, RefundFlowData, RefundSyncData, RefundsResponseData);
impl_source_verification_stub!(Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData);
impl_source_verification_stub!(Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData);
impl_source_verification_stub!(Refund, RefundFlowData, RefundsData, RefundsResponseData);
impl_source_verification_stub!(CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse);
impl_source_verification_stub!(CreateSessionToken, PaymentFlowData, SessionTokenRequestData, SessionTokenResponseData);
impl_source_verification_stub!(SetupMandate, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData);
impl_source_verification_stub!(RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData);
impl_source_verification_stub!(Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData);
impl_source_verification_stub!(DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData);
impl_source_verification_stub!(SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData);

// Implement all required connector traits
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::PaymentOrderCreate for crate::types::ConnectorData<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::PaymentSessionToken for crate::types::ConnectorData<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::PaymentVoidV2 for crate::types::ConnectorData<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::PaymentCaptureV2 for crate::types::ConnectorData<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::RefundV2 for crate::types::ConnectorData<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::RefundExecuteV2 for crate::types::ConnectorData<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::RefundSyncV2 for crate::types::ConnectorData<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::MandateSetupV2 for crate::types::ConnectorData<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::PaymentRepeatV2 for crate::types::ConnectorData<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::DisputeAcceptV2 for crate::types::ConnectorData<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::DisputeDefendV2 for crate::types::ConnectorData<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::DisputeSubmitEvidenceV2 for crate::types::ConnectorData<T> {}