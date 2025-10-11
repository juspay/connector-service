pub mod transformers;

use common_utils::{errors::CustomResult, ext_traits::ByteSliceExt, types::{FloatMajorUnit, StringMinorUnit}};
use domain_types::{
    connector_flow::{
        Accept, Authorize, Capture, CreateOrder, CreateSessionToken, DefendDispute, PSync, RSync,
        Refund, RepeatPayment, SetupMandate, SubmitEvidence, Void,
    },
    connector_types::{
        AcceptDisputeData, DisputeDefendData, DisputeFlowData,
        DisputeResponseData, PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData,
        PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData,
        PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData,
        RepeatPaymentData, SessionTokenRequestData, SessionTokenResponseData,
        SetupMandateRequestData, SubmitEvidenceData,
    },
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::{ConnectorInfo, Connectors},
};
use hyperswitch_masking::{Maskable, PeekInterface};
use interfaces::{
    api::ConnectorCommon,
    connector_integration_v2::ConnectorIntegrationV2,
    connector_types,
    events::connector_api_logs::ConnectorEvent,
    verification::{ConnectorSourceVerificationSecrets, SourceVerification},
};
use serde::Serialize;
use transformers::{ZaakPayPaymentsRequest, ZaakPayPaymentsResponse};

use super::macros;

pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const AUTHORIZATION: &str = "Authorization";
}

#[derive(Debug, Clone)]
pub struct ZaakPay<T: PaymentMethodDataTypes> {
    phantom: std::marker::PhantomData<T>,
}

impl<T: PaymentMethodDataTypes> ZaakPay<T> {
    pub fn new() -> Self {
        Self {
            phantom: std::marker::PhantomData,
        }
    }
}

// Trait implementations with generic type parameters
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize
            + std::default::Default,
    > ConnectorCommon for crate::types::ConnectorData<T>
{
    fn id(&self) -> &'static str {
        "zaakpay"
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.zaakpay.base_url.as_ref()
    }

    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        match auth_type {
            ConnectorAuthType::HeaderKey { api_key } => Ok(vec![(
                headers::AUTHORIZATION.to_string(),
                format!("Bearer {}", api_key.peek()).into(),
            )]),
            _ => Err(errors::ConnectorError::AuthenticationFailed.into()),
        }
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
        ) -> CustomResult<Option<common_utils::request::Request>, errors::ConnectorError> {
            let connector_request = ZaakPayPaymentsRequest::try_from(req)?;
            let auth_header = self.get_auth_header(&req.connector_auth_type)?;
            
            let request = common_utils::request::RequestBuilder::new()
                .method(common_utils::request::Method::Post)
                .url(&format!("{}/transact", self.base_url(&req.connector_meta_data)))
                .attach_default_headers()
                .headers(auth_header)
                .body(common_utils::request::RequestContent::Json(Box::new(connector_request)))
                .build();

            Ok(Some(request))
        }

        fn handle_response_v2(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            res: Response,
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

// Implement all required connector traits
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize + std::default::Default>
    connector_types::PaymentOrderCreate for crate::types::ConnectorData<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize + std::default::Default>
    connector_types::PaymentSessionToken for crate::types::ConnectorData<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize + std::default::Default>
    connector_types::PaymentVoidV2 for crate::types::ConnectorData<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize + std::default::Default>
    connector_types::PaymentCapture for crate::types::ConnectorData<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize + std::default::Default>
    connector_types::RefundV2 for crate::types::ConnectorData<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize + std::default::Default>
    connector_types::RefundSyncV2 for crate::types::ConnectorData<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize + std::default::Default>
    connector_types::SetupMandateV2<T> for crate::types::ConnectorData<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize + std::default::Default>
    connector_types::RepeatPaymentV2 for crate::types::ConnectorData<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize + std::default::Default>
    connector_types::AcceptDispute for crate::types::ConnectorData<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize + std::default::Default>
    connector_types::DisputeDefend for crate::types::ConnectorData<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize + std::default::Default>
    connector_types::SubmitEvidenceV2 for crate::types::ConnectorData<T> {}

// Implement not-implemented flows with proper error handling
macro_rules! impl_not_implemented_flow {
    ($flow:ty, $common_data:ty, $req:ty, $resp:ty) => {
        impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize + std::default::Default>
            ConnectorIntegrationV2<$flow, $common_data, $req, $resp> for crate::types::ConnectorData<T>
        {
            fn build_request_v2(
                &self,
                _req: &RouterDataV2<$flow, $common_data, $req, $resp>,
            ) -> CustomResult<Option<common_utils::request::Request>, errors::ConnectorError> {
                let flow_name = stringify!($flow);
                Err(errors::ConnectorError::NotImplemented(flow_name.to_string()).into())
            }

            fn handle_response_v2(
                &self,
                _req: &RouterDataV2<$flow, $common_data, $req, $resp>,
                _res: Response,
            ) -> CustomResult<RouterDataV2<$flow, $common_data, $req, $resp>, errors::ConnectorError> {
                let flow_name = stringify!($flow);
                Err(errors::ConnectorError::NotImplemented(flow_name.to_string()).into())
            }
        }
    };
}

// Apply not-implemented macro to all unimplemented flows
impl_not_implemented_flow!(PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData);
impl_not_implemented_flow!(RSync, RefundFlowData, RefundSyncData, RefundsResponseData);
impl_not_implemented_flow!(Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData);
impl_not_implemented_flow!(Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData);
impl_not_implemented_flow!(Refund, RefundFlowData, RefundsData, RefundsResponseData);
impl_not_implemented_flow!(CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse);
impl_not_implemented_flow!(CreateSessionToken, PaymentFlowData, SessionTokenRequestData, SessionTokenResponseData);
impl_not_implemented_flow!(SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData);
impl_not_implemented_flow!(RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData);
impl_not_implemented_flow!(Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData);
impl_not_implemented_flow!(DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData);
impl_not_implemented_flow!(SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData);

// Implement source verification stubs for all flows
macro_rules! impl_source_verification_stub {
    ($flow:ty, $common_data:ty, $req:ty, $resp:ty) => {
        impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize + std::default::Default>
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
impl_source_verification_stub!(SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData);
impl_source_verification_stub!(RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData);
impl_source_verification_stub!(Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData);
impl_source_verification_stub!(DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData);
impl_source_verification_stub!(SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData);