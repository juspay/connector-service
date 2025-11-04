pub mod transformers;



use common_enums::CurrencyUnit;
use common_utils::{
    errors::CustomResult,
    ext_traits::ByteSliceExt,
    types::{StringMinorUnit},
};
use domain_types::{
    connector_flow::{
        Authorize, PSync, CreateOrder, CreateSessionToken, CreateAccessToken, CreateConnectorCustomer,
        PaymentMethodToken, Void, VoidPC, Refund, RSync, Capture, SetupMandate, RepeatPayment,
        Accept, DefendDispute, SubmitEvidence, PreAuthenticate, Authenticate, PostAuthenticate,
    },
    connector_types::{
        PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData,
        PaymentCreateOrderData, PaymentCreateOrderResponse, SessionTokenRequestData, SessionTokenResponseData,
        AccessTokenRequestData, AccessTokenResponseData, ConnectorCustomerData, ConnectorCustomerResponse,
        PaymentMethodTokenizationData, PaymentMethodTokenResponse, PaymentVoidData, PaymentsCancelPostCaptureData,
        RefundsData, RefundsResponseData, RefundSyncData, PaymentsCaptureData, SetupMandateRequestData,
        RepeatPaymentData, AcceptDisputeData, DisputeDefendData, SubmitEvidenceData, DisputeResponseData,
        PaymentsPreAuthenticateData, PaymentsAuthenticateData, PaymentsPostAuthenticateData,
        RefundFlowData, DisputeFlowData,
    },
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
};
use error_stack::ResultExt;
use hyperswitch_masking::{Maskable, PeekInterface, Mask};
use interfaces::{
    api::ConnectorCommon,
    connector_integration_v2::ConnectorIntegrationV2,
    connector_types,
    events::connector_api_logs::ConnectorEvent,
    verification::{ConnectorSourceVerificationSecrets, SourceVerification},
};
use serde::Serialize;
use transformers::{
    self as easebuzz, 
    EaseBuzzPaymentsRequest, 
    EaseBuzzPaymentsResponse, 
    EaseBuzzPaymentsSyncRequest, 
    EaseBuzzPaymentsSyncResponse,
    // Additional dummy types for unsupported flows
    EaseBuzzPaymentOrderCreateRequest, EaseBuzzPaymentOrderCreateResponse,
    EaseBuzzSessionTokenRequest, EaseBuzzSessionTokenResponse,
    EaseBuzzAccessTokenRequest, EaseBuzzAccessTokenResponse,
    EaseBuzzCreateConnectorCustomerRequest, EaseBuzzCreateConnectorCustomerResponse,
    EaseBuzzPaymentMethodTokenRequest, EaseBuzzPaymentMethodTokenResponse,
    EaseBuzzPaymentVoidRequest, EaseBuzzPaymentVoidResponse,
    EaseBuzzPaymentVoidPostCaptureRequest, EaseBuzzPaymentVoidPostCaptureResponse,
    EaseBuzzRefundRequest, EaseBuzzRefundResponse,
    EaseBuzzRefundSyncRequest, EaseBuzzRefundSyncResponse,
    EaseBuzzPaymentCaptureRequest, EaseBuzzPaymentCaptureResponse,
    EaseBuzzSetupMandateRequest, EaseBuzzSetupMandateResponse,
    EaseBuzzRepeatPaymentRequest, EaseBuzzRepeatPaymentResponse,
    EaseBuzzAcceptDisputeRequest, EaseBuzzAcceptDisputeResponse,
    EaseBuzzDefendDisputeRequest, EaseBuzzDefendDisputeResponse,
    EaseBuzzSubmitEvidenceRequest, EaseBuzzSubmitEvidenceResponse,
    EaseBuzzPreAuthenticateRequest, EaseBuzzPreAuthenticateResponse,
    EaseBuzzAuthenticateRequest, EaseBuzzAuthenticateResponse,
    EaseBuzzPostAuthenticateRequest, EaseBuzzPostAuthenticateResponse,
};

use super::macros;
use crate::{types::ResponseRouterData, with_error_response_body};

pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const AUTHORIZATION: &str = "Authorization";
}





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
        // Additional flows for ConnectorServiceTrait compliance
        (
            flow: CreateOrder,
            request_body: EaseBuzzPaymentOrderCreateRequest,
            response_body: EaseBuzzPaymentOrderCreateResponse,
            router_data: RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>,
        ),
        (
            flow: CreateSessionToken,
            request_body: EaseBuzzSessionTokenRequest,
            response_body: EaseBuzzSessionTokenResponse,
            router_data: RouterDataV2<CreateSessionToken, PaymentFlowData, SessionTokenRequestData, SessionTokenResponseData>,
        ),
        (
            flow: CreateAccessToken,
            request_body: EaseBuzzAccessTokenRequest,
            response_body: EaseBuzzAccessTokenResponse,
            router_data: RouterDataV2<CreateAccessToken, PaymentFlowData, AccessTokenRequestData, AccessTokenResponseData>,
        ),
        (
            flow: CreateConnectorCustomer,
            request_body: EaseBuzzCreateConnectorCustomerRequest,
            response_body: EaseBuzzCreateConnectorCustomerResponse,
            router_data: RouterDataV2<CreateConnectorCustomer, PaymentFlowData, ConnectorCustomerData, ConnectorCustomerResponse>,
        ),
        (
            flow: PaymentMethodToken,
            request_body: EaseBuzzPaymentMethodTokenRequest,
            response_body: EaseBuzzPaymentMethodTokenResponse,
            router_data: RouterDataV2<PaymentMethodToken, PaymentFlowData, PaymentMethodTokenizationData<T>, PaymentMethodTokenResponse>,
        ),
        (
            flow: Void,
            request_body: EaseBuzzPaymentVoidRequest,
            response_body: EaseBuzzPaymentVoidResponse,
            router_data: RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ),
        (
            flow: VoidPC,
            request_body: EaseBuzzPaymentVoidPostCaptureRequest,
            response_body: EaseBuzzPaymentVoidPostCaptureResponse,
            router_data: RouterDataV2<VoidPC, PaymentFlowData, PaymentsCancelPostCaptureData, PaymentsResponseData>,
        ),
        (
            flow: Refund,
            request_body: EaseBuzzRefundRequest,
            response_body: EaseBuzzRefundResponse,
            router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ),
        (
            flow: RSync,
            request_body: EaseBuzzRefundSyncRequest,
            response_body: EaseBuzzRefundSyncResponse,
            router_data: RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ),
        (
            flow: Capture,
            request_body: EaseBuzzPaymentCaptureRequest,
            response_body: EaseBuzzPaymentCaptureResponse,
            router_data: RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ),
        (
            flow: SetupMandate,
            request_body: EaseBuzzSetupMandateRequest,
            response_body: EaseBuzzSetupMandateResponse,
            router_data: RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>,
        ),
        (
            flow: RepeatPayment,
            request_body: EaseBuzzRepeatPaymentRequest,
            response_body: EaseBuzzRepeatPaymentResponse,
            router_data: RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>,
        ),
        (
            flow: Accept,
            request_body: EaseBuzzAcceptDisputeRequest,
            response_body: EaseBuzzAcceptDisputeResponse,
            router_data: RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>,
        ),
        (
            flow: DefendDispute,
            request_body: EaseBuzzDefendDisputeRequest,
            response_body: EaseBuzzDefendDisputeResponse,
            router_data: RouterDataV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>,
        ),
        (
            flow: SubmitEvidence,
            request_body: EaseBuzzSubmitEvidenceRequest,
            response_body: EaseBuzzSubmitEvidenceResponse,
            router_data: RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>,
        ),
        (
            flow: PreAuthenticate,
            request_body: EaseBuzzPreAuthenticateRequest,
            response_body: EaseBuzzPreAuthenticateResponse,
            router_data: RouterDataV2<PreAuthenticate, PaymentFlowData, PaymentsPreAuthenticateData<T>, PaymentsResponseData>,
        ),
        (
            flow: Authenticate,
            request_body: EaseBuzzAuthenticateRequest,
            response_body: EaseBuzzAuthenticateResponse,
            router_data: RouterDataV2<Authenticate, PaymentFlowData, PaymentsAuthenticateData<T>, PaymentsResponseData>,
        ),
        (
            flow: PostAuthenticate,
            request_body: EaseBuzzPostAuthenticateRequest,
            response_body: EaseBuzzPostAuthenticateResponse,
            router_data: RouterDataV2<PostAuthenticate, PaymentFlowData, PaymentsPostAuthenticateData<T>, PaymentsResponseData>,
        )
    ],
    amount_converters: [
        amount_converter: StringMinorUnit
    ],
    member_functions: {
        pub fn build_headers<F, FCD, Req, Res>(
            &self,
            _req: &RouterDataV2<F, FCD, Req, Res>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError>
        where
            Self: ConnectorIntegrationV2<F, FCD, Req, Res>,
        {
            Ok(vec![(
                headers::CONTENT_TYPE.to_string(),
                self.common_get_content_type().to_string().into(),
            )])
        }

        pub fn connector_base_url_payments<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> &'a str {
            if req.resource_common_data.test_mode.unwrap_or(false) {
                "https://testpay.easebuzz.in"
            } else {
                "https://pay.easebuzz.in"
            }
        }
    }
);

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
        fn get_headers(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            let mut header = vec![(
                headers::CONTENT_TYPE.to_string(),
                self.common_get_content_type().to_string().into(),
            )];

            let auth_header = get_easebuzz_auth_header(&req.connector_auth_type)?;
            header.push((headers::AUTHORIZATION.to_string(), auth_header));

            Ok(header)
        }
        
        fn get_url(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            Ok(format!("{}/payment/initiateLink", self.connector_base_url_payments(req)))
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
        fn get_headers(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            let mut header = vec![(
                headers::CONTENT_TYPE.to_string(),
                self.common_get_content_type().to_string().into(),
            )];

            let auth_header = get_easebuzz_auth_header(&req.connector_auth_type)?;
            header.push((headers::AUTHORIZATION.to_string(), auth_header));

            Ok(header)
        }
        
        fn get_url(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            Ok(format!("{}/transaction/v1/retrieve", self.connector_base_url_payments(req)))
        }
    }
);

// Add the required trait implementations that are generated by the macro
impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::PaymentAuthorizeV2<T> for EaseBuzz<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::PaymentSyncV2 for EaseBuzz<T>
{
}



impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> ConnectorCommon for EaseBuzz<T>
{
    fn id(&self) -> &'static str {
        "easebuzz"
    }

    fn get_currency_unit(&self) -> CurrencyUnit {
        CurrencyUnit::Base
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn base_url<'a>(&self, _connectors: &'a Connectors) -> &'a str {
        "https://pay.easebuzz.in" // Default base URL
    }

    fn get_auth_header(
        &self,
        _auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        // EaseBuzz uses custom auth in get_headers
        Ok(vec![])
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: easebuzz::EaseBuzzErrorResponse = res
            .response
            .parse_struct("EaseBuzzErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        with_error_response_body!(event_builder, response);

        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response.status.to_string(),
            message: response.error_desc.clone().unwrap_or_default(),
            reason: response.error_desc,
            attempt_status: None,
            connector_transaction_id: None,
            network_advice_code: None,
            network_decline_code: None,
            network_error_message: None,
        })
    }
}



fn get_easebuzz_auth_header(
    connector_auth_type: &ConnectorAuthType,
) -> CustomResult<Maskable<String>, errors::ConnectorError> {
    match connector_auth_type {
        ConnectorAuthType::SignatureKey { api_key, .. } => {
            let key = api_key.peek();
            Ok(format!("key {}: {}", key, "easebuzz").into_masked())
        }
        _ => Err(errors::ConnectorError::FailedToObtainAuthType)?,
    }
}

// SourceVerification implementations
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
                Ok(Vec::new()) // STUB
            }
            fn get_algorithm(
                &self,
            ) -> CustomResult<
                Box<dyn common_utils::crypto::VerifySignature + Send>,
                errors::ConnectorError,
            > {
                Ok(Box::new(common_utils::crypto::NoAlgorithm)) // STUB
            }
            fn get_signature(
                &self,
                _payload: &[u8],
                _router_data: &RouterDataV2<$flow, $common_data, $req, $resp>,
                _secrets: &[u8],
            ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
                Ok(Vec::new()) // STUB
            }
            fn get_message(
                &self,
                payload: &[u8],
                _router_data: &RouterDataV2<$flow, $common_data, $req, $resp>,
                _secrets: &[u8],
            ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
                Ok(payload.to_owned()) // STUB
            }
        }
    };
}

// Apply to required flows
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

// Implement ConnectorServiceTrait - the macro generates ConnectorIntegrationV2 for Authorize and PSync
// We need to implement the trait itself which requires many sub-traits
impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::ConnectorServiceTrait<T> for EaseBuzz<T>
{
}

// Implement all required traits for ConnectorServiceTrait compliance
impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::ValidationTrait for EaseBuzz<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::PaymentOrderCreate for EaseBuzz<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::PaymentSessionToken for EaseBuzz<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::PaymentAccessToken for EaseBuzz<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::CreateConnectorCustomer for EaseBuzz<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::PaymentTokenV2<T> for EaseBuzz<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::PaymentVoidV2 for EaseBuzz<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::PaymentVoidPostCaptureV2 for EaseBuzz<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::IncomingWebhook for EaseBuzz<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::RefundV2 for EaseBuzz<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::PaymentCapture for EaseBuzz<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::SetupMandateV2<T> for EaseBuzz<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::RepeatPaymentV2 for EaseBuzz<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::AcceptDispute for EaseBuzz<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::RefundSyncV2 for EaseBuzz<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::DisputeDefend for EaseBuzz<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::SubmitEvidenceV2 for EaseBuzz<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::PaymentPreAuthenticateV2<T> for EaseBuzz<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::PaymentAuthenticateV2<T> for EaseBuzz<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::PaymentPostAuthenticateV2<T> for EaseBuzz<T>
{
}



