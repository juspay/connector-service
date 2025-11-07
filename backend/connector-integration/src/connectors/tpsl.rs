pub mod transformers;
pub mod constants;

use hyperswitch_masking::{Mask, Maskable, PeekInterface};

use common_enums::CurrencyUnit;
use common_utils::{
    errors::CustomResult,
    ext_traits::ByteSliceExt,
    types::StringMinorUnit,
};
use domain_types::{
    connector_flow::{Authorize, PSync, Void, Capture, Refund, RSync, PreAuthenticate, Authenticate, PostAuthenticate, SubmitEvidence, DefendDispute, Accept, RepeatPayment, PaymentMethodToken, SetupMandate, CreateSessionToken, CreateAccessToken, CreateConnectorCustomer, VoidPC, CreateOrder},
    connector_types::{
        ConnectorWebhookSecrets, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData,
        PaymentsSyncData, RequestDetails, DisputeResponseData, RepeatPaymentData, PaymentMethodTokenizationData, 
        SetupMandateRequestData, SessionTokenRequestData, AccessTokenRequestData, AccessTokenResponseData,
        ConnectorCustomerData, ConnectorCustomerResponse, SessionTokenResponseData, PaymentMethodTokenResponse,
        PaymentsPreAuthenticateData, PaymentsAuthenticateData, PaymentsPostAuthenticateData,
        SubmitEvidenceData, DisputeDefendData, AcceptDisputeData, DisputeFlowData, PaymentsCancelPostCaptureData,
        PaymentCreateOrderData, PaymentCreateOrderResponse,
    },
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
};

use error_stack::ResultExt;
use interfaces::{
    api::ConnectorCommon,
    connector_integration_v2::ConnectorIntegrationV2,
    connector_types,
    events::connector_api_logs::ConnectorEvent,
    verification::{ConnectorSourceVerificationSecrets, SourceVerification},
};
use serde::Serialize;
use transformers::{self as tpsl, TpslPaymentsRequest, TpslPaymentsResponse, TpslPaymentsSyncRequest, TpslPaymentsSyncResponse};

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
> connector_types::ConnectorServiceTrait<T> for TPSL<T>
{
}
impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::PaymentAuthorizeV2<T> for TPSL<T>
{
}
impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::PaymentSyncV2 for TPSL<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::IncomingWebhook for TPSL<T>
{
    fn verify_webhook_source(
        &self,
        _request: RequestDetails,
        _connector_webhook_secrets: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorAuthType>,
    ) -> Result<bool, error_stack::Report<domain_types::errors::ConnectorError>> {
        // TPSL webhook verification implementation would go here
        Ok(true) // STUB implementation
    }

    fn get_event_type(
        &self,
        _request: RequestDetails,
        _connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorAuthType>,
    ) -> Result<
        domain_types::connector_types::EventType,
        error_stack::Report<domain_types::errors::ConnectorError>,
    > {
        Ok(domain_types::connector_types::EventType::PaymentIntentSuccess)
    }

    fn process_payment_webhook(
        &self,
        _request: RequestDetails,
        _connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorAuthType>,
    ) -> Result<
        domain_types::connector_types::WebhookDetailsResponse,
        error_stack::Report<domain_types::errors::ConnectorError>,
    > {
        // TPSL webhook processing implementation would go here
        Err(errors::ConnectorError::WebhookResourceObjectNotFound.into())
    }
}

macros::create_all_prerequisites!(
    connector_name: TPSL,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: TpslPaymentsRequest,
            response_body: TpslPaymentsResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: PSync,
            request_body: TpslPaymentsSyncRequest,
            response_body: TpslPaymentsSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
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
                constants::TPSL_TEST_BASE_URL
            } else {
                constants::TPSL_PROD_BASE_URL
            }
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: TPSL,
    curl_request: Json(TpslPaymentsRequest),
    curl_response: TpslPaymentsResponse,
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

            let auth_type = transformers::TpslAuth::try_from(&req.connector_auth_type)?;

            let mut auth_header = get_tpsl_auth_headers(&auth_type)?;

            header.append(&mut auth_header);
            Ok(header)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            Ok(format!(
                "{}/PaymentGateway/services/TransactionDetailsNew",
                self.connector_base_url_payments(req)
            ))
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: TPSL,
    curl_request: Json(TpslPaymentsSyncRequest),
    curl_response: TpslPaymentsSyncResponse,
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

            let auth_type = transformers::TpslAuth::try_from(&req.connector_auth_type)?;

            let mut auth_header = get_tpsl_auth_headers(&auth_type)?;

            header.append(&mut auth_header);
            Ok(header)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            Ok(format!(
                "{}/PaymentGateway/services/TransactionDetailsNew",
                self.connector_base_url_payments(req)
            ))
        }
    }
);

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> ConnectorCommon for TPSL<T>
{
    fn id(&self) -> &'static str {
        "tpsl"
    }

    fn get_currency_unit(&self) -> CurrencyUnit {
        CurrencyUnit::Base
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.tpsl.base_url.as_ref()
    }

    fn get_auth_header(
        &self,
        _auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        // TPSL uses custom auth in get_headers
        Ok(vec![])
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: tpsl::TpslErrorResponse = res
            .response
            .parse_struct("TpslErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        with_error_response_body!(event_builder, response);

        let error_message = response.error_message.clone();
        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response.error_code.to_string(),
            message: error_message.clone(),
            reason: Some(error_message),
            attempt_status: Some(response.get_error_status()),
            connector_transaction_id: None,
            network_advice_code: None,
            network_decline_code: None,
            network_error_message: None,
        })
    }
}

// Additional required trait implementations
impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::PaymentSessionToken for TPSL<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::PaymentAccessToken for TPSL<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::CreateConnectorCustomer for TPSL<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::PaymentVoidV2 for TPSL<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::PaymentVoidPostCaptureV2 for TPSL<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::RefundSyncV2 for TPSL<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::RefundV2 for TPSL<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::PaymentCapture for TPSL<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::SetupMandateV2<T> for TPSL<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::AcceptDispute for TPSL<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::SubmitEvidenceV2 for TPSL<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::DisputeDefend for TPSL<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::RepeatPaymentV2 for TPSL<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::PaymentTokenV2<T> for TPSL<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::PaymentPreAuthenticateV2<T> for TPSL<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::PaymentAuthenticateV2<T> for TPSL<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::PaymentPostAuthenticateV2<T> for TPSL<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::ValidationTrait for TPSL<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::PaymentOrderCreate for TPSL<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> ConnectorIntegrationV2<PreAuthenticate, PaymentFlowData, PaymentsPreAuthenticateData<T>, PaymentsResponseData>
    for TPSL<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> ConnectorIntegrationV2<Authenticate, PaymentFlowData, PaymentsAuthenticateData<T>, PaymentsResponseData>
    for TPSL<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> ConnectorIntegrationV2<PostAuthenticate, PaymentFlowData, PaymentsPostAuthenticateData<T>, PaymentsResponseData>
    for TPSL<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
    for TPSL<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
    for TPSL<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    for TPSL<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> ConnectorIntegrationV2<VoidPC, PaymentFlowData, PaymentsCancelPostCaptureData, PaymentsResponseData>
    for TPSL<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> ConnectorIntegrationV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>
    for TPSL<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> ConnectorIntegrationV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>
    for TPSL<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> ConnectorIntegrationV2<PaymentMethodToken, PaymentFlowData, PaymentMethodTokenizationData<T>, PaymentMethodTokenResponse>
    for TPSL<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> ConnectorIntegrationV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>
    for TPSL<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> ConnectorIntegrationV2<CreateSessionToken, PaymentFlowData, SessionTokenRequestData, SessionTokenResponseData>
    for TPSL<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> ConnectorIntegrationV2<CreateAccessToken, PaymentFlowData, AccessTokenRequestData, AccessTokenResponseData>
    for TPSL<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> ConnectorIntegrationV2<CreateConnectorCustomer, PaymentFlowData, ConnectorCustomerData, ConnectorCustomerResponse>
    for TPSL<T>
{
}

// Stub implementations for unsupported flows
impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> ConnectorIntegrationV2<Void, PaymentFlowData, domain_types::connector_types::PaymentVoidData, PaymentsResponseData>
    for TPSL<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> ConnectorIntegrationV2<Capture, PaymentFlowData, domain_types::connector_types::PaymentsCaptureData, PaymentsResponseData>
    for TPSL<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> ConnectorIntegrationV2<Refund, domain_types::connector_types::RefundFlowData, domain_types::connector_types::RefundsData, domain_types::connector_types::RefundsResponseData>
    for TPSL<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> ConnectorIntegrationV2<RSync, domain_types::connector_types::RefundFlowData, domain_types::connector_types::RefundSyncData, domain_types::connector_types::RefundsResponseData>
    for TPSL<T>
{
}

// SourceVerification implementations for all flows
macro_rules! impl_source_verification_stub {
    ($flow:ty, $common_data:ty, $req:ty, $resp:ty) => {
        impl<
                T: PaymentMethodDataTypes
                    + std::fmt::Debug
                    + std::marker::Sync
                    + std::marker::Send
                    + 'static
                    + Serialize,
            > SourceVerification<$flow, $common_data, $req, $resp> for TPSL<T>
        {
            fn get_secrets(
                &self,
                _secrets: ConnectorSourceVerificationSecrets,
            ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
                Ok(Vec::new()) // STUB - will be implemented in Phase 10
            }
            fn get_algorithm(
                &self,
            ) -> CustomResult<
                Box<dyn common_utils::crypto::VerifySignature + Send>,
                errors::ConnectorError,
            > {
                Ok(Box::new(common_utils::crypto::NoAlgorithm)) // STUB - will be implemented in Phase 10
            }
            fn get_signature(
                &self,
                _payload: &[u8],
                _router_data: &RouterDataV2<$flow, $common_data, $req, $resp>,
                _secrets: &[u8],
            ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
                Ok(Vec::new()) // STUB - will be implemented in Phase 10
            }
            fn get_message(
                &self,
                payload: &[u8],
                _router_data: &RouterDataV2<$flow, $common_data, $req, $resp>,
                _secrets: &[u8],
            ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
                Ok(payload.to_owned()) // STUB - will be implemented in Phase 10
            }
        }
    };
}

// Apply to all flows
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
impl_source_verification_stub!(
    Capture,
    PaymentFlowData,
    domain_types::connector_types::PaymentsCaptureData,
    PaymentsResponseData
);
impl_source_verification_stub!(Void, PaymentFlowData, domain_types::connector_types::PaymentVoidData, PaymentsResponseData);
impl_source_verification_stub!(VoidPC, PaymentFlowData, PaymentsCancelPostCaptureData, PaymentsResponseData);
impl_source_verification_stub!(Refund, domain_types::connector_types::RefundFlowData, domain_types::connector_types::RefundsData, domain_types::connector_types::RefundsResponseData);
impl_source_verification_stub!(RSync, domain_types::connector_types::RefundFlowData, domain_types::connector_types::RefundSyncData, domain_types::connector_types::RefundsResponseData);
impl_source_verification_stub!(PreAuthenticate, PaymentFlowData, PaymentsPreAuthenticateData<T>, PaymentsResponseData);
impl_source_verification_stub!(Authenticate, PaymentFlowData, PaymentsAuthenticateData<T>, PaymentsResponseData);
impl_source_verification_stub!(PostAuthenticate, PaymentFlowData, PaymentsPostAuthenticateData<T>, PaymentsResponseData);
impl_source_verification_stub!(SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData);
impl_source_verification_stub!(DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData);
impl_source_verification_stub!(Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData);
impl_source_verification_stub!(RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData);
impl_source_verification_stub!(PaymentMethodToken, PaymentFlowData, PaymentMethodTokenizationData<T>, PaymentMethodTokenResponse);
impl_source_verification_stub!(SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData);
impl_source_verification_stub!(CreateSessionToken, PaymentFlowData, SessionTokenRequestData, SessionTokenResponseData);
impl_source_verification_stub!(CreateAccessToken, PaymentFlowData, AccessTokenRequestData, AccessTokenResponseData);
impl_source_verification_stub!(CreateConnectorCustomer, PaymentFlowData, ConnectorCustomerData, ConnectorCustomerResponse);
impl_source_verification_stub!(CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse);

fn get_tpsl_auth_headers(
    auth_type: &transformers::TpslAuth,
) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
    let api_key = auth_type
        .api_key
        .clone()
        .ok_or(errors::ConnectorError::FailedToObtainAuthType)?;
    
    Ok(vec![(
        headers::AUTHORIZATION.to_string(),
        format!("Bearer {}", api_key.peek()).into_masked(),
    )])
}