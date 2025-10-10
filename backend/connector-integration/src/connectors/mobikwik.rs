pub mod transformers;
pub mod constants;

use common_enums::CurrencyUnit;
use common_utils::{errors::CustomResult, ext_traits::ByteSliceExt, types::StringMinorUnit};
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
use hyperswitch_masking::Maskable;
use interfaces::{
    api::ConnectorCommon,
    connector_integration_v2::ConnectorIntegrationV2,
    connector_types,
    events::connector_api_logs::ConnectorEvent,
    verification::{ConnectorSourceVerificationSecrets, SourceVerification},
};
use serde::Serialize;
use transformers::{
    self as mobikwik, CheckStatusRequest, MobikwikPaymentsRequest, MobikwikPaymentsResponse,
    MobiSyncResponse,
};

use super::macros;
use crate::{types::ResponseRouterData, with_error_response_body};

pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const ACCEPT: &str = "Accept";
}

// Trait implementations with generic type parameters
impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::ConnectorServiceTrait<T> for Mobikwik<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::PaymentAuthorizeV2<T> for Mobikwik<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::PaymentSyncV2 for Mobikwik<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::PaymentSessionToken for Mobikwik<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::PaymentVoidV2 for Mobikwik<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::RefundSyncV2 for Mobikwik<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::RefundV2 for Mobikwik<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::PaymentCapture for Mobikwik<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::SetupMandateV2<T> for Mobikwik<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::AcceptDispute for Mobikwik<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::SubmitEvidenceV2 for Mobikwik<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::DisputeDefend for Mobikwik<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::IncomingWebhook for Mobikwik<T>
{
    fn verify_webhook_source(
        &self,
        _request: RequestDetails,
        _connector_webhook_secrets: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorAuthType>,
    ) -> Result<bool, error_stack::Report<domain_types::errors::ConnectorError>> {
        // TODO: Implement webhook verification when needed
        Ok(false)
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
        // TODO: Implement webhook processing when needed
        Err(errors::ConnectorError::NotImplemented("Webhook processing".to_string()).into())
    }
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::PaymentOrderCreate for Mobikwik<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::ValidationTrait for Mobikwik<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::RepeatPaymentV2 for Mobikwik<T>
{
}

// MANDATORY: Use create_all_prerequisites! macro - this is the foundation
macros::create_all_prerequisites!(
    connector_name: Mobikwik,
    generic_type: T,
    api: [
        // UPI Authorize flow
        (
            flow: Authorize,
            request_body: MobikwikPaymentsRequest,
            response_body: MobikwikPaymentsResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        // Payment Sync flow
        (
            flow: PSync,
            request_body: CheckStatusRequest,
            response_body: MobiSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ),
        // Stub types for all other flows (MANDATORY for compilation)
        (
            flow: Void,
            request_body: MobikwikVoidRequest,
            response_body: MobikwikVoidResponse,
            router_data: RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ),
        (
            flow: Capture,
            request_body: MobikwikCaptureRequest,
            response_body: MobikwikCaptureResponse,
            router_data: RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ),
        (
            flow: Refund,
            request_body: MobikwikRefundRequest,
            response_body: MobikwikRefundResponse,
            router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ),
        (
            flow: RSync,
            request_body: MobikwikRefundSyncRequest,
            response_body: MobikwikRefundSyncResponse,
            router_data: RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ),
        (
            flow: CreateOrder,
            request_body: MobikwikCreateOrderRequest,
            response_body: MobikwikCreateOrderResponse,
            router_data: RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>,
        ),
        (
            flow: CreateSessionToken,
            request_body: MobikwikSessionTokenRequest,
            response_body: MobikwikSessionTokenResponse,
            router_data: RouterDataV2<CreateSessionToken, PaymentFlowData, SessionTokenRequestData, SessionTokenResponseData>,
        ),
        (
            flow: SetupMandate,
            request_body: MobikwikSetupMandateRequest,
            response_body: MobikwikSetupMandateResponse,
            router_data: RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>,
        ),
        (
            flow: RepeatPayment,
            request_body: MobikwikRepeatPaymentRequest,
            response_body: MobikwikRepeatPaymentResponse,
            router_data: RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>,
        ),
        (
            flow: Accept,
            request_body: MobikwikAcceptDisputeRequest,
            response_body: MobikwikAcceptDisputeResponse,
            router_data: RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>,
        ),
        (
            flow: SubmitEvidence,
            request_body: MobikwikSubmitEvidenceRequest,
            response_body: MobikwikSubmitEvidenceResponse,
            router_data: RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>,
        ),
        (
            flow: DefendDispute,
            request_body: MobikwikDefendDisputeRequest,
            response_body: MobikwikDefendDisputeResponse,
            router_data: RouterDataV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>,
        )
    ],
    amount_converters: [
        amount_converter: StringMinorUnit  // Mobikwik expects amounts as strings in minor units
    ],
    member_functions: {
        pub fn build_headers<F, FCD, Req, Res>(
            &self,
            _req: &RouterDataV2<F, FCD, Req, Res>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError>
        where
            Self: ConnectorIntegrationV2<F, FCD, Req, Res>,
        {
            Ok(vec![
                (
                    headers::CONTENT_TYPE.to_string(),
                    self.common_get_content_type().to_string().into(),
                ),
                (
                    headers::ACCEPT.to_string(),
                    "application/json".to_string().into(),
                ),
            ])
        }

        pub fn connector_base_url<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> &'a str {
            let is_test = req.resource_common_data.test_mode.unwrap_or(false);
            if is_test {
                constants::endpoints::TEST_BASE_URL
            } else {
                constants::endpoints::PROD_BASE_URL
            }
        }

        pub fn connector_base_url_refunds<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, RefundFlowData, Req, Res>,
        ) -> &'a str {
            let is_test = req.resource_common_data.test_mode.unwrap_or(false);
            if is_test {
                constants::endpoints::TEST_BASE_URL
            } else {
                constants::endpoints::PROD_BASE_URL
            }
        }
    }
);

// MANDATORY: Use macro_connector_implementation! for Authorize flow
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Mobikwik,
    curl_request: Json(MobikwikPaymentsRequest),
    curl_response: MobikwikPaymentsResponse,
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
            let mut header = vec![
                (
                    headers::CONTENT_TYPE.to_string(),
                    self.common_get_content_type().to_string().into(),
                ),
                (
                    headers::ACCEPT.to_string(),
                    "application/json".to_string().into(),
                ),
            ];

            // Add any additional headers if needed
            Ok(header)
        }

        fn get_url(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            let base_url = self.connector_base_url(req);
            Ok(format!("{}{}", base_url, constants::endpoints::DEBIT_BALANCE_URL))
        }
    }
);

// MANDATORY: Use macro_connector_implementation! for PSync flow
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Mobikwik,
    curl_request: Json(CheckStatusRequest),
    curl_response: MobiSyncResponse,
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
            let mut header = vec![
                (
                    headers::CONTENT_TYPE.to_string(),
                    self.common_get_content_type().to_string().into(),
                ),
                (
                    headers::ACCEPT.to_string(),
                    "application/json".to_string().into(),
                ),
            ];

            Ok(header)
        }

        fn get_url(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            let base_url = self.connector_base_url(req);
            Ok(format!("{}{}", base_url, constants::endpoints::CHECK_STATUS_URL))
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
> ConnectorCommon for Mobikwik<T>
{
    fn id(&self) -> &'static str {
        "mobikwik"
    }

    fn get_currency_unit(&self) -> CurrencyUnit {
        CurrencyUnit::Minor
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.mobikwik.base_url.as_ref()
    }

    fn get_auth_header(
        &self,
        _auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        // Mobikwik uses custom auth in transformers
        Ok(vec![])
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: mobikwik::MobikwikErrorResponse = res
            .response
            .parse_struct("MobikwikErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        with_error_response_body!(event_builder, response);

        Ok(ErrorResponse {
            status_code: res.status_code,
            code: "MOBIKWIK_ERROR".to_string(),
            message: response.user_message.clone(),
            reason: Some(response.error_message),
            attempt_status: None,
            connector_transaction_id: None,
            network_advice_code: None,
            network_decline_code: None,
            network_error_message: None,
        })
    }
}

// Stub types for unsupported flows (MANDATORY for compilation)
#[derive(Debug, Clone, Serialize)]
pub struct MobikwikVoidRequest;
#[derive(Debug, Clone)]
pub struct MobikwikVoidResponse;

#[derive(Debug, Clone, Serialize)]
pub struct MobikwikCaptureRequest;
#[derive(Debug, Clone)]
pub struct MobikwikCaptureResponse;

#[derive(Debug, Clone, Serialize)]
pub struct MobikwikRefundRequest;
#[derive(Debug, Clone)]
pub struct MobikwikRefundResponse;

#[derive(Debug, Clone, Serialize)]
pub struct MobikwikRefundSyncRequest;
#[derive(Debug, Clone)]
pub struct MobikwikRefundSyncResponse;

#[derive(Debug, Clone, Serialize)]
pub struct MobikwikCreateOrderRequest;
#[derive(Debug, Clone)]
pub struct MobikwikCreateOrderResponse;

#[derive(Debug, Clone, Serialize)]
pub struct MobikwikSessionTokenRequest;
#[derive(Debug, Clone)]
pub struct MobikwikSessionTokenResponse;

#[derive(Debug, Clone, Serialize)]
pub struct MobikwikSetupMandateRequest;
#[derive(Debug, Clone)]
pub struct MobikwikSetupMandateResponse;

#[derive(Debug, Clone, Serialize)]
pub struct MobikwikRepeatPaymentRequest;
#[derive(Debug, Clone)]
pub struct MobikwikRepeatPaymentResponse;

#[derive(Debug, Clone, Serialize)]
pub struct MobikwikAcceptDisputeRequest;
#[derive(Debug, Clone)]
pub struct MobikwikAcceptDisputeResponse;

#[derive(Debug, Clone, Serialize)]
pub struct MobikwikSubmitEvidenceRequest;
#[derive(Debug, Clone)]
pub struct MobikwikSubmitEvidenceResponse;

#[derive(Debug, Clone, Serialize)]
pub struct MobikwikDefendDisputeRequest;
#[derive(Debug, Clone)]
pub struct MobikwikDefendDisputeResponse;

// Stub implementations for unsupported flows (MANDATORY for compilation)
impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
    for Mobikwik<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
    for Mobikwik<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
    for Mobikwik<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
    for Mobikwik<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> ConnectorIntegrationV2<
    CreateOrder,
    PaymentFlowData,
    PaymentCreateOrderData,
    PaymentCreateOrderResponse,
> for Mobikwik<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> ConnectorIntegrationV2<
    SubmitEvidence,
    DisputeFlowData,
    SubmitEvidenceData,
    DisputeResponseData,
> for Mobikwik<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> ConnectorIntegrationV2<
    DefendDispute,
    DisputeFlowData,
    DisputeDefendData,
    DisputeResponseData,
> for Mobikwik<T>
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
    for Mobikwik<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> ConnectorIntegrationV2<
    SetupMandate,
    PaymentFlowData,
    SetupMandateRequestData<T>,
    PaymentsResponseData,
> for Mobikwik<T>
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
    for Mobikwik<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> ConnectorIntegrationV2<
    CreateSessionToken,
    PaymentFlowData,
    SessionTokenRequestData,
    SessionTokenResponseData,
> for Mobikwik<T>
{
}

// SourceVerification implementations for all flows (MANDATORY)
macro_rules! impl_source_verification_stub {
    ($flow:ty, $common_data:ty, $req:ty, $resp:ty) => {
        impl<
                T: PaymentMethodDataTypes
                    + std::fmt::Debug
                    + std::marker::Sync
                    + std::marker::Send
                    + 'static
                    + Serialize,
            > SourceVerification<$flow, $common_data, $req, $resp> for Mobikwik<T>
        {
            fn get_secrets(
                &self,
                _secrets: ConnectorSourceVerificationSecrets,
            ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
                Ok(Vec::new()) // STUB - will be implemented when needed
            }
            fn get_algorithm(
                &self,
            ) -> CustomResult<
                Box<dyn common_utils::crypto::VerifySignature + Send>,
                errors::ConnectorError,
            > {
                Ok(Box::new(common_utils::crypto::NoAlgorithm)) // STUB - will be implemented when needed
            }
            fn get_signature(
                &self,
                _payload: &[u8],
                _router_data: &RouterDataV2<$flow, $common_data, $req, $resp>,
                _secrets: &[u8],
            ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
                Ok(Vec::new()) // STUB - will be implemented when needed
            }
            fn get_message(
                &self,
                payload: &[u8],
                _router_data: &RouterDataV2<$flow, $common_data, $req, $resp>,
                _secrets: &[u8],
            ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
                Ok(payload.to_owned()) // STUB - will be implemented when needed
            }
        }
    };
}

// Apply to all flows (MANDATORY)
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
impl_source_verification_stub!(Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData);
impl_source_verification_stub!(Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData);
impl_source_verification_stub!(Refund, RefundFlowData, RefundsData, RefundsResponseData);
impl_source_verification_stub!(RSync, RefundFlowData, RefundSyncData, RefundsResponseData);
impl_source_verification_stub!(
    SetupMandate,
    PaymentFlowData,
    SetupMandateRequestData<T>,
    PaymentsResponseData
);
impl_source_verification_stub!(
    RepeatPayment,
    PaymentFlowData,
    RepeatPaymentData,
    PaymentsResponseData
);
impl_source_verification_stub!(Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData);
impl_source_verification_stub!(
    SubmitEvidence,
    DisputeFlowData,
    SubmitEvidenceData,
    DisputeResponseData
);
impl_source_verification_stub!(
    DefendDispute,
    DisputeFlowData,
    DisputeDefendData,
    DisputeResponseData
);
impl_source_verification_stub!(
    CreateOrder,
    PaymentFlowData,
    PaymentCreateOrderData,
    PaymentCreateOrderResponse
);
impl_source_verification_stub!(
    CreateSessionToken,
    PaymentFlowData,
    SessionTokenRequestData,
    SessionTokenResponseData
);