pub mod constants;
pub mod transformers;

use std::fmt::Debug;

use common_enums::CurrencyUnit;
use common_utils::{errors::CustomResult, ext_traits::ByteSliceExt, types::StringMinorUnit};
use domain_types::{
    connector_flow::{
        Accept, Authenticate, Authorize, Capture, CreateOrder, CreateSessionToken, DefendDispute, PostAuthenticate, PreAuthenticate, PSync, RSync,
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
use transformers::{self as easebuzz, EasebuzzPaymentsRequest, EasebuzzPaymentsResponse, EasebuzzPaymentsSyncRequest, EasebuzzPaymentsSyncResponse};

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
    > connector_types::ConnectorServiceTrait<T> for Easebuzz<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::PaymentAuthorizeV2<T> for Easebuzz<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::PaymentSyncV2 for Easebuzz<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::PaymentSessionToken for Easebuzz<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAccessToken for Easebuzz<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::CreateConnectorCustomer for Easebuzz<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::PaymentVoidV2 for Easebuzz<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::RefundSyncV2 for Easebuzz<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::RefundV2 for Easebuzz<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::PaymentCapture for Easebuzz<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::SetupMandateV2<T> for Easebuzz<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::AcceptDispute for Easebuzz<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::SubmitEvidenceV2 for Easebuzz<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::DisputeDefend for Easebuzz<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::IncomingWebhook for Easebuzz<T>
{
    fn verify_webhook_source(
        &self,
        request: RequestDetails,
        connector_webhook_secrets: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorAuthType>,
    ) -> Result<bool, error_stack::Report<domain_types::errors::ConnectorError>> {
        let webhook_secret = match connector_webhook_secrets.clone() {
            Some(secrets) => secrets,
            None => return Ok(false),
        };

        let easebuzz_signature = request
            .headers
            .get("x-easebuzz-signature")
            .ok_or(errors::ConnectorError::WebhookSignatureNotFound)?;

        let signature = easebuzz_signature.as_bytes();

        let secret_auth = String::from_utf8(webhook_secret.secret.to_vec())
            .change_context(errors::ConnectorError::WebhookSourceVerificationFailed)
            .attach_printable("Could not convert secret to UTF-8")?;
        let signature_auth = String::from_utf8(signature.to_vec())
            .change_context(errors::ConnectorError::WebhookSourceVerificationFailed)
            .attach_printable("Could not convert signature to UTF-8")?;
        Ok(signature_auth == secret_auth)
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
        request: RequestDetails,
        _connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorAuthType>,
    ) -> Result<
        domain_types::connector_types::WebhookDetailsResponse,
        error_stack::Report<domain_types::errors::ConnectorError>,
    > {
        let webhook: transformers::EasebuzzIncomingWebhook = request
            .body
            .parse_struct("EasebuzzIncomingWebhook")
            .change_context(errors::ConnectorError::WebhookResourceObjectNotFound)?;

        let status = if webhook.status.unwrap_or(false) {
            common_enums::AttemptStatus::Charged
        } else {
            common_enums::AttemptStatus::Failure
        };

        Ok(domain_types::connector_types::WebhookDetailsResponse {
            resource_id: Some(
                domain_types::connector_types::ResponseId::ConnectorTransactionId(
                    webhook.txnid.clone().unwrap_or_else(|| "unknown".to_string()),
                ),
            ),
            status,
            status_code: 200,
            mandate_reference: None,
            connector_response_reference_id: None,
            error_code: webhook.error_code,
            error_message: webhook.error_desc.clone(),
            raw_connector_response: Some(String::from_utf8_lossy(&request.body).to_string()),
            response_headers: None,
            minor_amount_captured: None,
            amount_captured: None,
            error_reason: webhook.error_desc.clone(),
            network_txn_id: webhook.easebuzz_id,
            transformation_status: common_enums::WebhookTransformationStatus::Complete,
        })
    }
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::PaymentOrderCreate for Easebuzz<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::ValidationTrait for Easebuzz<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::RepeatPaymentV2 for Easebuzz<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::PaymentTokenV2<T> for Easebuzz<T>
{
}

// Authentication trait implementations
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::PaymentPreAuthenticateV2<T> for Easebuzz<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::PaymentAuthenticateV2<T> for Easebuzz<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::PaymentPostAuthenticateV2<T> for Easebuzz<T>
{
}

// Stub types for unsupported flows
#[derive(Debug, Clone, Serialize)]
pub struct EasebuzzVoidRequest;
#[derive(Debug, Clone)]
pub struct EasebuzzVoidResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EasebuzzCaptureRequest;
#[derive(Debug, Clone)]
pub struct EasebuzzCaptureResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EasebuzzRefundRequest;
#[derive(Debug, Clone)]
pub struct EasebuzzRefundResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EasebuzzRefundSyncRequest;
#[derive(Debug, Clone)]
pub struct EasebuzzRefundSyncResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EasebuzzCreateOrderRequest;
#[derive(Debug, Clone)]
pub struct EasebuzzCreateOrderResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EasebuzzSessionTokenRequest;
#[derive(Debug, Clone)]
pub struct EasebuzzSessionTokenResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EasebuzzSetupMandateRequest;
#[derive(Debug, Clone)]
pub struct EasebuzzSetupMandateResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EasebuzzRepeatPaymentRequest;
#[derive(Debug, Clone)]
pub struct EasebuzzRepeatPaymentResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EasebuzzAcceptDisputeRequest;
#[derive(Debug, Clone)]
pub struct EasebuzzAcceptDisputeResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EasebuzzSubmitEvidenceRequest;
#[derive(Debug, Clone)]
pub struct EasebuzzSubmitEvidenceResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EasebuzzDefendDisputeRequest;
#[derive(Debug, Clone)]
pub struct EasebuzzDefendDisputeResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EasebuzzPreAuthenticateRequest;
#[derive(Debug, Clone)]
pub struct EasebuzzPreAuthenticateResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EasebuzzAuthenticateRequest;
#[derive(Debug, Clone)]
pub struct EasebuzzAuthenticateResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EasebuzzPostAuthenticateRequest;
#[derive(Debug, Clone)]
pub struct EasebuzzPostAuthenticateResponse;

macros::create_all_prerequisites!(
    connector_name: Easebuzz,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: EasebuzzPaymentsRequest,
            response_body: EasebuzzPaymentsResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: PSync,
            request_body: EasebuzzPaymentsSyncRequest,
            response_body: EasebuzzPaymentsSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ),
        // Add all other flows with stub types
        (
            flow: Void,
            request_body: EasebuzzVoidRequest,
            response_body: EasebuzzVoidResponse,
            router_data: RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ),
        (
            flow: Capture,
            request_body: EasebuzzCaptureRequest,
            response_body: EasebuzzCaptureResponse,
            router_data: RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ),
        (
            flow: Refund,
            request_body: EasebuzzRefundRequest,
            response_body: EasebuzzRefundResponse,
            router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ),
        (
            flow: RSync,
            request_body: EasebuzzRefundSyncRequest,
            response_body: EasebuzzRefundSyncResponse,
            router_data: RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ),
        (
            flow: CreateOrder,
            request_body: EasebuzzCreateOrderRequest,
            response_body: EasebuzzCreateOrderResponse,
            router_data: RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>,
        ),
        (
            flow: CreateSessionToken,
            request_body: EasebuzzSessionTokenRequest,
            response_body: EasebuzzSessionTokenResponse,
            router_data: RouterDataV2<CreateSessionToken, PaymentFlowData, SessionTokenRequestData, SessionTokenResponseData>,
        ),
        (
            flow: SetupMandate,
            request_body: EasebuzzSetupMandateRequest,
            response_body: EasebuzzSetupMandateResponse,
            router_data: RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>,
        ),
        (
            flow: RepeatPayment,
            request_body: EasebuzzRepeatPaymentRequest,
            response_body: EasebuzzRepeatPaymentResponse,
            router_data: RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>,
        ),
        (
            flow: Accept,
            request_body: EasebuzzAcceptDisputeRequest,
            response_body: EasebuzzAcceptDisputeResponse,
            router_data: RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>,
        ),
        (
            flow: SubmitEvidence,
            request_body: EasebuzzSubmitEvidenceRequest,
            response_body: EasebuzzSubmitEvidenceResponse,
            router_data: RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>,
        ),
        (
            flow: DefendDispute,
            request_body: EasebuzzDefendDisputeRequest,
            response_body: EasebuzzDefendDisputeResponse,
            router_data: RouterDataV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>,
        ),
        (
            flow: PreAuthenticate,
            request_body: EasebuzzPreAuthenticateRequest,
            response_body: EasebuzzPreAuthenticateResponse,
            router_data: RouterDataV2<PreAuthenticate, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: Authenticate,
            request_body: EasebuzzAuthenticateRequest,
            response_body: EasebuzzAuthenticateResponse,
            router_data: RouterDataV2<Authenticate, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: PostAuthenticate,
            request_body: EasebuzzPostAuthenticateRequest,
            response_body: EasebuzzPostAuthenticateResponse,
            router_data: RouterDataV2<PostAuthenticate, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
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
                constants::EASEBUZZ_TEST_BASE_URL
            } else {
                constants::EASEBUZZ_PROD_BASE_URL
            }
        }

        pub fn connector_base_url_refunds<'a, F, Req, Res>(
            &self,
            _req: &'a RouterDataV2<F, RefundFlowData, Req, Res>,
        ) -> &'a str {
            constants::EASEBUZZ_TEST_BASE_URL // Default to test for now
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Easebuzz,
    curl_request: Json(EasebuzzPaymentsRequest),
    curl_response: EasebuzzPaymentsResponse,
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
            _req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            let header = vec![(
                headers::CONTENT_TYPE.to_string(),
                self.common_get_content_type().to_string().into(),
            )];

            // Add any additional headers if needed
            Ok(header)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            Ok(format!(
                "{}/{}",
                self.connector_base_url_payments(req),
                constants::EASEBUZZ_INITIATE_PAYMENT.trim_start_matches('/')
            ))
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Easebuzz,
    curl_request: Json(EasebuzzPaymentsSyncRequest),
    curl_response: EasebuzzPaymentsSyncResponse,
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
            _req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            let header = vec![(
                headers::CONTENT_TYPE.to_string(),
                self.common_get_content_type().to_string().into(),
            )];

            // Add any additional headers if needed
            Ok(header)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            Ok(format!(
                "{}/{}",
                self.connector_base_url_payments(req),
                constants::EASEBUZZ_TXN_SYNC.trim_start_matches('/')
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
    > ConnectorCommon for Easebuzz<T>
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
        constants::EASEBUZZ_TEST_BASE_URL // Default to test for now
    }

    fn get_auth_header(
        &self,
        _auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        // EaseBuzz uses custom auth in request body
        Ok(vec![])
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: easebuzz::EasebuzzErrorResponse = res
            .response
            .parse_struct("EasebuzzErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        with_error_response_body!(event_builder, response);

        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response.error_code.unwrap_or_else(|| "UNKNOWN".to_string()),
            message: response.message.clone(),
            reason: Some(response.message),
            attempt_status: None,
            connector_transaction_id: None,
            network_advice_code: None,
            network_decline_code: None,
            network_error_message: response.error_desc,
        })
    }
}

// Stub implementations for unsupported flows
macro_rules! impl_not_implemented_flow {
    ($flow:ty, $common_data:ty, $req:ty, $resp:ty) => {
        impl<
                T: PaymentMethodDataTypes
                    + std::fmt::Debug
                    + std::marker::Sync
                    + std::marker::Send
                    + 'static
                    + Serialize,
            > ConnectorIntegrationV2<$flow, $common_data, $req, $resp> for Easebuzz<T>
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
impl_not_implemented_flow!(SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData);
impl_not_implemented_flow!(RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData);
impl_not_implemented_flow!(Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData);
impl_not_implemented_flow!(SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData);
impl_not_implemented_flow!(DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData);
impl_not_implemented_flow!(PreAuthenticate, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData);
impl_not_implemented_flow!(Authenticate, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData);
impl_not_implemented_flow!(PostAuthenticate, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData);

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
            > SourceVerification<$flow, $common_data, $req, $resp> for Easebuzz<T>
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
    PreAuthenticate,
    PaymentFlowData,
    PaymentsAuthorizeData<T>,
    PaymentsResponseData
);
impl_source_verification_stub!(
    Authenticate,
    PaymentFlowData,
    PaymentsAuthorizeData<T>,
    PaymentsResponseData
);
impl_source_verification_stub!(
    PostAuthenticate,
    PaymentFlowData,
    PaymentsAuthorizeData<T>,
    PaymentsResponseData
);