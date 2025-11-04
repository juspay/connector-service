pub mod transformers;

use common_enums::CurrencyUnit;
use common_utils::{
    errors::CustomResult,
    ext_traits::ByteSliceExt,
    types::StringMinorUnit,
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
        PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsResponseData,
        RepeatPaymentData, RequestDetails, SessionTokenRequestData,
        SessionTokenResponseData, SetupMandateRequestData, SubmitEvidenceData,
    },
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
};
use error_stack::ResultExt;
use hyperswitch_masking::{Mask, Maskable, PeekInterface};
use interfaces::{
    api::ConnectorCommon,
    connector_integration_v2::ConnectorIntegrationV2,
    connector_types,
    events::connector_api_logs::ConnectorEvent,
    verification::{ConnectorSourceVerificationSecrets, SourceVerification},
};
use serde::Serialize;
use transformers::{
    self as billdesk, BilldeskPaymentsRequest, BilldeskPaymentsResponse,
    BilldeskPaymentsSyncRequest, BilldeskPaymentsSyncResponse,
};

use super::macros;
use crate::{types::ResponseRouterData, with_error_response_body};

pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const AUTHORIZATION: &str = "Authorization";
}

// Stub types for flows that aren't implemented yet
#[derive(Default, Debug, Serialize)]
pub struct BilldeskVoidRequest;
#[derive(Default, Debug, Serialize)]
pub struct BilldeskCaptureRequest;
#[derive(Default, Debug, Serialize)]
pub struct BilldeskRefundRequest;
#[derive(Default, Debug, Serialize)]
pub struct BilldeskRSyncRequest;
#[derive(Default, Debug, Serialize)]
pub struct BilldeskCreateOrderRequest;
#[derive(Default, Debug, Serialize)]
pub struct BilldeskSessionTokenRequest;
#[derive(Default, Debug, Serialize)]
pub struct BilldeskSetupMandateRequest;
#[derive(Default, Debug, Serialize)]
pub struct BilldeskRepeatPaymentRequest;
#[derive(Default, Debug, Serialize)]
pub struct BilldeskAcceptDisputeRequest;
#[derive(Default, Debug, Serialize)]
pub struct BilldeskDefendDisputeRequest;
#[derive(Default, Debug, Serialize)]
pub struct BilldeskSubmitEvidenceRequest;

#[derive(Default, Debug, Clone)]
pub struct BilldeskVoidResponse;
#[derive(Default, Debug, Clone)]
pub struct BilldeskCaptureResponse;
#[derive(Default, Debug, Clone)]
pub struct BilldeskRefundResponse;
#[derive(Default, Debug, Clone)]
pub struct BilldeskRSyncResponse;
#[derive(Default, Debug, Clone)]
pub struct BilldeskCreateOrderResponse;
#[derive(Default, Debug, Clone)]
pub struct BilldeskSessionTokenResponse;
#[derive(Default, Debug, Clone)]
pub struct BilldeskSetupMandateResponse;
#[derive(Default, Debug, Clone)]
pub struct BilldeskRepeatPaymentResponse;
#[derive(Default, Debug, Clone)]
pub struct BilldeskAcceptDisputeResponse;
#[derive(Default, Debug, Clone)]
pub struct BilldeskDefendDisputeResponse;
#[derive(Default, Debug, Clone)]
pub struct BilldeskSubmitEvidenceResponse;

macros::create_all_prerequisites!(
    connector_name: Billdesk,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: BilldeskPaymentsRequest,
            response_body: BilldeskPaymentsResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: PSync,
            request_body: BilldeskPaymentsSyncRequest,
            response_body: BilldeskPaymentsSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ),
        // Add all other flows with stub types
        (
            flow: Void,
            request_body: BilldeskVoidRequest,
            response_body: BilldeskVoidResponse,
            router_data: RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ),
        (
            flow: Capture,
            request_body: BilldeskCaptureRequest,
            response_body: BilldeskCaptureResponse,
            router_data: RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ),
        (
            flow: Refund,
            request_body: BilldeskRefundRequest,
            response_body: BilldeskRefundResponse,
            router_data: RouterDataV2<Refund, PaymentFlowData, RefundFlowData, RefundsResponseData>,
        ),
        (
            flow: RSync,
            request_body: BilldeskRSyncRequest,
            response_body: BilldeskRSyncResponse,
            router_data: RouterDataV2<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>,
        ),
        (
            flow: CreateOrder,
            request_body: BilldeskCreateOrderRequest,
            response_body: BilldeskCreateOrderResponse,
            router_data: RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>,
        ),
        (
            flow: CreateSessionToken,
            request_body: BilldeskSessionTokenRequest,
            response_body: BilldeskSessionTokenResponse,
            router_data: RouterDataV2<CreateSessionToken, PaymentFlowData, SessionTokenRequestData, SessionTokenResponseData>,
        ),
        (
            flow: SetupMandate,
            request_body: BilldeskSetupMandateRequest,
            response_body: BilldeskSetupMandateResponse,
            router_data: RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>,
        ),
        (
            flow: RepeatPayment,
            request_body: BilldeskRepeatPaymentRequest,
            response_body: BilldeskRepeatPaymentResponse,
            router_data: RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>,
        ),
        (
            flow: Accept,
            request_body: BilldeskAcceptDisputeRequest,
            response_body: BilldeskAcceptDisputeResponse,
            router_data: RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>,
        ),
        (
            flow: DefendDispute,
            request_body: BilldeskDefendDisputeRequest,
            response_body: BilldeskDefendDisputeResponse,
            router_data: RouterDataV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>,
        ),
        (
            flow: SubmitEvidence,
            request_body: BilldeskSubmitEvidenceRequest,
            response_body: BilldeskSubmitEvidenceResponse,
            router_data: RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>,
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
                "https://uat.billdesk.com/pgidsk/PGIDirectRequest"
            } else {
                "https://www.billdesk.com/pgidsk/PGIDirectRequest"
            }
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Billdesk,
    curl_request: Json(BilldeskPaymentsRequest),
    curl_response: BilldeskPaymentsResponse,
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

            let auth_header = get_billdesk_auth_header(&req.connector_auth_type)?;
            header.push((headers::AUTHORIZATION.to_string(), auth_header));

            Ok(header)
        }
        
        fn get_url(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            let base_url = self.connector_base_url_payments(req);
            let payment_method_type = req.request.payment_method_type
                .ok_or(errors::ConnectorError::MissingPaymentMethodType)?;
            
            match payment_method_type {
                common_enums::PaymentMethodType::UpiCollect => {
                    Ok(format!("{}?reqid=BDRDF011", base_url))
                }
                _ => Err(errors::ConnectorError::NotImplemented("Payment method".to_string()).into()),
            }
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Billdesk,
    curl_request: Json(BilldeskPaymentsSyncRequest),
    curl_response: BilldeskPaymentsSyncResponse,
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

            let auth_header = get_billdesk_auth_header(&req.connector_auth_type)?;
            header.push((headers::AUTHORIZATION.to_string(), auth_header));

            Ok(header)
        }
        
        fn get_url(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            let base_url = self.connector_base_url_payments(req);
            Ok(format!("{}?reqid=BDRDF003", base_url))
        }
    }
);

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::ConnectorServiceTrait<T> for Billdesk<T> {}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    ConnectorCommon for Billdesk<T>
{
    fn id(&self) -> &'static str {
        "billdesk"
    }

    fn get_currency_unit(&self) -> CurrencyUnit {
        CurrencyUnit::Base
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn base_url<'a>(&self, _connectors: &'a Connectors) -> &'a str {
        "https://www.billdesk.com/pgidsk/PGIDirectRequest"
    }

    fn get_auth_header(
        &self,
        _auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        // Billdesk uses custom auth in get_headers
        Ok(vec![])
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: billdesk::BilldeskErrorResponse = res
            .response
            .parse_struct("BilldeskErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        with_error_response_body!(event_builder, response);

        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response.error.to_string(),
            message: response.error_description.clone().unwrap_or_default(),
            reason: response.error_description.clone(),
            attempt_status: None,
            connector_transaction_id: None,
            network_advice_code: None,
            network_decline_code: None,
            network_error_message: None,
        })
    }
}

// Implement all connector_types traits for Billdesk
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::PaymentOrderCreate for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::PaymentSessionToken for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::PaymentVoidV2 for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::PaymentCapture for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::RefundV2 for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::RefundSyncV2 for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::SetupMandateV2<T> for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::RepeatPaymentV2 for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::AcceptDispute for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::DisputeDefend for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::SubmitEvidenceV2 for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::ValidationTrait for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::IncomingWebhook for Billdesk<T>
{
    fn verify_webhook_source(
        &self,
        _request: RequestDetails,
        _connector_webhook_secrets: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorAuthType>,
    ) -> Result<bool, error_stack::Report<domain_types::errors::ConnectorError>> {
        // Billdesk webhook verification will be implemented based on their signature mechanism
        Ok(true) // STUB - will be implemented with proper verification
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
        let webhook: transformers::BilldeskPaymentsSyncResponse = request
            .body
            .parse_struct("BilldeskPaymentsSyncResponse")
            .change_context(errors::ConnectorError::WebhookResourceObjectNotFound)?;

        Ok(domain_types::connector_types::WebhookDetailsResponse {
            resource_id: Some(
                domain_types::connector_types::ResponseId::ConnectorTransactionId(
                    webhook._txn_reference_no.clone(),
                ),
            ),
            status: common_enums::AttemptStatus::Charged,
            status_code: 200,
            mandate_reference: None,
            connector_response_reference_id: None,
            error_code: None,
            error_message: None,
            raw_connector_response: Some(String::from_utf8_lossy(&request.body).to_string()),
            response_headers: None,
            minor_amount_captured: None,
            amount_captured: None,
            error_reason: None,
            network_txn_id: None,
            transformation_status: common_enums::WebhookTransformationStatus::Complete,
        })
    }
}

// Macro for not implemented flows
macro_rules! impl_not_implemented_flow {
    ($flow:ty, $common_data:ty, $req:ty, $resp:ty) => {
        impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
            ConnectorIntegrationV2<$flow, $common_data, $req, $resp> for Billdesk<T>
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

// Apply to unimplemented flows
impl_not_implemented_flow!(Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData);
impl_not_implemented_flow!(Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData);
impl_not_implemented_flow!(Refund, PaymentFlowData, RefundFlowData, RefundsResponseData);
impl_not_implemented_flow!(RSync, PaymentFlowData, RefundSyncData, RefundsResponseData);
impl_not_implemented_flow!(CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse);
impl_not_implemented_flow!(CreateSessionToken, PaymentFlowData, SessionTokenRequestData, SessionTokenResponseData);
impl_not_implemented_flow!(SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData);
impl_not_implemented_flow!(RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData);
impl_not_implemented_flow!(Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData);
impl_not_implemented_flow!(DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData);
impl_not_implemented_flow!(SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData);

// SourceVerification implementations for flows
macro_rules! impl_source_verification_stub {
    ($flow:ty, $common_data:ty, $req:ty, $resp:ty) => {
        impl<
                T: PaymentMethodDataTypes
                    + std::fmt::Debug
                    + std::marker::Sync
                    + std::marker::Send
                    + 'static
                    + Serialize,
            > SourceVerification<$flow, $common_data, $req, $resp> for Billdesk<T>
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
impl_source_verification_stub!(Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData);
impl_source_verification_stub!(Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData);
impl_source_verification_stub!(Refund, PaymentFlowData, RefundFlowData, RefundsResponseData);
impl_source_verification_stub!(RSync, PaymentFlowData, RefundSyncData, RefundsResponseData);
impl_source_verification_stub!(CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse);
impl_source_verification_stub!(CreateSessionToken, PaymentFlowData, SessionTokenRequestData, SessionTokenResponseData);
impl_source_verification_stub!(SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData);
impl_source_verification_stub!(RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData);
impl_source_verification_stub!(Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData);
impl_source_verification_stub!(DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData);
impl_source_verification_stub!(SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData);

fn get_billdesk_auth_header(
    connector_auth_type: &ConnectorAuthType,
) -> CustomResult<Maskable<String>, errors::ConnectorError> {
    match connector_auth_type {
        ConnectorAuthType::SignatureKey { api_key, .. } => {
            let auth = format!("Bearer {}", api_key.peek());
            Ok(auth.into_masked())
        }
        _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
    }
}