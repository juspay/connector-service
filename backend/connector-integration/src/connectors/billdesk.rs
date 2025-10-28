pub mod transformers;
pub mod constants;

use std::fmt::Debug;

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
use transformers::{self as billdesk, BilldeskPaymentsRequest, BilldeskPaymentsResponse, BilldeskPaymentsSyncRequest, BilldeskPaymentsSyncResponse};

use super::macros;
use crate::{types::ResponseRouterData, with_error_response_body};

pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const CHECKSUM: &str = "CheckSum";
}

// MANDATORY: Use UCS v2 macro framework - NO manual trait implementations
macros::create_all_prerequisites!(
    connector_name: Billdesk,
    generic_type: T,
    api: [
        // Implemented flows for UPI and sync
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
        // Stub implementations for other flows (MANDATORY for compilation)
        (
            flow: Void,
            request_body: BilldeskVoidRequest,
            response_body: BilldeskVoidResponse,
            router_data: RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
        ),
        (
            flow: Capture,
            request_body: BilldeskCaptureRequest,
            response_body: BilldeskCaptureResponse,
            router_data: RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
        ),
        (
            flow: Refund,
            request_body: BilldeskRefundRequest,
            response_body: BilldeskRefundResponse,
            router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
        ),
        (
            flow: RSync,
            request_body: BilldeskRefundSyncRequest,
            response_body: BilldeskRefundSyncResponse,
            router_data: RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
        ),
        (
            flow: SetupMandate,
            request_body: BilldeskMandateRequest,
            response_body: BilldeskMandateResponse,
            router_data: RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>
        ),
        (
            flow: RepeatPayment,
            request_body: BilldeskRepeatPaymentRequest,
            response_body: BilldeskRepeatPaymentResponse,
            router_data: RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>
        ),
        (
            flow: CreateOrder,
            request_body: BilldeskCreateOrderRequest,
            response_body: BilldeskCreateOrderResponse,
            router_data: RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>
        ),
        (
            flow: CreateSessionToken,
            request_body: BilldeskSessionTokenRequest,
            response_body: BilldeskSessionTokenResponse,
            router_data: RouterDataV2<CreateSessionToken, PaymentFlowData, SessionTokenRequestData, SessionTokenResponseData>
        ),
        (
            flow: Accept,
            request_body: BilldeskAcceptDisputeRequest,
            response_body: BilldeskAcceptDisputeResponse,
            router_data: RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
        ),
        (
            flow: DefendDispute,
            request_body: BilldeskDefendDisputeRequest,
            response_body: BilldeskDefendDisputeResponse,
            router_data: RouterDataV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
        ),
        (
            flow: SubmitEvidence,
            request_body: BilldeskSubmitEvidenceRequest,
            response_body: BilldeskSubmitEvidenceResponse,
            router_data: RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
        ),
    ],
    amount_converters: [
        amount_converter: StringMinorUnit  // Billdesk expects amount in minor units as string
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
                constants::BILLDESK_UAT_BASE_URL
            } else {
                constants::BILLDESK_PROD_BASE_URL
            }
        }

        pub fn connector_base_url_refunds<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, RefundFlowData, Req, Res>,
        ) -> &'a str {
            if req.resource_common_data.test_mode.unwrap_or(false) {
                constants::BILLDESK_UAT_BASE_URL
            } else {
                constants::BILLDESK_PROD_BASE_URL
            }
        }
    }
);

// MANDATORY: Use macro for Authorize flow implementation
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

            let auth = billdesk::BilldeskAuth::try_from(&req.connector_auth_type)?;
            
            // Add checksum header for Billdesk authentication
            let checksum = billdesk::generate_checksum(req, &auth)?;
            header.push((headers::CHECKSUM.to_string(), checksum.into_masked()));

            Ok(header)
        }
        
        fn get_url(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            // Based on the Haskell implementation, use different endpoints for different request types
            match req.request.payment_method_type {
                Some(common_enums::PaymentMethodType::Upi) => {
                    Ok(format!("{}?reqid={}", self.connector_base_url_payments(req), constants::BILLDESK_UPI_REQUEST_ID))
                }
                Some(common_enums::PaymentMethodType::NetBanking) => {
                    Ok(format!("{}?reqid={}", self.connector_base_url_payments(req), constants::BILLDESK_NB_REQUEST_ID))
                }
                _ => Ok(format!("{}?reqid={}", self.connector_base_url_payments(req), constants::BILLDESK_AUTH_REQUEST_ID))
            }
        }
    }
);

// MANDATORY: Use macro for PSync flow implementation
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

            let auth = billdesk::BilldeskAuth::try_from(&req.connector_auth_type)?;
            
            // Add checksum header for Billdesk authentication
            let checksum_input = format!(
                "{}{}",
                req.resource_common_data.connector_request_reference_id,
                auth.checksum_key.expose()
            );
            
            use sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();
            hasher.update(checksum_input.as_bytes());
            let result = hasher.finalize();
            let checksum = hex::encode(result);
            
            header.push((headers::CHECKSUM.to_string(), checksum.into_masked()));

            Ok(header)
        }
        
        fn get_url(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            Ok(format!("{}?reqid={}", self.connector_base_url_payments(req), constants::BILLDESK_AUTH_REQUEST_ID))
        }
    }
);

// MANDATORY: Implement ConnectorCommon trait
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
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

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.billdesk.base_url.as_ref()
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
            message: response.error_description.clone(),
            reason: Some(response.error_description),
            attempt_status: None,
            connector_transaction_id: None,
            network_advice_code: None,
            network_decline_code: None,
            network_error_message: None,
        })
    }
}

// MANDATORY: Implement all connector_types traits (even for unused flows)
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ConnectorServiceTrait<T> for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAuthorizeV2<T> for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentSyncV2 for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentSessionToken for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAccessToken for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::CreateConnectorCustomer for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentVoidV2 for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundSyncV2 for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundV2 for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentCapture for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::SetupMandateV2<T> for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::AcceptDispute for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::SubmitEvidenceV2 for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::DisputeDefend for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::IncomingWebhook for Billdesk<T> {
    fn verify_webhook_source(
        &self,
        _request: RequestDetails,
        _connector_webhook_secrets: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorAuthType>,
    ) -> Result<bool, error_stack::Report<domain_types::errors::ConnectorError>> {
        // TODO: Implement webhook verification based on Billdesk's webhook signature
        Ok(true)
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
        // TODO: Implement webhook processing
        Err(errors::ConnectorError::WebhookNotImplemented)
    }
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentOrderCreate for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ValidationTrait for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RepeatPaymentV2 for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentTokenV2<T> for Billdesk<T> {}

// Authentication flow implementations
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentPreAuthenticateV2<T> for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAuthenticateV2<T> for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentPostAuthenticateV2<T> for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentVoidPostCaptureV2 for Billdesk<T> {}

// MANDATORY: Implement ConnectorIntegrationV2 for all flows (even stubs)
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
    for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
    for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
    for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
    for Billdesk<T> {}

// Additional flow implementations
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
    for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
    for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData<T>,
        PaymentsResponseData,
    > for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>
    for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        CreateSessionToken,
        PaymentFlowData,
        SessionTokenRequestData,
        SessionTokenResponseData,
    > for Billdesk<T> {}

// Authentication flow implementations
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        domain_types::connector_flow::PreAuthenticate,
        PaymentFlowData,
        domain_types::connector_types::PaymentsPreAuthenticateData<T>,
        PaymentsResponseData,
    > for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        domain_types::connector_flow::Authenticate,
        PaymentFlowData,
        domain_types::connector_types::PaymentsAuthenticateData<T>,
        PaymentsResponseData,
    > for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        domain_types::connector_flow::PostAuthenticate,
        PaymentFlowData,
        domain_types::connector_types::PaymentsPostAuthenticateData<T>,
        PaymentsResponseData,
    > for Billdesk<T> {}

// MANDATORY: SourceVerification implementations for all flows
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
impl_source_verification_stub!(
    Capture,
    PaymentFlowData,
    PaymentsCaptureData,
    PaymentsResponseData
);
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
impl_source_verification_stub!(
    Accept,
    DisputeFlowData,
    AcceptDisputeData,
    DisputeResponseData
);
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
    domain_types::connector_flow::PreAuthenticate,
    PaymentFlowData,
    domain_types::connector_types::PaymentsPreAuthenticateData<T>,
    PaymentsResponseData
);
impl_source_verification_stub!(
    domain_types::connector_flow::Authenticate,
    PaymentFlowData,
    domain_types::connector_types::PaymentsAuthenticateData<T>,
    PaymentsResponseData
);
impl_source_verification_stub!(
    domain_types::connector_flow::PostAuthenticate,
    PaymentFlowData,
    domain_types::connector_types::PaymentsPostAuthenticateData<T>,
    PaymentsResponseData
);
impl_source_verification_stub!(
    CreateSessionToken,
    PaymentFlowData,
    SessionTokenRequestData,
    SessionTokenResponseData
);