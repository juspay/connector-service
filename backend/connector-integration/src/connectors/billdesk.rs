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
        Accept, Authorize, Capture, CreateOrder, CreateSessionToken, DefendDispute, PSync, PostAuthenticate, RSync,
        Refund, RepeatPayment, SetupMandate, SubmitEvidence, Void,
    },
    connector_types::{
        PaymentFlowData, PaymentsAuthorizeData, PaymentsPostAuthenticateData, PaymentsResponseData, PaymentsSyncData,
    },
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
};
use error_stack::ResultExt;
use hyperswitch_masking::{Mask, Maskable, ExposeInterface};
use interfaces::{
    api::ConnectorCommon,
    connector_integration_v2::ConnectorIntegrationV2,
    connector_types,
    events::connector_api_logs::ConnectorEvent,
    verification::{ConnectorSourceVerificationSecrets, SourceVerification},
};
use serde::Serialize;
use transformers::{self as billdesk, BilldeskPaymentsRequest, BilldeskPaymentsResponse, BilldeskPaymentsSyncRequest, BilldeskPaymentsSyncResponse,
    BilldeskVoidRequest, BilldeskVoidResponse, BilldeskCaptureRequest, BilldeskCaptureResponse,
    BilldeskRefundRequest, BilldeskRefundResponse, BilldeskRefundSyncRequest, BilldeskRefundSyncResponse,
    BilldeskCreateOrderRequest, BilldeskCreateOrderResponse, BilldeskSessionTokenRequest, BilldeskSessionTokenResponse,
    BilldeskMandateRequest, BilldeskMandateResponse, BilldeskRepeatPaymentRequest, BilldeskRepeatPaymentResponse,
    BilldeskAcceptDisputeRequest, BilldeskAcceptDisputeResponse, BilldeskDefendDisputeRequest, BilldeskDefendDisputeResponse,
    BilldeskSubmitEvidenceRequest, BilldeskSubmitEvidenceResponse
};

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
        // MANDATORY: Add all other flows even if not implemented
        (
            flow: Void,
            request_body: BilldeskVoidRequest,
            response_body: BilldeskVoidResponse,
            router_data: RouterDataV2<Void, PaymentFlowData, domain_types::connector_types::PaymentVoidData, PaymentsResponseData>,
        ),
        (
            flow: Capture,
            request_body: BilldeskCaptureRequest,
            response_body: BilldeskCaptureResponse,
            router_data: RouterDataV2<Capture, PaymentFlowData, domain_types::connector_types::PaymentsCaptureData, PaymentsResponseData>,
        ),
        (
            flow: Refund,
            request_body: BilldeskRefundRequest,
            response_body: BilldeskRefundResponse,
            router_data: RouterDataV2<Refund, domain_types::connector_types::RefundFlowData, domain_types::connector_types::RefundsData, domain_types::connector_types::RefundsResponseData>,
        ),
        (
            flow: RSync,
            request_body: BilldeskRefundSyncRequest,
            response_body: BilldeskRefundSyncResponse,
            router_data: RouterDataV2<RSync, domain_types::connector_types::RefundFlowData, domain_types::connector_types::RefundSyncData, domain_types::connector_types::RefundsResponseData>,
        ),
        (
            flow: CreateOrder,
            request_body: BilldeskCreateOrderRequest,
            response_body: BilldeskCreateOrderResponse,
            router_data: RouterDataV2<CreateOrder, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::PaymentCreateOrderData, domain_types::connector_types::PaymentCreateOrderResponse>,
        ),
        (
            flow: CreateSessionToken,
            request_body: BilldeskSessionTokenRequest,
            response_body: BilldeskSessionTokenResponse,
            router_data: RouterDataV2<CreateSessionToken, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::SessionTokenRequestData, domain_types::connector_types::SessionTokenResponseData>,
        ),
        (
            flow: SetupMandate,
            request_body: BilldeskMandateRequest,
            response_body: BilldeskMandateResponse,
            router_data: RouterDataV2<SetupMandate, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::SetupMandateRequestData<T>, PaymentsResponseData>,
        ),
        (
            flow: RepeatPayment,
            request_body: BilldeskRepeatPaymentRequest,
            response_body: BilldeskRepeatPaymentResponse,
            router_data: RouterDataV2<RepeatPayment, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::RepeatPaymentData, PaymentsResponseData>,
        ),
        (
            flow: Accept,
            request_body: BilldeskAcceptDisputeRequest,
            response_body: BilldeskAcceptDisputeResponse,
            router_data: RouterDataV2<Accept, domain_types::connector_types::DisputeFlowData, domain_types::connector_types::AcceptDisputeData, domain_types::connector_types::DisputeResponseData>,
        ),
        (
            flow: DefendDispute,
            request_body: BilldeskDefendDisputeRequest,
            response_body: BilldeskDefendDisputeResponse,
            router_data: RouterDataV2<DefendDispute, domain_types::connector_types::DisputeFlowData, domain_types::connector_types::DisputeDefendData, domain_types::connector_types::DisputeResponseData>,
        ),
        (
            flow: SubmitEvidence,
            request_body: BilldeskSubmitEvidenceRequest,
            response_body: BilldeskSubmitEvidenceResponse,
            router_data: RouterDataV2<SubmitEvidence, domain_types::connector_types::DisputeFlowData, domain_types::connector_types::SubmitEvidenceData, domain_types::connector_types::DisputeResponseData>,
        ),
        (
            flow: PostAuthenticate,
            request_body: BilldeskPaymentsRequest,
            response_body: BilldeskPaymentsResponse,
            router_data: RouterDataV2<PostAuthenticate, PaymentFlowData, domain_types::connector_types::PaymentsPostAuthenticateData<T>, PaymentsResponseData>,
        )
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
            let checksum = billdesk::generate_checksum(req, &auth, self.amount_converter)?;
            header.push((headers::CHECKSUM.to_string(), checksum.into_masked()));

            Ok(header)
        }
        
        fn get_url(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            // Based on the Haskell implementation, use different endpoints for different request types
            match req.request.payment_method_type {
                Some(common_enums::PaymentMethodType::UpiCollect) => {
                    Ok(format!("{}?reqid={}", self.connector_base_url_payments(req), constants::BILLDESK_UPI_REQUEST_ID))
                }
                Some(common_enums::PaymentMethodType::UpiIntent) => {
                    Ok(format!("{}?reqid={}", self.connector_base_url_payments(req), constants::BILLDESK_UPI_REQUEST_ID))
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

    fn base_url<'a>(&self, _connectors: &'a Connectors) -> &'a str {
        // Return production URL by default, individual methods will handle test mode
        constants::BILLDESK_PROD_BASE_URL
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
            code: response.error.clone(),
            message: response.error_description.clone().unwrap_or_else(|| "Unknown error".to_string()),
            reason: response.error_description.clone(),
            attempt_status: None,
            connector_transaction_id: None,
            network_advice_code: None,
            network_decline_code: None,
            network_error_message: None,
        })
    }
}

// MANDATORY: Implement all connector_types traits (including stubs for unsupported flows)
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ConnectorServiceTrait<T> for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAuthorizeV2<T> for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentSyncV2 for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentCapture for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentVoidV2 for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentVoidPostCaptureV2 for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundV2 for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundSyncV2 for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentOrderCreate for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentSessionToken for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAccessToken for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentTokenV2<T> for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::SetupMandateV2<T> for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RepeatPaymentV2 for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::AcceptDispute for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::DisputeDefend for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::SubmitEvidenceV2 for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::IncomingWebhook for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::CreateConnectorCustomer for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentPreAuthenticateV2<T> for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAuthenticateV2<T> for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentPostAuthenticateV2<T> for Billdesk<T> {}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ValidationTrait for Billdesk<T> {}

// MANDATORY: SourceVerification implementations for supported flows only
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

// Apply to supported flows only
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

// MANDATORY: Add source verification stubs for all flows
impl_source_verification_stub!(
    Void,
    PaymentFlowData,
    domain_types::connector_types::PaymentVoidData,
    PaymentsResponseData
);
impl_source_verification_stub!(
    Capture,
    PaymentFlowData,
    domain_types::connector_types::PaymentsCaptureData,
    PaymentsResponseData
);
impl_source_verification_stub!(
    Refund,
    domain_types::connector_types::RefundFlowData,
    domain_types::connector_types::RefundsData,
    domain_types::connector_types::RefundsResponseData
);
impl_source_verification_stub!(
    RSync,
    domain_types::connector_types::RefundFlowData,
    domain_types::connector_types::RefundSyncData,
    domain_types::connector_types::RefundsResponseData
);
impl_source_verification_stub!(
    CreateOrder,
    domain_types::connector_types::PaymentFlowData,
    domain_types::connector_types::PaymentCreateOrderData,
    domain_types::connector_types::PaymentCreateOrderResponse
);
impl_source_verification_stub!(
    CreateSessionToken,
    domain_types::connector_types::PaymentFlowData,
    domain_types::connector_types::SessionTokenRequestData,
    domain_types::connector_types::SessionTokenResponseData
);
impl_source_verification_stub!(
    SetupMandate,
    domain_types::connector_types::PaymentFlowData,
    domain_types::connector_types::SetupMandateRequestData<T>,
    PaymentsResponseData
);
impl_source_verification_stub!(
    RepeatPayment,
    domain_types::connector_types::PaymentFlowData,
    domain_types::connector_types::RepeatPaymentData,
    PaymentsResponseData
);
impl_source_verification_stub!(
    Accept,
    domain_types::connector_types::DisputeFlowData,
    domain_types::connector_types::AcceptDisputeData,
    domain_types::connector_types::DisputeResponseData
);
impl_source_verification_stub!(
    DefendDispute,
    domain_types::connector_types::DisputeFlowData,
    domain_types::connector_types::DisputeDefendData,
    domain_types::connector_types::DisputeResponseData
);
impl_source_verification_stub!(
    SubmitEvidence,
    domain_types::connector_types::DisputeFlowData,
    domain_types::connector_types::SubmitEvidenceData,
    domain_types::connector_types::DisputeResponseData
);

// MANDATORY: Add not-implemented flow handlers for all unsupported flows
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

// Use macro for all unimplemented flows
impl_not_implemented_flow!(Void, PaymentFlowData, domain_types::connector_types::PaymentVoidData, PaymentsResponseData);
impl_not_implemented_flow!(Capture, PaymentFlowData, domain_types::connector_types::PaymentsCaptureData, PaymentsResponseData);
impl_not_implemented_flow!(Refund, domain_types::connector_types::RefundFlowData, domain_types::connector_types::RefundsData, domain_types::connector_types::RefundsResponseData);
impl_not_implemented_flow!(RSync, domain_types::connector_types::RefundFlowData, domain_types::connector_types::RefundSyncData, domain_types::connector_types::RefundsResponseData);
impl_not_implemented_flow!(CreateOrder, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::PaymentCreateOrderData, domain_types::connector_types::PaymentCreateOrderResponse);
impl_not_implemented_flow!(CreateSessionToken, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::SessionTokenRequestData, domain_types::connector_types::SessionTokenResponseData);
impl_not_implemented_flow!(SetupMandate, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::SetupMandateRequestData<T>, PaymentsResponseData);
impl_not_implemented_flow!(RepeatPayment, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::RepeatPaymentData, PaymentsResponseData);
impl_not_implemented_flow!(Accept, domain_types::connector_types::DisputeFlowData, domain_types::connector_types::AcceptDisputeData, domain_types::connector_types::DisputeResponseData);
impl_not_implemented_flow!(DefendDispute, domain_types::connector_types::DisputeFlowData, domain_types::connector_types::DisputeDefendData, domain_types::connector_types::DisputeResponseData);
impl_not_implemented_flow!(SubmitEvidence, domain_types::connector_types::DisputeFlowData, domain_types::connector_types::SubmitEvidenceData, domain_types::connector_types::DisputeResponseData);