pub mod transformers;
pub mod constants;

use std::fmt::Debug;

use base64::Engine;
use common_enums::{enums, CurrencyUnit};
use common_utils::{errors::CustomResult, ext_traits::ByteSliceExt, types::StringMajorUnit};
use domain_types::{
    connector_flow::{
        Accept, Authenticate, Authorize, Capture, CreateAccessToken, CreateConnectorCustomer,
        CreateOrder, CreateSessionToken, DefendDispute, PSync, PaymentMethodToken,
        PostAuthenticate, PreAuthenticate, RSync, Refund, RepeatPayment, SetupMandate,
        SubmitEvidence, Void, VoidPC,
    },
    connector_types::{
        AcceptDisputeData, AccessTokenRequestData, AccessTokenResponseData, ConnectorCustomerData,
        ConnectorCustomerResponse, DisputeDefendData, DisputeFlowData,
        DisputeResponseData, PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData,
        PaymentMethodTokenResponse, PaymentMethodTokenizationData, PaymentVoidData,
        PaymentsAuthenticateData, PaymentsAuthorizeData, PaymentsCancelPostCaptureData,
        PaymentsCaptureData, PaymentsPostAuthenticateData, PaymentsPreAuthenticateData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData,
        RefundsResponseData, RepeatPaymentData, SessionTokenRequestData,
        SessionTokenResponseData, SetupMandateRequestData, SubmitEvidenceData,
    },
    errors::{self, ConnectorError},
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
};
use error_stack::ResultExt;
use hyperswitch_masking::Maskable;
use interfaces::{
    api::ConnectorCommon, connector_integration_v2::ConnectorIntegrationV2, connector_types,
    events::connector_api_logs::ConnectorEvent,
};
use serde::Serialize;

pub const BASE64_ENGINE: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

use transformers::{
    is_upi_collect_flow, PayuAuthType, PayuPaymentRequest, PayuPaymentResponse, PayuSyncRequest,
    PayuSyncResponse,
};

use super::macros;
use crate::types::ResponseRouterData;

// MANDATORY: Use UCS v2 macro framework - NO manual trait implementations allowed
macros::create_all_prerequisites!(
    connector_name: Payu,
    generic_type: T,
    api: [
        // UPI and Sync flows only as per requirements
        (
            flow: Authorize,
            request_body: PayuPaymentRequest,
            response_body: PayuPaymentResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: PSync,
            request_body: PayuSyncRequest,
            response_body: PayuSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ),
        // MANDATORY: Include all other flows even if not implemented (stub types)
        (
            flow: Void,
            request_body: PayuVoidRequest,
            response_body: PayuVoidResponse,
            router_data: RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ),
        (
            flow: Capture,
            request_body: PayuCaptureRequest,
            response_body: PayuCaptureResponse,
            router_data: RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ),
        (
            flow: Refund,
            request_body: PayuRefundRequest,
            response_body: PayuRefundResponse,
            router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ),
        (
            flow: RSync,
            request_body: PayuRSyncRequest,
            response_body: PayuRSyncResponse,
            router_data: RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ),
        (
            flow: CreateOrder,
            request_body: PayuCreateOrderRequest,
            response_body: PayuCreateOrderResponse,
            router_data: RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>,
        ),
        (
            flow: CreateSessionToken,
            request_body: PayuSessionTokenRequest,
            response_body: PayuSessionTokenResponse,
            router_data: RouterDataV2<CreateSessionToken, PaymentFlowData, SessionTokenRequestData, SessionTokenResponseData>,
        ),
        (
            flow: SetupMandate,
            request_body: PayuSetupMandateRequest,
            response_body: PayuSetupMandateResponse,
            router_data: RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>,
        ),
        (
            flow: RepeatPayment,
            request_body: PayuRepeatPaymentRequest,
            response_body: PayuRepeatPaymentResponse,
            router_data: RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>,
        ),
        (
            flow: Accept,
            request_body: PayuAcceptDisputeRequest,
            response_body: PayuAcceptDisputeResponse,
            router_data: RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>,
        ),
        (
            flow: SubmitEvidence,
            request_body: PayuSubmitEvidenceRequest,
            response_body: PayuSubmitEvidenceResponse,
            router_data: RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>,
        ),
        (
            flow: DefendDispute,
            request_body: PayuDefendDisputeRequest,
            response_body: PayuDefendDisputeResponse,
            router_data: RouterDataV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>,
        ),
        (
            flow: PaymentMethodToken,
            request_body: PayuPaymentMethodTokenRequest,
            response_body: PayuPaymentMethodTokenResponse,
            router_data: RouterDataV2<PaymentMethodToken, PaymentFlowData, PaymentMethodTokenizationData<T>, PaymentMethodTokenResponse>,
        ),
        (
            flow: CreateAccessToken,
            request_body: PayuCreateAccessTokenRequest,
            response_body: PayuCreateAccessTokenResponse,
            router_data: RouterDataV2<CreateAccessToken, PaymentFlowData, AccessTokenRequestData, AccessTokenResponseData>,
        ),
        (
            flow: CreateConnectorCustomer,
            request_body: PayuCreateConnectorCustomerRequest,
            response_body: PayuCreateConnectorCustomerResponse,
            router_data: RouterDataV2<CreateConnectorCustomer, PaymentFlowData, ConnectorCustomerData, ConnectorCustomerResponse>,
        ),
        (
            flow: PreAuthenticate,
            request_body: PayuPreAuthenticateRequest,
            response_body: PayuPreAuthenticateResponse,
            router_data: RouterDataV2<PreAuthenticate, PaymentFlowData, PaymentsPreAuthenticateData<T>, PaymentsResponseData>,
        ),
        (
            flow: Authenticate,
            request_body: PayuAuthenticateRequest,
            response_body: PayuAuthenticateResponse,
            router_data: RouterDataV2<Authenticate, PaymentFlowData, PaymentsAuthenticateData<T>, PaymentsResponseData>,
        ),
        (
            flow: PostAuthenticate,
            request_body: PayuPostAuthenticateRequest,
            response_body: PayuPostAuthenticateResponse,
            router_data: RouterDataV2<PostAuthenticate, PaymentFlowData, PaymentsPostAuthenticateData<T>, PaymentsResponseData>,
        ),
        (
            flow: VoidPC,
            request_body: PayuVoidPCRequest,
            response_body: PayuVoidPCResponse,
            router_data: RouterDataV2<VoidPC, PaymentFlowData, PaymentsCancelPostCaptureData, PaymentsResponseData>,
        )
    ],
    amount_converters: [
        amount_converter: StringMajorUnit  // PayU expects amounts in major units as string
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
                ("Content-Type".to_string(), "application/x-www-form-urlencoded".into()),
                ("Accept".to_string(), "application/json".into()),
            ])
        }

        pub fn connector_base_url_payments<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.payu.base_url
        }

        pub fn connector_base_url_refunds<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, RefundFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.payu.base_url
        }

        pub fn preprocess_response_bytes<F, FCD, Res>(
            &self,
            req: &RouterDataV2<F, FCD, PaymentsAuthorizeData<T>, Res>,
            bytes: bytes::Bytes,
        ) -> CustomResult<bytes::Bytes, ConnectorError> {
            if is_upi_collect_flow(&req.request) {
                // For UPI collect flows, we need to return base64 decoded response
                let decoded_value = BASE64_ENGINE.decode(bytes.clone());
                match decoded_value {
                    Ok(decoded_bytes) => Ok(decoded_bytes.into()),
                    Err(_) => Ok(bytes.clone())
                }
            } else {
                // For other flows, we can use the response itself
                Ok(bytes)
            }
        }
    }
);

// Implement PSync flow using macro framework
macros::macro_connector_implementation!(
    connector_default_implementations: [],
    connector: Payu,
    curl_request: FormUrlEncoded(PayuSyncRequest),
    curl_response: PayuSyncResponse,
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
        ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
            Ok(vec![
                ("Content-Type".to_string(), "application/x-www-form-urlencoded".into()),
                ("Accept".to_string(), "application/json".into()),
            ])
        }

        fn get_url(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<String, ConnectorError> {
            // Based on Haskell implementation: uses /merchant/postservice.php?form=2 for verification
            // Test: https://test.payu.in/merchant/postservice.php?form=2
            let base_url = self.base_url(&req.resource_common_data.connectors);
            Ok(format!("{base_url}/merchant/postservice.php?form=2"))
        }

        fn get_content_type(&self) -> &'static str {
            "application/x-www-form-urlencoded"
        }

        fn get_error_response_v2(
            &self,
            res: Response,
            _event_builder: Option<&mut ConnectorEvent>,
        ) -> CustomResult<ErrorResponse, ConnectorError> {
            // PayU sync may return error responses in different formats
            let response: PayuSyncResponse = res
                .response
                .parse_struct("PayU Sync ErrorResponse")
                .change_context(ConnectorError::ResponseDeserializationFailed)?;

            // Check if PayU returned error status (0 = error)
            if response.status == Some(0) {
                Ok(ErrorResponse {
                    status_code: res.status_code,
                    code: "PAYU_SYNC_ERROR".to_string(),
                    message: response.msg.unwrap_or_default(),
                    reason: None,
                    attempt_status: Some(enums::AttemptStatus::Failure),
                    connector_transaction_id: None,
                    network_error_message: None,
                    network_advice_code: None,
                    network_decline_code: None,
                })
            } else {
                // Generic error response
                Ok(ErrorResponse {
                    status_code: res.status_code,
                    code: "SYNC_UNKNOWN_ERROR".to_string(),
                    message: "Unknown PayU sync error".to_string(),
                    reason: None,
                    attempt_status: Some(enums::AttemptStatus::Failure),
                    connector_transaction_id: None,
                    network_error_message: None,
                    network_advice_code: None,
                    network_decline_code: None,
                })
            }
        }
    }
);

// Implement authorize flow using macro framework
macros::macro_connector_implementation!(
    connector_default_implementations: [],
    connector: Payu,
    curl_request: FormUrlEncoded(PayuPaymentRequest),
    curl_response: PayuPaymentResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    preprocess_response: true,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
            self.build_headers(req)
        }

        fn get_url(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<String, ConnectorError> {
            // Based on Haskell Endpoints.hs: uses /_payment endpoint for UPI transactions
            // Test: https://test.payu.in/_payment
            // Prod: https://secure.payu.in/_payment
            let base_url = self.base_url(&req.resource_common_data.connectors);
            Ok(format!("{base_url}/_payment"))
        }
        fn get_content_type(&self) -> &'static str {
            "application/x-www-form-urlencoded"
        }
        fn get_error_response_v2(
            &self,
            res: Response,
            _event_builder: Option<&mut ConnectorEvent>,
        ) -> CustomResult<ErrorResponse, ConnectorError> {
            // PayU returns error responses in the same JSON format as success responses
            // We need to parse the response and check for error fields
            let response: PayuPaymentResponse = res
                .response
                .parse_struct("PayU ErrorResponse")
                        .change_context(ConnectorError::ResponseDeserializationFailed)?;

            // Check if this is an error response
            if response.error.is_some() {
                Ok(ErrorResponse {
                    status_code: res.status_code,
                    code: response.error.unwrap_or_default(),
                    message: response.message.unwrap_or_default(),
                    reason: None,
                    attempt_status: Some(enums::AttemptStatus::Failure),
                    connector_transaction_id: response.reference_id,
                    network_error_message: None,
                    network_advice_code: None,
                    network_decline_code: None,
                })
            } else {
                // This shouldn't happen as successful responses go through normal flow
                // But fallback to generic error
                Ok(ErrorResponse {
                    status_code: res.status_code,
                    code: "UNKNOWN_ERROR".to_string(),
                    message: "Unknown PayU error".to_string(),
                    reason: None,
                    attempt_status: Some(enums::AttemptStatus::Failure),
                    connector_transaction_id: None,
                    network_error_message: None,
                    network_advice_code: None,
                    network_decline_code: None,
                })
            }
        }
    }
);

// Implement ConnectorCommon trait
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    ConnectorCommon for Payu<T>
{
    fn id(&self) -> &'static str {
        "payu"
    }

    fn get_currency_unit(&self) -> common_enums::CurrencyUnit {
        CurrencyUnit::Minor
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        &connectors.payu.base_url
    }

    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        let _auth = PayuAuthType::try_from(auth_type)?;
        // Payu uses form-based authentication, not headers
        Ok(vec![])
    }
}

// Stub types for all unsupported flows - MANDATORY to avoid compilation errors
#[derive(Debug, Clone, Serialize)]
pub struct PayuVoidRequest;
#[derive(Debug, Clone)]
pub struct PayuVoidResponse;

#[derive(Debug, Clone, Serialize)]
pub struct PayuCaptureRequest;
#[derive(Debug, Clone)]
pub struct PayuCaptureResponse;

#[derive(Debug, Clone, Serialize)]
pub struct PayuRefundRequest;
#[derive(Debug, Clone)]
pub struct PayuRefundResponse;

#[derive(Debug, Clone, Serialize)]
pub struct PayuRSyncRequest;
#[derive(Debug, Clone)]
pub struct PayuRSyncResponse;

#[derive(Debug, Clone, Serialize)]
pub struct PayuCreateOrderRequest;
#[derive(Debug, Clone)]
pub struct PayuCreateOrderResponse;

#[derive(Debug, Clone, Serialize)]
pub struct PayuSessionTokenRequest;
#[derive(Debug, Clone)]
pub struct PayuSessionTokenResponse;

#[derive(Debug, Clone, Serialize)]
pub struct PayuSetupMandateRequest;
#[derive(Debug, Clone)]
pub struct PayuSetupMandateResponse;

#[derive(Debug, Clone, Serialize)]
pub struct PayuRepeatPaymentRequest;
#[derive(Debug, Clone)]
pub struct PayuRepeatPaymentResponse;

#[derive(Debug, Clone, Serialize)]
pub struct PayuAcceptDisputeRequest;
#[derive(Debug, Clone)]
pub struct PayuAcceptDisputeResponse;

#[derive(Debug, Clone, Serialize)]
pub struct PayuSubmitEvidenceRequest;
#[derive(Debug, Clone)]
pub struct PayuSubmitEvidenceResponse;

#[derive(Debug, Clone, Serialize)]
pub struct PayuDefendDisputeRequest;
#[derive(Debug, Clone)]
pub struct PayuDefendDisputeResponse;

#[derive(Debug, Clone, Serialize)]
pub struct PayuPaymentMethodTokenRequest;
#[derive(Debug, Clone)]
pub struct PayuPaymentMethodTokenResponse;

#[derive(Debug, Clone, Serialize)]
pub struct PayuCreateAccessTokenRequest;
#[derive(Debug, Clone)]
pub struct PayuCreateAccessTokenResponse;

#[derive(Debug, Clone, Serialize)]
pub struct PayuCreateConnectorCustomerRequest;
#[derive(Debug, Clone)]
pub struct PayuCreateConnectorCustomerResponse;

#[derive(Debug, Clone, Serialize)]
pub struct PayuPreAuthenticateRequest;
#[derive(Debug, Clone)]
pub struct PayuPreAuthenticateResponse;

#[derive(Debug, Clone, Serialize)]
pub struct PayuAuthenticateRequest;
#[derive(Debug, Clone)]
pub struct PayuAuthenticateResponse;

#[derive(Debug, Clone, Serialize)]
pub struct PayuPostAuthenticateRequest;
#[derive(Debug, Clone)]
pub struct PayuPostAuthenticateResponse;

#[derive(Debug, Clone, Serialize)]
pub struct PayuVoidPCRequest;
#[derive(Debug, Clone)]
pub struct PayuVoidPCResponse;

// **STUB IMPLEMENTATIONS**: Source Verification Framework stubs for main development
// These will be replaced with actual implementations in Phase 10
use common_utils::crypto;
use interfaces::verification::{ConnectorSourceVerificationSecrets, SourceVerification};

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    SourceVerification<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
    for Payu<T>
{
    fn get_secrets(
        &self,
        _secrets: ConnectorSourceVerificationSecrets,
    ) -> CustomResult<Vec<u8>, ConnectorError> {
        // STUB: Return empty secrets - will be implemented in Phase 10
        Ok(Vec::new())
    }

    fn get_algorithm(
        &self,
    ) -> CustomResult<Box<dyn crypto::VerifySignature + Send>, ConnectorError> {
        // STUB: Use NoAlgorithm - will be replaced with actual algorithm in Phase 10
        Ok(Box::new(crypto::NoAlgorithm))
    }

    fn get_signature(
        &self,
        _payload: &[u8],
        _router_data: &RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData<T>,
            PaymentsResponseData,
        >,
        _secrets: &[u8],
    ) -> CustomResult<Vec<u8>, ConnectorError> {
        // STUB: Return empty signature - will extract actual signature in Phase 10
        Ok(Vec::new())
    }

    fn get_message(
        &self,
        payload: &[u8],
        _router_data: &RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData<T>,
            PaymentsResponseData,
        >,
        _secrets: &[u8],
    ) -> CustomResult<Vec<u8>, ConnectorError> {
        // STUB: Return payload as-is - will implement gateway-specific message format in Phase 10
        Ok(payload.to_owned())
    }
}

// Add Source Verification stubs for all other flows
macro_rules! impl_source_verification_stub {
    ($flow:ty, $common_data:ty, $req:ty, $resp:ty) => {
        impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
            SourceVerification<$flow, $common_data, $req, $resp> for Payu<T>
        {
            fn get_secrets(
                &self,
                _secrets: ConnectorSourceVerificationSecrets,
            ) -> CustomResult<Vec<u8>, ConnectorError> {
                Ok(Vec::new()) // STUB - will be implemented in Phase 10
            }
            fn get_algorithm(
                &self,
            ) -> CustomResult<Box<dyn crypto::VerifySignature + Send>, ConnectorError> {
                Ok(Box::new(crypto::NoAlgorithm)) // STUB - will be implemented in Phase 10
            }
            fn get_signature(
                &self,
                _payload: &[u8],
                _router_data: &RouterDataV2<$flow, $common_data, $req, $resp>,
                _secrets: &[u8],
            ) -> CustomResult<Vec<u8>, ConnectorError> {
                Ok(Vec::new()) // STUB - will be implemented in Phase 10
            }
            fn get_message(
                &self,
                payload: &[u8],
                _router_data: &RouterDataV2<$flow, $common_data, $req, $resp>,
                _secrets: &[u8],
            ) -> CustomResult<Vec<u8>, ConnectorError> {
                Ok(payload.to_owned()) // STUB - will be implemented in Phase 10
            }
        }
    };
}

// Apply stub implementations to all flows
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
    SetupMandate,
    PaymentFlowData,
    SetupMandateRequestData<T>,
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
    RepeatPayment,
    PaymentFlowData,
    RepeatPaymentData,
    PaymentsResponseData
);
impl_source_verification_stub!(
    CreateSessionToken,
    PaymentFlowData,
    SessionTokenRequestData,
    SessionTokenResponseData
);
impl_source_verification_stub!(
    CreateAccessToken,
    PaymentFlowData,
    AccessTokenRequestData,
    AccessTokenResponseData
);
impl_source_verification_stub!(
    PaymentMethodToken,
    PaymentFlowData,
    PaymentMethodTokenizationData<T>,
    PaymentMethodTokenResponse
);
impl_source_verification_stub!(
    CreateConnectorCustomer,
    PaymentFlowData,
    ConnectorCustomerData,
    ConnectorCustomerResponse
);
impl_source_verification_stub!(
    PreAuthenticate,
    PaymentFlowData,
    PaymentsPreAuthenticateData<T>,
    PaymentsResponseData
);
impl_source_verification_stub!(
    Authenticate,
    PaymentFlowData,
    PaymentsAuthenticateData<T>,
    PaymentsResponseData
);
impl_source_verification_stub!(
    PostAuthenticate,
    PaymentFlowData,
    PaymentsPostAuthenticateData<T>,
    PaymentsResponseData
);
impl_source_verification_stub!(
    VoidPC,
    PaymentFlowData,
    PaymentsCancelPostCaptureData,
    PaymentsResponseData
);