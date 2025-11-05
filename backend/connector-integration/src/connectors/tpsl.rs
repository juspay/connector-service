pub mod transformers;

use std::fmt::Debug;

use common_utils::{
    consts,
    errors::CustomResult,
    ext_traits::ByteSliceExt,
    types::{StringMinorUnit},
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
        RepeatPaymentData, RequestDetails, ResponseId, SessionTokenRequestData,
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
use hyperswitch_masking::{Mask, Maskable, PeekInterface, Secret};
use interfaces::{
    api::ConnectorCommon,
    connector_integration_v2::ConnectorIntegrationV2,
    connector_types,
    events::connector_api_logs::ConnectorEvent,
    verification::{ConnectorSourceVerificationSecrets, SourceVerification},
};
use serde::Serialize;
use transformers::{self as tpsl, TpslPaymentsRequest, TpslPaymentsResponse};

use super::macros;
use crate::{types::ResponseRouterData, with_error_response_body};

// Stub types for unsupported flows - MANDATORY to avoid compilation errors
#[derive(Debug, Clone, Serialize)]
pub struct TpslVoidRequest;
#[derive(Debug, Clone)]
pub struct TpslVoidResponse;

#[derive(Debug, Clone, Serialize)]
pub struct TpslCaptureRequest;
#[derive(Debug, Clone)]
pub struct TpslCaptureResponse;

#[derive(Debug, Clone, Serialize)]
pub struct TpslRefundRequest;
#[derive(Debug, Clone)]
pub struct TpslRefundResponse;

#[derive(Debug, Clone, Serialize)]
pub struct TpslRSyncRequest;
#[derive(Debug, Clone)]
pub struct TpslRSyncResponse;

#[derive(Debug, Clone, Serialize)]
pub struct TpslCreateOrderRequest;
#[derive(Debug, Clone)]
pub struct TpslCreateOrderResponse;

#[derive(Debug, Clone, Serialize)]
pub struct TpslSessionTokenRequest;
#[derive(Debug, Clone)]
pub struct TpslSessionTokenResponse;

#[derive(Debug, Clone, Serialize)]
pub struct TpslSetupMandateRequest;
#[derive(Debug, Clone)]
pub struct TpslSetupMandateResponse;

#[derive(Debug, Clone, Serialize)]
pub struct TpslRepeatPaymentRequest;
#[derive(Debug, Clone)]
pub struct TpslRepeatPaymentResponse;

#[derive(Debug, Clone, Serialize)]
pub struct TpslAcceptDisputeRequest;
#[derive(Debug, Clone)]
pub struct TpslAcceptDisputeResponse;

#[derive(Debug, Clone, Serialize)]
pub struct TpslDefendDisputeRequest;
#[derive(Debug, Clone)]
pub struct TpslDefendDisputeResponse;

#[derive(Debug, Clone, Serialize)]
pub struct TpslSubmitEvidenceRequest;
#[derive(Debug, Clone)]
pub struct TpslSubmitEvidenceResponse;

// MANDATORY: Use the create_all_prerequisites! macro for all setup
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
            request_body: TpslPaymentsRequest,
            response_body: TpslPaymentsResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ),
        // MANDATORY: Add all other flows even if not implemented
        (
            flow: Void,
            request_body: TpslVoidRequest,
            response_body: TpslVoidResponse,
            router_data: RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ),
        (
            flow: Capture,
            request_body: TpslCaptureRequest,
            response_body: TpslCaptureResponse,
            router_data: RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ),
        (
            flow: Refund,
            request_body: TpslRefundRequest,
            response_body: TpslRefundResponse,
            router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ),
        (
            flow: RSync,
            request_body: TpslRSyncRequest,
            response_body: TpslRSyncResponse,
            router_data: RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ),
        (
            flow: CreateOrder,
            request_body: TpslCreateOrderRequest,
            response_body: TpslCreateOrderResponse,
            router_data: RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>,
        ),
        (
            flow: CreateSessionToken,
            request_body: TpslSessionTokenRequest,
            response_body: TpslSessionTokenResponse,
            router_data: RouterDataV2<CreateSessionToken, PaymentFlowData, SessionTokenRequestData, SessionTokenResponseData>,
        ),
        (
            flow: SetupMandate,
            request_body: TpslSetupMandateRequest,
            response_body: TpslSetupMandateResponse,
            router_data: RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData>,
        ),
        (
            flow: RepeatPayment,
            request_body: TpslRepeatPaymentRequest,
            response_body: TpslRepeatPaymentResponse,
            router_data: RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>,
        ),
        (
            flow: Accept,
            request_body: TpslAcceptDisputeRequest,
            response_body: TpslAcceptDisputeResponse,
            router_data: RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>,
        ),
        (
            flow: DefendDispute,
            request_body: TpslDefendDisputeRequest,
            response_body: TpslDefendDisputeResponse,
            router_data: RouterDataV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>,
        ),
        (
            flow: SubmitEvidence,
            request_body: TpslSubmitEvidenceRequest,
            response_body: TpslSubmitEvidenceResponse,
            router_data: RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>,
        )
    ],
    amount_converters: [
        amount_converter: StringMinorUnit  // TPSL expects amount in minor units as string
    ],
    member_functions: {
        fn get_api_tag(&self) -> &'static str {
            match self {
                _ => "default", // Default API tag
            }
        }

        fn build_headers(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            let mut headers = vec![];
            headers.push((
                consts::CONTENT_TYPE.to_string(),
                self.get_content_type().to_string().into(),
            ));
            
            // Add authentication headers based on connector auth type
            match &req.connector_auth_type {
                ConnectorAuthType::HeaderKey { api_key } => {
                    headers.push((
                        "Authorization".to_string(),
                        format!("Bearer {}", api_key.peek()).into(),
                    ));
                }
                ConnectorAuthType::SignatureKey { .. } => {
                    // Handle signature-based auth if needed
                }
                _ => {}
            }
            
            Ok(headers)
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

            event_builder.map(|i| i.set_error_response(&response));

            Ok(ErrorResponse {
                status_code: res.status_code,
                code: response.error_code,
                message: response.error_message,
                reason: None,
                attempt_status: None,
            })
        }

        fn common_get_content_type(&self) -> &'static str {
            "application/json"
        }
    }
);

// MANDATORY: Use macro_connector_implementation! for Authorize flow
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
        fn get_url(
            &self,
            _req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            let base_url = if _req.resource_common_data.test_mode.unwrap_or(false) {
                constants::urls::TEST_BASE
            } else {
                constants::urls::PRODUCTION_BASE
            };
            
            Ok(format!("{}{}", base_url, constants::endpoints::UPI_TRANSACTION))
        }
    }
);

// MANDATORY: Use macro_connector_implementation! for PSync flow
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: TPSL,
    curl_request: Json(TpslPaymentsRequest),
    curl_response: TpslPaymentsResponse,
    flow_name: PSync,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsSyncData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
    other_functions: {
        fn get_url(
            &self,
            _req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            let base_url = if _req.resource_common_data.test_mode.unwrap_or(false) {
                constants::urls::TEST_BASE
            } else {
                constants::urls::PRODUCTION_BASE
            };
            
            Ok(format!("{}{}", base_url, constants::endpoints::UPI_TOKEN_GENERATION))
        }
    }
);

// MANDATORY: Implement all connector_types traits even for unused flows
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::PaymentOrderCreate for TPSL<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::PaymentSessionToken for TPSL<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::PaymentVoidV2 for TPSL<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::PaymentCapture for TPSL<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::RefundV2 for TPSL<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::RefundSyncV2 for TPSL<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::SetupMandateV2<T> for TPSL<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::RepeatPayment for TPSL<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::AcceptDispute for TPSL<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::DefendDispute for TPSL<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::SubmitEvidenceV2 for TPSL<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::ValidationTrait for TPSL<T> {}

// Macro for not implemented flows
macro_rules! impl_not_implemented_flow {
    ($flow:ty, $common_data:ty, $req:ty, $resp:ty) => {
        impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
            ConnectorIntegrationV2<$flow, $common_data, $req, $resp> for TPSL<T>
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
impl_not_implemented_flow!(SetupMandate, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData);
impl_not_implemented_flow!(RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData);
impl_not_implemented_flow!(Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData);
impl_not_implemented_flow!(DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData);
impl_not_implemented_flow!(SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData);

// Source verification stubs
macro_rules! impl_source_verification_stub {
    ($flow:ty, $common_data:ty, $req:ty, $resp:ty) => {
        impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
            SourceVerification<$flow, $common_data, $req, $resp> for TPSL<T>
        {
            fn verify_source(
                &self,
                _request: &RequestDetails,
                _connector_webhook_secrets: &ConnectorSourceVerificationSecrets,
                _connector_account_details: &ConnectorAuthType,
            ) -> CustomResult<bool, errors::ConnectorError> {
                Err(errors::ConnectorError::NotImplemented("Source verification not implemented".to_string()).into())
            }
        }
    };
}

// Add source verification for all flows
impl_source_verification_stub!(Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData);
impl_source_verification_stub!(PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData);
impl_source_verification_stub!(Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData);
impl_source_verification_stub!(Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData);
impl_source_verification_stub!(Refund, RefundFlowData, RefundsData, RefundsResponseData);
impl_source_verification_stub!(RSync, RefundFlowData, RefundSyncData, RefundsResponseData);
impl_source_verification_stub!(CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse);
impl_source_verification_stub!(CreateSessionToken, PaymentFlowData, SessionTokenRequestData, SessionTokenResponseData);
impl_source_verification_stub!(SetupMandate, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData);
impl_source_verification_stub!(RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData);
impl_source_verification_stub!(Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData);
impl_source_verification_stub!(DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData);
impl_source_verification_stub!(SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData);

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    ConnectorCommon for TPSL<T>
{
    fn get_id(&self) -> &'static str {
        "tpsl"
    }

    fn get_name(&self) -> &'static str {
        "TPSL"
    }

    fn get_connector_type(&self) -> Connectors {
        Connectors::Tpsl
    }
}

pub mod constants {
    pub mod headers {
        pub const CONTENT_TYPE: &str = "Content-Type";
        pub const AUTHORIZATION: &str = "Authorization";
    }

    pub mod api_tags {
        pub const TRANSACTION: &str = "transaction";
        pub const AUTH_CAPTURE: &str = "auth_capture";
        pub const SI_TRANSACTION: &str = "si_transaction";
        pub const UPI_TRANSACTION: &str = "upi_transaction";
        pub const UPI_TOKEN_GENERATION: &str = "upi_token_generation";
        pub const REFUND_ARN_SYNC: &str = "refund_arn_sync";
    }

    pub mod endpoints {
        pub const TRANSACTION_DETAILS_NEW: &str = "/PaymentGateway/services/TransactionDetailsNew";
        pub const MERCHANT2_PG: &str = "/PaymentGateway/merchant2.pg";
        pub const UPI_TRANSACTION: &str = "/PaymentGateway/upi/transaction";
        pub const UPI_TOKEN_GENERATION: &str = "/PaymentGateway/upi/token";
        pub const REFUND_ARN_SYNC: &str = "/PaymentGateway/refund/arn/sync";
    }

    pub mod urls {
        pub const PRODUCTION_BASE: &str = "https://www.tpsl-india.in";
        pub const TEST_BASE: &str = "https://www.tekprocess.co.in";
    }

    pub mod payment_methods {
        pub const UPI: &str = "UPI";
        pub const UPI_INTENT: &str = "UPI_INTENT";
        pub const UPI_COLLECT: &str = "UPI_COLLECT";
    }

    pub mod transaction_types {
        pub const SALE: &str = "SALE";
        pub const AUTHORIZE: &str = "AUTHORIZE";
        pub const CAPTURE: &str = "CAPTURE";
        pub const REFUND: &str = "REFUND";
        pub const VOID: &str = "VOID";
    }

    pub mod response_codes {
        pub const SUCCESS: &str = "SUCCESS";
        pub const PENDING: &str = "PENDING";
        pub const FAILURE: &str = "FAILURE";
        pub const PROCESSING: &str = "PROCESSING";
    }
}