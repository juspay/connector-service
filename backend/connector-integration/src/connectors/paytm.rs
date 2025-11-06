pub mod transformers;

use std::fmt::Debug;
use common_enums::AttemptStatus;
use common_utils::{errors::CustomResult, ext_traits::BytesExt, types::StringMajorUnit,
    Maskable,
};
use domain_types::{
    connector_flow::{
        Accept, Authenticate, Authorize, Capture, CreateAccessToken, CreateConnectorCustomer,
        CreateOrder, CreateSessionToken, DefendDispute, PSync, PaymentMethodToken,
        PostAuthenticate, PreAuthenticate, RSync, Refund, RepeatPayment, SetupMandate,
        SubmitEvidence, Void, VoidPC,
    },
    connector_types::{
        AcceptDisputeData, AccessTokenRequestData, AccessTokenResponseData, ConnectorCustomerData,
        ConnectorCustomerResponse, DisputeDefendData, DisputeFlowData, DisputeResponseData,
        PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData,
        PaymentMethodTokenResponse, PaymentMethodTokenizationData, PaymentVoidData,
        PaymentsAuthenticateData, PaymentsAuthorizeData, PaymentsCancelPostCaptureData,
        PaymentsCaptureData, PaymentsPostAuthenticateData, PaymentsPreAuthenticateData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData,
        RefundsResponseData, RepeatPaymentData, SessionTokenRequestData, SessionTokenResponseData,
        SetupMandateRequestData, SubmitEvidenceData,
    },
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
};
// use crate::masking::{Maskable, PeekInterface};
use interfaces::{
    api::ConnectorCommon, connector_integration_v2::ConnectorIntegrationV2, connector_types,
    events::connector_api_logs::ConnectorEvent, verification,
};
use paytm::constants;
use serde::Serialize;
use transformers as paytm;
use self::transformers::{
    PaytmAuthorizeRequest, PaytmInitiateTxnRequest, PaytmInitiateTxnResponse,
    PaytmProcessTxnResponse, PaytmTransactionStatusRequest, PaytmTransactionStatusResponse,
};
use crate::{connectors::macros, types::ResponseRouterData};

// Define connector prerequisites using macros - following the exact pattern from other connectors
macros::create_all_prerequisites!(
    connector_name: Paytm,
    generic_type: T,
    api: [
        (
            flow: CreateSessionToken,
            request_body: PaytmInitiateTxnRequest,
            response_body: PaytmInitiateTxnResponse,
            router_data: RouterDataV2<CreateSessionToken, PaymentFlowData, SessionTokenRequestData, SessionTokenResponseData>,
        ),
        (
            flow: Authorize,
            request_body: PaytmAuthorizeRequest,
            response_body: PaytmProcessTxnResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: PSync,
            request_body: PaytmTransactionStatusRequest,
            response_body: PaytmTransactionStatusResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        )
    ],
    amount_converters: [amount_converter: StringMajorUnit],
    member_functions: {
        pub fn connector_base_url<F, Req, Res>(
            &self,
            req: &RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> String {
            req.resource_common_data.connectors.paytm.base_url.to_string()
        }
        fn get_attempt_status_from_http_code(status_code: u16) -> AttemptStatus {
            match status_code {
                500..=599 => AttemptStatus::Pending, // 5xx errors should be pending for retry
                _ => AttemptStatus::Failure,          // All other errors are final failures
            }
        }
        fn build_custom_error_response(
            res: Response,
            event_builder: Option<&mut ConnectorEvent>,
        ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
            // First try to parse as session token error response format
            if let Ok(session_error_response) = res
                .response
                .parse_struct::<paytm::PaytmSessionTokenErrorResponse>("PaytmSessionTokenErrorResponse")
            {
                if let Some(event) = event_builder {
                    event.set_error_response_body(&session_error_response);
                }
                return Ok(domain_types::router_data::ErrorResponse {
                    code: session_error_response.body.result_info.result_code,
                    message: session_error_response.body.result_info.result_msg,
                    reason: None,
                    status_code: res.status_code,
                    attempt_status: Some(Self::get_attempt_status_from_http_code(res.status_code)),
                    connector_transaction_id: None,
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                });
            }

            // Try to parse as transaction error response format
            if let Ok(txn_error_response) = res
                .response
                .parse_struct::<paytm::PaytmTransactionErrorResponse>("PaytmTransactionErrorResponse")
            {
                if let Some(event) = event_builder {
                    event.set_error_response_body(&txn_error_response);
                }
                return Ok(domain_types::router_data::ErrorResponse {
                    code: txn_error_response.body.result_info.result_code,
                    message: txn_error_response.body.result_info.result_msg,
                    reason: None,
                    status_code: res.status_code,
                    attempt_status: Some(Self::get_attempt_status_from_http_code(res.status_code)),
                    connector_transaction_id: None,
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                });
            }

            // If neither format matches, create a generic error response
            let raw_response = res.response.clone();
            let error_message = if raw_response.is_empty() {
                "Empty response from Paytm".to_string()
            } else {
                "Failed to parse Paytm error response".to_string()
            };

            Ok(domain_types::router_data::ErrorResponse {
                code: res.status_code.to_string(),
                message: error_message,
                reason: Some(format!(
                    "Raw response: {}",
                    raw_response.chars().take(200).collect::<String>()
                )),
                status_code: res.status_code,
                attempt_status: Some(Self::get_attempt_status_from_http_code(res.status_code)),
                connector_transaction_id: None,
                network_decline_code: None,
                network_advice_code: None,
                network_error_message: None,
            })
        }
    }
);

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ValidationTrait for Paytm<T>
{
    fn should_do_session_token(&self) -> bool {
        true // Enable CreateSessionToken flow for Paytm's initiate step
    }
    fn should_do_order_create(&self) -> bool {
        false // Paytm doesn't require separate order creation
    }
}

// Service trait implementations with generic type parameters
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ConnectorServiceTrait<T> for Paytm<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentSessionToken for Paytm<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAccessToken for Paytm<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::CreateConnectorCustomer for Paytm<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAuthorizeV2<T> for Paytm<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentSyncV2 for Paytm<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentOrderCreate for Paytm<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundV2 for Paytm<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundSyncV2 for Paytm<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RepeatPaymentV2 for Paytm<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentVoidPostCaptureV2<T> for Paytm<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        VoidPC,
        PaymentFlowData,
        PaymentsCancelPostCaptureData,
        PaymentsResponseData,
    > for Paytm<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        CreateSessionToken,
        PaymentFlowData,
        SessionTokenRequestData,
        SessionTokenResponseData,
    > for Paytm<T>
{
    fn get_secrets(
        &self,
        _secrets: interfaces::verification::ConnectorSourceVerificationSecrets,
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(Vec::new()) // Stub implementation
    }

    fn get_algorithm(
        &self,
    ) -> CustomResult<
        Box<dyn common_utils::crypto::VerifySignature + Send>,
        errors::ConnectorError,
    > {
        Ok(Box::new(common_utils::crypto::NoAlgorithm)) // Stub implementation
    }

    fn get_signature(
        &self,
        _payload: &[u8],
        _router_data: &domain_types::router_data_v2::RouterDataV2<
            CreateSessionToken,
            PaymentFlowData,
            SessionTokenRequestData,
            SessionTokenResponseData,
        >,
        _secrets: &[u8],
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(Vec::new()) // Stub implementation
    }

    fn get_message(
        &self,
        payload: &[u8],
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(payload.to_owned()) // Stub implementation
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentCapture for Paytm<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentVoidV2 for Paytm<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::SetupMandateV2<T> for Paytm<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::AcceptDispute for Paytm<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::DisputeDefend for Paytm<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::SubmitEvidenceV2 for Paytm<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::IncomingWebhook for Paytm<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentTokenV2<T> for Paytm<T>
{
}

// Additional trait implementations for authentication flows
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentPreAuthenticateV2<T> for Paytm<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAuthenticateV2<T> for Paytm<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentPostAuthenticateV2<T> for Paytm<T>
{
}

// Additional ConnectorIntegrationV2 implementations
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<CreateSessionToken, PaymentFlowData, SessionTokenRequestData, SessionTokenResponseData>
    for Paytm<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
    for Paytm<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    for Paytm<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
    for Paytm<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
    for Paytm<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
    for Paytm<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
    for Paytm<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>
    for Paytm<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    for Paytm<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
    for Paytm<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
    for Paytm<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<PaymentMethodToken, PaymentMethodTokenizationData<T>, PaymentMethodTokenResponse>
    for Paytm<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<CreateAccessToken, AccessTokenRequestData, AccessTokenResponseData>
    for Paytm<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<CreateConnectorCustomer, ConnectorCustomerData, ConnectorCustomerResponse>
    for Paytm<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<PreAuthenticate, PaymentFlowData, PaymentsPreAuthenticateData<T>, PaymentsResponseData>
    for Paytm<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Authenticate, PaymentFlowData, PaymentsAuthenticateData<T>, PaymentsResponseData>
    for Paytm<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<PostAuthenticate, PaymentFlowData, PaymentsPostAuthenticateData<T>, PaymentsResponseData>
    for Paytm<T>
{
}

// Additional SourceVerification implementations
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        Authorize,
        PaymentFlowData,
        PaymentsAuthorizeData<T>,
        PaymentsResponseData,
    > for Paytm<T>
{
    fn get_secrets(
        &self,
        _secrets: interfaces::verification::ConnectorSourceVerificationSecrets,
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(Vec::new()) // Stub implementation
    }

    fn get_algorithm(
        &self,
    ) -> CustomResult<
        Box<dyn common_utils::crypto::VerifySignature + Send>,
        errors::ConnectorError,
    > {
        Ok(Box::new(common_utils::crypto::NoAlgorithm)) // Stub implementation
    }

    fn get_signature(
        &self,
        _payload: &[u8],
        _router_data: &domain_types::router_data_v2::RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData<T>,
            PaymentsResponseData,
        >,
        _secrets: &[u8],
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(Vec::new()) // Stub implementation
    }

    fn get_message(
        &self,
        payload: &[u8],
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(payload.to_owned()) // Stub implementation
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        PSync,
        PaymentFlowData,
        PaymentsSyncData,
        PaymentsResponseData,
    > for Paytm<T>
{
    fn get_secrets(
        &self,
        _secrets: interfaces::verification::ConnectorSourceVerificationSecrets,
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(Vec::new()) // Stub implementation
    }

    fn get_algorithm(
        &self,
    ) -> CustomResult<
        Box<dyn common_utils::crypto::VerifySignature + Send>,
        errors::ConnectorError,
    > {
        Ok(Box::new(common_utils::crypto::NoAlgorithm)) // Stub implementation
    }

    fn get_signature(
        &self,
        _payload: &[u8],
        _router_data: &domain_types::router_data_v2::RouterDataV2<
            PSync,
            PaymentFlowData,
            PaymentsSyncData,
            PaymentsResponseData,
        >,
        _secrets: &[u8],
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(Vec::new()) // Stub implementation
    }

    fn get_message(
        &self,
        payload: &[u8],
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(payload.to_owned()) // Stub implementation
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        PreAuthenticate,
        PaymentFlowData,
        PaymentsPreAuthenticateData<T>,
        PaymentsResponseData,
    > for Paytm<T>
{
    fn get_secrets(
        &self,
        _secrets: interfaces::verification::ConnectorSourceVerificationSecrets,
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(Vec::new()) // Stub implementation
    }

    fn get_algorithm(
        &self,
    ) -> CustomResult<
        Box<dyn common_utils::crypto::VerifySignature + Send>,
        errors::ConnectorError,
    > {
        Ok(Box::new(common_utils::crypto::NoAlgorithm)) // Stub implementation
    }

    fn get_signature(
        &self,
        _payload: &[u8],
        _router_data: &domain_types::router_data_v2::RouterDataV2<
            PreAuthenticate,
            PaymentFlowData,
            PaymentsPreAuthenticateData<T>,
            PaymentsResponseData,
        >,
        _secrets: &[u8],
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(Vec::new()) // Stub implementation
    }

    fn get_message(
        &self,
        payload: &[u8],
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(payload.to_owned()) // Stub implementation
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        Authenticate,
        PaymentFlowData,
        PaymentsAuthenticateData<T>,
        PaymentsResponseData,
    > for Paytm<T>
{
    fn get_secrets(
        &self,
        _secrets: interfaces::verification::ConnectorSourceVerificationSecrets,
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(Vec::new()) // Stub implementation
    }

    fn get_algorithm(
        &self,
    ) -> CustomResult<
        Box<dyn common_utils::crypto::VerifySignature + Send>,
        errors::ConnectorError,
    > {
        Ok(Box::new(common_utils::crypto::NoAlgorithm)) // Stub implementation
    }

    fn get_signature(
        &self,
        _payload: &[u8],
        _router_data: &domain_types::router_data_v2::RouterDataV2<
            Authenticate,
            PaymentFlowData,
            PaymentsAuthenticateData<T>,
            PaymentsResponseData,
        >,
        _secrets: &[u8],
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(Vec::new()) // Stub implementation
    }

    fn get_message(
        &self,
        payload: &[u8],
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(payload.to_owned()) // Stub implementation
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        PostAuthenticate,
        PaymentFlowData,
        PaymentsPostAuthenticateData<T>,
        PaymentsResponseData,
    > for Paytm<T>
{
    fn get_secrets(
        &self,
        _secrets: interfaces::verification::ConnectorSourceVerificationSecrets,
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(Vec::new()) // Stub implementation
    }

    fn get_algorithm(
        &self,
    ) -> CustomResult<
        Box<dyn common_utils::crypto::VerifySignature + Send>,
        errors::ConnectorError,
    > {
        Ok(Box::new(common_utils::crypto::NoAlgorithm)) // Stub implementation
    }

    fn get_signature(
        &self,
        _payload: &[u8],
        _router_data: &domain_types::router_data_v2::RouterDataV2<
            PostAuthenticate,
            PaymentFlowData,
            PaymentsPostAuthenticateData<T>,
            PaymentsResponseData,
        >,
        _secrets: &[u8],
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(Vec::new()) // Stub implementation
    }

    fn get_message(
        &self,
        payload: &[u8],
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(payload.to_owned()) // Stub implementation
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        CreateConnectorCustomer,
        ConnectorCustomerData,
        ConnectorCustomerResponse,
        PaymentsResponseData,
    > for Paytm<T>
{
    fn get_secrets(
        &self,
        _secrets: interfaces::verification::ConnectorSourceVerificationSecrets,
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(Vec::new()) // Stub implementation
    }

    fn get_algorithm(
        &self,
    ) -> CustomResult<
        Box<dyn common_utils::crypto::VerifySignature + Send>,
        errors::ConnectorError,
    > {
        Ok(Box::new(common_utils::crypto::NoAlgorithm)) // Stub implementation
    }

    fn get_signature(
        &self,
        _payload: &[u8],
        _router_data: &domain_types::router_data_v2::RouterDataV2<
            CreateConnectorCustomer,
            ConnectorCustomerData,
            ConnectorCustomerResponse,
            PaymentsResponseData,
        >,
        _secrets: &[u8],
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(Vec::new()) // Stub implementation
    }

    fn get_message(
        &self,
        payload: &[u8],
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(payload.to_owned()) // Stub implementation
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        VoidPC,
        PaymentFlowData,
        PaymentsCancelPostCaptureData,
        PaymentsResponseData,
    > for Paytm<T>
{
    fn get_secrets(
        &self,
        _secrets: interfaces::verification::ConnectorSourceVerificationSecrets,
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(Vec::new()) // Stub implementation
    }

    fn get_algorithm(
        &self,
    ) -> CustomResult<
        Box<dyn common_utils::crypto::VerifySignature + Send>,
        errors::ConnectorError,
    > {
        Ok(Box::new(common_utils::crypto::NoAlgorithm)) // Stub implementation
    }

    fn get_signature(
        &self,
        _payload: &[u8],
        _router_data: &domain_types::router_data_v2::RouterDataV2<
            VoidPC,
            PaymentFlowData,
            PaymentsCancelPostCaptureData,
            PaymentsResponseData,
        >,
        _secrets: &[u8],
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(Vec::new()) // Stub implementation
    }

    fn get_message(
        &self,
        payload: &[u8],
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(payload.to_owned()) // Stub implementation
    }
}