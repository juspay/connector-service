pub mod constants;
pub mod headers;
pub mod transformers;

use common_enums as enums;
use common_utils::{
    errors::CustomResult,
    ext_traits::BytesExt,
    types::StringMinorUnit,
};
use domain_types::{
    connector_flow::{
        Accept, Authorize, Capture, CreateOrder, CreateSessionToken, DefendDispute, PSync, RSync,
        Refund, RepeatPayment, SetupMandate, SubmitEvidence, Void,
    },
    connector_types::{
        AcceptDisputeData, DisputeDefendData, DisputeFlowData,
        DisputeResponseData, PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData,
        PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData,
        PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData,
        RepeatPaymentData, SessionTokenRequestData, SessionTokenResponseData,
        SetupMandateRequestData, SubmitEvidenceData,
    },
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::{ConnectorInfo, Connectors},
};
use error_stack::ResultExt;
use hyperswitch_masking::{Maskable, PeekInterface, Secret};
use interfaces::{
    api::ConnectorCommon,
    connector_integration_v2::ConnectorIntegrationV2,
    connector_types,
    events::connector_api_logs::ConnectorEvent,
    verification::{ConnectorSourceVerificationSecrets, SourceVerification},
};
use serde::Serialize;
use transformers as phonepe;

use self::transformers::{
    PhonepePaymentsRequest, PhonepePaymentsResponse, PhonepeSyncRequest, PhonepeSyncResponse,
    PhonepeRefundRequest, PhonepeRefundResponse, PhonepeVoidRequest, PhonepeVoidResponse,
    PhonepeCaptureRequest, PhonepeCaptureResponse, PhonepeCreateOrderRequest, PhonepeCreateOrderResponse,
    PhonepeSessionTokenRequest, PhonepeSessionTokenResponse, PhonepeSetupMandateRequest,
    PhonepeSetupMandateResponse, PhonepeRepeatPaymentRequest, PhonepeRepeatPaymentResponse,
    PhonepeAcceptDisputeRequest, PhonepeAcceptDisputeResponse, PhonepeSubmitEvidenceRequest,
    PhonepeSubmitEvidenceResponse, PhonepeDefendDisputeRequest, PhonepeDefendDisputeResponse,
    PhonepeRSyncRequest, PhonepeRSyncResponse,
};
use super::macros;
use crate::types::ResponseRouterData;

// ===== CONNECTOR IMPLEMENTATION USING UCS v2 MACRO FRAMEWORK =====

// MANDATORY: Use create_all_prerequisites! macro - this is the foundation
macros::create_all_prerequisites!(
    connector_name: Phonepe,
    generic_type: T,
    api: [
        // Implemented flows
        (
            flow: Authorize,
            request_body: PhonepePaymentsRequest,
            response_body: PhonepePaymentsResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: PSync,
            request_body: PhonepeSyncRequest,
            response_body: PhonepeSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ),
        // MANDATORY: Add all other flows even if not implemented (stub types)
        (
            flow: Void,
            request_body: PhonepeVoidRequest,
            response_body: PhonepeVoidResponse,
            router_data: RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ),
        (
            flow: Capture,
            request_body: PhonepeCaptureRequest,
            response_body: PhonepeCaptureResponse,
            router_data: RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ),
        (
            flow: Refund,
            request_body: PhonepeRefundRequest,
            response_body: PhonepeRefundResponse,
            router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ),
        (
            flow: RSync,
            request_body: PhonepeRSyncRequest,
            response_body: PhonepeRSyncResponse,
            router_data: RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ),
        (
            flow: CreateOrder,
            request_body: PhonepeCreateOrderRequest,
            response_body: PhonepeCreateOrderResponse,
            router_data: RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>,
        ),
        (
            flow: CreateSessionToken,
            request_body: PhonepeSessionTokenRequest,
            response_body: PhonepeSessionTokenResponse,
            router_data: RouterDataV2<CreateSessionToken, PaymentFlowData, SessionTokenRequestData, SessionTokenResponseData>,
        ),
        (
            flow: SetupMandate,
            request_body: PhonepeSetupMandateRequest,
            response_body: PhonepeSetupMandateResponse,
            router_data: RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>,
        ),
        (
            flow: RepeatPayment,
            request_body: PhonepeRepeatPaymentRequest,
            response_body: PhonepeRepeatPaymentResponse,
            router_data: RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>,
        ),
        (
            flow: Accept,
            request_body: PhonepeAcceptDisputeRequest,
            response_body: PhonepeAcceptDisputeResponse,
            router_data: RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>,
        ),
        (
            flow: SubmitEvidence,
            request_body: PhonepeSubmitEvidenceRequest,
            response_body: PhonepeSubmitEvidenceResponse,
            router_data: RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>,
        ),
        (
            flow: DefendDispute,
            request_body: PhonepeDefendDisputeRequest,
            response_body: PhonepeDefendDisputeResponse,
            router_data: RouterDataV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>,
        )
    ],
    amount_converters: [
        // CRITICAL: PhonePe expects amount in minor units as string
        amount_converter: StringMinorUnit
    ],
    member_functions: {
        fn get_base_url<F, FCD, Req, Res>(
            &self,
            _req: &RouterDataV2<F, FCD, Req, Res>,
        ) -> String {
            // Default to production for now - can be enhanced with proper test mode detection
            constants::PRODUCTION_BASE_URL.to_string()
        }

        fn get_v2_base_url<F, FCD, Req, Res>(
            &self,
            _req: &RouterDataV2<F, FCD, Req, Res>,
        ) -> String {
            // Default to production for now - can be enhanced with proper test mode detection
            constants::V2_PRODUCTION_BASE_URL.to_string()
        }

        fn build_auth_headers<F, FCD, Req, Res>(
            &self,
            _req: &RouterDataV2<F, FCD, Req, Res>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            Ok(vec![
                (
                    headers::CONTENT_TYPE.to_string(),
                    constants::APPLICATION_JSON.to_string().into(),
                ),
            ])
        }
    }
);

// MANDATORY: Use macro_connector_implementation! for Authorize flow
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Phonepe,
    curl_request: Json(PhonepePaymentsRequest),
    curl_response: PhonepePaymentsResponse,
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
            // Get base headers first
            let mut headers = vec![
                (
                    headers::CONTENT_TYPE.to_string(),
                    constants::APPLICATION_JSON.to_string().into(),
                ),
            ];

            // Build the request to get the checksum for X-VERIFY header
            let connector_router_data = PhonepeRouterData {
                connector: self.clone(),
                router_data: req,
            };
            let connector_req = phonepe::PhonepePaymentsRequest::try_from(&connector_router_data)?;
            headers.push((headers::X_VERIFY.to_string(), connector_req.checksum.into()));

            // Get merchant ID for X-MERCHANT-ID header
            let auth = phonepe::PhonepeAuthType::from_auth_type_and_merchant_id(&req.connector_auth_type, Secret::new(
                req
                    .resource_common_data
                    .merchant_id
                    .get_string_repr()
                    .to_string(),
            ))?;

            headers.push((headers::X_MERCHANT_ID.to_string(), auth.merchant_id.peek().to_string().into()));

            Ok(headers)
        }

        fn get_url(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            let base_url = self.get_base_url(req);
            Ok(format!("{}{}", base_url, constants::API_PAY_ENDPOINT))
        }
    }
);

// MANDATORY: Use macro_connector_implementation! for PSync flow
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Phonepe,
    curl_request: Json(PhonepeSyncRequest),
    curl_response: PhonepeSyncResponse,
    flow_name: PSync,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsSyncData,
    flow_response: PaymentsResponseData,
    http_method: Get,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            // Get base headers first
            let mut headers = vec![
                (
                    headers::CONTENT_TYPE.to_string(),
                    constants::APPLICATION_JSON.to_string().into(),
                ),
            ];

            // Build the request to get the checksum for X-VERIFY header
            let connector_router_data = PhonepeRouterData {
                connector: self.clone(),
                router_data: req,
            };
            let connector_req = phonepe::PhonepeSyncRequest::try_from(&connector_router_data)?;

            // Get merchant ID for X-MERCHANT-ID header
            let auth = phonepe::PhonepeAuthType::from_auth_type_and_merchant_id(&req.connector_auth_type, Secret::new(
                req
                    .resource_common_data
                    .merchant_id
                    .get_string_repr()
                    .to_string(),
            ))?;

            headers.push((headers::X_VERIFY.to_string(), connector_req.checksum.into()));
            headers.push((headers::X_MERCHANT_ID.to_string(), auth.merchant_id.peek().to_string().into()));

            Ok(headers)
        }

        fn get_url(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            let base_url = self.get_base_url(req);
            let merchant_transaction_id = req
                .request
                .connector_transaction_id
                .get_connector_transaction_id()
                .change_context(errors::ConnectorError::MissingConnectorTransactionID)?;

            // Get merchant ID from auth
            let auth = phonepe::PhonepeAuthType::from_auth_type_and_merchant_id(&req.connector_auth_type, Secret::new(
                req
                    .resource_common_data
                    .merchant_id
                    .get_string_repr()
                    .to_string(),
            ))?;
            let merchant_id = auth.merchant_id.peek();
            Ok(format!("{}/v3/transaction/{}/{}", base_url, merchant_id, merchant_transaction_id))
        }
    }
);

// MANDATORY: Implement ConnectorCommon trait
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize> 
    ConnectorCommon for Phonepe<T>
{
    fn id(&self) -> &'static str {
        "phonepe"
    }

    fn get_currency_unit(&self) -> enums::CurrencyUnit {
        enums::CurrencyUnit::Minor
    }

    fn common_get_content_type(&self) -> &'static str {
        constants::APPLICATION_JSON
    }

    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let _auth = phonepe::PhonepeAuthType::try_from(auth_type)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        Ok(vec![
            ("Content-Type".to_string(), constants::APPLICATION_JSON.to_string().into()),
        ])
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.phonepe.base_url.as_ref()
    }

    fn build_error_response(
        &self,
        res: Response,
        _event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        // Parse PhonePe error response (unified for both sync and payments)
        let (error_message, error_code, attempt_status) = if let Ok(error_response) =
            res.response
                .parse_struct::<phonepe::PhonepeErrorResponse>("PhonePe ErrorResponse")
        {
            let attempt_status = phonepe::get_phonepe_error_status(&error_response.code);
            (error_response.message, error_response.code, attempt_status)
        } else {
            let raw_response = String::from_utf8_lossy(&res.response);
            (
                "Unknown PhonePe error".to_string(),
                raw_response.to_string(),
                None,
            )
        };

        Ok(ErrorResponse {
            status_code: res.status_code,
            code: error_code,
            message: error_message.clone(),
            reason: Some(error_message),
            attempt_status,
            connector_transaction_id: None,
            network_decline_code: None,
            network_advice_code: None,
            network_error_message: None,
        })
    }
}

// MANDATORY: Implement ConnectorSpecifications trait
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize> 
    domain_types::connector_types::ConnectorSpecifications for Phonepe<T>
{
    fn get_supported_payment_methods(
        &self,
    ) -> Option<&'static domain_types::types::SupportedPaymentMethods> {
        None // TODO: Add UPI payment methods support
    }

    fn get_supported_webhook_flows(&self) -> Option<&'static [enums::EventClass]> {
        None // TODO: Add webhook support
    }

    fn get_connector_about(&self) -> Option<&'static ConnectorInfo> {
        None // TODO: Add connector info
    }
}

// MANDATORY: Implement all connector_types traits (even for unused flows)
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize> 
    connector_types::PaymentAuthorizeV2<T> for Phonepe<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize> 
    connector_types::PaymentSyncV2 for Phonepe<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize> 
    connector_types::ConnectorServiceTrait<T> for Phonepe<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize> 
    connector_types::PaymentSessionToken for Phonepe<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize> 
    connector_types::PaymentVoidV2 for Phonepe<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize> 
    connector_types::RefundSyncV2 for Phonepe<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize> 
    connector_types::RefundV2 for Phonepe<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize> 
    connector_types::PaymentCapture for Phonepe<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize> 
    connector_types::SetupMandateV2<T> for Phonepe<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize> 
    connector_types::AcceptDispute for Phonepe<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize> 
    connector_types::SubmitEvidenceV2 for Phonepe<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize> 
    connector_types::DisputeDefend for Phonepe<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize> 
    connector_types::IncomingWebhook for Phonepe<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize> 
    connector_types::PaymentOrderCreate for Phonepe<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize> 
    connector_types::ValidationTrait for Phonepe<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize> 
    connector_types::RepeatPaymentV2 for Phonepe<T> {}

// MANDATORY: Stub implementations for unsupported flows
macro_rules! impl_not_implemented_flow {
    ($flow:ty, $common_data:ty, $req:ty, $resp:ty) => {
        impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
            ConnectorIntegrationV2<$flow, $common_data, $req, $resp> for Phonepe<T>
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
            > SourceVerification<$flow, $common_data, $req, $resp> for Phonepe<T>
        {
            fn get_secrets(
                &self,
                _secrets: ConnectorSourceVerificationSecrets,
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
                _router_data: &RouterDataV2<$flow, $common_data, $req, $resp>,
                _secrets: &[u8],
            ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
                Ok(Vec::new()) // Stub implementation
            }
            fn get_message(
                &self,
                payload: &[u8],
                _router_data: &RouterDataV2<$flow, $common_data, $req, $resp>,
                _secrets: &[u8],
            ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
                Ok(payload.to_owned()) // Stub implementation
            }
        }
    };
}

// Apply to all flows
impl_source_verification_stub!(
    CreateSessionToken,
    PaymentFlowData,
    SessionTokenRequestData,
    SessionTokenResponseData
);
impl_source_verification_stub!(
    Authorize,
    PaymentFlowData,
    PaymentsAuthorizeData<T>,
    PaymentsResponseData
);
impl_source_verification_stub!(
    CreateOrder,
    PaymentFlowData,
    PaymentCreateOrderData,
    PaymentCreateOrderResponse
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