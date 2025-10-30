pub mod constants;
pub mod test;
pub mod transformers;

use std::marker::PhantomData;

use common_enums::PaymentMethodType;
use common_utils::{
    errors::CustomResult,
    id_type::CustomerId,
    pii::SecretSerdeValue,
    types::{StringMinorUnit, MinorUnit},
};
use domain_types::{
    connector_flow::{
        Accept, Authorize, Capture, CreateOrder, CreateSessionToken, DefendDispute, PSync, RSync,
        Refund, RepeatPayment, SetupMandate, SubmitEvidence, Void,
    },
    connector_types::{
        AcceptDisputeData, ConnectorWebhookSecrets, DisputeDefendData,
        DisputeFlowData, DisputeResponseData, PaymentCreateOrderData,
        PaymentCreateOrderResponse, PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData,
        PaymentsCaptureData, PaymentsResponseData, PaymentsSyncData, RefundFlowData,
        RefundSyncData, RefundsData, RefundsResponseData,
        RepeatPaymentData, SessionTokenRequestData,
        SessionTokenResponseData, SetupMandateRequestData, SubmitEvidenceData,
    },
    payment_method_data::PaymentMethodDataTypes,
    router_data_v2::RouterDataV2,
    router_data::ConnectorAuthType,
    errors::ConnectorError,
    utils,
};
use hyperswitch_masking::Secret;

use interfaces::{
    api::ConnectorCommon,
    connector_integration_v2::ConnectorIntegrationV2,
    connector_types::ConnectorValidation,
};

#[derive(Debug, Clone)]
pub struct Tpsl<T> {
    amount_converter: &'static (dyn AmountConverterTrait<Output = String> + Sync),
    connector_name: &'static str,
    payment_method_data: PhantomData<T>,
}

impl<T> Tpsl<T> {
    pub fn new() -> Self {
        Self {
            amount_converter: &common_utils::types::StringMinorUnit,
            connector_name: "tpsl",
            payment_method_data: PhantomData,
        }
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    ConnectorCommon for Tpsl<T>
{
    fn get_id(&self) -> &'static str {
        self.connector_name
    }

    fn get_name(&self) -> &'static str {
        "TPSL"
    }

    fn get_connector_type(&self) -> domain_types::connector_types::ConnectorType {
        domain_types::connector_types::ConnectorType::PaymentProcessor
    }

    fn get_payment_method_types(&self) -> Vec<PaymentMethodType> {
        vec![PaymentMethodType::Upi]
    }

    fn get_connector_specifications(&self) -> domain_types::connector_types::ConnectorSpecifications {
        domain_types::connector_types::ConnectorSpecifications {
            connector_name: self.get_name().to_string(),
            connector_type: self.get_connector_type(),
            payment_method_types: self.get_payment_method_types(),
            ..Default::default()
        }
    }

    fn get_webhook_details(&self) -> Option<ConnectorWebhookSecrets> {
        None
    }

    fn get_test_mode(&self) -> bool {
        false
    }

    fn get_auth_type(&self) -> domain_types::router_data::ConnectorAuthType {
        domain_types::router_data::ConnectorAuthType::SignatureKey {
            api_key: Secret::new("".to_string()),
            key1: Secret::new("".to_string()),
        }
    }

    fn get_base_url(&self) -> &'static str {
        constants::get_base_url()
    }

    fn get_error_response_mapping(&self) -> Option<&'static std::collections::HashMap<String, String>> {
        Some(&constants::ERROR_RESPONSE_MAPPING)
    }
}

// Stub types for unsupported flows
#[derive(Debug, Clone, serde::Serialize)]
pub struct TpslVoidRequest;
#[derive(Debug, Clone)]
pub struct TpslVoidResponse;

#[derive(Debug, Clone, serde::Serialize)]
pub struct TpslCaptureRequest;
#[derive(Debug, Clone)]
pub struct TpslCaptureResponse;

#[derive(Debug, Clone, serde::Serialize)]
pub struct TpslRefundRequest;
#[derive(Debug, Clone)]
pub struct TpslRefundResponse;

#[derive(Debug, Clone, serde::Serialize)]
pub struct TpslRsyncRequest;
#[derive(Debug, Clone)]
pub struct TpslRsyncResponse;

#[derive(Debug, Clone, serde::Serialize)]
pub struct TpslCreateOrderRequest;
#[derive(Debug, Clone)]
pub struct TpslCreateOrderResponse;

#[derive(Debug, Clone, serde::Serialize)]
pub struct TpslSessionTokenRequest;
#[derive(Debug, Clone)]
pub struct TpslSessionTokenResponse;

#[derive(Debug, Clone, serde::Serialize)]
pub struct TpslSetupMandateRequest;
#[derive(Debug, Clone)]
pub struct TpslSetupMandateResponse;

#[derive(Debug, Clone, serde::Serialize)]
pub struct TpslRepeatPaymentRequest;
#[derive(Debug, Clone)]
pub struct TpslRepeatPaymentResponse;

#[derive(Debug, Clone, serde::Serialize)]
pub struct TpslAcceptDisputeRequest;
#[derive(Debug, Clone)]
pub struct TpslAcceptDisputeResponse;

#[derive(Debug, Clone, serde::Serialize)]
pub struct TpslDefendDisputeRequest;
#[derive(Debug, Clone)]
pub struct TpslDefendDisputeResponse;

#[derive(Debug, Clone, serde::Serialize)]
pub struct TpslSubmitEvidenceRequest;
#[derive(Debug, Clone)]
pub struct TpslSubmitEvidenceResponse;

// Macro for not implemented flows
macro_rules! impl_not_implemented_flow {
    ($flow:ty, $common_data:ty, $req:ty, $resp:ty) => {
        impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
            ConnectorIntegrationV2<$flow, $common_data, $req, $resp> for Tpsl<T>
        {
            fn build_request_v2(
                &self,
                _req: &RouterDataV2<$flow, $common_data, $req, $resp>,
            ) -> CustomResult<Option<common_utils::request::Request>, ConnectorError> {
                let flow_name = stringify!($flow);
                Err(ConnectorError::NotImplemented(flow_name.to_string()).into())
            }

            fn handle_response_v2(
                &self,
                _req: &RouterDataV2<$flow, $common_data, $req, $resp>,
                _response: &common_utils::request::Response,
            ) -> CustomResult<RouterDataV2<$flow, $common_data, $req, $resp>, ConnectorError> {
                let flow_name = stringify!($flow);
                Err(ConnectorError::NotImplemented(flow_name.to_string()).into())
            }

            fn get_error_response_v2(
                &self,
                _response: &reqwest::Response,
            ) -> CustomResult<ErrorResponse, ConnectorError> {
                Err(ConnectorError::NotImplemented("Error handling not implemented".to_string()).into())
            }
        }
    };
}

// Implement not implemented flows
impl_not_implemented_flow!(Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData);
impl_not_implemented_flow!(Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData);
impl_not_implemented_flow!(Refund, RefundFlowData, RefundsData, RefundsResponseData);
impl_not_implemented_flow!(RSync, RefundSyncData, RefundSyncData, RefundsResponseData);
impl_not_implemented_flow!(CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse);
impl_not_implemented_flow!(CreateSessionToken, PaymentFlowData, SessionTokenRequestData, SessionTokenResponseData);
impl_not_implemented_flow!(SetupMandate, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData);
impl_not_implemented_flow!(RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData);
impl_not_implemented_flow!(Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData);
impl_not_implemented_flow!(DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData);
impl_not_implemented_flow!(SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData);

// Implement connector types traits
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::PaymentOrderCreate for Tpsl<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::PaymentSessionToken for Tpsl<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::PaymentVoidV2 for Tpsl<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::PaymentCaptureV2 for Tpsl<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::PaymentRefundV2 for Tpsl<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::RefundSyncV2 for Tpsl<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::DisputeAccept for Tpsl<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::DisputeDefend for Tpsl<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::DisputeSubmitEvidence for Tpsl<T> {}

// Source verification stubs
macro_rules! impl_source_verification_stub {
    ($flow:ty, $common_data:ty, $req:ty, $resp:ty) => {
        impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
            services::SourceVerificationV2<$flow, $common_data, $req, $resp> for Tpsl<T>
        {
            fn verify_source_v2(
                &self,
                _req: &RouterDataV2<$flow, $common_data, $req, $resp>,
            ) -> CustomResult<bool, ConnectorError> {
                Ok(true)
            }
        }
    };
}

impl_source_verification_stub!(Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData);
impl_source_verification_stub!(PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData);
impl_source_verification_stub!(Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData);
impl_source_verification_stub!(Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData);
impl_source_verification_stub!(Refund, RefundFlowData, RefundsData, RefundsResponseData);
impl_source_verification_stub!(RSync, RefundSyncData, RefundSyncData, RefundsResponseData);
impl_source_verification_stub!(CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse);
impl_source_verification_stub!(CreateSessionToken, PaymentFlowData, SessionTokenRequestData, SessionTokenResponseData);
impl_source_verification_stub!(SetupMandate, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData);
impl_source_verification_stub!(RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData);
impl_source_verification_stub!(Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData);
impl_source_verification_stub!(DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData);
impl_source_verification_stub!(SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData);

// Validation implementation
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    ConnectorValidation for Tpsl<T>
{
    fn validate_merchant_id(&self, merchant_id: &str) -> CustomResult<(), ConnectorError> {
        if merchant_id.is_empty() {
            Err(ConnectorError::InvalidCredentials {
                message: "Merchant ID cannot be empty".to_string(),
            })?;
        }
        Ok(())
    }

    fn validate_api_key(&self, api_key: &str) -> CustomResult<(), ConnectorError> {
        if api_key.is_empty() {
            Err(ConnectorError::InvalidCredentials {
                message: "API key cannot be empty".to_string(),
            })?;
        }
        Ok(())
    }
}

// Default implementation
impl<T> Default for Tpsl<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Default)]
pub struct ErrorResponse {
    pub status_code: u16,
    pub code: String,
    pub message: String,
    pub reason: Option<String>,
    pub status_message: Option<String>,
}