mod constants;
mod test;
pub mod transformers;

use std::marker::PhantomData;

use common_enums::{AttemptStatus, PaymentMethodType};
use common_utils::{
    errors::CustomResult,
    ext_traits::BytesExt,
    request::RequestContent,
    types::{self, StringMinorUnit},
};
use domain_types::{
    connector_flow::{Accept, Authorize, Capture, PSync, RSync, Refund, Void},
    connector_types::{
        AcceptDisputeData, ConnectorSpecifications, ConnectorWebhookSecrets, DisputeDefendData,
        DisputeFlowData, DisputeResponseData, PaymentFlowData, PaymentVoidData,
        PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData, PaymentsSyncData,
        RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData, RequestDetails,
        ResponseId, SetupMandateRequestData, SubmitEvidenceData,
    },
    payment_method_data::PaymentMethodDataTypes,
    router_data_v2::RouterDataV2,
    types::{
        AccessToken, AccessTokenAuth, AccessTokenForRefresh, AccessTokenWrapper, AuthKey,
        ConnectorAuthType, ConnectorConfig, ConnectorCustomer, ConnectorCustomerType,
        ConnectorIntegrationV2, ConnectorMetadata, ConnectorRedirectUrl, ConnectorRequestParams,
        ConnectorSubType, ConnectorType, Currency, CustomerDetails, Email, Foreign, MandateData,
        MandateReference, MandateType, MinorUnit, PaymentAddress, PaymentId, PaymentMethodData,
        PaymentsCancelData, PaymentsCaptureMethod, PaymentsPreProcessingData, RefundId,
        RefundStatus, RouterData, Secret, SessionToken, SessionTokenCreateData, SessionTokenType,
        TransactionId,
    },
};
use error_stack::ResultExt;
use hyperswitch_masking::SecretSerdeValue;
use masking::ExposeInterface;
use transformers as easebuzz_transformers;

use crate::{
    services::{self, request as service_request, ConnectorCommon, ConnectorCommonExt},
    utils,
};

#[derive(Debug, Clone)]
pub struct EaseBuzz<T> {
    amount_converter: &'static (dyn types::AmountConverterTrait<Output = String> + Sync),
    connector_name: &'static str,
    payment_method_data: PhantomData<T>,
}

impl<T> ConnectorCommon for EaseBuzz<T>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize,
{
    fn get_id(&self) -> &'static str {
        self.connector_name
    }

    fn get_base_url(&self) -> &'static str {
        constants::BASE_URL
    }

    fn get_auth_type(&self) -> ConnectorAuthType {
        ConnectorAuthType::SignatureKey {
            api_key: self.get_api_key().expose().clone(),
            key1: self.get_merchant_id().expose().clone(),
        }
    }

    fn get_connector_metadata(&self) -> Option<ConnectorMetadata> {
        Some(ConnectorMetadata {
            connector_type: ConnectorType::PaymentGateway,
            connector_sub_type: Some(ConnectorSubType::Standard),
            description: Some("EaseBuzz payment gateway connector".to_string()),
            supported_payment_methods: vec![PaymentMethodType::Upi],
            supported_currencies: vec![Currency::INR],
            supported_countries: vec!["IN".to_string()],
            supported_features: vec![],
            webhook_details: None,
        })
    }
}

impl<T> EaseBuzz<T>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize,
{
    pub fn new() -> Self {
        Self {
            amount_converter: &StringMinorUnit,
            connector_name: "easebuzz",
            payment_method_data: PhantomData,
        }
    }

    fn get_api_key(&self) -> Secret<String> {
        Secret::new("test_api_key".to_string())
    }

    fn get_merchant_id(&self) -> Secret<String> {
        Secret::new("test_merchant_id".to_string())
    }
}

// Stub types for unsupported flows
#[derive(Debug, Clone, serde::Serialize)]
pub struct EaseBuzzVoidRequest;
#[derive(Debug, Clone)]
pub struct EaseBuzzVoidResponse;

#[derive(Debug, Clone, serde::Serialize)]
pub struct EaseBuzzCaptureRequest;
#[derive(Debug, Clone)]
pub struct EaseBuzzCaptureResponse;

#[derive(Debug, Clone, serde::Serialize)]
pub struct EaseBuzzRefundRequest;
#[derive(Debug, Clone)]
pub struct EaseBuzzRefundResponse;

#[derive(Debug, Clone, serde::Serialize)]
pub struct EaseBuzzCreateOrderRequest;
#[derive(Debug, Clone)]
pub struct EaseBuzzCreateOrderResponse;

#[derive(Debug, Clone, serde::Serialize)]
pub struct EaseBuzzSessionTokenRequest;
#[derive(Debug, Clone)]
pub struct EaseBuzzSessionTokenResponse;

#[derive(Debug, Clone, serde::Serialize)]
pub struct EaseBuzzSetupMandateRequest;
#[derive(Debug, Clone)]
pub struct EaseBuzzSetupMandateResponse;

#[derive(Debug, Clone, serde::Serialize)]
pub struct EaseBuzzRepeatPaymentRequest;
#[derive(Debug, Clone)]
pub struct EaseBuzzRepeatPaymentResponse;

#[derive(Debug, Clone, serde::Serialize)]
pub struct EaseBuzzAcceptDisputeRequest;
#[derive(Debug, Clone)]
pub struct EaseBuzzAcceptDisputeResponse;

#[derive(Debug, Clone, serde::Serialize)]
pub struct EaseBuzzDefendDisputeRequest;
#[derive(Debug, Clone)]
pub struct EaseBuzzDefendDisputeResponse;

#[derive(Debug, Clone, serde::Serialize)]
pub struct EaseBuzzSubmitEvidenceRequest;
#[derive(Debug, Clone)]
pub struct EaseBuzzSubmitEvidenceResponse;

// Implement all connector_types traits
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::PaymentOrderCreate for EaseBuzz<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::PaymentSessionToken for EaseBuzz<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::PaymentVoidV2 for EaseBuzz<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::PaymentCaptureV2 for EaseBuzz<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::RefundV2 for EaseBuzz<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::RefundSyncV2 for EaseBuzz<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::MandateSetupV2 for EaseBuzz<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::AcceptDispute for EaseBuzz<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::DefendDispute for EaseBuzz<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::SubmitEvidence for EaseBuzz<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::RepeatPayment for EaseBuzz<T> {}

// Macro for not implemented flows
macro_rules! impl_not_implemented_flow {
    ($flow:ty, $common_data:ty, $req:ty, $resp:ty) => {
        impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
            ConnectorIntegrationV2<$flow, $common_data, $req, $resp> for EaseBuzz<T>
        {
            fn build_request_v2(
                &self,
                _req: &RouterDataV2<$flow, $common_data, $req, $resp>,
            ) -> CustomResult<Option<service_request::Request>, domain_types::errors::ConnectorError> {
                let flow_name = stringify!($flow);
                Err(domain_types::errors::ConnectorError::NotImplemented(flow_name.to_string()).into())
            }
        }
    };
}

// Use macro for all unimplemented flows
impl_not_implemented_flow!(Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData);
impl_not_implemented_flow!(Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData);
impl_not_implemented_flow!(Refund, RefundFlowData, RefundsData, RefundsResponseData);
impl_not_implemented_flow!(Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData);
impl_not_implemented_flow!(DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData);
impl_not_implemented_flow!(SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData);

// Source verification stubs
macro_rules! impl_source_verification_stub {
    ($flow:ty, $common_data:ty, $req:ty, $resp:ty) => {
        impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
            services::SourceVerificationV2<$flow, $common_data, $req, $resp> for EaseBuzz<T>
        {
            fn verify_source(
                &self,
                _router_data: &RouterDataV2<$flow, $common_data, $req, $resp>,
            ) -> CustomResult<bool, domain_types::errors::ConnectorError> {
                Ok(true)
            }
        }
    };
}

impl_source_verification_stub!(Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData);
impl_source_verification_stub!(PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData);
impl_source_verification_stub!(RSync, RefundFlowData, RefundSyncData, RefundsResponseData);
impl_source_verification_stub!(Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData);
impl_source_verification_stub!(Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData);
impl_source_verification_stub!(Refund, RefundFlowData, RefundsData, RefundsResponseData);
impl_source_verification_stub!(Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData);
impl_source_verification_stub!(DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData);
impl_source_verification_stub!(SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData);