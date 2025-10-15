pub mod transformers;

use std::marker::PhantomData;

use common_enums::{AttemptStatus, PaymentMethodType};
use common_utils::{
    consts,
    crypto::{self, OptionalEncryptable},
    errors::CustomResult,
    ext_traits::BytesExt,
    request::RequestContent,
    types::{self, StringMinorUnit},
};
use domain_types::{
    connector_flow::{Authorize, PSync, RSync},
    connector_types::{
        ConnectorCommon, ConnectorCommonV2, ConnectorIntegrationV2, ConnectorSpecifications,
        ConnectorWebhookSecrets, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData,
        PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsResponseData,
    },
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data_v2::RouterDataV2,
    types::{self as domain_types},
};
use error_stack::ResultExt;
use hyperswitch_masking::Secret;
use masking::ExposeInterface;
use serde::{Deserialize, Serialize};

use crate::{
    services,
    utils::{self, ConnectorCommonData},
};

#[derive(Debug, Clone)]
pub struct ZaakPay<T> {
    amount_converter: &'static (dyn types::AmountConverterTrait<Output = String> + Sync),
    connector_name: &'static str,
    payment_method_data: PhantomData<T>,
}

impl<T> ConnectorCommon for ZaakPay<T>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize,
{
    fn get_id(&self) -> &'static str {
        self.connector_name
    }

    fn get_name(&self) -> String {
        "ZaakPay".to_string()
    }

    fn get_connector_type(&self) -> domain_types::ConnectorType {
        domain_types::ConnectorType::PaymentProcessor
    }

    fn get_connector_version(&self) -> String {
        "1.0.0".to_string()
    }

    fn get_supported_payment_methods(&self) -> Vec<PaymentMethodType> {
        vec![PaymentMethodType::Upi]
    }

    fn get_connector_specifications(&self) -> ConnectorSpecifications {
        ConnectorSpecifications {
            connector_name: self.get_name(),
            connector_type: self.get_connector_type(),
            supported_payment_methods: self.get_supported_payment_methods(),
            supported_flows: vec![
                domain_types::ConnectorFlow::Authorize,
                domain_types::ConnectorFlow::PaymentSync,
                domain_types::ConnectorFlow::RefundSync,
            ],
            supported_currencies: vec!["INR".to_string()],
            supported_countries: vec!["IN".to_string()],
        }
    }

    fn get_webhook_secret(&self) -> Option<&'static str> {
        None
    }

    fn get_webhook_details(&self) -> Option<ConnectorWebhookSecrets> {
        None
    }
}

impl<T> ConnectorCommonV2 for ZaakPay<T>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize,
{
    fn get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn get_error_response_v2(
        &self,
        response: &[u8],
    ) -> CustomResult<errors::ConnectorError, errors::ConnectorError> {
        let error_response: ZaakPayErrorResponse = response
            .parse_struct("ZaakPayErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        Ok(errors::ConnectorError::from(error_response))
    }
}

macros::create_all_prerequisites!(
    connector_name: ZaakPay,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: ZaakPayPaymentsRequest,
            response_body: ZaakPayPaymentsResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: PSync,
            request_body: ZaakPayPaymentsSyncRequest,
            response_body: ZaakPayPaymentsSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ),
        (
            flow: RSync,
            request_body: ZaakPayRefundSyncRequest,
            response_body: ZaakPayRefundSyncResponse,
            router_data: RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        )
    ],
    amount_converters: [
        amount_converter: StringMinorUnit
    ],
    member_functions: {
        fn generate_checksum(&self, data: &str, secret_key: &str) -> String {
            let combined = format!("{}|{}", data, secret_key);
            crypto::Sha512::hash(combined.as_bytes()).to_hex()
        }

        fn verify_checksum(&self, data: &str, checksum: &str, secret_key: &str) -> bool {
            let expected_checksum = self.generate_checksum(data, secret_key);
            expected_checksum == checksum
        }

        fn encrypt_data(&self, data: &str, key: &str) -> CustomResult<String, errors::ConnectorError> {
            crypto::Aes256Gcm::encrypt(data, key)
                .change_context(errors::ConnectorError::EncryptionFailed)
        }

        fn decrypt_data(&self, encrypted_data: &str, key: &str) -> CustomResult<String, errors::ConnectorError> {
            crypto::Aes256Gcm::decrypt(encrypted_data, key)
                .change_context(errors::ConnectorError::DecryptionFailed)
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: ZaakPay,
    curl_request: Json(ZaakPayPaymentsRequest),
    curl_response: ZaakPayPaymentsResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
    other_functions: {
        fn build_request_v2(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<Option<services::Request>, errors::ConnectorError> {
            let request = ZaakPayPaymentsRequest::try_from(req)?;
            let url = self.base_url(req) + "/transaction/.do";
            Ok(Some(services::RequestBuilder::new()
                .method(services::Method::Post)
                .url(&url)
                .attach_default_headers()
                .set_body(RequestContent::Json(request))
                .build()))
        }

        fn handle_response_v2(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            res: services::Response,
        ) -> CustomResult<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, errors::ConnectorError> {
            let response: ZaakPayPaymentsResponse = res
                .response
                .parse_struct("ZaakPayPaymentsResponse")
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
            
            let router_data = RouterDataV2::try_from((req, response))?;
            Ok(router_data)
        }

        fn get_error_response_v2(
            &self,
            res: &[u8],
        ) -> CustomResult<errors::ConnectorError, errors::ConnectorError> {
            let error_response: ZaakPayErrorResponse = res
                .parse_struct("ZaakPayErrorResponse")
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
            Ok(errors::ConnectorError::from(error_response))
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: ZaakPay,
    curl_request: Json(ZaakPayPaymentsSyncRequest),
    curl_response: ZaakPayPaymentsSyncResponse,
    flow_name: PSync,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsSyncData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
    other_functions: {
        fn build_request_v2(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<Option<services::Request>, errors::ConnectorError> {
            let request = ZaakPayPaymentsSyncRequest::try_from(req)?;
            let url = self.base_url(req) + "/status.do";
            Ok(Some(services::RequestBuilder::new()
                .method(services::Method::Post)
                .url(&url)
                .attach_default_headers()
                .set_body(RequestContent::Json(request))
                .build()))
        }

        fn handle_response_v2(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            res: services::Response,
        ) -> CustomResult<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, errors::ConnectorError> {
            let response: ZaakPayPaymentsSyncResponse = res
                .response
                .parse_struct("ZaakPayPaymentsSyncResponse")
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
            
            let router_data = RouterDataV2::try_from((req, response))?;
            Ok(router_data)
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: ZaakPay,
    curl_request: Json(ZaakPayRefundSyncRequest),
    curl_response: ZaakPayRefundSyncResponse,
    flow_name: RSync,
    resource_common_data: RefundFlowData,
    flow_request: RefundSyncData,
    flow_response: RefundsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
    other_functions: {
        fn build_request_v2(
            &self,
            req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ) -> CustomResult<Option<services::Request>, errors::ConnectorError> {
            let request = ZaakPayRefundSyncRequest::try_from(req)?;
            let url = self.base_url(req) + "/status.do";
            Ok(Some(services::RequestBuilder::new()
                .method(services::Method::Post)
                .url(&url)
                .attach_default_headers()
                .set_body(RequestContent::Json(request))
                .build()))
        }

        fn handle_response_v2(
            &self,
            req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            res: services::Response,
        ) -> CustomResult<RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>, errors::ConnectorError> {
            let response: ZaakPayRefundSyncResponse = res
                .response
                .parse_struct("ZaakPayRefundSyncResponse")
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
            
            let router_data = RouterDataV2::try_from((req, response))?;
            Ok(router_data)
        }
    }
);

// Stub types for unsupported flows
#[derive(Debug, Clone, Serialize)]
pub struct ZaakPayVoidRequest;
#[derive(Debug, Clone)]
pub struct ZaakPayVoidResponse;

#[derive(Debug, Clone, Serialize)]
pub struct ZaakPayCaptureRequest;
#[derive(Debug, Clone)]
pub struct ZaakPayCaptureResponse;

#[derive(Debug, Clone, Serialize)]
pub struct ZaakPayRefundRequest;
#[derive(Debug, Clone)]
pub struct ZaakPayRefundResponse;

#[derive(Debug, Clone, Serialize)]
pub struct ZaakPayCreateOrderRequest;
#[derive(Debug, Clone)]
pub struct ZaakPayCreateOrderResponse;

#[derive(Debug, Clone, Serialize)]
pub struct ZaakPaySessionTokenRequest;
#[derive(Debug, Clone)]
pub struct ZaakPaySessionTokenResponse;

#[derive(Debug, Clone, Serialize)]
pub struct ZaakPaySetupMandateRequest;
#[derive(Debug, Clone)]
pub struct ZaakPaySetupMandateResponse;

#[derive(Debug, Clone, Serialize)]
pub struct ZaakPayRepeatPaymentRequest;
#[derive(Debug, Clone)]
pub struct ZaakPayRepeatPaymentResponse;

#[derive(Debug, Clone, Serialize)]
pub struct ZaakPayAcceptDisputeRequest;
#[derive(Debug, Clone)]
pub struct ZaakPayAcceptDisputeResponse;

#[derive(Debug, Clone, Serialize)]
pub struct ZaakPayDefendDisputeRequest;
#[derive(Debug, Clone)]
pub struct ZaakPayDefendDisputeResponse;

#[derive(Debug, Clone, Serialize)]
pub struct ZaakPaySubmitEvidenceRequest;
#[derive(Debug, Clone)]
pub struct ZaakPaySubmitEvidenceResponse;

// Implement all required traits for unsupported flows
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    domain_types::connector_types::PaymentVoidV2 for ZaakPay<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    domain_types::connector_types::PaymentCaptureV2 for ZaakPay<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    domain_types::connector_types::PaymentRefundV2 for ZaakPay<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    domain_types::connector_types::PaymentOrderCreate for ZaakPay<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    domain_types::connector_types::PaymentSessionToken for ZaakPay<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    domain_types::connector_types::PaymentSetupMandate for ZaakPay<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    domain_types::connector_types::PaymentRepeatPayment for ZaakPay<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    domain_types::connector_types::DisputeAccept for ZaakPay<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    domain_types::connector_types::DisputeDefend for ZaakPay<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    domain_types::connector_types::DisputeSubmitEvidence for ZaakPay<T> {}

// Not-implemented flow handlers
macro_rules! impl_not_implemented_flow {
    ($flow:ty, $common_data:ty, $req:ty, $resp:ty) => {
        impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
            ConnectorIntegrationV2<$flow, $common_data, $req, $resp> for ZaakPay<T>
        {
            fn build_request_v2(
                &self,
                _req: &RouterDataV2<$flow, $common_data, $req, $resp>,
            ) -> CustomResult<Option<services::Request>, errors::ConnectorError> {
                let flow_name = stringify!($flow);
                Err(errors::ConnectorError::NotImplemented(flow_name.to_string()).into())
            }
        }
    };
}

// Use macro for all unimplemented flows
impl_not_implemented_flow!(domain_types::connector_flow::Void, PaymentFlowData, domain_types::connector_types::PaymentVoidData, PaymentsResponseData);
impl_not_implemented_flow!(domain_types::connector_flow::Capture, PaymentFlowData, domain_types::connector_types::PaymentsCaptureData, PaymentsResponseData);
impl_not_implemented_flow!(domain_types::connector_flow::Refund, RefundFlowData, domain_types::connector_types::RefundsData, RefundsResponseData);
impl_not_implemented_flow!(domain_types::connector_flow::CreateOrder, PaymentFlowData, domain_types::connector_types::PaymentCreateOrderData, domain_types::connector_types::PaymentCreateOrderResponse);
impl_not_implemented_flow!(domain_types::connector_flow::CreateSessionToken, PaymentFlowData, domain_types::connector_types::SessionTokenRequestData, domain_types::connector_types::SessionTokenResponseData);
impl_not_implemented_flow!(domain_types::connector_flow::SetupMandate, PaymentFlowData, domain_types::connector_types::SetupMandateRequestData, domain_types::connector_types::SetupMandateResponseData);
impl_not_implemented_flow!(domain_types::connector_flow::RepeatPayment, PaymentFlowData, domain_types::connector_types::RepeatPaymentData, PaymentsResponseData);
impl_not_implemented_flow!(domain_types::connector_flow::Accept, domain_types::connector_types::DisputeFlowData, domain_types::connector_types::AcceptDisputeData, domain_types::connector_types::DisputeResponseData);
impl_not_implemented_flow!(domain_types::connector_flow::DefendDispute, domain_types::connector_types::DisputeFlowData, domain_types::connector_types::DisputeDefendData, domain_types::connector_types::DisputeResponseData);
impl_not_implemented_flow!(domain_types::connector_flow::SubmitEvidence, domain_types::connector_types::DisputeFlowData, domain_types::connector_types::SubmitEvidenceData, domain_types::connector_types::DisputeResponseData);

// Source verification stubs
macro_rules! impl_source_verification_stub {
    ($flow:ty, $common_data:ty, $req:ty, $resp:ty) => {
        impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
            domain_types::connector_types::SourceVerificationV2<$flow, $common_data, $req, $resp> for ZaakPay<T>
        {
            fn get_source_verification_data(
                &self,
                _req: &RouterDataV2<$flow, $common_data, $req, $resp>,
            ) -> CustomResult<Option<domain_types::connector_types::SourceVerificationData>, errors::ConnectorError> {
                Ok(None)
            }
        }
    };
}

impl_source_verification_stub!(Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData);
impl_source_verification_stub!(PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData);
impl_source_verification_stub!(RSync, RefundFlowData, RefundSyncData, RefundsResponseData);
impl_source_verification_stub!(domain_types::connector_flow::Void, PaymentFlowData, domain_types::connector_types::PaymentVoidData, PaymentsResponseData);
impl_source_verification_stub!(domain_types::connector_flow::Capture, PaymentFlowData, domain_types::connector_types::PaymentsCaptureData, PaymentsResponseData);
impl_source_verification_stub!(domain_types::connector_flow::Refund, RefundFlowData, domain_types::connector_types::RefundsData, RefundsResponseData);
impl_source_verification_stub!(domain_types::connector_flow::CreateOrder, PaymentFlowData, domain_types::connector_types::PaymentCreateOrderData, domain_types::connector_types::PaymentCreateOrderResponse);
impl_source_verification_stub!(domain_types::connector_flow::CreateSessionToken, PaymentFlowData, domain_types::connector_types::SessionTokenRequestData, domain_types::connector_types::SessionTokenResponseData);
impl_source_verification_stub!(domain_types::connector_flow::SetupMandate, PaymentFlowData, domain_types::connector_types::SetupMandateRequestData, domain_types::connector_types::SetupMandateResponseData);
impl_source_verification_stub!(domain_types::connector_flow::RepeatPayment, PaymentFlowData, domain_types::connector_types::RepeatPaymentData, PaymentsResponseData);
impl_source_verification_stub!(domain_types::connector_flow::Accept, domain_types::connector_types::DisputeFlowData, domain_types::connector_types::AcceptDisputeData, domain_types::connector_types::DisputeResponseData);
impl_source_verification_stub!(domain_types::connector_flow::DefendDispute, domain_types::connector_types::DisputeFlowData, domain_types::connector_types::DisputeDefendData, domain_types::connector_types::DisputeResponseData);
impl_source_verification_stub!(domain_types::connector_flow::SubmitEvidence, domain_types::connector_types::DisputeFlowData, domain_types::connector_types::SubmitEvidenceData, domain_types::connector_types::DisputeResponseData);

// Error response types
#[derive(Debug, Deserialize)]
pub struct ZaakPayErrorResponse {
    pub response_code: String,
    pub response_description: String,
}

impl From<ZaakPayErrorResponse> for errors::ConnectorError {
    fn from(error: ZaakPayErrorResponse) -> Self {
        match error.response_code.as_str() {
            "100" => errors::ConnectorError::AuthenticationFailed,
            "101" => errors::ConnectorError::InvalidRequestData {
                message: error.response_description,
            },
            "102" => errors::ConnectorError::InvalidRequestData {
                message: error.response_description,
            },
            "103" => errors::ConnectorError::InvalidRequestData {
                message: error.response_description,
            },
            _ => errors::ConnectorError::UnexpectedResponse {
                status_code: 400,
                response_body: error.response_description,
            },
        }
    }
}