pub mod transformers;

use common_enums::{AttemptStatus, PaymentMethodType};
use common_utils::{
    errors::CustomResult,
    ext_traits::ByteSliceExt,
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
    router_response_types::Response,
    types::Connectors,
};
use error_stack::ResultExt;
use hyperswitch_masking::Secret;
use masking::ExposeInterface;
use serde::{Deserialize, Serialize};

use crate::{
    services,
    utils::{self, ConnectorCommonData},
    with_error_response_body,
};

use super::macros;

#[derive(Debug, Clone)]
pub struct ZaakPay<T> {
    amount_converter: &'static (dyn types::AmountConverterTrait<Output = String> + Sync),
    connector_name: &'static str,
    payment_method_data: std::marker::PhantomData<T>,
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

    fn base_url<'a>(&self, _req: &'a utils::ConnectorCommonData) -> &'a str {
        "https://api.zaakpay.com"
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

impl<T> interfaces::verification::SourceVerification<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
    for ZaakPay<T>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize,
{
    fn get_source_verification_data(
        &self,
        _req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    ) -> CustomResult<Option<domain_types::connector_types::SourceVerificationData>, errors::ConnectorError> {
        Ok(None)
    }
}

impl<T> interfaces::verification::SourceVerification<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    for ZaakPay<T>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize,
{
    fn get_source_verification_data(
        &self,
        _req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<Option<domain_types::connector_types::SourceVerificationData>, errors::ConnectorError> {
        Ok(None)
    }
}

impl<T> interfaces::verification::SourceVerification<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
    for ZaakPay<T>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize,
{
    fn get_source_verification_data(
        &self,
        _req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
    ) -> CustomResult<Option<domain_types::connector_types::SourceVerificationData>, errors::ConnectorError> {
        Ok(None)
    }
}

impl<T> interfaces::verification::SourceVerification<domain_types::connector_flow::Void, PaymentFlowData, domain_types::connector_types::PaymentVoidData, PaymentsResponseData>
    for ZaakPay<T>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize,
{
    fn get_source_verification_data(
        &self,
        _req: &RouterDataV2<domain_types::connector_flow::Void, PaymentFlowData, domain_types::connector_types::PaymentVoidData, PaymentsResponseData>,
    ) -> CustomResult<Option<domain_types::connector_types::SourceVerificationData>, errors::ConnectorError> {
        Ok(None)
    }
}

impl<T> interfaces::verification::SourceVerification<domain_types::connector_flow::Capture, PaymentFlowData, domain_types::connector_types::PaymentsCaptureData, PaymentsResponseData>
    for ZaakPay<T>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize,
{
    fn get_source_verification_data(
        &self,
        _req: &RouterDataV2<domain_types::connector_flow::Capture, PaymentFlowData, domain_types::connector_types::PaymentsCaptureData, PaymentsResponseData>,
    ) -> CustomResult<Option<domain_types::connector_types::SourceVerificationData>, errors::ConnectorError> {
        Ok(None)
    }
}

impl<T> interfaces::verification::SourceVerification<domain_types::connector_flow::Refund, RefundFlowData, domain_types::connector_types::RefundsData, RefundsResponseData>
    for ZaakPay<T>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize,
{
    fn get_source_verification_data(
        &self,
        _req: &RouterDataV2<domain_types::connector_flow::Refund, RefundFlowData, domain_types::connector_types::RefundsData, RefundsResponseData>,
    ) -> CustomResult<Option<domain_types::connector_types::SourceVerificationData>, errors::ConnectorError> {
        Ok(None)
    }
}

impl<T> interfaces::verification::SourceVerification<domain_types::connector_flow::CreateOrder, PaymentFlowData, domain_types::connector_types::PaymentCreateOrderData, domain_types::connector_types::PaymentCreateOrderResponse>
    for ZaakPay<T>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize,
{
    fn get_source_verification_data(
        &self,
        _req: &RouterDataV2<domain_types::connector_flow::CreateOrder, PaymentFlowData, domain_types::connector_types::PaymentCreateOrderData, domain_types::connector_types::PaymentCreateOrderResponse>,
    ) -> CustomResult<Option<domain_types::connector_types::SourceVerificationData>, errors::ConnectorError> {
        Ok(None)
    }
}

impl<T> interfaces::verification::SourceVerification<domain_types::connector_flow::CreateSessionToken, PaymentFlowData, domain_types::connector_types::SessionTokenRequestData, domain_types::connector_types::SessionTokenResponseData>
    for ZaakPay<T>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize,
{
    fn get_source_verification_data(
        &self,
        _req: &RouterDataV2<domain_types::connector_flow::CreateSessionToken, PaymentFlowData, domain_types::connector_types::SessionTokenRequestData, domain_types::connector_types::SessionTokenResponseData>,
    ) -> CustomResult<Option<domain_types::connector_types::SourceVerificationData>, errors::ConnectorError> {
        Ok(None)
    }
}

impl<T> interfaces::verification::SourceVerification<domain_types::connector_flow::SetupMandate, PaymentFlowData, domain_types::connector_types::SetupMandateRequestData, PaymentsResponseData>
    for ZaakPay<T>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize,
{
    fn get_source_verification_data(
        &self,
        _req: &RouterDataV2<domain_types::connector_flow::SetupMandate, PaymentFlowData, domain_types::connector_types::SetupMandateRequestData, PaymentsResponseData>,
    ) -> CustomResult<Option<domain_types::connector_types::SourceVerificationData>, errors::ConnectorError> {
        Ok(None)
    }
}

impl<T> interfaces::verification::SourceVerification<domain_types::connector_flow::RepeatPayment, PaymentFlowData, domain_types::connector_types::RepeatPaymentData, PaymentsResponseData>
    for ZaakPay<T>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize,
{
    fn get_source_verification_data(
        &self,
        _req: &RouterDataV2<domain_types::connector_flow::RepeatPayment, PaymentFlowData, domain_types::connector_types::RepeatPaymentData, PaymentsResponseData>,
    ) -> CustomResult<Option<domain_types::connector_types::SourceVerificationData>, errors::ConnectorError> {
        Ok(None)
    }
}

impl<T> interfaces::verification::SourceVerification<domain_types::connector_flow::Accept, domain_types::connector_types::DisputeFlowData, domain_types::connector_types::AcceptDisputeData, domain_types::connector_types::DisputeResponseData>
    for ZaakPay<T>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize,
{
    fn get_source_verification_data(
        &self,
        _req: &RouterDataV2<domain_types::connector_flow::Accept, domain_types::connector_types::DisputeFlowData, domain_types::connector_types::AcceptDisputeData, domain_types::connector_types::DisputeResponseData>,
    ) -> CustomResult<Option<domain_types::connector_types::SourceVerificationData>, errors::ConnectorError> {
        Ok(None)
    }
}

impl<T> interfaces::verification::SourceVerification<domain_types::connector_flow::DefendDispute, domain_types::connector_types::DisputeFlowData, domain_types::connector_types::DisputeDefendData, domain_types::connector_types::DisputeResponseData>
    for ZaakPay<T>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize,
{
    fn get_source_verification_data(
        &self,
        _req: &RouterDataV2<domain_types::connector_flow::DefendDispute, domain_types::connector_types::DisputeFlowData, domain_types::connector_types::DisputeDefendData, domain_types::connector_types::DisputeResponseData>,
    ) -> CustomResult<Option<domain_types::connector_types::SourceVerificationData>, errors::ConnectorError> {
        Ok(None)
    }
}

impl<T> interfaces::verification::SourceVerification<domain_types::connector_flow::SubmitEvidence, domain_types::connector_types::DisputeFlowData, domain_types::connector_types::SubmitEvidenceData, domain_types::connector_types::DisputeResponseData>
    for ZaakPay<T>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize,
{
    fn get_source_verification_data(
        &self,
        _req: &RouterDataV2<domain_types::connector_flow::SubmitEvidence, domain_types::connector_types::DisputeFlowData, domain_types::connector_types::SubmitEvidenceData, domain_types::connector_types::DisputeResponseData>,
    ) -> CustomResult<Option<domain_types::connector_types::SourceVerificationData>, errors::ConnectorError> {
        Ok(None)
    }
}

impl<T> ConnectorIntegrationV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
    for ZaakPay<T>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize,
{
    fn build_request_v2(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    ) -> CustomResult<Option<services::Request>, errors::ConnectorError> {
        let request = transformers::ZaakPayPaymentsRequest::try_from(req)?;
        let url = self.base_url(&utils::ConnectorCommonData {
            connector_name: self.connector_name,
            resource_common_data: &req.router_data.resource_common_data,
            connector_auth_type: &req.router_data.connector_auth_type,
            test_mode: req.router_data.resource_common_data.test_mode,
        }) + "/transaction/.do";
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
        res: Response,
        _event_builder: Option<&mut interfaces::events::connector_api_logs::ConnectorEvent>,
    ) -> CustomResult<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, errors::ConnectorError> {
        let response: transformers::ZaakPayPaymentsResponse = res
            .response
            .parse_struct("ZaakPayPaymentsResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        
        let router_response = transformers::PaymentsResponseData::try_from(response)?;
        Ok(req.clone().with_response(router_response))
    }

    fn get_error_response_v2(
        &self,
        res: &[u8],
        _event_builder: Option<&mut interfaces::events::connector_api_logs::ConnectorEvent>,
    ) -> CustomResult<errors::ConnectorError, errors::ConnectorError> {
        self.get_error_response_v2(res)
    }
}

impl<T> ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    for ZaakPay<T>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize,
{
    fn build_request_v2(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<Option<services::Request>, errors::ConnectorError> {
        let request = transformers::ZaakPayPaymentsSyncRequest::try_from(req)?;
        let url = self.base_url(&utils::ConnectorCommonData {
            connector_name: self.connector_name,
            resource_common_data: &req.router_data.resource_common_data,
            connector_auth_type: &req.router_data.connector_auth_type,
            test_mode: req.router_data.resource_common_data.test_mode,
        }) + "/status.do";
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
        res: Response,
        _event_builder: Option<&mut interfaces::events::connector_api_logs::ConnectorEvent>,
    ) -> CustomResult<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, errors::ConnectorError> {
        let response: transformers::ZaakPayPaymentsSyncResponse = res
            .response
            .parse_struct("ZaakPayPaymentsSyncResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        
        let router_response = transformers::PaymentsResponseData::try_from(response)?;
        Ok(req.clone().with_response(router_response))
    }

    fn get_error_response_v2(
        &self,
        res: &[u8],
        _event_builder: Option<&mut interfaces::events::connector_api_logs::ConnectorEvent>,
    ) -> CustomResult<errors::ConnectorError, errors::ConnectorError> {
        self.get_error_response_v2(res)
    }
}

impl<T> ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
    for ZaakPay<T>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize,
{
    fn build_request_v2(
        &self,
        req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
    ) -> CustomResult<Option<services::Request>, errors::ConnectorError> {
        let request = transformers::ZaakPayRefundSyncRequest::try_from(req)?;
        let url = self.base_url(&utils::ConnectorCommonData {
            connector_name: self.connector_name,
            resource_common_data: &req.router_data.resource_common_data,
            connector_auth_type: &req.router_data.connector_auth_type,
            test_mode: req.router_data.resource_common_data.test_mode,
        }) + "/status.do";
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
        res: Response,
        _event_builder: Option<&mut interfaces::events::connector_api_logs::ConnectorEvent>,
    ) -> CustomResult<RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>, errors::ConnectorError> {
        let response: transformers::ZaakPayRefundSyncResponse = res
            .response
            .parse_struct("ZaakPayRefundSyncResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        
        let router_response = transformers::RefundsResponseData::try_from(response)?;
        Ok(req.clone().with_response(router_response))
    }

    fn get_error_response_v2(
        &self,
        res: &[u8],
        _event_builder: Option<&mut interfaces::events::connector_api_logs::ConnectorEvent>,
    ) -> CustomResult<errors::ConnectorError, errors::ConnectorError> {
        self.get_error_response_v2(res)
    }
}

// Stub implementations for unsupported flows
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

            fn handle_response_v2(
                &self,
                _req: &RouterDataV2<$flow, $common_data, $req, $resp>,
                _res: Response,
                _event_builder: Option<&mut interfaces::events::connector_api_logs::ConnectorEvent>,
            ) -> CustomResult<RouterDataV2<$flow, $common_data, $req, $resp>, errors::ConnectorError> {
                let flow_name = stringify!($flow);
                Err(errors::ConnectorError::NotImplemented(flow_name.to_string()).into())
            }

            fn get_error_response_v2(
                &self,
                _res: &[u8],
                _event_builder: Option<&mut interfaces::events::connector_api_logs::ConnectorEvent>,
            ) -> CustomResult<errors::ConnectorError, errors::ConnectorError> {
                Ok(errors::ConnectorError::NotImplemented("Error handling not implemented".to_string()))
            }
        }
    };
}

impl_not_implemented_flow!(domain_types::connector_flow::Void, PaymentFlowData, domain_types::connector_types::PaymentVoidData, PaymentsResponseData);
impl_not_implemented_flow!(domain_types::connector_flow::Capture, PaymentFlowData, domain_types::connector_types::PaymentsCaptureData, PaymentsResponseData);
impl_not_implemented_flow!(domain_types::connector_flow::Refund, RefundFlowData, domain_types::connector_types::RefundsData, RefundsResponseData);
impl_not_implemented_flow!(domain_types::connector_flow::CreateOrder, PaymentFlowData, domain_types::connector_types::PaymentCreateOrderData, domain_types::connector_types::PaymentCreateOrderResponse);
impl_not_implemented_flow!(domain_types::connector_flow::CreateSessionToken, PaymentFlowData, domain_types::connector_types::SessionTokenRequestData, domain_types::connector_types::SessionTokenResponseData);
impl_not_implemented_flow!(domain_types::connector_flow::SetupMandate, PaymentFlowData, domain_types::connector_types::SetupMandateRequestData, PaymentsResponseData);
impl_not_implemented_flow!(domain_types::connector_flow::RepeatPayment, PaymentFlowData, domain_types::connector_types::RepeatPaymentData, PaymentsResponseData);
impl_not_implemented_flow!(domain_types::connector_flow::Accept, domain_types::connector_types::DisputeFlowData, domain_types::connector_types::AcceptDisputeData, domain_types::connector_types::DisputeResponseData);
impl_not_implemented_flow!(domain_types::connector_flow::DefendDispute, domain_types::connector_types::DisputeFlowData, domain_types::connector_types::DisputeDefendData, domain_types::connector_types::DisputeResponseData);
impl_not_implemented_flow!(domain_types::connector_flow::SubmitEvidence, domain_types::connector_types::DisputeFlowData, domain_types::connector_types::SubmitEvidenceData, domain_types::connector_types::DisputeResponseData);

// Implement all required connector type traits
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

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    domain_types::connector_types::ConnectorServiceTrait<T> for ZaakPay<T> {}

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