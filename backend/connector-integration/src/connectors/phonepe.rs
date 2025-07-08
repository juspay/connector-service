pub mod test;
pub mod transformers;

use common_enums::{AttemptStatus, PaymentMethodType};
use common_utils::{
    errors::CustomResult,
    ext_traits::ByteSliceExt,
    request::RequestContent,
    types::{AmountConvertor, StringMajorUnitForConnector},
};
use domain_types::{
    connector_flow::{
        Accept, Authorize, Capture, DefendDispute, PSync, RSync, Refund, SetupMandate,
        SubmitEvidence, Void,
    },
    connector_types::{
        AcceptDisputeData, DisputeDefendData, DisputeFlowData, DisputeResponseData,
        PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundSyncData,
        RefundsData, RefundsResponseData, SetupMandateRequestData, SubmitEvidenceData,
    },
    types::Connectors,
};

use domain_types::errors;
use domain_types::router_response_types::Response;
use domain_types::{
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
};
use error_stack::ResultExt;
use hyperswitch_masking::Maskable;
use interfaces::{
    api::ConnectorCommon,
    connector_integration_v2::ConnectorIntegrationV2,
    connector_types,
    events::connector_api_logs::ConnectorEvent,
};

use transformers::{self as phonepe, ForeignTryFrom};

pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const X_VERIFY: &str = "X-VERIFY";
}

#[derive(Clone)]
pub struct Phonepe {
    pub(crate) amount_converter: &'static (dyn AmountConvertor<Output = common_utils::types::StringMajorUnit> + Sync),
}

impl connector_types::ConnectorServiceTrait for Phonepe {}
impl connector_types::PaymentAuthorizeV2 for Phonepe {}
impl connector_types::PaymentSyncV2 for Phonepe {}
impl connector_types::PaymentVoidV2 for Phonepe {}
impl connector_types::RefundSyncV2 for Phonepe {}
impl connector_types::RefundV2 for Phonepe {}
impl connector_types::PaymentCapture for Phonepe {}
impl connector_types::SetupMandateV2 for Phonepe {}
impl connector_types::AcceptDispute for Phonepe {}
impl connector_types::SubmitEvidenceV2 for Phonepe {}
impl connector_types::DisputeDefend for Phonepe {}
impl connector_types::IncomingWebhook for Phonepe {}
impl connector_types::PaymentOrderCreate for Phonepe {}
impl connector_types::ValidationTrait for Phonepe {}

impl Phonepe {
    pub const fn new() -> &'static Self {
        &Self {
            // PhonePe uses string amounts in major units (e.g., "10.50" for $10.50)
            amount_converter: &StringMajorUnitForConnector,
        }
    }
}

impl ConnectorCommon for Phonepe {
    fn id(&self) -> &'static str {
        "phonepe"
    }

    fn get_currency_unit(&self) -> common_enums::CurrencyUnit {
        common_enums::CurrencyUnit::Minor
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        &connectors.phonepe.base_url
    }

    fn get_auth_header(
        &self,
        _auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        Ok(vec![
            (headers::CONTENT_TYPE.to_string(), "application/json".into()),
            // X-VERIFY header will be added per request based on payload
        ])
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: phonepe::PhonepeErrorResponse = res
            .response
            .parse_struct("PhonepeErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        event_builder.map(|e| e.set_error_response_body(&response));

        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response.code.unwrap_or_default(),
            message: response.message.unwrap_or_default(),
            reason: response.data.and_then(|data| data.error_description),
            attempt_status: Some(AttemptStatus::Failure),
            connector_transaction_id: None,
            network_error_message: None,
            network_advice_code: None,
            network_decline_code: None,
        })
    }
}

// Stub implementations for source verification framework
// These will be replaced with actual implementations in Phase 5
impl interfaces::verification::SourceVerification<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData> for Phonepe {
    fn get_secrets(&self, _secrets: interfaces::verification::ConnectorSourceVerificationSecrets) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(Vec::new()) // STUB - will be implemented in Phase 5
    }
    
    fn get_algorithm(&self) -> CustomResult<Box<dyn common_utils::crypto::VerifySignature + Send>, errors::ConnectorError> {
        Ok(Box::new(common_utils::crypto::NoAlgorithm)) // STUB - will be implemented in Phase 5
    }
    
    fn get_signature(&self, _payload: &[u8], _router_data: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>, _secrets: &[u8]) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(Vec::new()) // STUB - will be implemented in Phase 5
    }
    
    fn get_message(&self, payload: &[u8], _router_data: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>, _secrets: &[u8]) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(payload.to_owned()) // STUB - will be implemented in Phase 5
    }
}

// Stub implementations for other flows
macro_rules! impl_source_verification_stub {
    ($flow:ty, $common_data:ty, $req:ty, $resp:ty) => {
        impl interfaces::verification::SourceVerification<$flow, $common_data, $req, $resp> for Phonepe {
            fn get_secrets(&self, _secrets: interfaces::verification::ConnectorSourceVerificationSecrets) -> CustomResult<Vec<u8>, errors::ConnectorError> {
                Ok(Vec::new()) // STUB - will be implemented in Phase 5
            }
            fn get_algorithm(&self) -> CustomResult<Box<dyn common_utils::crypto::VerifySignature + Send>, errors::ConnectorError> {
                Ok(Box::new(common_utils::crypto::NoAlgorithm)) // STUB - will be implemented in Phase 5
            }
            fn get_signature(&self, _payload: &[u8], _router_data: &RouterDataV2<$flow, $common_data, $req, $resp>, _secrets: &[u8]) -> CustomResult<Vec<u8>, errors::ConnectorError> {
                Ok(Vec::new()) // STUB - will be implemented in Phase 5
            }
            fn get_message(&self, payload: &[u8], _router_data: &RouterDataV2<$flow, $common_data, $req, $resp>, _secrets: &[u8]) -> CustomResult<Vec<u8>, errors::ConnectorError> {
                Ok(payload.to_owned()) // STUB - will be implemented in Phase 5
            }
        }
    };
}

// Apply stub implementations to all flows
impl_source_verification_stub!(PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData);
impl_source_verification_stub!(Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData);
impl_source_verification_stub!(Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData);
impl_source_verification_stub!(Refund, RefundFlowData, RefundsData, RefundsResponseData);
impl_source_verification_stub!(RSync, RefundFlowData, RefundSyncData, RefundsResponseData);
impl_source_verification_stub!(SetupMandate, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData);
impl_source_verification_stub!(Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData);
impl_source_verification_stub!(SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData);
impl_source_verification_stub!(DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData);
impl_source_verification_stub!(domain_types::connector_flow::CreateOrder, PaymentFlowData, domain_types::connector_types::PaymentCreateOrderData, domain_types::connector_types::PaymentCreateOrderResponse);

// Connector integration stub implementations for unsupported flows
impl ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData> for Phonepe {}
impl ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData> for Phonepe {}
impl ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData> for Phonepe {}
impl ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData> for Phonepe {}
impl ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData> for Phonepe {}
impl ConnectorIntegrationV2<SetupMandate, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData> for Phonepe {}
impl ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData> for Phonepe {}
impl ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData> for Phonepe {}
impl ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData> for Phonepe {}

// CreateOrder flow stub implementation - PhonePe doesn't require separate order creation
impl ConnectorIntegrationV2<domain_types::connector_flow::CreateOrder, PaymentFlowData, domain_types::connector_types::PaymentCreateOrderData, domain_types::connector_types::PaymentCreateOrderResponse> for Phonepe {}

// Main Authorize flow implementation following PhonePe UPI analysis patterns
impl ConnectorIntegrationV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData> for Phonepe {
    fn get_headers(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError>
    where
        Self: ConnectorIntegrationV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData,
            PaymentsResponseData,
        >,
    {
        // Generate PhonePe request for X-VERIFY header generation
        let phonepe_req = phonepe::PhonepePaymentRequest::try_from(req)?;
        let auth = phonepe::PhonepeAuthType::try_from(&req.connector_auth_type)?;
        let verify_header = phonepe_req.generate_verify_header(&auth, "/apis/hermes/pg/v1/pay")?;
        
        let headers = vec![
            (headers::CONTENT_TYPE.to_string(), "application/json".to_string().into()),
            (headers::X_VERIFY.to_string(), verify_header.into()),
        ];
        
        Ok(headers)
    }

    fn get_url(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(format!(
            "{}/apis/hermes/pg/v1/pay",
            req.resource_common_data.connectors.phonepe.base_url
        ))
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let phonepe_req = phonepe::PhonepePaymentRequest::try_from(req)?;
        let encoded_payload = phonepe_req.encode_payload()?;
        
        // PhonePe V2 API expects JSON with base64 encoded request field
        Ok(Some(RequestContent::Json(Box::new(serde_json::json!({
            "request": encoded_payload
        })))))
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData,
            PaymentsResponseData,
        >,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<
        RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        errors::ConnectorError,
    > {
        let response: phonepe::PhonepePaymentResponse = res
            .response
            .parse_struct("PhonepePaymentResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        
        event_builder.map(|e| e.set_response_body(&response));
        
        RouterDataV2::foreign_try_from((
            response,
            data.clone(),
            res.status_code,
            data.request.capture_method,
            false,
            data.request.payment_method_type.unwrap_or(PaymentMethodType::UpiIntent),
        ))
        .change_context(errors::ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }

    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}