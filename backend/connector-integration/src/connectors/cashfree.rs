pub mod test;
pub mod transformers;

use common_enums::AttemptStatus;
use common_utils::{
    errors::CustomResult,
    types::{AmountConvertor, StringMajorUnitForConnector},
    ext_traits::ByteSliceExt,
    request::RequestContent,
};
use domain_types::{
    connector_flow::{Authorize, CreateOrder, PSync, RSync, Refund, Capture, Void, SetupMandate, Accept, SubmitEvidence, DefendDispute},
    connector_types::{
        PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData,
        PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, PaymentsCaptureData,
        PaymentVoidData, RefundFlowData, RefundsData, RefundsResponseData, RefundSyncData,
        SetupMandateRequestData, DisputeFlowData, AcceptDisputeData, DisputeResponseData,
        SubmitEvidenceData, DisputeDefendData,
    },
    errors,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_response_types::Response,
    types::Connectors,
};
use error_stack::ResultExt;
use hyperswitch_masking::{Mask, Maskable};
use interfaces::{
    api::ConnectorCommon,
    connector_integration_v2::ConnectorIntegrationV2,
    connector_types,
    events::connector_api_logs::ConnectorEvent,
    verification::{SourceVerification, ConnectorSourceVerificationSecrets},
};
use transformers as cashfree;

pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const X_CLIENT_ID: &str = "X-Client-Id";
    pub(crate) const X_CLIENT_SECRET: &str = "X-Client-Secret";
    pub(crate) const X_API_VERSION: &str = "x-api-version";
}

#[derive(Clone)]
pub struct Cashfree {
    pub(crate) amount_converter: &'static (dyn AmountConvertor<Output = common_utils::types::StringMajorUnit> + Sync),
}

impl connector_types::ValidationTrait for Cashfree {
    fn should_do_order_create(&self) -> bool {
        true // Cashfree V3 requires order creation
    }
}

impl connector_types::ConnectorServiceTrait for Cashfree {}
impl connector_types::PaymentAuthorizeV2 for Cashfree {}
impl connector_types::PaymentOrderCreate for Cashfree {}

impl Cashfree {
    pub const fn new() -> &'static Self {
        &Self {
            // Cashfree V3 uses decimal string amounts (e.g., "10.50")
            amount_converter: &StringMajorUnitForConnector,
        }
    }
}

impl ConnectorCommon for Cashfree {
    fn id(&self) -> &'static str {
        "cashfree"
    }
    
    fn get_currency_unit(&self) -> common_enums::CurrencyUnit {
        common_enums::CurrencyUnit::Base // For major units
    }
    
    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        &connectors.cashfree.base_url
    }
    
    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth = cashfree::CashfreeAuthType::try_from(auth_type)?;
        Ok(vec![
            (headers::X_CLIENT_ID.to_string(), auth.app_id.into_masked()),
            (headers::X_CLIENT_SECRET.to_string(), auth.secret_key.into_masked()),
            (headers::X_API_VERSION.to_string(), "2022-09-01".to_string().into()),
            (headers::CONTENT_TYPE.to_string(), "application/json".to_string().into()),
        ])
    }
    
    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: cashfree::CashfreeErrorResponse = res
            .response
            .parse_struct("CashfreeErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        
        if let Some(event_builder) = event_builder {
            event_builder.set_error_response_body(&response);
        }
        // router_env::logger::info!(connector_response=?response);
        
        let attempt_status = match response.code.as_str() {
            "AUTHENTICATION_ERROR" => AttemptStatus::AuthenticationFailed,
            "AUTHORIZATION_ERROR" => AttemptStatus::AuthorizationFailed,
            "INVALID_REQUEST_ERROR" => AttemptStatus::Failure,
            "GATEWAY_ERROR" => AttemptStatus::Failure,
            "SERVER_ERROR" => AttemptStatus::Pending,
            _ => AttemptStatus::Failure,
        };
        
        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response.code.clone(),
            message: response.message.clone(),
            reason: Some(response.message),
            attempt_status: Some(attempt_status),
            connector_transaction_id: None,
            network_decline_code: None,
            network_advice_code: None,
            network_error_message: None,
            raw_connector_response: Some(String::from_utf8_lossy(&res.response).to_string()),
        })
    }
}

// CreateOrder flow implementation
impl ConnectorIntegrationV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse> for Cashfree {
    fn get_headers(
        &self,
        req: &domain_types::router_data_v2::RouterDataV2<
            CreateOrder,
            PaymentFlowData,
            PaymentCreateOrderData,
            PaymentCreateOrderResponse,
        >,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let mut headers = vec![(
            headers::CONTENT_TYPE.to_string(),
            "application/json".to_string().into(),
        )];
        let mut auth_headers = self.get_auth_header(&req.connector_auth_type)?;
        headers.append(&mut auth_headers);
        Ok(headers)
    }

    fn get_url(
        &self,
        req: &domain_types::router_data_v2::RouterDataV2<
            CreateOrder,
            PaymentFlowData,
            PaymentCreateOrderData,
            PaymentCreateOrderResponse,
        >,
    ) -> CustomResult<String, errors::ConnectorError> {
        let base_url = &req.resource_common_data.connectors.cashfree.base_url;
        Ok(format!("{base_url}pg/orders"))
    }

    fn get_request_body(
        &self,
        req: &domain_types::router_data_v2::RouterDataV2<
            CreateOrder,
            PaymentFlowData,
            PaymentCreateOrderData,
            PaymentCreateOrderResponse,
        >,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let connector_req = cashfree::CashfreeOrderCreateRequest::try_from(req)?;
        Ok(Some(RequestContent::Json(Box::new(connector_req))))
    }

    fn handle_response_v2(
        &self,
        data: &domain_types::router_data_v2::RouterDataV2<
            CreateOrder,
            PaymentFlowData,
            PaymentCreateOrderData,
            PaymentCreateOrderResponse,
        >,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<
        domain_types::router_data_v2::RouterDataV2<
            CreateOrder,
            PaymentFlowData,
            PaymentCreateOrderData,
            PaymentCreateOrderResponse,
        >,
        errors::ConnectorError,
    > {
        let response: cashfree::CashfreeOrderCreateResponse = res
            .response
            .parse_struct("CashfreeOrderCreateResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        if let Some(event_builder) = event_builder {
            event_builder.set_response_body(&response);
        }

        let order_response = PaymentCreateOrderResponse::try_from(response)?;

        Ok(domain_types::router_data_v2::RouterDataV2 {
            response: Ok(order_response),
            ..data.clone()
        })
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

// Authorize flow implementation  
impl ConnectorIntegrationV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData> for Cashfree {
    fn get_headers(
        &self,
        req: &domain_types::router_data_v2::RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData,
            PaymentsResponseData,
        >,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let mut headers = vec![(
            headers::CONTENT_TYPE.to_string(),
            "application/json".to_string().into(),
        )];
        let mut auth_headers = self.get_auth_header(&req.connector_auth_type)?;
        headers.append(&mut auth_headers);
        Ok(headers)
    }

    fn get_url(
        &self,
        req: &domain_types::router_data_v2::RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData,
            PaymentsResponseData,
        >,
    ) -> CustomResult<String, errors::ConnectorError> {
        let base_url = &req.resource_common_data.connectors.cashfree.base_url;
        Ok(format!("{base_url}pg/orders/sessions"))
    }

    fn get_request_body(
        &self,
        req: &domain_types::router_data_v2::RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData,
            PaymentsResponseData,
        >,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let connector_req = cashfree::CashfreePaymentRequest::try_from(req)?;
        Ok(Some(RequestContent::Json(Box::new(connector_req))))
    }

    fn handle_response_v2(
        &self,
        data: &domain_types::router_data_v2::RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData,
            PaymentsResponseData,
        >,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<
        domain_types::router_data_v2::RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData,
            PaymentsResponseData,
        >,
        errors::ConnectorError,
    > {
        let response: cashfree::CashfreePaymentResponse = res
            .response
            .parse_struct("CashfreePaymentResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        if let Some(event_builder) = event_builder {
            event_builder.set_response_body(&response);
        }

        use crate::types::ResponseRouterData;
        use domain_types::router_data_v2::RouterDataV2;
        let response_router_data = ResponseRouterData {
            response,
            router_data: data.clone(),
            http_code: res.status_code,
        };

        RouterDataV2::try_from(response_router_data)
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

// Stub implementations for unsupported flows
impl ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData> for Cashfree {}
impl ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData> for Cashfree {}
impl ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData> for Cashfree {}
impl ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData> for Cashfree {}
impl ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData> for Cashfree {}
impl ConnectorIntegrationV2<SetupMandate, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData> for Cashfree {}
impl ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData> for Cashfree {}
impl ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData> for Cashfree {}
impl ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData> for Cashfree {}

// Trait implementations for all flows
impl connector_types::PaymentSyncV2 for Cashfree {}
impl connector_types::PaymentVoidV2 for Cashfree {}
impl connector_types::RefundSyncV2 for Cashfree {}
impl connector_types::RefundV2 for Cashfree {}
impl connector_types::PaymentCapture for Cashfree {}
impl connector_types::SetupMandateV2 for Cashfree {}
impl connector_types::AcceptDispute for Cashfree {}
impl connector_types::SubmitEvidenceV2 for Cashfree {}
impl connector_types::DisputeDefend for Cashfree {}
impl connector_types::IncomingWebhook for Cashfree {}

// SourceVerification implementations for all flows
macro_rules! impl_source_verification_stub {
    ($flow:ty, $common_data:ty, $req:ty, $resp:ty) => {
        impl SourceVerification<$flow, $common_data, $req, $resp> for Cashfree {
            fn get_secrets(&self, _secrets: ConnectorSourceVerificationSecrets) -> CustomResult<Vec<u8>, errors::ConnectorError> {
                Ok(Vec::new()) // Stub implementation
            }
            fn get_algorithm(&self) -> CustomResult<Box<dyn common_utils::crypto::VerifySignature + Send>, errors::ConnectorError> {
                Ok(Box::new(common_utils::crypto::NoAlgorithm)) // Stub implementation
            }
            fn get_signature(&self, _payload: &[u8], _router_data: &domain_types::router_data_v2::RouterDataV2<$flow, $common_data, $req, $resp>, _secrets: &[u8]) -> CustomResult<Vec<u8>, errors::ConnectorError> {
                Ok(Vec::new()) // Stub implementation
            }
            fn get_message(&self, payload: &[u8], _router_data: &domain_types::router_data_v2::RouterDataV2<$flow, $common_data, $req, $resp>, _secrets: &[u8]) -> CustomResult<Vec<u8>, errors::ConnectorError> {
                Ok(payload.to_owned()) // Stub implementation
            }
        }
    };
}

// Apply to all flows
impl_source_verification_stub!(Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData);
impl_source_verification_stub!(CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse);
impl_source_verification_stub!(PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData);
impl_source_verification_stub!(Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData);
impl_source_verification_stub!(Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData);
impl_source_verification_stub!(Refund, RefundFlowData, RefundsData, RefundsResponseData);
impl_source_verification_stub!(RSync, RefundFlowData, RefundSyncData, RefundsResponseData);
impl_source_verification_stub!(SetupMandate, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData);
impl_source_verification_stub!(Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData);
impl_source_verification_stub!(SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData);
impl_source_verification_stub!(DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData);