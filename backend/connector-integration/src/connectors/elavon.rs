pub mod transformers;
pub mod test;

use domain_types::{
    connector_flow::{
        Accept, Authorize, Capture, CreateOrder, PSync, RSync, Refund, SetupMandate, SubmitEvidence, Void
    },
    connector_types::{
        AcceptDispute, AcceptDisputeData, ConnectorServiceTrait, DisputeFlowData, DisputeResponseData, IncomingWebhook, PaymentAuthorizeV2, PaymentCapture, PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData, PaymentOrderCreate, PaymentSyncV2, PaymentVoidData, PaymentVoidV2, PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundSyncData, RefundSyncV2, RefundV2, RefundsData, RefundsResponseData, SetupMandateRequestData, SetupMandateV2, SubmitEvidenceData, SubmitEvidenceV2, ValidationTrait
    },
};
use error_stack::ResultExt;
use hyperswitch_common_utils::{
    errors::CustomResult,
    ext_traits::ByteSliceExt,
    request::RequestContent,
    types::{AmountConvertor, StringMajorUnit, StringMajorUnitForConnector},
    
};
use hyperswitch_connectors::utils;
use hyperswitch_domain_models::{
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2, router_request_types::SyncRequestType,
};
use hyperswitch_interfaces::{
    api::{self as api, ConnectorCommon},
    configs::Connectors,
    consts as hs_consts,
    connector_integration_v2::{self, ConnectorIntegrationV2},
    errors as hs_errors,
    events::connector_api_logs::ConnectorEvent,
    types as hs_types,
};
use hyperswitch_masking::{ Maskable, Secret, WithoutType};
use serde::Serialize;
use std::collections::HashMap;

use transformers::{self as elavon, ForeignTryFrom};
use crate::with_response_body;
use hyperswitch_common_enums;

pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
}
pub struct Elavon {
    amount_converter: &'static (dyn AmountConvertor<Output = StringMajorUnit> + Sync),
}

pub fn deserialize_xml_to_struct<T: serde::de::DeserializeOwned>(
    xml_data: &[u8],
) -> Result<T, hs_errors::ConnectorError> {
    let response_str = std::str::from_utf8(xml_data)
        .map_err(|_e| {
             hs_errors::ConnectorError::ResponseDeserializationFailed
        })?
        .trim();
    let result: T = quick_xml::de::from_str(response_str).map_err(|_e| {
        hs_errors::ConnectorError::ResponseDeserializationFailed
    })?;

    Ok(result)
}

impl Elavon {
    pub fn new() -> &'static Self {
        &Self {
            amount_converter: &StringMajorUnitForConnector,
        }
    }
}

impl api::ConnectorCommon for Elavon {
    fn id(&self) -> &'static str {
        "elavon"
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/x-www-form-urlencoded"
    }

    fn get_auth_header(
        &self,
        _auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, hs_errors::ConnectorError> {
        Ok(Vec::new())
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.elavon.base_url.as_ref()
    }

    fn build_error_response(
        &self,
        res: hs_types::Response,
         event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, hs_errors::ConnectorError> {
        match res
            .response
            .parse_struct::<elavon::ElavonPaymentsResponse>("ElavonPaymentsResponse")
            .map_err(|_| hs_errors::ConnectorError::ResponseDeserializationFailed)
        {
            Ok(elavon_response) => {
                with_response_body!(event_builder, elavon_response);
                match elavon_response.result {
                    elavon::ElavonResult::Error(error_payload) => {
                        Ok(ErrorResponse {
                            status_code: res.status_code,
                            code: error_payload.error_code.unwrap_or_else(|| hs_consts::NO_ERROR_CODE.to_string()),
                            message: error_payload.error_message,
                            reason: error_payload.error_name,
                            attempt_status: Some(hyperswitch_common_enums::AttemptStatus::Failure),
                            connector_transaction_id: error_payload.ssl_txn_id,
                        })
                    }
                    elavon::ElavonResult::Success(success_payload) => {
                        Ok(ErrorResponse {
                            status_code: res.status_code,
                            code: hs_consts::NO_ERROR_CODE.to_string(),
                            message: "Received success response in error flow".to_string(),
                            reason: Some(format!("Unexpected success: {:?}", success_payload.ssl_result_message)),
                            attempt_status: Some(hyperswitch_common_enums::AttemptStatus::Failure),
                            connector_transaction_id: Some(success_payload.ssl_txn_id),
                        })
                    }
                }
            }
            Err(_parsing_error) => {
                let (message, reason) = match res.status_code {
                    500..=599 => (
                        "Elavon server error".to_string(),
                        Some(String::from_utf8_lossy(&res.response).into_owned()),
                    ),
                    _ => (
                        "Elavon error response".to_string(),
                        Some(String::from_utf8_lossy(&res.response).into_owned()),
                    ),
                };
                Ok(ErrorResponse {
                    status_code: res.status_code,
                    code: hs_consts::NO_ERROR_CODE.to_string(),
                    message,
                    reason,
                    attempt_status: Some(hyperswitch_common_enums::AttemptStatus::Failure),
                    connector_transaction_id: None,
                })
            }
        }
    }
}

impl api::ConnectorValidation for Elavon {}
impl ValidationTrait for Elavon {}
impl ConnectorServiceTrait for Elavon {}

impl PaymentAuthorizeV2 for Elavon {}
impl PaymentSyncV2 for Elavon {}
impl PaymentOrderCreate for Elavon {}
impl PaymentVoidV2 for Elavon {}
impl RefundSyncV2 for Elavon {}
impl RefundV2 for Elavon {}
impl PaymentCapture for Elavon {}
impl SetupMandateV2 for Elavon {}
impl AcceptDispute for Elavon {}
impl SubmitEvidenceV2 for Elavon {}
impl IncomingWebhook for Elavon {}

pub fn struct_to_xml<T: Serialize>(
    item: &T,
) -> Result<HashMap<String, Secret<String, WithoutType>>, hs_errors::ConnectorError> {
    let xml_content = quick_xml::se::to_string_with_root("txn", &item).map_err(|_e| {
        hs_errors::ConnectorError::ResponseDeserializationFailed
    })?;

    let mut result = HashMap::new();
    result.insert(
        "xmldata".to_string(),
        Secret::<_, WithoutType>::new(xml_content),
    );
    Ok(result)
}

impl connector_integration_v2::ConnectorIntegrationV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>
    for Elavon
{
    fn get_headers(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, hs_errors::ConnectorError> {
        let mut header = vec![(
            headers::CONTENT_TYPE.to_string(),
            self.common_get_content_type().to_string().into(),
        )];
        let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
        header.append(&mut api_key);
        Ok(header)
    }

    fn get_url(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
    ) -> CustomResult<String, hs_errors::ConnectorError> {
        Ok(format!("{}processxml.do", req.resource_common_data.connectors.elavon.base_url))
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
    ) -> CustomResult<Option<RequestContent>, hs_errors::ConnectorError> {
        
        let amount=utils::convert_amount(
            self.amount_converter,
            req.request.minor_amount,
            req.request.currency,
        )?;

        let elavon_router_data = elavon::ElavonRouterData::try_from((amount, req))
            .change_context(hs_errors::ConnectorError::RequestEncodingFailed)
            .attach_printable("Failed to create ElavonRouterData for request")?;

        let elavon_req = elavon::ElavonPaymentsRequest::try_from(&elavon_router_data)
            .change_context(hs_errors::ConnectorError::RequestEncodingFailed)
            .attach_printable("Failed to create ElavonPaymentsRequest from ElavonRouterData")?;

        Ok(Some(RequestContent::FormUrlEncoded(Box::new(struct_to_xml(
            &elavon_req,
        )?))))
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
         event_builder: Option<&mut ConnectorEvent>,
        res: hs_types::Response,
    ) -> CustomResult<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>, hs_errors::ConnectorError> {
        let response: elavon::ElavonPaymentsResponse =
            deserialize_xml_to_struct(&res.response)?;
            with_response_body!(event_builder, response);

            RouterDataV2::foreign_try_from((
                response.result,
                data.clone(),
                res.status_code,
                data.request.capture_method,
                false,
                data.request.payment_method_type,
            ))
            .change_context(hs_errors::ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response_v2(
        &self,
        res: hs_types::Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, hs_errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    for Elavon
{
    fn get_http_method(&self) -> hyperswitch_common_utils::request::Method {
        hyperswitch_common_utils::request::Method::Post
    }

    fn get_headers(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, hs_errors::ConnectorError> {
        let mut header = vec![(
            headers::CONTENT_TYPE.to_string(),
            self.common_get_content_type().to_string().into(),
        )];
        let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
        header.append(&mut api_key);
        Ok(header)
    }

    fn get_url(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<String, hs_errors::ConnectorError> {
        Ok(format!("{}processxml.do", req.resource_common_data.connectors.elavon.base_url))
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<Option<RequestContent>, hs_errors::ConnectorError> {
        let elavon_req = elavon::ElavonPsyncRequest::try_from(req)
            .change_context(hs_errors::ConnectorError::RequestEncodingFailed)
            .attach_printable("Failed to create ElavonPsyncRequest")?;

        Ok(Some(RequestContent::FormUrlEncoded(Box::new(struct_to_xml(
            &elavon_req,
        )?))))
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        event_builder: Option<&mut ConnectorEvent>,
        res: hs_types::Response,
    ) -> CustomResult<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, hs_errors::ConnectorError> {
        let response: elavon::ElavonPSyncResponse = res
            .response
            .parse_struct("RazorpayPaymentResponse")
            .change_context(hs_errors::ConnectorError::ResponseDeserializationFailed)?;

        with_response_body!(event_builder, response);

        let is_multiple_capture_sync = match data.request.sync_type {
            SyncRequestType::MultipleCaptureSync(_) => true,
            SyncRequestType::SinglePaymentSync => false,
        };
        RouterDataV2::foreign_try_from((
            response,
            data.clone(),
            res.status_code,
            data.request.capture_method,
            is_multiple_capture_sync,
            data.request.payment_method_type,
        ))
        .change_context(hs_errors::ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response_v2(
        &self,
        res: hs_types::Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, hs_errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl connector_integration_v2::ConnectorIntegrationV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse> for Elavon {
    fn get_headers(&self, _req: &RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>) -> CustomResult<Vec<(String, Maskable<String>)>, hs_errors::ConnectorError> { Err(hs_errors::ConnectorError::NotImplemented("CreateOrder get_headers".to_string()).into()) }
    fn get_url(&self, _req: &RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>) -> CustomResult<String, hs_errors::ConnectorError> { Err(hs_errors::ConnectorError::NotImplemented("CreateOrder get_url".to_string()).into()) }
    fn get_request_body(&self, _req: &RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>) -> CustomResult<Option<RequestContent>, hs_errors::ConnectorError> { Err(hs_errors::ConnectorError::NotImplemented("CreateOrder get_request_body".to_string()).into()) }
    fn handle_response_v2(&self, _data: &RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>, _event_builder: Option<&mut ConnectorEvent>, _res: hs_types::Response) -> CustomResult<RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>, hs_errors::ConnectorError> { Err(hs_errors::ConnectorError::NotImplemented("CreateOrder handle_response_v2".to_string()).into()) }
    fn get_error_response_v2(&self, res: hs_types::Response, event_builder: Option<&mut ConnectorEvent>) -> CustomResult<ErrorResponse, hs_errors::ConnectorError> { self.build_error_response(res, event_builder) }
}

impl connector_integration_v2::ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData> for Elavon {
    fn get_http_method(&self) -> hyperswitch_common_utils::request::Method {
        hyperswitch_common_utils::request::Method::Post
    }

    fn get_headers(
        &self,
        req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, hs_errors::ConnectorError> {
        let mut header = vec![(
            headers::CONTENT_TYPE.to_string(),
            self.common_get_content_type().to_string().into(),
        )];
        let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
        header.append(&mut api_key);
        Ok(header)
    }

    fn get_url(
        &self,
        req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
    ) -> CustomResult<String, hs_errors::ConnectorError> {
        Ok(format!("{}/processxml.asp", req.resource_common_data.connectors.elavon.base_url))
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
    ) -> CustomResult<Option<RequestContent>, hs_errors::ConnectorError> {
        let elavon_request = elavon::ElavonRSyncRequest::try_from(req)?;
        let form_payload = struct_to_xml(&elavon_request)?;

        Ok(Some(RequestContent::FormUrlEncoded(Box::new(form_payload))))
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        event_builder: Option<&mut ConnectorEvent>,
        res: hs_types::Response,
    ) -> CustomResult<RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>, hs_errors::ConnectorError> {
        let response_data = deserialize_xml_to_struct::<elavon::ElavonRSyncResponse>(&res.response)
            .change_context(hs_errors::ConnectorError::ResponseDeserializationFailed)?;
        with_response_body!(event_builder, response_data);

        RouterDataV2::foreign_try_from((
            response_data,
            data.clone(),
            res.status_code,
        ))
    }

    fn get_error_response_v2(
        &self,
        res: hs_types::Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, hs_errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl connector_integration_v2::ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData> for Elavon {
    fn get_headers(&self, _req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>) -> CustomResult<Vec<(String, Maskable<String>)>, hs_errors::ConnectorError> { Err(hs_errors::ConnectorError::NotImplemented("Void get_headers".to_string()).into()) }
    fn get_url(&self, _req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>) -> CustomResult<String, hs_errors::ConnectorError> { Err(hs_errors::ConnectorError::NotImplemented("Void get_url".to_string()).into()) }
    fn get_request_body(&self, _req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>) -> CustomResult<Option<RequestContent>, hs_errors::ConnectorError> { Err(hs_errors::ConnectorError::NotImplemented("Void get_request_body".to_string()).into()) }
    fn handle_response_v2(&self, _data: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>, _event_builder: Option<&mut ConnectorEvent>, _res: hs_types::Response) -> CustomResult<RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>, hs_errors::ConnectorError> { Err(hs_errors::ConnectorError::NotImplemented("Void handle_response_v2".to_string()).into()) }
    fn get_error_response_v2(&self, res: hs_types::Response, event_builder: Option<&mut ConnectorEvent>) -> CustomResult<ErrorResponse, hs_errors::ConnectorError> { self.build_error_response(res, event_builder) }
}

impl connector_integration_v2::ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData> for Elavon {
    fn get_headers(
        &self,
        req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, hs_errors::ConnectorError> {
        let mut header = vec![(
            headers::CONTENT_TYPE.to_string(),
            self.common_get_content_type().to_string().into(),
        )];
        let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
        header.append(&mut api_key);
        Ok(header)
    }

    fn get_url(
        &self,
        req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> CustomResult<String, hs_errors::ConnectorError> {
        Ok(format!("{}processxml.do", req.resource_common_data.connectors.elavon.base_url))
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> CustomResult<Option<RequestContent>, hs_errors::ConnectorError> {
        let amount = self.amount_converter.convert(
            req.request.minor_refund_amount,
            req.request.currency,
        ).change_context(hs_errors::ConnectorError::RequestEncodingFailed)
         .attach_printable("Failed to convert amount for Elavon Refund request")?;

        let elavon_router_data = elavon::ElavonRouterData::try_from((amount, req))
            .change_context(hs_errors::ConnectorError::RequestEncodingFailed)
            .attach_printable("Failed to create ElavonRouterData for refund request")?;

        let elavon_refund_req = elavon::ElavonRefundRequest::try_from(&elavon_router_data)
            .change_context(hs_errors::ConnectorError::RequestEncodingFailed)
            .attach_printable("Failed to create ElavonRefundRequest from ElavonRouterData")?;

        Ok(Some(RequestContent::FormUrlEncoded(Box::new(struct_to_xml(
            &elavon_refund_req,
        )?))))
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        event_builder: Option<&mut ConnectorEvent>,
        res: hs_types::Response,
    ) -> CustomResult<RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>, hs_errors::ConnectorError> {
        let response: elavon::ElavonPaymentsResponse =
            deserialize_xml_to_struct(&res.response)?;
            with_response_body!(event_builder, response);

            RouterDataV2::foreign_try_from((
                response.result,
                data.clone(),
                res.status_code,
            ))
            .change_context(hs_errors::ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response_v2(
        &self,
        res: hs_types::Response, 
        event_builder: Option<&mut ConnectorEvent>
    ) -> CustomResult<ErrorResponse, hs_errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
    
    fn get_5xx_error_response(
        &self,
        res: hs_types::Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, hs_errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl connector_integration_v2::ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData> for Elavon {
    fn get_headers(
        &self,
        _req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, hs_errors::ConnectorError> {
        Ok(vec![(
            headers::CONTENT_TYPE.to_string(),
            self.common_get_content_type().to_string().into(),
        )])
    }

    fn get_url(
        &self,
        req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
    ) -> CustomResult<String, hs_errors::ConnectorError> {
        Ok(format!("{}processxml.do", req.resource_common_data.connectors.elavon.base_url))
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
    ) -> CustomResult<Option<RequestContent>, hs_errors::ConnectorError> {
        let amount = self.amount_converter.convert(
            req.request.minor_amount_to_capture,
            req.request.currency,
        ).change_context(hs_errors::ConnectorError::RequestEncodingFailed)
         .attach_printable("Failed to convert amount for Elavon Capture request")?;

        let elavon_router_data = elavon::ElavonRouterData::try_from((amount, req))?;
        
        let elavon_req = elavon::ElavonCaptureRequest::try_from(&elavon_router_data)?;

        Ok(Some(RequestContent::FormUrlEncoded(Box::new(struct_to_xml(
            &elavon_req,
        )?))))
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        event_builder: Option<&mut ConnectorEvent>,
        res: hs_types::Response,
    ) -> CustomResult<RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>, hs_errors::ConnectorError> {
        let elavon_response: elavon::ElavonPaymentsResponse = deserialize_xml_to_struct(&res.response)
            .change_context(hs_errors::ConnectorError::ResponseDeserializationFailed)?;
        
        with_response_body!(event_builder, elavon_response);
        
        RouterDataV2::foreign_try_from((
            elavon_response.result,
            data.clone(),
            res.status_code,
        ))
        .change_context(hs_errors::ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response_v2(
        &self,
        res: hs_types::Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, hs_errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl connector_integration_v2::ConnectorIntegrationV2<SetupMandate, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData> for Elavon {
    fn get_headers(&self, _req: &RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData>) -> CustomResult<Vec<(String, Maskable<String>)>, hs_errors::ConnectorError> { Err(hs_errors::ConnectorError::NotImplemented("SetupMandate get_headers".to_string()).into()) }
    fn get_url(&self, _req: &RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData>) -> CustomResult<String, hs_errors::ConnectorError> { Err(hs_errors::ConnectorError::NotImplemented("SetupMandate get_url".to_string()).into()) }
    fn get_request_body(&self, _req: &RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData>) -> CustomResult<Option<RequestContent>, hs_errors::ConnectorError> { Err(hs_errors::ConnectorError::NotImplemented("SetupMandate get_request_body".to_string()).into()) }
    fn handle_response_v2(&self, _data: &RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData>, _event_builder: Option<&mut ConnectorEvent>, _res: hs_types::Response) -> CustomResult<RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData>, hs_errors::ConnectorError> { Err(hs_errors::ConnectorError::NotImplemented("SetupMandate handle_response_v2".to_string()).into()) }
    fn get_error_response_v2(&self, res: hs_types::Response, event_builder: Option<&mut ConnectorEvent>) -> CustomResult<ErrorResponse, hs_errors::ConnectorError> { self.build_error_response(res, event_builder) }
}

impl connector_integration_v2::ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData> for Elavon {
    fn get_headers(&self, _req: &RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>) -> CustomResult<Vec<(String, Maskable<String>)>, hs_errors::ConnectorError> { Err(hs_errors::ConnectorError::NotImplemented("Accept get_headers".to_string()).into()) }
    fn get_url(&self, _req: &RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>) -> CustomResult<String, hs_errors::ConnectorError> { Err(hs_errors::ConnectorError::NotImplemented("Accept get_url".to_string()).into()) }
    fn get_request_body(&self, _req: &RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>) -> CustomResult<Option<RequestContent>, hs_errors::ConnectorError> { Err(hs_errors::ConnectorError::NotImplemented("Accept get_request_body".to_string()).into()) }
    fn handle_response_v2(&self, _data: &RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>, _event_builder: Option<&mut ConnectorEvent>, _res: hs_types::Response) -> CustomResult<RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>, hs_errors::ConnectorError> { Err(hs_errors::ConnectorError::NotImplemented("Accept handle_response_v2".to_string()).into()) }
    fn get_error_response_v2(&self, res: hs_types::Response, event_builder: Option<&mut ConnectorEvent>) -> CustomResult<ErrorResponse, hs_errors::ConnectorError> { self.build_error_response(res, event_builder) }
}

impl connector_integration_v2::ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData> for Elavon {
    fn get_headers(&self, _req: &RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>) -> CustomResult<Vec<(String, Maskable<String>)>, hs_errors::ConnectorError> { Err(hs_errors::ConnectorError::NotImplemented("SubmitEvidence get_headers".to_string()).into()) }
    fn get_url(&self, _req: &RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>) -> CustomResult<String, hs_errors::ConnectorError> { Err(hs_errors::ConnectorError::NotImplemented("SubmitEvidence get_url".to_string()).into()) }
    fn get_request_body(&self, _req: &RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>) -> CustomResult<Option<RequestContent>, hs_errors::ConnectorError> { Err(hs_errors::ConnectorError::NotImplemented("SubmitEvidence get_request_body".to_string()).into()) }
    fn handle_response_v2(&self, _data: &RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>, _event_builder: Option<&mut ConnectorEvent>, _res: hs_types::Response) -> CustomResult<RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>, hs_errors::ConnectorError> { Err(hs_errors::ConnectorError::NotImplemented("SubmitEvidence handle_response_v2".to_string()).into()) }
    fn get_error_response_v2(&self, res: hs_types::Response, event_builder: Option<&mut ConnectorEvent>) -> CustomResult<ErrorResponse, hs_errors::ConnectorError> { self.build_error_response(res, event_builder) }
}