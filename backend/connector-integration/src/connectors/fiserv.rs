use domain_types::{
    connector_flow::{Authorize, Capture, PSync, Refund, Void, CreateOrder, SetupMandate, Accept, SubmitEvidence},
    connector_types::{
        ConnectorServiceTrait, PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData,
        PaymentsCaptureData, PaymentsResponseData, RefundFlowData, RefundsData,
        RefundsResponseData, PaymentsSyncData, PaymentCreateOrderData, PaymentCreateOrderResponse,
        SetupMandateRequestData, AcceptDisputeData, DisputeFlowData, DisputeResponseData, SubmitEvidenceData,
        ValidationTrait, PaymentAuthorizeV2, PaymentSyncV2, PaymentOrderCreate, PaymentVoidV2, IncomingWebhook, RefundV2, PaymentCapture, SetupMandateV2, AcceptDispute, RefundSyncV2, SubmitEvidenceV2
    },
};
use error_stack::ResultExt;
use hyperswitch_api_models::enums::{self as api_enums};
use hyperswitch_common_utils::{
    errors::CustomResult,
    request::RequestContent,
    types::{FloatMajorUnit, FloatMajorUnitForConnector, AmountConvertor},
    ext_traits::BytesExt,
};
use hyperswitch_connectors::utils; 

use hyperswitch_domain_models::{
    router_data::{ConnectorAuthType, ErrorResponse as DomainErrorResponse},
    router_data_v2::RouterDataV2,
};
use domain_types::connector_types::RefundSyncData as DomainRefundSyncData;
use domain_types::connector_types::ResponseId as ConnectorResponseId; 


use hyperswitch_interfaces::{
    api::ConnectorCommon,
    configs::Connectors as InterfaceConnectors, 
    consts::{NO_ERROR_CODE, NO_ERROR_MESSAGE},
    connector_integration_v2::ConnectorIntegrationV2,
    errors,
    events::connector_api_logs::ConnectorEvent,
    types::Response,
};
use hyperswitch_masking::{Maskable, Mask, PeekInterface, ExposeInterface}; // Added PeekInterface, ExposeInterface
use time::OffsetDateTime;
use uuid::Uuid; 
// Dependencies ring and base64 should already be in Cargo.toml
use ring::hmac; 
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD_ENGINE, Engine};


// Declare submodules directly in the main fiserv.rs file
pub mod transformers; 
// No need for: use self::transformers as fiserv_transformers; 
// it will be available as just `transformers` or `self::transformers`

// Local headers module
mod headers {
    pub const API_KEY: &str = "Api-Key"; 
    pub const CONTENT_TYPE: &str = "Content-Type";
    pub const TIMESTAMP: &str = "Timestamp";
    pub const CLIENT_REQUEST_ID: &str = "Client-Request-Id";
    pub const AUTH_TOKEN_TYPE: &str = "Auth-Token-Type"; 
    pub const AUTHORIZATION: &str = "Authorization"; 
}

#[derive(Clone)]
pub struct Fiserv {
    amount_converter: &'static (dyn AmountConvertor<Output = FloatMajorUnit> + Sync),
}

impl Fiserv {
    pub fn new() -> &'static Self {
        &Self {
            amount_converter: &FloatMajorUnitForConnector,
        }
    }

    fn generate_authorization_signature(
        &self,
        auth: &self::transformers::FiservAuthType, // Corrected path
        client_request_id: &str,
        payload_str: &str,
        timestamp_ms: i128,
    ) -> CustomResult<String, errors::ConnectorError> {
        let raw_signature = format!(
            "{}{}{}{}",
            auth.api_key.peek(),
            client_request_id,
            timestamp_ms,
            payload_str
        );

        let key = hmac::Key::new(hmac::HMAC_SHA256, auth.api_secret.clone().expose().as_bytes()); // Added clone()
        let tag = hmac::sign(&key, raw_signature.as_bytes());
        
        Ok(BASE64_STANDARD_ENGINE.encode(tag.as_ref()))
    }
    // Removed extraneous closing comment '*/'
}

impl ConnectorCommon for Fiserv {
    fn id(&self) -> &'static str {
        "fiserv"
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn base_url<'a>(&self, connectors: &'a InterfaceConnectors) -> &'a str {
        connectors.fiserv.base_url.as_ref() 
    }

    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth: self::transformers::FiservAuthType = self::transformers::FiservAuthType::try_from(auth_type)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        Ok(vec![(
            headers::API_KEY.to_string(), 
            auth.api_key.clone().into_masked().into(), 
        )])
    }

     fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<DomainErrorResponse, errors::ConnectorError> {
        let response: self::transformers::ErrorResponse = res
            .response
            .parse_struct("FiservErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        event_builder.map(|i| i.set_error_response_body(&response));
        
        let first_error_detail = response.error.as_ref().or(response.details.as_ref()).and_then(|e| e.first());

        Ok(DomainErrorResponse {
            status_code: res.status_code,
            code: first_error_detail.and_then(|e| e.code.clone()).unwrap_or(NO_ERROR_CODE.to_string()),
            message: first_error_detail.map_or(NO_ERROR_MESSAGE.to_string(), |e| e.message.clone()),
            reason: first_error_detail.and_then(|e| e.field.clone()),
            attempt_status: None,
            connector_transaction_id: None, 
        })
    }
}

impl ValidationTrait for Fiserv {}
impl ConnectorServiceTrait for Fiserv {}

impl PaymentAuthorizeV2 for Fiserv {}
impl ConnectorIntegrationV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>
    for Fiserv
{
    fn get_headers(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let timestamp_ms = OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000;
        let client_request_id = Uuid::new_v4().to_string();
        
        let auth_type_for_sig = self::transformers::FiservAuthType::try_from(&req.connector_auth_type)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;

        // Get the request body string for signature
        // Note: This requires get_request_body to be called, which might be tricky if it consumes req or needs specific state.
        // For simplicity, assuming get_request_body can be called here to get a representation.
        // A more robust way might be to serialize the already transformed request from a prior step if available.
        // However, the Hyperswitch reference generates the signature using the final request body string.
        let temp_request_body_for_sig = self.get_request_body(req)?;
        let payload_string_for_sig = match temp_request_body_for_sig {
            Some(RequestContent::Json(json_body)) => serde_json::to_string(&json_body)
                .change_context(errors::ConnectorError::RequestEncodingFailed)
                .attach_printable("Failed to serialize JSON request body for signature")?,
            Some(RequestContent::FormUrlEncoded(form_body)) => serde_urlencoded::to_string(&form_body)
                .change_context(errors::ConnectorError::RequestEncodingFailed)
                .attach_printable("Failed to serialize form request body for signature")?,
            None => "".to_string(), // Empty payload if no body
            _ => return Err(errors::ConnectorError::RequestEncodingFailed)
                .attach_printable("Unsupported request body type for signature generation")?,
        };
        
        let signature = self.generate_authorization_signature(
            &auth_type_for_sig,
            &client_request_id,
            &payload_string_for_sig, 
            timestamp_ms,
        )?;

        let mut http_headers = vec![
            (headers::CONTENT_TYPE.to_string(), self.common_get_content_type().to_string().into()),
            (headers::CLIENT_REQUEST_ID.to_string(), client_request_id.into()),
            (headers::TIMESTAMP.to_string(), timestamp_ms.to_string().into()),
            (headers::AUTH_TOKEN_TYPE.to_string(), "HMAC".to_string().into()), 
            (headers::AUTHORIZATION.to_string(), signature.into_masked()),
        ];
        
        let mut api_key_header = self.get_auth_header(&req.connector_auth_type)?;
        http_headers.append(&mut api_key_header);
        
        Ok(http_headers)
    }

    fn get_url(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(format!(
            "{}ch/payments/v1/charges", 
             req.resource_common_data.connectors.fiserv.base_url
        ))
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let converted_amount = utils::convert_amount(
            self.amount_converter,
            req.request.minor_amount,
            req.request.currency,
        )?;
        let fiserv_router_data = self::transformers::FiservRouterData::try_from((converted_amount, req))?;
        let connector_req =
            self::transformers::FiservPaymentsRequest::try_from(&fiserv_router_data)?;
        Ok(Some(RequestContent::Json(Box::new(connector_req))))
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>, errors::ConnectorError> {
        let http_status_code = res.status_code;
        let response_bytes = res.response;
        let fiserv_response: self::transformers::FiservPaymentsResponse = response_bytes
            .parse_struct("FiservPaymentsResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        event_builder.map(|i| i.set_response_body(&fiserv_response));
        
        let mut router_data_out = data.clone();
        let gateway_resp = &fiserv_response.gateway_response; 
        let status = api_enums::AttemptStatus::from(gateway_resp.transaction_state.clone()); 

        router_data_out.resource_common_data.status = status;
        
        let response_payload = PaymentsResponseData::TransactionResponse {
            resource_id: ConnectorResponseId::ConnectorTransactionId(
                gateway_resp.gateway_transaction_id.clone().unwrap_or_else(|| gateway_resp.transaction_processing_details.transaction_id.clone()),
            ),
            redirection_data: Box::new(None), 
            mandate_reference: Box::new(None), 
            connector_metadata: None, 
            network_txn_id: None, 
            connector_response_reference_id: Some(gateway_resp.transaction_processing_details.order_id.clone()),
            incremental_authorization_allowed: None, 
        };

        if status == api_enums::AttemptStatus::Failure || status == api_enums::AttemptStatus::Voided { 
             router_data_out.response = Err(DomainErrorResponse { 
                code: gateway_resp.transaction_processing_details.transaction_id.clone(), 
                message: format!("Payment status: {:?}", gateway_resp.transaction_state), 
                reason: None, 
                status_code: http_status_code,
                attempt_status: Some(status),
                connector_transaction_id: gateway_resp.gateway_transaction_id.clone(),
            });
        } else {
            router_data_out.response = Ok(response_payload);
        }
        Ok(router_data_out)
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<DomainErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

// Stub implementations for other flows
impl PaymentSyncV2 for Fiserv {}
impl ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData> for Fiserv {
    fn get_headers(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let timestamp_ms = OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000;
        let client_request_id = Uuid::new_v4().to_string();
        
        let auth_type_for_sig = self::transformers::FiservAuthType::try_from(&req.connector_auth_type)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;

        // For POST requests with a body, serialize the body for the signature.
        let request_body_for_sig = self.get_request_body(req)?;
        let payload_string_for_sig = match request_body_for_sig {
            Some(RequestContent::Json(json_body)) => serde_json::to_string(&json_body)
                .change_context(errors::ConnectorError::RequestEncodingFailed)
                .attach_printable("Failed to serialize JSON request body for PSync signature")?,
            Some(RequestContent::FormUrlEncoded(form_body)) => serde_urlencoded::to_string(&form_body)
                .change_context(errors::ConnectorError::RequestEncodingFailed)
                .attach_printable("Failed to serialize form request body for PSync signature")?,
            None => "".to_string(), // Should not happen for POST with body, but handle defensively
            _ => return Err(errors::ConnectorError::RequestEncodingFailed)
                .attach_printable("Unsupported request body type for PSync signature generation")?,
        };
        
        let signature = self.generate_authorization_signature(
            &auth_type_for_sig,
            &client_request_id,
            &payload_string_for_sig, 
            timestamp_ms,
        )?;

        let mut http_headers = vec![
            (headers::CONTENT_TYPE.to_string(), self.common_get_content_type().to_string().into()), // Added Content-Type for POST
            (headers::CLIENT_REQUEST_ID.to_string(), client_request_id.into()),
            (headers::TIMESTAMP.to_string(), timestamp_ms.to_string().into()),
            (headers::AUTH_TOKEN_TYPE.to_string(), "HMAC".to_string().into()), 
            (headers::AUTHORIZATION.to_string(), signature.into_masked()),
        ];
        
        let mut api_key_header = self.get_auth_header(&req.connector_auth_type)?;
        http_headers.append(&mut api_key_header);
        
        Ok(http_headers)
    }

    fn get_url(
        &self, 
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    ) -> CustomResult<String, errors::ConnectorError> { 
        // PSync is a POST request to /transaction-inquiry
        Ok(format!(
            "{}ch/payments/v1/transaction-inquiry",
             req.resource_common_data.connectors.fiserv.base_url
        )) 
    }
    
    // PSync is a POST request, it requires a body.
    fn get_request_body(
        &self, 
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> { 
        let connector_req = self::transformers::FiservSyncRequest::try_from(req)?;
        Ok(Some(RequestContent::Json(Box::new(connector_req))))
    }

    fn handle_response_v2(
        &self, 
        data: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, 
        event_builder: Option<&mut ConnectorEvent>, 
        res: Response
    ) -> CustomResult<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, errors::ConnectorError> { 
        let response_bytes = res.response;
        
        // Fiserv's transaction inquiry returns an array of transactions, even if only one matches.
        // We expect FiservSyncResponse which contains Vec<FiservPaymentsResponse>.
        let fiserv_sync_response: self::transformers::FiservSyncResponse = response_bytes
            .parse_struct("FiservSyncResponse") 
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        event_builder.map(|i| i.set_response_body(&fiserv_sync_response));
        
        let mut router_data_out = data.clone();

        // Get the first transaction from the response array.
        // If the array is empty, it means the transaction was not found or an error occurred that didn't fit the FiservErrorResponse struct.
        let fiserv_payment_response = fiserv_sync_response.sync_responses.first()
            .ok_or_else(|| errors::ConnectorError::ResponseHandlingFailed)
            .attach_printable("Fiserv PSync response array was empty")?;

        let gateway_resp = &fiserv_payment_response.gateway_response; 
        let status = api_enums::AttemptStatus::from(gateway_resp.transaction_state.clone()); 

        router_data_out.resource_common_data.status = status;
        
        let response_payload = PaymentsResponseData::TransactionResponse {
            resource_id: ConnectorResponseId::ConnectorTransactionId(
                 gateway_resp.gateway_transaction_id.clone().unwrap_or_else(|| gateway_resp.transaction_processing_details.transaction_id.clone()),
            ),
            redirection_data: Box::new(None), 
            mandate_reference: Box::new(None), 
            connector_metadata: None, 
            network_txn_id: None, 
            connector_response_reference_id: Some(gateway_resp.transaction_processing_details.order_id.clone()),
            incremental_authorization_allowed: None, 
        };
        
        router_data_out.response = Ok(response_payload);
        
        Ok(router_data_out)
    }

    fn get_error_response_v2(&self, res: Response, event_builder: Option<&mut ConnectorEvent>) -> CustomResult<DomainErrorResponse, errors::ConnectorError> { 
        // Attempt to parse as FiservErrorResponse first
        // If that fails, it might be an unexpected structure or an empty body for certain errors.
        // The build_error_response handles FiservErrorResponse.
        // If parsing FiservErrorResponse fails, it will return a generic deserialization error.
        self.build_error_response(res, event_builder) 
    }
}

#[cfg(test)]
pub mod test;

impl PaymentOrderCreate for Fiserv {}
impl ConnectorIntegrationV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse> for Fiserv {
     fn get_headers(&self, _req: &RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> { Err(errors::ConnectorError::NotImplemented("get_headers for CreateOrder".to_string()).into()) }
    fn get_url(&self, _req: &RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>) -> CustomResult<String, errors::ConnectorError> { Err(errors::ConnectorError::NotImplemented("get_url for CreateOrder".to_string()).into()) }
    fn get_request_body(&self, _req: &RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>) -> CustomResult<Option<RequestContent>, errors::ConnectorError> { Err(errors::ConnectorError::NotImplemented("get_request_body for CreateOrder".to_string()).into()) }
    fn handle_response_v2(&self, _data: &RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>, _event_builder: Option<&mut ConnectorEvent>, _res: Response) -> CustomResult<RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>, errors::ConnectorError> { Err(errors::ConnectorError::NotImplemented("handle_response_v2 for CreateOrder".to_string()).into()) }
    fn get_error_response_v2(&self, res: Response, event_builder: Option<&mut ConnectorEvent>) -> CustomResult<DomainErrorResponse, errors::ConnectorError> { self.build_error_response(res, event_builder) }
}

impl PaymentVoidV2 for Fiserv {}
impl ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData> for Fiserv {
    fn get_headers(&self, _req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> { Err(errors::ConnectorError::NotImplemented("get_headers for Void".to_string()).into()) }
    fn get_url(&self, req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>) -> CustomResult<String, errors::ConnectorError> { Ok(format!("{}ch/payments/v1/cancels", req.resource_common_data.connectors.fiserv.base_url)) } 
    fn get_request_body(&self, _req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>) -> CustomResult<Option<RequestContent>, errors::ConnectorError> { Err(errors::ConnectorError::NotImplemented("get_request_body for Void".to_string()).into()) }
    fn handle_response_v2(&self, _data: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>, _event_builder: Option<&mut ConnectorEvent>, _res: Response) -> CustomResult<RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>, errors::ConnectorError> { Err(errors::ConnectorError::NotImplemented("handle_response_v2 for Void".to_string()).into()) }
    fn get_error_response_v2(&self, res: Response, event_builder: Option<&mut ConnectorEvent>) -> CustomResult<DomainErrorResponse, errors::ConnectorError> { self.build_error_response(res, event_builder) }
}

impl IncomingWebhook for Fiserv {} 

impl RefundV2 for Fiserv {}
// Reverted to RefundFlowData to match the RefundV2 trait definition
impl ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData> for Fiserv { 
    fn get_headers(
        &self, 
        req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let timestamp_ms = OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000;
        let client_request_id = Uuid::new_v4().to_string();
        
        let auth_type_for_sig = self::transformers::FiservAuthType::try_from(&req.connector_auth_type)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;

        let refund_request_payload = self.get_request_body(req)?; // Get the body first
        let payload_string_for_sig = match refund_request_payload {
            Some(RequestContent::Json(json_body)) => serde_json::to_string(&json_body)
                .change_context(errors::ConnectorError::RequestEncodingFailed)
                .attach_printable("Failed to serialize JSON refund request body for signature")?,
            None => "".to_string(), // Should not happen for refund POST
            _ => return Err(errors::ConnectorError::RequestEncodingFailed)
                .attach_printable("Unsupported refund request body type for signature generation")?,
        };
        
        let signature = self.generate_authorization_signature(
            &auth_type_for_sig,
            &client_request_id,
            &payload_string_for_sig, 
            timestamp_ms,
        )?;

        let mut http_headers = vec![
            (headers::CONTENT_TYPE.to_string(), self.common_get_content_type().to_string().into()),
            (headers::CLIENT_REQUEST_ID.to_string(), client_request_id.into()),
            (headers::TIMESTAMP.to_string(), timestamp_ms.to_string().into()),
            (headers::AUTH_TOKEN_TYPE.to_string(), "HMAC".to_string().into()), 
            (headers::AUTHORIZATION.to_string(), signature.into_masked()),
        ];
        
        let mut api_key_header = self.get_auth_header(&req.connector_auth_type)?;
        http_headers.append(&mut api_key_header);
        
        Ok(http_headers)
    }

    fn get_url(&self, req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>) -> CustomResult<String, errors::ConnectorError> { 
        Ok(format!("{}ch/payments/v1/refunds", req.resource_common_data.connectors.fiserv.base_url)) 
    } 
    
    fn get_request_body(
        &self, 
        req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> { 
        let converted_amount = utils::convert_amount(
            self.amount_converter,
            req.request.minor_refund_amount, // Use minor_refund_amount
            req.request.currency,
        )?;

        // Need a FiservRefundRouterData or similar if the TryFrom for FiservRefundRequest expects it
        // For now, assuming FiservRefundRequest can be built directly or via a simple wrapper
        let fiserv_router_data = self::transformers::FiservRefundRouterData::try_from((converted_amount, req))?;


        let connector_req = self::transformers::FiservRefundRequest::try_from(&fiserv_router_data)?;
        Ok(Some(RequestContent::Json(Box::new(connector_req))))
    }

    fn handle_response_v2(
        &self, 
        data: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>, 
        event_builder: Option<&mut ConnectorEvent>, 
        res: Response
    ) -> CustomResult<RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>, errors::ConnectorError> { 
        // Assuming Fiserv refund response is similar to FiservPaymentsResponse for now
        // This will likely need adjustment based on actual Fiserv API for refunds.
        let response_bytes = res.response;
        let fiserv_response: self::transformers::RefundResponse = response_bytes // Potentially a new struct like FiservRefundOpResponse
            .parse_struct("FiservRefundResponse") 
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        event_builder.map(|i| i.set_response_body(&fiserv_response));
        
        let mut router_data_out = data.clone(); // router_data_out is RouterDataV2<Refund, RefundFlowData, ...>
        let gateway_resp = &fiserv_response.gateway_response; 
        
        let internal_refund_status = api_enums::RefundStatus::from(gateway_resp.transaction_state.clone());

        router_data_out.resource_common_data.status = internal_refund_status; // Update RefundFlowData status
        
        let response_payload = RefundsResponseData {
            connector_refund_id: gateway_resp.gateway_transaction_id.clone().unwrap_or_else(|| gateway_resp.transaction_processing_details.transaction_id.clone()),
            refund_status: internal_refund_status,
        };
        
        if internal_refund_status == api_enums::RefundStatus::Failure || internal_refund_status == api_enums::RefundStatus::TransactionFailure {
            router_data_out.response = Err(DomainErrorResponse { 
                code: gateway_resp.transaction_processing_details.transaction_id.clone(), 
                message: format!("Refund status: {:?}", gateway_resp.transaction_state), 
                reason: None, 
                status_code: res.status_code,
                attempt_status: None, 
                connector_transaction_id: gateway_resp.gateway_transaction_id.clone(),
            });
        } else {
            router_data_out.response = Ok(response_payload);
        }
        
        Ok(router_data_out)
    }

    fn get_error_response_v2(&self, res: Response, event_builder: Option<&mut ConnectorEvent>) -> CustomResult<DomainErrorResponse, errors::ConnectorError> { 
        self.build_error_response(res, event_builder) 
    }
}

impl PaymentCapture for Fiserv {}
impl ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData> for Fiserv {
    fn get_headers(
        &self, 
        req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let timestamp_ms = OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000;
        let client_request_id = Uuid::new_v4().to_string();
        
        let auth_type_for_sig = self::transformers::FiservAuthType::try_from(&req.connector_auth_type)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;

        let request_body_for_sig = self.get_request_body(req)?;
        let payload_string_for_sig = match request_body_for_sig {
            Some(RequestContent::Json(json_body)) => serde_json::to_string(&json_body)
                .change_context(errors::ConnectorError::RequestEncodingFailed)
                .attach_printable("Failed to serialize JSON request body for Capture signature")?,
            Some(RequestContent::FormUrlEncoded(form_body)) => serde_urlencoded::to_string(&form_body)
                .change_context(errors::ConnectorError::RequestEncodingFailed)
                .attach_printable("Failed to serialize form request body for Capture signature")?,
            None => "".to_string(),
            _ => return Err(errors::ConnectorError::RequestEncodingFailed)
                .attach_printable("Unsupported request body type for Capture signature generation")?,
        };
        
        let signature = self.generate_authorization_signature(
            &auth_type_for_sig,
            &client_request_id,
            &payload_string_for_sig, 
            timestamp_ms,
        )?;

        let mut http_headers = vec![
            (headers::CONTENT_TYPE.to_string(), self.common_get_content_type().to_string().into()),
            (headers::CLIENT_REQUEST_ID.to_string(), client_request_id.into()),
            (headers::TIMESTAMP.to_string(), timestamp_ms.to_string().into()),
            (headers::AUTH_TOKEN_TYPE.to_string(), "HMAC".to_string().into()), 
            (headers::AUTHORIZATION.to_string(), signature.into_masked()),
        ];
        
        let mut api_key_header = self.get_auth_header(&req.connector_auth_type)?;
        http_headers.append(&mut api_key_header);
        
        Ok(http_headers)
    }

    fn get_url(
        &self, 
        req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
    ) -> CustomResult<String, errors::ConnectorError> { 
        // Capture is typically a POST to the same endpoint as authorize, but with a reference to the original auth.
        // The Fiserv API uses POST /charges for captures as well, with specific fields in the body.
        Ok(format!("{}ch/payments/v1/charges", req.resource_common_data.connectors.fiserv.base_url)) 
    } 

    fn get_request_body(
        &self, 
        req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> { 
        let converted_amount = utils::convert_amount(
            self.amount_converter,
            req.request.minor_amount_to_capture, // Use minor_amount_to_capture
            req.request.currency,
        )?;
        // Ensure FiservCaptureRouterData is correctly defined and used if needed by transformers
        let fiserv_router_data = self::transformers::FiservCaptureRouterData::try_from((converted_amount, req))?;
        let connector_req = self::transformers::FiservCaptureRequest::try_from(&fiserv_router_data)?;
        Ok(Some(RequestContent::Json(Box::new(connector_req))))
    }

    fn handle_response_v2(
        &self, 
        data: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>, 
        event_builder: Option<&mut ConnectorEvent>, 
        res: Response
    ) -> CustomResult<RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>, errors::ConnectorError> { 
        let http_status_code = res.status_code;
        let response_bytes = res.response;
        let fiserv_response: self::transformers::FiservPaymentsResponse = response_bytes
            .parse_struct("FiservPaymentsResponse (Capture)")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        event_builder.map(|i| i.set_response_body(&fiserv_response));
        
        let mut router_data_out = data.clone();
        let gateway_resp = &fiserv_response.gateway_response; 
        let status = api_enums::AttemptStatus::from(gateway_resp.transaction_state.clone()); 

        router_data_out.resource_common_data.status = status;
        
        let response_payload = PaymentsResponseData::TransactionResponse {
            resource_id: ConnectorResponseId::ConnectorTransactionId(
                gateway_resp.gateway_transaction_id.clone().unwrap_or_else(|| gateway_resp.transaction_processing_details.transaction_id.clone()),
            ),
            redirection_data: Box::new(None), 
            mandate_reference: Box::new(None), 
            connector_metadata: None, 
            network_txn_id: None, 
            connector_response_reference_id: Some(gateway_resp.transaction_processing_details.order_id.clone()),
            incremental_authorization_allowed: None, 
        };

        if status == api_enums::AttemptStatus::Failure || status == api_enums::AttemptStatus::Voided {
             router_data_out.response = Err(DomainErrorResponse { 
                code: gateway_resp.transaction_processing_details.transaction_id.clone(), 
                message: format!("Capture status: {:?}", gateway_resp.transaction_state), 
                reason: None, 
                status_code: http_status_code,
                attempt_status: Some(status),
                connector_transaction_id: gateway_resp.gateway_transaction_id.clone(),
            });
        } else {
            router_data_out.response = Ok(response_payload);
        }
        Ok(router_data_out)
    }

    fn get_error_response_v2(&self, res: Response, event_builder: Option<&mut ConnectorEvent>) -> CustomResult<DomainErrorResponse, errors::ConnectorError> { 
        self.build_error_response(res, event_builder) 
    }
}

impl SetupMandateV2 for Fiserv {}
impl ConnectorIntegrationV2<SetupMandate, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData> for Fiserv {
    fn get_headers(&self, _req: &RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData>) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> { Err(errors::ConnectorError::NotImplemented("get_headers for SetupMandate".to_string()).into()) }
    fn get_url(&self, _req: &RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData>) -> CustomResult<String, errors::ConnectorError> { Err(errors::ConnectorError::NotImplemented("get_url for SetupMandate".to_string()).into()) }
    fn get_request_body(&self, _req: &RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData>) -> CustomResult<Option<RequestContent>, errors::ConnectorError> { Err(errors::ConnectorError::NotImplemented("get_request_body for SetupMandate".to_string()).into()) }
    fn handle_response_v2(&self, _data: &RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData>, _event_builder: Option<&mut ConnectorEvent>, _res: Response) -> CustomResult<RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData>, errors::ConnectorError> { Err(errors::ConnectorError::NotImplemented("handle_response_v2 for SetupMandate".to_string()).into()) }
    fn get_error_response_v2(&self, res: Response, event_builder: Option<&mut ConnectorEvent>) -> CustomResult<DomainErrorResponse, errors::ConnectorError> { self.build_error_response(res, event_builder) }
}

impl AcceptDispute for Fiserv {}
impl ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData> for Fiserv {
    fn get_headers(&self, _req: &RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> { Err(errors::ConnectorError::NotImplemented("get_headers for AcceptDispute".to_string()).into()) }
    fn get_url(&self, _req: &RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>) -> CustomResult<String, errors::ConnectorError> { Err(errors::ConnectorError::NotImplemented("get_url for AcceptDispute".to_string()).into()) }
    fn get_request_body(&self, _req: &RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>) -> CustomResult<Option<RequestContent>, errors::ConnectorError> { Err(errors::ConnectorError::NotImplemented("get_request_body for AcceptDispute".to_string()).into()) }
    fn handle_response_v2(&self, _data: &RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>, _event_builder: Option<&mut ConnectorEvent>, _res: Response) -> CustomResult<RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>, errors::ConnectorError> { Err(errors::ConnectorError::NotImplemented("handle_response_v2 for AcceptDispute".to_string()).into()) }
    fn get_error_response_v2(&self, res: Response, event_builder: Option<&mut ConnectorEvent>) -> CustomResult<DomainErrorResponse, errors::ConnectorError> { self.build_error_response(res, event_builder) }
}

impl RefundSyncV2 for Fiserv {}
impl ConnectorIntegrationV2<domain_types::connector_flow::RSync, RefundFlowData, DomainRefundSyncData, RefundsResponseData> for Fiserv {
    fn get_headers(
        &self, 
        req: &RouterDataV2<domain_types::connector_flow::RSync, RefundFlowData, DomainRefundSyncData, RefundsResponseData>
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let timestamp_ms = OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000;
        let client_request_id = Uuid::new_v4().to_string();
        
        let auth_type_for_sig = self::transformers::FiservAuthType::try_from(&req.connector_auth_type)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;

        let request_body_for_sig = self.get_request_body(req)?;
        let payload_string_for_sig = match request_body_for_sig {
            Some(RequestContent::Json(json_body)) => serde_json::to_string(&json_body)
                .change_context(errors::ConnectorError::RequestEncodingFailed)
                .attach_printable("Failed to serialize JSON request body for RSync signature")?,
            Some(RequestContent::FormUrlEncoded(form_body)) => serde_urlencoded::to_string(&form_body)
                .change_context(errors::ConnectorError::RequestEncodingFailed)
                .attach_printable("Failed to serialize form request body for RSync signature")?,
            None => "".to_string(),
            _ => return Err(errors::ConnectorError::RequestEncodingFailed)
                .attach_printable("Unsupported request body type for RSync signature generation")?,
        };
        
        let signature = self.generate_authorization_signature(
            &auth_type_for_sig,
            &client_request_id,
            &payload_string_for_sig, 
            timestamp_ms,
        )?;

        let mut http_headers = vec![
            (headers::CONTENT_TYPE.to_string(), self.common_get_content_type().to_string().into()),
            (headers::CLIENT_REQUEST_ID.to_string(), client_request_id.into()),
            (headers::TIMESTAMP.to_string(), timestamp_ms.to_string().into()),
            (headers::AUTH_TOKEN_TYPE.to_string(), "HMAC".to_string().into()), 
            (headers::AUTHORIZATION.to_string(), signature.into_masked()),
        ];
        
        let mut api_key_header = self.get_auth_header(&req.connector_auth_type)?;
        http_headers.append(&mut api_key_header);
        
        Ok(http_headers)
    }

    fn get_url(
        &self, 
        req: &RouterDataV2<domain_types::connector_flow::RSync, RefundFlowData, DomainRefundSyncData, RefundsResponseData>
    ) -> CustomResult<String, errors::ConnectorError> { 
        Ok(format!("{}ch/payments/v1/transaction-inquiry", req.resource_common_data.connectors.fiserv.base_url)) 
    } 

    fn get_request_body(
        &self, 
        req: &RouterDataV2<domain_types::connector_flow::RSync, RefundFlowData, DomainRefundSyncData, RefundsResponseData>
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> { 
        let connector_req = self::transformers::FiservSyncRequest::try_from(req)?;
        Ok(Some(RequestContent::Json(Box::new(connector_req))))
    }

    fn handle_response_v2(
        &self, 
        data: &RouterDataV2<domain_types::connector_flow::RSync, RefundFlowData, DomainRefundSyncData, RefundsResponseData>, 
        event_builder: Option<&mut ConnectorEvent>, 
        res: Response
    ) -> CustomResult<RouterDataV2<domain_types::connector_flow::RSync, RefundFlowData, DomainRefundSyncData, RefundsResponseData>, errors::ConnectorError> { 
        let response_bytes = res.response;
        let fiserv_sync_response: self::transformers::FiservSyncResponse = response_bytes
            .parse_struct("FiservSyncResponse (RSync)") 
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        event_builder.map(|i| i.set_response_body(&fiserv_sync_response));
        
        let mut router_data_out = data.clone();

        let fiserv_payment_response = fiserv_sync_response.sync_responses.first()
            .ok_or_else(|| errors::ConnectorError::ResponseHandlingFailed)
            .attach_printable("Fiserv RSync response array was empty")?;

        let gateway_resp = &fiserv_payment_response.gateway_response; 
        // For RSync, we map Fiserv's transaction_state to our internal RefundStatus
        let refund_status = api_enums::RefundStatus::from(gateway_resp.transaction_state.clone()); 

        // The status in resource_common_data for RSync should reflect the refund status
        router_data_out.resource_common_data.status = refund_status; 
        
        let response_payload = RefundsResponseData {
            // The connector_refund_id in the response should be the one we are querying.
            // Fiserv's transaction_id in this context refers to the refund transaction.
            connector_refund_id: gateway_resp.gateway_transaction_id.clone().unwrap_or_else(|| gateway_resp.transaction_processing_details.transaction_id.clone()),
            refund_status,
        };
        
        router_data_out.response = Ok(response_payload);
        
        Ok(router_data_out)
    }

    fn get_error_response_v2(&self, res: Response, event_builder: Option<&mut ConnectorEvent>) -> CustomResult<DomainErrorResponse, errors::ConnectorError> { 
        self.build_error_response(res, event_builder) 
    }
}

impl SubmitEvidenceV2 for Fiserv {}
impl ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData> for Fiserv {
    fn get_headers(&self, _req: &RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> { Err(errors::ConnectorError::NotImplemented("get_headers for SubmitEvidence".to_string()).into()) }
    fn get_url(&self, _req: &RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>) -> CustomResult<String, errors::ConnectorError> { Err(errors::ConnectorError::NotImplemented("get_url for SubmitEvidence".to_string()).into()) }
    fn get_request_body(&self, _req: &RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>) -> CustomResult<Option<RequestContent>, errors::ConnectorError> { Err(errors::ConnectorError::NotImplemented("get_request_body for SubmitEvidence".to_string()).into()) }
    fn handle_response_v2(&self, _data: &RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>, _event_builder: Option<&mut ConnectorEvent>, _res: Response) -> CustomResult<RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>, errors::ConnectorError> { Err(errors::ConnectorError::NotImplemented("handle_response_v2 for SubmitEvidence".to_string()).into()) }
    fn get_error_response_v2(&self, res: Response, event_builder: Option<&mut ConnectorEvent>) -> CustomResult<DomainErrorResponse, errors::ConnectorError> { self.build_error_response(res, event_builder) }
}
