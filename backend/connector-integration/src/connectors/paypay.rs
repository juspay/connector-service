// pub mod test;
pub mod transformers;
use crate::{with_error_response_body, with_response_body};
use domain_types::{
    connector_flow::{
        Accept, Authorize, Capture, CreateOrder, DefendDispute, PSync, RSync, Refund, SetupMandate,
        SubmitEvidence, Void,
    },
    connector_types::{
        AcceptDispute, AcceptDisputeData, ConnectorServiceTrait, DisputeDefend, DisputeDefendData,
        DisputeFlowData, DisputeResponseData, IncomingWebhook, PaymentAuthorizeV2, PaymentCapture,
        PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData, PaymentOrderCreate,
        PaymentSyncV2, PaymentVoidData, PaymentVoidV2, PaymentsAuthorizeData, PaymentsCaptureData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundSyncData, RefundSyncV2,
        RefundV2, RefundsData, RefundsResponseData, SetupMandateRequestData, SetupMandateV2,
        SubmitEvidenceData, SubmitEvidenceV2, ValidationTrait,
    },
};

use base64::engine::general_purpose;
use base64::Engine;
use error_stack::{report, ResultExt};
use hmac::{Hmac, Mac};
use hyperswitch_common_utils::{
    errors::CustomResult,
    ext_traits::ByteSliceExt,
    request::{Method, RequestContent},
    types::{AmountConvertor, MinorUnit},
};
use hyperswitch_domain_models::{
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
};
use hyperswitch_interfaces::{
    api::{self, ConnectorCommon},
    configs::Connectors,
    connector_integration_v2::ConnectorIntegrationV2,
    errors,
    events::connector_api_logs::ConnectorEvent,
    types::Response,
};
use hyperswitch_masking::{Mask, Maskable, PeekInterface};
use md5;
use serde_json::json;
use sha2::Sha256;
use transformers::ForeignTryFrom;
use transformers::{self as paypay};

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub struct Paypay {
    #[allow(dead_code)]
    pub(crate) amount_converter: &'static (dyn AmountConvertor<Output = MinorUnit> + Sync),
}

impl ValidationTrait for Paypay {
    fn should_do_order_create(&self) -> bool {
        false
    }
}

impl ConnectorServiceTrait for Paypay {}
impl PaymentAuthorizeV2 for Paypay {}
impl PaymentSyncV2 for Paypay {}
impl PaymentOrderCreate for Paypay {}
impl PaymentVoidV2 for Paypay {}
impl RefundSyncV2 for Paypay {}
impl RefundV2 for Paypay {}
impl PaymentCapture for Paypay {}
impl SetupMandateV2 for Paypay {}
impl AcceptDispute for Paypay {}
impl SubmitEvidenceV2 for Paypay {}
impl DisputeDefend for Paypay {}
impl IncomingWebhook for Paypay {}

impl Paypay {
    pub const fn new() -> &'static Self {
        &Self {
            amount_converter: &hyperswitch_common_utils::types::MinorUnitForConnector,
        }
    }

    pub fn create_auth_header(
        method: &str,
        path: &str,
        body: &str,
        epoch: &str,
        nonce: &str,
        client_id: &str,
        client_secret: &str,
    ) -> CustomResult<String, errors::ConnectorError> {
        let jsonified = body.to_string();
        let isempty = ["undefined", "null", "", "{}"];

        let (content_type, payload_hash) = if isempty.contains(&jsonified.as_str()) {
            ("empty".to_string(), "empty".to_string())
        } else {
            let content_type = "application/json".to_string();
            let combined = format!("{}{}", content_type, jsonified);
            let digest = md5::compute(combined.as_bytes());
            let payload_hash = general_purpose::STANDARD.encode(digest.0);
            (content_type, payload_hash)
        };

        let signature_raw_data = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            path, method, nonce, epoch, content_type, payload_hash
        );

        let mut mac = HmacSha256::new_from_slice(client_secret.as_bytes())
            .map_err(|_| errors::ConnectorError::RequestEncodingFailed)?;
        mac.update(signature_raw_data.as_bytes());
        let hashed = mac.finalize().into_bytes();
        let hashed64 = general_purpose::STANDARD.encode(hashed);

        let header = format!(
            "{}:{}:{}:{}:{}",
            client_id, hashed64, nonce, epoch, payload_hash
        );

        let auth_header = format!("hmac OPA-Auth:{}", header);

        Ok(auth_header)
    }

    fn extract_body_string_and_value(
        body: &Option<RequestContent>,
    ) -> CustomResult<String, errors::ConnectorError> {
        match body {
            Some(RequestContent::Json(json_body)) => {
                // Serialize the struct into a JSON string
                let body_json_string = serde_json::to_string(&**json_body)
                    .map_err(|_| errors::ConnectorError::RequestEncodingFailed)?;

                Ok(body_json_string)
            }
            Some(other) => {
                let fallback = json!({
                    "note": "Non-JSON request content",
                    "raw": format!("{:?}", other),
                });

                Ok(fallback.to_string())
            }
            None => Ok("null".to_string()),
        }
    }

    fn extract_path_from_url(full_url: &str) -> CustomResult<&str, errors::ConnectorError> {
        full_url
            .find("/v")
            .map(|start| &full_url[start..])
            .ok_or_else(|| report!(errors::ConnectorError::RequestEncodingFailed))
    }
}

impl ConnectorCommon for Paypay {
    fn id(&self) -> &'static str {
        "paypay"
    }
    fn get_currency_unit(&self) -> api::CurrencyUnit {
        api::CurrencyUnit::Minor
    }
    fn get_auth_header(
        &self,
        _auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        Ok(vec![])
    }

    fn base_url(&self, _connectors: &Connectors) -> &'static str {
        "https://stg-api.sandbox.paypay.ne.jp/"
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: paypay::PaypayErrorResponse = res
            .response
            .parse_struct("ErrorResponse")
            .map_err(|_| errors::ConnectorError::ResponseDeserializationFailed)?;

        with_error_response_body!(event_builder, response);

        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response.error.code,
            message: response.error.description,
            reason: Some(response.error.reason),
            attempt_status: None,
            connector_transaction_id: None,
        })
    }
}

impl ConnectorIntegrationV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>
    for Paypay
{
    fn get_http_method(&self) -> Method {
        Method::Post
    }

    fn get_headers(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth = paypay::PaypayAuthType::try_from(&req.connector_auth_type)
            .map_err(|_| errors::ConnectorError::FailedToObtainAuthType)?;
        let timestamp = (chrono::Utc::now().timestamp() as u64).to_string();
        let nonce = uuid::Uuid::new_v4().to_string();
        let merchant_id = auth.merchant_id.peek();
        let body = self.get_request_body(req)?;
        let body_string = Self::extract_body_string_and_value(&body)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;
        // Get the full URL and use the complete path for authorization
        let url = self.get_url(req)?;

        let path = Self::extract_path_from_url(&url)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;
        // Get the HTTP method dynamically
        let method = <Paypay as ConnectorIntegrationV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData,
            PaymentsResponseData,
        >>::get_http_method(self);
        // Generate authorization header
        let auth_header = Self::create_auth_header(
            &method.to_string(),
            path,
            &body_string,
            &timestamp,
            &nonce,
            auth.key_id.peek(),
            auth.secret_key.peek(),
        )
        .map_err(|_| errors::ConnectorError::RequestEncodingFailed)?;
        let header = vec![
            (
                "X-ASSUME-MERCHANT".to_string(),
                merchant_id.to_string().into(),
            ),
            ("Authorization".to_string(), auth_header.into_masked()),
        ];

        Ok(header)
    }

    fn get_url(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(format!(
            "{}v2/payments",
            req.resource_common_data.connectors.paypay.base_url
        ))
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let paypay_router_data = paypay::PaypayRouterData {
            amount: hyperswitch_common_utils::types::MinorUnit::new(req.request.amount),
            router_data: req,
        };
        let connector_req = paypay::PaypayPaymentRequest::try_from(&paypay_router_data)?;
        Ok(Some(RequestContent::Json(Box::new(connector_req))))
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
        let response: paypay::PaypayPaymentResponse = res
            .response
            .parse_struct("PaypayPaymentResponse")
            .map_err(|_| errors::ConnectorError::ResponseDeserializationFailed)?;

        with_response_body!(event_builder, response);

        RouterDataV2::foreign_try_from((
            response,
            data.clone(),
            res.status_code,
            data.request.capture_method,
            false,
            data.request.payment_method_type,
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

// Empty implementations for unimplemented flows
impl ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    for Paypay
{
    fn get_http_method(&self) -> Method {
        Method::Get
    }

    fn get_headers(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth = paypay::PaypayAuthType::try_from(&req.connector_auth_type)
            .map_err(|_| errors::ConnectorError::FailedToObtainAuthType)?;
        let timestamp = (chrono::Utc::now().timestamp() as u64).to_string();
        let nonce = uuid::Uuid::new_v4().to_string();
        let merchant_id = auth.merchant_id.peek();
        let body = self.get_request_body(req)?;
        let body_string = Self::extract_body_string_and_value(&body)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;
        // Get the full URL and use the complete path for authorization
        let url = self.get_url(req)?;
        let path = Self::extract_path_from_url(&url)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;
        // Get the HTTP method dynamically
        let method = <Paypay as ConnectorIntegrationV2<
            PSync,
            PaymentFlowData,
            PaymentsSyncData,
            PaymentsResponseData,
        >>::get_http_method(self);
        // Generate authorization header
        let auth_header = Self::create_auth_header(
            &method.to_string(),
            path,
            &body_string,
            &timestamp,
            &nonce,
            auth.key_id.peek(),
            auth.secret_key.peek(),
        )
        .map_err(|_| errors::ConnectorError::RequestEncodingFailed)?;

        let header = vec![
            (
                "X-ASSUME-MERCHANT".to_string(),
                merchant_id.to_string().into(),
            ),
            ("Authorization".to_string(), auth_header.into_masked()),
        ];
        Ok(header)
    }

    fn get_url(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        let merchant_payment_id = req
            .request
            .connector_transaction_id
            .get_connector_transaction_id()
            .change_context(errors::ConnectorError::MissingRequiredField {
                field_name: "merchant_payment_id",
            })?
            .to_string();
        Ok(format!(
            "{}v2/payments/{}",
            req.resource_common_data.connectors.paypay.base_url, merchant_payment_id
        ))
    }

    fn get_request_body(
        &self,
        _req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        // PSync is a GET request, so no request body needed
        Ok(None)
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<
        RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        errors::ConnectorError,
    > {
        let response: paypay::PaypaySyncResponse = res
            .response
            .parse_struct("PaypaySyncResponse")
            .map_err(|_| errors::ConnectorError::ResponseDeserializationFailed)?;

        with_response_body!(event_builder, response);

        RouterDataV2::foreign_try_from((
            response,
            data.clone(),
            res.status_code,
            data.request.capture_method,
            false,
            data.request.payment_method_type,
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
}

impl
    ConnectorIntegrationV2<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for Paypay
{
    fn get_headers(
        &self,
        _req: &RouterDataV2<
            CreateOrder,
            PaymentFlowData,
            PaymentCreateOrderData,
            PaymentCreateOrderResponse,
        >,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::NotImplemented(
            "CreateOrder not implemented".into()
        )))
    }

    fn get_url(
        &self,
        _req: &RouterDataV2<
            CreateOrder,
            PaymentFlowData,
            PaymentCreateOrderData,
            PaymentCreateOrderResponse,
        >,
    ) -> CustomResult<String, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::NotImplemented(
            "CreateOrder not implemented".into()
        )))
    }

    fn get_request_body(
        &self,
        _req: &RouterDataV2<
            CreateOrder,
            PaymentFlowData,
            PaymentCreateOrderData,
            PaymentCreateOrderResponse,
        >,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::NotImplemented(
            "CreateOrder not implemented".into()
        )))
    }

    fn handle_response_v2(
        &self,
        _data: &RouterDataV2<
            CreateOrder,
            PaymentFlowData,
            PaymentCreateOrderData,
            PaymentCreateOrderResponse,
        >,
        _event_builder: Option<&mut ConnectorEvent>,
        _res: Response,
    ) -> CustomResult<
        RouterDataV2<
            CreateOrder,
            PaymentFlowData,
            PaymentCreateOrderData,
            PaymentCreateOrderResponse,
        >,
        errors::ConnectorError,
    > {
        Err(report!(errors::ConnectorError::NotImplemented(
            "CreateOrder not implemented".into()
        )))
    }

    fn get_error_response_v2(
        &self,
        _res: Response,
        _event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::NotImplemented(
            "CreateOrder not implemented".into()
        )))
    }
}

impl ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
    for Paypay
{
    fn get_http_method(&self) -> Method {
        Method::Post
    }

    fn get_headers(
        &self,
        req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth = paypay::PaypayAuthType::try_from(&req.connector_auth_type)
            .map_err(|_| errors::ConnectorError::FailedToObtainAuthType)?;
        let timestamp = (chrono::Utc::now().timestamp() as u64).to_string();
        let nonce = uuid::Uuid::new_v4().to_string();
        let merchant_id = auth.merchant_id.peek();
        let body = self.get_request_body(req)?;
        let body_string = Self::extract_body_string_and_value(&body)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;
        // Get the full URL and use the complete path for authorization
        let url = self.get_url(req)?;
        let path = Self::extract_path_from_url(&url)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;
        // Get the HTTP method dynamically
        let method = <Paypay as ConnectorIntegrationV2<
            Capture,
            PaymentFlowData,
            PaymentsCaptureData,
            PaymentsResponseData,
        >>::get_http_method(self);
        // Generate authorization header
        let auth_header = Self::create_auth_header(
            &method.to_string(),
            path,
            &body_string,
            &timestamp,
            &nonce,
            auth.key_id.peek(),
            auth.secret_key.peek(),
        )
        .map_err(|_| errors::ConnectorError::RequestEncodingFailed)?;

        let header = vec![
            (
                "X-ASSUME-MERCHANT".to_string(),
                merchant_id.to_string().into(),
            ),
            ("Authorization".to_string(), auth_header.into_masked()),
        ];
        Ok(header)
    }

    fn get_url(
        &self,
        req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(format!(
            "{}v2/payments/capture",
            req.resource_common_data.connectors.paypay.base_url
        ))
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let paypay_router_data = paypay::PaypayRouterData {
            amount: req.request.minor_amount_to_capture,
            router_data: req,
        };
        let connector_req = paypay::PaypayCaptureRequest::try_from(&paypay_router_data)?;
        Ok(Some(RequestContent::Json(Box::new(connector_req))))
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<
        RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        errors::ConnectorError,
    > {
        let response: paypay::PaypayCaptureResponse = res
            .response
            .parse_struct("PaypayCaptureResponse")
            .map_err(|_| errors::ConnectorError::ResponseDeserializationFailed)?;

        with_response_body!(event_builder, response);

        RouterDataV2::foreign_try_from((response, data.clone()))
            .change_context(errors::ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
    for Paypay
{
    fn get_http_method(&self) -> Method {
        Method::Delete
    }

    fn get_headers(
        &self,
        req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth = paypay::PaypayAuthType::try_from(&req.connector_auth_type)
            .map_err(|_| errors::ConnectorError::FailedToObtainAuthType)?;
        let timestamp = (chrono::Utc::now().timestamp() as u64).to_string();
        let nonce = uuid::Uuid::new_v4().to_string();
        let merchant_id = auth.merchant_id.peek();
        let body = self.get_request_body(req)?;
        let body_string = Self::extract_body_string_and_value(&body)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;
        // Get the full URL and use the complete path for authorization
        let url = self.get_url(req)?;
        let path = Self::extract_path_from_url(&url)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;
        // Get the HTTP method dynamically
        let method = <Paypay as ConnectorIntegrationV2<
            Void,
            PaymentFlowData,
            PaymentVoidData,
            PaymentsResponseData,
        >>::get_http_method(self);
        // Generate authorization header
        let auth_header = Self::create_auth_header(
            &method.to_string(),
            path,
            &body_string,
            &timestamp,
            &nonce,
            auth.key_id.peek(),
            auth.secret_key.peek(),
        )
        .map_err(|_| errors::ConnectorError::RequestEncodingFailed)?;

        let header = vec![
            (
                "X-ASSUME-MERCHANT".to_string(),
                merchant_id.to_string().into(),
            ),
            ("Authorization".to_string(), auth_header.into_masked()),
        ];
        Ok(header)
    }

    fn get_url(
        &self,
        req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        let merchant_payment_id = req
            .resource_common_data
            .connector_request_reference_id
            .clone();
        Ok(format!(
            "{}v2/payments/{}",
            req.resource_common_data.connectors.paypay.base_url, merchant_payment_id
        ))
    }

    fn get_request_body(
        &self,
        _req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        // Void is a DELETE request, so no request body needed
        Ok(None)
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<
        RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        errors::ConnectorError,
    > {
        let response: paypay::PaypayVoidResponse = res
            .response
            .parse_struct("PaypayVoidResponse")
            .map_err(|_| errors::ConnectorError::ResponseDeserializationFailed)?;

        with_response_body!(event_builder, response);

        RouterDataV2::foreign_try_from((response, data.clone()))
            .change_context(errors::ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData> for Paypay {
    fn get_http_method(&self) -> Method {
        Method::Post
    }

    fn get_headers(
        &self,
        req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth = paypay::PaypayAuthType::try_from(&req.connector_auth_type)
            .map_err(|_| errors::ConnectorError::FailedToObtainAuthType)?;
        let timestamp = (chrono::Utc::now().timestamp() as u64).to_string();
        let nonce = uuid::Uuid::new_v4().to_string();
        let merchant_id = auth.merchant_id.peek();
        let body = self.get_request_body(req)?;
        let body_string = Self::extract_body_string_and_value(&body)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;
        // Get the full URL and use the complete path for authorization
        let url = self.get_url(req)?;
        let path = Self::extract_path_from_url(&url)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;
        // Get the HTTP method dynamically
        let method = <Paypay as ConnectorIntegrationV2<
            Refund,
            RefundFlowData,
            RefundsData,
            RefundsResponseData,
        >>::get_http_method(self);
        // Generate authorization header
        let auth_header = Self::create_auth_header(
            &method.to_string(),
            path,
            &body_string,
            &timestamp,
            &nonce,
            auth.key_id.peek(),
            auth.secret_key.peek(),
        )
        .map_err(|_| errors::ConnectorError::RequestEncodingFailed)?;

        let header = vec![
            (
                "X-ASSUME-MERCHANT".to_string(),
                merchant_id.to_string().into(),
            ),
            ("Authorization".to_string(), auth_header.into_masked()),
        ];
        Ok(header)
    }

    fn get_url(
        &self,
        req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(format!(
            "{}v2/refunds",
            req.resource_common_data.connectors.paypay.base_url
        ))
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let paypay_router_data = paypay::PaypayRouterData {
            amount: req.request.minor_refund_amount,
            router_data: req,
        };
        let connector_req = paypay::PaypayRefundRequest::try_from(&paypay_router_data)?;
        Ok(Some(RequestContent::Json(Box::new(connector_req))))
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<
        RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        errors::ConnectorError,
    > {
        let response: paypay::PaypayRefundResponse = res
            .response
            .parse_struct("PaypayRefundResponse")
            .map_err(|_| errors::ConnectorError::ResponseDeserializationFailed)?;

        with_response_body!(event_builder, response);

        RouterDataV2::foreign_try_from((response, data.clone()))
            .change_context(errors::ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData> for Paypay {
    fn get_http_method(&self) -> Method {
        Method::Get
    }

    fn get_headers(
        &self,
        req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth = paypay::PaypayAuthType::try_from(&req.connector_auth_type)
            .map_err(|_| errors::ConnectorError::FailedToObtainAuthType)?;
        let timestamp = (chrono::Utc::now().timestamp() as u64).to_string();
        let nonce = uuid::Uuid::new_v4().to_string();
        let merchant_id = auth.merchant_id.peek();
        let body = self.get_request_body(req)?;
        let body_string = Self::extract_body_string_and_value(&body)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;
        // Get the full URL and use the complete path for authorization
        let url = self.get_url(req)?;
        let path = Self::extract_path_from_url(&url)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;
        // Get the HTTP method dynamically
        let method = <Paypay as ConnectorIntegrationV2<
            RSync,
            RefundFlowData,
            RefundSyncData,
            RefundsResponseData,
        >>::get_http_method(self);
        // Generate authorization header
        let auth_header = Self::create_auth_header(
            &method.to_string(),
            path,
            &body_string,
            &timestamp,
            &nonce,
            auth.key_id.peek(),
            auth.secret_key.peek(),
        )
        .map_err(|_| errors::ConnectorError::RequestEncodingFailed)?;

        let header = vec![
            (
                "X-ASSUME-MERCHANT".to_string(),
                merchant_id.to_string().into(),
            ),
            ("Authorization".to_string(), auth_header.into_masked()),
        ];
        Ok(header)
    }

    fn get_url(
        &self,
        req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        let merchant_refund_id = if req.request.connector_refund_id.is_empty() {
            return Err(report!(errors::ConnectorError::MissingRequiredField {
                field_name: "merchant_refund_id",
            }));
        } else {
            req.request.connector_refund_id.clone()
        };

        Ok(format!(
            "{}v2/refunds/{}",
            req.resource_common_data.connectors.paypay.base_url, merchant_refund_id
        ))
    }

    fn get_request_body(
        &self,
        _req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        // RSync is a GET request, so no request body needed
        Ok(None)
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<
        RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        errors::ConnectorError,
    > {
        let response: paypay::PaypayRsyncResponse = res
            .response
            .parse_struct("PaypayRsyncResponse")
            .map_err(|_| errors::ConnectorError::ResponseDeserializationFailed)?;

        with_response_body!(event_builder, response);

        RouterDataV2::foreign_try_from((response, data.clone()))
            .change_context(errors::ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl
    ConnectorIntegrationV2<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData,
        PaymentsResponseData,
    > for Paypay
{
    fn get_http_method(&self) -> Method {
        Method::Post
    }

    fn get_headers(
        &self,
        req: &RouterDataV2<
            SetupMandate,
            PaymentFlowData,
            SetupMandateRequestData,
            PaymentsResponseData,
        >,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth = paypay::PaypayAuthType::try_from(&req.connector_auth_type)
            .map_err(|_| errors::ConnectorError::FailedToObtainAuthType)?;
        let timestamp = (chrono::Utc::now().timestamp() as u64).to_string();
        let nonce = uuid::Uuid::new_v4().to_string();
        let merchant_id = auth.merchant_id.peek();
        let body = self.get_request_body(req)?;
        let body_string = Self::extract_body_string_and_value(&body)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;
        // Get the full URL and use the complete path for authorization
        let url = self.get_url(req)?;
        let path = Self::extract_path_from_url(&url)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;
        // Get the HTTP method dynamically
        let method = <Paypay as ConnectorIntegrationV2<
            SetupMandate,
            PaymentFlowData,
            SetupMandateRequestData,
            PaymentsResponseData,
        >>::get_http_method(self);
        // Generate authorization header
        let auth_header = Self::create_auth_header(
            &method.to_string(),
            path,
            &body_string,
            &timestamp,
            &nonce,
            auth.key_id.peek(),
            auth.secret_key.peek(),
        )
        .map_err(|_| errors::ConnectorError::RequestEncodingFailed)?;

        let header = vec![
            (
                "X-ASSUME-MERCHANT".to_string(),
                merchant_id.to_string().into(),
            ),
            ("Authorization".to_string(), auth_header.into_masked()),
        ];
        Ok(header)
    }

    fn get_url(
        &self,
        req: &RouterDataV2<
            SetupMandate,
            PaymentFlowData,
            SetupMandateRequestData,
            PaymentsResponseData,
        >,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(format!(
            "{}v1/subscription/payments",
            req.resource_common_data.connectors.paypay.base_url
        ))
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<
            SetupMandate,
            PaymentFlowData,
            SetupMandateRequestData,
            PaymentsResponseData,
        >,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let amount = match req.request.amount {
            Some(amount) => amount,
            None => {
                return Err(report!(errors::ConnectorError::MissingRequiredField {
                    field_name: "amount",
                }))
            }
        };
        let paypay_router_data = paypay::PaypayRouterData {
            amount: hyperswitch_common_utils::types::MinorUnit::new(amount),
            router_data: req,
        };
        let connector_req = paypay::PaypaySetupMandateRequest::try_from(&paypay_router_data)?;
        Ok(Some(RequestContent::Json(Box::new(connector_req))))
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<
            SetupMandate,
            PaymentFlowData,
            SetupMandateRequestData,
            PaymentsResponseData,
        >,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<
        RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData>,
        errors::ConnectorError,
    > {
        let response: paypay::PaypaySetupMandateResponse = res
            .response
            .parse_struct("PaypaySetupMandateResponse")
            .map_err(|_| errors::ConnectorError::ResponseDeserializationFailed)?;

        with_response_body!(event_builder, response);

        RouterDataV2::foreign_try_from((response, data.clone()))
            .change_context(errors::ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    for Paypay
{
    fn get_headers(
        &self,
        _req: &RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::NotImplemented(
            "Accept not implemented".into()
        )))
    }

    fn get_url(
        &self,
        _req: &RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::NotImplemented(
            "Accept not implemented".into()
        )))
    }

    fn get_request_body(
        &self,
        _req: &RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::NotImplemented(
            "Accept not implemented".into()
        )))
    }

    fn handle_response_v2(
        &self,
        _data: &RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>,
        _event_builder: Option<&mut ConnectorEvent>,
        _res: Response,
    ) -> CustomResult<
        RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>,
        errors::ConnectorError,
    > {
        Err(report!(errors::ConnectorError::NotImplemented(
            "Accept not implemented".into()
        )))
    }

    fn get_error_response_v2(
        &self,
        _res: Response,
        _event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::NotImplemented(
            "Accept not implemented".into()
        )))
    }
}

impl
    ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
    for Paypay
{
    fn get_headers(
        &self,
        _req: &RouterDataV2<
            SubmitEvidence,
            DisputeFlowData,
            SubmitEvidenceData,
            DisputeResponseData,
        >,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::NotImplemented(
            "SubmitEvidence not implemented".into()
        )))
    }

    fn get_url(
        &self,
        _req: &RouterDataV2<
            SubmitEvidence,
            DisputeFlowData,
            SubmitEvidenceData,
            DisputeResponseData,
        >,
    ) -> CustomResult<String, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::NotImplemented(
            "SubmitEvidence not implemented".into()
        )))
    }

    fn get_request_body(
        &self,
        _req: &RouterDataV2<
            SubmitEvidence,
            DisputeFlowData,
            SubmitEvidenceData,
            DisputeResponseData,
        >,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::NotImplemented(
            "SubmitEvidence not implemented".into()
        )))
    }

    fn handle_response_v2(
        &self,
        _data: &RouterDataV2<
            SubmitEvidence,
            DisputeFlowData,
            SubmitEvidenceData,
            DisputeResponseData,
        >,
        _event_builder: Option<&mut ConnectorEvent>,
        _res: Response,
    ) -> CustomResult<
        RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>,
        errors::ConnectorError,
    > {
        Err(report!(errors::ConnectorError::NotImplemented(
            "SubmitEvidence not implemented".into()
        )))
    }

    fn get_error_response_v2(
        &self,
        _res: Response,
        _event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::NotImplemented(
            "SubmitEvidence not implemented".into()
        )))
    }
}

impl ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
    for Paypay
{
    fn get_headers(
        &self,
        _req: &RouterDataV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::NotImplemented(
            "DefendDispute not implemented".into()
        )))
    }

    fn get_url(
        &self,
        _req: &RouterDataV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::NotImplemented(
            "DefendDispute not implemented".into()
        )))
    }

    fn get_request_body(
        &self,
        _req: &RouterDataV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::NotImplemented(
            "DefendDispute not implemented".into()
        )))
    }

    fn handle_response_v2(
        &self,
        _data: &RouterDataV2<
            DefendDispute,
            DisputeFlowData,
            DisputeDefendData,
            DisputeResponseData,
        >,
        _event_builder: Option<&mut ConnectorEvent>,
        _res: Response,
    ) -> CustomResult<
        RouterDataV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>,
        errors::ConnectorError,
    > {
        Err(report!(errors::ConnectorError::NotImplemented(
            "DefendDispute not implemented".into()
        )))
    }

    fn get_error_response_v2(
        &self,
        _res: Response,
        _event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::NotImplemented(
            "DefendDispute not implemented".into()
        )))
    }
}
