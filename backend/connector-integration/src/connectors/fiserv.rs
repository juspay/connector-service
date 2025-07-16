use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD_ENGINE, Engine};
use common_utils::{
    consts::{NO_ERROR_CODE, NO_ERROR_MESSAGE},
    errors::CustomResult,
    ext_traits::BytesExt,
    request::RequestContent,
    types::FloatMajorUnit,
};
use domain_types::{
    connector_flow::{
        Accept, Authorize, Capture, CreateOrder, DefendDispute, PSync, RSync, Refund, SetupMandate,
        SubmitEvidence, Void,
    },
    connector_types::{
        AcceptDisputeData, ConnectorSpecifications, DisputeDefendData, DisputeFlowData,
        DisputeResponseData, PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData,
        PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData,
        PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData,
        SetupMandateRequestData, SubmitEvidenceData,
    },
    errors,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, Mask, Maskable, PeekInterface};
use interfaces::{
    api::ConnectorCommon, connector_integration_v2::ConnectorIntegrationV2, connector_types,
    events::connector_api_logs::ConnectorEvent,
};
use ring::hmac;
use time::OffsetDateTime;
use uuid::Uuid;

pub mod transformers;

use transformers::{
    FiservCaptureRequest, FiservCaptureResponse, FiservPaymentsRequest, FiservPaymentsResponse,
    FiservRefundRequest, FiservRefundResponse, FiservRefundSyncRequest, FiservRefundSyncResponse,
    FiservSyncRequest, FiservSyncResponse, FiservVoidRequest, FiservVoidResponse,
};

use super::macros;
use crate::{types::ResponseRouterData, with_error_response_body};

// Local headers module
mod headers {
    pub const API_KEY: &str = "Api-Key";
    pub const CONTENT_TYPE: &str = "Content-Type";
    pub const TIMESTAMP: &str = "Timestamp";
    pub const CLIENT_REQUEST_ID: &str = "Client-Request-Id";
    pub const AUTH_TOKEN_TYPE: &str = "Auth-Token-Type";
    pub const AUTHORIZATION: &str = "Authorization";
}

impl connector_types::ConnectorServiceTrait for Fiserv {}
impl connector_types::PaymentAuthorizeV2 for Fiserv {}
impl connector_types::PaymentSyncV2 for Fiserv {}
impl connector_types::PaymentVoidV2 for Fiserv {}
impl connector_types::RefundSyncV2 for Fiserv {}
impl connector_types::RefundV2 for Fiserv {}
impl connector_types::PaymentCapture for Fiserv {}
impl connector_types::ValidationTrait for Fiserv {}
impl connector_types::PaymentOrderCreate for Fiserv {}
impl connector_types::SetupMandateV2 for Fiserv {}
impl connector_types::AcceptDispute for Fiserv {}
impl connector_types::SubmitEvidenceV2 for Fiserv {}
impl connector_types::DisputeDefend for Fiserv {}
impl connector_types::IncomingWebhook for Fiserv {}

// Implement RSync to fix the RefundSyncV2 trait requirement
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Fiserv,
    curl_request: Json(FiservRefundSyncRequest),
    curl_response: FiservRefundSyncResponse,
    flow_name: RSync,
    resource_common_data: RefundFlowData,
    flow_request: RefundSyncData,
    flow_response: RefundsResponseData,
    http_method: Post,
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<domain_types::connector_flow::RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            Ok(format!(
                "{}ch/payments/v1/transaction-inquiry",
                self.connector_base_url_refunds(req)
            ))
        }
    }
);

macros::create_all_prerequisites!(
    connector_name: Fiserv,
    api: [
        (
            flow: Authorize,
            request_body: FiservPaymentsRequest,
            response_body: FiservPaymentsResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>
        ),
        (
            flow: PSync,
            request_body: FiservSyncRequest,
            response_body: FiservSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
        ),
        (
            flow: Capture,
            request_body: FiservCaptureRequest,
            response_body: FiservCaptureResponse,
            router_data: RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
        ),
        (
            flow: Void,
            request_body: FiservVoidRequest,
            response_body: FiservVoidResponse,
            router_data: RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
        ),
        (
            flow: Refund,
            request_body: FiservRefundRequest,
            response_body: FiservRefundResponse,
            router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
        ),
        (
            flow: RSync,
            request_body: FiservRefundSyncRequest,
            response_body: FiservRefundSyncResponse,
            router_data: RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
        )
    ],
    amount_converters: [
        amount_converter: FloatMajorUnit
    ],
    member_functions: {
        pub fn generate_authorization_signature(
            &self,
            auth: &self::transformers::FiservAuthType,
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

            let key = hmac::Key::new(hmac::HMAC_SHA256, auth.api_secret.clone().expose().as_bytes());
            let tag = hmac::sign(&key, raw_signature.as_bytes());

            Ok(BASE64_STANDARD_ENGINE.encode(tag.as_ref()))
        }

        pub fn build_headers<F, FCD, Req, Res>(
            &self,
            req: &RouterDataV2<F, FCD, Req, Res>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError>
        where
            Self: ConnectorIntegrationV2<F, FCD, Req, Res>,
        {
            let temp_request_body_for_sig = self.get_request_body(req)?;
            let payload_string_for_sig = match temp_request_body_for_sig {
                Some(RequestContent::Json(json_body)) => serde_json::to_string(&json_body)
                    .change_context(errors::ConnectorError::RequestEncodingFailed)
                    .attach_printable("Failed to serialize JSON request body for signature")?,
                Some(RequestContent::FormUrlEncoded(form_body)) => serde_urlencoded::to_string(&form_body)
                    .change_context(errors::ConnectorError::RequestEncodingFailed)
                    .attach_printable("Failed to serialize form request body for signature")?,
                None => "".to_string(),
                _ => return Err(errors::ConnectorError::RequestEncodingFailed)
                    .attach_printable("Unsupported request body type for signature generation")?,
            };

            let timestamp_ms = OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000;
            let client_request_id = Uuid::new_v4().to_string();

            let auth_type_for_sig = self::transformers::FiservAuthType::try_from(&req.connector_auth_type)
                .change_context(errors::ConnectorError::FailedToObtainAuthType)?;

            let signature = self.generate_authorization_signature(
                &auth_type_for_sig,
                &client_request_id,
                &payload_string_for_sig,
                timestamp_ms,
            )?;

            // Step 4: Build and return the headers
            let mut http_headers = vec![
                (headers::CONTENT_TYPE.to_string(), self.common_get_content_type().into()),
                (headers::CLIENT_REQUEST_ID.to_string(), client_request_id.into()),
                (headers::TIMESTAMP.to_string(), timestamp_ms.to_string().into()),
                (headers::AUTH_TOKEN_TYPE.to_string(), "HMAC".to_string().into()),
                (headers::AUTHORIZATION.to_string(), signature.into_masked()),
            ];

            let mut api_key_header = self.get_auth_header(&req.connector_auth_type)?;
            http_headers.append(&mut api_key_header);

            Ok(http_headers)
        }

        pub fn connector_base_url_payments<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.fiserv.base_url
        }

        pub fn connector_base_url_refunds<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, RefundFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.fiserv.base_url
        }
    }
);

impl ConnectorCommon for Fiserv {
    fn id(&self) -> &'static str {
        "fiserv"
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.fiserv.base_url.as_ref()
    }

    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth: self::transformers::FiservAuthType =
            self::transformers::FiservAuthType::try_from(auth_type)
                .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        Ok(vec![(
            headers::API_KEY.to_string(),
            auth.api_key.clone().into_masked(),
        )])
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: self::transformers::FiservErrorResponse = res
            .response
            .parse_struct("FiservErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        with_error_response_body!(event_builder, response);

        let first_error_detail = response
            .error
            .as_ref()
            .or(response.details.as_ref())
            .and_then(|e| e.first());

        Ok(ErrorResponse {
            status_code: res.status_code,
            code: first_error_detail
                .and_then(|e| e.code.clone())
                .unwrap_or_else(|| NO_ERROR_CODE.to_string()),
            message: first_error_detail.map_or(NO_ERROR_MESSAGE.to_string(), |e| e.message.clone()),
            reason: first_error_detail.and_then(|e| e.field.clone()),
            attempt_status: None,
            connector_transaction_id: None,
            network_decline_code: None,
            network_advice_code: None,
            network_error_message: None,
            raw_connector_response: Some(String::from_utf8_lossy(&res.response).to_string()),
        })
    }
}

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Fiserv,
    curl_request: Json(FiservPaymentsRequest),
    curl_response: FiservPaymentsResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            Ok(format!(
                "{}ch/payments/v1/charges",
                self.connector_base_url_payments(req)
            ))
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Fiserv,
    curl_request: Json(FiservSyncRequest),
    curl_response: FiservSyncResponse,
    flow_name: PSync,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsSyncData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            Ok(format!(
                "{}ch/payments/v1/transaction-inquiry",
                self.connector_base_url_payments(req)
            ))
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Fiserv,
    curl_request: Json(FiservCaptureRequest),
    curl_response: FiservCaptureResponse,
    flow_name: Capture,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsCaptureData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            Ok(format!(
                "{}ch/payments/v1/charges",
                self.connector_base_url_payments(req)
            ))
        }
    }
);

// Add implementation for Void
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Fiserv,
    curl_request: Json(FiservVoidRequest),
    curl_response: FiservVoidResponse,
    flow_name: Void,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentVoidData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            Ok(format!(
                "{}ch/payments/v1/cancels",
                self.connector_base_url_payments(req)
            ))
        }
    }
);

// Add implementation for Refund
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Fiserv,
    curl_request: Json(FiservRefundRequest),
    curl_response: FiservRefundResponse,
    flow_name: Refund,
    resource_common_data: RefundFlowData,
    flow_request: RefundsData,
    flow_response: RefundsResponseData,
    http_method: Post,
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            Ok(format!(
                "{}ch/payments/v1/refunds",
                self.connector_base_url_refunds(req)
            ))
        }
    }
);

// Implementation for empty stubs - these will need to be properly implemented later
impl
    ConnectorIntegrationV2<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for Fiserv
{
}
impl
    ConnectorIntegrationV2<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData,
        PaymentsResponseData,
    > for Fiserv
{
}
impl ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    for Fiserv
{
}
impl
    ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
    for Fiserv
{
}
impl ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
    for Fiserv
{
}

// SourceVerification implementations for all flows
impl
    interfaces::verification::SourceVerification<
        Authorize,
        PaymentFlowData,
        PaymentsAuthorizeData,
        PaymentsResponseData,
    > for Fiserv
{
}

impl
    interfaces::verification::SourceVerification<
        PSync,
        PaymentFlowData,
        PaymentsSyncData,
        PaymentsResponseData,
    > for Fiserv
{
}

impl
    interfaces::verification::SourceVerification<
        Capture,
        PaymentFlowData,
        PaymentsCaptureData,
        PaymentsResponseData,
    > for Fiserv
{
}

impl
    interfaces::verification::SourceVerification<
        Void,
        PaymentFlowData,
        PaymentVoidData,
        PaymentsResponseData,
    > for Fiserv
{
}

impl
    interfaces::verification::SourceVerification<
        Refund,
        RefundFlowData,
        RefundsData,
        RefundsResponseData,
    > for Fiserv
{
}

impl
    interfaces::verification::SourceVerification<
        RSync,
        RefundFlowData,
        RefundSyncData,
        RefundsResponseData,
    > for Fiserv
{
}

impl
    interfaces::verification::SourceVerification<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData,
        PaymentsResponseData,
    > for Fiserv
{
}

impl
    interfaces::verification::SourceVerification<
        Accept,
        DisputeFlowData,
        AcceptDisputeData,
        DisputeResponseData,
    > for Fiserv
{
}

impl
    interfaces::verification::SourceVerification<
        SubmitEvidence,
        DisputeFlowData,
        SubmitEvidenceData,
        DisputeResponseData,
    > for Fiserv
{
}

impl
    interfaces::verification::SourceVerification<
        DefendDispute,
        DisputeFlowData,
        DisputeDefendData,
        DisputeResponseData,
    > for Fiserv
{
}

impl
    interfaces::verification::SourceVerification<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for Fiserv
{
}

impl ConnectorSpecifications for Fiserv {}

// We already have an implementation for ValidationTrait above
