pub mod transformers;

use std::fmt::Debug;

use common_enums::CurrencyUnit;

// Helper function to recursively flatten $text fields in JSON values
fn flatten_text_fields(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            // If empty object, convert to empty string
            if map.is_empty() {
                return serde_json::Value::String(String::new());
            }

            // If this object has a single "$text" field, extract it
            if map.len() == 1 && map.contains_key("$text") {
                return flatten_text_fields(map.get("$text").unwrap().clone());
            }

            // Otherwise, recursively flatten all fields
            let flattened_map: serde_json::Map<String, serde_json::Value> = map
                .into_iter()
                .map(|(k, v)| (k, flatten_text_fields(v)))
                .collect();
            serde_json::Value::Object(flattened_map)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.into_iter().map(flatten_text_fields).collect())
        }
        other => other,
    }
}
use common_utils::{
    errors::CustomResult,
    events,
    ext_traits::ByteSliceExt,
    request::{Method, RequestContent},
    types::StringMajorUnit,
};
use domain_types::{
    connector_flow::{
        Accept, Authenticate, Authorize, Capture, CreateAccessToken, CreateOrder,
        CreateSessionToken, DefendDispute, PSync, PaymentMethodToken, PostAuthenticate,
        PreAuthenticate, RSync, Refund, RepeatPayment, SetupMandate, SubmitEvidence, Void, VoidPC,
    },
    connector_types::{
        AcceptDisputeData, AccessTokenRequestData, AccessTokenResponseData, ConnectorCustomerData,
        ConnectorCustomerResponse, DisputeDefendData, DisputeFlowData, DisputeResponseData,
        PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData,
        PaymentMethodTokenResponse, PaymentMethodTokenizationData, PaymentVoidData,
        PaymentsAuthenticateData, PaymentsAuthorizeData, PaymentsCancelPostCaptureData,
        PaymentsCaptureData, PaymentsPostAuthenticateData, PaymentsPreAuthenticateData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData,
        RefundsResponseData, RepeatPaymentData, SessionTokenRequestData, SessionTokenResponseData,
        SetupMandateRequestData, SubmitEvidenceData,
    },
    errors::{self},
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, Maskable};
use interfaces::{
    api::ConnectorCommon, connector_integration_v2::ConnectorIntegrationV2, connector_types,
};
use serde::Serialize;
use transformers::{
    self as hipay, HipayAuthorizeResponse, HipayCaptureRequest, HipayCaptureResponse,
    HipayPSyncResponse, HipayPaymentsRequest, HipayRSyncResponse, HipayRefundRequest,
    HipayRefundResponse, HipayTokenRequest, HipayTokenResponse, HipayVoidRequest,
    HipayVoidResponse,
};

use crate::{types::ResponseRouterData, with_error_response_body, with_response_body};

pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const AUTHORIZATION: &str = "Authorization";
}

pub(crate) mod constants {
    pub(crate) const FORM_CONTENT_TYPE: &str = "application/x-www-form-urlencoded";
}

#[derive(Clone)]
pub struct Hipay<T> {
    #[allow(dead_code)]
    pub(crate) amount_converter:
        &'static (dyn common_utils::types::AmountConvertor<Output = StringMajorUnit> + Sync),
    #[allow(dead_code)]
    _phantom: std::marker::PhantomData<T>,
}

impl<T> Hipay<T> {
    pub const fn new() -> &'static Self {
        &Self {
            amount_converter: &common_utils::types::StringMajorUnitForConnector,
            _phantom: std::marker::PhantomData,
        }
    }

    fn get_tokenization_base_url<F, Req, Res>(
        &self,
        req: &RouterDataV2<F, PaymentFlowData, Req, Res>,
    ) -> String {
        // Use secondary_base_url from config for tokenization endpoint (similar to base_url pattern)
        req.resource_common_data
            .connectors
            .hipay
            .secondary_base_url
            .as_ref()
            .cloned()
            .expect("HiPay secondary_base_url must be configured in connectors config")
    }

    fn get_sync_base_url<F, Req, Res>(
        &self,
        req: &RouterDataV2<F, PaymentFlowData, Req, Res>,
    ) -> String {
        // Use third_base_url from config for sync operations (PSync, RSync)
        req.resource_common_data
            .connectors
            .hipay
            .third_base_url
            .as_ref()
            .cloned()
            .expect("HiPay third_base_url must be configured in connectors config")
    }

    fn get_refund_sync_base_url<Req, Res>(
        &self,
        req: &RouterDataV2<RSync, RefundFlowData, Req, Res>,
    ) -> String {
        // Use third_base_url from config for refund sync operations
        req.resource_common_data
            .connectors
            .hipay
            .third_base_url
            .as_ref()
            .cloned()
            .expect("HiPay third_base_url must be configured in connectors config")
    }
}

// Trait implementations with generic type parameters
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::ConnectorServiceTrait<T> for Hipay<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::PaymentAuthorizeV2<T> for Hipay<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::PaymentSyncV2 for Hipay<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::PaymentSessionToken for Hipay<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAccessToken for Hipay<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::CreateConnectorCustomer for Hipay<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::PaymentVoidV2 for Hipay<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::RefundSyncV2 for Hipay<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::RefundV2 for Hipay<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::PaymentCapture for Hipay<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::SetupMandateV2<T> for Hipay<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::AcceptDispute for Hipay<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::SubmitEvidenceV2 for Hipay<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::DisputeDefend for Hipay<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::IncomingWebhook for Hipay<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::PaymentOrderCreate for Hipay<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::ValidationTrait for Hipay<T>
{
    fn should_do_payment_method_token(&self) -> bool {
        true
    }
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::RepeatPaymentV2 for Hipay<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::PaymentTokenV2<T> for Hipay<T>
{
}

// Authentication trait implementations
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::PaymentPreAuthenticateV2<T> for Hipay<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::PaymentAuthenticateV2<T> for Hipay<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::PaymentPostAuthenticateV2<T> for Hipay<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::PaymentVoidPostCaptureV2 for Hipay<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    ConnectorIntegrationV2<
        VoidPC,
        PaymentFlowData,
        PaymentsCancelPostCaptureData,
        PaymentsResponseData,
    > for Hipay<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > ConnectorCommon for Hipay<T>
{
    fn id(&self) -> &'static str {
        "hipay"
    }

    fn get_currency_unit(&self) -> CurrencyUnit {
        CurrencyUnit::Minor
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.hipay.base_url.as_ref()
    }

    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth = hipay::HipayAuthType::try_from(auth_type)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;

        // Use HTTP Basic Auth for HiPay
        let auth_value = if let Some(api_secret) = auth.api_secret {
            use base64::Engine;
            let credentials = format!("{}:{}", auth.api_key.expose(), api_secret.expose());
            let base64_credentials = base64::engine::general_purpose::STANDARD.encode(credentials);
            format!("Basic {}", base64_credentials)
        } else {
            // Fallback to API key only (shouldn't happen for HiPay)
            format!("Bearer {}", auth.api_key.expose())
        };

        Ok(vec![(
            headers::AUTHORIZATION.to_string(),
            auth_value.into(),
        )])
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut events::Event>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        use crate::utils::preprocess_xml_response_bytes;

        let response_bytes = res.response.clone();

        // Check if response is XML
        let error_response: hipay::HipayErrorResponse =
            if let Ok(response_str) = std::str::from_utf8(&response_bytes) {
                if response_str.trim().starts_with("<?xml") {
                    // Convert XML to JSON
                    let json_bytes = preprocess_xml_response_bytes(response_bytes.into())
                        .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

                    // Parse as HipayErrorResponse
                    serde_json::from_slice(&json_bytes)
                        .change_context(errors::ConnectorError::ResponseDeserializationFailed)?
                } else {
                    // Parse as JSON directly
                    res.response
                        .parse_struct("HipayErrorResponse")
                        .change_context(errors::ConnectorError::ResponseDeserializationFailed)?
                }
            } else {
                // Fallback to JSON parsing
                res.response
                    .parse_struct("HipayErrorResponse")
                    .change_context(errors::ConnectorError::ResponseDeserializationFailed)?
            };

        with_error_response_body!(event_builder, error_response);

        Ok(ErrorResponse {
            status_code: res.status_code,
            code: error_response.code,
            message: error_response.message,
            reason: None,
            attempt_status: None,
            connector_transaction_id: None,
            network_decline_code: None,
            network_advice_code: None,
            network_error_message: None,
        })
    }
}

// PaymentMethodToken flow implementation
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    ConnectorIntegrationV2<
        PaymentMethodToken,
        PaymentFlowData,
        PaymentMethodTokenizationData<T>,
        PaymentMethodTokenResponse,
    > for Hipay<T>
{
    fn get_headers(
        &self,
        req: &RouterDataV2<
            PaymentMethodToken,
            PaymentFlowData,
            PaymentMethodTokenizationData<T>,
            PaymentMethodTokenResponse,
        >,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth = hipay::HipayAuthType::try_from(&req.connector_auth_type)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;

        // HTTP Basic Auth for tokenization API
        let auth_value = if let Some(api_secret) = auth.api_secret {
            use base64::Engine;
            let credentials = format!("{}:{}", auth.api_key.expose(), api_secret.expose());
            let base64_credentials = base64::engine::general_purpose::STANDARD.encode(credentials);
            format!("Basic {}", base64_credentials)
        } else {
            return Err(errors::ConnectorError::FailedToObtainAuthType.into());
        };

        Ok(vec![
            (
                headers::CONTENT_TYPE.to_string(),
                constants::FORM_CONTENT_TYPE.to_string().into(),
            ),
            (headers::AUTHORIZATION.to_string(), auth_value.into()),
        ])
    }

    fn get_url(
        &self,
        req: &RouterDataV2<
            PaymentMethodToken,
            PaymentFlowData,
            PaymentMethodTokenizationData<T>,
            PaymentMethodTokenResponse,
        >,
    ) -> CustomResult<String, errors::ConnectorError> {
        let base_url = self.get_tokenization_base_url(req);
        Ok(format!("{}/create", base_url.trim_end_matches('/')))
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<
            PaymentMethodToken,
            PaymentFlowData,
            PaymentMethodTokenizationData<T>,
            PaymentMethodTokenResponse,
        >,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let connector_req = HipayTokenRequest::try_from(req)?;
        Ok(Some(RequestContent::FormUrlEncoded(Box::new(
            connector_req,
        ))))
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<
            PaymentMethodToken,
            PaymentFlowData,
            PaymentMethodTokenizationData<T>,
            PaymentMethodTokenResponse,
        >,
        event_builder: Option<&mut events::Event>,
        res: Response,
    ) -> CustomResult<
        RouterDataV2<
            PaymentMethodToken,
            PaymentFlowData,
            PaymentMethodTokenizationData<T>,
            PaymentMethodTokenResponse,
        >,
        errors::ConnectorError,
    > {
        // HiPay tokenization API returns XML responses
        use crate::utils::preprocess_xml_response_bytes;

        let response_bytes = res.response.clone();

        // Convert XML to JSON
        let json_bytes = preprocess_xml_response_bytes(response_bytes.into())
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        // Parse as HipayTokenResponse
        let response: HipayTokenResponse = serde_json::from_slice(&json_bytes)
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        with_response_body!(event_builder, response);

        RouterDataV2::try_from(ResponseRouterData {
            response,
            router_data: data.clone(),
            http_code: res.status_code,
        })
        .change_context(errors::ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut events::Event>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }

    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut events::Event>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

// Authorize flow implementation
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    ConnectorIntegrationV2<
        Authorize,
        PaymentFlowData,
        PaymentsAuthorizeData<T>,
        PaymentsResponseData,
    > for Hipay<T>
{
    fn get_headers(
        &self,
        req: &RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData<T>,
            PaymentsResponseData,
        >,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let mut header = vec![(
            headers::CONTENT_TYPE.to_string(),
            constants::FORM_CONTENT_TYPE.to_string().into(),
        )];
        let mut auth_header = self.get_auth_header(&req.connector_auth_type)?;
        header.append(&mut auth_header);
        Ok(header)
    }

    fn get_url(
        &self,
        req: &RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData<T>,
            PaymentsResponseData,
        >,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(format!(
            "{}/v1/order",
            req.resource_common_data
                .connectors
                .hipay
                .base_url
                .trim_end_matches('/')
        ))
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData<T>,
            PaymentsResponseData,
        >,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let connector_req = HipayPaymentsRequest::try_from(req)?;
        Ok(Some(RequestContent::FormUrlEncoded(Box::new(
            connector_req,
        ))))
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData<T>,
            PaymentsResponseData,
        >,
        event_builder: Option<&mut events::Event>,
        res: Response,
    ) -> CustomResult<
        RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        errors::ConnectorError,
    > {
        // HiPay gateway API returns XML responses
        use crate::utils::preprocess_xml_response_bytes;

        let response_bytes = res.response.clone();

        // Convert XML to JSON
        let json_bytes = preprocess_xml_response_bytes(response_bytes.into())
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        // Parse JSON and flatten $text fields
        let json_value: serde_json::Value = serde_json::from_slice(&json_bytes)
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        // Flatten $text fields recursively
        let flattened_value = flatten_text_fields(json_value);

        // Parse as HipayAuthorizeResponse
        let response: HipayAuthorizeResponse = serde_json::from_value(flattened_value)
            .map_err(|e| {
                tracing::error!(error=?e, json=?std::str::from_utf8(&json_bytes), "Failed to deserialize HipayAuthorizeResponse");
                e
            })
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        with_response_body!(event_builder, response);

        RouterDataV2::try_from(ResponseRouterData {
            response,
            router_data: data.clone(),
            http_code: res.status_code,
        })
        .change_context(errors::ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut events::Event>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }

    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut events::Event>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

// PSync flow implementation
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    for Hipay<T>
{
    fn get_http_method(&self) -> Method {
        Method::Get
    }

    fn get_headers(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let mut header = vec![(
            headers::CONTENT_TYPE.to_string(),
            self.common_get_content_type().to_string().into(),
        )];
        let mut auth_header = self.get_auth_header(&req.connector_auth_type)?;
        header.append(&mut auth_header);
        Ok(header)
    }


    fn get_url(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        let transaction_reference = req
            .request
            .connector_transaction_id
            .get_connector_transaction_id()
            .change_context(errors::ConnectorError::MissingConnectorTransactionID)?;

        let base_url = self.get_sync_base_url(req);
        Ok(format!(
            "{}/v1/transaction/{}",
            base_url.trim_end_matches('/'),
            transaction_reference
        ))
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        event_builder: Option<&mut events::Event>,
        res: Response,
    ) -> CustomResult<
        RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        errors::ConnectorError,
    > {
        // HiPay gateway API returns XML responses
        use crate::utils::preprocess_xml_response_bytes;

        let response_bytes = res.response.clone();

        // Convert XML to JSON
        let json_bytes = preprocess_xml_response_bytes(response_bytes.into())
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        // PSync responses have a "transaction" wrapper, extract it
        let json_value: serde_json::Value = serde_json::from_slice(&json_bytes)
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        let transaction_value = json_value
            .get("transaction")
            .ok_or(errors::ConnectorError::ResponseDeserializationFailed)?;

        // Flatten $text fields recursively
        let flattened_value = flatten_text_fields(transaction_value.clone());

        // Parse as HipayPSyncResponse
        let response: HipayPSyncResponse = serde_json::from_value(flattened_value)
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        with_response_body!(event_builder, response);

        RouterDataV2::try_from(ResponseRouterData {
            response,
            router_data: data.clone(),
            http_code: res.status_code,
        })
        .change_context(errors::ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut events::Event>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }

    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut events::Event>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

// Capture flow implementation
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
    for Hipay<T>
{
    fn get_headers(
        &self,
        req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let mut header = vec![(
            headers::CONTENT_TYPE.to_string(),
            constants::FORM_CONTENT_TYPE.to_string().into(),
        )];
        let mut auth_header = self.get_auth_header(&req.connector_auth_type)?;
        header.append(&mut auth_header);
        Ok(header)
    }

    fn get_url(
        &self,
        req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        let transaction_reference = req
            .request
            .connector_transaction_id
            .get_connector_transaction_id()
            .change_context(errors::ConnectorError::MissingConnectorTransactionID)?;

        Ok(format!(
            "{}/v1/maintenance/transaction/{}",
            req.resource_common_data
                .connectors
                .hipay
                .base_url
                .trim_end_matches('/'),
            transaction_reference
        ))
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let connector_req = HipayCaptureRequest::try_from(req)?;
        Ok(Some(RequestContent::FormUrlEncoded(Box::new(
            connector_req,
        ))))
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        event_builder: Option<&mut events::Event>,
        res: Response,
    ) -> CustomResult<
        RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        errors::ConnectorError,
    > {
        // HiPay gateway API returns XML responses
        use crate::utils::preprocess_xml_response_bytes;

        let response_bytes = res.response.clone();

        // Convert XML to JSON
        let json_bytes = preprocess_xml_response_bytes(response_bytes.into())
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        // Parse JSON and flatten $text fields
        let json_value: serde_json::Value = serde_json::from_slice(&json_bytes)
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        // Flatten $text fields recursively
        let flattened_value = flatten_text_fields(json_value);

        // Parse as HipayCaptureResponse
        let response: HipayCaptureResponse = serde_json::from_value(flattened_value)
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        with_response_body!(event_builder, response);

        RouterDataV2::try_from(ResponseRouterData {
            response,
            router_data: data.clone(),
            http_code: res.status_code,
        })
        .change_context(errors::ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut events::Event>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }

    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut events::Event>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

// Void flow implementation
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
    for Hipay<T>
{
    fn get_headers(
        &self,
        req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let mut header = vec![(
            headers::CONTENT_TYPE.to_string(),
            constants::FORM_CONTENT_TYPE.to_string().into(),
        )];
        let mut auth_header = self.get_auth_header(&req.connector_auth_type)?;
        header.append(&mut auth_header);
        Ok(header)
    }


    fn get_url(
        &self,
        req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        let transaction_reference = &req.request.connector_transaction_id;

        Ok(format!(
            "{}/v1/maintenance/transaction/{}",
            req.resource_common_data
                .connectors
                .hipay
                .base_url
                .trim_end_matches('/'),
            transaction_reference
        ))
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let connector_req = HipayVoidRequest::try_from(req)?;
        Ok(Some(RequestContent::FormUrlEncoded(Box::new(
            connector_req,
        ))))
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        event_builder: Option<&mut events::Event>,
        res: Response,
    ) -> CustomResult<
        RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        errors::ConnectorError,
    > {
        // HiPay gateway API returns XML responses
        use crate::utils::preprocess_xml_response_bytes;

        let response_bytes = res.response.clone();

        // Convert XML to JSON
        let json_bytes = preprocess_xml_response_bytes(response_bytes.into())
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        // Parse JSON and flatten $text fields
        let json_value: serde_json::Value = serde_json::from_slice(&json_bytes)
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        // Flatten $text fields recursively
        let flattened_value = flatten_text_fields(json_value);

        // Parse as HipayVoidResponse
        let response: HipayVoidResponse = serde_json::from_value(flattened_value)
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        with_response_body!(event_builder, response);

        RouterDataV2::try_from(ResponseRouterData {
            response,
            router_data: data.clone(),
            http_code: res.status_code,
        })
        .change_context(errors::ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut events::Event>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }

    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut events::Event>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

// Refund flow implementation
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
    for Hipay<T>
{
    fn get_headers(
        &self,
        req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let mut header = vec![(
            headers::CONTENT_TYPE.to_string(),
            constants::FORM_CONTENT_TYPE.to_string().into(),
        )];
        let mut auth_header = self.get_auth_header(&req.connector_auth_type)?;
        header.append(&mut auth_header);
        Ok(header)
    }


    fn get_url(
        &self,
        req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        let transaction_reference = req.request.connector_transaction_id.clone();

        Ok(format!(
            "{}/v1/maintenance/transaction/{}",
            req.resource_common_data
                .connectors
                .hipay
                .base_url
                .trim_end_matches('/'),
            transaction_reference
        ))
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let connector_req = HipayRefundRequest::try_from(req)?;
        Ok(Some(RequestContent::FormUrlEncoded(Box::new(
            connector_req,
        ))))
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        event_builder: Option<&mut events::Event>,
        res: Response,
    ) -> CustomResult<
        RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        errors::ConnectorError,
    > {
        // HiPay gateway API returns XML responses
        use crate::utils::preprocess_xml_response_bytes;

        let response_bytes = res.response.clone();

        // Convert XML to JSON
        let json_bytes = preprocess_xml_response_bytes(response_bytes.into())
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        // Parse JSON and flatten $text fields
        let json_value: serde_json::Value = serde_json::from_slice(&json_bytes)
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        // Flatten $text fields recursively
        let flattened_value = flatten_text_fields(json_value);

        // Parse as HipayRefundResponse
        let response: HipayRefundResponse = serde_json::from_value(flattened_value)
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        with_response_body!(event_builder, response);

        RouterDataV2::try_from(ResponseRouterData {
            response,
            router_data: data.clone(),
            http_code: res.status_code,
        })
        .change_context(errors::ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut events::Event>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }

    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut events::Event>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

// RSync flow implementation
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
    for Hipay<T>
{
    fn get_http_method(&self) -> Method {
        Method::Get
    }

    fn get_headers(
        &self,
        req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let mut header = vec![(
            headers::CONTENT_TYPE.to_string(),
            self.common_get_content_type().to_string().into(),
        )];
        let mut auth_header = self.get_auth_header(&req.connector_auth_type)?;
        header.append(&mut auth_header);
        Ok(header)
    }


    fn get_url(
        &self,
        req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        let transaction_reference = req.request.connector_refund_id.clone();

        let base_url = self.get_refund_sync_base_url(req);
        Ok(format!(
            "{}/v1/transaction/{}",
            base_url.trim_end_matches('/'),
            transaction_reference
        ))
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        event_builder: Option<&mut events::Event>,
        res: Response,
    ) -> CustomResult<
        RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        errors::ConnectorError,
    > {
        // HiPay gateway API returns XML responses
        use crate::utils::preprocess_xml_response_bytes;

        let response_bytes = res.response.clone();

        // Convert XML to JSON
        let json_bytes = preprocess_xml_response_bytes(response_bytes.into())
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        // RSync responses may have a "transaction" wrapper (success) or be error responses (no wrapper)
        let json_value: serde_json::Value = serde_json::from_slice(&json_bytes)
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        // Check if response has "transaction" wrapper (success case) or is error response
        let value_to_deserialize = if let Some(transaction_value) = json_value.get("transaction") {
            // Success response - flatten $text fields recursively
            flatten_text_fields(transaction_value.clone())
        } else {
            // Error response - use whole JSON (no transaction wrapper)
            flatten_text_fields(json_value)
        };

        // Parse as HipayRSyncResponse (enum handles both Response and Error variants)
        let response: HipayRSyncResponse = serde_json::from_value(value_to_deserialize)
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        with_response_body!(event_builder, response);

        RouterDataV2::try_from(ResponseRouterData {
            response,
            router_data: data.clone(),
            http_code: res.status_code,
        })
        .change_context(errors::ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut events::Event>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }

    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut events::Event>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

// Stub implementations for unsupported flows
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    ConnectorIntegrationV2<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData<T>,
        PaymentsResponseData,
    > for Hipay<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    ConnectorIntegrationV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>
    for Hipay<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    ConnectorIntegrationV2<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for Hipay<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    ConnectorIntegrationV2<
        CreateSessionToken,
        PaymentFlowData,
        SessionTokenRequestData,
        SessionTokenResponseData,
    > for Hipay<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    for Hipay<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
    for Hipay<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
    for Hipay<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    ConnectorIntegrationV2<
        CreateAccessToken,
        PaymentFlowData,
        AccessTokenRequestData,
        AccessTokenResponseData,
    > for Hipay<T>
{
}

// Authentication flow implementations
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    ConnectorIntegrationV2<
        PreAuthenticate,
        PaymentFlowData,
        PaymentsPreAuthenticateData<T>,
        PaymentsResponseData,
    > for Hipay<T>
{
    fn get_headers(
        &self,
        req: &RouterDataV2<
            PreAuthenticate,
            PaymentFlowData,
            PaymentsPreAuthenticateData<T>,
            PaymentsResponseData,
        >,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth = hipay::HipayAuthType::try_from(&req.connector_auth_type)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;

        // HTTP Basic Auth for tokenization API
        let auth_value = if let Some(api_secret) = auth.api_secret {
            use base64::Engine;
            let credentials = format!("{}:{}", auth.api_key.expose(), api_secret.expose());
            let base64_credentials = base64::engine::general_purpose::STANDARD.encode(credentials);
            format!("Basic {}", base64_credentials)
        } else {
            return Err(errors::ConnectorError::FailedToObtainAuthType.into());
        };

        Ok(vec![
            (
                headers::CONTENT_TYPE.to_string(),
                constants::FORM_CONTENT_TYPE.to_string().into(),
            ),
            (headers::AUTHORIZATION.to_string(), auth_value.into()),
        ])
    }


    fn get_url(
        &self,
        req: &RouterDataV2<
            PreAuthenticate,
            PaymentFlowData,
            PaymentsPreAuthenticateData<T>,
            PaymentsResponseData,
        >,
    ) -> CustomResult<String, errors::ConnectorError> {
        let base_url = self.get_tokenization_base_url(req);
        Ok(format!("{}/create", base_url.trim_end_matches('/')))
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<
            PreAuthenticate,
            PaymentFlowData,
            PaymentsPreAuthenticateData<T>,
            PaymentsResponseData,
        >,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let connector_req = HipayTokenRequest::try_from(req)?;
        Ok(Some(RequestContent::FormUrlEncoded(Box::new(
            connector_req,
        ))))
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<
            PreAuthenticate,
            PaymentFlowData,
            PaymentsPreAuthenticateData<T>,
            PaymentsResponseData,
        >,
        event_builder: Option<&mut events::Event>,
        res: Response,
    ) -> CustomResult<
        RouterDataV2<
            PreAuthenticate,
            PaymentFlowData,
            PaymentsPreAuthenticateData<T>,
            PaymentsResponseData,
        >,
        errors::ConnectorError,
    > {
        // HiPay tokenization API returns XML responses
        use crate::utils::preprocess_xml_response_bytes;

        let response_bytes = res.response.clone();

        // Convert XML to JSON
        let json_bytes = preprocess_xml_response_bytes(response_bytes.into())
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        // Parse as HipayTokenResponse
        let response: HipayTokenResponse = serde_json::from_slice(&json_bytes)
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        with_response_body!(event_builder, response);

        RouterDataV2::try_from(ResponseRouterData {
            response,
            router_data: data.clone(),
            http_code: res.status_code,
        })
        .change_context(errors::ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut events::Event>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        // HiPay tokenization API returns XML errors
        use crate::utils::preprocess_xml_response_bytes;

        let response_bytes = res.response.clone();

        // Check if response is XML
        if let Ok(response_str) = std::str::from_utf8(&response_bytes) {
            if response_str.trim().starts_with("<?xml") {
                // Convert XML to JSON
                let json_bytes = preprocess_xml_response_bytes(response_bytes.into())
                    .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

                // Parse as HipayErrorResponse
                let error_response: hipay::HipayErrorResponse = serde_json::from_slice(&json_bytes)
                    .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

                with_error_response_body!(event_builder, error_response);

                return Ok(ErrorResponse {
                    status_code: res.status_code,
                    code: error_response.code,
                    message: error_response.message,
                    reason: None,
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                });
            }
        }

        // Fallback to regular JSON error parsing
        self.build_error_response(res, event_builder)
    }
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    ConnectorIntegrationV2<
        Authenticate,
        PaymentFlowData,
        PaymentsAuthenticateData<T>,
        PaymentsResponseData,
    > for Hipay<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    ConnectorIntegrationV2<
        PostAuthenticate,
        PaymentFlowData,
        PaymentsPostAuthenticateData<T>,
        PaymentsResponseData,
    > for Hipay<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    ConnectorIntegrationV2<
        domain_types::connector_flow::CreateConnectorCustomer,
        PaymentFlowData,
        ConnectorCustomerData,
        ConnectorCustomerResponse,
    > for Hipay<T>
{
}

// SourceVerification implementations for all flows
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    interfaces::verification::SourceVerification<
        Authorize,
        PaymentFlowData,
        PaymentsAuthorizeData<T>,
        PaymentsResponseData,
    > for Hipay<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    interfaces::verification::SourceVerification<
        CreateSessionToken,
        PaymentFlowData,
        SessionTokenRequestData,
        SessionTokenResponseData,
    > for Hipay<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    interfaces::verification::SourceVerification<
        CreateAccessToken,
        PaymentFlowData,
        AccessTokenRequestData,
        AccessTokenResponseData,
    > for Hipay<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    interfaces::verification::SourceVerification<
        domain_types::connector_flow::CreateConnectorCustomer,
        PaymentFlowData,
        ConnectorCustomerData,
        ConnectorCustomerResponse,
    > for Hipay<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    interfaces::verification::SourceVerification<
        PSync,
        PaymentFlowData,
        PaymentsSyncData,
        PaymentsResponseData,
    > for Hipay<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    interfaces::verification::SourceVerification<
        Capture,
        PaymentFlowData,
        PaymentsCaptureData,
        PaymentsResponseData,
    > for Hipay<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    interfaces::verification::SourceVerification<
        Void,
        PaymentFlowData,
        PaymentVoidData,
        PaymentsResponseData,
    > for Hipay<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    interfaces::verification::SourceVerification<
        Refund,
        RefundFlowData,
        RefundsData,
        RefundsResponseData,
    > for Hipay<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    interfaces::verification::SourceVerification<
        RSync,
        RefundFlowData,
        RefundSyncData,
        RefundsResponseData,
    > for Hipay<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    interfaces::verification::SourceVerification<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData<T>,
        PaymentsResponseData,
    > for Hipay<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    interfaces::verification::SourceVerification<
        Accept,
        DisputeFlowData,
        AcceptDisputeData,
        DisputeResponseData,
    > for Hipay<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    interfaces::verification::SourceVerification<
        SubmitEvidence,
        DisputeFlowData,
        SubmitEvidenceData,
        DisputeResponseData,
    > for Hipay<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    interfaces::verification::SourceVerification<
        DefendDispute,
        DisputeFlowData,
        DisputeDefendData,
        DisputeResponseData,
    > for Hipay<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    interfaces::verification::SourceVerification<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for Hipay<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    interfaces::verification::SourceVerification<
        PaymentMethodToken,
        PaymentFlowData,
        PaymentMethodTokenizationData<T>,
        PaymentMethodTokenResponse,
    > for Hipay<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    interfaces::verification::SourceVerification<
        PreAuthenticate,
        PaymentFlowData,
        PaymentsPreAuthenticateData<T>,
        PaymentsResponseData,
    > for Hipay<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    interfaces::verification::SourceVerification<
        Authenticate,
        PaymentFlowData,
        PaymentsAuthenticateData<T>,
        PaymentsResponseData,
    > for Hipay<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    interfaces::verification::SourceVerification<
        PostAuthenticate,
        PaymentFlowData,
        PaymentsPostAuthenticateData<T>,
        PaymentsResponseData,
    > for Hipay<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    interfaces::verification::SourceVerification<
        VoidPC,
        PaymentFlowData,
        PaymentsCancelPostCaptureData,
        PaymentsResponseData,
    > for Hipay<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    interfaces::verification::SourceVerification<
        RepeatPayment,
        PaymentFlowData,
        RepeatPaymentData,
        PaymentsResponseData,
    > for Hipay<T>
{
}
