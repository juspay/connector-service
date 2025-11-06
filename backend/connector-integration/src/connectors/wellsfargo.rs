pub mod transformers;

use base64::Engine;
use common_enums::CurrencyUnit;
use common_utils::{
    errors::CustomResult, ext_traits::ByteSliceExt,
    consts::{NO_ERROR_CODE, NO_ERROR_MESSAGE},
    request::{Method, Request, RequestBuilder, RequestContent},
    };
use time::OffsetDateTime;
use url::Url;
use domain_types::{
    connector_flow::{
        Accept, Authenticate, Authorize, Capture, CreateAccessToken, CreateConnectorCustomer,
        CreateOrder, DefendDispute, PaymentMethodToken, PostAuthenticate, PreAuthenticate,
        PSync, RSync, Refund, RepeatPayment, SetupMandate, SubmitEvidence, Void, VoidPC,
        CreateSessionToken,
    },
    connector_types::{
        AcceptDisputeData, AccessTokenRequestData, AccessTokenResponseData,
        ConnectorCustomerData, ConnectorCustomerResponse, DisputeDefendData, DisputeFlowData,
        DisputeResponseData, PaymentCreateOrderData, PaymentCreateOrderResponse,
        PaymentFlowData, PaymentMethodTokenizationData, PaymentMethodTokenResponse,
        PaymentVoidData, PaymentsAuthenticateData, PaymentsAuthorizeData,
        PaymentsCancelPostCaptureData, PaymentsCaptureData, PaymentsPostAuthenticateData,
        PaymentsPreAuthenticateData, PaymentsResponseData, PaymentsSyncData, RefundFlowData,
        RefundSyncData, RefundsData, RefundsResponseData, RepeatPaymentData,
        SetupMandateRequestData, SubmitEvidenceData, SessionTokenRequestData,
        SessionTokenResponseData,
    },
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
};
use serde::Serialize;
use std::fmt::Debug;
use hyperswitch_masking::{ExposeInterface, Mask, Maskable, PeekInterface};
use interfaces::{
    api::ConnectorCommon, connector_integration_v2::ConnectorIntegrationV2, connector_types,
    events::connector_api_logs::ConnectorEvent,
};
use transformers::{
    self as wellsfargo, WellsfargoCaptureRequest, WellsfargoPaymentsRequest,
    WellsfargoPaymentsResponse,
};

use super::macros;
use crate::{types::ResponseRouterData, with_error_response_body};

pub const BASE64_ENGINE: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

use error_stack::{Report, ResultExt};

// Trait implementations with generic type parameters
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentPostAuthenticateV2<T> for Wellsfargo<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAuthenticateV2<T> for Wellsfargo<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentPreAuthenticateV2<T> for Wellsfargo<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentVoidPostCaptureV2 for Wellsfargo<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentTokenV2<T> for Wellsfargo<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::CreateConnectorCustomer for Wellsfargo<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAccessToken for Wellsfargo<T>
{
}

// Empty SourceVerification implementations for unimplemented flows
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<Authenticate, PaymentFlowData, PaymentsAuthenticateData<T>, PaymentsResponseData>
    for Wellsfargo<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<PostAuthenticate, PaymentFlowData, PaymentsPostAuthenticateData<T>, PaymentsResponseData>
    for Wellsfargo<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<PreAuthenticate, PaymentFlowData, PaymentsPreAuthenticateData<T>, PaymentsResponseData>
    for Wellsfargo<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<VoidPC, PaymentFlowData, PaymentsCancelPostCaptureData, PaymentsResponseData>
    for Wellsfargo<T>
{
}

// Empty ConnectorIntegrationV2 implementations for unimplemented flows
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Authenticate, PaymentFlowData, PaymentsAuthenticateData<T>, PaymentsResponseData>
    for Wellsfargo<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<PostAuthenticate, PaymentFlowData, PaymentsPostAuthenticateData<T>, PaymentsResponseData>
    for Wellsfargo<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<PreAuthenticate, PaymentFlowData, PaymentsPreAuthenticateData<T>, PaymentsResponseData>
    for Wellsfargo<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<VoidPC, PaymentFlowData, PaymentsCancelPostCaptureData, PaymentsResponseData>
    for Wellsfargo<T>
{
}

// Additional empty implementations for token, customer, and access token flows
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<PaymentMethodToken, PaymentFlowData, PaymentMethodTokenizationData<T>, PaymentMethodTokenResponse>
    for Wellsfargo<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<PaymentMethodToken, PaymentFlowData, PaymentMethodTokenizationData<T>, PaymentMethodTokenResponse>
    for Wellsfargo<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<CreateConnectorCustomer, PaymentFlowData, ConnectorCustomerData, ConnectorCustomerResponse>
    for Wellsfargo<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<CreateConnectorCustomer, PaymentFlowData, ConnectorCustomerData, ConnectorCustomerResponse>
    for Wellsfargo<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<CreateAccessToken, PaymentFlowData, AccessTokenRequestData, AccessTokenResponseData>
    for Wellsfargo<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<CreateAccessToken, PaymentFlowData, AccessTokenRequestData, AccessTokenResponseData>
    for Wellsfargo<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ConnectorServiceTrait<T> for Wellsfargo<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAuthorizeV2<T> for Wellsfargo<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentSyncV2 for Wellsfargo<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentVoidV2 for Wellsfargo<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundSyncV2 for Wellsfargo<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundV2 for Wellsfargo<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentCapture for Wellsfargo<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ValidationTrait for Wellsfargo<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentOrderCreate for Wellsfargo<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::SetupMandateV2<T> for Wellsfargo<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RepeatPaymentV2 for Wellsfargo<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::AcceptDispute for Wellsfargo<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::SubmitEvidenceV2 for Wellsfargo<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::DisputeDefend for Wellsfargo<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::IncomingWebhook for Wellsfargo<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentSessionToken for Wellsfargo<T>
{
}

pub(crate) mod headers {
    pub(crate) const ACCEPT: &str = "Accept";
    pub(crate) const API_KEY: &str = "API-KEY";
    pub(crate) const APIKEY: &str = "apikey";
    pub(crate) const API_TOKEN: &str = "Api-Token";
    pub(crate) const AUTHORIZATION: &str = "Authorization";
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const DATE: &str = "Date";
    pub(crate) const IDEMPOTENCY_KEY: &str = "Idempotency-Key";
    pub(crate) const MESSAGE_SIGNATURE: &str = "Message-Signature";
    pub(crate) const MERCHANT_ID: &str = "Merchant-ID";
    pub(crate) const REQUEST_ID: &str = "request-id";
    pub(crate) const NONCE: &str = "nonce";
    pub(crate) const TIMESTAMP: &str = "Timestamp";
    pub(crate) const TOKEN: &str = "token";
    pub(crate) const X_ACCEPT_VERSION: &str = "X-Accept-Version";
    pub(crate) const X_CC_API_KEY: &str = "X-CC-Api-Key";
    pub(crate) const X_CC_VERSION: &str = "X-CC-Version";
    pub(crate) const X_DATE: &str = "X-Date";
    pub(crate) const X_LOGIN: &str = "X-Login";
    pub(crate) const X_NN_ACCESS_KEY: &str = "X-NN-Access-Key";
    pub(crate) const X_TRANS_KEY: &str = "X-Trans-Key";
    pub(crate) const X_RANDOM_VALUE: &str = "X-RandomValue";
    pub(crate) const X_REQUEST_DATE: &str = "X-RequestDate";
    pub(crate) const X_VERSION: &str = "X-Version";
    pub(crate) const X_API_KEY: &str = "X-Api-Key";
    pub(crate) const CORRELATION_ID: &str = "Correlation-Id";
    pub(crate) const WP_API_VERSION: &str = "WP-Api-Version";
    pub(crate) const STRIPE_COMPATIBLE_CONNECT_ACCOUNT: &str = "Stripe-Account";
    pub(crate) const SOURCE: &str = "Source";
    pub(crate) const USER_AGENT: &str = "User-Agent";
    pub(crate) const KEY: &str = "key";
    pub(crate) const X_SIGNATURE: &str = "X-Signature";
    pub(crate) const SOAP_ACTION: &str = "SOAPAction";
    pub(crate) const X_PROFILE_ID: &str = "X-Profile-Id";
}

macros::create_all_prerequisites!(
    connector_name: Wellsfargo,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: WellsfargoPaymentsRequest<T>,
            response_body: WellsfargoPaymentsResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        )
    ],
    amount_converters: [],
    member_functions: {
        fn generate_digest(&self, payload: &[u8]) -> String {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(payload);
            BASE64_ENGINE.encode(hasher.finalize())
        }

        fn generate_signature(
            &self,
            auth: transformers::WellsfargoAuthType,
            host: String,
            resource: &str,
            payload: &str,
            date: OffsetDateTime,
            http_method: Method,
        ) -> CustomResult<String, errors::ConnectorError> {
            let api_key = auth.api_key.expose();
            let api_secret = auth.api_secret.expose();
            let merchant_id = auth.merchant_account.expose();

            let is_post_method = matches!(http_method, Method::Post);
            let is_patch_method = matches!(http_method, Method::Patch);
            let digest_str = if is_post_method || is_patch_method {
                "digest "
            } else {
                ""
            };

            let headers_str = format!("host date (request-target) {digest_str}v-c-merchant-id");

            let request_target = if is_post_method {
                format!("(request-target): post {resource}\ndigest: SHA-256={payload}\n")
            } else if is_patch_method {
                format!("(request-target): patch {resource}\ndigest: SHA-256={payload}\n")
            } else {
                format!("(request-target): get {resource}\n")
            };

            let signature_string = format!(
                "host: {host}\ndate: {date}\n{request_target}v-c-merchant-id: {merchant_id}"
            );

            // Decode the base64-encoded API secret before using it for HMAC
            let key_value = BASE64_ENGINE
                .decode(api_secret.as_bytes())
                .change_context(errors::ConnectorError::InvalidConnectorConfig {
                    config: "connector_account_details.api_secret",
                })?;

            // Use ring::hmac for HMAC-SHA256
            let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key_value);
            let signature = ring::hmac::sign(&key, signature_string.as_bytes());
            let signature_value = BASE64_ENGINE.encode(signature.as_ref());

            Ok(format!(
                r#"keyid="{api_key}", algorithm="HmacSHA256", headers="{headers_str}", signature="{signature_value}""#
            ))
        }

        pub fn build_headers<F, Req, Res>(
            &self,
            req: &RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError>
        where
            Self: ConnectorIntegrationV2<F, PaymentFlowData, Req, Res>,
        {
            let date = OffsetDateTime::now_utc();
            let auth = transformers::WellsfargoAuthType::try_from(&req.connector_auth_type)?;
            let merchant_account = auth.merchant_account.clone().expose();

            let base_url = &req.resource_common_data.connectors.wellsfargo.base_url;
            let wellsfargo_host = Url::parse(base_url)
                .change_context(errors::ConnectorError::RequestEncodingFailed)?;
            let host = wellsfargo_host
                .host_str()
                .ok_or(errors::ConnectorError::RequestEncodingFailed)?;

            // Get the request body for digest calculation
            let request_body = self.get_request_body(req)?;
            let sha256 = if let Some(body) = request_body {
                let body_string = body.get_inner_value();
                self.generate_digest(body_string.expose().as_bytes())
            } else {
                String::new()
            };

            // Get URL path
            let url = self.get_url(req)?;
            let path: String = url.chars().skip(base_url.len() - 1).collect();

            let http_method = self.get_http_method();
            let signature = self.generate_signature(
                auth,
                host.to_string(),
                &path,
                &sha256,
                date,
                http_method,
            )?;

            let mut headers = vec![
                (
                    headers::CONTENT_TYPE.to_string(),
                    self.get_content_type().to_string().into(),
                ),
                (
                    headers::ACCEPT.to_string(),
                    "application/hal+json;charset=utf-8".to_string().into(),
                ),
                ("v-c-merchant-id".to_string(), merchant_account.into_masked()),
                ("Date".to_string(), date.to_string().into()),
                ("Host".to_string(), host.to_string().into()),
                ("Signature".to_string(), signature.into_masked()),
            ];

            if matches!(http_method, Method::Post | Method::Put | Method::Patch) {
                headers.push((
                    "Digest".to_string(),
                    format!("SHA-256={sha256}").into_masked(),
                ));
            }

            Ok(headers)
        }

        pub fn connector_base_url_payments<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.wellsfargo.base_url
        }

        pub fn connector_base_url_refunds<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, RefundFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.wellsfargo.base_url
        }
    }
);

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> ConnectorCommon
    for Wellsfargo<T>
{
    fn id(&self) -> &'static str {
        "wellsfargo"
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/json;charset=utf-8"
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.wellsfargo.base_url.as_ref()
    }

    fn get_currency_unit(&self) -> CurrencyUnit {
        CurrencyUnit::Base
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: Result<
            wellsfargo::WellsfargoErrorResponse,
            Report<common_utils::errors::ParsingError>,
        > = res.response.parse_struct("Wellsfargo ErrorResponse");

        let error_message = if res.status_code == 401 {
            "Authentication failed"
        } else {
            NO_ERROR_MESSAGE
        };
        match response {
            Ok(transformers::WellsfargoErrorResponse::StandardError(response)) => {
                with_error_response_body!(event_builder, response);

                let (code, message, reason) = match response.error_information {
                    Some(ref error_info) => {
                        let detailed_error_info = error_info.details.as_ref().map(|details| {
                            details
                                .iter()
                                .map(|det| {
                                    let field = det.field.as_deref().unwrap_or("unknown");
                                    let reason = det.reason.as_deref().unwrap_or("unknown");
                                    format!("{} : {}", field, reason)
                                })
                                .collect::<Vec<_>>()
                                .join(", ")
                        });
                        (
                            error_info.reason.clone().unwrap_or_else(|| NO_ERROR_CODE.to_string()),
                            error_info.message.clone().unwrap_or_else(|| error_message.to_string()),
                            detailed_error_info.unwrap_or_else(|| error_message.to_string()),
                        )
                    }
                    None => {
                        let detailed_error_info = response.details.as_ref().map(|details| {
                            details
                                .iter()
                                .map(|det| {
                                    let field = det.field.as_deref().unwrap_or("unknown");
                                    let reason = det.reason.as_deref().unwrap_or("unknown");
                                    format!("{} : {}", field, reason)
                                })
                                .collect::<Vec<_>>()
                                .join(", ")
                        });
                        (
                            response.reason.clone().unwrap_or_else(|| NO_ERROR_CODE.to_string()),
                            response.message.clone().unwrap_or_else(|| error_message.to_string()),
                            detailed_error_info.unwrap_or_else(|| error_message.to_string()),
                        )
                    }
                };

                Ok(ErrorResponse {
                    status_code: res.status_code,
                    code,
                    message,
                    reason: Some(reason),
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                })
            }
            Ok(transformers::WellsfargoErrorResponse::NotAvailableError(response)) => {
                event_builder.map(|i| i.set_error_response_body(&response));
                tracing::info!(connector_response=?response);
                let error_response = response
                    .errors
                    .iter()
                    .filter_map(|error_info| error_info.message.clone())
                    .collect::<Vec<String>>()
                    .join(" & ");
                Ok(ErrorResponse {
                    status_code: res.status_code,
                    code: NO_ERROR_CODE.to_string(),
                    message: error_response.clone(),
                    reason: Some(error_response),
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                })
            }
            Err(error_msg) => {
                event_builder.map(|event| event.set_error(serde_json::json!({"error": res.response.escape_ascii().to_string(), "status_code": res.status_code})));
                tracing::error!(deserialization_error =? error_msg);
                domain_types::utils::handle_json_response_deserialization_failure(res, "wellsfargo")
            }
        }
    }
}

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Wellsfargo,
    curl_request: Json(WellsfargoPaymentsRequest),
    curl_response: WellsfargoPaymentsResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            Ok(format!(
                "{}pts/v2/payments/",
                self.connector_base_url_payments(req)
            ))
        }
    }
);

// Capture implementation - POST request to capture authorized payment
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
    for Wellsfargo<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
    for Wellsfargo<T>
{
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
        let connector_payment_id = req.request
            .connector_transaction_id
            .get_connector_transaction_id()
            .change_context(errors::ConnectorError::MissingConnectorTransactionID)?;

        Ok(format!(
            "{}pts/v2/payments/{}/captures",
            self.connector_base_url_payments(req),
            connector_payment_id
        ))
    }

    fn get_http_method(&self) -> Method {
        Method::Post
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let wellsfargo_req = WellsfargoCaptureRequest::try_from(req)?;
        Ok(Some(RequestContent::Json(Box::new(wellsfargo_req))))
    }

    fn build_request_v2(
        &self,
        req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        let wellsfargo_req = WellsfargoCaptureRequest::try_from(req)?;

        Ok(Some(
            RequestBuilder::new()
                .method(Method::Post)
                .url(&self.get_url(req)?)
                .attach_default_headers()
                .headers(self.get_headers(req)?)
                .set_body(RequestContent::Json(Box::new(wellsfargo_req)))
                .build(),
        ))
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>, errors::ConnectorError> {
        let response: wellsfargo::WellsfargoPaymentsResponse = res
            .response
            .parse_struct("WellsfargoPaymentsResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        event_builder.map(|i| i.set_response_body(&response));
        RouterDataV2::try_from(ResponseRouterData {
            response,
            router_data: data.clone(),
            http_code: res.status_code,
        })
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

// PSync (Payment Sync) implementation - GET request, no request body
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    for Wellsfargo<T>
{
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
        let connector_payment_id = req.request
            .connector_transaction_id
            .get_connector_transaction_id()
            .change_context(errors::ConnectorError::MissingConnectorTransactionID)?;

        Ok(format!(
            "{}pts/v2/payments/{}",
            self.connector_base_url_payments(req),
            connector_payment_id
        ))
    }

    fn get_http_method(&self) -> Method {
        Method::Get
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn build_request_v2(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Get)
                .url(&self.get_url(req)?)
                .attach_default_headers()
                .headers(self.get_headers(req)?)
                .build(),
        ))
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, errors::ConnectorError> {
        let response: wellsfargo::WellsfargoPaymentsResponse = res
            .response
            .parse_struct("WellsfargoPaymentsResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        event_builder.map(|i| i.set_response_body(&response));
        RouterDataV2::try_from(ResponseRouterData {
            response,
            router_data: data.clone(),
            http_code: res.status_code,
        })
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
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
    > ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
    for Wellsfargo<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
    for Wellsfargo<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
    for Wellsfargo<T>
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
    > for Wellsfargo<T>
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
    for Wellsfargo<T>
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
    for Wellsfargo<T>
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
    for Wellsfargo<T>
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
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData<T>,
        PaymentsResponseData,
    > for Wellsfargo<T>
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
    for Wellsfargo<T>
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
    > for Wellsfargo<T>
{
}

// SourceVerification implementations for all flows
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        Authorize,
        PaymentFlowData,
        PaymentsAuthorizeData<T>,
        PaymentsResponseData,
    > for Wellsfargo<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        PSync,
        PaymentFlowData,
        PaymentsSyncData,
        PaymentsResponseData,
    > for Wellsfargo<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        Void,
        PaymentFlowData,
        PaymentVoidData,
        PaymentsResponseData,
    > for Wellsfargo<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        Refund,
        RefundFlowData,
        RefundsData,
        RefundsResponseData,
    > for Wellsfargo<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        RSync,
        RefundFlowData,
        RefundSyncData,
        RefundsResponseData,
    > for Wellsfargo<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData<T>,
        PaymentsResponseData,
    > for Wellsfargo<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        Accept,
        DisputeFlowData,
        AcceptDisputeData,
        DisputeResponseData,
    > for Wellsfargo<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        SubmitEvidence,
        DisputeFlowData,
        SubmitEvidenceData,
        DisputeResponseData,
    > for Wellsfargo<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        DefendDispute,
        DisputeFlowData,
        DisputeDefendData,
        DisputeResponseData,
    > for Wellsfargo<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for Wellsfargo<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        RepeatPayment,
        PaymentFlowData,
        RepeatPaymentData,
        PaymentsResponseData,
    > for Wellsfargo<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        CreateSessionToken,
        PaymentFlowData,
        SessionTokenRequestData,
        SessionTokenResponseData,
    > for Wellsfargo<T>
{
}
