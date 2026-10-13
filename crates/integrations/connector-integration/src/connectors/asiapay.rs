//! AsiaPay (PayDollar) — cards-only hosted-page integration.
//!
//! Authorize is the Web-Integration "Direct Client Side Connection" post of
//! the card + order fields to the hosted payment page `payForm.jsp`; the
//! gateway answers with a redirect or an HTML page (plan UD-01: the post is
//! executed server side and the outcome is surfaced as a pending/redirect
//! state). PSync and the other sync/refund units use the merchant API
//! (`orderApi.jsp`, form-encoded POST; the Query answer is XML). Credentials
//! travel as form fields — there is no HTTP auth header
//! (spec:## Authentication).

pub mod transformers;

use std::fmt::Debug;

use common_utils::{errors::CustomResult, events, types::StringMajorUnit};
use error_stack::ResultExt;

use crate::types::ResponseRouterData;
use domain_types::{
    connector_flow::{Authorize, PSync, RSync, Refund},
    connector_types::{
        PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData,
        RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData,
    },
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorSpecificConfig, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
};
use hyperswitch_masking::Maskable;
use interfaces::{
    api::ConnectorCommon, connector_integration_v2::ConnectorIntegrationV2, connector_types,
    decode::BodyDecoding, verification::SourceVerification,
};
use serde::Serialize;

use self::transformers::{
    AsiapayAuthorizeResponse, AsiapayError, AsiapayPSyncRequest, AsiapayPaymentsRequest,
    AsiapayQueryResponse, AsiapayRSyncRequest, AsiapayRSyncResponse, AsiapayRefundRequest,
    AsiapayRefundResponse,
};
use super::macros;

pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> ConnectorCommon
    for Asiapay<T>
{
    fn id(&self) -> &'static str {
        "asiapay"
    }

    fn get_currency_unit(&self) -> common_enums::CurrencyUnit {
        // StringMajorUnit — wire amounts are decimal major-unit strings.
        common_enums::CurrencyUnit::Base
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/x-www-form-urlencoded"
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.asiapay.base_url.as_ref()
    }

    /// No HTTP auth header on purpose: the payment page authenticates by the
    /// `merchantId` form field (plus `secureHash` when enabled on the
    /// account), the merchant API by `merchantId`/`loginId`/`password` form
    /// fields (spec:## Authentication).
    fn get_auth_header(
        &self,
        _auth_type: &ConnectorSpecificConfig,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, domain_types::errors::IntegrationError> {
        Ok(vec![])
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut events::Event>,
        _connector_config: &ConnectorSpecificConfig,
    ) -> CustomResult<ErrorResponse, domain_types::errors::ConnectorError> {
        // Non-2xx/5xx bodies: either the merchant-API URL-encoded failure
        // shape (resultCode/errMsg) or an HTML error page. Both are parsed
        // leniently — a transport failure must say HTTP-status-mostly, not
        // become a deserialization failure of its own.
        let body = String::from_utf8_lossy(res.response.as_ref()).to_string();
        let mut response = AsiapayError::from_form_encoded(&body);
        if response.is_empty() {
            response.err_msg = extract_error_message(&body);
        }

        crate::with_error_response_body!(event_builder, response);

        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response
                .result_code
                .clone()
                .unwrap_or_else(|| common_utils::consts::NO_ERROR_CODE.to_string()),
            message: response
                .err_msg
                .clone()
                .unwrap_or_else(|| common_utils::consts::NO_ERROR_MESSAGE.to_string()),
            reason: response.err_msg.clone(),
            // AsiaPay answers HTTP 200 on the documented paths; a non-2xx
            // here proves transport, not a terminal attempt state.
            attempt_status: None,
            connector_transaction_id: None,
            network_advice_code: None,
            network_decline_code: None,
            network_error_message: None,
            typed_connector_response: macros::serialize_typed_connector_payload(
                &response,
                "typed_connector_response",
            ),
            raw_connector_response: None,
            raw_connector_request: None,
            typed_connector_request: None,
        })
    }
}

/// Pull the human-readable reason out of the gateway's HTML error page
/// (`Error Message  Parameter currCode Incorrect`). Returns `None` when the
/// marker phrase is absent — i.e. the page is the hosted channel page.
fn extract_error_message(body: &str) -> Option<String> {
    let idx = body.find("Error Message")?;
    let tail = &body[idx + "Error Message".len()..];
    let cleaned: String = tail
        .trim_start_matches(|c: char| c.is_whitespace() || c == ':')
        .chars()
        .take_while(|c| *c != '<' && *c != '\n' && *c != '\r')
        .collect();
    let message = cleaned.trim();
    if message.is_empty() {
        None
    } else {
        Some(message.to_string())
    }
}

// ---------------------------------------------------------------------------
// Response preprocessing — the gateway answers, depending on the channel,
// with (a) an XML Query record (merchant API, PSync/RSync), (b) a URL-encoded
// merchant-API failure (`resultCode=-1&errMsg=…`), (c) an HTML page (hosted
// channel page, or the parameter-error page), or (d) an empty 3xx body. The
// macro bridge deserializes with serde_json, so each body kind is converted
// here into the JSON shape its response struct models.
// ---------------------------------------------------------------------------
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> Asiapay<T> {
    pub fn preprocess_response_bytes<F, FCD, Req, Res>(
        &self,
        _req: &RouterDataV2<F, FCD, Req, Res>,
        bytes: bytes::Bytes,
        status_code: u16,
    ) -> CustomResult<bytes::Bytes, domain_types::errors::IntegrationError> {
        if bytes.is_empty() {
            // 3xx redirect with no body; the pending state is all there is to
            // report (the macro bridge parses an empty body as `{}`).
            return Ok(bytes);
        }

        let body = String::from_utf8(bytes.to_vec()).change_context(
            domain_types::errors::IntegrationError::InvalidDataFormat {
                field_name: "response_body",
                context: domain_types::errors::IntegrationErrorContext {
                    suggested_action: None,
                    doc_url: None,
                    additional_context: Some(format!(
                    "asiapay: payment-page response body is not valid UTF-8 (HTTP {status_code})"
                )),
                },
            },
        )?;

        let trimmed = body.trim_start();
        let synthesized = if trimmed.starts_with("<?xml") {
            // Merchant-API Query answer (spec:## Payment Status (PSync —
            // Merchant API)): XML → JSON of the first <record>.
            return transformers::query_xml_to_json(trimmed).map_err(|report| {
                report.change_context(domain_types::errors::IntegrationError::InvalidDataFormat {
                    field_name: "response_body",
                    context: domain_types::errors::IntegrationErrorContext {
                        suggested_action: None,
                        doc_url: None,
                        additional_context: Some(format!(
                            "asiapay: Query XML parse failed (HTTP {status_code})"
                        )),
                    },
                })
            });
        } else if !trimmed.starts_with('<') && trimmed.contains('=') {
            // Merchant-API auth/parameter failure is URL-encoded
            // (`resultCode=-1&errMsg=Parameter Merchant Id Incorrect`; probe
            // evidence in run:test/capabilities.json), and Refund responses
            // are URL-encoded (`resultCode=0&orderStatus=Voided&payRef=...`).
            // Convert all key=value pairs into a JSON object so that both
            // AsiapayQueryResponse and AsiapayRefundResponse can deserialize.
            let mut map = serde_json::Map::new();
            for pair in trimmed.split('&') {
                if let Some((key, value)) = pair.split_once('=') {
                    map.insert(
                        key.trim().to_string(),
                        serde_json::Value::String(value.trim().to_string()),
                    );
                }
            }
            serde_json::Value::Object(map)
        } else if let Some(error_message) = extract_error_message(&body) {
            serde_json::json!({ "error_message": error_message })
        } else {
            serde_json::json!({ "html_body": body })
        };

        Ok(bytes::Bytes::from(synthesized.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Marker traits — Authorize and PSync are the implemented flows; every other
// flow's marker + stub comes from macro_connector_flow_status_impls or the
// shared default-implementations lists.
// ---------------------------------------------------------------------------
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ConnectorServiceTrait<T> for Asiapay<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAuthorizeV2<T> for Asiapay<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentSyncV2 for Asiapay<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundV2 for Asiapay<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundSyncV2 for Asiapay<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ValidationTrait for Asiapay<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::IncomingWebhook for Asiapay<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::VerifyRedirectResponse for Asiapay<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> SourceVerification
    for Asiapay<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> BodyDecoding
    for Asiapay<T>
{
}

macros::create_all_prerequisites!(
    connector_name: Asiapay,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: AsiapayPaymentsRequest<T>,
            response_body: AsiapayAuthorizeResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: PSync,
            request_body: AsiapayPSyncRequest,
            response_body: AsiapayQueryResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ),
        (
            flow: Refund,
            request_body: AsiapayRefundRequest,
            response_body: AsiapayRefundResponse,
            router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ),
        (
            flow: RSync,
            request_body: AsiapayRSyncRequest,
            response_body: AsiapayRSyncResponse,
            router_data: RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        )
    ],
    amount_converters: [
        amount_converter: StringMajorUnit
    ],
    member_functions: {
        pub fn build_headers<F, FCD, Req, Res>(
            &self,
            req: &RouterDataV2<F, FCD, Req, Res>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, domain_types::errors::IntegrationError>
        where
            Self: ConnectorIntegrationV2<F, FCD, Req, Res>,
        {
            let mut header = vec![(
                headers::CONTENT_TYPE.to_string(),
                self.get_content_type().to_string().into(),
            )];
            let mut auth_headers = self.get_auth_header(&req.connector_config)?;
            header.append(&mut auth_headers);
            Ok(header)
        }

        pub fn connector_base_url_payments<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.asiapay.base_url
        }

        pub fn connector_base_url_refunds<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, RefundFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.asiapay.base_url
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Asiapay,
    curl_request: FormUrlEncoded(AsiapayPaymentsRequest),
    curl_response: AsiapayAuthorizeResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    preprocess_response: true,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, domain_types::errors::IntegrationError> {
            self.build_headers(req)
        }

        fn get_url(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<String, domain_types::errors::IntegrationError> {
            Ok(format!(
                "{}/b2cDemo/eng/payment/payForm.jsp",
                self.connector_base_url_payments(req)
            ))
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Asiapay,
    curl_request: FormUrlEncoded(AsiapayPSyncRequest),
    curl_response: AsiapayQueryResponse,
    flow_name: PSync,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsSyncData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    preprocess_response: true,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, domain_types::errors::IntegrationError> {
            self.build_headers(req)
        }

        fn get_url(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<String, domain_types::errors::IntegrationError> {
            Ok(format!(
                "{}/b2cDemo/eng/merchant/api/orderApi.jsp",
                self.connector_base_url_payments(req)
            ))
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Asiapay,
    curl_request: FormUrlEncoded(AsiapayRefundRequest),
    curl_response: AsiapayRefundResponse,
    flow_name: Refund,
    resource_common_data: RefundFlowData,
    flow_request: RefundsData,
    flow_response: RefundsResponseData,
    http_method: Post,
    preprocess_response: true,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, domain_types::errors::IntegrationError> {
            self.build_headers(req)
        }

        fn get_url(
            &self,
            req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ) -> CustomResult<String, domain_types::errors::IntegrationError> {
            Ok(format!(
                "{}/b2cDemo/eng/merchant/api/orderApi.jsp",
                self.connector_base_url_refunds(req)
            ))
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Asiapay,
    curl_request: FormUrlEncoded(AsiapayRSyncRequest),
    curl_response: AsiapayRSyncResponse,
    flow_name: RSync,
    resource_common_data: RefundFlowData,
    flow_request: RefundSyncData,
    flow_response: RefundsResponseData,
    http_method: Post,
    preprocess_response: true,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, domain_types::errors::IntegrationError> {
            self.build_headers(req)
        }

        fn get_url(
            &self,
            req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ) -> CustomResult<String, domain_types::errors::IntegrationError> {
            Ok(format!(
                "{}/b2cDemo/eng/merchant/api/orderApi.jsp",
                self.connector_base_url_refunds(req)
            ))
        }
    }
);

macros::macro_connector_flow_status_impls!(
    connector: Asiapay,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    not_implemented: [
        Capture,
        Void,
        SetupMandate,
        RepeatPayment,
        ClientAuthenticationToken,
        IncrementalAuthorization,
        CreateOrder,
        CreateConnectorCustomer,
        GetConnectorCustomer,
        MandateRevoke,
        PaymentMethodToken,
        PreAuthenticate,
        Authenticate,
        PostAuthenticate,
    ],
    not_supported: [
        VoidPostRefund,
        VoidPC,
        ServerSessionAuthenticationToken,
        ServerAuthenticationToken,
        SubmitEvidence,
        DefendDispute,
        Accept,
    ],
);
