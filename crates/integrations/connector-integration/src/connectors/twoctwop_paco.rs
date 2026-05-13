//! # 2C2P PACO connector
//!
//! JOSE-encrypted (PS256 + RSA-OAEP/A128CBC-HS256) connector for the 2C2P PACO
//! Payment Orchestration Layer.
//!
//! ## Merchant-facing contracts that aren't in the proto types
//!
//! ### Refund — original orderNo passthrough
//!
//! PACO matches refunds against the *original* transaction's `orderNo`, which
//! is the value the merchant supplied to Authorize as
//! `merchant_transaction_id` / `x-connector-request-reference-id`. The prism
//! orchestrator overrides `RefundFlowData.connector_request_reference_id`
//! with the refund id, so the connector cannot recover the original orderNo
//! from there. The merchant **must** pass it through on the Refund request,
//! in one of these proto fields, in priority order:
//!
//! 1. `refund_metadata` (proto field 10) — preferred.
//! 2. `connector_feature_data` (proto field 11) — fallback.
//!
//! Each accepts either a plain JSON string (treated as the orderNo) or an
//! object: `{"original_order_no":"<auth orderNo>"}`. If neither is supplied,
//! the connector errors with `MissingRequiredField` and a `suggested_action`
//! pointing the merchant at the contract.
//!
//! See `creds_dummy.json` for an example credentials block.

pub mod transformers;

use std::{self, fmt::Debug};

use common_enums::CurrencyUnit;
use common_utils::{
    consts::{NO_ERROR_CODE, NO_ERROR_MESSAGE},
    errors::CustomResult,
    events,
};
use domain_types::{
    connector_flow::{
        Accept, Authenticate, Authorize, Capture, ClientAuthenticationToken,
        CreateConnectorCustomer, CreateOrder, DefendDispute, IncrementalAuthorization,
        MandateRevoke, PSync, PaymentMethodToken, PostAuthenticate, PreAuthenticate, RSync, Refund,
        RepeatPayment, ServerAuthenticationToken, ServerSessionAuthenticationToken, SetupMandate,
        SubmitEvidence, Void, VoidPC,
    },
    connector_types::{
        AcceptDisputeData, ClientAuthenticationTokenRequestData, ConnectorCustomerData,
        ConnectorCustomerResponse, DisputeDefendData, DisputeFlowData, DisputeResponseData,
        MandateRevokeRequestData, MandateRevokeResponseData, PaymentCreateOrderData,
        PaymentCreateOrderResponse, PaymentFlowData, PaymentMethodTokenResponse,
        PaymentMethodTokenizationData, PaymentVoidData, PaymentsAuthenticateData,
        PaymentsAuthorizeData, PaymentsCancelPostCaptureData, PaymentsCaptureData,
        PaymentsIncrementalAuthorizationData, PaymentsPostAuthenticateData,
        PaymentsPreAuthenticateData, PaymentsResponseData, PaymentsSyncData, RefundFlowData,
        RefundSyncData, RefundsData, RefundsResponseData, RepeatPaymentData,
        ServerAuthenticationTokenRequestData, ServerAuthenticationTokenResponseData,
        ServerSessionAuthenticationTokenRequestData, ServerSessionAuthenticationTokenResponseData,
        SetupMandateRequestData, SubmitEvidenceData,
    },
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorSpecificConfig, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, Maskable, PeekInterface};
use interfaces::{
    api::ConnectorCommon, connector_integration_v2::ConnectorIntegrationV2, connector_types,
    decode::BodyDecoding, verification::SourceVerification,
};
use serde::Serialize;
use transformers::{
    self as twoctwop_paco, AuthorizeRoute, TwoctwopPacoAuthType, TwoctwopPacoAuthenticateRequest,
    TwoctwopPacoAuthenticateResponse, TwoctwopPacoAuthorizeRequest, TwoctwopPacoAuthorizeResponse,
    TwoctwopPacoCaptureRequest, TwoctwopPacoCaptureResponse, TwoctwopPacoErrorResponse,
    TwoctwopPacoNonUiResponse, TwoctwopPacoPSyncInquiryResponse, TwoctwopPacoRSyncInquiryResponse,
    TwoctwopPacoRefundRequest, TwoctwopPacoRefundResponse, TwoctwopPacoVoidPcRequest,
    TwoctwopPacoVoidPcResponse, TwoctwopPacoVoidRequest, TwoctwopPacoVoidResponse,
};

use super::macros;
use crate::{types::ResponseRouterData, with_error_response_body};

pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const ACCEPT: &str = "Accept";
    pub(crate) const TOKEN: &str = "token";
    pub(crate) const APIKEY: &str = "apikey";
}

const CONTENT_TYPE_JOSE: &str = "application/jose";
const CONTENT_TYPE_JSON: &str = "application/json";

// Marker trait impls (mirrors imerchantsolutions).

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ClientAuthentication for TwoctwopPaco<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ConnectorServiceTrait<T> for TwoctwopPaco<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAuthorizeV2<T> for TwoctwopPaco<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentSyncV2 for TwoctwopPaco<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentVoidV2 for TwoctwopPaco<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentVoidPostCaptureV2 for TwoctwopPaco<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundSyncV2 for TwoctwopPaco<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentIncrementalAuthorization for TwoctwopPaco<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundV2 for TwoctwopPaco<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentCapture for TwoctwopPaco<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ValidationTrait for TwoctwopPaco<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentOrderCreate for TwoctwopPaco<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::SetupMandateV2<T> for TwoctwopPaco<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RepeatPaymentV2<T> for TwoctwopPaco<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::AcceptDispute for TwoctwopPaco<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::SubmitEvidenceV2 for TwoctwopPaco<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::DisputeDefend for TwoctwopPaco<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::VerifyRedirectResponse for TwoctwopPaco<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> SourceVerification
    for TwoctwopPaco<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> BodyDecoding
    for TwoctwopPaco<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ServerSessionAuthentication for TwoctwopPaco<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ServerAuthentication for TwoctwopPaco<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::CreateConnectorCustomer for TwoctwopPaco<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentTokenV2<T> for TwoctwopPaco<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentPreAuthenticateV2<T> for TwoctwopPaco<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAuthenticateV2<T> for TwoctwopPaco<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentPostAuthenticateV2<T> for TwoctwopPaco<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::MandateRevokeV2 for TwoctwopPaco<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        ClientAuthenticationToken,
        PaymentFlowData,
        ClientAuthenticationTokenRequestData,
        PaymentsResponseData,
    > for TwoctwopPaco<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        IncrementalAuthorization,
        PaymentFlowData,
        PaymentsIncrementalAuthorizationData,
        PaymentsResponseData,
    > for TwoctwopPaco<T>
{
}

macros::macro_connector_payout_implementation!(
    connector: TwoctwopPaco,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize]
);

macros::create_all_prerequisites!(
    connector_name: TwoctwopPaco,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: TwoctwopPacoAuthorizeRequest,
            response_body: TwoctwopPacoAuthorizeResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: PSync,
            response_body: TwoctwopPacoPSyncInquiryResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ),
        (
            flow: Capture,
            request_body: TwoctwopPacoCaptureRequest,
            response_body: TwoctwopPacoCaptureResponse,
            router_data: RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ),
        (
            flow: Void,
            request_body: TwoctwopPacoVoidRequest,
            response_body: TwoctwopPacoVoidResponse,
            router_data: RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ),
        (
            flow: VoidPC,
            request_body: TwoctwopPacoVoidPcRequest,
            response_body: TwoctwopPacoVoidPcResponse,
            router_data: RouterDataV2<VoidPC, PaymentFlowData, PaymentsCancelPostCaptureData, PaymentsResponseData>,
        ),
        (
            flow: Refund,
            request_body: TwoctwopPacoRefundRequest,
            response_body: TwoctwopPacoRefundResponse,
            router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ),
        (
            flow: RSync,
            response_body: TwoctwopPacoRSyncInquiryResponse,
            router_data: RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ),
        (
            flow: Authenticate,
            request_body: TwoctwopPacoAuthenticateRequest,
            response_body: TwoctwopPacoAuthenticateResponse,
            router_data: RouterDataV2<Authenticate, PaymentFlowData, PaymentsAuthenticateData<T>, PaymentsResponseData>,
        )
    ],
    amount_converters: [],
    member_functions: {
        pub fn build_jose_headers(
            &self,
            auth: &TwoctwopPacoAuthType,
        ) -> Vec<(String, Maskable<String>)> {
            vec![
                (
                    headers::CONTENT_TYPE.to_string(),
                    CONTENT_TYPE_JOSE.to_string().into(),
                ),
                (
                    headers::ACCEPT.to_string(),
                    CONTENT_TYPE_JOSE.to_string().into(),
                ),
                (
                    headers::TOKEN.to_string(),
                    auth.access_token.clone().expose().into(),
                ),
            ]
        }

        pub fn build_inquiry_headers(
            &self,
            auth: &TwoctwopPacoAuthType,
        ) -> Vec<(String, Maskable<String>)> {
            vec![
                (
                    headers::CONTENT_TYPE.to_string(),
                    CONTENT_TYPE_JSON.to_string().into(),
                ),
                (
                    headers::ACCEPT.to_string(),
                    CONTENT_TYPE_JSON.to_string().into(),
                ),
                (
                    headers::APIKEY.to_string(),
                    auth.access_token.clone().expose().into(),
                ),
            ]
        }

        pub fn connector_base_url_payments<F, Req, Res>(
            &self,
            req: &RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> String {
            req.resource_common_data
                .connectors
                .twoctwop_paco
                .base_url
                .to_string()
        }

        pub fn connector_base_url_refunds<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, RefundFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.twoctwop_paco.base_url
        }

        // Request-side JOSE preprocessing. Receives the JSON-serialised inner
        // request body, wraps it in a `PacoJoseClaims` envelope (iss/aud/iat/
        // nbf/exp + `request: <body>`), signs as PS256 JWS, then seals as
        // RSA-OAEP/A128CBC-HS256 JWE. Returns the compact JWE bytes that go
        // on the wire. Symmetric counterpart to `preprocess_response_bytes`.
        pub fn preprocess_request_bytes<F, FCD, Req, Res>(
            &self,
            req: &RouterDataV2<F, FCD, Req, Res>,
            bytes: Vec<u8>,
        ) -> CustomResult<Vec<u8>, errors::IntegrationError> {
            let auth = TwoctwopPacoAuthType::try_from(&req.connector_config)?;
            let inner: serde_json::Value = serde_json::from_slice(&bytes).map_err(|err| {
                error_stack::report!(errors::IntegrationError::InvalidDataFormat {
                    field_name: "twoctwop_paco request body",
                    context: errors::IntegrationErrorContext {
                        suggested_action: None,
                        doc_url: None,
                        additional_context: Some(format!(
                            "Inner PACO body was not valid JSON before JOSE wrap: {err}"
                        )),
                    },
                })
            })?;
            let claims = transformers::PacoJoseClaims::new(auth.access_token.peek(), inner);
            let jwe = common_utils::crypto::jose::sign_then_encrypt(&claims, &auth.jose_cfg)
                .map_err(|err| {
                    error_stack::report!(errors::IntegrationError::FailedToObtainAuthType {
                        context: errors::IntegrationErrorContext {
                            suggested_action: Some(
                                "Confirm the PACO PEMs and `kid` resolve a valid JOSE pair."
                                    .to_string(),
                            ),
                            doc_url: None,
                            additional_context: Some(format!(
                                "JOSE sign+encrypt failed: {err}"
                            )),
                        },
                    })
                })?;
            Ok(jwe.into_bytes())
        }

        // Response-side JOSE preprocessing. Decrypts the compact JWE, verifies
        // the inner JWS signature against PACO's signing pubkey, enforces
        // aud/exp/nbf claims, and returns the inner `response` body as JSON
        // bytes for the bridge to deserialise into `TwoctwopPacoNonUiResponse`.
        pub fn preprocess_response_bytes<F, FCD, Req, Res>(
            &self,
            req: &RouterDataV2<F, FCD, Req, Res>,
            bytes: bytes::Bytes,
            status_code: u16,
        ) -> CustomResult<bytes::Bytes, errors::ConnectorError> {
            let auth = TwoctwopPacoAuthType::try_from(&req.connector_config).change_context(
                errors::ConnectorError::response_deserialization_failed_with_context(
                    status_code,
                    Some(
                        "twoctwop_paco: failed to read auth config for response decoding"
                            .to_string(),
                    ),
                ),
            )?;
            let compact = std::str::from_utf8(&bytes).map_err(|_| {
                error_stack::report!(
                    errors::ConnectorError::response_deserialization_failed_with_context(
                        status_code,
                        Some("twoctwop_paco: response was not valid UTF-8".to_string()),
                    )
                )
            })?;
            let trimmed = compact.trim().trim_matches('"');
            let validation = common_utils::crypto::jose::JoseClaimValidation {
                expected_audience: Some(auth.response_audience.peek().clone()),
                clock_skew_seconds: 60,
            };
            let claims = common_utils::crypto::jose::decrypt_then_verify_with_claims(
                trimmed,
                &auth.jose_cfg,
                Some(&validation),
            )
            .map_err(|err| {
                error_stack::report!(
                    errors::ConnectorError::response_deserialization_failed_with_context(
                        status_code,
                        Some(format!("JOSE decrypt+verify failed: {err}")),
                    )
                )
            })?;
            let inner = match claims.get("response") {
                Some(value) => value.clone(),
                None => claims,
            };
            let inner_bytes = serde_json::to_vec(&inner).map_err(|err| {
                error_stack::report!(
                    errors::ConnectorError::response_deserialization_failed_with_context(
                        status_code,
                        Some(format!(
                            "twoctwop_paco: failed to re-serialise inner response: {err}"
                        )),
                    )
                )
            })?;
            Ok(bytes::Bytes::from(inner_bytes))
        }
    }
);

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> ConnectorCommon
    for TwoctwopPaco<T>
{
    fn id(&self) -> &'static str {
        "twoctwop_paco"
    }

    fn get_currency_unit(&self) -> CurrencyUnit {
        CurrencyUnit::Minor
    }

    fn common_get_content_type(&self) -> &'static str {
        CONTENT_TYPE_JOSE
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        &connectors.twoctwop_paco.base_url
    }

    fn get_auth_header(
        &self,
        auth_type: &ConnectorSpecificConfig,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::IntegrationError> {
        let auth = TwoctwopPacoAuthType::try_from(auth_type)?;
        Ok(vec![(
            headers::TOKEN.to_string(),
            auth.access_token.expose().into(),
        )])
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut events::Event>,
        connector_config: &ConnectorSpecificConfig,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let body = res.response.to_vec();
        let body_str = String::from_utf8_lossy(&body).to_string();
        let trimmed = body_str.trim().trim_matches('"');
        let looks_like_jose = trimmed.split('.').count() == 5
            && trimmed
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_');

        // Up to 128 bytes of the wire body, hex-encoded, surfaced into the
        // error `reason` whenever the connector can't parse a typed error
        // code out of the response. Lets operators correlate prism errors
        // with PACO wire captures even without access to server logs.
        let body_prefix_hex = || {
            let take = body.len().min(128);
            let hex: String = body
                .iter()
                .take(take)
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join("");
            if body.len() > take {
                format!("body[0..{take}]=0x{hex}…")
            } else {
                format!("body=0x{hex}")
            }
        };
        let fallback = |context: &str| {
            (
                NO_ERROR_CODE.to_string(),
                format!("{NO_ERROR_MESSAGE} ({context}; {})", body_prefix_hex()),
            )
        };

        let (code, message) = if looks_like_jose {
            match TwoctwopPacoAuthType::try_from(connector_config) {
                Ok(auth) => {
                    match common_utils::crypto::jose::decrypt_then_verify(trimmed, &auth.jose_cfg) {
                        Ok(value) => {
                            let inner = value
                                .get("response")
                                .cloned()
                                .unwrap_or_else(|| value.clone());
                            match serde_json::from_value::<TwoctwopPacoNonUiResponse>(inner) {
                                Ok(parsed) => {
                                    let prior = parsed
                                        .merged_result()
                                        .and_then(|b| b.prior_payment_response_details.clone());
                                    let api = parsed.api_response.clone();
                                    with_error_response_body!(event_builder, parsed);
                                    twoctwop_paco::error_code_message(&api, &prior)
                                }
                                Err(err) => {
                                    tracing::warn!(
                                        error = %err,
                                        "twoctwop_paco: failed to parse decrypted error envelope"
                                    );
                                    fallback("envelope parse failed")
                                }
                            }
                        }
                        Err(err) => {
                            tracing::warn!(
                                error = %err,
                                "twoctwop_paco: JOSE decrypt failed for error response"
                            );
                            fallback("JOSE decrypt failed")
                        }
                    }
                }
                Err(_) => fallback("connector auth config missing"),
            }
        } else {
            match serde_json::from_slice::<TwoctwopPacoErrorResponse>(&body) {
                Ok(parsed) => {
                    with_error_response_body!(event_builder, parsed);
                    parsed.flatten()
                }
                Err(_) => fallback("response is neither JOSE nor recognised JSON"),
            }
        };

        Ok(ErrorResponse {
            status_code: res.status_code,
            code,
            message: message.clone(),
            reason: Some(message),
            attempt_status: None,
            connector_transaction_id: None,
            network_advice_code: None,
            network_decline_code: None,
            network_error_message: None,
        })
    }
}

// PSync — JSON Inquiry endpoint, GET, header `apikey`.
macros::macro_connector_implementation!(
    connector_default_implementations: [get_error_response_v2],
    connector: TwoctwopPaco,
    curl_response: TwoctwopPacoPSyncInquiryResponse,
    flow_name: PSync,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsSyncData,
    flow_response: PaymentsResponseData,
    http_method: Get,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::IntegrationError> {
            let auth = TwoctwopPacoAuthType::try_from(&req.connector_config)?;
            Ok(self.build_inquiry_headers(&auth))
        }

        fn get_content_type(&self) -> &'static str {
            CONTENT_TYPE_JSON
        }

        fn get_url(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<String, errors::IntegrationError> {
            let auth = TwoctwopPacoAuthType::try_from(&req.connector_config)?;
            let base_url = self.connector_base_url_payments(req);
            let order_no = req
                .resource_common_data
                .connector_request_reference_id
                .clone();
            Ok(format!(
                "{base_url}/api/2.0/Inquiry/transactionStatus?merchantId={}&orderNo={}",
                urlencoding::encode(auth.merchant_id.peek()),
                urlencoding::encode(&order_no),
            ))
        }
    }
);

// RSync — same Inquiry endpoint as PSync. Uses a distinct
// `TwoctwopPacoRSyncInquiryResponse` newtype so the macro's templating
// struct doesn't collide with PSync's.
macros::macro_connector_implementation!(
    connector_default_implementations: [get_error_response_v2],
    connector: TwoctwopPaco,
    curl_response: TwoctwopPacoRSyncInquiryResponse,
    flow_name: RSync,
    resource_common_data: RefundFlowData,
    flow_request: RefundSyncData,
    flow_response: RefundsResponseData,
    http_method: Get,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::IntegrationError> {
            let auth = TwoctwopPacoAuthType::try_from(&req.connector_config)?;
            Ok(self.build_inquiry_headers(&auth))
        }

        fn get_content_type(&self) -> &'static str {
            CONTENT_TYPE_JSON
        }

        fn get_url(
            &self,
            req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ) -> CustomResult<String, errors::IntegrationError> {
            let auth = TwoctwopPacoAuthType::try_from(&req.connector_config)?;
            let base_url = self.connector_base_url_refunds(req);
            let order_no = req.request.connector_refund_id.clone();
            Ok(format!(
                "{base_url}/api/2.0/Inquiry/transactionStatus?merchantId={}&orderNo={}",
                urlencoding::encode(auth.merchant_id.peek()),
                urlencoding::encode(&order_no),
            ))
        }
    }
);

// ---------- JOSE-bodied flows ----------
//
// All six flows below share the same wire envelope: a typed inner JSON body
// (per-flow `try_from` impl) is wrapped by the framework's
// `preprocess_request_bytes` hook into a `PacoJoseClaims` envelope, signed
// PS256, sealed RSA-OAEP / A128CBC-HS256, then sent as `application/jose`.
// Responses run in reverse via `preprocess_response_bytes`. The JOSE plumbing
// itself lives in the `create_all_prerequisites!` member_functions block
// further up.

// Authorize — POST. Dual URL: `/Payment/nonUi` for cards, `/Payment/prepaymentUi`
// for GCash hosted-page redirect. Route is picked at request time by
// `transformers::authorize_route` which inspects the payment method data.
macros::macro_connector_implementation!(
    connector_default_implementations: [get_error_response_v2],
    connector: TwoctwopPaco,
    curl_request: Json(TwoctwopPacoAuthorizeRequest),
    curl_response: TwoctwopPacoAuthorizeResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    preprocess_request: true,
    preprocess_response: true,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::IntegrationError> {
            let auth = TwoctwopPacoAuthType::try_from(&req.connector_config)?;
            Ok(self.build_jose_headers(&auth))
        }

        fn get_content_type(&self) -> &'static str {
            CONTENT_TYPE_JOSE
        }

        fn get_url(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<String, errors::IntegrationError> {
            let base_url = self.connector_base_url_payments(req);
            let path = match transformers::authorize_route(req)? {
                AuthorizeRoute::CardNonUi => "/api/2.0/Payment/nonUi",
                AuthorizeRoute::WalletPrepaymentUi => "/api/2.0/Payment/prepaymentUi",
            };
            Ok(format!("{base_url}{path}"))
        }
    }
);

// Capture — PUT /api/2.0/Settlement.
macros::macro_connector_implementation!(
    connector_default_implementations: [get_error_response_v2],
    connector: TwoctwopPaco,
    curl_request: Json(TwoctwopPacoCaptureRequest),
    curl_response: TwoctwopPacoCaptureResponse,
    flow_name: Capture,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsCaptureData,
    flow_response: PaymentsResponseData,
    http_method: Put,
    preprocess_request: true,
    preprocess_response: true,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::IntegrationError> {
            let auth = TwoctwopPacoAuthType::try_from(&req.connector_config)?;
            Ok(self.build_jose_headers(&auth))
        }

        fn get_content_type(&self) -> &'static str {
            CONTENT_TYPE_JOSE
        }

        fn get_url(
            &self,
            req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ) -> CustomResult<String, errors::IntegrationError> {
            let base_url = self.connector_base_url_payments(req);
            Ok(format!("{base_url}/api/2.0/Settlement"))
        }
    }
);

// Void — POST /api/2.0/Void.
macros::macro_connector_implementation!(
    connector_default_implementations: [get_error_response_v2],
    connector: TwoctwopPaco,
    curl_request: Json(TwoctwopPacoVoidRequest),
    curl_response: TwoctwopPacoVoidResponse,
    flow_name: Void,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentVoidData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    preprocess_request: true,
    preprocess_response: true,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::IntegrationError> {
            let auth = TwoctwopPacoAuthType::try_from(&req.connector_config)?;
            Ok(self.build_jose_headers(&auth))
        }

        fn get_content_type(&self) -> &'static str {
            CONTENT_TYPE_JOSE
        }

        fn get_url(
            &self,
            req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ) -> CustomResult<String, errors::IntegrationError> {
            let base_url = self.connector_base_url_payments(req);
            Ok(format!("{base_url}/api/2.0/Void"))
        }
    }
);

// VoidPC (post-capture reverse) — POST /api/2.0/Void. Same endpoint as Void;
// the office config decides which lifecycle states are accepted at request
// time. Body shape is identical to Void, but the typed wrapper gives this
// flow a distinct bridge slot.
macros::macro_connector_implementation!(
    connector_default_implementations: [get_error_response_v2],
    connector: TwoctwopPaco,
    curl_request: Json(TwoctwopPacoVoidPcRequest),
    curl_response: TwoctwopPacoVoidPcResponse,
    flow_name: VoidPC,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsCancelPostCaptureData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    preprocess_request: true,
    preprocess_response: true,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<VoidPC, PaymentFlowData, PaymentsCancelPostCaptureData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::IntegrationError> {
            let auth = TwoctwopPacoAuthType::try_from(&req.connector_config)?;
            Ok(self.build_jose_headers(&auth))
        }

        fn get_content_type(&self) -> &'static str {
            CONTENT_TYPE_JOSE
        }

        fn get_url(
            &self,
            req: &RouterDataV2<VoidPC, PaymentFlowData, PaymentsCancelPostCaptureData, PaymentsResponseData>,
        ) -> CustomResult<String, errors::IntegrationError> {
            let base_url = self.connector_base_url_payments(req);
            Ok(format!("{base_url}/api/2.0/Void"))
        }
    }
);

// Refund — POST /api/2.0/Refund/refund. Uses the refund base URL helper
// which still resolves to the same configured `twoctwop_paco.base_url`.
macros::macro_connector_implementation!(
    connector_default_implementations: [get_error_response_v2],
    connector: TwoctwopPaco,
    curl_request: Json(TwoctwopPacoRefundRequest),
    curl_response: TwoctwopPacoRefundResponse,
    flow_name: Refund,
    resource_common_data: RefundFlowData,
    flow_request: RefundsData,
    flow_response: RefundsResponseData,
    http_method: Post,
    preprocess_request: true,
    preprocess_response: true,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::IntegrationError> {
            let auth = TwoctwopPacoAuthType::try_from(&req.connector_config)?;
            Ok(self.build_jose_headers(&auth))
        }

        fn get_content_type(&self) -> &'static str {
            CONTENT_TYPE_JOSE
        }

        fn get_url(
            &self,
            req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ) -> CustomResult<String, errors::IntegrationError> {
            let base_url = self.connector_base_url_refunds(req);
            Ok(format!("{base_url}/api/2.0/Refund/refund"))
        }
    }
);

// ---------- IncomingWebhook ----------
//
// PACO supports backend webhook notifications (JOSE-encrypted, same wire
// envelope as API responses) for hosted-page wallet flows and async
// settlement state changes. The verification path needs the merchant's
// encryption private key, which is per-merchant and reaches us via
// `ConnectorSpecificConfig::TwoctwopPaco` — i.e. the same auth bundle
// the API flows use.
//
// Intentionally left as the default empty impl for now: the trait's
// default `verify_webhook_source` returns Ok(false), which rejects
// every incoming webhook as unverified. That is fail-closed by design.
// Until a wired implementation lands, merchants should poll
// `/Inquiry/transactionStatus` (PSync) to get final state for the
// hosted-page and post-3DS flows.
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::IncomingWebhook for TwoctwopPaco<T>
{
}

// ---------- Stubs for unsupported flows ----------

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for TwoctwopPaco<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
    for TwoctwopPaco<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
    for TwoctwopPaco<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    for TwoctwopPaco<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData<T>,
        PaymentsResponseData,
    > for TwoctwopPaco<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        RepeatPayment,
        PaymentFlowData,
        RepeatPaymentData<T>,
        PaymentsResponseData,
    > for TwoctwopPaco<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        ServerSessionAuthenticationToken,
        PaymentFlowData,
        ServerSessionAuthenticationTokenRequestData,
        ServerSessionAuthenticationTokenResponseData,
    > for TwoctwopPaco<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        CreateConnectorCustomer,
        PaymentFlowData,
        ConnectorCustomerData,
        ConnectorCustomerResponse,
    > for TwoctwopPaco<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        PaymentMethodToken,
        PaymentFlowData,
        PaymentMethodTokenizationData<T>,
        PaymentMethodTokenResponse,
    > for TwoctwopPaco<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        ServerAuthenticationToken,
        PaymentFlowData,
        ServerAuthenticationTokenRequestData,
        ServerAuthenticationTokenResponseData,
    > for TwoctwopPaco<T>
{
}

// ---------- 3DS trio ----------
//
// PACO is native 3DS. The merchant-facing surface collapses to:
//   PreAuthenticate  empty marker — PACO has no DDC endpoint
//   Authenticate     POST /Payment/nonUi with request3dsFlag=Y → either an
//                    ACS challenge (RedirectForm) or inline CAVV/ECI
//   PostAuthenticate empty marker — PACO has no CRes-submit endpoint; the
//                    challenge result flows back via ACS callback into
//                    PACO's underlying 3DSS, server-side. Merchants call
//                    PSync after the browser challenge to fetch the final
//                    state from /Inquiry/transactionStatus (PSync surfaces
//                    `authenticationData` + post-3DS payment status).

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        PreAuthenticate,
        PaymentFlowData,
        PaymentsPreAuthenticateData<T>,
        PaymentsResponseData,
    > for TwoctwopPaco<T>
{
}

// Authenticate — POST /api/2.0/Payment/nonUi with `request3dsFlag=Y`. Wire
// envelope and body shape are identical to a Card Authorize, only the flow
// marker differs.
macros::macro_connector_implementation!(
    connector_default_implementations: [get_error_response_v2],
    connector: TwoctwopPaco,
    curl_request: Json(TwoctwopPacoAuthenticateRequest),
    curl_response: TwoctwopPacoAuthenticateResponse,
    flow_name: Authenticate,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthenticateData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    preprocess_request: true,
    preprocess_response: true,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Authenticate, PaymentFlowData, PaymentsAuthenticateData<T>, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::IntegrationError> {
            let auth = TwoctwopPacoAuthType::try_from(&req.connector_config)?;
            Ok(self.build_jose_headers(&auth))
        }

        fn get_content_type(&self) -> &'static str {
            CONTENT_TYPE_JOSE
        }

        fn get_url(
            &self,
            req: &RouterDataV2<Authenticate, PaymentFlowData, PaymentsAuthenticateData<T>, PaymentsResponseData>,
        ) -> CustomResult<String, errors::IntegrationError> {
            let base_url = self.connector_base_url_payments(req);
            Ok(format!("{base_url}/api/2.0/Payment/nonUi"))
        }
    }
);

// PostAuthenticate — empty marker. The prism convention for this flow is
// "merchant submits the CRes / 3DS challenge result, gateway returns the
// final auth state" (POST with body — Cybersource / Nexixpay / Worldpay).
// PACO doesn't expose a merchant-facing endpoint to push a CRes — the
// challenge result flows back through PACO's underlying 3DSS via the ACS
// callback, server-to-server, transparent to the merchant. After the
// browser challenge completes, merchants should call PSync to retrieve
// the final state from `/Inquiry/transactionStatus`; PSync already
// surfaces `authenticationData` and the post-3DS payment status.
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        PostAuthenticate,
        PaymentFlowData,
        PaymentsPostAuthenticateData<T>,
        PaymentsResponseData,
    > for TwoctwopPaco<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        MandateRevoke,
        PaymentFlowData,
        MandateRevokeRequestData,
        MandateRevokeResponseData,
    > for TwoctwopPaco<T>
{
}
