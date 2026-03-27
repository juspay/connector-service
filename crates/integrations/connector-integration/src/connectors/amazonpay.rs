pub mod transformers;

use std::fmt::Debug;

use common_enums::CurrencyUnit;
use common_utils::{errors::CustomResult, events, ext_traits::ByteSliceExt, types::MinorUnit};
use domain_types::{
    connector_flow::{self, Authorize, Capture, PSync, RSync, Refund, Void},
    connector_types::*,
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorSpecificConfig, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_request_types::VerifyWebhookSourceRequestData,
    router_response_types::{Response, VerifyWebhookSourceResponseData},
    types::{
        ConnectorInfo, Connectors, FeatureStatus, PaymentConnectorCategory,
        PaymentMethodDetails, SupportedPaymentMethods,
    },
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, Mask, Maskable, PeekInterface};
use time::OffsetDateTime;
use interfaces::{
    api::ConnectorCommon, connector_integration_v2::ConnectorIntegrationV2, connector_types,
    decode::BodyDecoding,
};
use ring::{digest as ring_digest, hmac};
use serde::Serialize;
use transformers as amazonpay;
use url;

use self::transformers::{
    AmazonpayAuthorizeRequest, AmazonpayAuthorizeResponse, AmazonpayCaptureRequest,
    AmazonpayCaptureResponse, AmazonpayRefundRequest, AmazonpayRefundResponse,
    AmazonpayRefundSyncResponse, AmazonpaySyncResponse, AmazonpayVoidRequest, AmazonpayVoidResponse,
};
use super::macros;
use crate::{types::ResponseRouterData, with_error_response_body};

pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const AUTHORIZATION: &str = "Authorization";
    pub(crate) const X_AMZ_DATE: &str = "x-amz-date";
    pub(crate) const X_AMZ_ALGORITHM: &str = "x-amz-algorithm";
    pub(crate) const X_AMZ_EXPIRES: &str = "x-amz-expires";
    pub(crate) const X_AMZ_SOURCE: &str = "x-amz-source";
    pub(crate) const X_AMZ_USER_AGENT: &str = "x-amz-user-agent";
    pub(crate) const X_AMZ_CLIENT_ID: &str = "x-amz-client-id";
    pub(crate) const X_AMZ_USER_IP: &str = "x-amz-user-ip";
}

// =============================================================================
// AMZ SIGNATURE COMPUTATION — V2 PreAuth
// Mirrors AmazonServerSDK.getSignatureForPreAuthFlow (Haskell SDK)
//
// Algorithm:
//   1. Build canonical request:
//      POST\n{hostname}{uri}\n\n{sortedHeaderQueryString}\n{sortedBodyQueryString}
//   2. Hash canonical request with SHA384 (hex)
//   3. Build string_to_sign:
//      AWS4-HMAC-SHA384\n{amz_date}\n{date}/{region}/{service}/aws4_request\n{canonical_hash}
//   4. Derive signing key (AWS4 key derivation with SHA384):
//      k1 = HMAC-SHA384("AWS4" + secret_key, date)
//      k2 = HMAC-SHA384(k1, region)
//      k3 = HMAC-SHA384(k2, service)
//      k4 = HMAC-SHA384(k3, "aws4_request")
//      sig = HMAC-SHA384(k4, string_to_sign)
//   5. Final signature: base64url_no_padding(sig_bytes)
//      where sig_bytes comes from the hex digest -> decoded to bytes
// =============================================================================

/// URL-encodes a string value matching the Haskell `urlEncode` used in `sortKeysAndMakeQueryString`.
fn amz_url_encode(s: &str) -> String {
    urlencoding::encode(s).into_owned()
}

/// Takes a JSON object, filters null values, sorts keys alphabetically, and produces
/// `key=value&key=value` query string (URL-encoded). Mirrors `sortKeysAndMakeQueryString`.
fn sort_keys_query_string(obj: &serde_json::Map<String, serde_json::Value>) -> String {
    let mut pairs: Vec<(String, String)> = obj
        .iter()
        .filter_map(|(k, v)| {
            match v {
                serde_json::Value::Null => None,
                serde_json::Value::String(s) => {
                    Some((amz_url_encode(k), amz_url_encode(s)))
                }
                serde_json::Value::Bool(b) => {
                    Some((amz_url_encode(k), amz_url_encode(&b.to_string())))
                }
                serde_json::Value::Number(n) => {
                    Some((amz_url_encode(k), amz_url_encode(&n.to_string())))
                }
                _ => None,
            }
        })
        .collect();
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    pairs
        .into_iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join("&")
}

/// Computes HMAC-SHA384 over `data` using `key` and returns raw bytes.
fn hmac_sha384(key: &[u8], data: &[u8]) -> Vec<u8> {
    let k = hmac::Key::new(hmac::HMAC_SHA384, key);
    hmac::sign(&k, data).as_ref().to_vec()
}

/// Computes SHA384 digest of `data` and returns it as a lowercase hex string.
fn sha384_hex(data: &[u8]) -> String {
    let digest = ring_digest::digest(&ring_digest::SHA384, data);
    hex::encode(digest.as_ref())
}

/// Derives the AWS4 signing key: HMAC-SHA384 chain over (date, region, service, "aws4_request").
fn get_amz_signing_key(secret_key: &str, date_stamp: &str) -> Vec<u8> {
    const REGION: &str = "eu-west-1";
    const SERVICE: &str = "AmazonPay";
    const TERMINATION: &str = "aws4_request";

    let k_secret = format!("AWS4{}", secret_key);
    let k_date = hmac_sha384(k_secret.as_bytes(), date_stamp.as_bytes());
    let k_region = hmac_sha384(&k_date, REGION.as_bytes());
    let k_service = hmac_sha384(&k_region, SERVICE.as_bytes());
    hmac_sha384(&k_service, TERMINATION.as_bytes())
}

/// Computes the AMZ signature given:
/// - `headers_json`: JSON object of APayPreAuthHeaders (with `__x_45_amz_45_*` keys)
/// - `body_json`: JSON object of the request body
/// - `amz_date`: UTC timestamp string (e.g., "20260326T230052Z")
/// - `secret_key`: Amazon Pay S2S secret key
/// - `uri`: endpoint path (e.g., "/v1/payments/charge")
/// - `http_method`: HTTP method ("POST" or "GET")
/// - `test_mode`: true for sandbox
///
/// Returns the base64url (no-padding) encoded signature.
fn compute_amz_signature(
    headers_json: &serde_json::Map<String, serde_json::Value>,
    body_json: &serde_json::Map<String, serde_json::Value>,
    amz_date: &str,
    secret_key: &str,
    uri: &str,
    http_method: &str,
    test_mode: bool,
) -> String {
    let hostname = if test_mode {
        "amazonpay-sandbox.amazon.in"
    } else {
        "amazonpay.amazon.in"
    };

    // Step 1: Build canonical request
    let header_qs = sort_keys_query_string(headers_json);
    let body_qs = sort_keys_query_string(body_json);
    let canonical_request = format!(
        "{}\n{}{}\n\n{}\n{}",
        http_method, hostname, uri, header_qs, body_qs
    );

    // Step 2: Hash canonical request
    let canonical_hash = sha384_hex(canonical_request.as_bytes());

    // Step 3: Build string_to_sign
    // date_stamp = first 8 chars of amz_date (YYYYMMDD)
    let date_stamp = &amz_date[..8];
    let credential_scope = format!("{}/eu-west-1/AmazonPay/aws4_request", date_stamp);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA384\n{}\n{}\n{}",
        amz_date, credential_scope, canonical_hash
    );

    // Step 4: Derive signing key and compute signature
    let signing_key = get_amz_signing_key(secret_key, date_stamp);
    let sig_bytes = hmac_sha384(&signing_key, string_to_sign.as_bytes());

    // Step 5: Base64url encode (no padding) — mirrors Haskell's encodeBase64Unpadded
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&sig_bytes)
}

// =============================================================================
// CONNECTOR TRAIT IMPLEMENTATIONS
// =============================================================================

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ConnectorServiceTrait<T> for Amazonpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::AcceptDispute for Amazonpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::CreateConnectorCustomer for Amazonpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::DisputeDefend for Amazonpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::IncomingWebhook for Amazonpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::MandateRevokeV2 for Amazonpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAccessToken for Amazonpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAuthenticateV2<T> for Amazonpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAuthorizeV2<T> for Amazonpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentCapture for Amazonpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentIncrementalAuthorization for Amazonpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentOrderCreate for Amazonpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentPostAuthenticateV2<T> for Amazonpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentPreAuthenticateV2<T> for Amazonpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentSessionToken for Amazonpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentSyncV2 for Amazonpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentTokenV2<T> for Amazonpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentVoidPostCaptureV2 for Amazonpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentVoidV2 for Amazonpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundSyncV2 for Amazonpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundV2 for Amazonpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RepeatPaymentV2<T> for Amazonpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::SdkSessionTokenV2 for Amazonpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::SetupMandateV2<T> for Amazonpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::SubmitEvidenceV2 for Amazonpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ValidationTrait for Amazonpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::VerifyRedirectResponse for Amazonpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::VerifyWebhookSourceV2 for Amazonpay<T>
{
}

// ===== CONNECTOR INTEGRATION V2 IMPLEMENTATIONS (non-Authorize flows) =====

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        connector_flow::Accept,
        DisputeFlowData,
        AcceptDisputeData,
        DisputeResponseData,
    > for Amazonpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        connector_flow::CreateConnectorCustomer,
        PaymentFlowData,
        ConnectorCustomerData,
        ConnectorCustomerResponse,
    > for Amazonpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        connector_flow::DefendDispute,
        DisputeFlowData,
        DisputeDefendData,
        DisputeResponseData,
    > for Amazonpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        connector_flow::MandateRevoke,
        PaymentFlowData,
        MandateRevokeRequestData,
        MandateRevokeResponseData,
    > for Amazonpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        connector_flow::CreateAccessToken,
        PaymentFlowData,
        AccessTokenRequestData,
        AccessTokenResponseData,
    > for Amazonpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        connector_flow::Authenticate,
        PaymentFlowData,
        PaymentsAuthenticateData<T>,
        PaymentsResponseData,
    > for Amazonpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        connector_flow::IncrementalAuthorization,
        PaymentFlowData,
        PaymentsIncrementalAuthorizationData,
        PaymentsResponseData,
    > for Amazonpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        connector_flow::CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for Amazonpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        connector_flow::PostAuthenticate,
        PaymentFlowData,
        PaymentsPostAuthenticateData<T>,
        PaymentsResponseData,
    > for Amazonpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        connector_flow::PreAuthenticate,
        PaymentFlowData,
        PaymentsPreAuthenticateData<T>,
        PaymentsResponseData,
    > for Amazonpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        connector_flow::CreateSessionToken,
        PaymentFlowData,
        SessionTokenRequestData,
        SessionTokenResponseData,
    > for Amazonpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        connector_flow::PaymentMethodToken,
        PaymentFlowData,
        PaymentMethodTokenizationData<T>,
        PaymentMethodTokenResponse,
    > for Amazonpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        connector_flow::VoidPC,
        PaymentFlowData,
        PaymentsCancelPostCaptureData,
        PaymentsResponseData,
    > for Amazonpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        connector_flow::RepeatPayment,
        PaymentFlowData,
        RepeatPaymentData<T>,
        PaymentsResponseData,
    > for Amazonpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        connector_flow::SdkSessionToken,
        PaymentFlowData,
        PaymentsSdkSessionTokenData,
        PaymentsResponseData,
    > for Amazonpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        connector_flow::SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData<T>,
        PaymentsResponseData,
    > for Amazonpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        connector_flow::SubmitEvidence,
        DisputeFlowData,
        SubmitEvidenceData,
        DisputeResponseData,
    > for Amazonpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        connector_flow::VerifyWebhookSource,
        VerifyWebhookSourceFlowData,
        VerifyWebhookSourceRequestData,
        VerifyWebhookSourceResponseData,
    > for Amazonpay<T>
{
}

// ===== SOURCE VERIFICATION IMPLEMENTATION =====
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification for Amazonpay<T>
{
}

// =============================================================================
// MACRO-BASED PREREQUISITES (creates the Amazonpay<T> struct and Authorize bridge)
// =============================================================================
macros::create_all_prerequisites!(
    connector_name: Amazonpay,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: AmazonpayAuthorizeRequest<T>,
            response_body: AmazonpayAuthorizeResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: Capture,
            request_body: AmazonpayCaptureRequest,
            response_body: AmazonpayCaptureResponse,
            router_data: RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ),
        (
            flow: PSync,
            response_body: AmazonpaySyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ),
        (
            flow: Void,
            request_body: AmazonpayVoidRequest,
            response_body: AmazonpayVoidResponse,
            router_data: RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ),
        (
            flow: Refund,
            request_body: AmazonpayRefundRequest,
            response_body: AmazonpayRefundResponse,
            router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ),
        (
            flow: RSync,
            response_body: AmazonpayRefundSyncResponse,
            router_data: RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        )
    ],
    amount_converters: [
        amount_converter: MinorUnit
    ],
    member_functions: {
        pub fn build_headers<F, FCD, Req, Res>(
            &self,
            req: &RouterDataV2<F, FCD, Req, Res>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError>
        where
            Self: ConnectorIntegrationV2<F, FCD, Req, Res>,
        {
            // Format UTC timestamp as yyyyMMddTHHmmssZ (e.g., 20260326T230052Z)
            let now = OffsetDateTime::now_utc();
            let amz_date = format!(
                "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
                now.year(),
                now.month() as u8,
                now.day(),
                now.hour(),
                now.minute(),
                now.second(),
            );

            let auth = amazonpay::AmazonpayAuthType::try_from(&req.connector_config)
                .change_context(errors::ConnectorError::FailedToObtainAuthType)?;

            // Amazon OAuth2 client IDs follow the format
            // `amzn1.application-oa2-client.{hex}` which is 67+ characters.
            // No length restriction is applied here.
            let client_id_val = auth.client_id.as_ref()
                .map(|c| c.clone().expose())
                .unwrap_or_default();

            let mut header = vec![
                (
                    headers::CONTENT_TYPE.to_string(),
                    "application/json".to_string().into(),
                ),
                (
                    headers::X_AMZ_DATE.to_string(),
                    amz_date.clone().into(),
                ),
                (
                    headers::X_AMZ_ALGORITHM.to_string(),
                    "AWS4-HMAC-SHA384".to_string().into(),
                ),
                (
                    headers::X_AMZ_EXPIRES.to_string(),
                    "900".to_string().into(),
                ),
                (
                    headers::X_AMZ_SOURCE.to_string(),
                    "Server".to_string().into(),
                ),
                (
                    headers::X_AMZ_USER_AGENT.to_string(),
                    "amazon-pay-connector/1.0".to_string().into(),
                ),
                (
                    headers::X_AMZ_USER_IP.to_string(),
                    "127.0.0.1".to_string().into(),
                ),
            ];

            // Include x-amz-client-id whenever client_id is configured.
            if !client_id_val.is_empty() {
                header.push((
                    headers::X_AMZ_CLIENT_ID.to_string(),
                    client_id_val.clone().into(),
                ));
            }

            // Compute AMZ signature if secret_key is configured (V2 PreAuth).
            // Falls back to plain "AMZ {api_key}" when no secret_key is present.
            let authorization = if let Some(secret_key) = auth.secret_key.as_ref() {
                let secret_key_val = secret_key.peek();

                // Get the URI path for the current request
                let url_str = self.get_url(req)?;
                let uri_path = url::Url::parse(&url_str)
                    .ok()
                    .and_then(|u| {
                        let p = u.path().to_string();
                        if p.is_empty() { None } else { Some(p) }
                    })
                    .unwrap_or_else(|| "/v1/payments/charge".to_string());

                // Determine sandbox mode from the resolved request URL (which reflects
                // the service-level base_url config), falling back to connector_config
                // base_url override if present.
                let test_mode = url_str.contains("sandbox")
                    || req
                        .connector_config
                        .base_url_override()
                        .unwrap_or("")
                        .contains("sandbox");

                // Build headers JSON object with Haskell __x_45_amz_45_* keys
                let mut headers_map = serde_json::Map::new();
                headers_map.insert(
                    "__x_45_amz_45_algorithm".to_string(),
                    serde_json::Value::String("AWS4-HMAC-SHA384".to_string()),
                );
                if !client_id_val.is_empty() {
                    headers_map.insert(
                        "__x_45_amz_45_client_45_id".to_string(),
                        serde_json::Value::String(client_id_val.clone()),
                    );
                }
                headers_map.insert(
                    "__x_45_amz_45_date".to_string(),
                    serde_json::Value::String(amz_date.clone()),
                );
                headers_map.insert(
                    "__x_45_amz_45_expires".to_string(),
                    serde_json::Value::String("900".to_string()),
                );
                headers_map.insert(
                    "__x_45_amz_45_source".to_string(),
                    serde_json::Value::String("Server".to_string()),
                );
                headers_map.insert(
                    "__x_45_amz_45_user_45_agent".to_string(),
                    serde_json::Value::String("amazon-pay-connector/1.0".to_string()),
                );
                headers_map.insert(
                    "__x_45_amz_45_user_45_ip".to_string(),
                    serde_json::Value::String("127.0.0.1".to_string()),
                );

                // Get request body JSON for signing
                let body_json_map = if let Some(body) = self.get_request_body(req)? {
                    let body_str = body.get_inner_value().peek().to_owned();
                    serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&body_str)
                        .unwrap_or_default()
                } else {
                    serde_json::Map::new()
                };

                let http_method = match self.get_http_method() {
                    common_utils::request::Method::Post => "POST",
                    common_utils::request::Method::Get => "GET",
                    common_utils::request::Method::Put => "PUT",
                    common_utils::request::Method::Delete => "DELETE",
                    common_utils::request::Method::Patch => "PATCH",
                };

                let signature = compute_amz_signature(
                    &headers_map,
                    &body_json_map,
                    &amz_date,
                    secret_key_val,
                    &uri_path,
                    http_method,
                    test_mode,
                );

                format!("AMZ {}:{}", auth.api_key.peek(), signature)
            } else {
                // Legacy fallback: no secret key configured
                format!("AMZ {}", auth.api_key.clone().expose())
            };

            header.push((
                headers::AUTHORIZATION.to_string(),
                authorization.into_masked(),
            ));

            Ok(header)
        }

        pub fn connector_base_url_payments<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.amazonpay.base_url
        }
    }
);

// =============================================================================
// CONNECTOR COMMON IMPLEMENTATION
// =============================================================================
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> ConnectorCommon
    for Amazonpay<T>
{
    fn id(&self) -> &'static str {
        "amazonpay"
    }

    fn get_currency_unit(&self) -> CurrencyUnit {
        CurrencyUnit::Minor
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn base_url<'a>(&self, _connectors: &'a Connectors) -> &'a str {
        "https://amazonpay.amazon.in"
    }

    fn get_auth_header(
        &self,
        auth_type: &ConnectorSpecificConfig,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth = amazonpay::AmazonpayAuthType::try_from(auth_type)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        // AmazonPay V2 PreAuth uses AMZ signature format: AMZ {accessKeyId}:{signature}
        // The api_key field holds the access key (amazonPayS2SAccessKey).
        // The signature is computed via HMAC-SHA384 by the AmazonPay SDK at request time.
        Ok(vec![(
            headers::AUTHORIZATION.to_string(),
            format!("AMZ {}", auth.api_key.expose()).into(),
        )])
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut events::Event>,
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        // Handle empty or non-JSON response bodies gracefully
        if res.response.is_empty() {
            return Ok(domain_types::router_data::ErrorResponse {
                status_code: res.status_code,
                code: res.status_code.to_string(),
                message: format!("HTTP error {}", res.status_code),
                reason: None,
                attempt_status: None,
                connector_transaction_id: None,
                network_decline_code: None,
                network_advice_code: None,
                network_error_message: None,
            });
        }

        let response: amazonpay::AmazonpayErrorResponse = match res
            .response
            .parse_struct("AmazonpayErrorResponse")
        {
            Ok(r) => r,
            Err(_) => {
                return Ok(domain_types::router_data::ErrorResponse {
                    status_code: res.status_code,
                    code: res.status_code.to_string(),
                    message: format!("HTTP error {}", res.status_code),
                    reason: None,
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                });
            }
        };

        with_error_response_body!(event_builder, response);

        Ok(domain_types::router_data::ErrorResponse {
            status_code: res.status_code,
            code: response.code,
            message: response.message,
            reason: None,
            attempt_status: None,
            connector_transaction_id: None,
            network_decline_code: None,
            network_advice_code: None,
            network_error_message: None,
        })
    }
}

// =============================================================================
// BODY DECODING IMPLEMENTATION
// =============================================================================
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> BodyDecoding
    for Amazonpay<T>
{
}

// =============================================================================
// AUTHORIZE FLOW IMPLEMENTATION
// =============================================================================
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Amazonpay,
    curl_request: Json(AmazonpayAuthorizeRequest),
    curl_response: AmazonpayAuthorizeResponse,
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
            let base_url = self.connector_base_url_payments(req);
            Ok(format!("{}/v1/payments/charge", base_url))
        }
    }
);

// =============================================================================
// PSYNC FLOW IMPLEMENTATION
// =============================================================================
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Amazonpay,
    curl_response: AmazonpaySyncResponse,
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
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req)
        }

        fn get_url(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            let connector_payment_id = req
                .request
                .connector_transaction_id
                .get_connector_transaction_id()
                .change_context(errors::ConnectorError::MissingConnectorTransactionID)?;

            let base_url = self.connector_base_url_payments(req);
            Ok(format!(
                "{}/v1/payments/charge?txnIdType=AmazonTransactionId&txnId={connector_payment_id}",
                base_url,
            ))
        }
    }
);

// =============================================================================
// CAPTURE FLOW IMPLEMENTATION
// =============================================================================
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Amazonpay,
    curl_request: Json(AmazonpayCaptureRequest),
    curl_response: AmazonpayCaptureResponse,
    flow_name: Capture,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsCaptureData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
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
            let base_url = self.connector_base_url_payments(req);
            Ok(format!("{}/v1/payments/capture", base_url))
        }
    }
);

// =============================================================================
// VOID FLOW IMPLEMENTATION
// =============================================================================
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Amazonpay,
    curl_request: Json(AmazonpayVoidRequest),
    curl_response: AmazonpayVoidResponse,
    flow_name: Void,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentVoidData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
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
            let base_url = self.connector_base_url_payments(req);
            Ok(format!("{}/v1/payments/release", base_url))
        }
    }
);

// =============================================================================
// REFUND FLOW IMPLEMENTATION
// =============================================================================
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Amazonpay,
    curl_request: Json(AmazonpayRefundRequest),
    curl_response: AmazonpayRefundResponse,
    flow_name: Refund,
    resource_common_data: RefundFlowData,
    flow_request: RefundsData,
    flow_response: RefundsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
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
            let base_url = &req.resource_common_data.connectors.amazonpay.base_url;
            Ok(format!("{}/v1/payments/refund", base_url))
        }
    }
);

// =============================================================================
// RSYNC FLOW IMPLEMENTATION
// =============================================================================
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Amazonpay,
    curl_response: AmazonpayRefundSyncResponse,
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
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req)
        }

        fn get_url(
            &self,
            req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            let base_url = &req.resource_common_data.connectors.amazonpay.base_url;
            let connector_refund_id = &req.request.connector_refund_id;
            Ok(format!(
                "{}/v1/payments/refund?refundId={}",
                base_url, connector_refund_id
            ))
        }
    }
);

// =============================================================================
// SUPPORTED PAYMENT METHODS
// =============================================================================

static AMAZONPAY_SUPPORTED_PAYMENT_METHODS: std::sync::LazyLock<SupportedPaymentMethods> =
    std::sync::LazyLock::new(|| {
        let mut supported = SupportedPaymentMethods::new();

        // WALLET: REDIRECT_WALLET_DEBIT and DIRECT_WALLET_DEBIT both use AmazonPay wallet
        supported.add(
            common_enums::PaymentMethod::Wallet,
            common_enums::PaymentMethodType::AmazonPay,
            PaymentMethodDetails {
                mandates: FeatureStatus::NotSupported,
                refunds: FeatureStatus::NotSupported,
                supported_capture_methods: vec![common_enums::CaptureMethod::Automatic],
                specific_features: None,
            },
        );

        supported
    });

static AMAZONPAY_CONNECTOR_INFO: ConnectorInfo = ConnectorInfo {
    display_name: "AmazonPay",
    description:
        "Amazon Pay is a digital wallet payment service that enables customers to pay using their Amazon account.",
    connector_type: PaymentConnectorCategory::PaymentGateway,
};

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorSpecifications for Amazonpay<T>
{
    fn get_connector_about(&self) -> Option<&'static ConnectorInfo> {
        Some(&AMAZONPAY_CONNECTOR_INFO)
    }

    fn get_supported_payment_methods(&self) -> Option<&'static SupportedPaymentMethods> {
        Some(&AMAZONPAY_SUPPORTED_PAYMENT_METHODS)
    }
}
