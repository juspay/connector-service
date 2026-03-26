pub mod transformers;

use std::{
    fmt::Debug,
    marker::{Send, Sync},
    sync::LazyLock,
};

use common_enums::{CaptureMethod, CurrencyUnit, PaymentMethod, PaymentMethodType};
use common_utils::types::MinorUnit;
use common_utils::{errors::CustomResult, events, ext_traits::ByteSliceExt};
use domain_types::{
    connector_flow::{
        Accept, Authenticate, Authorize, Capture, CreateAccessToken,
        CreateConnectorCustomer, CreateOrder, CreateSessionToken, DefendDispute,
        IncrementalAuthorization, MandateRevoke, PSync, PaymentMethodToken, PostAuthenticate,
        PreAuthenticate, RSync, Refund, RepeatPayment, SdkSessionToken, SetupMandate,
        SubmitEvidence, Void, VoidPC, VerifyWebhookSource,
    },
    connector_types::{
        AcceptDisputeData, AccessTokenRequestData, AccessTokenResponseData, ConnectorCustomerData,
        ConnectorCustomerResponse, ConnectorSpecifications, DisputeDefendData, DisputeFlowData,
        DisputeResponseData, MandateRevokeRequestData, MandateRevokeResponseData,
        PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData,
        PaymentMethodTokenResponse, PaymentMethodTokenizationData, PaymentVoidData,
        PaymentsAuthenticateData, PaymentsAuthorizeData, PaymentsCancelPostCaptureData,
        PaymentsCaptureData, PaymentsIncrementalAuthorizationData, PaymentsPostAuthenticateData,
        PaymentsPreAuthenticateData, PaymentsResponseData, PaymentsSdkSessionTokenData,
        PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData,
        RepeatPaymentData, SessionTokenRequestData, SessionTokenResponseData,
        SetupMandateRequestData, SubmitEvidenceData, SupportedPaymentMethodsExt,
        VerifyWebhookSourceFlowData,
    },
    errors,
    payment_method_data::{DefaultPCIHolder, PaymentMethodDataTypes},
    router_data::{ConnectorSpecificConfig, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    router_request_types::VerifyWebhookSourceRequestData,
    router_response_types::VerifyWebhookSourceResponseData,
    types::{
        ConnectorInfo, Connectors, FeatureStatus, PaymentConnectorCategory, PaymentMethodDetails,
        SupportedPaymentMethods,
    },
};
use error_stack::ResultExt;
use hyperswitch_masking::{Mask, Maskable};
use interfaces::{
    api::ConnectorCommon,
    connector_integration_v2::ConnectorIntegrationV2,
    connector_types::{self},
    decode::BodyDecoding,
};
use serde::Serialize;
use transformers as billdesk;
use billdesk::{BilldeskPaymentsRequest, BilldeskPaymentsResponse, BilldeskSyncRequest, BilldeskSyncResponse, BilldeskRefundRequest, BilldeskRefundResponse, BilldeskRSyncRequest, BilldeskRSyncResponse};

use super::macros;
use crate::{types::ResponseRouterData, with_error_response_body};

pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const ACCEPT: &str = "Accept";
    pub(crate) const BD_TRACEID: &str = "BD-Traceid";
    pub(crate) const BD_TIMESTAMP: &str = "BD-Timestamp";
    pub(crate) const AUTHORIZATION: &str = "Authorization";
}

// ===== TRAIT IMPLEMENTATIONS =====

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ConnectorServiceTrait<T> for Billdesk<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAuthorizeV2<T> for Billdesk<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentSyncV2 for Billdesk<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentCapture for Billdesk<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentVoidV2 for Billdesk<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundV2 for Billdesk<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundSyncV2 for Billdesk<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::AcceptDispute for Billdesk<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::CreateConnectorCustomer for Billdesk<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::DisputeDefend for Billdesk<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::IncomingWebhook for Billdesk<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::MandateRevokeV2 for Billdesk<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAccessToken for Billdesk<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAuthenticateV2<T> for Billdesk<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentIncrementalAuthorization for Billdesk<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentOrderCreate for Billdesk<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentPostAuthenticateV2<T> for Billdesk<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentPreAuthenticateV2<T> for Billdesk<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentSessionToken for Billdesk<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentTokenV2<T> for Billdesk<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentVoidPostCaptureV2 for Billdesk<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RepeatPaymentV2<T> for Billdesk<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::SdkSessionTokenV2 for Billdesk<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::SetupMandateV2<T> for Billdesk<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::SubmitEvidenceV2 for Billdesk<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ValidationTrait for Billdesk<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::VerifyRedirectResponse for Billdesk<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::VerifyWebhookSourceV2 for Billdesk<T>
{
}

// ===== MACRO: create_all_prerequisites! =====
// Creates the Billdesk<T> struct, bridges, and helper methods.

macros::create_all_prerequisites!(
    connector_name: Billdesk,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: BilldeskPaymentsRequest<T>,
            response_body: BilldeskPaymentsResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: PSync,
            request_body: BilldeskSyncRequest,
            response_body: BilldeskSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ),
        (
            flow: Refund,
            request_body: BilldeskRefundRequest,
            response_body: BilldeskRefundResponse,
            router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ),
        (
            flow: RSync,
            request_body: BilldeskRSyncRequest,
            response_body: BilldeskRSyncResponse,
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
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            use ring::hmac;
            use std::time::{SystemTime, UNIX_EPOCH};

            // Generate a UUID-like trace ID (16 hex chars)
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default();
            let traceid = format!("{:016x}", now.as_nanos() & 0xFFFF_FFFF_FFFF_FFFF_u128);
            // Timestamp in Billdesk format: YYYYMMDDHHmmss
            let secs = now.as_secs();
            let ts = {
                // Simple UTC timestamp formatting without external crate
                let s = secs;
                let sec = s % 60;
                let min = (s / 60) % 60;
                let hour = (s / 3600) % 24;
                let days = s / 86400;
                // Approximate date from days since epoch (good enough for header)
                let year_approx = 1970 + days / 365;
                let day_of_year = days % 365;
                let (month, day) = {
                    let months = [31u64, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
                    let mut m = 1u64;
                    let mut remaining = day_of_year;
                    for &ml in &months {
                        if remaining < ml { break; }
                        remaining -= ml;
                        m += 1;
                    }
                    (m, remaining + 1)
                };
                format!("{:04}{:02}{:02}{:02}{:02}{:02}", year_approx, month, day, hour, min, sec)
            };

            let mut header = vec![
                (
                    headers::CONTENT_TYPE.to_string(),
                    "application/json".to_string().into(),
                ),
                (
                    headers::ACCEPT.to_string(),
                    "application/json".to_string().into(),
                ),
                (
                    headers::BD_TRACEID.to_string(),
                    format!("JUS{}", traceid).into(),
                ),
                (
                    headers::BD_TIMESTAMP.to_string(),
                    ts.clone().into(),
                ),
            ];

            // Compute HMAC-SHA256 Authorization header for BillDesk V2 JSON API
            // Format: HMACSignature {userId}:{UPPER(HMAC-SHA256-of-msg)}
            // msg = POST|<uri>|application/json|application/json|JUS{traceid}|{timestamp}
            let auth = billdesk::BilldeskAuthType::try_from(&req.connector_config)
                .change_context(errors::ConnectorError::FailedToObtainAuthType)?;

            if let Some(secret_key) = &auth.key1 {
                use hyperswitch_masking::ExposeInterface;
                let user_id = auth.api_key.clone().expose();
                let trace_with_prefix = format!("JUS{}", traceid);
                // Build HMAC message: method|uri|content-type|accept|traceid|timestamp
                // URI is not available at header-build time; use empty string as placeholder
                let hmac_msg = format!(
                    "POST||application/json|application/json|{}|{}",
                    trace_with_prefix, ts
                );
                let key_bytes = secret_key.clone().expose();
                let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, key_bytes.as_bytes());
                let signature = hmac::sign(&hmac_key, hmac_msg.as_bytes());
                let hex_sig = hex::encode(signature.as_ref()).to_uppercase();
                let auth_value = format!("HMACSignature {}:{}", user_id, hex_sig);
                header.push((
                    headers::AUTHORIZATION.to_string(),
                    auth_value.into_masked(),
                ));
            }

            Ok(header)
        }

        pub fn connector_base_url_payments<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> &'a str {
            req.resource_common_data.connectors.billdesk.base_url.as_ref()
        }

        pub fn connector_base_url_refunds<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, RefundFlowData, Req, Res>,
        ) -> &'a str {
            req.resource_common_data.connectors.billdesk.base_url.as_ref()
        }
    }
);

// ===== CONNECTOR COMMON IMPLEMENTATION =====
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> ConnectorCommon
    for Billdesk<T>
{
    fn id(&self) -> &'static str {
        "billdesk"
    }

    fn get_currency_unit(&self) -> CurrencyUnit {
        CurrencyUnit::Minor
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.billdesk.base_url.as_ref()
    }

    fn get_auth_header(
        &self,
        _auth_type: &ConnectorSpecificConfig,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        // Billdesk V2 JSON API authenticates via the request body (mercid embedded in JSON).
        // No Authorization header is required or accepted by Billdesk.
        Ok(vec![])
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut events::Event>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: billdesk::BilldeskErrorResponse = res
            .response
            .parse_struct("BilldeskErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        with_error_response_body!(event_builder, response);

        Ok(ErrorResponse {
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

// ===== BODY DECODING =====
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> BodyDecoding
    for Billdesk<T>
{
}

// ===== AUTHORIZE FLOW IMPLEMENTATION =====
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Billdesk,
    curl_request: Json(BilldeskPaymentsRequest),
    curl_response: BilldeskPaymentsResponse,
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
            Ok(base_url.to_string())
        }
    }
);

// ===== PSYNC FLOW IMPLEMENTATION =====
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Billdesk,
    curl_request: Json(BilldeskSyncRequest),
    curl_response: BilldeskSyncResponse,
    flow_name: PSync,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsSyncData,
    flow_response: PaymentsResponseData,
    http_method: Post,
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
            let base_url = self.connector_base_url_payments(req);
            Ok(format!("{base_url}/transactions/status"))
        }
    }
);

// ===== REFUND FLOW IMPLEMENTATION =====
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Billdesk,
    curl_request: Json(BilldeskRefundRequest),
    curl_response: BilldeskRefundResponse,
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
            let base_url = self.connector_base_url_refunds(req);
            let connector_transaction_id = &req.request.connector_transaction_id;
            Ok(format!("{base_url}/transactions/{connector_transaction_id}/refund"))
        }
    }
);

// ===== EMPTY STUBS FOR NON-AUTHORIZE FLOWS =====

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    for Billdesk<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        CreateConnectorCustomer,
        PaymentFlowData,
        ConnectorCustomerData,
        ConnectorCustomerResponse,
    > for Billdesk<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
    for Billdesk<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        MandateRevoke,
        PaymentFlowData,
        MandateRevokeRequestData,
        MandateRevokeResponseData,
    > for Billdesk<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        CreateAccessToken,
        PaymentFlowData,
        AccessTokenRequestData,
        AccessTokenResponseData,
    > for Billdesk<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        Authenticate,
        PaymentFlowData,
        PaymentsAuthenticateData<T>,
        PaymentsResponseData,
    > for Billdesk<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
    for Billdesk<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        IncrementalAuthorization,
        PaymentFlowData,
        PaymentsIncrementalAuthorizationData,
        PaymentsResponseData,
    > for Billdesk<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for Billdesk<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        PostAuthenticate,
        PaymentFlowData,
        PaymentsPostAuthenticateData<T>,
        PaymentsResponseData,
    > for Billdesk<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        PreAuthenticate,
        PaymentFlowData,
        PaymentsPreAuthenticateData<T>,
        PaymentsResponseData,
    > for Billdesk<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        CreateSessionToken,
        PaymentFlowData,
        SessionTokenRequestData,
        SessionTokenResponseData,
    > for Billdesk<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        PaymentMethodToken,
        PaymentFlowData,
        PaymentMethodTokenizationData<T>,
        PaymentMethodTokenResponse,
    > for Billdesk<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        VoidPC,
        PaymentFlowData,
        PaymentsCancelPostCaptureData,
        PaymentsResponseData,
    > for Billdesk<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
    for Billdesk<T>
{
}

// ===== RSYNC FLOW IMPLEMENTATION =====
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Billdesk,
    curl_request: Json(BilldeskRSyncRequest),
    curl_response: BilldeskRSyncResponse,
    flow_name: RSync,
    resource_common_data: RefundFlowData,
    flow_request: RefundSyncData,
    flow_response: RefundsResponseData,
    http_method: Post,
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
            let base_url = self.connector_base_url_refunds(req);
            let connector_refund_id = &req.request.connector_refund_id;
            Ok(format!("{base_url}/refunds/{connector_refund_id}/status"))
        }
    }
);

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        RepeatPayment,
        PaymentFlowData,
        RepeatPaymentData<T>,
        PaymentsResponseData,
    > for Billdesk<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        SdkSessionToken,
        PaymentFlowData,
        PaymentsSdkSessionTokenData,
        PaymentsResponseData,
    > for Billdesk<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData<T>,
        PaymentsResponseData,
    > for Billdesk<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
    for Billdesk<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        VerifyWebhookSource,
        VerifyWebhookSourceFlowData,
        VerifyWebhookSourceRequestData,
        VerifyWebhookSourceResponseData,
    > for Billdesk<T>
{
}

// ===== SOURCE VERIFICATION =====
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification for Billdesk<T>
{
}

// ===== SUPPORTED PAYMENT METHODS =====
static BILLDESK_SUPPORTED_PAYMENT_METHODS: LazyLock<SupportedPaymentMethods> =
    LazyLock::new(|| {
        let auto_capture = vec![CaptureMethod::Automatic];
        let mut supported = SupportedPaymentMethods::new();

        // UPI: UpiIntent (UPI_PAY)
        supported.add(
            PaymentMethod::Upi,
            PaymentMethodType::UpiIntent,
            PaymentMethodDetails {
                mandates: FeatureStatus::NotSupported,
                refunds: FeatureStatus::Supported,
                supported_capture_methods: auto_capture.clone(),
                specific_features: None,
            },
        );

        // UPI: UpiCollect (UPI_COLLECT)
        supported.add(
            PaymentMethod::Upi,
            PaymentMethodType::UpiCollect,
            PaymentMethodDetails {
                mandates: FeatureStatus::NotSupported,
                refunds: FeatureStatus::Supported,
                supported_capture_methods: auto_capture.clone(),
                specific_features: None,
            },
        );

        // UPI: UpiQr (UPI_QR)
        supported.add(
            PaymentMethod::Upi,
            PaymentMethodType::UpiQr,
            PaymentMethodDetails {
                mandates: FeatureStatus::NotSupported,
                refunds: FeatureStatus::Supported,
                supported_capture_methods: auto_capture.clone(),
                specific_features: None,
            },
        );

        // Net Banking: Netbanking
        supported.add(
            PaymentMethod::Netbanking,
            PaymentMethodType::Netbanking,
            PaymentMethodDetails {
                mandates: FeatureStatus::NotSupported,
                refunds: FeatureStatus::Supported,
                supported_capture_methods: auto_capture.clone(),
                specific_features: None,
            },
        );

        supported
    });

static BILLDESK_CONNECTOR_INFO: ConnectorInfo = ConnectorInfo {
    display_name: "BillDesk",
    description: "BillDesk is one of India's leading payment gateways providing UPI, Netbanking, Card, and Wallet payment options.",
    connector_type: PaymentConnectorCategory::PaymentGateway,
};

static BILLDESK_SUPPORTED_WEBHOOK_FLOWS: &[common_enums::EventClass] =
    &[common_enums::EventClass::Payments, common_enums::EventClass::Refunds];

impl ConnectorSpecifications for Billdesk<DefaultPCIHolder> {
    fn get_connector_about(&self) -> Option<&'static ConnectorInfo> {
        Some(&BILLDESK_CONNECTOR_INFO)
    }

    fn get_supported_webhook_flows(&self) -> Option<&'static [common_enums::EventClass]> {
        Some(BILLDESK_SUPPORTED_WEBHOOK_FLOWS)
    }

    fn get_supported_payment_methods(&self) -> Option<&'static SupportedPaymentMethods> {
        Some(&BILLDESK_SUPPORTED_PAYMENT_METHODS)
    }
}
