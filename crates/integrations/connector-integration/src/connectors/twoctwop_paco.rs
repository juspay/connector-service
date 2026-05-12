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
    self as twoctwop_paco, AuthorizeRoute, TwoctwopPacoAuthType, TwoctwopPacoErrorResponse,
    TwoctwopPacoInquiryResponse, TwoctwopPacoNonUiResponse,
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
        VoidPC,
        PaymentFlowData,
        PaymentsCancelPostCaptureData,
        PaymentsResponseData,
    > for TwoctwopPaco<T>
{
    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Post
    }

    fn get_content_type(&self) -> &'static str {
        CONTENT_TYPE_JOSE
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut events::Event>,
        connector_config: &ConnectorSpecificConfig,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder, connector_config)
    }

    fn build_request_v2(
        &self,
        req: &RouterDataV2<
            VoidPC,
            PaymentFlowData,
            PaymentsCancelPostCaptureData,
            PaymentsResponseData,
        >,
    ) -> CustomResult<Option<common_utils::request::Request>, errors::IntegrationError> {
        // Reverse (post-capture cancellation) routes through PACO's
        // /api/2.0/Void endpoint with the same JOSE envelope as Void;
        // the office config decides which lifecycle states it accepts.
        let auth = TwoctwopPacoAuthType::try_from(&req.connector_config)?;
        let body = transformers::build_void_pc_request(req, &auth)?;
        let base_url = self.connector_base_url_payments(req);
        let url = format!("{base_url}/api/2.0/Void");
        let headers = self.build_jose_headers(&auth);
        build_jose_request(
            url,
            common_utils::request::Method::Post,
            &auth,
            body,
            headers,
        )
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<
            VoidPC,
            PaymentFlowData,
            PaymentsCancelPostCaptureData,
            PaymentsResponseData,
        >,
        event_builder: Option<&mut events::Event>,
        res: Response,
    ) -> CustomResult<
        RouterDataV2<VoidPC, PaymentFlowData, PaymentsCancelPostCaptureData, PaymentsResponseData>,
        errors::ConnectorError,
    > {
        let auth = TwoctwopPacoAuthType::try_from(&data.connector_config).change_context(
            errors::ConnectorError::response_deserialization_failed_with_context(
                res.status_code,
                Some("twoctwop_paco: failed to read auth config for response decoding".to_string()),
            ),
        )?;
        let parsed: TwoctwopPacoNonUiResponse =
            transformers::decode_jose_response(&res.response, res.status_code, &auth)?;
        with_error_response_body!(event_builder, parsed);

        let router_data = <ResponseRouterData<
            TwoctwopPacoNonUiResponse,
            RouterDataV2<
                VoidPC,
                PaymentFlowData,
                PaymentsCancelPostCaptureData,
                PaymentsResponseData,
            >,
        > as TryInto<
            RouterDataV2<
                VoidPC,
                PaymentFlowData,
                PaymentsCancelPostCaptureData,
                PaymentsResponseData,
            >,
        >>::try_into(ResponseRouterData {
            response: parsed,
            router_data: data.clone(),
            http_code: res.status_code,
        })?;
        Ok(router_data)
    }
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
            flow: PSync,
            response_body: TwoctwopPacoInquiryResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
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
                                    (NO_ERROR_CODE.to_string(), NO_ERROR_MESSAGE.to_string())
                                }
                            }
                        }
                        Err(err) => {
                            tracing::warn!(
                                error = %err,
                                "twoctwop_paco: JOSE decrypt failed for error response"
                            );
                            (NO_ERROR_CODE.to_string(), NO_ERROR_MESSAGE.to_string())
                        }
                    }
                }
                Err(_) => (NO_ERROR_CODE.to_string(), NO_ERROR_MESSAGE.to_string()),
            }
        } else {
            match serde_json::from_slice::<TwoctwopPacoErrorResponse>(&body) {
                Ok(parsed) => {
                    with_error_response_body!(event_builder, parsed);
                    parsed.flatten()
                }
                Err(_) => (NO_ERROR_CODE.to_string(), NO_ERROR_MESSAGE.to_string()),
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
    curl_response: TwoctwopPacoInquiryResponse,
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

// RSync — same Inquiry endpoint as PSync. Hand-rolled because the bridge
// templating struct would clash with PSync's (same response_body type).
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
    for TwoctwopPaco<T>
{
    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Get
    }

    fn get_content_type(&self) -> &'static str {
        CONTENT_TYPE_JSON
    }

    fn get_headers(
        &self,
        req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::IntegrationError> {
        let auth = TwoctwopPacoAuthType::try_from(&req.connector_config)?;
        Ok(self.build_inquiry_headers(&auth))
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

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut events::Event>,
        connector_config: &ConnectorSpecificConfig,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder, connector_config)
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
        let parsed: TwoctwopPacoInquiryResponse = if res.response.is_empty() {
            serde_json::from_str("{}").change_context(
                errors::ConnectorError::response_deserialization_failed_with_context(
                    res.status_code,
                    Some("twoctwop_paco rsync: empty response".to_string()),
                ),
            )?
        } else {
            serde_json::from_slice(&res.response).change_context(
                errors::ConnectorError::response_deserialization_failed_with_context(
                    res.status_code,
                    Some(
                        "twoctwop_paco rsync: response shape mismatch on Inquiry endpoint"
                            .to_string(),
                    ),
                ),
            )?
        };
        with_error_response_body!(event_builder, parsed);

        let router_data = <ResponseRouterData<
            TwoctwopPacoInquiryResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        > as TryInto<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >>::try_into(ResponseRouterData {
            response: parsed,
            router_data: data.clone(),
            http_code: res.status_code,
        })?;
        Ok(router_data)
    }
}

// ---------- Hand-rolled JOSE flows ----------

fn build_jose_request<B>(
    url: String,
    method: common_utils::request::Method,
    auth: &TwoctwopPacoAuthType,
    body: B,
    headers: Vec<(String, Maskable<String>)>,
) -> CustomResult<Option<common_utils::request::Request>, errors::IntegrationError>
where
    B: Serialize,
{
    let jwe_bytes = transformers::build_jose_envelope(body, auth)?;
    Ok(Some(
        common_utils::request::RequestBuilder::new()
            .method(method)
            .url(&url)
            .attach_default_headers()
            .headers(headers)
            .set_body(common_utils::request::RequestContent::RawBytes(jwe_bytes))
            .build(),
    ))
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        Authorize,
        PaymentFlowData,
        PaymentsAuthorizeData<T>,
        PaymentsResponseData,
    > for TwoctwopPaco<T>
{
    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Post
    }

    fn get_content_type(&self) -> &'static str {
        CONTENT_TYPE_JOSE
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut events::Event>,
        connector_config: &ConnectorSpecificConfig,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder, connector_config)
    }

    fn build_request_v2(
        &self,
        req: &RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData<T>,
            PaymentsResponseData,
        >,
    ) -> CustomResult<Option<common_utils::request::Request>, errors::IntegrationError> {
        let auth = TwoctwopPacoAuthType::try_from(&req.connector_config)?;
        let request = transformers::build_authorize_request(req, &auth)?;
        let base_url = self.connector_base_url_payments(req);
        let path = match request.route {
            AuthorizeRoute::CardNonUi => "/api/2.0/Payment/nonUi",
            AuthorizeRoute::WalletPrepaymentUi => "/api/2.0/Payment/prepaymentUi",
        };
        let url = format!("{base_url}{path}");
        let headers = self.build_jose_headers(&auth);
        build_jose_request(
            url,
            common_utils::request::Method::Post,
            &auth,
            request.body,
            headers,
        )
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
        let auth = TwoctwopPacoAuthType::try_from(&data.connector_config).change_context(
            errors::ConnectorError::response_deserialization_failed_with_context(
                res.status_code,
                Some("twoctwop_paco: failed to read auth config for response decoding".to_string()),
            ),
        )?;
        let parsed: TwoctwopPacoNonUiResponse =
            transformers::decode_jose_response(&res.response, res.status_code, &auth)?;
        with_error_response_body!(event_builder, parsed);

        let router_data = <ResponseRouterData<
            TwoctwopPacoNonUiResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        > as TryInto<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >>::try_into(ResponseRouterData {
            response: parsed,
            router_data: data.clone(),
            http_code: res.status_code,
        })?;
        Ok(router_data)
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
    for TwoctwopPaco<T>
{
    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Put
    }

    fn get_content_type(&self) -> &'static str {
        CONTENT_TYPE_JOSE
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut events::Event>,
        connector_config: &ConnectorSpecificConfig,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder, connector_config)
    }

    fn build_request_v2(
        &self,
        req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
    ) -> CustomResult<Option<common_utils::request::Request>, errors::IntegrationError> {
        let auth = TwoctwopPacoAuthType::try_from(&req.connector_config)?;
        let body = transformers::build_capture_request(req, &auth)?;
        let base_url = self.connector_base_url_payments(req);
        let url = format!("{base_url}/api/2.0/Settlement");
        let headers = self.build_jose_headers(&auth);
        build_jose_request(
            url,
            common_utils::request::Method::Put,
            &auth,
            body,
            headers,
        )
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
        let auth = TwoctwopPacoAuthType::try_from(&data.connector_config).change_context(
            errors::ConnectorError::response_deserialization_failed_with_context(
                res.status_code,
                Some("twoctwop_paco: failed to read auth config for response decoding".to_string()),
            ),
        )?;
        let parsed: TwoctwopPacoNonUiResponse =
            transformers::decode_jose_response(&res.response, res.status_code, &auth)?;
        with_error_response_body!(event_builder, parsed);

        let router_data = <ResponseRouterData<
            TwoctwopPacoNonUiResponse,
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        > as TryInto<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >>::try_into(ResponseRouterData {
            response: parsed,
            router_data: data.clone(),
            http_code: res.status_code,
        })?;
        Ok(router_data)
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
    for TwoctwopPaco<T>
{
    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Post
    }

    fn get_content_type(&self) -> &'static str {
        CONTENT_TYPE_JOSE
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut events::Event>,
        connector_config: &ConnectorSpecificConfig,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder, connector_config)
    }

    fn build_request_v2(
        &self,
        req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
    ) -> CustomResult<Option<common_utils::request::Request>, errors::IntegrationError> {
        let auth = TwoctwopPacoAuthType::try_from(&req.connector_config)?;
        let body = transformers::build_void_request(req, &auth)?;
        let base_url = self.connector_base_url_payments(req);
        let url = format!("{base_url}/api/2.0/Void");
        let headers = self.build_jose_headers(&auth);
        build_jose_request(
            url,
            common_utils::request::Method::Post,
            &auth,
            body,
            headers,
        )
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
        let auth = TwoctwopPacoAuthType::try_from(&data.connector_config).change_context(
            errors::ConnectorError::response_deserialization_failed_with_context(
                res.status_code,
                Some("twoctwop_paco: failed to read auth config for response decoding".to_string()),
            ),
        )?;
        let parsed: TwoctwopPacoNonUiResponse =
            transformers::decode_jose_response(&res.response, res.status_code, &auth)?;
        with_error_response_body!(event_builder, parsed);

        let router_data = <ResponseRouterData<
            TwoctwopPacoNonUiResponse,
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        > as TryInto<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        >>::try_into(ResponseRouterData {
            response: parsed,
            router_data: data.clone(),
            http_code: res.status_code,
        })?;
        Ok(router_data)
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
    for TwoctwopPaco<T>
{
    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Post
    }

    fn get_content_type(&self) -> &'static str {
        CONTENT_TYPE_JOSE
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut events::Event>,
        connector_config: &ConnectorSpecificConfig,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder, connector_config)
    }

    fn build_request_v2(
        &self,
        req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> CustomResult<Option<common_utils::request::Request>, errors::IntegrationError> {
        let auth = TwoctwopPacoAuthType::try_from(&req.connector_config)?;
        let body = transformers::build_refund_request(req, &auth)?;
        let base_url = self.connector_base_url_refunds(req);
        let url = format!("{base_url}/api/2.0/Refund/refund");
        let headers = self.build_jose_headers(&auth);
        build_jose_request(
            url,
            common_utils::request::Method::Post,
            &auth,
            body,
            headers,
        )
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
        let auth = TwoctwopPacoAuthType::try_from(&data.connector_config).change_context(
            errors::ConnectorError::response_deserialization_failed_with_context(
                res.status_code,
                Some("twoctwop_paco: failed to read auth config for response decoding".to_string()),
            ),
        )?;
        let parsed: TwoctwopPacoNonUiResponse =
            transformers::decode_jose_response(&res.response, res.status_code, &auth)?;
        with_error_response_body!(event_builder, parsed);

        let router_data = <ResponseRouterData<
            TwoctwopPacoNonUiResponse,
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        > as TryInto<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >>::try_into(ResponseRouterData {
            response: parsed,
            router_data: data.clone(),
            http_code: res.status_code,
        })?;
        Ok(router_data)
    }
}

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
// PACO is native 3DS. The handshake collapses into:
//   PreAuthenticate (no-op — PACO has no DDC step)
//   Authenticate    (POST /Payment/nonUi with request3dsFlag=Y → ACS challenge or CAVV)
//   PostAuthenticate (GET /Inquiry/transactionStatus to confirm completion)

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        PreAuthenticate,
        PaymentFlowData,
        PaymentsPreAuthenticateData<T>,
        PaymentsResponseData,
    > for TwoctwopPaco<T>
{
    // No build_request_v2: PACO has no DDC step. Returning None from the
    // default implementation tells the orchestrator there is no network call,
    // and handle_response_v2 below shapes the response router data.
    fn build_request_v2(
        &self,
        _req: &RouterDataV2<
            PreAuthenticate,
            PaymentFlowData,
            PaymentsPreAuthenticateData<T>,
            PaymentsResponseData,
        >,
    ) -> CustomResult<Option<common_utils::request::Request>, errors::IntegrationError> {
        tracing::debug!("twoctwop_paco: PreAuthenticate is a no-op (no DDC step)");
        Ok(None)
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<
            PreAuthenticate,
            PaymentFlowData,
            PaymentsPreAuthenticateData<T>,
            PaymentsResponseData,
        >,
        _event_builder: Option<&mut events::Event>,
        _res: Response,
    ) -> CustomResult<
        RouterDataV2<
            PreAuthenticate,
            PaymentFlowData,
            PaymentsPreAuthenticateData<T>,
            PaymentsResponseData,
        >,
        errors::ConnectorError,
    > {
        Ok(transformers::build_preauthenticate_passthrough(data))
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut events::Event>,
        connector_config: &ConnectorSpecificConfig,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder, connector_config)
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        Authenticate,
        PaymentFlowData,
        PaymentsAuthenticateData<T>,
        PaymentsResponseData,
    > for TwoctwopPaco<T>
{
    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Post
    }

    fn get_content_type(&self) -> &'static str {
        CONTENT_TYPE_JOSE
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut events::Event>,
        connector_config: &ConnectorSpecificConfig,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder, connector_config)
    }

    fn build_request_v2(
        &self,
        req: &RouterDataV2<
            Authenticate,
            PaymentFlowData,
            PaymentsAuthenticateData<T>,
            PaymentsResponseData,
        >,
    ) -> CustomResult<Option<common_utils::request::Request>, errors::IntegrationError> {
        let auth = TwoctwopPacoAuthType::try_from(&req.connector_config)?;
        let body = transformers::build_authenticate_request(req, &auth)?;
        let base_url = self.connector_base_url_payments(req);
        let url = format!("{base_url}/api/2.0/Payment/nonUi");
        let headers = self.build_jose_headers(&auth);
        tracing::debug!(url = %url, "twoctwop_paco: Authenticate request built");
        build_jose_request(
            url,
            common_utils::request::Method::Post,
            &auth,
            body,
            headers,
        )
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<
            Authenticate,
            PaymentFlowData,
            PaymentsAuthenticateData<T>,
            PaymentsResponseData,
        >,
        event_builder: Option<&mut events::Event>,
        res: Response,
    ) -> CustomResult<
        RouterDataV2<
            Authenticate,
            PaymentFlowData,
            PaymentsAuthenticateData<T>,
            PaymentsResponseData,
        >,
        errors::ConnectorError,
    > {
        let auth = TwoctwopPacoAuthType::try_from(&data.connector_config).change_context(
            errors::ConnectorError::response_deserialization_failed_with_context(
                res.status_code,
                Some("twoctwop_paco: failed to read auth config for response decoding".to_string()),
            ),
        )?;
        let parsed: TwoctwopPacoNonUiResponse =
            transformers::decode_jose_response(&res.response, res.status_code, &auth)?;
        with_error_response_body!(event_builder, parsed);

        let router_data = <ResponseRouterData<
            TwoctwopPacoNonUiResponse,
            RouterDataV2<
                Authenticate,
                PaymentFlowData,
                PaymentsAuthenticateData<T>,
                PaymentsResponseData,
            >,
        > as TryInto<
            RouterDataV2<
                Authenticate,
                PaymentFlowData,
                PaymentsAuthenticateData<T>,
                PaymentsResponseData,
            >,
        >>::try_into(ResponseRouterData {
            response: parsed,
            router_data: data.clone(),
            http_code: res.status_code,
        })?;
        Ok(router_data)
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        PostAuthenticate,
        PaymentFlowData,
        PaymentsPostAuthenticateData<T>,
        PaymentsResponseData,
    > for TwoctwopPaco<T>
{
    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Get
    }

    fn get_content_type(&self) -> &'static str {
        CONTENT_TYPE_JSON
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut events::Event>,
        connector_config: &ConnectorSpecificConfig,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder, connector_config)
    }

    fn get_headers(
        &self,
        req: &RouterDataV2<
            PostAuthenticate,
            PaymentFlowData,
            PaymentsPostAuthenticateData<T>,
            PaymentsResponseData,
        >,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::IntegrationError> {
        let auth = TwoctwopPacoAuthType::try_from(&req.connector_config)?;
        Ok(self.build_inquiry_headers(&auth))
    }

    fn get_url(
        &self,
        req: &RouterDataV2<
            PostAuthenticate,
            PaymentFlowData,
            PaymentsPostAuthenticateData<T>,
            PaymentsResponseData,
        >,
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

    fn build_request_v2(
        &self,
        req: &RouterDataV2<
            PostAuthenticate,
            PaymentFlowData,
            PaymentsPostAuthenticateData<T>,
            PaymentsResponseData,
        >,
    ) -> CustomResult<Option<common_utils::request::Request>, errors::IntegrationError> {
        let auth = TwoctwopPacoAuthType::try_from(&req.connector_config)?;
        let url = self.get_url(req)?;
        let headers = self.build_inquiry_headers(&auth);
        tracing::debug!(url = %url, "twoctwop_paco: PostAuthenticate inquiry request built");
        Ok(Some(
            common_utils::request::RequestBuilder::new()
                .method(common_utils::request::Method::Get)
                .url(&url)
                .attach_default_headers()
                .headers(headers)
                .build(),
        ))
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<
            PostAuthenticate,
            PaymentFlowData,
            PaymentsPostAuthenticateData<T>,
            PaymentsResponseData,
        >,
        event_builder: Option<&mut events::Event>,
        res: Response,
    ) -> CustomResult<
        RouterDataV2<
            PostAuthenticate,
            PaymentFlowData,
            PaymentsPostAuthenticateData<T>,
            PaymentsResponseData,
        >,
        errors::ConnectorError,
    > {
        let parsed: TwoctwopPacoInquiryResponse = if res.response.is_empty() {
            serde_json::from_str("{}").change_context(
                errors::ConnectorError::response_deserialization_failed_with_context(
                    res.status_code,
                    Some("twoctwop_paco PostAuthenticate: empty response".to_string()),
                ),
            )?
        } else {
            serde_json::from_slice(&res.response).change_context(
                errors::ConnectorError::response_deserialization_failed_with_context(
                    res.status_code,
                    Some(
                        "twoctwop_paco PostAuthenticate: response shape mismatch on Inquiry endpoint"
                            .to_string(),
                    ),
                ),
            )?
        };
        with_error_response_body!(event_builder, parsed);

        let router_data = <ResponseRouterData<
            TwoctwopPacoInquiryResponse,
            RouterDataV2<
                PostAuthenticate,
                PaymentFlowData,
                PaymentsPostAuthenticateData<T>,
                PaymentsResponseData,
            >,
        > as TryInto<
            RouterDataV2<
                PostAuthenticate,
                PaymentFlowData,
                PaymentsPostAuthenticateData<T>,
                PaymentsResponseData,
            >,
        >>::try_into(ResponseRouterData {
            response: parsed,
            router_data: data.clone(),
            http_code: res.status_code,
        })?;
        Ok(router_data)
    }
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
