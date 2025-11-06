pub mod transformers;
use common_utils::Maskable;

use common_utils::{
    consts::NO_ERROR_CODE, errors::CustomResult, ext_traits::BytesExt, fp_utils::generate_id,
    types::FloatMajorUnit,
};
use domain_types::{
    connector_flow::{
        Accept, Authenticate, Authorize, Capture, CreateConnectorCustomer, CreateOrder,
        CreateSessionToken, DefendDispute, PSync, PostAuthenticate, PreAuthenticate, RSync, Refund,
        RepeatPayment, SetupMandate, SubmitEvidence, Void, VoidPC,
    },
    connector_types::{
        AcceptDisputeData, ConnectorCustomerData, ConnectorCustomerResponse, DisputeDefendData,
        DisputeFlowData, DisputeResponseData, PaymentCreateOrderData, PaymentCreateOrderResponse,
        PaymentFlowData, PaymentVoidData, PaymentsAuthenticateData, PaymentsAuthorizeData,
        PaymentsCancelPostCaptureData, PaymentsCaptureData, PaymentsPostAuthenticateData,
        PaymentsPreAuthenticateData, PaymentsResponseData, PaymentsSyncData, RefundFlowData,
        RefundSyncData, RefundsData, RefundsResponseData, RepeatPaymentData,
        SessionTokenRequestData, SessionTokenResponseData, SetupMandateRequestData,
        SubmitEvidenceData,
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
use error_stack::ResultExt;
// use crate::masking::{ExposeInterface, Mask, Maskable};
use interfaces::{
    api::ConnectorCommon, connector_integration_v2::ConnectorIntegrationV2, connector_types,
    events::connector_api_logs::ConnectorEvent,
use serde::Serialize;
use std::{
    fmt::Debug,
    marker::{Send, Sync},
use transformers::{
    self as helcim, HelcimCaptureRequest, HelcimPaymentsCaptureResponse, HelcimPaymentsRequest,
    HelcimPaymentsResponse, HelcimPaymentsSyncResponse, HelcimPaymentsVoidResponse,
    HelcimRefundRequest, HelcimVoidRequest, RefundResponse, RefundSyncResponse,
use super::macros;
use crate::{types::ResponseRouterData, with_error_response_body};
pub const BASE64_ENGINE: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
// Helcim requires an Idempotency Key of length 25. We prefix every ID by "HS_".
const ID_LENGTH: usize = 22;
pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const API_TOKEN: &str = "api-token";
    pub(crate) const IDEMPOTENCY_KEY: &str = "idempotency-key";
}
// Trait implementations with generic type parameters
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ConnectorServiceTrait<T> for Helcim<T>
{
    connector_types::PaymentAuthorizeV2<T> for Helcim<T>
    connector_types::PaymentSyncV2 for Helcim<T>
    connector_types::PaymentVoidV2 for Helcim<T>
    connector_types::RefundSyncV2 for Helcim<T>
    connector_types::RefundV2 for Helcim<T>
    connector_types::PaymentCapture for Helcim<T>
    connector_types::PaymentVoidPostCaptureV2 for Helcim<T>
    ConnectorIntegrationV2<
        VoidPC,
        PaymentFlowData,
        PaymentsCancelPostCaptureData,
        PaymentsResponseData,
    > for Helcim<T>
    interfaces::verification::SourceVerification<
    connector_types::ValidationTrait for Helcim<T>
    connector_types::PaymentOrderCreate for Helcim<T>
    connector_types::SetupMandateV2<T> for Helcim<T>
    connector_types::RepeatPaymentV2 for Helcim<T>
    connector_types::AcceptDispute for Helcim<T>
    connector_types::SubmitEvidenceV2 for Helcim<T>
    connector_types::DisputeDefend for Helcim<T>
    connector_types::IncomingWebhook for Helcim<T>
    connector_types::PaymentSessionToken for Helcim<T>
    connector_types::PaymentTokenV2<T> for Helcim<T>
    connector_types::PaymentAccessToken for Helcim<T>
    connector_types::CreateConnectorCustomer for Helcim<T>
    connector_types::PaymentPreAuthenticateV2<T> for Helcim<T>
    connector_types::PaymentAuthenticateV2<T> for Helcim<T>
    connector_types::PaymentPostAuthenticateV2<T> for Helcim<T>
macros::create_all_prerequisites!(
    connector_name: Helcim,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: HelcimPaymentsRequest<T>,
            response_body: HelcimPaymentsResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
            flow: PSync,
            response_body: HelcimPaymentsSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            flow: Capture,
            request_body: HelcimCaptureRequest,
            response_body: HelcimPaymentsCaptureResponse,
            router_data: RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            flow: Void,
            request_body: HelcimVoidRequest,
            response_body: HelcimPaymentsVoidResponse,
            router_data: RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            flow: Refund,
            request_body: HelcimRefundRequest,
            response_body: RefundResponse,
            router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            flow: RSync,
            response_body: RefundSyncResponse,
            router_data: RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        )
    ],
    amount_converters: [amount_converter: FloatMajorUnit],
    member_functions: {
        pub fn build_headers<F, FCD, Req, Res>(
            &self,
            req: &RouterDataV2<F, FCD, Req, Res>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError>
        where
            Self: ConnectorIntegrationV2<F, FCD, Req, Res>,
        {
            let mut header = vec![(
                headers::CONTENT_TYPE.to_string(),
                "application/json".to_string().into(),
            )];
            let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
            // Helcim requires an Idempotency Key of length 25. We prefix every ID by "HS_".
            let mut idempotency_key = vec![(
                headers::IDEMPOTENCY_KEY.to_string(),
                generate_id(ID_LENGTH, "HS").into_masked(),
            header.append(&mut api_key);
            header.append(&mut idempotency_key);
            Ok(header)
        }
        pub fn connector_base_url_payments<'a, F, Req, Res>(
            req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.helcim.base_url
        pub fn connector_base_url_refunds<'a, F, Req, Res>(
            req: &'a RouterDataV2<F, RefundFlowData, Req, Res>,
    }
);
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> ConnectorCommon
    for Helcim<T>
    fn id(&self) -> &'static str {
        "helcim"
    fn get_currency_unit(&self) -> common_enums::CurrencyUnit {
        common_enums::CurrencyUnit::Base
    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth = helcim::HelcimAuthType::try_from(auth_type)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        Ok(vec![(
            headers::API_TOKEN.to_string(),
            auth.api_key.expose().into_masked(),
        )])
    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.helcim.base_url.as_ref()
    fn build_error_response(
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: helcim::HelcimErrorResponse = res
            .response
            .parse_struct("HelcimErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        with_error_response_body!(event_builder, response);
        let error_string = match response {
            helcim::HelcimErrorResponse::Payment(response) => match response.errors {
                helcim::HelcimErrorTypes::StringType(error) => error,
                helcim::HelcimErrorTypes::JsonType(error) => error.to_string(),
            },
            helcim::HelcimErrorResponse::General(error_string) => error_string,
        };
        Ok(ErrorResponse {
            status_code: res.status_code,
            code: NO_ERROR_CODE.to_owned(),
            message: error_string.clone(),
            reason: Some(error_string),
            attempt_status: None,
            connector_transaction_id: None,
            network_advice_code: None,
            network_decline_code: None,
            network_error_message: None,
        })
// Authorize flow implementation
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Helcim,
    curl_request: Json(HelcimPaymentsRequest),
    curl_response: HelcimPaymentsResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req)
        fn get_url(
        ) -> CustomResult<String, errors::ConnectorError> {
            if req.request.is_auto_capture()? {
                return Ok(format!("{}v2/payment/purchase", self.connector_base_url_payments(req)));
            }
            Ok(format!("{}v2/payment/preauth", self.connector_base_url_payments(req)))
// PSync flow implementation
    flow_name: PSync,
    flow_request: PaymentsSyncData,
    http_method: Get,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            let connector_payment_id = req.request.get_connector_transaction_id()?;
            Ok(format!(
                "{}v2/card-transactions/{connector_payment_id}",
                self.connector_base_url_payments(req)
            ))
// Capture flow implementation
    curl_request: Json(HelcimCaptureRequest),
    flow_name: Capture,
    flow_request: PaymentsCaptureData,
            req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            Ok(format!("{}v2/payment/capture", self.connector_base_url_payments(req)))
// Void flow implementation
    curl_request: Json(HelcimVoidRequest),
    flow_name: Void,
    flow_request: PaymentVoidData,
            req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            Ok(format!("{}v2/payment/reverse", self.connector_base_url_payments(req)))
// Refund flow implementation
    curl_request: Json(HelcimRefundRequest),
    curl_response: RefundResponse,
    flow_name: Refund,
    resource_common_data: RefundFlowData,
    flow_request: RefundsData,
    flow_response: RefundsResponseData,
            req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            Ok(format!("{}v2/payment/refund", self.connector_base_url_refunds(req)))
// RSync flow implementation
    flow_name: RSync,
    flow_request: RefundSyncData,
            req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            let connector_refund_id = req.request.connector_refund_id.clone();
                "{}v2/card-transactions/{connector_refund_id}",
                self.connector_base_url_refunds(req)
// Stub implementations for unsupported flows
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
        SetupMandate,
        SetupMandateRequestData<T>,
        CreateOrder,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
    > ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
    > ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    ConnectorIntegrationV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>
        CreateSessionToken,
        SessionTokenRequestData,
        SessionTokenResponseData,
        domain_types::connector_flow::PaymentMethodToken,
        domain_types::connector_types::PaymentMethodTokenizationData<T>,
        domain_types::connector_types::PaymentMethodTokenResponse,
        domain_types::connector_flow::CreateAccessToken,
        domain_types::connector_types::AccessTokenRequestData,
        domain_types::connector_types::AccessTokenResponseData,
        PreAuthenticate,
        PaymentsPreAuthenticateData<T>,
        Authenticate,
        PaymentsAuthenticateData<T>,
        PostAuthenticate,
        PaymentsPostAuthenticateData<T>,
        CreateConnectorCustomer,
        ConnectorCustomerData,
        ConnectorCustomerResponse,
// SourceVerification implementations for all flows
        Authorize,
        PaymentsAuthorizeData<T>,
        PSync,
        PaymentsSyncData,
        Capture,
        PaymentsCaptureData,
        Void,
        PaymentVoidData,
        Refund,
        RefundFlowData,
        RefundsData,
        RefundsResponseData,
        RSync,
        RefundSyncData,
        Accept,
        DisputeFlowData,
        AcceptDisputeData,
        DisputeResponseData,
        SubmitEvidence,
        DefendDispute,
        DisputeDefendData,
        RepeatPayment,
        RepeatPaymentData,
