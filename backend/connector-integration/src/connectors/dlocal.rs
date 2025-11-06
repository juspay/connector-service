pub mod transformers;
use common_utils::Maskable;

use common_utils::{
    crypto::{self, SignMessage},
    date_time,
    errors::CustomResult,
    ext_traits::ByteSliceExt,
    types::MinorUnit,
};
use domain_types::{
    connector_flow::{
        Accept, Authenticate, Authorize, Capture, CreateAccessToken, CreateConnectorCustomer,
        CreateOrder, CreateSessionToken, DefendDispute, PSync, PaymentMethodToken,
        PostAuthenticate, PreAuthenticate, RSync, Refund, RepeatPayment, SetupMandate,
        SubmitEvidence, Void, VoidPC,
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
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data::ErrorResponse,
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
use error_stack::ResultExt;
// use crate::masking::{Mask, Maskable, PeekInterface};
use interfaces::{
    api::ConnectorCommon, connector_integration_v2::ConnectorIntegrationV2, connector_types,
    events::connector_api_logs::ConnectorEvent,
use serde::Serialize;
use std::fmt::Debug;
use transformers::{
    self as dlocal, DlocalPaymentsCaptureRequest, DlocalPaymentsRequest, DlocalPaymentsResponse,
    DlocalPaymentsResponse as DlocalPaymentsSyncResponse,
    DlocalPaymentsResponse as DlocalPaymentsCaptureResponse,
    DlocalPaymentsResponse as DlocalPaymentsVoidResponse, DlocalRefundRequest, RefundResponse,
    RefundResponse as RefundSyncResponse,
use super::macros;
use crate::{types::ResponseRouterData, with_error_response_body};
const VERSION: &str = "2.1";
// Trait implementations with generic type parameters
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ConnectorServiceTrait<T> for Dlocal<T>
{
}
    connector_types::PaymentAuthorizeV2<T> for Dlocal<T>
    connector_types::PaymentSyncV2 for Dlocal<T>
    connector_types::PaymentVoidV2 for Dlocal<T>
    connector_types::RefundSyncV2 for Dlocal<T>
    connector_types::RefundV2 for Dlocal<T>
    connector_types::PaymentCapture for Dlocal<T>
    connector_types::PaymentVoidPostCaptureV2 for Dlocal<T>
    ConnectorIntegrationV2<
        VoidPC,
        PaymentFlowData,
        PaymentsCancelPostCaptureData,
        PaymentsResponseData,
    > for Dlocal<T>
    interfaces::verification::SourceVerification<
    connector_types::ValidationTrait for Dlocal<T>
    connector_types::PaymentOrderCreate for Dlocal<T>
    connector_types::SetupMandateV2<T> for Dlocal<T>
    connector_types::RepeatPaymentV2 for Dlocal<T>
    connector_types::AcceptDispute for Dlocal<T>
    connector_types::SubmitEvidenceV2 for Dlocal<T>
    connector_types::DisputeDefend for Dlocal<T>
    connector_types::IncomingWebhook for Dlocal<T>
    connector_types::PaymentSessionToken for Dlocal<T>
    connector_types::PaymentTokenV2<T> for Dlocal<T>
    connector_types::PaymentAccessToken for Dlocal<T>
    connector_types::CreateConnectorCustomer for Dlocal<T>
    connector_types::PaymentPreAuthenticateV2<T> for Dlocal<T>
    connector_types::PaymentAuthenticateV2<T> for Dlocal<T>
    connector_types::PaymentPostAuthenticateV2<T> for Dlocal<T>
pub(crate) mod headers {
    pub(crate) const AUTHORIZATION: &str = "Authorization";
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const X_DATE: &str = "X-Date";
    pub(crate) const X_LOGIN: &str = "X-Login";
    pub(crate) const X_TRANS_KEY: &str = "X-Trans-Key";
    pub(crate) const X_VERSION: &str = "X-Version";
macros::create_all_prerequisites!(
    connector_name: Dlocal,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: DlocalPaymentsRequest<T>,
            response_body: DlocalPaymentsResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
            flow: PSync,
            response_body: DlocalPaymentsSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            flow: Refund,
            request_body: DlocalRefundRequest,
            response_body: RefundResponse,
            router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            flow: RSync,
            response_body: RefundSyncResponse,
            router_data: RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            flow: Capture,
            request_body: DlocalPaymentsCaptureRequest,
            response_body: DlocalPaymentsCaptureResponse,
            router_data: RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            flow: Void,
            response_body: DlocalPaymentsVoidResponse,
            router_data: RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        )
    ],
    amount_converters: [
        amount_converter: MinorUnit
    member_functions: {
        pub fn build_headers<F, FCD, Req, Res>(
            &self,
            req: &RouterDataV2<F, FCD, Req, Res>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError>
        where
            Self: ConnectorIntegrationV2<F, FCD, Req, Res>,
        {
            let date = date_time::date_as_yyyymmddthhmmssmmmz()
                .change_context(errors::ConnectorError::RequestEncodingFailed)?;
            let auth = dlocal::DlocalAuthType::try_from(&req.connector_auth_type)?;
            let request_body = match self.get_request_body(req)? {
                Some(dlocal_req) => dlocal_req.get_inner_value().peek().to_owned(),
                None => String::new(),
            };
            let sign_req: String = format!(
                "{}{}{}",
                auth.x_login.peek(),
                date,
                request_body
            );
            let authz = crypto::HmacSha256::sign_message(
                &crypto::HmacSha256,
                auth.secret.peek().as_bytes(),
                sign_req.as_bytes(),
            )
            .change_context(errors::ConnectorError::RequestEncodingFailed)
            .attach_printable("Failed to sign the message")?;
            let auth_string: String = format!("V2-HMAC-SHA256, Signature: {}", hex::encode(authz));
            let headers = vec![
                (
                    headers::AUTHORIZATION.to_string(),
                    auth_string.into_masked(),
                ),
                (headers::X_LOGIN.to_string(), auth.x_login.into_masked()),
                    headers::X_TRANS_KEY.to_string(),
                    auth.x_trans_key.into_masked(),
                (headers::X_VERSION.to_string(), VERSION.to_string().into()),
                (headers::X_DATE.to_string(), date.into()),
                    headers::CONTENT_TYPE.to_string(),
                    self.get_content_type().to_string().into(),
            ];
            Ok(headers)
        }
        pub fn connector_base_url_payments<'a, F, Req, Res>(
            req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.dlocal.base_url
        pub fn connector_base_url_refunds<'a, F, Req, Res>(
            req: &'a RouterDataV2<F, RefundFlowData, Req, Res>,
    }
);
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> ConnectorCommon
    for Dlocal<T>
    fn id(&self) -> &'static str {
        "dlocal"
    fn get_currency_unit(&self) -> common_enums::CurrencyUnit {
        common_enums::CurrencyUnit::Minor
    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.dlocal.base_url.as_ref()
    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: dlocal::DlocalErrorResponse = res
            .response
            .parse_struct("Dlocal ErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        with_error_response_body!(event_builder, response);
        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response.code.to_string(),
            message: response.message,
            reason: response.param,
            attempt_status: None,
            connector_transaction_id: None,
            network_advice_code: None,
            network_decline_code: None,
            network_error_message: None,
        })
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Dlocal,
    curl_request: Json(DlocalPaymentsRequest),
    curl_response: DlocalPaymentsResponse,
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
            Ok(format!("{}secure_payments", self.connector_base_url_payments(req)))
    flow_name: PSync,
    flow_request: PaymentsSyncData,
    http_method: Get,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            let sync_data = dlocal::DlocalPaymentsSyncRequest::try_from(req)?;
            Ok(format!(
                "{}payments/{}/status",
                self.connector_base_url_payments(req),
                sync_data.authz_id,
            ))
    curl_request: Json(DlocalRefundRequest),
    curl_response: RefundResponse,
    flow_name: Refund,
    resource_common_data: RefundFlowData,
    flow_request: RefundsData,
    flow_response: RefundsResponseData,
            req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            Ok(format!("{}refunds", self.connector_base_url_refunds(req)))
    flow_name: RSync,
    flow_request: RefundSyncData,
            req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            let sync_data = dlocal::DlocalRefundsSyncRequest::try_from(req)?;
                "{}refunds/{}/status",
                self.connector_base_url_refunds(req),
                sync_data.refund_id,
    curl_request: Json(DlocalPaymentsCaptureRequest),
    flow_name: Capture,
    flow_request: PaymentsCaptureData,
            req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            Ok(format!("{}payments", self.connector_base_url_payments(req)))
    flow_name: Void,
    flow_request: PaymentVoidData,
            req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            let cancel_data = dlocal::DlocalPaymentsCancelRequest::try_from(req)?;
                "{}payments/{}/cancel",
                cancel_data.cancel_id
// Stub implementations for unsupported flows
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
        CreateOrder,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
    > ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
    > ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
        SetupMandate,
        SetupMandateRequestData<T>,
    ConnectorIntegrationV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>
        CreateSessionToken,
        SessionTokenRequestData,
        SessionTokenResponseData,
        PaymentMethodToken,
        PaymentMethodTokenizationData<T>,
        PaymentMethodTokenResponse,
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
        SubmitEvidenceData,
        DefendDispute,
        DisputeDefendData,
        RepeatPayment,
        RepeatPaymentData,
        CreateAccessToken,
        AccessTokenRequestData,
        AccessTokenResponseData,
