pub mod transformers;
use common_utils::Maskable;

use std::fmt::Debug;
use common_utils::{consts, errors::CustomResult, ext_traits::ByteSliceExt,
    Maskable,
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
        RefundsResponseData, RepeatPaymentData, ResponseId, SessionTokenRequestData,
        SessionTokenResponseData, SetupMandateRequestData, SubmitEvidenceData,
    errors::{self, ConnectorError},
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
use error_stack::ResultExt;
// use crate::masking::{Mask, Maskable, PeekInterface};
use interfaces::{
    api::ConnectorCommon, connector_integration_v2::ConnectorIntegrationV2, connector_types,
    events::connector_api_logs::ConnectorEvent,
use serde::Serialize;
use transformers::{
    ActionResponse, CheckoutAuthorizeResponse, CheckoutErrorResponse, CheckoutPSyncResponse,
    CheckoutPaymentsRequest, CheckoutRefundSyncRequest, CheckoutSyncRequest, PaymentCaptureRequest,
    PaymentCaptureResponse, PaymentVoidRequest, PaymentVoidResponse, RefundRequest, RefundResponse,
use super::macros;
use crate::types::ResponseRouterData;
pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const AUTHORIZATION: &str = "Authorization";
}
// Type alias for non-generic trait implementations
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::ConnectorServiceTrait<T> for Checkout<T>
{
    > connector_types::PaymentAuthorizeV2<T> for Checkout<T>
    > connector_types::PaymentSessionToken for Checkout<T>
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAccessToken for Checkout<T>
    > connector_types::CreateConnectorCustomer for Checkout<T>
    > connector_types::PaymentSyncV2 for Checkout<T>
    > connector_types::PaymentVoidV2 for Checkout<T>
    > connector_types::RefundSyncV2 for Checkout<T>
    > connector_types::RefundV2 for Checkout<T>
    > connector_types::PaymentCapture for Checkout<T>
    > connector_types::ValidationTrait for Checkout<T>
    > connector_types::SetupMandateV2<T> for Checkout<T>
    > connector_types::AcceptDispute for Checkout<T>
    > connector_types::SubmitEvidenceV2 for Checkout<T>
    > connector_types::DisputeDefend for Checkout<T>
    > connector_types::IncomingWebhook for Checkout<T>
    > connector_types::PaymentOrderCreate for Checkout<T>
    > connector_types::RepeatPaymentV2 for Checkout<T>
    > connector_types::PaymentTokenV2<T> for Checkout<T>
    > connector_types::PaymentPreAuthenticateV2<T> for Checkout<T>
    > connector_types::PaymentAuthenticateV2<T> for Checkout<T>
    > connector_types::PaymentPostAuthenticateV2<T> for Checkout<T>
    > connector_types::PaymentVoidPostCaptureV2 for Checkout<T>
macros::create_all_prerequisites!(
    connector_name: Checkout,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: CheckoutPaymentsRequest<T>,
            response_body: CheckoutAuthorizeResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
            flow: PSync,
            request_body: CheckoutSyncRequest,
            response_body: CheckoutPSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            flow: Capture,
            request_body: PaymentCaptureRequest,
            response_body: PaymentCaptureResponse,
            router_data: RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            flow: Void,
            request_body: PaymentVoidRequest,
            response_body: PaymentVoidResponse,
            router_data: RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            flow: Refund,
            request_body: RefundRequest,
            response_body: RefundResponse,
            router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            flow: RSync,
            request_body: CheckoutRefundSyncRequest,
            response_body: ActionResponse,
            router_data: RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        )
    ],
    amount_converters: [],
    member_functions: {
        pub fn build_headers<F, FCD, Req, Res>(
            &self,
            req: &RouterDataV2<F, FCD, Req, Res>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
            let mut header = vec![(
                headers::CONTENT_TYPE.to_string(),
                "application/json".to_string().into(),
            )];
            let mut auth_header = self.get_auth_header(&req.connector_auth_type)?;
            header.append(&mut auth_header);
            Ok(header)
        }
        pub fn connector_base_url_payments<'a, F, Req, Res>(
            req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.checkout.base_url
        pub fn connector_base_url_refunds<'a, F, Req, Res>(
            req: &'a RouterDataV2<F, RefundFlowData, Req, Res>,
    }
);
    > ConnectorCommon for Checkout<T>
    fn id(&self) -> &'static str {
        "checkout"
    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth = transformers::CheckoutAuthType::try_from(auth_type)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        Ok(vec![(
            headers::AUTHORIZATION.to_string(),
            format!("Bearer {}", auth.api_secret.peek()).into_masked(),
        )])
    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.checkout.base_url.as_ref()
    fn build_error_response(
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: CheckoutErrorResponse = if res.response.is_empty() {
            let (error_codes, error_type) = if res.status_code == 401 {
                (
                    Some(vec!["Invalid api key".to_string()]),
                    Some("invalid_api_key".to_string()),
                )
            } else {
                (None, None)
            };
            CheckoutErrorResponse {
                request_id: None,
                error_codes,
                error_type,
            }
        } else {
            res.response
                .parse_struct("ErrorResponse")
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?
        };
        if let Some(i) = event_builder {
            i.set_error_response_body(&response);
        Ok(ErrorResponse {
            status_code: res.status_code,
            code: consts::NO_ERROR_CODE.to_string(),
            message: consts::NO_ERROR_MESSAGE.to_string(),
            reason: response
                .error_codes
                .map(|errors| errors.join(" & "))
                .or(response.error_type),
            attempt_status: None,
            connector_transaction_id: response.request_id,
            network_decline_code: None,
            network_advice_code: None,
            network_error_message: None,
        })
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Checkout,
    curl_request: Json(CheckoutPaymentsRequest),
    curl_response: CheckoutAuthorizeResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req)
        fn get_url(
        ) -> CustomResult<String, errors::ConnectorError> {
            Ok(format!("{}payments", self.connector_base_url_payments(req)))
    curl_request: Json(CheckoutSyncRequest),
    curl_response: CheckoutPSyncResponse,
    flow_name: PSync,
    flow_request: PaymentsSyncData,
    http_method: Get,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            let connector_tx_id = match &req.request.connector_transaction_id {
                domain_types::connector_types::ResponseId::ConnectorTransactionId(id) => id.clone(),
                _ => return Err(errors::ConnectorError::MissingConnectorTransactionID.into()),
            Ok(format!("{}payments/{}", self.connector_base_url_payments(req), connector_tx_id))
    curl_request: Json(PaymentCaptureRequest),
    curl_response: PaymentCaptureResponse,
    flow_name: Capture,
    flow_request: PaymentsCaptureData,
            req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
                ResponseId::ConnectorTransactionId(id) => id.clone(),
            Ok(format!("{}payments/{}/captures", self.connector_base_url_payments(req), connector_tx_id))
    curl_request: Json(RefundRequest),
    curl_response: RefundResponse,
    flow_name: Refund,
    resource_common_data: RefundFlowData,
    flow_request: RefundsData,
    flow_response: RefundsResponseData,
            req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            let connector_tx_id = &req.request.connector_transaction_id;
            Ok(format!("{}payments/{}/refunds", self.connector_base_url_refunds(req), connector_tx_id))
    curl_request: Json(CheckoutRefundSyncRequest),
    curl_response: ActionResponse,
    flow_name: RSync,
    flow_request: RefundSyncData,
            req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            Ok(format!(
                "{}payments/{}/actions",
                self.connector_base_url_refunds(req),
                connector_tx_id
            ))
    curl_request: Json(PaymentVoidRequest),
    curl_response: PaymentVoidResponse,
    flow_name: Void,
    flow_request: PaymentVoidData,
            req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            let connector_tx_id = req.request.connector_transaction_id.clone();
            Ok(format!("{}payments/{}/voids", self.connector_base_url_payments(req), connector_tx_id))
    >
    ConnectorIntegrationV2<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData<T>,
        PaymentsResponseData,
    > for Checkout<T>
        CreateSessionToken,
        SessionTokenRequestData,
        SessionTokenResponseData,
        CreateAccessToken,
        AccessTokenRequestData,
        AccessTokenResponseData,
        CreateConnectorCustomer,
        ConnectorCustomerData,
        ConnectorCustomerResponse,
    interfaces::verification::SourceVerification<
    > ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    for Checkout<T>
    ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
    > ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
        CreateOrder,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
        PaymentMethodToken,
        PaymentMethodTokenizationData<T>,
        PaymentMethodTokenResponse,
        PreAuthenticate,
        PaymentsPreAuthenticateData<T>,
        Authenticate,
        PaymentsAuthenticateData<T>,
        PostAuthenticate,
        PaymentsPostAuthenticateData<T>,
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
    ConnectorIntegrationV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>
        VoidPC,
        PaymentsCancelPostCaptureData,
