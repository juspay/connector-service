pub mod transformers;
use common_utils::Maskable;

use common_utils::{
    consts::{NO_ERROR_CODE, NO_ERROR_MESSAGE},
    errors::CustomResult,
    ext_traits::ByteSliceExt,
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
};
use error_stack::ResultExt;
// use crate::masking::Maskable;
use interfaces::{
    api::ConnectorCommon, connector_integration_v2::ConnectorIntegrationV2, connector_types,
    events::connector_api_logs::ConnectorEvent,
};
use serde::Serialize;
use std::fmt::Debug;
use transformers::{
    self as placetopay, PlacetopayNextActionRequest,
    PlacetopayNextActionRequest as PlacetopayVoidRequest, PlacetopayPaymentsRequest,
    PlacetopayPaymentsResponse as PlacetopayPSyncResponse, PlacetopayPaymentsResponse,
    PlacetopayPaymentsResponse as PlacetopayCaptureResponse,
    PlacetopayPaymentsResponse as PlacetopayVoidResponse, PlacetopayPsyncRequest,
    PlacetopayRefundRequest, PlacetopayRefundResponse as PlacetopayRSyncResponse,
    PlacetopayRefundResponse, PlacetopayRsyncRequest,
use super::macros;
use crate::{types::ResponseRouterData, with_error_response_body};
pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
}
// Simplified macro usage to avoid duplicate type definitions
macros::create_all_prerequisites!(
    connector_name: Placetopay,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: PlacetopayPaymentsRequest<T>,
            response_body: PlacetopayPaymentsResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
            flow: PSync,
            request_body: PlacetopayPsyncRequest,
            response_body: PlacetopayPSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            flow: Capture,
            request_body: PlacetopayNextActionRequest,
            response_body: PlacetopayCaptureResponse,
            router_data: RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            flow: Void,
            request_body: PlacetopayVoidRequest,
            response_body: PlacetopayVoidResponse,
            router_data: RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            flow: Refund,
            request_body: PlacetopayRefundRequest,
            response_body: PlacetopayRefundResponse,
            router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            flow: RSync,
            request_body: PlacetopayRsyncRequest,
            response_body: PlacetopayRSyncResponse,
            router_data: RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        )
    ],
    amount_converters: [],
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
            header.append(&mut api_key);
            Ok(header)
        }
        pub fn connector_base_url_payments<'a, F, Req, Res>(
            req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.placetopay.base_url
        pub fn connector_base_url_refunds<'a, F, Req, Res>(
            req: &'a RouterDataV2<F, RefundFlowData, Req, Res>,
    }
);
// Trait implementations with generic type parameters
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAuthorizeV2<T> for Placetopay<T>
{
    ConnectorIntegrationV2<
        PaymentMethodToken,
        PaymentFlowData,
        PaymentMethodTokenizationData<T>,
        PaymentMethodTokenResponse,
    > for Placetopay<T>
// Higher-level trait implementations
    connector_types::ValidationTrait for Placetopay<T>
    connector_types::PaymentSyncV2 for Placetopay<T>
    connector_types::PaymentOrderCreate for Placetopay<T>
    connector_types::PaymentSessionToken for Placetopay<T>
    connector_types::PaymentTokenV2<T> for Placetopay<T>
    connector_types::PaymentVoidV2 for Placetopay<T>
    connector_types::IncomingWebhook for Placetopay<T>
    connector_types::RefundV2 for Placetopay<T>
    connector_types::PaymentCapture for Placetopay<T>
    connector_types::SetupMandateV2<T> for Placetopay<T>
    connector_types::RepeatPaymentV2 for Placetopay<T>
    connector_types::AcceptDispute for Placetopay<T>
    connector_types::RefundSyncV2 for Placetopay<T>
    connector_types::DisputeDefend for Placetopay<T>
    connector_types::SubmitEvidenceV2 for Placetopay<T>
    connector_types::PaymentAccessToken for Placetopay<T>
    connector_types::CreateConnectorCustomer for Placetopay<T>
    connector_types::PaymentPreAuthenticateV2<T> for Placetopay<T>
    connector_types::PaymentAuthenticateV2<T> for Placetopay<T>
    connector_types::PaymentPostAuthenticateV2<T> for Placetopay<T>
    connector_types::PaymentVoidPostCaptureV2 for Placetopay<T>
        VoidPC,
        PaymentsCancelPostCaptureData,
        PaymentsResponseData,
    interfaces::verification::SourceVerification<
// Finally implement ConnectorServiceTrait
    connector_types::ConnectorServiceTrait<T> for Placetopay<T>
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> ConnectorCommon
    for Placetopay<T>
    fn id(&self) -> &'static str {
        "placetopay"
    fn get_currency_unit(&self) -> common_enums::CurrencyUnit {
        common_enums::CurrencyUnit::Minor
    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.placetopay.base_url.as_ref()
    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: placetopay::PlacetopayErrorResponse = res
            .response
            .parse_struct("PlacetopayErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        with_error_response_body!(event_builder, response);
        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response
                .status
                .reason
                .unwrap_or_else(|| NO_ERROR_CODE.to_string()),
            message: response
                .message
                .clone()
                .unwrap_or_else(|| NO_ERROR_MESSAGE.to_string()),
            reason: response.status.message,
            attempt_status: None,
            connector_transaction_id: None,
            network_decline_code: None,
            network_advice_code: None,
            network_error_message: None,
        })
// Macro implementation for Authorize flow
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Placetopay,
    curl_request: Json(PlacetopayPaymentsRequest<T>),
    curl_response: PlacetopayPaymentsResponse,
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
            Ok(format!("{}/process", self.connector_base_url_payments(req)))
// Macro implementation for PSync flow
    curl_request: Json(PlacetopayPsyncRequest),
    curl_response: PlacetopayPSyncResponse,
    flow_name: PSync,
    flow_request: PaymentsSyncData,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
             Ok(format!("{}/query", self.connector_base_url_payments(req)))
// Macro implementation for Capture flow
    curl_request: Json(PlacetopayNextActionRequest),
    curl_response: PlacetopayCaptureResponse,
    flow_name: Capture,
    flow_request: PaymentsCaptureData,
            req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            Ok(format!("{}/transaction", self.connector_base_url_payments(req)))
// Macro implementation for Void flow
    curl_request: Json(PlacetopayVoidRequest),
    curl_response: PlacetopayVoidResponse,
    flow_name: Void,
    flow_request: PaymentVoidData,
            req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
// Macro implementation for Refund flow
    curl_request: Json(PlacetopayRefundRequest),
    curl_response: PlacetopayRefundResponse,
    flow_name: Refund,
    resource_common_data: RefundFlowData,
    flow_request: RefundsData,
    flow_response: RefundsResponseData,
            req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            Ok(format!("{}/transaction", self.connector_base_url_refunds(req)))
// Macro implementation for RSync flow
    curl_request: Json(PlacetopayRsyncRequest),
    curl_response: PlacetopayRSyncResponse,
    flow_name: RSync,
    flow_request: RefundSyncData,
            req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            Ok(format!("{}/query", self.connector_base_url_refunds(req)))
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
        CreateAccessToken,
        AccessTokenRequestData,
        AccessTokenResponseData,
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
