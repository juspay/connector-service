pub mod transformers;
use common_utils::Maskable;

use std::fmt::Debug;
use bytes::Bytes;
use common_utils::{errors::CustomResult, ext_traits::ByteSliceExt,
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
        ConnectorCustomerResponse, ConnectorSpecifications, DisputeDefendData, DisputeFlowData,
        DisputeResponseData, PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData,
        PaymentMethodTokenResponse, PaymentMethodTokenizationData, PaymentVoidData,
        PaymentsAuthenticateData, PaymentsAuthorizeData, PaymentsCancelPostCaptureData,
        PaymentsCaptureData, PaymentsPostAuthenticateData, PaymentsPreAuthenticateData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData,
        RefundsResponseData, RepeatPaymentData, SessionTokenRequestData, SessionTokenResponseData,
        SetupMandateRequestData, SubmitEvidenceData,
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
// use crate::masking::Maskable;
use interfaces::{
    api::ConnectorCommon,
    connector_integration_v2::{self, ConnectorIntegrationV2},
    connector_types,
    events::connector_api_logs::ConnectorEvent,
use serde::Serialize;
use transformers::{
    self as elavon, ElavonCaptureResponse, ElavonPSyncResponse, ElavonPaymentsResponse,
    ElavonRSyncResponse, ElavonRefundResponse, XMLCaptureRequest, XMLElavonRequest,
    XMLPSyncRequest, XMLRSyncRequest, XMLRefundRequest,
use super::macros;
use crate::{
    types::ResponseRouterData, utils::preprocess_xml_response_bytes, with_error_response_body,
pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::ConnectorServiceTrait<T> for Elavon<T>
{
    > connector_types::PaymentSessionToken for Elavon<T>
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAccessToken for Elavon<T>
    > connector_types::CreateConnectorCustomer for Elavon<T>
    > connector_types::PaymentAuthorizeV2<T> for Elavon<T>
    > connector_types::PaymentSyncV2 for Elavon<T>
    > connector_types::PaymentVoidV2 for Elavon<T>
    > connector_types::RefundSyncV2 for Elavon<T>
    > connector_types::RefundV2 for Elavon<T>
// Type alias for non-generic trait implementations
    > connector_types::ValidationTrait for Elavon<T>
    > connector_types::PaymentCapture for Elavon<T>
    > connector_types::SetupMandateV2<T> for Elavon<T>
    > connector_types::AcceptDispute for Elavon<T>
    > connector_types::SubmitEvidenceV2 for Elavon<T>
    > connector_types::DisputeDefend for Elavon<T>
    > connector_types::IncomingWebhook for Elavon<T>
    > connector_types::PaymentOrderCreate for Elavon<T>
    > connector_types::RepeatPaymentV2 for Elavon<T>
    > connector_types::PaymentTokenV2<T> for Elavon<T>
    > connector_types::PaymentPreAuthenticateV2<T> for Elavon<T>
    > connector_types::PaymentAuthenticateV2<T> for Elavon<T>
    > connector_types::PaymentPostAuthenticateV2<T> for Elavon<T>
    > connector_types::PaymentVoidPostCaptureV2 for Elavon<T>
    > ConnectorCommon for Elavon<T>
    fn id(&self) -> &'static str {
        "elavon"
    }
    fn common_get_content_type(&self) -> &'static str {
        "application/x-www-form-urlencoded"
    fn get_auth_header(
        &self,
        _auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        Ok(Vec::new())
    fn base_url<'a>(&self, _connectors: &'a Connectors) -> &'a str {
        "https://api.demo.convergepay.com/VirtualMerchantDemo/"
    fn build_error_response(
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        match res
            .response
            .parse_struct::<elavon::ElavonPaymentsResponse>("ElavonPaymentsResponse")
            .map_err(|_| errors::ConnectorError::ResponseDeserializationFailed)
        {
            Ok(elavon_response) => {
                with_error_response_body!(event_builder, elavon_response);
                match elavon_response.result {
                    elavon::ElavonResult::Error(error_payload) => Ok(ErrorResponse {
                        status_code: res.status_code,
                        code: error_payload.error_code.unwrap_or_else(|| "".to_string()),
                        message: error_payload.error_message,
                        reason: error_payload.error_name,
                        attempt_status: Some(common_enums::AttemptStatus::Failure),
                        connector_transaction_id: error_payload.ssl_txn_id,
                        network_decline_code: None,
                        network_advice_code: None,
                        network_error_message: None,
                    }),
                    elavon::ElavonResult::Success(success_payload) => Ok(ErrorResponse {
                        code: "".to_string(),
                        message: "Received success response in error flow".to_string(),
                        reason: Some(format!(
                            "Unexpected success: {:?}",
                            success_payload.ssl_result_message
                        )),
                        connector_transaction_id: Some(success_payload.ssl_txn_id),
                }
            }
            Err(_parsing_error) => {
                let (message, reason) = match res.status_code {
                    500..=599 => (
                        "Elavon server error".to_string(),
                        Some(String::from_utf8_lossy(&res.response).into_owned()),
                    ),
                    _ => (
                        "Elavon error response".to_string(),
                };
                Ok(ErrorResponse {
                    status_code: res.status_code,
                    code: "".to_string(),
                    message,
                    reason,
                    attempt_status: Some(common_enums::AttemptStatus::Failure),
                    connector_transaction_id: None,
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                })
        }
macros::create_all_prerequisites!(
    connector_name: Elavon,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: XMLElavonRequest,
            response_body: ElavonPaymentsResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
            flow: PSync,
            request_body: XMLPSyncRequest,
            response_body: ElavonPSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            flow: Capture,
            request_body: XMLCaptureRequest,
            response_body: ElavonCaptureResponse,
            router_data: RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            flow: Refund,
            request_body: XMLRefundRequest,
            response_body: ElavonRefundResponse,
            router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            flow: RSync,
            request_body: XMLRSyncRequest,
            response_body: ElavonRSyncResponse,
            router_data: RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        )
    ],
    amount_converters: [],
    member_functions: {
        pub fn preprocess_response_bytes<F, FCD, Req, Res>(
            &self,
            _req: &RouterDataV2<F, FCD, Req, Res>,
            response_bytes: Bytes,
        ) -> Result<Bytes, errors::ConnectorError> {
            // Use the utility function to preprocess XML response bytes
            preprocess_xml_response_bytes(response_bytes)
        pub fn build_headers<F, FCD, Req, Res>(
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            Ok(vec![(
                headers::CONTENT_TYPE.to_string(),
                self.common_get_content_type().to_string().into(),
            )])
);
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type],
    connector: Elavon,
    curl_request: FormUrlEncoded(XMLElavonRequest),
    curl_response: ElavonPaymentsResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    preprocess_response: true,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            self.build_headers(req)
        fn get_url(
        ) -> CustomResult<String, errors::ConnectorError> {
            Ok(format!(
                "{}processxml.do",
                req.resource_common_data.connectors.elavon.base_url
            ))
    curl_request: FormUrlEncoded(XMLPSyncRequest),
    curl_response: ElavonPSyncResponse,
    flow_name: PSync,
    flow_request: PaymentsSyncData,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    >
    connector_integration_v2::ConnectorIntegrationV2<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for Elavon<T>
    curl_request: FormUrlEncoded(XMLCaptureRequest),
    curl_response: ElavonCaptureResponse,
    flow_name: Capture,
    flow_request: PaymentsCaptureData,
            req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
    curl_request: FormUrlEncoded(XMLRefundRequest),
    curl_response: ElavonRefundResponse,
    flow_name: Refund,
    resource_common_data: RefundFlowData,
    flow_request: RefundsData,
    flow_response: RefundsResponseData,
            req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    curl_request: FormUrlEncoded(XMLRSyncRequest),
    curl_response: ElavonRSyncResponse,
    flow_name: RSync,
    flow_request: RefundSyncData,
            req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        Void,
        PaymentVoidData,
        PaymentsResponseData,
        SetupMandate,
        SetupMandateRequestData<T>,
        Accept,
        DisputeFlowData,
        AcceptDisputeData,
        DisputeResponseData,
        SubmitEvidence,
        SubmitEvidenceData,
        DefendDispute,
        DisputeDefendData,
    ConnectorIntegrationV2<
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
    interfaces::verification::SourceVerification<
        Authorize,
        PaymentsAuthorizeData<T>,
        CreateSessionToken,
        SessionTokenRequestData,
        SessionTokenResponseData,
        CreateAccessToken,
        AccessTokenRequestData,
        AccessTokenResponseData,
        CreateConnectorCustomer,
        ConnectorCustomerData,
        ConnectorCustomerResponse,
        PSync,
        PaymentsSyncData,
        Capture,
        PaymentsCaptureData,
        Refund,
        RefundFlowData,
        RefundsData,
        RefundsResponseData,
        RSync,
        RefundSyncData,
        VoidPC,
        PaymentsCancelPostCaptureData,
    > ConnectorSpecifications for Elavon<T>
        RepeatPayment,
        RepeatPaymentData,
    ConnectorIntegrationV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>
    for Elavon<T>
