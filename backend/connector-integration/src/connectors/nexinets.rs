pub mod transformers;
use common_utils::Maskable;
use std::fmt::Debug;

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
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
};
// use crate::masking::{Mask, Maskable};
use interfaces::{
    api::ConnectorCommon, connector_integration_v2::ConnectorIntegrationV2, connector_types,
    events::connector_api_logs::ConnectorEvent,
};
use serde::Serialize;
use serde_json;
use transformers::{
    self as nexinets, NexinetsCaptureOrVoidRequest, NexinetsErrorResponse,
    NexinetsPaymentResponse as NexinetsCaptureResponse, NexinetsPaymentResponse,
    NexinetsPaymentsRequest, NexinetsPreAuthOrDebitResponse, NexinetsRefundRequest,
    NexinetsRefundResponse, NexinetsRefundResponse as RefundSyncResponse,
use super::macros;
use crate::{types::ResponseRouterData, with_error_response_body};
pub const BASE64_ENGINE: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
use error_stack::ResultExt;
pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const AUTHORIZATION: &str = "Authorization";
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> ConnectorCommon
    for Nexinets<T>
{
    fn id(&self) -> &'static str {
        "nexinets"
    }
    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth = nexinets::NexinetsAuthType::try_from(auth_type)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        Ok(vec![(
            headers::AUTHORIZATION.to_string(),
            auth.api_key.into_masked(),
        )])
    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.nexinets.base_url.as_ref()
    fn build_error_response(
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: NexinetsErrorResponse = res
            .response
            .parse_struct("NexinetsErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        with_error_response_body!(event_builder, response);
        let errors = response.errors;
        let mut message = String::new();
        let mut static_message = String::new();
        for error in errors.iter() {
            let field = error.field.to_owned().unwrap_or_default();
            let mut msg = String::new();
            if !field.is_empty() {
                msg.push_str(format!("{} : {}", field, error.message).as_str());
            } else {
                error.message.clone_into(&mut msg)
            }
            if message.is_empty() {
                message.push_str(&msg);
                static_message.push_str(&msg);
                message.push_str(format!(", {msg}").as_str());
        }
        let connector_reason = format!("reason : {} , message : {}", response.message, message);
        Ok(ErrorResponse {
            status_code: response.status,
            code: response.code.to_string(),
            message: static_message,
            reason: Some(connector_reason),
            attempt_status: None,
            connector_transaction_id: None,
            network_advice_code: None,
            network_decline_code: None,
            network_error_message: None,
        })
//marker traits
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ConnectorServiceTrait<T> for Nexinets<T>
    connector_types::PaymentAuthorizeV2<T> for Nexinets<T>
    connector_types::PaymentSyncV2 for Nexinets<T>
    connector_types::PaymentSessionToken for Nexinets<T>
    connector_types::PaymentAccessToken for Nexinets<T>
    connector_types::CreateConnectorCustomer for Nexinets<T>
    connector_types::PaymentVoidV2 for Nexinets<T>
    connector_types::RefundSyncV2 for Nexinets<T>
    connector_types::RefundV2 for Nexinets<T>
    connector_types::PaymentCapture for Nexinets<T>
    connector_types::ValidationTrait for Nexinets<T>
    connector_types::PaymentOrderCreate for Nexinets<T>
    connector_types::SetupMandateV2<T> for Nexinets<T>
    connector_types::RepeatPaymentV2 for Nexinets<T>
    connector_types::PaymentVoidPostCaptureV2 for Nexinets<T>
    ConnectorIntegrationV2<
        VoidPC,
        PaymentFlowData,
        PaymentsCancelPostCaptureData,
        PaymentsResponseData,
    > for Nexinets<T>
    connector_types::AcceptDispute for Nexinets<T>
    connector_types::SubmitEvidenceV2 for Nexinets<T>
    connector_types::DisputeDefend for Nexinets<T>
    connector_types::IncomingWebhook for Nexinets<T>
    connector_types::PaymentTokenV2<T> for Nexinets<T>
    connector_types::PaymentPreAuthenticateV2<T> for Nexinets<T>
    connector_types::PaymentAuthenticateV2<T> for Nexinets<T>
    connector_types::PaymentPostAuthenticateV2<T> for Nexinets<T>
macros::create_all_prerequisites!(
    connector_name: Nexinets,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: NexinetsPaymentsRequest<T>,
            response_body: NexinetsPreAuthOrDebitResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
            flow: PSync,
            response_body: NexinetsPaymentResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            flow: Capture,
            request_body: NexinetsCaptureOrVoidRequest,
            response_body: NexinetsCaptureResponse,
            router_data: RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            flow: Refund,
            request_body: NexinetsRefundRequest,
            response_body: NexinetsRefundResponse,
            router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            flow: RSync,
            response_body: RefundSyncResponse,
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
                self.get_content_type().to_string().into(),
            )];
            let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
            header.append(&mut api_key);
            Ok(header)
        pub fn connector_base_url_payments<'a, F, Req, Res>(
            req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.nexinets.base_url
        pub fn connector_base_url_refunds<'a, F, Req, Res>(
            req: &'a RouterDataV2<F, RefundFlowData, Req, Res>,
);
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Nexinets,
    curl_request: Json(NexinetsPaymentsRequest),
    curl_response: NexinetsPreAuthOrDebitResponse,
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
                    let url = if matches!(
            req.request.capture_method,
            Some(common_enums::CaptureMethod::Automatic) | Some(common_enums::CaptureMethod::SequentialAutomatic)
        ) {
            format!("{}/orders/debit", self.connector_base_url_payments(req))
        } else {
            format!("{}/orders/preauth", self.connector_base_url_payments(req))
        };
        Ok(url)
// Macro implementations for PSync, Capture, Refund, and RSync flows
    flow_name: PSync,
    flow_request: PaymentsSyncData,
    http_method: Get,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        let transaction_id = req.request.get_connector_transaction_id()?;
        let order_id = &req.resource_common_data.connector_request_reference_id;
            Ok(format!(
                "{}/orders/{order_id}/transactions/{transaction_id}",
                self.connector_base_url_payments(req),
            ))
    curl_request: Json(NexinetsCaptureOrVoidRequest),
    curl_response: NexinetsCaptureResponse,
    flow_name: Capture,
    flow_request: PaymentsCaptureData,
            req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        let transaction_id = req
                .request
                .connector_transaction_id
                .get_connector_transaction_id()
                .change_context(errors::ConnectorError::MissingConnectorTransactionID)?;
        Ok(format!(
            "{}/orders/{order_id}/transactions/{transaction_id}/capture",
            self.connector_base_url_payments(req),
        ))
    curl_request: Json(NexinetsRefundRequest),
    curl_response: NexinetsRefundResponse,
    flow_name: Refund,
    resource_common_data: RefundFlowData,
    flow_request: RefundsData,
    flow_response: RefundsResponseData,
            req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            let connector_metadata = req
                .get_connector_metadata()
                .change_context(errors::ConnectorError::MissingRequiredField {
                    field_name: "connector_metadata",
                })?;
            // connector_metadata is a Value::String, so extract and parse
            let metadata_str = connector_metadata
                .as_str()
                .ok_or(errors::ConnectorError::InvalidDataFormat {
                    field_name: "connector_metadata as string",
            let parsed_metadata: serde_json::Value =
                serde_json::from_str(metadata_str).change_context(
                    errors::ConnectorError::ParsingFailed
                )?;
            let order_id = parsed_metadata
                .get("order_id")
                .and_then(|v| v.as_str())
                .ok_or(errors::ConnectorError::MissingRequiredField {
                    field_name: "order_id in connector_metadata",
                "{}/orders/{order_id}/transactions/{}/refund",
                self.connector_base_url_refunds(req),
                req.request.connector_transaction_id
    curl_response: RefundSyncResponse,
    flow_name: RSync,
    flow_request: RefundSyncData,
            req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            let transaction_id = req
                .connector_refund_id
                .clone();
            let order_id = req.resource_common_data.connector_request_reference_id.clone();
        CreateOrder,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
        CreateSessionToken,
        SessionTokenRequestData,
        SessionTokenResponseData,
        CreateAccessToken,
        AccessTokenRequestData,
        AccessTokenResponseData,
        CreateConnectorCustomer,
        ConnectorCustomerData,
        ConnectorCustomerResponse,
    ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
    ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
    ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
        SetupMandate,
        SetupMandateRequestData<T>,
    ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
// SourceVerification implementations for all flows
    interfaces::verification::SourceVerification<
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
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
        PaymentMethodToken,
        PaymentMethodTokenizationData<T>,
        PaymentMethodTokenResponse,
        SubmitEvidence,
        SubmitEvidenceData,
        DefendDispute,
        DisputeDefendData,
        RepeatPayment,
        RepeatPaymentData,
    ConnectorIntegrationV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>
// ConnectorIntegrationV2 implementations for authentication flows
        PreAuthenticate,
        PaymentsPreAuthenticateData<T>,
        Authenticate,
        PaymentsAuthenticateData<T>,
        PostAuthenticate,
        PaymentsPostAuthenticateData<T>,
// SourceVerification implementations for authentication flows
