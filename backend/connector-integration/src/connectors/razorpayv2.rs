pub mod test;
use common_utils::Maskable;
pub mod transformers;
use common_enums::AttemptStatus;
use common_utils::{
    errors::CustomResult,
    ext_traits::BytesExt,
    request::RequestContent,
    types::{AmountConvertor, MinorUnit},
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
    errors,
    payment_method_data::{DefaultPCIHolder, PaymentMethodData, PaymentMethodDataTypes},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
use error_stack::ResultExt;
// use crate::masking::Maskable;
use interfaces::{
    api::ConnectorCommon,
    connector_integration_v2::ConnectorIntegrationV2,
    connector_types::{self},
    events::connector_api_logs::ConnectorEvent,
use serde::Serialize;
use transformers as razorpayv2;

use crate::connectors::razorpay::transformers::ForeignTryFrom;
pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const AUTHORIZATION: &str = "Authorization";
}
#[derive(Clone)]
pub struct RazorpayV2<T> {
    #[allow(dead_code)]
    pub(crate) amount_converter: &'static (dyn AmountConvertor<Output = MinorUnit> + Sync),
    _phantom: std::marker::PhantomData<T>,
impl<T> RazorpayV2<T> {
    pub const fn new() -> &'static Self {
        &Self {
            amount_converter: &common_utils::types::MinorUnitForConnector,
            _phantom: std::marker::PhantomData,
        }
    }
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > interfaces::connector_types::ValidationTrait for RazorpayV2<T>
{
    fn should_do_order_create(&self) -> bool {
        true
    > ConnectorCommon for RazorpayV2<T>
    fn id(&self) -> &'static str {
        "razorpayv2"
    fn get_currency_unit(&self) -> common_enums::CurrencyUnit {
        common_enums::CurrencyUnit::Base
    fn get_auth_header(
        &self,
        auth_type: &domain_types::router_data::ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth = razorpayv2::RazorpayV2AuthType::try_from(auth_type)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        Ok(vec![(
            headers::AUTHORIZATION.to_string(),
            auth.generate_authorization_header().into(),
        )])
    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        &connectors.razorpayv2.base_url
    fn build_error_response(
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        let response: razorpayv2::RazorpayV2ErrorResponse = res
            .response
            .parse_struct("RazorpayV2ErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        if let Some(i) = event_builder {
            i.set_error_response_body(&response)
        let (code, message, attempt_status) = match response {
            razorpayv2::RazorpayV2ErrorResponse::StandardError { error } => {
                let attempt_status = match error.code.as_str() {
                    "BAD_REQUEST_ERROR" => AttemptStatus::Failure,
                    "GATEWAY_ERROR" => AttemptStatus::Failure,
                    "AUTHENTICATION_ERROR" => AttemptStatus::AuthenticationFailed,
                    "AUTHORIZATION_ERROR" => AttemptStatus::AuthorizationFailed,
                    "SERVER_ERROR" => AttemptStatus::Pending,
                    _ => AttemptStatus::Pending,
                };
                (error.code, error.description.clone(), attempt_status)
            }
            razorpayv2::RazorpayV2ErrorResponse::SimpleError { message } => {
                // For simple error messages like "no Route matched with those values"
                // Default to failure status and use a generic error code
                (
                    "ROUTE_ERROR".to_string(),
                    message.clone(),
                    AttemptStatus::Failure,
                )
        };
        Ok(domain_types::router_data::ErrorResponse {
            code,
            message: message.clone(),
            reason: Some(message),
            status_code: res.status_code,
            attempt_status: Some(attempt_status),
            connector_transaction_id: None,
            network_decline_code: None,
            network_advice_code: None,
            network_error_message: None,
        })
    >
    ConnectorIntegrationV2<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for RazorpayV2<T>
    fn get_headers(
        req: &domain_types::router_data_v2::RouterDataV2<
            CreateOrder,
            PaymentFlowData,
            PaymentCreateOrderData,
            PaymentCreateOrderResponse,
        >,
        let mut headers = vec![(
            headers::CONTENT_TYPE.to_string(),
            "application/json".to_string().into(),
        )];
        let mut auth_headers = self.get_auth_header(&req.connector_auth_type)?;
        headers.append(&mut auth_headers);
        Ok(headers)
    fn get_url(
    ) -> CustomResult<String, errors::ConnectorError> {
        let base_url = &req.resource_common_data.connectors.razorpayv2.base_url;
        Ok(format!("{base_url}v1/orders"))
    fn get_request_body(
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let connector_router_data: razorpayv2::RazorpayV2RouterData<&PaymentCreateOrderData, T> =
            razorpayv2::RazorpayV2RouterData::try_from((
                req.request.amount,
                &req.request,
                Some(
                    req.resource_common_data
                        .connector_request_reference_id
                        .clone(),
                ),
            ))?;
        let connector_req =
            razorpayv2::RazorpayV2CreateOrderRequest::try_from(&connector_router_data)?;
        Ok(Some(RequestContent::Json(Box::new(connector_req))))
    fn handle_response_v2(
        data: &domain_types::router_data_v2::RouterDataV2<
    ) -> CustomResult<
        domain_types::router_data_v2::RouterDataV2<
        errors::ConnectorError,
    > {
        let response: razorpayv2::RazorpayV2CreateOrderResponse = res
            .parse_struct("RazorpayV2CreateOrderResponse")
            i.set_response_body(&response)
        let order_response = PaymentCreateOrderResponse {
            order_id: response.id,
        Ok(domain_types::router_data_v2::RouterDataV2 {
            response: Ok(order_response),
            ..data.clone()
    fn get_error_response_v2(
        self.build_error_response(res, event_builder)
    fn get_5xx_error_response(
        let (code, message) = match response {
                (error.code, error.description.clone())
                ("ROUTE_ERROR".to_string(), message.clone())
            attempt_status: Some(AttemptStatus::Pending),
        Authorize,
        PaymentsAuthorizeData<T>,
        PaymentsResponseData,
            Authorize,
            PaymentsAuthorizeData<T>,
            PaymentsResponseData,
        // For UPI payments, use the specific UPI endpoint
        match &req.request.payment_method_data {
            PaymentMethodData::Upi(_) => Ok(format!("{base_url}v1/payments/create/upi")),
            _ => Ok(format!("{base_url}v1/payments")),
        let order_id = req
            .resource_common_data
            .reference_id
            .as_ref()
            .ok_or_else(|| errors::ConnectorError::MissingRequiredField {
                field_name: "reference_id",
            })?
            .clone();
        let converted_amount = self
            .amount_converter
            .convert(req.request.minor_amount, req.request.currency)
            .change_context(domain_types::errors::ConnectorError::RequestEncodingFailed)?;
        let connector_router_data = razorpayv2::RazorpayV2RouterData::try_from((
            converted_amount,
            req,
            Some(order_id),
            req.resource_common_data
                .address
                .get_payment_method_billing()
                .cloned(),
        ))?;
        // Always use v2 request format
            razorpayv2::RazorpayV2PaymentsRequest::try_from(&connector_router_data)?;
        // Try to parse as UPI response first
        let upi_response_result = res
            .parse_struct::<razorpayv2::RazorpayV2UpiPaymentsResponse>(
                "RazorpayV2UpiPaymentsResponse",
            );
        match upi_response_result {
            Ok(upi_response) => {
                if let Some(i) = event_builder {
                    i.set_response_body(&upi_response)
                }
                // Use the transformer for UPI response handling
                RouterDataV2::foreign_try_from((
                    upi_response,
                    data.clone(),
                    res.status_code,
                    res.response.to_vec(),
                ))
                .change_context(errors::ConnectorError::ResponseHandlingFailed)
            Err(_) => {
                // Fall back to regular payment response
                let response: razorpayv2::RazorpayV2PaymentsResponse = res
                    .response
                    .parse_struct("RazorpayV2PaymentsResponse")
                    .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
                    i.set_response_body(&response)
                // Use the transformer for regular response handling
                    response,
// Implement required traits for ConnectorServiceTrait
    > interfaces::connector_types::PaymentAuthorizeV2<T> for RazorpayV2<T>
    > interfaces::connector_types::PaymentSyncV2 for RazorpayV2<T>
    > interfaces::connector_types::PaymentOrderCreate for RazorpayV2<T>
    > interfaces::connector_types::PaymentVoidV2 for RazorpayV2<T>
    > interfaces::connector_types::IncomingWebhook for RazorpayV2<T>
    > interfaces::connector_types::RefundV2 for RazorpayV2<T>
    > interfaces::connector_types::PaymentCapture for RazorpayV2<T>
    > interfaces::connector_types::SetupMandateV2<T> for RazorpayV2<T>
    > interfaces::connector_types::AcceptDispute for RazorpayV2<T>
    > interfaces::connector_types::RefundSyncV2 for RazorpayV2<T>
    > interfaces::connector_types::DisputeDefend for RazorpayV2<T>
    > interfaces::connector_types::SubmitEvidenceV2 for RazorpayV2<T>
// Type alias for non-generic trait implementations
        CreateSessionToken,
        SessionTokenRequestData,
        SessionTokenResponseData,
        CreateAccessToken,
        AccessTokenRequestData,
        AccessTokenResponseData,
        CreateConnectorCustomer,
        ConnectorCustomerData,
        ConnectorCustomerResponse,
    > interfaces::connector_types::ConnectorServiceTrait<T> for RazorpayV2<T>
    > interfaces::connector_types::PaymentSessionToken for RazorpayV2<T>
    > interfaces::connector_types::PaymentAccessToken for RazorpayV2<T>
    > connector_types::CreateConnectorCustomer for RazorpayV2<T>
    > interfaces::connector_types::PaymentTokenV2<T> for RazorpayV2<T>
    > interfaces::connector_types::RepeatPaymentV2 for RazorpayV2<T>
    > interfaces::connector_types::PaymentPreAuthenticateV2<T> for RazorpayV2<T>
    > interfaces::connector_types::PaymentAuthenticateV2<T> for RazorpayV2<T>
    > interfaces::connector_types::PaymentPostAuthenticateV2<T> for RazorpayV2<T>
    > interfaces::connector_types::PaymentVoidPostCaptureV2 for RazorpayV2<T>
        VoidPC,
        PaymentsCancelPostCaptureData,
// Stub implementations for flows not yet implemented
    > ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
    for RazorpayV2<T>
    > ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
    > ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    fn get_http_method(&self) -> common_utils::Method {
        common_utils::Method::Get
            PSync,
            PaymentsSyncData,
        // Check if request_ref_id is provided to determine URL pattern
        let request_ref_id = &req.resource_common_data.connector_request_reference_id;
        if !request_ref_id.is_empty() {
            // Use orders endpoint when request_ref_id is provided
            let url = format!("{base_url}v1/orders/{request_ref_id}/payments");
            Ok(url)
        } else {
            // Extract payment ID from connector_transaction_id for standard payment sync
            let payment_id = match &req.request.connector_transaction_id {
                ResponseId::ConnectorTransactionId(id) => id,
                ResponseId::EncodedData(data) => data,
                ResponseId::NoResponseId => {
                    return Err(errors::ConnectorError::MissingRequiredField {
                        field_name: "connector_transaction_id",
                    }
                    .into());
            };
            let url = format!("{base_url}v1/payments/{payment_id}");
        _req: &domain_types::router_data_v2::RouterDataV2<
        // GET request doesn't need a body
        Ok(None)
        // Parse the response using the enum that handles both collection and direct payment responses
        let sync_response: razorpayv2::RazorpayV2SyncResponse = res
            .parse_struct("RazorpayV2SyncResponse")
            i.set_response_body(&sync_response)
        // Use the transformer for PSync response handling
        RouterDataV2::foreign_try_from((
            sync_response,
            data.clone(),
            res.status_code,
            res.response.to_vec(),
        ))
        .change_context(errors::ConnectorError::ResponseHandlingFailed)
        SetupMandate,
        SetupMandateRequestData<T>,
    > ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
            RSync,
            RefundFlowData,
            RefundSyncData,
            RefundsResponseData,
        // Extract refund ID from connector_refund_id
        let refund_id = &req.request.connector_refund_id;
        Ok(format!("{base_url}v1/refunds/{refund_id}"))
        let response: razorpayv2::RazorpayV2RefundResponse = res
            .parse_struct("RazorpayV2RefundResponse")
            response,
    > ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
            Refund,
            RefundsData,
        let connector_payment_id = &req.request.connector_transaction_id;
        Ok(format!(
            "{base_url}v1/payments/{connector_payment_id}/refund"
            .convert(req.request.minor_refund_amount, req.request.currency)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;
        let connector_router_data = razorpayv2::RazorpayV2RouterData::<
            &RefundsData,
            DefaultPCIHolder,
        >::try_from((converted_amount, &req.request, None))?;
        let connector_req = razorpayv2::RazorpayV2RefundRequest::try_from(&connector_router_data)?;
    > ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
    > ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
    interfaces::verification::SourceVerification<
        PaymentMethodToken,
        PaymentMethodTokenizationData<T>,
        PaymentMethodTokenResponse,
// SourceVerification implementations for all flows
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
    > domain_types::connector_types::ConnectorSpecifications for RazorpayV2<T>
        RepeatPayment,
        RepeatPaymentData,
    ConnectorIntegrationV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>
        PreAuthenticate,
        PaymentsPreAuthenticateData<T>,
        Authenticate,
        PaymentsAuthenticateData<T>,
        PostAuthenticate,
        PaymentsPostAuthenticateData<T>,
