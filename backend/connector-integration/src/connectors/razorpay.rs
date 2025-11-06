pub mod test;
use common_utils::Maskable;
pub mod transformers;
use std::sync::LazyLock;

use common_enums::{
    AttemptStatus, CaptureMethod, CardNetwork, EventClass, PaymentMethod, PaymentMethodType,
};
use common_utils::{
    errors::CustomResult,
    ext_traits::ByteSliceExt,
    pii::SecretSerdeValue,
    request::{Method, RequestContent},
    types::{AmountConvertor, MinorUnit},
};
use domain_types::{
    connector_flow::{
        Accept, Authenticate, Authorize, Capture, CreateAccessToken, CreateConnectorCustomer,
        CreateOrder, CreateSessionToken, DefendDispute, PSync, PaymentMethodToken,
        PostAuthenticate, PreAuthenticate, RSync, Refund, SetupMandate, SubmitEvidence, Void,
        VoidPC,
    },
    connector_types::{
        AcceptDisputeData, AccessTokenRequestData, AccessTokenResponseData, ConnectorCustomerData,
        ConnectorCustomerResponse, ConnectorSpecifications, ConnectorWebhookSecrets,
        DisputeDefendData, DisputeFlowData, DisputeResponseData, EventType, PaymentCreateOrderData,
        PaymentCreateOrderResponse, PaymentFlowData, PaymentMethodTokenResponse,
        PaymentMethodTokenizationData, PaymentVoidData, PaymentsAuthenticateData,
        PaymentsAuthorizeData, PaymentsCancelPostCaptureData, PaymentsCaptureData,
        PaymentsPostAuthenticateData, PaymentsPreAuthenticateData, PaymentsResponseData,
        PaymentsSyncData, RefundFlowData, RefundSyncData, RefundWebhookDetailsResponse,
        RefundsData, RefundsResponseData, RequestDetails, ResponseId, SessionTokenRequestData,
        SessionTokenResponseData, SetupMandateRequestData, SubmitEvidenceData,
        SupportedPaymentMethodsExt, WebhookDetailsResponse,
    },
    errors,
    payment_method_data::{DefaultPCIHolder, PaymentMethodData, PaymentMethodDataTypes},
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::{
        CardSpecificFeatures, ConnectorInfo, Connectors, FeatureStatus, PaymentConnectorCategory,
        PaymentMethodDataType, PaymentMethodDetails, PaymentMethodSpecificFeatures,
        SupportedPaymentMethods,
    },
    utils,
};
use error_stack::{report, ResultExt};
// use crate::masking::{Mask, Maskable};
use interfaces::{
    api::ConnectorCommon,
    connector_integration_v2::ConnectorIntegrationV2,
    connector_types::{self, is_mandate_supported},
    events::connector_api_logs::ConnectorEvent,
};
use serde::Serialize;
use transformers::{self as razorpay, ForeignTryFrom};
use crate::{
    connectors::razorpayv2::transformers::RazorpayV2SyncResponse, with_error_response_body,
    with_response_body,
pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const AUTHORIZATION: &str = "Authorization";
    pub(crate) const ACCEPT: &str = "Accept";
}
#[derive(Clone)]
pub struct Razorpay<T> {
    #[allow(dead_code)]
    pub(crate) amount_converter: &'static (dyn AmountConvertor<Output = MinorUnit> + Sync),
    _phantom: std::marker::PhantomData<T>,
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::ValidationTrait for Razorpay<T>
{
    fn should_do_order_create(&self) -> bool {
        true
    }
// Type alias for non-generic trait implementations
    > connector_types::ConnectorServiceTrait<T> for Razorpay<T>
    > connector_types::PaymentAuthorizeV2<T> for Razorpay<T>
    > connector_types::PaymentSessionToken for Razorpay<T>
    > connector_types::PaymentAccessToken for Razorpay<T>
    > connector_types::CreateConnectorCustomer for Razorpay<T>
    > connector_types::PaymentSyncV2 for Razorpay<T>
    > connector_types::PaymentOrderCreate for Razorpay<T>
    > connector_types::PaymentVoidV2 for Razorpay<T>
    > connector_types::RefundSyncV2 for Razorpay<T>
    > connector_types::RefundV2 for Razorpay<T>
    > connector_types::PaymentCapture for Razorpay<T>
    > connector_types::SetupMandateV2<T> for Razorpay<T>
    > connector_types::AcceptDispute for Razorpay<T>
    > connector_types::SubmitEvidenceV2 for Razorpay<T>
    > connector_types::DisputeDefend for Razorpay<T>
    > connector_types::RepeatPaymentV2 for Razorpay<T>
    > connector_types::PaymentVoidPostCaptureV2 for Razorpay<T>
    >
    ConnectorIntegrationV2<
        PaymentFlowData,
        PaymentsCancelPostCaptureData,
        PaymentsResponseData,
    > for Razorpay<T>
    > connector_types::PaymentTokenV2<T> for Razorpay<T>
    > connector_types::PaymentPreAuthenticateV2<T> for Razorpay<T>
    > connector_types::PaymentAuthenticateV2<T> for Razorpay<T>
    > connector_types::PaymentPostAuthenticateV2<T> for Razorpay<T>
impl<T> Razorpay<T> {
    pub const fn new() -> &'static Self {
        &Self {
            amount_converter: &common_utils::types::MinorUnitForConnector,
            _phantom: std::marker::PhantomData,
        }
    > ConnectorCommon for Razorpay<T>
    fn id(&self) -> &'static str {
        "razorpay"
    fn get_currency_unit(&self) -> common_enums::CurrencyUnit {
        common_enums::CurrencyUnit::Minor
    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth = razorpay::RazorpayAuthType::try_from(auth_type)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        Ok(vec![(
            headers::AUTHORIZATION.to_string(),
            auth.generate_authorization_header().into_masked(),
        )])
    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.razorpay.base_url.as_ref()
    fn build_error_response(
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: razorpay::RazorpayErrorResponse = res
            .response
            .parse_struct("ErrorResponse")
            .map_err(|_| errors::ConnectorError::ResponseDeserializationFailed)?;
        with_error_response_body!(event_builder, response);
        let (code, message, reason, attempt_status) = match response {
            razorpay::RazorpayErrorResponse::StandardError { error } => {
                let attempt_status = match error.code.as_str() {
                    "BAD_REQUEST_ERROR" => AttemptStatus::Failure,
                    "GATEWAY_ERROR" => AttemptStatus::Failure,
                    "AUTHENTICATION_ERROR" => AttemptStatus::AuthenticationFailed,
                    "AUTHORIZATION_ERROR" => AttemptStatus::AuthorizationFailed,
                    "SERVER_ERROR" => AttemptStatus::Pending,
                    _ => AttemptStatus::Pending,
                };
                (error.code, error.description, error.reason, attempt_status)
            }
            razorpay::RazorpayErrorResponse::SimpleError { message } => {
                // For simple error messages like "no Route matched with those values"
                // Default to a generic error code
                (
                    "ROUTE_ERROR".to_string(),
                    message.clone(),
                    Some(message.clone()),
                    AttemptStatus::Failure,
                )
        };
        Ok(ErrorResponse {
            status_code: res.status_code,
            code,
            message: message.clone(),
            reason,
            attempt_status: Some(attempt_status),
            connector_transaction_id: None,
            network_decline_code: None,
            network_advice_code: None,
            network_error_message: None,
        })
        Authorize,
        PaymentsAuthorizeData<T>,
    fn get_headers(
        req: &RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData<T>,
            PaymentsResponseData,
        >,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError>
    where
        Self: ConnectorIntegrationV2<
    {
        let mut header = vec![
            (
                headers::CONTENT_TYPE.to_string(),
                "application/x-www-form-urlencoded".to_string().into(),
            ),
                headers::ACCEPT.to_string(),
                "application/json".to_string().into(),
        ];
        let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
        header.append(&mut api_key);
        Ok(header)
    fn get_url(
    ) -> CustomResult<String, errors::ConnectorError> {
        let base_url = &req.resource_common_data.connectors.razorpay.base_url;
        // For UPI payments, use the specific UPI endpoint
        match &req.request.payment_method_data {
            PaymentMethodData::Upi(_) => Ok(format!("{base_url}v1/payments/create/upi")),
            _ => Ok(format!("{base_url}v1/payments/create/json")),
    fn get_request_body(
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let converted_amount = self
            .amount_converter
            .convert(req.request.minor_amount, req.request.currency)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;
        let connector_router_data =
            razorpay::RazorpayRouterData::try_from((converted_amount, req))?;
            PaymentMethodData::Upi(_) => {
                let connector_req =
                    razorpay::RazorpayWebCollectRequest::try_from(&connector_router_data)?;
                Ok(Some(RequestContent::FormUrlEncoded(Box::new(
                    connector_req,
                ))))
            _ => {
                    razorpay::RazorpayPaymentRequest::try_from(&connector_router_data)?;
                Ok(Some(RequestContent::Json(Box::new(connector_req))))
    fn handle_response_v2(
        data: &RouterDataV2<
    ) -> CustomResult<
        RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        errors::ConnectorError,
    > {
        // Handle UPI payments differently from regular payments
        match &data.request.payment_method_data {
                // Try to parse as UPI response first
                let upi_response_result = res
                    .response
                    .parse_struct::<razorpay::RazorpayUpiPaymentsResponse>(
                        "RazorpayUpiPaymentsResponse",
                    );
                match upi_response_result {
                    Ok(upi_response) => {
                        with_response_body!(event_builder, upi_response);
                        // Use the transformer for UPI response handling
                        RouterDataV2::foreign_try_from((
                            upi_response,
                            data.clone(),
                            res.status_code,
                            res.response.to_vec(),
                        ))
                        .change_context(errors::ConnectorError::ResponseHandlingFailed)
                    }
                    Err(_) => {
                        // Fall back to regular payment response
                        let response: razorpay::RazorpayResponse = res
                            .response
                            .parse_struct("RazorpayPaymentResponse")
                            .change_context(
                                errors::ConnectorError::ResponseDeserializationFailed,
                            )?;
                        with_response_body!(event_builder, response);
                            response,
                            data.request.capture_method,
                            false,
                            data.request.payment_method_type,
                }
                // Regular payment response handling
                let response: razorpay::RazorpayResponse = res
                    .parse_struct("RazorpayPaymentResponse")
                    .map_err(|_| errors::ConnectorError::ResponseDeserializationFailed)?;
                with_response_body!(event_builder, response);
                RouterDataV2::foreign_try_from((
                    response,
                    data.clone(),
                    res.status_code,
                    data.request.capture_method,
                    false,
                    data.request.payment_method_type,
                ))
                .change_context(errors::ConnectorError::ResponseHandlingFailed)
    fn get_error_response_v2(
        self.build_error_response(res, event_builder)
    fn get_5xx_error_response(
    > ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    for Razorpay<T>
    fn get_http_method(&self) -> Method {
        Method::Get
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        let mut header = vec![(
            headers::CONTENT_TYPE.to_string(),
            "application/json".to_string().into(),
        )];
        // Check if request_ref_id is provided to determine URL pattern
        let request_ref_id = &req.resource_common_data.connector_request_reference_id;
        if request_ref_id != "default_reference_id" {
            // Use orders endpoint when request_ref_id is provided
            let url = format!("{base_url}v1/orders/{request_ref_id}/payments");
            Ok(url)
        } else {
            // Extract payment ID from connector_transaction_id for standard payment sync
            let payment_id = req
                .request
                .connector_transaction_id
                .get_connector_transaction_id()
                .change_context(errors::ConnectorError::RequestEncodingFailed)?;
            let url = format!("{base_url}v1/payments/{payment_id}");
        data: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        // Parse the response using the enum that handles both collection and direct payment responses
        let sync_response: RazorpayV2SyncResponse = res
            .parse_struct("RazorpayV2SyncResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        with_response_body!(event_builder, sync_response);
        // Use the transformer for PSync response handling
        RouterDataV2::foreign_try_from((
            sync_response,
            data.clone(),
            res.status_code,
            res.response.to_vec(),
        ))
        .change_context(errors::ConnectorError::ResponseHandlingFailed)
        CreateOrder,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
            CreateOrder,
            PaymentCreateOrderData,
            PaymentCreateOrderResponse,
        Ok(format!(
            "{}v1/orders",
            req.resource_common_data.connectors.razorpay.base_url
            .convert(req.request.amount, req.request.currency)
        let connector_req = razorpay::RazorpayOrderRequest::try_from(&connector_router_data)?;
        Ok(Some(RequestContent::FormUrlEncoded(Box::new(
            connector_req,
        ))))
        RouterDataV2<
        let response: razorpay::RazorpayOrderResponse = res
            .parse_struct("RazorpayOrderResponse")
        with_response_body!(event_builder, response);
        RouterDataV2::foreign_try_from((response, data.clone(), res.status_code, false))
            .change_context(errors::ConnectorError::ResponseHandlingFailed)
    > ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
        req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        Self: ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        let refund_id = req.request.connector_refund_id.clone();
            "{}v1/refunds/{}",
            req.resource_common_data.connectors.razorpay.base_url, refund_id
        data: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        let response: razorpay::RazorpayRefundResponse = res
            .parse_struct("RazorpayRefundSyncResponse")
        RouterDataV2::foreign_try_from((response, data.clone(), res.status_code))
    > connector_types::IncomingWebhook for Razorpay<T>
    fn get_event_type(
        request: RequestDetails,
        _connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorAuthType>,
    ) -> Result<EventType, error_stack::Report<errors::ConnectorError>> {
        let payload = transformers::get_webhook_object_from_body(request.body).map_err(|err| {
            report!(errors::ConnectorError::WebhookBodyDecodingFailed)
                .attach_printable(format!("error while decoing webhook body {err}"))
        })?;
        if payload.refund.is_some() {
            Ok(EventType::RefundSuccess)
            Ok(EventType::PaymentIntentSuccess)
    fn process_payment_webhook(
    ) -> Result<WebhookDetailsResponse, error_stack::Report<errors::ConnectorError>> {
        let request_body_copy = request.body.clone();
                .attach_printable(format!("error while decoding webhook body {err}"))
        let notif = payload.payment.ok_or_else(|| {
            error_stack::Report::new(errors::ConnectorError::RequestEncodingFailed)
        Ok(WebhookDetailsResponse {
            resource_id: Some(ResponseId::ConnectorTransactionId(notif.entity.order_id)),
            status: transformers::get_razorpay_payment_webhook_status(
                notif.entity.entity,
                notif.entity.status,
            )?,
            mandate_reference: None,
            connector_response_reference_id: None,
            error_code: notif.entity.error_code,
            error_message: notif.entity.error_reason,
            raw_connector_response: Some(String::from_utf8_lossy(&request_body_copy).to_string()),
            status_code: 200,
            response_headers: None,
            transformation_status: common_enums::WebhookTransformationStatus::Complete,
            minor_amount_captured: None,
            amount_captured: None,
            error_reason: None,
            network_txn_id: None,
    fn process_refund_webhook(
    ) -> Result<RefundWebhookDetailsResponse, error_stack::Report<errors::ConnectorError>> {
        let notif = payload.refund.ok_or_else(|| {
        Ok(RefundWebhookDetailsResponse {
            connector_refund_id: Some(notif.entity.id),
            status: transformers::get_razorpay_refund_webhook_status(
            error_code: None,
            error_message: None,
    > ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
    > ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
        req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        Self: ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        let connector_payment_id = req.request.connector_transaction_id.clone();
            "{}v1/payments/{}/refund",
            req.resource_common_data.connectors.razorpay.base_url, connector_payment_id
            .convert(req.request.minor_refund_amount, req.request.currency)
        let refund_router_data = razorpay::RazorpayRouterData::try_from((converted_amount, req))?;
        let connector_req = razorpay::RazorpayRefundRequest::try_from(&refund_router_data)?;
        Ok(Some(RequestContent::Json(Box::new(connector_req))))
        data: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            .parse_struct("RazorpayRefundResponse")
    > ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
        req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            Capture,
            PaymentsCaptureData,
        let id = match &req.request.connector_transaction_id {
            ResponseId::ConnectorTransactionId(id) => id,
                return Err(errors::ConnectorError::MissingConnectorTransactionID.into());
            "{}v1/payments/{}/capture",
            req.resource_common_data.connectors.razorpay.base_url, id
            .convert(req.request.minor_amount_to_capture, req.request.currency)
        let connector_req = razorpay::RazorpayCaptureRequest::try_from(&connector_router_data)?;
        data: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        let response: razorpay::RazorpayCaptureResponse = res
            .parse_struct("RazorpayCaptureResponse")
            .map_err(|err| {
                report!(errors::ConnectorError::ResponseDeserializationFailed)
                    .attach_printable(format!("Failed to parse RazorpayCaptureResponse: {err:?}"))
            })?;
        SetupMandate,
        SetupMandateRequestData<T>,
    > ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
    > ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
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
impl connector_types::ConnectorValidation for Razorpay<DefaultPCIHolder> {
    fn validate_mandate_payment(
        pm_type: Option<PaymentMethodType>,
        pm_data: PaymentMethodData<DefaultPCIHolder>,
    ) -> CustomResult<(), errors::ConnectorError> {
        let mandate_supported_pmd = std::collections::HashSet::from([PaymentMethodDataType::Card]);
        is_mandate_supported(pm_data, pm_type, mandate_supported_pmd, self.id())
    fn validate_psync_reference_id(
        data: &PaymentsSyncData,
        _is_three_ds: bool,
        _status: AttemptStatus,
        _connector_meta_data: Option<SecretSerdeValue>,
        if data.encoded_data.is_some() {
            return Ok(());
        Err(errors::ConnectorError::MissingRequiredField {
            field_name: "encoded_data",
        }
        .into())
    fn is_webhook_source_verification_mandatory(&self) -> bool {
        false
    }
}

static RAZORPAY_SUPPORTED_PAYMENT_METHODS: LazyLock<SupportedPaymentMethods> =
    LazyLock::new(|| {
        let razorpay_supported_capture_methods = vec![
            CaptureMethod::Automatic,
            CaptureMethod::Manual,
            CaptureMethod::ManualMultiple,
            // CaptureMethod::Scheduled,
        ];
        let razorpay_supported_card_network = vec![
            CardNetwork::Visa,
            CardNetwork::Mastercard,
            CardNetwork::AmericanExpress,
            CardNetwork::Maestro,
            CardNetwork::RuPay,
            CardNetwork::DinersClub,
            //have to add bajaj to this list too
            // ref : https://razorpay.com/docs/payments/payment-methods/cards/
        ];
        let mut razorpay_supported_payment_methods = SupportedPaymentMethods::new();
        razorpay_supported_payment_methods.add(
            PaymentMethod::Card,
            PaymentMethodType::Debit,
            PaymentMethodDetails {
                mandates: FeatureStatus::NotSupported,
                refunds: FeatureStatus::Supported,
                supported_capture_methods: razorpay_supported_capture_methods.clone(),
                specific_features: Some(PaymentMethodSpecificFeatures::Card(
                    CardSpecificFeatures {
                        three_ds: FeatureStatus::NotSupported,
                        no_three_ds: FeatureStatus::Supported,
                        supported_card_networks: razorpay_supported_card_network.clone(),
                    },
                )),
            },
        );
        razorpay_supported_payment_methods.add(
            PaymentMethod::Card,
            PaymentMethodType::Credit,
            PaymentMethodDetails {
                mandates: FeatureStatus::NotSupported,
                refunds: FeatureStatus::Supported,
                supported_capture_methods: razorpay_supported_capture_methods.clone(),
                specific_features: Some(PaymentMethodSpecificFeatures::Card(
                    CardSpecificFeatures {
                        three_ds: FeatureStatus::NotSupported,
                        no_three_ds: FeatureStatus::Supported,
                        supported_card_networks: razorpay_supported_card_network.clone(),
                    },
                )),
            },
        );
        razorpay_supported_payment_methods
    });
static RAZORPAY_CONNECTOR_INFO: ConnectorInfo = ConnectorInfo {
    display_name: "Razorpay",
    description: "Razorpay is a payment gateway that allows businesses to accept, process, and disburse payments with its product suite.",
    connector_type: PaymentConnectorCategory::PaymentGateway
static RAZORPAY_SUPPORTED_WEBHOOK_FLOWS: &[EventClass] =
    &[EventClass::Payments, EventClass::Refunds];
    > ConnectorSpecifications for Razorpay<T>
    fn get_connector_about(&self) -> Option<&'static ConnectorInfo> {
        Some(&RAZORPAY_CONNECTOR_INFO)
    fn get_supported_webhook_flows(&self) -> Option<&'static [EventClass]> {
        Some(RAZORPAY_SUPPORTED_WEBHOOK_FLOWS)
    fn get_supported_payment_methods(&self) -> Option<&'static SupportedPaymentMethods> {
        Some(&RAZORPAY_SUPPORTED_PAYMENT_METHODS)
        domain_types::connector_flow::RepeatPayment,
        domain_types::connector_types::RepeatPaymentData,
