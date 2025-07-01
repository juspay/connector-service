pub mod test;
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
        Accept, Authorize, Capture, CreateOrder, DefendDispute, PSync, RSync, Refund, SetupMandate,
        SubmitEvidence, Void,
    },
    connector_types::{
        AcceptDisputeData, ConnectorSpecifications, ConnectorWebhookSecrets, DisputeDefendData,
        DisputeFlowData, DisputeResponseData, EventType, PaymentCreateOrderData,
        PaymentCreateOrderResponse, PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData,
        PaymentsCaptureData, PaymentsResponseData, PaymentsSyncData, RefundFlowData,
        RefundSyncData, RefundWebhookDetailsResponse, RefundsData, RefundsResponseData,
        RequestDetails, ResponseId, SetupMandateRequestData, SubmitEvidenceData,
        SupportedPaymentMethodsExt, WebhookDetailsResponse,
    },
    errors,
    payment_method_data::PaymentMethodData,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::{
        CardSpecificFeatures, ConnectorInfo, Connectors, FeatureStatus, PaymentConnectorCategory,
        PaymentMethodDataType, PaymentMethodDetails, PaymentMethodSpecificFeatures,
        SupportedPaymentMethods,
    },
};
use error_stack::{report, ResultExt};
use hyperswitch_masking::{Mask, Maskable};
use interfaces::{
    api::ConnectorCommon,
    connector_integration_v2::ConnectorIntegrationV2,
    connector_types::{self, is_mandate_supported},
    events::connector_api_logs::ConnectorEvent,
};
use transformers::{self as razorpay, ForeignTryFrom};

use crate::{
    connectors::razorpayv2::transformers::RazorpayV2SyncResponse, with_error_response_body,
    with_response_body,
};

pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const AUTHORIZATION: &str = "Authorization";
}

#[derive(Clone)]
pub struct Razorpay {
    #[allow(dead_code)]
    pub(crate) amount_converter: &'static (dyn AmountConvertor<Output = MinorUnit> + Sync),
}

impl connector_types::ValidationTrait for Razorpay {
    fn should_do_order_create(&self) -> bool {
        true
    }
}

impl connector_types::ConnectorServiceTrait for Razorpay {}
impl connector_types::PaymentAuthorizeV2 for Razorpay {}
impl connector_types::PaymentSyncV2 for Razorpay {}
impl connector_types::PaymentOrderCreate for Razorpay {}
impl connector_types::PaymentVoidV2 for Razorpay {}
impl connector_types::RefundSyncV2 for Razorpay {}
impl connector_types::RefundV2 for Razorpay {}
impl connector_types::PaymentCapture for Razorpay {}
impl connector_types::SetupMandateV2 for Razorpay {}
impl connector_types::AcceptDispute for Razorpay {}
impl connector_types::SubmitEvidenceV2 for Razorpay {}
impl connector_types::DisputeDefend for Razorpay {}

impl Razorpay {
    pub const fn new() -> &'static Self {
        &Self {
            amount_converter: &common_utils::types::MinorUnitForConnector,
        }
    }
}

impl ConnectorCommon for Razorpay {
    fn id(&self) -> &'static str {
        "razorpay"
    }
    fn get_currency_unit(&self) -> common_enums::CurrencyUnit {
        common_enums::CurrencyUnit::Minor
    }
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
    }
    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.razorpay.base_url.as_ref()
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: razorpay::RazorpayErrorResponse = res
            .response
            .parse_struct("ErrorResponse")
            .map_err(|_| errors::ConnectorError::ResponseDeserializationFailed)?;

        with_error_response_body!(event_builder, response);

        let (code, message, reason) = match response {
            razorpay::RazorpayErrorResponse::StandardError { error } => {
                (error.code, error.description, Some(error.reason))
            }
            razorpay::RazorpayErrorResponse::SimpleError { message } => {
                // For simple error messages like "no Route matched with those values"
                // Default to a generic error code
                (
                    "ROUTE_ERROR".to_string(),
                    message.clone(),
                    Some(message.clone()),
                )
            }
        };

        Ok(ErrorResponse {
            status_code: res.status_code,
            code,
            message: message.clone(),
            reason,
            attempt_status: None,
            connector_transaction_id: None,
            network_decline_code: None,
            network_advice_code: None,
            network_error_message: None,
            raw_connector_response: Some(String::from_utf8_lossy(&res.response).to_string()),
        })
    }
}

impl ConnectorIntegrationV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>
    for Razorpay
{
    fn get_headers(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError>
    where
        Self: ConnectorIntegrationV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData,
            PaymentsResponseData,
        >,
    {
        let mut header = vec![(
            headers::CONTENT_TYPE.to_string(),
            "application/json".to_string().into(),
        )];
        let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
        header.append(&mut api_key);
        Ok(header)
    }

    fn get_url(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        let base_url = &req.resource_common_data.connectors.razorpay.base_url;

        // For UPI payments, use the specific UPI endpoint
        use domain_types::payment_method_data::PaymentMethodData;
        match &req.request.payment_method_data {
            PaymentMethodData::Upi(_) => Ok(format!("{base_url}v1/payments/create/upi")),
            _ => Ok(format!("{base_url}v1/payments/create/json")),
        }
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let connector_router_data =
            razorpay::RazorpayRouterData::try_from((req.request.minor_amount, req))?;

        // Use different request types for UPI vs other payment methods
        use domain_types::payment_method_data::PaymentMethodData;
        match &req.request.payment_method_data {
            PaymentMethodData::Upi(_) => {
                let connector_req =
                    razorpay::RazorpayWebCollectRequest::try_from(&connector_router_data)?;
                Ok(Some(RequestContent::Json(Box::new(connector_req))))
            }
            _ => {
                let connector_req =
                    razorpay::RazorpayPaymentRequest::try_from(&connector_router_data)?;
                Ok(Some(RequestContent::Json(Box::new(connector_req))))
            }
        }
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData,
            PaymentsResponseData,
        >,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<
        RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        errors::ConnectorError,
    > {
        // Handle UPI payments differently from regular payments
        use domain_types::payment_method_data::PaymentMethodData;
        match &data.request.payment_method_data {
            PaymentMethodData::Upi(_) => {
                // Try to parse as UPI response first
                let upi_response_result = res
                    .response
                    .parse_struct::<razorpay::RazorpayUpiPaymentsResponse>(
                        "RazorpayUpiPaymentsResponse",
                    );

                let (transaction_id, redirection_data) = match upi_response_result {
                    Ok(upi_response) => {
                        with_response_body!(event_builder, upi_response);

                        match upi_response {
                            razorpay::RazorpayUpiPaymentsResponse::SuccessIntent {
                                razorpay_payment_id,
                                link,
                            } => {
                                let redirect_form =
                                    domain_types::router_response_types::RedirectForm::Uri {
                                        uri: link,
                                    };
                                (
                                    ResponseId::ConnectorTransactionId(razorpay_payment_id),
                                    Some(redirect_form),
                                )
                            }
                            razorpay::RazorpayUpiPaymentsResponse::SuccessCollect {
                                razorpay_payment_id,
                            } => {
                                // For UPI Collect, there's no link, so no redirection data
                                (
                                    ResponseId::ConnectorTransactionId(razorpay_payment_id),
                                    None,
                                )
                            }
                            razorpay::RazorpayUpiPaymentsResponse::NullResponse {
                                razorpay_payment_id,
                            } => {
                                // Handle null response - likely an error condition
                                match razorpay_payment_id {
                                    Some(payment_id) => {
                                        (ResponseId::ConnectorTransactionId(payment_id), None)
                                    }
                                    None => {
                                        // Payment ID is null, this is likely an error
                                        return Err(
                                            errors::ConnectorError::ResponseHandlingFailed.into()
                                        );
                                    }
                                }
                            }
                            razorpay::RazorpayUpiPaymentsResponse::Error { error: _ } => {
                                // Handle error case - this should probably return an error instead
                                return Err(errors::ConnectorError::ResponseHandlingFailed.into());
                            }
                        }
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
                        return RouterDataV2::foreign_try_from((
                            response,
                            data.clone(),
                            res.status_code,
                            data.request.capture_method,
                            false,
                            data.request.payment_method_type,
                        ))
                        .change_context(errors::ConnectorError::ResponseHandlingFailed);
                    }
                };

                let payments_response_data = PaymentsResponseData::TransactionResponse {
                    resource_id: transaction_id,
                    redirection_data: Box::new(redirection_data),
                    connector_metadata: None,
                    mandate_reference: Box::new(None),
                    network_txn_id: None,
                    connector_response_reference_id: data.resource_common_data.reference_id.clone(),
                    incremental_authorization_allowed: None,
                    raw_connector_response: Some(
                        String::from_utf8_lossy(&res.response).to_string(),
                    ),
                };

                Ok(RouterDataV2 {
                    response: Ok(payments_response_data),
                    ..data.clone()
                })
            }
            _ => {
                // Regular payment response handling
                let response: razorpay::RazorpayResponse = res
                    .response
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
            }
        }
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }

    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    for Razorpay
{
    fn get_http_method(&self) -> Method {
        Method::Get
    }
    fn get_headers(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError>
    where
        Self: ConnectorIntegrationV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData,
            PaymentsResponseData,
        >,
    {
        let mut header = vec![(
            headers::CONTENT_TYPE.to_string(),
            "application/json".to_string().into(),
        )];
        let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
        header.append(&mut api_key);
        Ok(header)
    }

    fn get_url(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        let base_url = &req.resource_common_data.connectors.razorpay.base_url;
        // Check if request_ref_id is provided to determine URL pattern
        let request_ref_id = &req.resource_common_data.connector_request_reference_id;

        if request_ref_id != "default_reference_id" {
            // Use orders endpoint when request_ref_id is provided
            let url = format!("{base_url}v1/orders/{request_ref_id}/payments");
            tracing::info!("Razorpay PSync URL (orders endpoint): {}", url);
            Ok(url)
        } else {
            // Extract payment ID from connector_transaction_id for standard payment sync
            let payment_id = req
                .request
                .connector_transaction_id
                .get_connector_transaction_id()
                .change_context(errors::ConnectorError::RequestEncodingFailed)?;

            let url = format!("{}v1/payments/{}", base_url, payment_id);
            tracing::info!("Razorpay PSync URL (payments endpoint): {}", url);
            Ok(url)
        }
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<
        RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        errors::ConnectorError,
    > {
        // Parse the response using the enum that handles both collection and direct payment responses
        let sync_response: RazorpayV2SyncResponse = res
            .response
            .parse_struct("RazorpayV2SyncResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        with_response_body!(event_builder, sync_response);

        // Extract the payment response from either format
        let payment_response = match sync_response {
            RazorpayV2SyncResponse::PaymentResponse(payment) => {
                tracing::info!("Razorpay PSync: Direct payment response received");
                *payment
            }
            RazorpayV2SyncResponse::OrderPaymentsCollection(collection) => {
                tracing::info!(
                    "Razorpay PSync: Order payments collection received with {} items",
                    collection.count
                );

                // Get the first (and typically only) payment from the collection
                collection.items.into_iter().next().ok_or_else(|| {
                    tracing::error!("Razorpay PSync: Empty payments collection received");
                    errors::ConnectorError::ResponseHandlingFailed
                })?
            }
        };

        // Map Razorpay payment status to internal status, preserving original status
        let status = match payment_response.status.as_str() {
            "created" => AttemptStatus::Pending,
            "authorized" => AttemptStatus::Authorized,
            "captured" => AttemptStatus::Charged, // This is the mapping, but we preserve original in metadata
            "refunded" => AttemptStatus::AutoRefunded,
            "failed" => AttemptStatus::Failure,
            _ => AttemptStatus::Pending,
        };

        let payments_response_data = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(payment_response.id),
            redirection_data: Box::new(None),
            connector_metadata: None,
            mandate_reference: Box::new(None),
            network_txn_id: None,
            connector_response_reference_id: payment_response.order_id,
            incremental_authorization_allowed: None,
            raw_connector_response: Some(String::from_utf8_lossy(&res.response).to_string()),
        };

        Ok(RouterDataV2 {
            response: Ok(payments_response_data),
            resource_common_data: PaymentFlowData {
                status,
                ..data.resource_common_data.clone()
            },
            ..data.clone()
        })
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }

    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl
    ConnectorIntegrationV2<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for Razorpay
{
    fn get_headers(
        &self,
        req: &RouterDataV2<
            CreateOrder,
            PaymentFlowData,
            PaymentCreateOrderData,
            PaymentCreateOrderResponse,
        >,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let mut header = vec![(
            headers::CONTENT_TYPE.to_string(),
            "application/json".to_string().into(),
        )];
        let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
        header.append(&mut api_key);
        Ok(header)
    }

    fn get_url(
        &self,
        req: &RouterDataV2<
            CreateOrder,
            PaymentFlowData,
            PaymentCreateOrderData,
            PaymentCreateOrderResponse,
        >,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(format!(
            "{}v1/orders",
            req.resource_common_data.connectors.razorpay.base_url
        ))
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<
            CreateOrder,
            PaymentFlowData,
            PaymentCreateOrderData,
            PaymentCreateOrderResponse,
        >,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let connector_router_data =
            razorpay::RazorpayRouterData::try_from((req.request.amount, req))?;
        let connector_req = razorpay::RazorpayOrderRequest::try_from(&connector_router_data)?;
        Ok(Some(RequestContent::Json(Box::new(connector_req))))
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<
            CreateOrder,
            PaymentFlowData,
            PaymentCreateOrderData,
            PaymentCreateOrderResponse,
        >,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<
        RouterDataV2<
            CreateOrder,
            PaymentFlowData,
            PaymentCreateOrderData,
            PaymentCreateOrderResponse,
        >,
        errors::ConnectorError,
    > {
        let response: razorpay::RazorpayOrderResponse = res
            .response
            .parse_struct("RazorpayOrderResponse")
            .map_err(|_| errors::ConnectorError::ResponseDeserializationFailed)?;

        with_response_body!(event_builder, response);

        RouterDataV2::foreign_try_from((response, data.clone(), res.status_code, false))
            .change_context(errors::ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }

    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
    for Razorpay
{
    fn get_http_method(&self) -> Method {
        Method::Get
    }

    fn get_headers(
        &self,
        req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError>
    where
        Self: ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
    {
        let mut header = vec![(
            headers::CONTENT_TYPE.to_string(),
            "application/json".to_string().into(),
        )];
        let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
        header.append(&mut api_key);
        Ok(header)
    }

    fn get_url(
        &self,
        req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        let refund_id = req.request.connector_refund_id.clone();
        Ok(format!(
            "{}v1/refunds/{}",
            req.resource_common_data.connectors.razorpay.base_url, refund_id
        ))
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<
        RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        errors::ConnectorError,
    > {
        let response: razorpay::RazorpayRefundResponse = res
            .response
            .parse_struct("RazorpayRefundSyncResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        with_response_body!(event_builder, response);

        RouterDataV2::foreign_try_from((response, data.clone()))
            .change_context(errors::ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }

    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl connector_types::IncomingWebhook for Razorpay {
    fn get_event_type(
        &self,
        request: RequestDetails,
        _connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorAuthType>,
    ) -> Result<EventType, error_stack::Report<errors::ConnectorError>> {
        let payload = transformers::get_webhook_object_from_body(request.body).map_err(|err| {
            report!(errors::ConnectorError::WebhookBodyDecodingFailed)
                .attach_printable(format!("error while decoing webhook body {err}"))
        })?;

        if payload.refund.is_some() {
            Ok(EventType::Refund)
        } else {
            Ok(EventType::Payment)
        }
    }

    fn process_payment_webhook(
        &self,
        request: RequestDetails,
        _connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorAuthType>,
    ) -> Result<WebhookDetailsResponse, error_stack::Report<errors::ConnectorError>> {
        let request_body_copy = request.body.clone();
        let payload = transformers::get_webhook_object_from_body(request.body).map_err(|err| {
            report!(errors::ConnectorError::WebhookBodyDecodingFailed)
                .attach_printable(format!("error while decoing webhook body {err}"))
        })?;

        let notif = payload.payment.ok_or_else(|| {
            error_stack::Report::new(errors::ConnectorError::RequestEncodingFailed)
        })?;

        Ok(WebhookDetailsResponse {
            resource_id: Some(ResponseId::ConnectorTransactionId(notif.entity.order_id)),
            status: transformers::get_razorpay_payment_webhook_status(
                notif.entity.entity,
                notif.entity.status,
            )?,
            connector_response_reference_id: None,
            error_code: notif.entity.error_code,
            error_message: notif.entity.error_reason,
            raw_connector_response: Some(String::from_utf8_lossy(&request_body_copy).to_string()),
        })
    }

    fn process_refund_webhook(
        &self,
        request: RequestDetails,
        _connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorAuthType>,
    ) -> Result<RefundWebhookDetailsResponse, error_stack::Report<errors::ConnectorError>> {
        let request_body_copy = request.body.clone();
        let payload = transformers::get_webhook_object_from_body(request.body).map_err(|err| {
            report!(errors::ConnectorError::WebhookBodyDecodingFailed)
                .attach_printable(format!("error while decoing webhook body {err}"))
        })?;

        let notif = payload.refund.ok_or_else(|| {
            error_stack::Report::new(errors::ConnectorError::RequestEncodingFailed)
        })?;

        Ok(RefundWebhookDetailsResponse {
            connector_refund_id: Some(notif.entity.id),
            status: transformers::get_razorpay_refund_webhook_status(
                notif.entity.entity,
                notif.entity.status,
            )?,
            connector_response_reference_id: None,
            error_code: None,
            error_message: None,
            raw_connector_response: Some(String::from_utf8_lossy(&request_body_copy).to_string()),
        })
    }
}

impl ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
    for Razorpay
{
}

impl ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData> for Razorpay {
    fn get_headers(
        &self,
        req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError>
    where
        Self: ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    {
        let mut header = vec![(
            headers::CONTENT_TYPE.to_string(),
            "application/json".to_string().into(),
        )];
        let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
        header.append(&mut api_key);
        Ok(header)
    }

    fn get_url(
        &self,
        req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        let connector_payment_id = req.request.connector_transaction_id.clone();
        Ok(format!(
            "{}v1/payments/{}/refund",
            req.resource_common_data.connectors.razorpay.base_url, connector_payment_id
        ))
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let refund_router_data =
            razorpay::RazorpayRouterData::try_from((req.request.minor_refund_amount, req))?;
        let connector_req = razorpay::RazorpayRefundRequest::try_from(&refund_router_data)?;

        Ok(Some(RequestContent::Json(Box::new(connector_req))))
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<
        RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        errors::ConnectorError,
    > {
        let response: razorpay::RazorpayRefundResponse = res
            .response
            .parse_struct("RazorpayRefundResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        with_response_body!(event_builder, response);

        RouterDataV2::foreign_try_from((response, data.clone()))
            .change_context(errors::ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }

    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
    for Razorpay
{
    fn get_headers(
        &self,
        req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError>
    where
        Self: ConnectorIntegrationV2<
            Capture,
            PaymentFlowData,
            PaymentsCaptureData,
            PaymentsResponseData,
        >,
    {
        let mut header = vec![(
            headers::CONTENT_TYPE.to_string(),
            "application/json".to_string().into(),
        )];
        let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
        header.append(&mut api_key);
        Ok(header)
    }

    fn get_url(
        &self,
        req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        let id = match &req.request.connector_transaction_id {
            ResponseId::ConnectorTransactionId(id) => id,
            _ => {
                return Err(errors::ConnectorError::MissingConnectorTransactionID.into());
            }
        };
        Ok(format!(
            "{}v1/payments/{}/capture",
            req.resource_common_data.connectors.razorpay.base_url, id
        ))
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let connector_router_data =
            razorpay::RazorpayRouterData::try_from((req.request.minor_amount_to_capture, req))?;
        let connector_req = razorpay::RazorpayCaptureRequest::try_from(&connector_router_data)?;
        Ok(Some(RequestContent::Json(Box::new(connector_req))))
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<
        RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        errors::ConnectorError,
    > {
        let response: razorpay::RazorpayCaptureResponse = res
            .response
            .parse_struct("RazorpayCaptureResponse")
            .map_err(|err| {
                report!(errors::ConnectorError::ResponseDeserializationFailed)
                    .attach_printable(format!("Failed to parse RazorpayCaptureResponse: {err:?}"))
            })?;

        with_response_body!(event_builder, response);

        RouterDataV2::foreign_try_from((response, data.clone()))
            .change_context(errors::ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }

    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl
    ConnectorIntegrationV2<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData,
        PaymentsResponseData,
    > for Razorpay
{
}

impl ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    for Razorpay
{
}

impl
    ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
    for Razorpay
{
}

impl ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
    for Razorpay
{
}

// SourceVerification implementations for all flows
impl
    interfaces::verification::SourceVerification<
        Authorize,
        PaymentFlowData,
        PaymentsAuthorizeData,
        PaymentsResponseData,
    > for Razorpay
{
}

impl
    interfaces::verification::SourceVerification<
        PSync,
        PaymentFlowData,
        PaymentsSyncData,
        PaymentsResponseData,
    > for Razorpay
{
}

impl
    interfaces::verification::SourceVerification<
        Capture,
        PaymentFlowData,
        PaymentsCaptureData,
        PaymentsResponseData,
    > for Razorpay
{
}

impl
    interfaces::verification::SourceVerification<
        Void,
        PaymentFlowData,
        PaymentVoidData,
        PaymentsResponseData,
    > for Razorpay
{
}

impl
    interfaces::verification::SourceVerification<
        Refund,
        RefundFlowData,
        RefundsData,
        RefundsResponseData,
    > for Razorpay
{
}

impl
    interfaces::verification::SourceVerification<
        RSync,
        RefundFlowData,
        RefundSyncData,
        RefundsResponseData,
    > for Razorpay
{
}

impl
    interfaces::verification::SourceVerification<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData,
        PaymentsResponseData,
    > for Razorpay
{
}

impl
    interfaces::verification::SourceVerification<
        Accept,
        DisputeFlowData,
        AcceptDisputeData,
        DisputeResponseData,
    > for Razorpay
{
}

impl
    interfaces::verification::SourceVerification<
        SubmitEvidence,
        DisputeFlowData,
        SubmitEvidenceData,
        DisputeResponseData,
    > for Razorpay
{
}

impl
    interfaces::verification::SourceVerification<
        DefendDispute,
        DisputeFlowData,
        DisputeDefendData,
        DisputeResponseData,
    > for Razorpay
{
}

impl
    interfaces::verification::SourceVerification<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for Razorpay
{
}

impl connector_types::ConnectorValidation for Razorpay {
    fn validate_mandate_payment(
        &self,
        pm_type: Option<PaymentMethodType>,
        pm_data: PaymentMethodData,
    ) -> CustomResult<(), errors::ConnectorError> {
        let mandate_supported_pmd = std::collections::HashSet::from([PaymentMethodDataType::Card]);
        is_mandate_supported(pm_data, pm_type, mandate_supported_pmd, self.id())
    }

    fn validate_psync_reference_id(
        &self,
        data: &PaymentsSyncData,
        _is_three_ds: bool,
        _status: AttemptStatus,
        _connector_meta_data: Option<SecretSerdeValue>,
    ) -> CustomResult<(), errors::ConnectorError> {
        if data.encoded_data.is_some() {
            return Ok(());
        }
        Err(errors::ConnectorError::MissingRequiredField {
            field_name: "encoded_data",
        }
        .into())
    }
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
};

static RAZORPAY_SUPPORTED_WEBHOOK_FLOWS: &[EventClass] =
    &[EventClass::Payments, EventClass::Refunds];

impl ConnectorSpecifications for Razorpay {
    fn get_connector_about(&self) -> Option<&'static ConnectorInfo> {
        Some(&RAZORPAY_CONNECTOR_INFO)
    }

    fn get_supported_webhook_flows(&self) -> Option<&'static [EventClass]> {
        Some(RAZORPAY_SUPPORTED_WEBHOOK_FLOWS)
    }

    fn get_supported_payment_methods(&self) -> Option<&'static SupportedPaymentMethods> {
        Some(&RAZORPAY_SUPPORTED_PAYMENT_METHODS)
    }
}
