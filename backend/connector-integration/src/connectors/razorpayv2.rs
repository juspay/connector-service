pub mod test;
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
        Accept, Authorize, Capture, CreateOrder, DefendDispute, PSync, RSync, Refund, SetupMandate,
        SubmitEvidence, Void,
    },
    connector_types::{
        AcceptDisputeData, DisputeDefendData, DisputeFlowData, DisputeResponseData,
        PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData, PaymentVoidData,
        PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData, PaymentsSyncData,
        RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData, ResponseId,
        SetupMandateRequestData, SubmitEvidenceData,
    },
    errors,
    router_response_types::Response,
    types::Connectors,
};
use error_stack::ResultExt;
use hyperswitch_masking::Maskable;
use interfaces::{
    api::ConnectorCommon, connector_integration_v2::ConnectorIntegrationV2,
    events::connector_api_logs::ConnectorEvent,
};
use tracing::info;
use transformers as razorpayv2;

pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const AUTHORIZATION: &str = "Authorization";
}

#[derive(Clone)]
pub struct RazorpayV2 {
    #[allow(dead_code)]
    pub(crate) amount_converter: &'static (dyn AmountConvertor<Output = MinorUnit> + Sync),
}

impl RazorpayV2 {
    pub const fn new() -> &'static Self {
        &Self {
            amount_converter: &common_utils::types::MinorUnitForConnector,
        }
    }
}

impl interfaces::connector_types::ValidationTrait for RazorpayV2 {
    fn should_do_order_create(&self) -> bool {
        true
    }
}

impl ConnectorCommon for RazorpayV2 {
    fn id(&self) -> &'static str {
        "razorpayv2"
    }

    fn get_currency_unit(&self) -> common_enums::CurrencyUnit {
        common_enums::CurrencyUnit::Base
    }

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
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        &connectors.razorpayv2.base_url
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        let response: razorpayv2::RazorpayV2ErrorResponse = res
            .response
            .parse_struct("RazorpayV2ErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        if let Some(i) = event_builder {
            i.set_error_response_body(&response)
        }

        let (code, message, attempt_status) = match response {
            razorpayv2::RazorpayV2ErrorResponse::StandardError { error } => {
                let attempt_status = match error.code.as_str() {
                    "BAD_REQUEST_ERROR" => AttemptStatus::Failure,
                    "GATEWAY_ERROR" => AttemptStatus::Failure,
                    "AUTHENTICATION_ERROR" => AttemptStatus::AuthenticationFailed,
                    "AUTHORIZATION_ERROR" => AttemptStatus::AuthorizationFailed,
                    "SERVER_ERROR" => AttemptStatus::Pending,
                    _ => AttemptStatus::Failure,
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
            }
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
            raw_connector_response: Some(String::from_utf8_lossy(&res.response).to_string()),
        })
    }
}

impl
    ConnectorIntegrationV2<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for RazorpayV2
{
    fn get_headers(
        &self,
        req: &domain_types::router_data_v2::RouterDataV2<
            CreateOrder,
            PaymentFlowData,
            PaymentCreateOrderData,
            PaymentCreateOrderResponse,
        >,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let mut headers = vec![(
            headers::CONTENT_TYPE.to_string(),
            "application/json".to_string().into(),
        )];
        let mut auth_headers = self.get_auth_header(&req.connector_auth_type)?;
        headers.append(&mut auth_headers);
        Ok(headers)
    }

    fn get_url(
        &self,
        req: &domain_types::router_data_v2::RouterDataV2<
            CreateOrder,
            PaymentFlowData,
            PaymentCreateOrderData,
            PaymentCreateOrderResponse,
        >,
    ) -> CustomResult<String, errors::ConnectorError> {
        let base_url = &req.resource_common_data.connectors.razorpayv2.base_url;
        Ok(format!("{base_url}v1/orders"))
    }

    fn get_request_body(
        &self,
        req: &domain_types::router_data_v2::RouterDataV2<
            CreateOrder,
            PaymentFlowData,
            PaymentCreateOrderData,
            PaymentCreateOrderResponse,
        >,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let connector_router_data =
            razorpayv2::RazorpayV2RouterData::try_from((req.request.amount, &req.request, None))?;
        let connector_req =
            razorpayv2::RazorpayV2CreateOrderRequest::try_from(&connector_router_data)?;
        Ok(Some(RequestContent::Json(Box::new(connector_req))))
    }

    fn handle_response_v2(
        &self,
        data: &domain_types::router_data_v2::RouterDataV2<
            CreateOrder,
            PaymentFlowData,
            PaymentCreateOrderData,
            PaymentCreateOrderResponse,
        >,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<
        domain_types::router_data_v2::RouterDataV2<
            CreateOrder,
            PaymentFlowData,
            PaymentCreateOrderData,
            PaymentCreateOrderResponse,
        >,
        errors::ConnectorError,
    > {
        let response: razorpayv2::RazorpayV2CreateOrderResponse = res
            .response
            .parse_struct("RazorpayV2CreateOrderResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        if let Some(i) = event_builder {
            i.set_response_body(&response)
        }

        let order_response = PaymentCreateOrderResponse {
            order_id: response.id,
        };

        Ok(domain_types::router_data_v2::RouterDataV2 {
            response: Ok(order_response),
            ..data.clone()
        })
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }

    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        let response: razorpayv2::RazorpayV2ErrorResponse = res
            .response
            .parse_struct("RazorpayV2ErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        if let Some(i) = event_builder {
            i.set_error_response_body(&response)
        }

        let (code, message) = match response {
            razorpayv2::RazorpayV2ErrorResponse::StandardError { error } => {
                (error.code, error.description.clone())
            }
            razorpayv2::RazorpayV2ErrorResponse::SimpleError { message } => {
                ("ROUTE_ERROR".to_string(), message.clone())
            }
        };

        Ok(domain_types::router_data::ErrorResponse {
            code,
            message: message.clone(),
            reason: Some(message),
            status_code: res.status_code,
            attempt_status: Some(AttemptStatus::Pending),
            connector_transaction_id: None,
            network_decline_code: None,
            network_advice_code: None,
            network_error_message: None,
            raw_connector_response: Some(String::from_utf8_lossy(&res.response).to_string()),
        })
    }
}

impl ConnectorIntegrationV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>
    for RazorpayV2
{
    fn get_headers(
        &self,
        req: &domain_types::router_data_v2::RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData,
            PaymentsResponseData,
        >,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let mut headers = vec![(
            headers::CONTENT_TYPE.to_string(),
            "application/json".to_string().into(),
        )];
        let mut auth_headers = self.get_auth_header(&req.connector_auth_type)?;
        headers.append(&mut auth_headers);
        Ok(headers)
    }

    fn get_url(
        &self,
        req: &domain_types::router_data_v2::RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData,
            PaymentsResponseData,
        >,
    ) -> CustomResult<String, errors::ConnectorError> {
        let base_url = &req.resource_common_data.connectors.razorpayv2.base_url;

        // For UPI payments, use the specific UPI endpoint
        use domain_types::payment_method_data::PaymentMethodData;
        match &req.request.payment_method_data {
            PaymentMethodData::Upi(_) => Ok(format!("{base_url}v1/payments/create/upi")),
            _ => Ok(format!("{base_url}v1/payments")),
        }
    }

    fn get_request_body(
        &self,
        req: &domain_types::router_data_v2::RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData,
            PaymentsResponseData,
        >,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let order_id = req
            .resource_common_data
            .reference_id
            .as_ref()
            .ok_or_else(|| errors::ConnectorError::MissingRequiredField {
                field_name: "reference_id",
            })?
            .clone();

        let connector_router_data = razorpayv2::RazorpayV2RouterData::try_from((
            req.request.minor_amount,
            &req.request,
            Some(order_id),
            req.resource_common_data
                .address
                .get_payment_method_billing()
                .cloned(),
        ))?;
        info!("Metadaata is {:?}", req.request.metadata);
        // Always use v2 request format
        let connector_req =
            razorpayv2::RazorpayV2PaymentsRequest::try_from(&connector_router_data)?;
        Ok(Some(RequestContent::Json(Box::new(connector_req))))
    }

    fn handle_response_v2(
        &self,
        data: &domain_types::router_data_v2::RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData,
            PaymentsResponseData,
        >,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<
        domain_types::router_data_v2::RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData,
            PaymentsResponseData,
        >,
        errors::ConnectorError,
    > {
        // Try to parse as UPI response first
        let upi_response_result = res
            .response
            .parse_struct::<razorpayv2::RazorpayV2UpiPaymentsResponse>(
                "RazorpayV2UpiPaymentsResponse",
            );

        let (transaction_id, redirection_data) = match upi_response_result {
            Ok(upi_response) => {
                if let Some(i) = event_builder {
                    i.set_response_body(&upi_response)
                }

                match upi_response {
                    razorpayv2::RazorpayV2UpiPaymentsResponse::SuccessIntent {
                        razorpay_payment_id,
                        link,
                    } => {
                        let redirect_form =
                            domain_types::router_response_types::RedirectForm::Uri { uri: link };
                        (
                            ResponseId::ConnectorTransactionId(razorpay_payment_id),
                            Some(redirect_form),
                        )
                    }
                    razorpayv2::RazorpayV2UpiPaymentsResponse::SuccessCollect {
                        razorpay_payment_id,
                    } => {
                        // For UPI Collect, there's no link, so no redirection data
                        (
                            ResponseId::ConnectorTransactionId(razorpay_payment_id),
                            None,
                        )
                    }
                    razorpayv2::RazorpayV2UpiPaymentsResponse::Error { error: _ } => {
                        // Handle error case - this should probably return an error instead
                        return Err(errors::ConnectorError::ResponseHandlingFailed.into());
                    }
                }
            }
            Err(_) => {
                // Fall back to regular payment response
                let response: razorpayv2::RazorpayV2PaymentsResponse = res
                    .response
                    .parse_struct("RazorpayV2PaymentsResponse")
                    .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

                if let Some(i) = event_builder {
                    i.set_response_body(&response)
                }
                (ResponseId::ConnectorTransactionId(response.id), None)
            }
        };

        // Debug logging to trace reference_id
        let reference_id = data.resource_common_data.reference_id.clone();
        info!(
            "RazorpayV2 Authorization Response - reference_id: {:?}",
            reference_id
        );

        let payments_response_data = PaymentsResponseData::TransactionResponse {
            resource_id: transaction_id,
            redirection_data: Box::new(redirection_data),
            connector_metadata: None,
            mandate_reference: Box::new(None),
            network_txn_id: None,
            connector_response_reference_id: reference_id,
            incremental_authorization_allowed: None,
            raw_connector_response: Some(String::from_utf8_lossy(&res.response).to_string()),
        };

        Ok(domain_types::router_data_v2::RouterDataV2 {
            response: Ok(payments_response_data),
            ..data.clone()
        })
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }

    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

// Implement required traits for ConnectorServiceTrait
impl interfaces::connector_types::PaymentAuthorizeV2 for RazorpayV2 {}
impl interfaces::connector_types::PaymentSyncV2 for RazorpayV2 {}
impl interfaces::connector_types::PaymentOrderCreate for RazorpayV2 {}
impl interfaces::connector_types::PaymentVoidV2 for RazorpayV2 {}
impl interfaces::connector_types::IncomingWebhook for RazorpayV2 {}
impl interfaces::connector_types::RefundV2 for RazorpayV2 {}
impl interfaces::connector_types::PaymentCapture for RazorpayV2 {}
impl interfaces::connector_types::SetupMandateV2 for RazorpayV2 {}
impl interfaces::connector_types::AcceptDispute for RazorpayV2 {}
impl interfaces::connector_types::RefundSyncV2 for RazorpayV2 {}
impl interfaces::connector_types::DisputeDefend for RazorpayV2 {}
impl interfaces::connector_types::SubmitEvidenceV2 for RazorpayV2 {}
impl interfaces::connector_types::ConnectorServiceTrait for RazorpayV2 {}

// Stub implementations for flows not yet implemented
impl ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
    for RazorpayV2
{
}

impl ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
    for RazorpayV2
{
}

impl ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    for RazorpayV2
{
    fn get_http_method(&self) -> common_utils::Method {
        common_utils::Method::Get
    }
    fn get_headers(
        &self,
        req: &domain_types::router_data_v2::RouterDataV2<
            PSync,
            PaymentFlowData,
            PaymentsSyncData,
            PaymentsResponseData,
        >,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let mut headers = vec![(
            headers::CONTENT_TYPE.to_string(),
            "application/json".to_string().into(),
        )];
        let mut auth_headers = self.get_auth_header(&req.connector_auth_type)?;
        headers.append(&mut auth_headers);
        Ok(headers)
    }

    fn get_url(
        &self,
        req: &domain_types::router_data_v2::RouterDataV2<
            PSync,
            PaymentFlowData,
            PaymentsSyncData,
            PaymentsResponseData,
        >,
    ) -> CustomResult<String, errors::ConnectorError> {
        let base_url = &req.resource_common_data.connectors.razorpayv2.base_url;

        // Check if request_ref_id is provided to determine URL pattern
        let request_ref_id = &req.resource_common_data.connector_request_reference_id;

        if !request_ref_id.is_empty() {
            // Use orders endpoint when request_ref_id is provided
            let url = format!("{base_url}v1/orders/{request_ref_id}/payments");
            tracing::info!("RazorpayV2 PSync URL (orders endpoint): {}", url);
            Ok(url)
        } else {
            // Extract payment ID from connector_transaction_id for standard payment sync
            let payment_id = match &req.request.connector_transaction_id {
                ResponseId::ConnectorTransactionId(id) => {
                    tracing::info!(
                        "RazorpayV2 PSync payment_id from ConnectorTransactionId: {}",
                        id
                    );
                    id
                }
                ResponseId::EncodedData(data) => {
                    tracing::info!("RazorpayV2 PSync payment_id from EncodedData: {}", data);
                    data
                }
                ResponseId::NoResponseId => {
                    tracing::error!("RazorpayV2 PSync: No payment ID provided");
                    return Err(errors::ConnectorError::MissingRequiredField {
                        field_name: "connector_transaction_id",
                    }
                    .into());
                }
            };

            let url = format!("{base_url}v1/payments/{payment_id}");
            tracing::info!("RazorpayV2 PSync URL (payments endpoint): {}", url);
            Ok(url)
        }
    }

    fn get_request_body(
        &self,
        _req: &domain_types::router_data_v2::RouterDataV2<
            PSync,
            PaymentFlowData,
            PaymentsSyncData,
            PaymentsResponseData,
        >,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        // GET request doesn't need a body
        Ok(None)
    }

    fn handle_response_v2(
        &self,
        data: &domain_types::router_data_v2::RouterDataV2<
            PSync,
            PaymentFlowData,
            PaymentsSyncData,
            PaymentsResponseData,
        >,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<
        domain_types::router_data_v2::RouterDataV2<
            PSync,
            PaymentFlowData,
            PaymentsSyncData,
            PaymentsResponseData,
        >,
        errors::ConnectorError,
    > {
        // Parse the response using the enum that handles both collection and direct payment responses
        let sync_response: razorpayv2::RazorpayV2SyncResponse = res
            .response
            .parse_struct("RazorpayV2SyncResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        if let Some(i) = event_builder {
            i.set_response_body(&sync_response)
        }

        // Extract the payment response from either format
        let payment_response = match sync_response {
            razorpayv2::RazorpayV2SyncResponse::PaymentResponse(payment) => {
                tracing::info!("RazorpayV2 PSync: Direct payment response received");
                *payment
            }
            razorpayv2::RazorpayV2SyncResponse::OrderPaymentsCollection(collection) => {
                tracing::info!(
                    "RazorpayV2 PSync: Order payments collection received with {} items",
                    collection.count
                );

                // Get the first (and typically only) payment from the collection
                collection.items.into_iter().next().ok_or_else(|| {
                    tracing::error!("RazorpayV2 PSync: Empty payments collection received");
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

        Ok(domain_types::router_data_v2::RouterDataV2 {
            response: Ok(payments_response_data),
            resource_common_data: domain_types::connector_types::PaymentFlowData {
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
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }

    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl
    ConnectorIntegrationV2<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData,
        PaymentsResponseData,
    > for RazorpayV2
{
}

impl ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
    for RazorpayV2
{
    fn get_http_method(&self) -> common_utils::Method {
        common_utils::Method::Get
    }

    fn get_headers(
        &self,
        req: &domain_types::router_data_v2::RouterDataV2<
            RSync,
            RefundFlowData,
            RefundSyncData,
            RefundsResponseData,
        >,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let mut headers = vec![(
            headers::CONTENT_TYPE.to_string(),
            "application/json".to_string().into(),
        )];
        let mut auth_headers = self.get_auth_header(&req.connector_auth_type)?;
        headers.append(&mut auth_headers);
        Ok(headers)
    }

    fn get_url(
        &self,
        req: &domain_types::router_data_v2::RouterDataV2<
            RSync,
            RefundFlowData,
            RefundSyncData,
            RefundsResponseData,
        >,
    ) -> CustomResult<String, errors::ConnectorError> {
        let base_url = &req.resource_common_data.connectors.razorpayv2.base_url;

        // Extract refund ID from connector_refund_id
        let refund_id = &req.request.connector_refund_id;

        Ok(format!("{base_url}v1/refunds/{refund_id}"))
    }

    fn get_request_body(
        &self,
        _req: &domain_types::router_data_v2::RouterDataV2<
            RSync,
            RefundFlowData,
            RefundSyncData,
            RefundsResponseData,
        >,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        // GET request doesn't need a body
        Ok(None)
    }

    fn handle_response_v2(
        &self,
        data: &domain_types::router_data_v2::RouterDataV2<
            RSync,
            RefundFlowData,
            RefundSyncData,
            RefundsResponseData,
        >,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<
        domain_types::router_data_v2::RouterDataV2<
            RSync,
            RefundFlowData,
            RefundSyncData,
            RefundsResponseData,
        >,
        errors::ConnectorError,
    > {
        let response: razorpayv2::RazorpayV2RefundResponse = res
            .response
            .parse_struct("RazorpayV2RefundResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        if let Some(i) = event_builder {
            i.set_response_body(&response)
        }

        // Map Razorpay refund status to internal status
        use common_enums::RefundStatus;
        let status = match response.status.as_str() {
            "processed" => RefundStatus::Success,
            "pending" | "created" => RefundStatus::Pending,
            "failed" => RefundStatus::Failure,
            _ => RefundStatus::Pending,
        };

        let refunds_response_data = RefundsResponseData {
            connector_refund_id: response.id,
            refund_status: status,
            raw_connector_response: Some(String::from_utf8_lossy(&res.response).to_string()),
        };

        Ok(domain_types::router_data_v2::RouterDataV2 {
            response: Ok(refunds_response_data),
            resource_common_data: RefundFlowData {
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
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }

    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
    for RazorpayV2
{
    fn get_headers(
        &self,
        req: &domain_types::router_data_v2::RouterDataV2<
            Refund,
            RefundFlowData,
            RefundsData,
            RefundsResponseData,
        >,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let mut headers = vec![(
            headers::CONTENT_TYPE.to_string(),
            "application/json".to_string().into(),
        )];
        let mut auth_headers = self.get_auth_header(&req.connector_auth_type)?;
        headers.append(&mut auth_headers);
        Ok(headers)
    }

    fn get_url(
        &self,
        req: &domain_types::router_data_v2::RouterDataV2<
            Refund,
            RefundFlowData,
            RefundsData,
            RefundsResponseData,
        >,
    ) -> CustomResult<String, errors::ConnectorError> {
        let base_url = &req.resource_common_data.connectors.razorpayv2.base_url;

        // Extract payment ID from connector_transaction_id
        let payment_id = &req.request.connector_transaction_id;

        Ok(format!("{base_url}v1/payments/{payment_id}/refund"))
    }

    fn get_request_body(
        &self,
        req: &domain_types::router_data_v2::RouterDataV2<
            Refund,
            RefundFlowData,
            RefundsData,
            RefundsResponseData,
        >,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let connector_router_data = razorpayv2::RazorpayV2RouterData::try_from((
            req.request.minor_refund_amount,
            &req.request,
            None,
        ))?;
        let connector_req = razorpayv2::RazorpayV2RefundRequest::try_from(&connector_router_data)?;
        Ok(Some(RequestContent::Json(Box::new(connector_req))))
    }

    fn handle_response_v2(
        &self,
        data: &domain_types::router_data_v2::RouterDataV2<
            Refund,
            RefundFlowData,
            RefundsData,
            RefundsResponseData,
        >,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<
        domain_types::router_data_v2::RouterDataV2<
            Refund,
            RefundFlowData,
            RefundsData,
            RefundsResponseData,
        >,
        errors::ConnectorError,
    > {
        let response: razorpayv2::RazorpayV2RefundResponse = res
            .response
            .parse_struct("RazorpayV2RefundResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        if let Some(i) = event_builder {
            i.set_response_body(&response)
        }

        // Map Razorpay refund status to internal status
        use common_enums::RefundStatus;
        let status = match response.status.as_str() {
            "processed" => RefundStatus::Success,
            "pending" | "created" => RefundStatus::Pending,
            "failed" => RefundStatus::Failure,
            _ => RefundStatus::Pending,
        };

        let refunds_response_data = RefundsResponseData {
            connector_refund_id: response.id,
            refund_status: status,
            raw_connector_response: Some(String::from_utf8_lossy(&res.response).to_string()),
        };

        Ok(domain_types::router_data_v2::RouterDataV2 {
            response: Ok(refunds_response_data),
            resource_common_data: RefundFlowData {
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
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }

    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    for RazorpayV2
{
}

impl ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
    for RazorpayV2
{
}

impl
    ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
    for RazorpayV2
{
}
