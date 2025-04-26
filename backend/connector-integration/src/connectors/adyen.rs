mod test;
pub mod transformers;

use crate::types::ResponseRouterData;
use hyperswitch_common_utils::{
    errors::CustomResult,
    ext_traits::{ByteSliceExt, OptionExt},
    request::RequestContent,
};

use crate::{with_error_response_body, with_response_body};

use hyperswitch_common_utils::types::MinorUnit;

use hyperswitch_domain_models::{
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_request_types::SyncRequestType,
};

use error_stack::{report, ResultExt};
use hyperswitch_interfaces::errors::ConnectorError;
use hyperswitch_interfaces::{
    api::{self, CaptureSyncMethod, ConnectorCommon},
    configs::Connectors,
    connector_integration_v2::ConnectorIntegrationV2,
    errors,
    events::connector_api_logs::ConnectorEvent,
    types::Response,
};
use hyperswitch_masking::{Mask, Maskable};

use super::macros;
use domain_types::{
    connector_flow::{AcceptDispute, Authorize, Capture, CreateOrder, PSync, RSync, Refund, SetupMandate, Void},
    connector_types::{
        AcceptDisputeData, AcceptDisputeV2, ConnectorServiceTrait, ConnectorWebhookSecrets,
        DisputeFlowData, DisputeResponseData, IncomingWebhook, PaymentAuthorizeV2, PaymentCapture,
        PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData, PaymentOrderCreate,
        PaymentSyncV2, PaymentVoidData, PaymentVoidV2, PaymentsAuthorizeData, PaymentsCaptureData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundSyncData, RefundSyncV2,
        RefundV2, RefundWebhookDetailsResponse, RefundsData, RefundsResponseData, RequestDetails, ResponseId, SetupMandateRequestData, SetupMandateV2,
       
        ValidationTrait, WebhookDetailsResponse,
    },
};
use transformers::{
    self as adyen, AdyenNotificationRequestItemWH, AdyenPaymentRequest, AdyenPaymentResponse,
    ForeignTryFrom,
};

pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const X_API_KEY: &str = "X-Api-Key";
}

impl ConnectorServiceTrait for Adyen {}
impl PaymentAuthorizeV2 for Adyen {}
impl PaymentSyncV2 for Adyen {}
impl PaymentVoidV2 for Adyen {}
impl RefundSyncV2 for Adyen {}
impl RefundV2 for Adyen {}
impl PaymentCapture for Adyen {}
impl SetupMandateV2 for Adyen {}
impl AcceptDisputeV2 for Adyen {}

macros::create_all_prerequisites!(
    connector_name: Adyen,
    api: [
        (
            flow: Authorize,
            request_body: AdyenPaymentRequest,
            response_body: AdyenPaymentResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>
        )
    ],
    amount_converters: [],
    member_functions: {
        pub fn build_headers(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
            let mut header = vec![(
                headers::CONTENT_TYPE.to_string(),
                "application/json".to_string().into(),
            )];
            let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
            header.append(&mut api_key);
            Ok(header)
        }
        pub fn connector_base_url<'a>(
            &self,
            req: &'a RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        ) -> &'a str {
            &req.resource_common_data.connectors.adyen.base_url
        }
    }
);

impl ConnectorCommon for Adyen {
    fn id(&self) -> &'static str {
        "adyen"
    }
    fn get_currency_unit(&self) -> api::CurrencyUnit {
        api::CurrencyUnit::Minor
    }
    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth = adyen::AdyenAuthType::try_from(auth_type)
            .map_err(|_| errors::ConnectorError::FailedToObtainAuthType)?;
        Ok(vec![(
            headers::X_API_KEY.to_string(),
            auth.api_key.into_masked(),
        )])
    }
    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.adyen.base_url.as_ref()
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: adyen::AdyenErrorResponse = res
            .response
            .parse_struct("ErrorResponse")
            .map_err(|_| errors::ConnectorError::ResponseDeserializationFailed)?;

        with_error_response_body!(event_builder, response);

        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response.error_code,
            message: response.message.to_owned(),
            reason: Some(response.message),
            attempt_status: None,
            connector_transaction_id: response.psp_reference,
        })
    }
}

impl TryFrom<ResponseRouterData<PaymentsResponseData, Self>>
    for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        value: ResponseRouterData<PaymentsResponseData, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code: _,
        } = value;

        Ok(Self {
            response: Ok(response),
            ..router_data
        })
    }
}

const ADYEN_API_VERSION: &str = "v68";

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Adyen,
    curl_request: Json(AdyenPaymentRequest),
    curl_response: AdyenPaymentResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            Ok(format!("{}{}/payments", self.connector_base_url(req), ADYEN_API_VERSION))
        }
    }
);

impl ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    for Adyen
{
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
        _req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(format!(
            "{}{}/payments/details",
            "https://checkout-test.adyen.com/", ADYEN_API_VERSION
        ))
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let encoded_data = req
            .request
            .encoded_data
            .clone()
            .get_required_value("encoded_data")
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;
        let adyen_redirection_type = serde_urlencoded::from_str::<
            transformers::AdyenRedirectRequestTypes,
        >(encoded_data.as_str())
        .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        let connector_req = match adyen_redirection_type {
            adyen::AdyenRedirectRequestTypes::AdyenRedirection(req) => {
                adyen::AdyenRedirectRequest {
                    details: adyen::AdyenRedirectRequestTypes::AdyenRedirection(
                        adyen::AdyenRedirection {
                            redirect_result: req.redirect_result,
                            type_of_redirection_result: None,
                            result_code: None,
                        },
                    ),
                }
            }
            adyen::AdyenRedirectRequestTypes::AdyenThreeDS(req) => adyen::AdyenRedirectRequest {
                details: adyen::AdyenRedirectRequestTypes::AdyenThreeDS(adyen::AdyenThreeDS {
                    three_ds_result: req.three_ds_result,
                    type_of_redirection_result: None,
                    result_code: None,
                }),
            },
            adyen::AdyenRedirectRequestTypes::AdyenRefusal(req) => adyen::AdyenRedirectRequest {
                details: adyen::AdyenRedirectRequestTypes::AdyenRefusal(adyen::AdyenRefusal {
                    payload: req.payload,
                    type_of_redirection_result: None,
                    result_code: None,
                }),
            },
        };

        Ok(Some(RequestContent::Json(Box::new(connector_req))))
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
        let response: adyen::AdyenPaymentResponse = res
            .response
            .parse_struct("AdyenPaymentResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        with_response_body!(event_builder, response);

        let is_multiple_capture_sync = match data.request.sync_type {
            SyncRequestType::MultipleCaptureSync(_) => true,
            SyncRequestType::SinglePaymentSync => false,
        };
        RouterDataV2::foreign_try_from((
            response,
            data.clone(),
            res.status_code,
            data.request.capture_method,
            is_multiple_capture_sync,
            data.request.payment_method_type,
        ))
        .change_context(errors::ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }

    fn get_multiple_capture_sync_method(
        &self,
    ) -> CustomResult<CaptureSyncMethod, errors::ConnectorError> {
        Ok(CaptureSyncMethod::Individual)
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
    for Adyen
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
            "{}{}/payments/{}/captures",
            req.resource_common_data.connectors.adyen.base_url, ADYEN_API_VERSION, id
        ))
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let connector_router_data =
            adyen::AdyenRouterData1::try_from((req.request.minor_amount_to_capture, req))?;
        let connector_req = adyen::AdyenCaptureRequest::try_from(&connector_router_data)?;
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
        let response: adyen::AdyenCaptureResponse = res
            .response
            .parse_struct("AdyenCaptureResponse")
            .map_err(|err| {
                report!(errors::ConnectorError::ResponseDeserializationFailed)
                    .attach_printable(format!("Failed to parse AdyenCaptureResponse: {err:?}"))
            })?;

        with_response_body!(event_builder, response);

        let is_multi_capture = data.request.multiple_capture_data.is_some();

        RouterDataV2::foreign_try_from((response, data.clone(), is_multi_capture))
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

impl ValidationTrait for Adyen {}

impl PaymentOrderCreate for Adyen {}

impl
    ConnectorIntegrationV2<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for Adyen
{
}

impl ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
    for Adyen
{
    fn get_headers(
        &self,
        req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError>
    where
        Self: ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
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
        req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        let id = req.request.connector_transaction_id.clone();
        let endpoint = req.resource_common_data.connectors.adyen.base_url.clone();
        Ok(format!(
            "{}{}/payments/{}/cancels",
            endpoint, ADYEN_API_VERSION, id
        ))
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let connector_req = adyen::AdyenVoidRequest::try_from(req)?;
        Ok(Some(RequestContent::Json(Box::new(connector_req))))
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<
        RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        errors::ConnectorError,
    > {
        let response: adyen::AdyenVoidResponse =
            res.response
                .parse_struct("AdyenCancelResponse")
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
}

impl ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData> for Adyen {}

impl IncomingWebhook for Adyen {
    fn get_event_type(
        &self,
        request: RequestDetails,
        _connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorAuthType>,
    ) -> Result<domain_types::connector_types::EventType, error_stack::Report<errors::ConnectorError>>
    {
        let notif: AdyenNotificationRequestItemWH =
            transformers::get_webhook_object_from_body(request.body).map_err(|err| {
                report!(errors::ConnectorError::WebhookBodyDecodingFailed)
                    .attach_printable(format!("error while decoing webhook body {err}"))
            })?;
        Ok(transformers::get_adyen_webhook_event_type(notif.event_code))
    }

    fn process_payment_webhook(
        &self,
        request: RequestDetails,
        _connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorAuthType>,
    ) -> Result<WebhookDetailsResponse, error_stack::Report<errors::ConnectorError>> {
        let notif: AdyenNotificationRequestItemWH =
            transformers::get_webhook_object_from_body(request.body).map_err(|err| {
                report!(errors::ConnectorError::WebhookBodyDecodingFailed)
                    .attach_printable(format!("error while decoing webhook body {err}"))
            })?;
        Ok(WebhookDetailsResponse {
            resource_id: Some(ResponseId::ConnectorTransactionId(
                notif.psp_reference.clone(),
            )),
            status: transformers::get_adyen_payment_webhook_event(notif.event_code, notif.success)?,
            connector_response_reference_id: Some(notif.psp_reference),
            error_code: notif.reason.clone(),
            error_message: notif.reason,
        })
    }

    fn process_refund_webhook(
        &self,
        request: RequestDetails,
        _connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorAuthType>,
    ) -> Result<
        domain_types::connector_types::RefundWebhookDetailsResponse,
        error_stack::Report<errors::ConnectorError>,
    > {
        let notif: AdyenNotificationRequestItemWH =
            transformers::get_webhook_object_from_body(request.body).map_err(|err| {
                report!(errors::ConnectorError::WebhookBodyDecodingFailed)
                    .attach_printable(format!("error while decoing webhook body {err}"))
            })?;

        Ok(RefundWebhookDetailsResponse {
            connector_refund_id: Some(notif.psp_reference.clone()),
            status: transformers::get_adyen_refund_webhook_event(notif.event_code, notif.success)?,
            connector_response_reference_id: Some(notif.psp_reference.clone()),
            error_code: notif.reason.clone(),
            error_message: notif.reason,
        })
    }
}

impl ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData> for Adyen {
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
            "{}{}/payments/{}/refunds",
            req.resource_common_data.connectors.adyen.base_url,
            ADYEN_API_VERSION,
            connector_payment_id
        ))
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let refund_router_data =
            adyen::AdyenRouterData1::try_from((req.request.minor_refund_amount, req))?;
        let connector_req = adyen::AdyenRefundRequest::try_from(&refund_router_data)?;

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
        let response: adyen::AdyenRefundResponse = res
            .response
            .parse_struct("AdyenRefundResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        with_response_body!(event_builder, response);

        RouterDataV2::foreign_try_from((response, data.clone(), res.status_code))
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
    > for Adyen
{
    fn get_headers(
        &self,
        req: &RouterDataV2<
            SetupMandate,
            PaymentFlowData,
            SetupMandateRequestData,
            PaymentsResponseData,
        >,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError>
    where
        Self: ConnectorIntegrationV2<
            SetupMandate,
            PaymentFlowData,
            SetupMandateRequestData,
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
        req: &RouterDataV2<
            SetupMandate,
            PaymentFlowData,
            SetupMandateRequestData,
            PaymentsResponseData,
        >,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(format!(
            "{}{}/payments",
            req.resource_common_data.connectors.adyen.base_url, ADYEN_API_VERSION
        ))
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<
            SetupMandate,
            PaymentFlowData,
            SetupMandateRequestData,
            PaymentsResponseData,
        >,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let connector_router_data = adyen::AdyenRouterData1::try_from((
            req.request
                .minor_amount
                .unwrap_or_else(|| MinorUnit::new(0)),
            req,
        ))?;
        let connector_req = adyen::AdyenPaymentRequest::try_from(&connector_router_data)?;
        Ok(Some(RequestContent::Json(Box::new(connector_req))))
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<
            SetupMandate,
            PaymentFlowData,
            SetupMandateRequestData,
            PaymentsResponseData,
        >,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<
        RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData>,
        errors::ConnectorError,
    > {
        let response: adyen::AdyenPaymentResponse = res
            .response
            .parse_struct("AdyenPaymentResponse")
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

impl ConnectorIntegrationV2<AcceptDispute, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    for Adyen
{
    fn get_headers(
        &self,
        req: &RouterDataV2<AcceptDispute, DisputeFlowData, AcceptDisputeData, DisputeResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError>
    where
        Self: ConnectorIntegrationV2<
            AcceptDispute,
            DisputeFlowData,
            AcceptDisputeData,
            DisputeResponseData,
        >,
    {
        let mut headers = vec![(
            headers::CONTENT_TYPE.to_string(),
            "application/json".to_string().into(),
        )];

        let mut auth_header = self.get_auth_header(&req.connector_auth_type)?;
        headers.append(&mut auth_header);
        Ok(headers)
    }

    fn get_url(
        &self,
        req: &RouterDataV2<AcceptDispute, DisputeFlowData, AcceptDisputeData, DisputeResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        let _connector_dispute_id = req.request.connector_dispute_id.clone();
        Ok("https://ca-test.adyen.com/ca/services/DisputeService/v30/acceptDispute".to_string())
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<AcceptDispute, DisputeFlowData, AcceptDisputeData, DisputeResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let adyen_req = adyen::AdyenDisputeAcceptRequest::try_from(req)?;

        Ok(Some(RequestContent::Json(Box::new(adyen_req))))
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<AcceptDispute, DisputeFlowData, AcceptDisputeData, DisputeResponseData>,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<
        RouterDataV2<AcceptDispute, DisputeFlowData, AcceptDisputeData, DisputeResponseData>,
        errors::ConnectorError,
    > {
        let response: adyen::AdyenDisputeAcceptResponse = res
            .response
            .parse_struct("AdyenDisputeAcceptResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        with_response_body!(event_builder, response);

        RouterDataV2::foreign_try_from((response, data.clone(), res.status_code))
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
