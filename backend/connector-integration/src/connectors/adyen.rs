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
    connector_flow::{Accept, Authorize, Capture, CreateOrder, PSync, RSync, Refund, SetupMandate, Void},
    connector_types::{
        AcceptDispute, AcceptDisputeData, ConnectorServiceTrait, ConnectorWebhookSecrets,
        DisputeFlowData, DisputeResponseData, IncomingWebhook, PaymentAuthorizeV2, PaymentCapture,
        PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData, PaymentOrderCreate,
        PaymentSyncV2, PaymentVoidData, PaymentVoidV2, PaymentsAuthorizeData, PaymentsCaptureData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundSyncData, RefundSyncV2,
        RefundV2, RefundWebhookDetailsResponse, RefundsData, RefundsResponseData, RequestDetails,
        ResponseId, SetupMandateRequestData, SetupMandateV2,
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
impl AcceptDispute for Adyen {}

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
    TryFrom<(
        &AdyenRouterData1<
            &RouterDataV2<
                SetupMandate,
                PaymentFlowData,
                SetupMandateRequestData,
                PaymentsResponseData,
            >,
        >,
        &Card,
    )> for AdyenPaymentRequest
{
    type Error = Error;
    fn try_from(
        value: (
            &AdyenRouterData1<
                &RouterDataV2<
                    SetupMandate,
                    PaymentFlowData,
                    SetupMandateRequestData,
                    PaymentsResponseData,
                >,
            >,
            &Card,
        ),
    ) -> Result<Self, Self::Error> {
        let (item, card_data) = value;
        let amount = get_amount_data_for_setup_mandate(item);
        let auth_type = AdyenAuthType::try_from(&item.router_data.connector_auth_type)?;
        let shopper_interaction = AdyenShopperInteraction::from(item.router_data);
        let shopper_reference = build_shopper_reference(
            &item.router_data.request.customer_id.clone(),
            item.router_data.resource_common_data.merchant_id.clone(),
        );
        let (recurring_processing_model, store_payment_method, _) =
            get_recurring_processing_model_for_setup_mandate(item.router_data)?;

        let return_url = item
            .router_data
            .request
            .router_return_url
            .clone()
            .ok_or_else(Box::new(move || {
                errors::ConnectorError::MissingRequiredField {
                    field_name: "return_url",
                }
            }))?;

        let billing_address = get_address_info(
            item.router_data
                .resource_common_data
                .address
                .get_payment_billing(),
        )
        .and_then(Result::ok);

        let card_holder_name = item.router_data.request.customer_name.clone();

        let additional_data = get_additional_data_for_setup_mandate(item.router_data);

        let payment_method = PaymentMethod::AdyenPaymentMethod(Box::new(
            AdyenPaymentMethod::try_from((card_data, card_holder_name))?,
        ));

        Ok(AdyenPaymentRequest {
            amount,
            merchant_account: auth_type.merchant_account,
            payment_method,
            reference: item.router_data.connector_request_reference_id.clone(),
            return_url,
            shopper_interaction,
            recurring_processing_model,
            browser_info: None,
            additional_data,
            mpi_data: None,
            telephone_number: None,
            shopper_name: None,
            shopper_email: None,
            shopper_locale: None,
            social_security_number: None,
            billing_address,
            delivery_address: None,
            country_code: None,
            line_items: None,
            shopper_reference,
            store_payment_method,
            channel: None,
            shopper_statement: item.router_data.request.statement_descriptor.clone(),
            shopper_ip: None,
            merchant_order_reference: item.router_data.request.merchant_order_reference_id.clone(),
            store: None,
            splits: None,
            device_fingerprint: None,
        })
    }
}

impl
    TryFrom<
        &AdyenRouterData1<
            &RouterDataV2<
                SetupMandate,
                PaymentFlowData,
                SetupMandateRequestData,
                PaymentsResponseData,
            >,
        >,
    > for AdyenPaymentRequest
{
    type Error = Error;
    fn try_from(
        item: &AdyenRouterData1<
            &RouterDataV2<
                SetupMandate,
                PaymentFlowData,
                SetupMandateRequestData,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        match item
            .router_data
            .request
            .mandate_id
            .to_owned()
            .and_then(|mandate_ids| mandate_ids.mandate_reference_id)
        {
            Some(_mandate_ref) => Err(
                hyperswitch_interfaces::errors::ConnectorError::NotImplemented(
                    "payment_method".into(),
                ),
            )?,
            None => match item.router_data.request.payment_method_data {
                PaymentMethodData::Card(ref card) => AdyenPaymentRequest::try_from((item, card)),
                PaymentMethodData::Wallet(_)
                | PaymentMethodData::PayLater(_)
                | PaymentMethodData::BankRedirect(_)
                | PaymentMethodData::BankDebit(_)
                | PaymentMethodData::BankTransfer(_)
                | PaymentMethodData::CardRedirect(_)
                | PaymentMethodData::Voucher(_)
                | PaymentMethodData::GiftCard(_)
                | PaymentMethodData::Crypto(_)
                | PaymentMethodData::MandatePayment
                | PaymentMethodData::Reward
                | PaymentMethodData::RealTimePayment(_)
                | PaymentMethodData::Upi(_)
                | PaymentMethodData::OpenBanking(_)
                | PaymentMethodData::CardToken(_) => Err(
                    hyperswitch_interfaces::errors::ConnectorError::NotImplemented(
                        "payment method".into(),
                    ),
                )?,
            },
        }
    }
}

fn get_amount_data_for_setup_mandate(
    item: &AdyenRouterData1<
        &RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData>,
    >,
) -> Amount {
    Amount {
        currency: item.router_data.request.currency,
        value: MinorUnit::new(item.router_data.request.amount.unwrap_or(0)),
    }
}

impl
    From<
        &RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData>,
    > for AdyenShopperInteraction
{
    fn from(
        item: &RouterDataV2<
            SetupMandate,
            PaymentFlowData,
            SetupMandateRequestData,
            PaymentsResponseData,
        >,
    ) -> Self {
        match item.request.off_session {
            Some(true) => Self::ContinuedAuthentication,
            _ => Self::Ecommerce,
        }
    }
}

fn get_recurring_processing_model_for_setup_mandate(
    item: &RouterDataV2<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData,
        PaymentsResponseData,
    >,
) -> Result<RecurringDetails, Error> {
    let customer_id = item
        .request
        .customer_id
        .clone()
        .ok_or_else(Box::new(move || {
            errors::ConnectorError::MissingRequiredField {
                field_name: "customer_id",
            }
        }))?;

    match (item.request.setup_future_usage, item.request.off_session) {
        (Some(hyperswitch_common_enums::enums::FutureUsage::OffSession), _) => {
            let shopper_reference = format!(
                "{}_{}",
                item.merchant_id.get_string_repr(),
                customer_id.get_string_repr()
            );
            let store_payment_method = is_mandate_payment_for_setup_mandate(item);
            Ok((
                Some(AdyenRecurringModel::UnscheduledCardOnFile),
                Some(store_payment_method),
                Some(shopper_reference),
            ))
        }
        (_, Some(true)) => Ok((
            Some(AdyenRecurringModel::UnscheduledCardOnFile),
            None,
            Some(format!(
                "{}_{}",
                item.merchant_id.get_string_repr(),
                customer_id.get_string_repr()
            )),
        )),
        _ => Ok((None, None, None)),
    }
}

fn get_additional_data_for_setup_mandate(
    item: &RouterDataV2<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData,
        PaymentsResponseData,
    >,
) -> Option<AdditionalData> {
    let (authorisation_type, manual_capture) = match item.request.capture_method {
        Some(hyperswitch_common_enums::enums::CaptureMethod::Manual)
        | Some(enums::CaptureMethod::ManualMultiple) => {
            (Some(AuthType::PreAuth), Some("true".to_string()))
        }
        _ => (None, None),
    };
    let riskdata = item.request.metadata.clone().and_then(get_risk_data);

    let execute_three_d = if matches!(
        item.resource_common_data.auth_type,
        hyperswitch_common_enums::enums::AuthenticationType::ThreeDs
    ) {
        Some("true".to_string())
    } else {
        None
    };

    if authorisation_type.is_none()
        && manual_capture.is_none()
        && execute_three_d.is_none()
        && riskdata.is_none()
    {
        //without this if-condition when the above 3 values are None, additionalData will be serialized to JSON like this -> additionalData: {}
        //returning None, ensures that additionalData key will not be present in the serialized JSON
        None
    } else {
        Some(AdditionalData {
            authorisation_type,
            manual_capture,
            execute_three_d,
            network_tx_reference: None,
            recurring_detail_reference: None,
            recurring_shopper_reference: None,
            recurring_processing_model: None,
            riskdata,
            ..AdditionalData::default()
        })
    }
}

fn is_mandate_payment_for_setup_mandate(
    item: &RouterDataV2<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData,
        PaymentsResponseData,
    >,
) -> bool {
    (item.request.setup_future_usage
        == Some(hyperswitch_common_enums::enums::FutureUsage::OffSession))
        || item
            .request
            .mandate_id
            .as_ref()
            .and_then(|mandate_ids| mandate_ids.mandate_reference_id.as_ref())
            .is_some()
}

impl ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    for Adyen
{
    fn get_headers(
        &self,
        req: &RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError>
    where
        Self:
            ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>,
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
        req: &RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        let dispute_base_url = req
            .resource_common_data
            .connectors
            .adyen
            .dispute_base_url
            .clone()
            .ok_or_else(|| {
                report!(errors::ConnectorError::FailedToObtainIntegrationUrl).attach_printable(
                    "Missing Adyen dispute_base_url while constructing acceptDispute URL",
                )
            })?;

        Ok(format!(
            "{}ca/services/DisputeService/v30/acceptDispute",
            dispute_base_url
        ))
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let adyen_req = adyen::AdyenDisputeAcceptRequest::try_from(req)?;

        Ok(Some(RequestContent::Json(Box::new(adyen_req))))
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<
        RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>,
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
