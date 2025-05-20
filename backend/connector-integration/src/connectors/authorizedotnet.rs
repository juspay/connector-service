pub mod transformers;

use domain_types::{
    connector_flow::{Authorize, Capture, PSync, RSync, Refund, Void, SetupMandate, CreateOrder, Accept, SubmitEvidence},
    connector_types::{
        AcceptDisputeData, ConnectorServiceTrait, DisputeFlowData, DisputeResponseData,
        PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData,
        PaymentsCaptureData, PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData,
        RefundsResponseData, SetupMandateRequestData, ValidationTrait, PaymentAuthorizeV2, PaymentSyncV2, PaymentOrderCreate, PaymentVoidV2, RefundSyncV2, RefundV2, PaymentCapture, SetupMandateV2, AcceptDispute, SubmitEvidenceV2, SubmitEvidenceData, IncomingWebhook
    },
};
use error_stack::ResultExt;
use hyperswitch_common_utils::{
    errors::CustomResult,
    request::{RequestContent},
    ext_traits::ByteSliceExt,
};
use hyperswitch_domain_models::{
    router_data::ErrorResponse,
    router_data_v2::RouterDataV2,
};
use hyperswitch_interfaces::{
    api::{self, ConnectorCommon},
    connector_integration_v2::ConnectorIntegrationV2,
    errors::{ConnectorError as HsInterfacesConnectorError},
    events::connector_api_logs::ConnectorEvent,
    consts,
    types::{Response},
    configs::Connectors as GlobalConnectorsConfig,
};
use hyperswitch_masking::Maskable;
use crate::with_response_body;
use std::str::FromStr;

use self::transformers::{self as authorizedotnet_transformers, ForeignTryFrom};

pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    // pub(crate) const AUTHORIZATION: &str = "Authorization"; // Commented out as unused previously
}

#[derive(Debug, Clone)]
pub struct Authorizedotnet;

static AUTHORIZEDOTNET_INSTANCE: Authorizedotnet = Authorizedotnet;

impl Authorizedotnet {
    pub fn new() -> &'static Self {
        &AUTHORIZEDOTNET_INSTANCE
    }
}

impl ConnectorCommon for Authorizedotnet {
    fn id(&self) -> &'static str {
        "authorizedotnet"
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn base_url<'a>(&self, connectors: &'a GlobalConnectorsConfig) -> &'a str {
        connectors.authorizedotnet.base_url.as_ref()
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, HsInterfacesConnectorError> {
        let parsed_error_response: Result<authorizedotnet_transformers::AuthorizedotnetErrorResponse, _> = res
            .response
            .parse_struct("AuthorizedotnetErrorResponse")
            .change_context(HsInterfacesConnectorError::ResponseDeserializationFailed);

        match parsed_error_response {
            Ok(authorizedotnet_error) => {
                // Log the successfully parsed error response
                with_response_body!(event_builder, authorizedotnet_error);
                Ok(ErrorResponse {
                    status_code: res.status_code,
                    code: authorizedotnet_error.messages.message.first().map(|m| m.code.clone()).unwrap_or_else(|| consts::NO_ERROR_CODE.to_string()),
                    message: authorizedotnet_error.messages.message.first().map(|m| m.text.clone()).unwrap_or_else(|| consts::NO_ERROR_MESSAGE.to_string()),
                    reason: None, 
                    attempt_status: None,
                    connector_transaction_id: None, 
                })
            },
            Err(report) => {
                // If parsing fails, we can't log the structured error body the same way.
                // Log a generic message or the raw response if possible (though with_response_body expects serializable T)
                // For now, just pass the error through.
                // Consider adding raw response logging here if needed, e.g. event_builder.map(|eb| eb.set_raw_response(&res.response));
                Err(report).change_context(HsInterfacesConnectorError::ResponseHandlingFailed) 
            },
        }
    }

    fn get_currency_unit(&self) -> api::CurrencyUnit {
        api::CurrencyUnit::Base // Changed from BaseMajor to Base
    }
}

impl ConnectorServiceTrait for Authorizedotnet {}
impl ValidationTrait for Authorizedotnet {}
impl IncomingWebhook for Authorizedotnet {}
impl PaymentAuthorizeV2 for Authorizedotnet {}
impl PaymentSyncV2 for Authorizedotnet {}
impl PaymentOrderCreate for Authorizedotnet {}
impl PaymentVoidV2 for Authorizedotnet {}
impl RefundSyncV2 for Authorizedotnet {}
impl RefundV2 for Authorizedotnet {}
impl PaymentCapture for Authorizedotnet {}
impl SetupMandateV2 for Authorizedotnet {}
impl AcceptDispute for Authorizedotnet {}
impl SubmitEvidenceV2 for Authorizedotnet {}


impl ConnectorIntegrationV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>
    for Authorizedotnet
{
    fn get_headers(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, HsInterfacesConnectorError> {
        let mut header = vec![( 
            headers::CONTENT_TYPE.to_string(),
            self.common_get_content_type().to_string().into(),
        )];
        let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
        header.append(&mut api_key);
        Ok(header)
    }

    fn get_url(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
    ) -> CustomResult<String, HsInterfacesConnectorError> {
        Ok(req.resource_common_data.connectors.authorizedotnet.base_url.clone())
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
    ) -> CustomResult<Option<RequestContent>, HsInterfacesConnectorError> {
        
        let merchant_auth = authorizedotnet_transformers::MerchantAuthentication::try_from(&req.connector_auth_type)?;

        let connector_router_data = authorizedotnet_transformers::AuthorizedotnetRouterData::try_from((
            &self.get_currency_unit(),
            req.request.currency,
            req.request.minor_amount,
            req,
            merchant_auth,
        ))?;

        let connector_req =
            authorizedotnet_transformers::AuthorizedotnetPaymentsRequest::try_from(
                &connector_router_data,
            )?;
        Ok(Some(RequestContent::Json(Box::new(connector_req))))
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
        HsInterfacesConnectorError,
    > {
        use bytes::Buf;

        let encoding = encoding_rs::UTF_8;
        let intermediate_response_bytes = encoding.decode_with_bom_removal(res.response.chunk());
        let intermediate_response_body = bytes::Bytes::copy_from_slice(intermediate_response_bytes.0.as_bytes());

        let response_struct: authorizedotnet_transformers::AuthorizedotnetPaymentsResponse = intermediate_response_body
            .parse_struct("AuthorizedotnetPaymentsResponse")
            .change_context(HsInterfacesConnectorError::ResponseDeserializationFailed)?;

        with_response_body!(event_builder, response_struct);

        RouterDataV2::foreign_try_from((
            response_struct,
            data.clone(),
            res.status_code,
            authorizedotnet_transformers::Operation::Authorize,
        ))
        .change_context(HsInterfacesConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, HsInterfacesConnectorError> {
        self.build_error_response(res, event_builder)
    }

     fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, HsInterfacesConnectorError> {
        self.build_error_response(res, event_builder)
    }
}


impl ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
    for Authorizedotnet
{
    fn get_headers(
        &self,
        req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, HsInterfacesConnectorError> {
        let mut header = vec![( 
            headers::CONTENT_TYPE.to_string(),
            self.common_get_content_type().to_string().into(),
        )];
        let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
        header.append(&mut api_key);
        Ok(header)
    }

    fn get_url(
        &self,
        req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
    ) -> CustomResult<String, HsInterfacesConnectorError> {
        Ok(req.resource_common_data.connectors.authorizedotnet.base_url.clone())
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
    ) -> CustomResult<Option<RequestContent>, HsInterfacesConnectorError> {
        let merchant_auth = authorizedotnet_transformers::MerchantAuthentication::try_from(&req.connector_auth_type)?;

        let app_currency = req.request.currency;
        let api_currency = hyperswitch_api_models::enums::Currency::from_str(&app_currency.to_string())
            .map_err(|_| HsInterfacesConnectorError::RequestEncodingFailed)?;

        let connector_router_data = authorizedotnet_transformers::AuthorizedotnetRouterData::try_from((
            &self.get_currency_unit(),
            api_currency, 
            req.request.minor_amount_to_capture,
            req, 
            merchant_auth,
        ))?;

        let connector_req =
            authorizedotnet_transformers::AuthorizedotnetCaptureRequest::try_from(
                &connector_router_data,
            )?;
        Ok(Some(RequestContent::Json(Box::new(connector_req))))
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<
        RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        HsInterfacesConnectorError,
    > {
        use bytes::Buf;

        let encoding = encoding_rs::UTF_8;
        let intermediate_response_bytes = encoding.decode_with_bom_removal(res.response.chunk());
        let intermediate_response_body = bytes::Bytes::copy_from_slice(intermediate_response_bytes.0.as_bytes());

        let response_struct: authorizedotnet_transformers::AuthorizedotnetPaymentsResponse = intermediate_response_body
            .parse_struct("AuthorizedotnetPaymentsResponse")
            .change_context(HsInterfacesConnectorError::ResponseDeserializationFailed)?;

        with_response_body!(event_builder, response_struct);

        RouterDataV2::foreign_try_from((
            response_struct,
            data.clone(),
            res.status_code,
            authorizedotnet_transformers::Operation::Capture,
        ))
        .change_context(HsInterfacesConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, HsInterfacesConnectorError> {
        self.build_error_response(res, event_builder)
    }

     fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, HsInterfacesConnectorError> {
        self.build_error_response(res, event_builder)
    }
}


// -------- Stubs for other flows ------------

impl ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    for Authorizedotnet
{
    fn get_headers(
        &self,
        _req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, HsInterfacesConnectorError> {
        Err(HsInterfacesConnectorError::NotImplemented("get_headers for PSync".to_string()).into())
    }
    fn get_url(
        &self,
        _req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<String, HsInterfacesConnectorError> {
        Err(HsInterfacesConnectorError::NotImplemented("get_url for PSync".to_string()).into())
    }
    fn get_request_body(
        &self,
        _req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<Option<RequestContent>, HsInterfacesConnectorError> {
        Err(HsInterfacesConnectorError::NotImplemented("get_request_body for PSync".to_string()).into())
    }
    fn handle_response_v2(
        &self,
        _data: &RouterDataV2<
            PSync,
            PaymentFlowData,
            PaymentsSyncData,
            PaymentsResponseData,
        >,
        _event_builder: Option<&mut ConnectorEvent>,
        _res: Response,
    ) -> CustomResult<
        RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        HsInterfacesConnectorError,
    > {
        Err(HsInterfacesConnectorError::NotImplemented("handle_response_v2 for PSync".to_string()).into())
    }
    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, HsInterfacesConnectorError> {
        self.build_error_response(res, event_builder)
    }
     fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, HsInterfacesConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl ConnectorIntegrationV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>
    for Authorizedotnet
{
    // Stubs
    fn get_headers(
        &self,
        _req: &RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, HsInterfacesConnectorError> {
        Err(HsInterfacesConnectorError::NotImplemented("get_headers for CreateOrder".to_string()).into())
    }
    fn get_url(
        &self,
        _req: &RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>,
    ) -> CustomResult<String, HsInterfacesConnectorError> {
        Err(HsInterfacesConnectorError::NotImplemented("get_url for CreateOrder".to_string()).into())
    }
    fn get_request_body(
        &self,
        _req: &RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>,
    ) -> CustomResult<Option<RequestContent>, HsInterfacesConnectorError> {
        Err(HsInterfacesConnectorError::NotImplemented("get_request_body for CreateOrder".to_string()).into())
    }
    fn handle_response_v2(
        &self,
        _data: &RouterDataV2<
            CreateOrder,
            PaymentFlowData,
            PaymentCreateOrderData,
            PaymentCreateOrderResponse,
        >,
        _event_builder: Option<&mut ConnectorEvent>,
        _res: Response,
    ) -> CustomResult<
        RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>,
        HsInterfacesConnectorError,
    > {
        Err(HsInterfacesConnectorError::NotImplemented("handle_response_v2 for CreateOrder".to_string()).into())
    }
    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, HsInterfacesConnectorError> {
        self.build_error_response(res, event_builder)
    }
     fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, HsInterfacesConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
    for Authorizedotnet
{
    // Stubs
    fn get_headers(
        &self,
        _req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, HsInterfacesConnectorError> {
        Err(HsInterfacesConnectorError::NotImplemented("get_headers for RSync".to_string()).into())
    }
    fn get_url(
        &self,
        _req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
    ) -> CustomResult<String, HsInterfacesConnectorError> {
        Err(HsInterfacesConnectorError::NotImplemented("get_url for RSync".to_string()).into())
    }
    fn get_request_body(
        &self,
        _req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
    ) -> CustomResult<Option<RequestContent>, HsInterfacesConnectorError> {
        Err(HsInterfacesConnectorError::NotImplemented("get_request_body for RSync".to_string()).into())
    }
    fn handle_response_v2(
        &self,
        _data: &RouterDataV2<
            RSync,
            RefundFlowData,
            RefundSyncData,
            RefundsResponseData,
        >,
        _event_builder: Option<&mut ConnectorEvent>,
        _res: Response,
    ) -> CustomResult<
        RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        HsInterfacesConnectorError,
    > {
        Err(HsInterfacesConnectorError::NotImplemented("handle_response_v2 for RSync".to_string()).into())
    }
    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, HsInterfacesConnectorError> {
        self.build_error_response(res, event_builder)
    }
     fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, HsInterfacesConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData> for Authorizedotnet {
    fn get_headers(
        &self,
        _req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, HsInterfacesConnectorError> {
        Ok(vec![( 
            headers::CONTENT_TYPE.to_string(),
            self.common_get_content_type().to_string().into(),
        )])
    }

    fn get_url(
        &self,
        req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
    ) -> CustomResult<String, HsInterfacesConnectorError> {
        Ok(req.resource_common_data.connectors.authorizedotnet.base_url.clone())
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
    ) -> CustomResult<Option<RequestContent>, HsInterfacesConnectorError> {
        let merchant_auth = authorizedotnet_transformers::MerchantAuthentication::try_from(&req.connector_auth_type)?;
        let connector_req =
            authorizedotnet_transformers::AuthorizedotnetVoidRequest::try_from((req, merchant_auth))?;
        Ok(Some(RequestContent::Json(Box::new(connector_req))))
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>, HsInterfacesConnectorError> {
        use bytes::Buf;

        let encoding = encoding_rs::UTF_8;
        let intermediate_response = encoding.decode_with_bom_removal(res.response.chunk());
        let intermediate_response_body =
            bytes::Bytes::copy_from_slice(intermediate_response.0.as_bytes());
        let response_struct: authorizedotnet_transformers::AuthorizedotnetPaymentsResponse = intermediate_response_body
            .parse_struct("AuthorizedotnetPaymentsResponse")
            .change_context(HsInterfacesConnectorError::ResponseDeserializationFailed)?;

        with_response_body!(event_builder, response_struct);

        RouterDataV2::foreign_try_from((
            response_struct,
            data.clone(),
            res.status_code,
            authorizedotnet_transformers::Operation::Void, 
        ))
        .change_context(HsInterfacesConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, HsInterfacesConnectorError> {
        self.build_error_response(res, event_builder)
    }

     fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, HsInterfacesConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData> for Authorizedotnet {
    fn get_headers(
        &self,
        _req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, HsInterfacesConnectorError> {
        Ok(vec![( 
            headers::CONTENT_TYPE.to_string(),
            self.common_get_content_type().to_string().into(),
        )])
    }

    fn get_url(
        &self,
        req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> CustomResult<String, HsInterfacesConnectorError> {
        Ok(req.resource_common_data.connectors.authorizedotnet.base_url.clone())
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> CustomResult<Option<RequestContent>, HsInterfacesConnectorError> {
        let merchant_auth = authorizedotnet_transformers::MerchantAuthentication::try_from(&req.connector_auth_type)?;
        let connector_req =
            authorizedotnet_transformers::AuthorizedotnetRefundRequest::try_from((req, merchant_auth))?;
        Ok(Some(RequestContent::Json(Box::new(connector_req))))
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>, HsInterfacesConnectorError> {
        use bytes::Buf;

        let encoding = encoding_rs::UTF_8;
        let intermediate_response = encoding.decode_with_bom_removal(res.response.chunk());
        let intermediate_response =
            bytes::Bytes::copy_from_slice(intermediate_response.0.as_bytes());
        let response: authorizedotnet_transformers::AuthorizedotnetPaymentsResponse = intermediate_response
            .parse_struct("AuthorizedotnetPaymentsResponse")
            .change_context(HsInterfacesConnectorError::ResponseDeserializationFailed)?;

        with_response_body!(event_builder, response);

        let (_attempt_status, refund_response_payload_result) =
            authorizedotnet_transformers::convert_to_refund_response_data_or_error(
                &response,
                res.status_code,
            )
            .change_context(HsInterfacesConnectorError::ResponseHandlingFailed)?;
        
        let mut router_data_out = data.clone();
        router_data_out.resource_common_data.status = match &refund_response_payload_result {
            Ok(refund_data) => refund_data.refund_status,
            Err(_) => hyperswitch_common_enums::enums::RefundStatus::Failure,
        };
        router_data_out.response = refund_response_payload_result;

        Ok(router_data_out)
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, HsInterfacesConnectorError> {
        self.build_error_response(res, event_builder)
    }

     fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, HsInterfacesConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl ConnectorIntegrationV2<SetupMandate, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData>
    for Authorizedotnet
{
    // Stubs
    fn get_headers(
        &self,
        _req: &RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, HsInterfacesConnectorError> {
        Err(HsInterfacesConnectorError::NotImplemented("get_headers for SetupMandate".to_string()).into())
    }
    fn get_url(
        &self,
        _req: &RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData>,
    ) -> CustomResult<String, HsInterfacesConnectorError> {
        Err(HsInterfacesConnectorError::NotImplemented("get_url for SetupMandate".to_string()).into())
    }
    fn get_request_body(
        &self,
        _req: &RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData>,
    ) -> CustomResult<Option<RequestContent>, HsInterfacesConnectorError> {
        Err(HsInterfacesConnectorError::NotImplemented("get_request_body for SetupMandate".to_string()).into())
    }
    fn handle_response_v2(
        &self,
        _data: &RouterDataV2<
            SetupMandate,
            PaymentFlowData,
            SetupMandateRequestData,
            PaymentsResponseData,
        >,
        _event_builder: Option<&mut ConnectorEvent>,
        _res: Response,
    ) -> CustomResult<
        RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData>,
        HsInterfacesConnectorError,
    > {
        Err(HsInterfacesConnectorError::NotImplemented("handle_response_v2 for SetupMandate".to_string()).into())
    }
    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, HsInterfacesConnectorError> {
        self.build_error_response(res, event_builder)
    }
     fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, HsInterfacesConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    for Authorizedotnet
{
    // Stubs
     fn get_headers(
        &self,
        _req: &RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, HsInterfacesConnectorError> {
        Err(HsInterfacesConnectorError::NotImplemented("get_headers for AcceptDispute".to_string()).into())
    }
    fn get_url(
        &self,
        _req: &RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>,
    ) -> CustomResult<String, HsInterfacesConnectorError> {
        Err(HsInterfacesConnectorError::NotImplemented("get_url for AcceptDispute".to_string()).into())
    }
    fn get_request_body(
        &self,
        _req: &RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>,
    ) -> CustomResult<Option<RequestContent>, HsInterfacesConnectorError> {
        Err(HsInterfacesConnectorError::NotImplemented("get_request_body for AcceptDispute".to_string()).into())
    }
    fn handle_response_v2(
        &self,
        _data: &RouterDataV2<
            Accept,
            DisputeFlowData,
            AcceptDisputeData,
            DisputeResponseData,
        >,
        _event_builder: Option<&mut ConnectorEvent>,
        _res: Response,
    ) -> CustomResult<
        RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>,
        HsInterfacesConnectorError,
    > {
        Err(HsInterfacesConnectorError::NotImplemented("handle_response_v2 for AcceptDispute".to_string()).into())
    }
    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, HsInterfacesConnectorError> {
        self.build_error_response(res, event_builder)
    }
     fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, HsInterfacesConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
    for Authorizedotnet
{
    // Stubs
     fn get_headers(
        &self,
        _req: &RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, HsInterfacesConnectorError> {
        Err(HsInterfacesConnectorError::NotImplemented("get_headers for SubmitEvidence".to_string()).into())
    }
    fn get_url(
        &self,
        _req: &RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>,
    ) -> CustomResult<String, HsInterfacesConnectorError> {
        Err(HsInterfacesConnectorError::NotImplemented("get_url for SubmitEvidence".to_string()).into())
    }
    fn get_request_body(
        &self,
        _req: &RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>,
    ) -> CustomResult<Option<RequestContent>, HsInterfacesConnectorError> {
        Err(HsInterfacesConnectorError::NotImplemented("get_request_body for SubmitEvidence".to_string()).into())
    }
    fn handle_response_v2(
        &self,
        _data: &RouterDataV2<
            SubmitEvidence,
            DisputeFlowData,
            SubmitEvidenceData,
            DisputeResponseData,
        >,
        _event_builder: Option<&mut ConnectorEvent>,
        _res: Response,
    ) -> CustomResult<
        RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>,
        HsInterfacesConnectorError,
    > {
        Err(HsInterfacesConnectorError::NotImplemented("handle_response_v2 for SubmitEvidence".to_string()).into())
    }
    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, HsInterfacesConnectorError> {
        self.build_error_response(res, event_builder)
    }
     fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, HsInterfacesConnectorError> {
        self.build_error_response(res, event_builder)
    }
} 