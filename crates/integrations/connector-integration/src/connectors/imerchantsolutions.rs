pub mod transformers;

use std::fmt::Debug;

use common_enums::CurrencyUnit;
use common_utils::{
    errors::CustomResult, events, ext_traits::ByteSliceExt, request::RequestContent,
};
use domain_types::{
    connector_flow::{
        Authorize, Capture, PSync, RSync, Refund, SetupMandate, Void,
    },
    connector_types::{
        AccessTokenRequestData, AccessTokenResponseData, PaymentFlowData, PaymentVoidData,
        PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData, PaymentsSyncData,
        RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData, ResponseId,
        SetupMandateRequestData, SetupMandateResponseData,
    },
    errors,
    router_data::ConnectorSpecificConfig,
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, Mask, Maskable, Secret};
use interfaces::{
    api::ConnectorCommon, connector_integration_v2::ConnectorIntegrationV2, connector_types,
};
use serde::Serialize;
use transformers as imerchantsolutions;
use transformers::{
    ImerchantsolutionsAuthType, ImerchantsolutionsAuthorizeRequest,
    ImerchantsolutionsAuthorizeResponse, ImerchantsolutionsCaptureRequest,
    ImerchantsolutionsCaptureResponse, ImerchantsolutionsErrorResponse,
    ImerchantsolutionsPSyncRequest, ImerchantsolutionsPSyncResponse,
    ImerchantsolutionsRefundRequest, ImerchantsolutionsRefundResponse,
    ImerchantsolutionsRSyncRequest, ImerchantsolutionsRSyncResponse,
    ImerchantsolutionsSetupMandateRequest, ImerchantsolutionsSetupMandateResponse,
    ImerchantsolutionsVoidRequest, ImerchantsolutionsVoidResponse,
};

use super::macros;
use crate::{types::ResponseRouterData, with_error_response_body};

pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const AUTHORIZATION: &str = "Authorization";
    pub(crate) const API_KEY: &str = "X-API-Key";
}

// =============================================================================
// MACRO PREREQUISITES
// =============================================================================
macros::create_all_prerequisites!(
    connector_name: Imerchantsolutions,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: ImerchantsolutionsAuthorizeRequest,
            response_body: ImerchantsolutionsAuthorizeResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: Capture,
            request_body: ImerchantsolutionsCaptureRequest,
            response_body: ImerchantsolutionsCaptureResponse,
            router_data: RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ),
        (
            flow: PSync,
            request_body: ImerchantsolutionsPSyncRequest,
            response_body: ImerchantsolutionsPSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ),
        (
            flow: Refund,
            request_body: ImerchantsolutionsRefundRequest,
            response_body: ImerchantsolutionsRefundResponse,
            router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ),
        (
            flow: RSync,
            request_body: ImerchantsolutionsRSyncRequest,
            response_body: ImerchantsolutionsRSyncResponse,
            router_data: RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ),
        (
            flow: Void,
            request_body: ImerchantsolutionsVoidRequest,
            response_body: ImerchantsolutionsVoidResponse,
            router_data: RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ),
        (
            flow: SetupMandate,
            request_body: ImerchantsolutionsSetupMandateRequest,
            response_body: ImerchantsolutionsSetupMandateResponse,
            router_data: RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData, SetupMandateResponseData>,
        )
    ],
    member_functions: {}
);

impl<T> ConnectorCommon for Imerchantsolutions<T> {
    fn id(&self) -> &'static str {
        "imerchantsolutions"
    }

    fn get_currency_unit(&self) -> CurrencyUnit {
        CurrencyUnit::Base
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn base_url<'a>(&self, connector_config: &'a connector_types::ConnectorConfig) -> &'a str {
        connector_config.base_url.as_str()
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut common_utils::events::EventBuilder>,
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        let response = res
            .response
            .parse_struct::<ImerchantsolutionsErrorResponse>("Imerchantsolutions Error Response")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        event_builder.map(|i| i.set_response_body(&response));

        Ok(domain_types::router_data::ErrorResponse {
            status_code: res.status_code,
            code: response.error_code.unwrap_or_else(|| "UNKNOWN".to_string()),
            message: response.error_message.unwrap_or_else(|| "Unknown error".to_string()),
            reason: response.error_description,
            attempt_status: None,
            connector_transaction_id: None,
        })
    }
}

// =============================================================================
// AUTHORIZE FLOW
// =============================================================================
impl<T> ConnectorIntegrationV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
    for Imerchantsolutions<T>
where
    T: Debug + Clone + Sync + Send,
{
    fn get_headers(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth = ImerchantsolutionsAuthType::try_from(&req.connector_config)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;

        Ok(vec![
            (
                headers::CONTENT_TYPE.to_string(),
                self.common_get_content_type().to_string().into(),
            ),
            (
                headers::AUTHORIZATION.to_string(),
                format!("Bearer {}", auth.api_key.expose()).into_masked(),
            ),
        ])
    }

    fn get_url(
        &self,
        _req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(format!("{}/payments/authorize", self.base_url(connectors)))
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<Option<common_utils::request::RequestContent>, errors::ConnectorError> {
        let connector_router_data = ImerchantsolutionsRouterData::try_from((self, req))?;
        let connector_req = ImerchantsolutionsAuthorizeRequest::try_from(&connector_router_data)?;
        Ok(Some(RequestContent::Json(Box::new(connector_req))))
    }

    fn handle_response(
        &self,
        data: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        event_builder: Option<&mut common_utils::events::EventBuilder>,
        res: Response,
    ) -> CustomResult<ResponseRouterData<Authorize, PaymentsResponseData>, errors::ConnectorError> {
        let response: ImerchantsolutionsAuthorizeResponse = res
            .response
            .parse_struct("Imerchantsolutions AuthorizeResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        event_builder.map(|i| i.set_response_body(&response));

        ResponseRouterData {
            response,
            data: data.clone(),
        }
        .try_into()
        .change_context(errors::ConnectorError::ResponseHandlingFailed)
    }

    with_error_response_body!();
}

// =============================================================================
// CAPTURE FLOW
// =============================================================================
impl<T> ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
    for Imerchantsolutions<T>
{
    fn get_headers(
        &self,
        req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth = ImerchantsolutionsAuthType::try_from(&req.connector_config)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;

        Ok(vec![
            (
                headers::CONTENT_TYPE.to_string(),
                self.common_get_content_type().to_string().into(),
            ),
            (
                headers::AUTHORIZATION.to_string(),
                format!("Bearer {}", auth.api_key.expose()).into_masked(),
            ),
        ])
    }

    fn get_url(
        &self,
        req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        let connector_payment_id = req.request.connector_transaction_id.clone()
            .ok_or(errors::ConnectorError::MissingConnectorTransactionID)?;
        Ok(format!("{}/payments/{}/capture", self.base_url(connectors), connector_payment_id))
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<Option<common_utils::request::RequestContent>, errors::ConnectorError> {
        let connector_router_data = ImerchantsolutionsRouterData::try_from((self, req))?;
        let connector_req = ImerchantsolutionsCaptureRequest::try_from(&connector_router_data)?;
        Ok(Some(RequestContent::Json(Box::new(connector_req))))
    }

    fn handle_response(
        &self,
        data: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        event_builder: Option<&mut common_utils::events::EventBuilder>,
        res: Response,
    ) -> CustomResult<ResponseRouterData<Capture, PaymentsResponseData>, errors::ConnectorError> {
        let response: ImerchantsolutionsCaptureResponse = res
            .response
            .parse_struct("Imerchantsolutions CaptureResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        event_builder.map(|i| i.set_response_body(&response));

        ResponseRouterData {
            response,
            data: data.clone(),
        }
        .try_into()
        .change_context(errors::ConnectorError::ResponseHandlingFailed)
    }

    with_error_response_body!();
}

// =============================================================================
// VOID FLOW
// =============================================================================
impl<T> ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
    for Imerchantsolutions<T>
{
    fn get_headers(
        &self,
        req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth = ImerchantsolutionsAuthType::try_from(&req.connector_config)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;

        Ok(vec![
            (
                headers::CONTENT_TYPE.to_string(),
                self.common_get_content_type().to_string().into(),
            ),
            (
                headers::AUTHORIZATION.to_string(),
                format!("Bearer {}", auth.api_key.expose()).into_masked(),
            ),
        ])
    }

    fn get_url(
        &self,
        req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        let connector_payment_id = req.request.connector_transaction_id.clone()
            .ok_or(errors::ConnectorError::MissingConnectorTransactionID)?;
        Ok(format!("{}/payments/{}/void", self.base_url(connectors), connector_payment_id))
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<Option<common_utils::request::RequestContent>, errors::ConnectorError> {
        let connector_req = ImerchantsolutionsVoidRequest::try_from(req)?;
        Ok(Some(RequestContent::Json(Box::new(connector_req))))
    }

    fn handle_response(
        &self,
        data: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        event_builder: Option<&mut common_utils::events::EventBuilder>,
        res: Response,
    ) -> CustomResult<ResponseRouterData<Void, PaymentsResponseData>, errors::ConnectorError> {
        let response: ImerchantsolutionsVoidResponse = res
            .response
            .parse_struct("Imerchantsolutions VoidResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        event_builder.map(|i| i.set_response_body(&response));

        ResponseRouterData {
            response,
            data: data.clone(),
        }
        .try_into()
        .change_context(errors::ConnectorError::ResponseHandlingFailed)
    }

    with_error_response_body!();
}

// =============================================================================
// REFUND FLOW
// =============================================================================
impl<T> ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
    for Imerchantsolutions<T>
{
    fn get_headers(
        &self,
        req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth = ImerchantsolutionsAuthType::try_from(&req.connector_config)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;

        Ok(vec![
            (
                headers::CONTENT_TYPE.to_string(),
                self.common_get_content_type().to_string().into(),
            ),
            (
                headers::AUTHORIZATION.to_string(),
                format!("Bearer {}", auth.api_key.expose()).into_masked(),
            ),
        ])
    }

    fn get_url(
        &self,
        req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        let connector_payment_id = req.request.connector_transaction_id.clone()
            .ok_or(errors::ConnectorError::MissingConnectorTransactionID)?;
        Ok(format!("{}/payments/{}/refund", self.base_url(connectors), connector_payment_id))
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<Option<common_utils::request::RequestContent>, errors::ConnectorError> {
        let connector_router_data = ImerchantsolutionsRouterData::try_from((self, req))?;
        let connector_req = ImerchantsolutionsRefundRequest::try_from(&connector_router_data)?;
        Ok(Some(RequestContent::Json(Box::new(connector_req))))
    }

    fn handle_response(
        &self,
        data: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        event_builder: Option<&mut common_utils::events::EventBuilder>,
        res: Response,
    ) -> CustomResult<ResponseRouterData<Refund, RefundsResponseData>, errors::ConnectorError> {
        let response: ImerchantsolutionsRefundResponse = res
            .response
            .parse_struct("Imerchantsolutions RefundResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        event_builder.map(|i| i.set_response_body(&response));

        ResponseRouterData {
            response,
            data: data.clone(),
        }
        .try_into()
        .change_context(errors::ConnectorError::ResponseHandlingFailed)
    }

    with_error_response_body!();
}

// =============================================================================
// PAYMENT SYNC FLOW
// =============================================================================
impl<T> ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    for Imerchantsolutions<T>
{
    fn get_headers(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth = ImerchantsolutionsAuthType::try_from(&req.connector_config)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;

        Ok(vec![
            (
                headers::CONTENT_TYPE.to_string(),
                self.common_get_content_type().to_string().into(),
            ),
            (
                headers::AUTHORIZATION.to_string(),
                format!("Bearer {}", auth.api_key.expose()).into_masked(),
            ),
        ])
    }

    fn get_url(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        let connector_payment_id = req.request.connector_transaction_id.clone()
            .ok_or(errors::ConnectorError::MissingConnectorTransactionID)?;
        Ok(format!("{}/payments/{}", self.base_url(connectors), connector_payment_id))
    }

    fn get_request_body(
        &self,
        _req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<Option<common_utils::request::RequestContent>, errors::ConnectorError> {
        Ok(None)
    }

    fn handle_response(
        &self,
        data: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        event_builder: Option<&mut common_utils::events::EventBuilder>,
        res: Response,
    ) -> CustomResult<ResponseRouterData<PSync, PaymentsResponseData>, errors::ConnectorError> {
        let response: ImerchantsolutionsPSyncResponse = res
            .response
            .parse_struct("Imerchantsolutions PSyncResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        event_builder.map(|i| i.set_response_body(&response));

        ResponseRouterData {
            response,
            data: data.clone(),
        }
        .try_into()
        .change_context(errors::ConnectorError::ResponseHandlingFailed)
    }

    with_error_response_body!();
}

// =============================================================================
// REFUND SYNC FLOW
// =============================================================================
impl<T> ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
    for Imerchantsolutions<T>
{
    fn get_headers(
        &self,
        req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth = ImerchantsolutionsAuthType::try_from(&req.connector_config)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;

        Ok(vec![
            (
                headers::CONTENT_TYPE.to_string(),
                self.common_get_content_type().to_string().into(),
            ),
            (
                headers::AUTHORIZATION.to_string(),
                format!("Bearer {}", auth.api_key.expose()).into_masked(),
            ),
        ])
    }

    fn get_url(
        &self,
        req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        let connector_refund_id = req.request.connector_refund_id.clone()
            .ok_or(errors::ConnectorError::MissingConnectorRefundID)?;
        Ok(format!("{}/refunds/{}", self.base_url(connectors), connector_refund_id))
    }

    fn get_request_body(
        &self,
        _req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<Option<common_utils::request::RequestContent>, errors::ConnectorError> {
        Ok(None)
    }

    fn handle_response(
        &self,
        data: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        event_builder: Option<&mut common_utils::events::EventBuilder>,
        res: Response,
    ) -> CustomResult<ResponseRouterData<RSync, RefundsResponseData>, errors::ConnectorError> {
        let response: ImerchantsolutionsRSyncResponse = res
            .response
            .parse_struct("Imerchantsolutions RSyncResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        event_builder.map(|i| i.set_response_body(&response));

        ResponseRouterData {
            response,
            data: data.clone(),
        }
        .try_into()
        .change_context(errors::ConnectorError::ResponseHandlingFailed)
    }

    with_error_response_body!();
}

// =============================================================================
// SETUP MANDATE FLOW
// =============================================================================
impl<T> ConnectorIntegrationV2<SetupMandate, PaymentFlowData, SetupMandateRequestData, SetupMandateResponseData>
    for Imerchantsolutions<T>
where
    T: Debug + Clone + Sync + Send,
{
    fn get_headers(
        &self,
        req: &RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData, SetupMandateResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth = ImerchantsolutionsAuthType::try_from(&req.connector_config)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;

        Ok(vec![
            (
                headers::CONTENT_TYPE.to_string(),
                self.common_get_content_type().to_string().into(),
            ),
            (
                headers::AUTHORIZATION.to_string(),
                format!("Bearer {}", auth.api_key.expose()).into_masked(),
            ),
        ])
    }

    fn get_url(
        &self,
        _req: &RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData, SetupMandateResponseData>,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(format!("{}/mandates/setup", self.base_url(connectors)))
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData, SetupMandateResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<Option<common_utils::request::RequestContent>, errors::ConnectorError> {
        let connector_router_data = ImerchantsolutionsRouterData::try_from((self, req))?;
        let connector_req = ImerchantsolutionsSetupMandateRequest::try_from(&connector_router_data)?;
        Ok(Some(RequestContent::Json(Box::new(connector_req))))
    }

    fn handle_response(
        &self,
        data: &RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData, SetupMandateResponseData>,
        event_builder: Option<&mut common_utils::events::EventBuilder>,
        res: Response,
    ) -> CustomResult<ResponseRouterData<SetupMandate, SetupMandateResponseData>, errors::ConnectorError> {
        let response: ImerchantsolutionsSetupMandateResponse = res
            .response
            .parse_struct("Imerchantsolutions SetupMandateResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        event_builder.map(|i| i.set_response_body(&response));

        ResponseRouterData {
            response,
            data: data.clone(),
        }
        .try_into()
        .change_context(errors::ConnectorError::ResponseHandlingFailed)
    }

    with_error_response_body!();
}
