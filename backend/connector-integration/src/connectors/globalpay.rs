pub mod transformers;

use std::fmt::Debug;

use common_enums::CurrencyUnit;
use common_utils::{errors::CustomResult, ext_traits::ByteSliceExt, request::RequestContent};
use domain_types::{
    connector_flow::{
        Accept, Authenticate, Authorize, Capture, CreateAccessToken, CreateOrder,
        CreateSessionToken, DefendDispute, PSync, PaymentMethodToken, PostAuthenticate,
        PreAuthenticate, RSync, Refund, RepeatPayment, SetupMandate, SubmitEvidence, Void, VoidPC,
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
    errors::{self},
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
};
use error_stack::ResultExt;
use hyperswitch_masking::{Mask, Maskable};
use interfaces::{
    api::ConnectorCommon, connector_integration_v2::ConnectorIntegrationV2, connector_types,
    events::connector_api_logs::ConnectorEvent,
};
use serde::Serialize;
use transformers as globalpay;

use crate::types::ResponseRouterData;

pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const AUTHORIZATION: &str = "Authorization";
    pub(crate) const X_GP_VERSION: &str = "X-GP-Version";
    pub(crate) const X_GP_IDEMPOTENCY: &str = "X-GP-Idempotency";
}

#[derive(Debug, Clone)]
pub struct Globalpay<T: PaymentMethodDataTypes> {
    payment_method_type: std::marker::PhantomData<T>,
}

impl<T: PaymentMethodDataTypes> Globalpay<T> {
    pub const fn new() -> &'static Self {
        &Self {
            payment_method_type: std::marker::PhantomData,
        }
    }
}

// ===== CONNECTOR SERVICE TRAIT IMPLEMENTATIONS =====
// Main service trait - aggregates all other traits
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ConnectorServiceTrait<T> for Globalpay<T>
{
}

// ===== PAYMENT FLOW TRAIT IMPLEMENTATIONS =====
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAuthorizeV2<T> for Globalpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentSyncV2 for Globalpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentVoidV2 for Globalpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentVoidPostCaptureV2 for Globalpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentCapture for Globalpay<T>
{
}

// ===== REFUND FLOW TRAIT IMPLEMENTATIONS =====
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundV2 for Globalpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundSyncV2 for Globalpay<T>
{
}

// ===== ADVANCED FLOW TRAIT IMPLEMENTATIONS =====
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::SetupMandateV2<T> for Globalpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RepeatPaymentV2 for Globalpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentOrderCreate for Globalpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentSessionToken for Globalpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAccessToken for Globalpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentTokenV2<T> for Globalpay<T>
{
}

// ===== AUTHENTICATION FLOW TRAIT IMPLEMENTATIONS =====
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentPreAuthenticateV2<T> for Globalpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAuthenticateV2<T> for Globalpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentPostAuthenticateV2<T> for Globalpay<T>
{
}

// ===== DISPUTE FLOW TRAIT IMPLEMENTATIONS =====
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::AcceptDispute for Globalpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::DisputeDefend for Globalpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::SubmitEvidenceV2 for Globalpay<T>
{
}

// ===== WEBHOOK TRAIT IMPLEMENTATIONS =====
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::IncomingWebhook for Globalpay<T>
{
}

// ===== VALIDATION TRAIT IMPLEMENTATIONS =====
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ValidationTrait for Globalpay<T>
{
    fn should_do_access_token(&self) -> bool {
        true // Enable OAuth flow - framework will call CreateAccessToken before payment flows
    }
}

// ===== CONNECTOR CUSTOMER TRAIT IMPLEMENTATIONS =====
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::CreateConnectorCustomer for Globalpay<T>
{
}

// ===== MAIN CONNECTOR INTEGRATION IMPLEMENTATIONS =====
// Primary authorize implementation - customize as needed
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        Authorize,
        PaymentFlowData,
        PaymentsAuthorizeData<T>,
        PaymentsResponseData,
    > for Globalpay<T>
{
    fn get_headers(
        &self,
        req: &RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData<T>,
            PaymentsResponseData,
        >,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let mut header = vec![
            (
                headers::CONTENT_TYPE.to_string(),
                "application/json".to_string().into(),
            ),
            (
                headers::X_GP_VERSION.to_string(),
                "2021-03-22".to_string().into(),
            ),
            (
                headers::X_GP_IDEMPOTENCY.to_string(),
                req.resource_common_data
                    .connector_request_reference_id
                    .clone()
                    .into(),
            ),
        ];
        let mut auth_header = self.build_payment_headers(req)?;
        header.append(&mut auth_header);
        Ok(header)
    }

    fn get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn get_url(
        &self,
        req: &RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData<T>,
            PaymentsResponseData,
        >,
    ) -> CustomResult<String, errors::ConnectorError> {
        let base_url = &req.resource_common_data.connectors.globalpay.base_url;
        Ok(format!("{}/transactions", base_url))
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData<T>,
            PaymentsResponseData,
        >,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let request = globalpay::GlobalpayPaymentsRequest::try_from(req)?;
        Ok(Some(RequestContent::Json(Box::new(request))))
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData<T>,
            PaymentsResponseData,
        >,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<
        RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        errors::ConnectorError,
    > {
        let response: globalpay::GlobalpayPaymentsResponse = res
            .response
            .parse_struct("GlobalpayPaymentsResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        if let Some(i) = event_builder {
            i.set_response_body(&response)
        }

        RouterDataV2::try_from(ResponseRouterData {
            response,
            router_data: data.clone(),
            http_code: res.status_code,
        })
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

// ===== EMPTY IMPLEMENTATIONS FOR OTHER FLOWS =====
// Implement these as needed for your connector

// Payment Sync
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    for Globalpay<T>
{
    fn get_headers(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let mut header = vec![(
            headers::X_GP_VERSION.to_string(),
            "2021-03-22".to_string().into(),
        )];
        let mut auth_header = self.build_payment_headers(req)?;
        header.append(&mut auth_header);
        Ok(header)
    }

    fn get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn get_url(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        let transaction_id = req
            .request
            .get_connector_transaction_id()
            .change_context(errors::ConnectorError::MissingConnectorTransactionID)?;
        let base_url = &req.resource_common_data.connectors.globalpay.base_url;
        Ok(format!("{}/transactions/{}", base_url, transaction_id))
    }

    fn get_request_body(
        &self,
        _req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        Ok(None)
    }

    fn build_request_v2(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<Option<common_utils::request::Request>, errors::ConnectorError> {
        Ok(Some(
            common_utils::request::RequestBuilder::new()
                .method(common_utils::request::Method::Get)
                .url(&self.get_url(req)?)
                .attach_default_headers()
                .headers(self.get_headers(req)?)
                .build(),
        ))
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
        let response: globalpay::GlobalpayPaymentsResponse = res
            .response
            .parse_struct("GlobalpayPaymentsResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        if let Some(i) = event_builder {
            i.set_response_body(&response)
        }

        <RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>::try_from(
            ResponseRouterData {
                response,
                router_data: data.clone(),
                http_code: res.status_code,
            },
        )
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

// Payment Void
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
    for Globalpay<T>
{
    fn get_headers(
        &self,
        req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let mut header = vec![
            (
                headers::CONTENT_TYPE.to_string(),
                "application/json".to_string().into(),
            ),
            (
                headers::X_GP_VERSION.to_string(),
                "2021-03-22".to_string().into(),
            ),
            (
                headers::X_GP_IDEMPOTENCY.to_string(),
                req.resource_common_data
                    .connector_request_reference_id
                    .clone()
                    .into(),
            ),
        ];
        let mut auth_header = self.build_payment_headers(req)?;
        header.append(&mut auth_header);
        Ok(header)
    }

    fn get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn get_url(
        &self,
        req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        let transaction_id = &req.request.connector_transaction_id;
        let base_url = &req.resource_common_data.connectors.globalpay.base_url;
        Ok(format!(
            "{}/transactions/{}/reversal",
            base_url, transaction_id
        ))
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let request = globalpay::GlobalpayVoidRequest::try_from(req)?;
        Ok(Some(RequestContent::Json(Box::new(request))))
    }

    fn build_request_v2(
        &self,
        req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
    ) -> CustomResult<Option<common_utils::request::Request>, errors::ConnectorError> {
        let request_body = self.get_request_body(req)?;
        let mut request_builder = common_utils::request::RequestBuilder::new()
            .method(common_utils::request::Method::Post)
            .url(&self.get_url(req)?)
            .attach_default_headers()
            .headers(self.get_headers(req)?);

        if let Some(body) = request_body {
            request_builder = request_builder.set_body(body);
        }

        Ok(Some(request_builder.build()))
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
        let response: globalpay::GlobalpayPaymentsResponse = res
            .response
            .parse_struct("GlobalpayPaymentsResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        if let Some(i) = event_builder {
            i.set_response_body(&response)
        }

        RouterDataV2::try_from(ResponseRouterData {
            response,
            router_data: data.clone(),
            http_code: res.status_code,
        })
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

// Payment Void Post Capture
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        VoidPC,
        PaymentFlowData,
        PaymentsCancelPostCaptureData,
        PaymentsResponseData,
    > for Globalpay<T>
{
}

// Payment Capture
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
    for Globalpay<T>
{
    fn get_headers(
        &self,
        req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let mut header = vec![
            (
                headers::CONTENT_TYPE.to_string(),
                "application/json".to_string().into(),
            ),
            (
                headers::X_GP_VERSION.to_string(),
                "2021-03-22".to_string().into(),
            ),
            (
                headers::X_GP_IDEMPOTENCY.to_string(),
                req.resource_common_data
                    .connector_request_reference_id
                    .clone()
                    .into(),
            ),
        ];
        let mut auth_header = self.build_payment_headers(req)?;
        header.append(&mut auth_header);
        Ok(header)
    }

    fn get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn get_url(
        &self,
        req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        let transaction_id = req
            .request
            .get_connector_transaction_id()
            .change_context(errors::ConnectorError::MissingConnectorTransactionID)?;
        let base_url = &req.resource_common_data.connectors.globalpay.base_url;
        Ok(format!(
            "{}/transactions/{}/capture",
            base_url, transaction_id
        ))
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let request = globalpay::GlobalpayCaptureRequest::try_from(req)?;
        Ok(Some(RequestContent::Json(Box::new(request))))
    }

    fn build_request_v2(
        &self,
        req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
    ) -> CustomResult<Option<common_utils::request::Request>, errors::ConnectorError> {
        let request_body = self.get_request_body(req)?;
        let mut request_builder = common_utils::request::RequestBuilder::new()
            .method(common_utils::request::Method::Post)
            .url(&self.get_url(req)?)
            .attach_default_headers()
            .headers(self.get_headers(req)?);

        if let Some(body) = request_body {
            request_builder = request_builder.set_body(body);
        }

        Ok(Some(request_builder.build()))
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
        let response: globalpay::GlobalpayPaymentsResponse = res
            .response
            .parse_struct("GlobalpayPaymentsResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        if let Some(i) = event_builder {
            i.set_response_body(&response)
        }

        RouterDataV2::try_from(ResponseRouterData {
            response,
            router_data: data.clone(),
            http_code: res.status_code,
        })
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

// Refund
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
    for Globalpay<T>
{
    fn get_headers(
        &self,
        req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let mut header = vec![
            (
                headers::CONTENT_TYPE.to_string(),
                "application/json".to_string().into(),
            ),
            (
                headers::X_GP_VERSION.to_string(),
                "2021-03-22".to_string().into(),
            ),
            (
                headers::X_GP_IDEMPOTENCY.to_string(),
                req.resource_common_data
                    .connector_request_reference_id
                    .clone()
                    .into(),
            ),
        ];
        let mut auth_header = self.build_refund_headers(req)?;
        header.append(&mut auth_header);
        Ok(header)
    }

    fn get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn get_url(
        &self,
        req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        let transaction_id = req.request.connector_transaction_id.clone();
        let base_url = &req.resource_common_data.connectors.globalpay.base_url;
        Ok(format!(
            "{}/transactions/{}/refund",
            base_url, transaction_id
        ))
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let request = globalpay::GlobalpayRefundRequest::try_from(req)?;
        Ok(Some(RequestContent::Json(Box::new(request))))
    }

    fn build_request_v2(
        &self,
        req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> CustomResult<Option<common_utils::request::Request>, errors::ConnectorError> {
        let request_body = self.get_request_body(req)?;
        let mut request_builder = common_utils::request::RequestBuilder::new()
            .method(common_utils::request::Method::Post)
            .url(&self.get_url(req)?)
            .attach_default_headers()
            .headers(self.get_headers(req)?);

        if let Some(body) = request_body {
            request_builder = request_builder.set_body(body);
        }

        Ok(Some(request_builder.build()))
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
        let response: globalpay::GlobalpayRefundResponse = res
            .response
            .parse_struct("GlobalpayRefundResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        if let Some(i) = event_builder {
            i.set_response_body(&response)
        }

        RouterDataV2::try_from(ResponseRouterData {
            response,
            router_data: data.clone(),
            http_code: res.status_code,
        })
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

// Refund Sync
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
    for Globalpay<T>
{
    fn get_headers(
        &self,
        req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let mut header = vec![(
            headers::X_GP_VERSION.to_string(),
            "2021-03-22".to_string().into(),
        )];
        let mut auth_header = self.build_refund_headers(req)?;
        header.append(&mut auth_header);
        Ok(header)
    }

    fn get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn get_url(
        &self,
        req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        // For RSync, we need to get the refund transaction status
        // Using the connector_refund_id which is the refund transaction ID
        let refund_id = req.request.connector_refund_id.clone();
        let base_url = &req.resource_common_data.connectors.globalpay.base_url;
        Ok(format!("{}/transactions/{}", base_url, refund_id))
    }

    fn get_request_body(
        &self,
        _req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        Ok(None)
    }

    fn build_request_v2(
        &self,
        req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
    ) -> CustomResult<Option<common_utils::request::Request>, errors::ConnectorError> {
        Ok(Some(
            common_utils::request::RequestBuilder::new()
                .method(common_utils::request::Method::Get)
                .url(&self.get_url(req)?)
                .attach_default_headers()
                .headers(self.get_headers(req)?)
                .build(),
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
        let response: globalpay::GlobalpayRefundResponse = res
            .response
            .parse_struct("GlobalpayRefundResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        if let Some(i) = event_builder {
            i.set_response_body(&response)
        }

        <RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>>::try_from(
            ResponseRouterData {
                response,
                router_data: data.clone(),
                http_code: res.status_code,
            },
        )
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

// Setup Mandate
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData<T>,
        PaymentsResponseData,
    > for Globalpay<T>
{
}

// Repeat Payment
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>
    for Globalpay<T>
{
}

// Order Create
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for Globalpay<T>
{
}

// Session Token
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        CreateSessionToken,
        PaymentFlowData,
        SessionTokenRequestData,
        SessionTokenResponseData,
    > for Globalpay<T>
{
}

// Dispute Accept
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    for Globalpay<T>
{
}

// Dispute Defend
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
    for Globalpay<T>
{
}

// Submit Evidence
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
    for Globalpay<T>
{
}

// Payment Token (required by PaymentTokenV2 trait)
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        PaymentMethodToken,
        PaymentFlowData,
        PaymentMethodTokenizationData<T>,
        PaymentMethodTokenResponse,
    > for Globalpay<T>
{
}

// Access Token (required by PaymentAccessToken trait)
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        CreateAccessToken,
        PaymentFlowData,
        AccessTokenRequestData,
        AccessTokenResponseData,
    > for Globalpay<T>
{
    fn get_headers(
        &self,
        _req: &RouterDataV2<
            CreateAccessToken,
            PaymentFlowData,
            AccessTokenRequestData,
            AccessTokenResponseData,
        >,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        Ok(vec![
            (
                headers::CONTENT_TYPE.to_string(),
                "application/json".to_string().into(),
            ),
            (
                headers::X_GP_VERSION.to_string(),
                "2021-03-22".to_string().into(),
            ),
        ])
    }

    fn get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn get_url(
        &self,
        req: &RouterDataV2<
            CreateAccessToken,
            PaymentFlowData,
            AccessTokenRequestData,
            AccessTokenResponseData,
        >,
    ) -> CustomResult<String, errors::ConnectorError> {
        let base_url = &req.resource_common_data.connectors.globalpay.base_url;
        Ok(format!("{}/accesstoken", base_url))
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<
            CreateAccessToken,
            PaymentFlowData,
            AccessTokenRequestData,
            AccessTokenResponseData,
        >,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let request = globalpay::GlobalpayAccessTokenRequest::try_from(req)?;
        Ok(Some(RequestContent::Json(Box::new(request))))
    }

    fn build_request_v2(
        &self,
        req: &RouterDataV2<
            CreateAccessToken,
            PaymentFlowData,
            AccessTokenRequestData,
            AccessTokenResponseData,
        >,
    ) -> CustomResult<Option<common_utils::request::Request>, errors::ConnectorError> {
        let request_body = self.get_request_body(req)?;
        let mut request_builder = common_utils::request::RequestBuilder::new()
            .method(common_utils::request::Method::Post)
            .url(&self.get_url(req)?)
            .attach_default_headers()
            .headers(self.get_headers(req)?);

        if let Some(body) = request_body {
            request_builder = request_builder.set_body(body);
        }

        Ok(Some(request_builder.build()))
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<
            CreateAccessToken,
            PaymentFlowData,
            AccessTokenRequestData,
            AccessTokenResponseData,
        >,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<
        RouterDataV2<
            CreateAccessToken,
            PaymentFlowData,
            AccessTokenRequestData,
            AccessTokenResponseData,
        >,
        errors::ConnectorError,
    > {
        let response: globalpay::GlobalpayAccessTokenResponse = res
            .response
            .parse_struct("GlobalpayAccessTokenResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        if let Some(i) = event_builder {
            i.set_response_body(&response)
        }

        RouterDataV2::try_from(ResponseRouterData {
            response,
            router_data: data.clone(),
            http_code: res.status_code,
        })
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

// ===== AUTHENTICATION FLOW CONNECTOR INTEGRATIONS =====
// Pre Authentication
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        PreAuthenticate,
        PaymentFlowData,
        PaymentsPreAuthenticateData<T>,
        PaymentsResponseData,
    > for Globalpay<T>
{
}

// Authentication
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        Authenticate,
        PaymentFlowData,
        PaymentsAuthenticateData<T>,
        PaymentsResponseData,
    > for Globalpay<T>
{
}

// Post Authentication
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        PostAuthenticate,
        PaymentFlowData,
        PaymentsPostAuthenticateData<T>,
        PaymentsResponseData,
    > for Globalpay<T>
{
}

// ===== CONNECTOR CUSTOMER CONNECTOR INTEGRATIONS =====
// Create Connector Customer
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        domain_types::connector_flow::CreateConnectorCustomer,
        PaymentFlowData,
        ConnectorCustomerData,
        ConnectorCustomerResponse,
    > for Globalpay<T>
{
}

// ===== SOURCE VERIFICATION IMPLEMENTATIONS =====
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        Authorize,
        PaymentFlowData,
        PaymentsAuthorizeData<T>,
        PaymentsResponseData,
    > for Globalpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        PSync,
        PaymentFlowData,
        PaymentsSyncData,
        PaymentsResponseData,
    > for Globalpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        Capture,
        PaymentFlowData,
        PaymentsCaptureData,
        PaymentsResponseData,
    > for Globalpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        Void,
        PaymentFlowData,
        PaymentVoidData,
        PaymentsResponseData,
    > for Globalpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        VoidPC,
        PaymentFlowData,
        PaymentsCancelPostCaptureData,
        PaymentsResponseData,
    > for Globalpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        Refund,
        RefundFlowData,
        RefundsData,
        RefundsResponseData,
    > for Globalpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        RSync,
        RefundFlowData,
        RefundSyncData,
        RefundsResponseData,
    > for Globalpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData<T>,
        PaymentsResponseData,
    > for Globalpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        Accept,
        DisputeFlowData,
        AcceptDisputeData,
        DisputeResponseData,
    > for Globalpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        SubmitEvidence,
        DisputeFlowData,
        SubmitEvidenceData,
        DisputeResponseData,
    > for Globalpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        DefendDispute,
        DisputeFlowData,
        DisputeDefendData,
        DisputeResponseData,
    > for Globalpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for Globalpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        RepeatPayment,
        PaymentFlowData,
        RepeatPaymentData,
        PaymentsResponseData,
    > for Globalpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        CreateSessionToken,
        PaymentFlowData,
        SessionTokenRequestData,
        SessionTokenResponseData,
    > for Globalpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        PaymentMethodToken,
        PaymentFlowData,
        PaymentMethodTokenizationData<T>,
        PaymentMethodTokenResponse,
    > for Globalpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        CreateAccessToken,
        PaymentFlowData,
        AccessTokenRequestData,
        AccessTokenResponseData,
    > for Globalpay<T>
{
}

// ===== AUTHENTICATION FLOW SOURCE VERIFICATION =====
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        PreAuthenticate,
        PaymentFlowData,
        PaymentsPreAuthenticateData<T>,
        PaymentsResponseData,
    > for Globalpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        Authenticate,
        PaymentFlowData,
        PaymentsAuthenticateData<T>,
        PaymentsResponseData,
    > for Globalpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        PostAuthenticate,
        PaymentFlowData,
        PaymentsPostAuthenticateData<T>,
        PaymentsResponseData,
    > for Globalpay<T>
{
}

// ===== CONNECTOR CUSTOMER SOURCE VERIFICATION =====
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        domain_types::connector_flow::CreateConnectorCustomer,
        PaymentFlowData,
        ConnectorCustomerData,
        ConnectorCustomerResponse,
    > for Globalpay<T>
{
}

// ===== CONNECTOR COMMON IMPLEMENTATION =====
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> ConnectorCommon
    for Globalpay<T>
{
    fn id(&self) -> &'static str {
        "globalpay"
    }

    fn get_currency_unit(&self) -> CurrencyUnit {
        CurrencyUnit::Minor
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn base_url<'a>(&self, _connectors: &'a Connectors) -> &'a str {
        "https://apis.sandbox.globalpay.com/ucp"
    }

    fn get_auth_header(
        &self,
        _auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        // Note: This method should not be used for OAuth-based connectors
        // Use build_payment_headers or build_refund_headers instead
        Err(errors::ConnectorError::FailedToObtainAuthType.into())
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        // Try to parse as structured error first
        let error_response = match res
            .response
            .parse_struct::<globalpay::GlobalpayErrorResponse>("GlobalpayErrorResponse")
        {
            Ok(response) => {
                if let Some(i) = event_builder {
                    i.set_error_response_body(&response)
                }
                ErrorResponse {
                    status_code: res.status_code,
                    code: response.code.unwrap_or_else(|| "UNKNOWN_ERROR".to_string()),
                    message: response
                        .message
                        .unwrap_or_else(|| "Unknown error from GlobalPay".to_string()),
                    reason: None,
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                }
            }
            Err(_) => {
                // If structured parsing fails, use the raw response as the error message
                let raw_response = String::from_utf8(res.response.to_vec())
                    .unwrap_or_else(|_| "Non-UTF8 response".to_string());

                ErrorResponse {
                    status_code: res.status_code,
                    code: format!("HTTP_{}", res.status_code),
                    message: format!("GlobalPay API error: {}", raw_response),
                    reason: None,
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                }
            }
        };

        Ok(error_response)
    }
}

// Helper functions for building headers with OAuth token
impl<T: PaymentMethodDataTypes> Globalpay<T> {
    pub fn build_payment_headers<F, Req, Res>(
        &self,
        req: &RouterDataV2<F, PaymentFlowData, Req, Res>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let access_token = req
            .resource_common_data
            .get_access_token()
            .change_context(errors::ConnectorError::FailedToObtainAuthType)
            .attach_printable("Failed to get OAuth access token for GlobalPay")?;

        Ok(vec![(
            headers::AUTHORIZATION.to_string(),
            format!("Bearer {}", access_token).into_masked(),
        )])
    }

    pub fn build_refund_headers<F, Req, Res>(
        &self,
        req: &RouterDataV2<F, RefundFlowData, Req, Res>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let access_token = req
            .resource_common_data
            .get_access_token()
            .change_context(errors::ConnectorError::FailedToObtainAuthType)
            .attach_printable("Failed to get OAuth access token for GlobalPay refund flow")?;

        Ok(vec![(
            headers::AUTHORIZATION.to_string(),
            format!("Bearer {}", access_token).into_masked(),
        )])
    }
}
