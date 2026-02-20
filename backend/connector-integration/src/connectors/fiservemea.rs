pub mod transformers;

use std::fmt::Debug;

use common_enums::CurrencyUnit;
use common_utils::{errors::CustomResult, events, ext_traits::ByteSliceExt, types::StringMajorUnit};
use domain_types::{
    connector_flow::{
        Accept, Authenticate, Authorize, Capture, CreateAccessToken, CreateConnectorCustomer,
        CreateOrder, CreateSessionToken, DefendDispute, IncrementalAuthorization, MandateRevoke,
        PSync, PaymentMethodToken, PostAuthenticate, PreAuthenticate, RSync, Refund, RepeatPayment,
        SdkSessionToken, SetupMandate, SubmitEvidence, Void, VoidPC,
    },
    connector_types::{
        AcceptDisputeData, AccessTokenRequestData, AccessTokenResponseData, ConnectorCustomerData,
        ConnectorCustomerResponse, DisputeDefendData, DisputeFlowData, DisputeResponseData,
        MandateRevokeRequestData, MandateRevokeResponseData, PaymentCreateOrderData,
        PaymentCreateOrderResponse, PaymentFlowData, PaymentMethodTokenResponse,
        PaymentMethodTokenizationData, PaymentVoidData, PaymentsAuthenticateData,
        PaymentsAuthorizeData, PaymentsCancelPostCaptureData, PaymentsCaptureData,
        PaymentsIncrementalAuthorizationData, PaymentsPostAuthenticateData,
        PaymentsPreAuthenticateData, PaymentsResponseData, PaymentsSdkSessionTokenData,
        PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData,
        RepeatPaymentData, ResponseId, SessionTokenRequestData, SessionTokenResponseData,
        SetupMandateRequestData, SubmitEvidenceData,
    },
    errors::{self, ConnectorError},
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, Mask, Maskable, PeekInterface};
use interfaces::{
    api::ConnectorCommon, connector_integration_v2::ConnectorIntegrationV2, connector_types,
    verification::SourceVerification,
};
use serde::Serialize;
use transformers::{
    FiservemeaAuthorizeRequest, FiservemeaAuthorizeResponse, FiservemeaCaptureRequest,
    FiservemeaCaptureResponse, FiservemeaErrorResponse, FiservemeaRefundRequest,
    FiservemeaRefundResponse, FiservemeaRSyncRequest, FiservemeaRSyncResponse,
    FiservemeaSyncRequest, FiservemeaSyncResponse, FiservemeaVoidRequest, FiservemeaVoidResponse,
};

use super::macros;
use crate::{types::ResponseRouterData, with_error_response_body};

pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const API_KEY: &str = "Api-Key";
    pub(crate) const CLIENT_REQUEST_ID: &str = "Client-Request-Id";
    pub(crate) const TIMESTAMP: &str = "Timestamp";
    pub(crate) const MESSAGE_SIGNATURE: &str = "Message-Signature";
}

// =============================================================================
// CONNECTOR STRUCT
// =============================================================================
#[derive(Debug, Clone)]
pub struct Fiservemea<T: PaymentMethodDataTypes> {
    payment_method_type: std::marker::PhantomData<T>,
}

impl<T: PaymentMethodDataTypes> Fiservemea<T> {
    pub const fn new() -> &'static Self {
        &Self {
            payment_method_type: std::marker::PhantomData,
        }
    }
}

// =============================================================================
// TRAIT IMPLEMENTATIONS
// =============================================================================
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ConnectorServiceTrait<T> for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAuthorizeV2<T> for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentSyncV2 for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentCapture for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentVoidV2 for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundV2 for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundSyncV2 for Fiservemea<T>
{
}

// =============================================================================
// MACRO PREREQUISITES
// =============================================================================
macros::create_all_prerequisites!(
    connector_name: Fiservemea,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: FiservemeaAuthorizeRequest<T>,
            response_body: FiservemeaAuthorizeResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: PSync,
            request_body: FiservemeaSyncRequest,
            response_body: FiservemeaSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ),
        (
            flow: Capture,
            request_body: FiservemeaCaptureRequest,
            response_body: FiservemeaCaptureResponse,
            router_data: RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ),
        (
            flow: Refund,
            request_body: FiservemeaRefundRequest,
            response_body: FiservemeaRefundResponse,
            router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ),
        (
            flow: RSync,
            request_body: FiservemeaRSyncRequest,
            response_body: FiservemeaRSyncResponse,
            router_data: RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ),
        (
            flow: Void,
            request_body: FiservemeaVoidRequest,
            response_body: FiservemeaVoidResponse,
            router_data: RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ),
    ],
    amount_converters: [
        amount_converter: StringMajorUnit
    ],
    member_functions: {
        /// Build headers with Message-Signature authentication
        /// Headers: Content-Type, Api-Key, Client-Request-Id, Timestamp, Message-Signature
        pub fn build_headers<F, FCD, Req, Res>(
            &self,
            req: &RouterDataV2<F, FCD, Req, Res>,
            request_body: Option<&str>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError>
        where
            F: domain_types::connector_flow::FlowTypes,
            FCD: Clone,
            Req: Clone,
            Res: Clone,
        {
            let auth = fiservemea::FiservemeaAuthType::try_from(&req.connector_auth_type)
                .change_context(errors::ConnectorError::FailedToObtainAuthType)?;

            let timestamp = chrono::Utc::now().timestamp_millis().to_string();
            let client_request_id = uuid::Uuid::new_v4().to_string();
            let body_str = request_body.unwrap_or("");

            let signature = auth.generate_signature(&client_request_id, &timestamp, body_str);

            Ok(vec![
                (
                    headers::CONTENT_TYPE.to_string(),
                    "application/json".to_string().into(),
                ),
                (
                    headers::API_KEY.to_string(),
                    auth.api_key.peek().to_string().into(),
                ),
                (
                    headers::CLIENT_REQUEST_ID.to_string(),
                    client_request_id.into(),
                ),
                (
                    headers::TIMESTAMP.to_string(),
                    timestamp.into(),
                ),
                (
                    headers::MESSAGE_SIGNATURE.to_string(),
                    signature.into(),
                ),
            ])
        }

        pub fn connector_base_url_payments<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.fiservemea.base_url
        }

        pub fn connector_base_url_refunds<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, RefundFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.fiservemea.base_url
        }
    }
);

// =============================================================================
// CONNECTOR COMMON IMPLEMENTATION
// =============================================================================
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> ConnectorCommon
    for Fiservemea<T>
{
    fn id(&self) -> &'static str {
        "fiservemea"
    }

    fn get_currency_unit(&self) -> CurrencyUnit {
        CurrencyUnit::Minor
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.fiservemea.base_url.as_ref()
    }

    fn get_auth_header(
        &self,
        _auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        // Auth headers are built in build_headers method with signature
        Ok(vec![])
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut events::Event>,
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        let response: fiservemea::FiservemeaErrorResponse = if res.response.is_empty() {
            fiservemea::FiservemeaErrorResponse::default()
        } else {
            res.response
                .parse_struct("FiservemeaErrorResponse")
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?
        };

        with_error_response_body!(event_builder, response);

        let error_detail = response.error.unwrap_or(fiservemea::FiservemeaErrorDetail {
            code: "UNKNOWN_ERROR".to_string(),
            message: "Unknown error occurred".to_string(),
            details: None,
            decline_reason_code: None,
        });

        Ok(domain_types::router_data::ErrorResponse {
            status_code: res.status_code,
            code: error_detail.code,
            message: error_detail.message,
            reason: error_detail.decline_reason_code,
            attempt_status: None,
            connector_transaction_id: None,
            network_decline_code: None,
            network_advice_code: None,
            network_error_message: None,
        })
    }
}

// =============================================================================
// AUTHORIZE FLOW IMPLEMENTATION
// =============================================================================
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Fiservemea,
    curl_request: Json(FiservemeaAuthorizeRequest),
    curl_response: FiservemeaAuthorizeResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            // Serialize request body for signature generation
            let connector_req = FiservemeaAuthorizeRequest::try_from(
                FiservemeaRouterData::try_from((
                    self.amount_converter.convert(
                        req.request.minor_amount,
                        req.request.currency
                    ).change_context(errors::ConnectorError::RequestEncodingFailed)?,
                    req.clone(),
                    std::marker::PhantomData::<T>,
                )).change_context(errors::ConnectorError::RequestEncodingFailed)?
            ).change_context(errors::ConnectorError::RequestEncodingFailed)?;

            let body_str = serde_json::to_string(&connector_req)
                .change_context(errors::ConnectorError::RequestEncodingFailed)?;

            self.build_headers(req, Some(&body_str))
        }

        fn get_url(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            let base_url = self.connector_base_url_payments(req);
            Ok(format!("{}/ipp/payments-gateway/v2/payments", base_url))
        }
    }
);

// =============================================================================
// PSYNC FLOW IMPLEMENTATION
// =============================================================================
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Fiservemea,
    curl_response: FiservemeaSyncResponse,
    flow_name: PSync,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsSyncData,
    flow_response: PaymentsResponseData,
    http_method: Get,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            // GET request has no body, so signature uses empty body
            self.build_headers(req, None)
        }

        fn get_url(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            let transaction_id = req.request.get_connector_transaction_id()
                .change_context(errors::ConnectorError::MissingConnectorTransactionID)?;
            let base_url = self.connector_base_url_payments(req);
            Ok(format!("{}/ipp/payments-gateway/v2/payments/{}", base_url, transaction_id))
        }
    }
);

// =============================================================================
// CAPTURE FLOW IMPLEMENTATION
// =============================================================================
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Fiservemea,
    curl_request: Json(FiservemeaCaptureRequest),
    curl_response: FiservemeaCaptureResponse,
    flow_name: Capture,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsCaptureData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            // Serialize request body for signature generation
            let connector_req = FiservemeaCaptureRequest::try_from(
                FiservemeaRouterData::try_from((
                    self.amount_converter.convert(
                        req.request.minor_amount_to_capture,
                        req.request.currency
                    ).change_context(errors::ConnectorError::RequestEncodingFailed)?,
                    req.clone(),
                    (),
                )).change_context(errors::ConnectorError::RequestEncodingFailed)?
            ).change_context(errors::ConnectorError::RequestEncodingFailed)?;

            let body_str = serde_json::to_string(&connector_req)
                .change_context(errors::ConnectorError::RequestEncodingFailed)?;

            self.build_headers(req, Some(&body_str))
        }

        fn get_url(
            &self,
            req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            let transaction_id = req.request.connector_transaction_id.clone()
                .ok_or(errors::ConnectorError::MissingConnectorTransactionID)?;
            let base_url = self.connector_base_url_payments(req);
            Ok(format!("{}/ipp/payments-gateway/v2/payments/{}", base_url, transaction_id))
        }
    }
);

// =============================================================================
// REFUND FLOW IMPLEMENTATION
// =============================================================================
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Fiservemea,
    curl_request: Json(FiservemeaRefundRequest),
    curl_response: FiservemeaRefundResponse,
    flow_name: Refund,
    resource_common_data: RefundFlowData,
    flow_request: RefundsData,
    flow_response: RefundsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            // Serialize request body for signature generation
            let connector_req = FiservemeaRefundRequest::try_from(
                FiservemeaRouterData::try_from((
                    self.amount_converter.convert(
                        req.request.minor_refund_amount,
                        req.request.currency
                    ).change_context(errors::ConnectorError::RequestEncodingFailed)?,
                    req.clone(),
                    (),
                )).change_context(errors::ConnectorError::RequestEncodingFailed)?
            ).change_context(errors::ConnectorError::RequestEncodingFailed)?;

            let body_str = serde_json::to_string(&connector_req)
                .change_context(errors::ConnectorError::RequestEncodingFailed)?;

            self.build_headers(req, Some(&body_str))
        }

        fn get_url(
            &self,
            req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            let transaction_id = req.request.connector_transaction_id.clone();
            let base_url = self.connector_base_url_refunds(req);
            Ok(format!("{}/ipp/payments-gateway/v2/payments/{}", base_url, transaction_id))
        }
    }
);

// =============================================================================
// RSYNC FLOW IMPLEMENTATION
// =============================================================================
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Fiservemea,
    curl_response: FiservemeaRSyncResponse,
    flow_name: RSync,
    resource_common_data: RefundFlowData,
    flow_request: RefundSyncData,
    flow_response: RefundsResponseData,
    http_method: Get,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            // GET request has no body, so signature uses empty body
            self.build_headers(req, None)
        }

        fn get_url(
            &self,
            req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            let refund_id = req.request.connector_refund_id.clone();
            let base_url = self.connector_base_url_refunds(req);
            Ok(format!("{}/ipp/payments-gateway/v2/payments/{}", base_url, refund_id))
        }
    }
);

// =============================================================================
// VOID FLOW IMPLEMENTATION
// =============================================================================
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Fiservemea,
    curl_request: Json(FiservemeaVoidRequest),
    curl_response: FiservemeaVoidResponse,
    flow_name: Void,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentVoidData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            // Serialize request body for signature generation
            let connector_req = FiservemeaVoidRequest::try_from(
                FiservemeaRouterData::try_from((
                    StringMajorUnit::from("0.00".to_string()), // Void doesn't need amount
                    req.clone(),
                    (),
                )).change_context(errors::ConnectorError::RequestEncodingFailed)?
            ).change_context(errors::ConnectorError::RequestEncodingFailed)?;

            let body_str = serde_json::to_string(&connector_req)
                .change_context(errors::ConnectorError::RequestEncodingFailed)?;

            self.build_headers(req, Some(&body_str))
        }

        fn get_url(
            &self,
            req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            let transaction_id = req.request.connector_transaction_id.clone();
            let base_url = self.connector_base_url_payments(req);
            Ok(format!("{}/ipp/payments-gateway/v2/payments/{}", base_url, transaction_id))
        }
    }
);

// =============================================================================
// SOURCE VERIFICATION STUBS
// =============================================================================
use interfaces::verification::SourceVerification;

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    SourceVerification<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
    for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    SourceVerification<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    SourceVerification<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
    for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    SourceVerification<Refund, RefundFlowData, RefundsData, RefundsResponseData> for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    SourceVerification<RSync, RefundFlowData, RefundSyncData, RefundsResponseData> for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    SourceVerification<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
    for Fiservemea<T>
{
}

// =============================================================================
// STUB IMPLEMENTATIONS FOR UNSUPPORTED FLOWS
// =============================================================================
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        connector_flow::Accept,
        DisputeFlowData,
        AcceptDisputeData,
        DisputeResponseData,
    > for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        connector_flow::CreateConnectorCustomer,
        PaymentFlowData,
        ConnectorCustomerData,
        ConnectorCustomerResponse,
    > for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        connector_flow::DefendDispute,
        DisputeFlowData,
        DisputeDefendData,
        DisputeResponseData,
    > for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        connector_flow::MandateRevoke,
        PaymentFlowData,
        MandateRevokeRequestData,
        MandateRevokeResponseData,
    > for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        connector_flow::CreateAccessToken,
        PaymentFlowData,
        AccessTokenRequestData,
        AccessTokenResponseData,
    > for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        connector_flow::Authenticate,
        PaymentFlowData,
        PaymentsAuthenticateData<T>,
        PaymentsResponseData,
    > for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        connector_flow::IncrementalAuthorization,
        PaymentFlowData,
        PaymentsIncrementalAuthorizationData,
        PaymentsResponseData,
    > for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        connector_flow::CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        connector_flow::PostAuthenticate,
        PaymentFlowData,
        PaymentsPostAuthenticateData<T>,
        PaymentsResponseData,
    > for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        connector_flow::PreAuthenticate,
        PaymentFlowData,
        PaymentsPreAuthenticateData<T>,
        PaymentsResponseData,
    > for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        connector_flow::CreateSessionToken,
        PaymentFlowData,
        SessionTokenRequestData,
        SessionTokenResponseData,
    > for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        connector_flow::PaymentMethodToken,
        PaymentFlowData,
        PaymentMethodTokenizationData<T>,
        PaymentMethodTokenResponse,
    > for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        connector_flow::VoidPC,
        PaymentFlowData,
        PaymentsCancelPostCaptureData,
        PaymentsResponseData,
    > for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        connector_flow::RepeatPayment,
        PaymentFlowData,
        RepeatPaymentData<T>,
        PaymentsResponseData,
    > for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        connector_flow::SdkSessionToken,
        PaymentFlowData,
        PaymentsSdkSessionTokenData,
        PaymentsResponseData,
    > for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        connector_flow::SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData<T>,
        PaymentsResponseData,
    > for Fiservemea<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        connector_flow::SubmitEvidence,
        DisputeFlowData,
        SubmitEvidenceData,
        DisputeResponseData,
    > for Fiservemea<T>
{
}

// =============================================================================
// SOURCE VERIFICATION FOR REMAINING FLOWS
// =============================================================================
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification for Fiservemea<T>
{
}
