pub mod transformers;
use common_utils::Maskable;

use std::fmt::Debug;
use common_enums::CurrencyUnit;
use common_utils::{errors::CustomResult, ext_traits::ByteSliceExt,
    Maskable,
};
use domain_types::{
    connector_flow::{
        Accept, Authenticate, Authorize, Capture, CreateAccessToken, CreateConnectorCustomer,
        CreateOrder, CreateSessionToken, DefendDispute, PSync, PaymentMethodToken,
        PostAuthenticate, PreAuthenticate, RSync, Refund, RepeatPayment, SetupMandate,
        SubmitEvidence, Void,
    },
    connector_types::{
        AcceptDisputeData, AccessTokenRequestData, AccessTokenResponseData, ConnectorCustomerData,
        ConnectorCustomerResponse, DisputeDefendData, DisputeFlowData, DisputeResponseData,
        PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData,
        PaymentMethodTokenResponse, PaymentMethodTokenizationData, PaymentVoidData,
        PaymentsAuthenticateData, PaymentsAuthorizeData, PaymentsCaptureData,
        PaymentsPostAuthenticateData, PaymentsPreAuthenticateData, PaymentsResponseData,
        PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData,
        RepeatPaymentData, SessionTokenRequestData, SessionTokenResponseData,
        SetupMandateRequestData, SubmitEvidenceData,
    },
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data::ErrorResponse,
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
};
// use crate::masking::{Mask, Maskable};
use interfaces::{
    api::ConnectorCommon, connector_integration_v2::ConnectorIntegrationV2, connector_types,
    events::connector_api_logs::ConnectorEvent,
};
use serde::Serialize;
use transformers::{
    self as volt, VoltAuthUpdateRequest, VoltAuthUpdateResponse, VoltPaymentsRequest,
    VoltPaymentsResponse, VoltPsyncRequest, VoltPsyncResponse,
};
use super::macros;
use crate::{types::ResponseRouterData, with_error_response_body};
pub const BASE64_ENGINE: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
use error_stack::ResultExt;
// Trait implementations with generic type parameters
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ConnectorServiceTrait<T> for Volt<T>
{
}
    connector_types::PaymentAuthorizeV2<T> for Volt<T>
    connector_types::PaymentSyncV2 for Volt<T>
    connector_types::PaymentVoidV2 for Volt<T>
    connector_types::PaymentVoidPostCaptureV2 for Volt<T>
    connector_types::RefundSyncV2 for Volt<T>
    connector_types::RefundV2 for Volt<T>
    connector_types::PaymentCapture for Volt<T>
    connector_types::ValidationTrait for Volt<T>
    fn should_do_access_token(&self) -> bool {
        true
    }
    connector_types::PaymentOrderCreate for Volt<T>
    connector_types::SetupMandateV2<T> for Volt<T>
    connector_types::RepeatPaymentV2 for Volt<T>
    connector_types::AcceptDispute for Volt<T>
    connector_types::SubmitEvidenceV2 for Volt<T>
    connector_types::DisputeDefend for Volt<T>
    connector_types::IncomingWebhook for Volt<T>
    connector_types::PaymentSessionToken for Volt<T>
    connector_types::PaymentAccessToken for Volt<T>
    connector_types::CreateConnectorCustomer for Volt<T>
    connector_types::PaymentTokenV2<T> for Volt<T>
    connector_types::PaymentPreAuthenticateV2<T> for Volt<T>
    connector_types::PaymentAuthenticateV2<T> for Volt<T>
    connector_types::PaymentPostAuthenticateV2<T> for Volt<T>
    ConnectorIntegrationV2<
        domain_types::connector_flow::VoidPC,
        PaymentFlowData,
        domain_types::connector_types::PaymentsCancelPostCaptureData,
        PaymentsResponseData,
    > for Volt<T>
pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const AUTHORIZATION: &str = "Authorization";
macros::create_all_prerequisites!(
    connector_name: Volt,
    generic_type: T,
    api: [
        (
            flow: CreateAccessToken,
            request_body: VoltAuthUpdateRequest,
            response_body: VoltAuthUpdateResponse,
            router_data: RouterDataV2<CreateAccessToken, PaymentFlowData, AccessTokenRequestData, AccessTokenResponseData>,
        ),
            flow: Authorize,
            request_body: VoltPaymentsRequest,
            response_body: VoltPaymentsResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            flow: PSync,
            request_body: VoltPsyncRequest,
            response_body: VoltPsyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        )
    ],
    amount_converters: [],
    member_functions: {
        pub fn build_headers<F, Req, Res>(
            &self,
            req: &RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError>
        where
            Self: ConnectorIntegrationV2<F, PaymentFlowData, Req, Res>,
        {
            let mut header = vec![(
                headers::CONTENT_TYPE.to_string(),
                "application/json".to_string().into(),
            )];
            // Add Bearer token for access token authentication
            let access_token = req.resource_common_data
                .get_access_token()
                .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
            let auth_header = (
                headers::AUTHORIZATION.to_string(),
                format!("Bearer {access_token}").into_masked(),
            );
            header.push(auth_header);
            Ok(header)
        }
        pub fn connector_base_url<F, Req, Res>(
        ) -> String {
            req.resource_common_data.connectors.volt.base_url.to_string()
);
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> ConnectorCommon
    for Volt<T>
    fn id(&self) -> &'static str {
        "volt"
    fn get_currency_unit(&self) -> CurrencyUnit {
        CurrencyUnit::Minor
    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        &connectors.volt.base_url
    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: volt::VoltErrorResponse = res
            .response
            .parse_struct("VoltErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        with_error_response_body!(event_builder, response);
        let reason = match &response.exception.error_list {
            Some(error_list) => error_list
                .iter()
                .map(|error| error.message.clone())
                .collect::<Vec<String>>()
                .join(" & "),
            None => response.exception.message.clone(),
        };
        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response.exception.message.to_string(),
            message: response.exception.message.clone(),
            reason: Some(reason),
            attempt_status: None,
            connector_transaction_id: None,
            network_advice_code: None,
            network_decline_code: None,
            network_error_message: None,
        })
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Volt,
    curl_request: Json(VoltPaymentsRequest),
    curl_response: VoltPaymentsResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req)
        fn get_url(
        ) -> CustomResult<String, errors::ConnectorError> {
            let base_url = self.connector_base_url(req);
            Ok(format!("{base_url}v2/payments"))
    curl_request: FormUrlEncoded(VoltAuthUpdateRequest),
    curl_response: VoltAuthUpdateResponse,
    flow_name: CreateAccessToken,
    flow_request: AccessTokenRequestData,
    flow_response: AccessTokenResponseData,
            _req: &RouterDataV2<CreateAccessToken, PaymentFlowData, AccessTokenRequestData, AccessTokenResponseData>,
            Ok(vec![(
                "application/x-www-form-urlencoded".to_string().into(),
            )])
            req: &RouterDataV2<CreateAccessToken, PaymentFlowData, AccessTokenRequestData, AccessTokenResponseData>,
            Ok(format!("{base_url}oauth"))
    curl_request: Json(VoltPsyncRequest),
    curl_response: VoltPsyncResponse,
    flow_name: PSync,
    flow_request: PaymentsSyncData,
    http_method: Get,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            let connector_payment_id = req
                .request
                .connector_transaction_id
                .get_connector_transaction_id()
                .change_context(errors::ConnectorError::MissingConnectorTransactionID)?;
            Ok(format!("{base_url}payments/{connector_payment_id}"))
// Stub implementations for unsupported flows (required by macro system)
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
    > ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
    > ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData> for Volt<T>
    > ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
    >
        CreateOrder,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
    > ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
    > ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
        SetupMandate,
        SetupMandateRequestData<T>,
    ConnectorIntegrationV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>
        CreateSessionToken,
        SessionTokenRequestData,
        SessionTokenResponseData,
        CreateConnectorCustomer,
        ConnectorCustomerData,
        ConnectorCustomerResponse,
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
        Authorize,
        PaymentsAuthorizeData<T>,
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
        RepeatPayment,
        RepeatPaymentData,
        CreateAccessToken,
        AccessTokenRequestData,
        AccessTokenResponseData,
