pub mod aci_result_codes;
use common_utils::Maskable;
pub mod transformers;

use common_utils::{errors::CustomResult, ext_traits::ByteSliceExt, StringMajorUnit,
    Maskable,
};
use domain_types::{
    connector_flow::{
        Accept, Authenticate, Authorize, Capture, CreateAccessToken, CreateConnectorCustomer,
        CreateOrder, CreateSessionToken, DefendDispute, PSync, PaymentMethodToken,
        PostAuthenticate, PreAuthenticate, RSync, Refund, RepeatPayment, SetupMandate,
        SubmitEvidence, Void, VoidPC,
    },
    connector_types::{
        AcceptDisputeData, AccessTokenRequestData, AccessTokenResponseData, ConnectorCustomerData,
        ConnectorCustomerResponse, DisputeDefendData, DisputeFlowData, DisputeResponseData,
        MandateReferenceId, PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData,
        PaymentMethodTokenResponse, PaymentMethodTokenizationData, PaymentVoidData,
        PaymentsAuthenticateData, PaymentsAuthorizeData, PaymentsCancelPostCaptureData,
        PaymentsCaptureData, PaymentsPostAuthenticateData, PaymentsPreAuthenticateData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData,
        RefundsResponseData, RepeatPaymentData, SessionTokenRequestData, SessionTokenResponseData,
        SetupMandateRequestData, SubmitEvidenceData,
    },
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
use error_stack::ResultExt;
// use crate::masking::{Mask, Maskable, PeekInterface};
use interfaces::{
    api::ConnectorCommon, connector_integration_v2::ConnectorIntegrationV2, connector_types,
    events::connector_api_logs::ConnectorEvent,
use common_enums::CurrencyUnit;
use serde::Serialize;
use std::fmt::Debug;
use transformers::{
    self as aci, AciCancelRequest, AciCaptureRequest, AciCaptureResponse, AciMandateRequest,
    AciMandateResponse, AciPaymentsRequest, AciPaymentsResponse,
    AciPaymentsResponse as AciPaymentsSyncResponse,
    AciPaymentsResponse as AciRepeatPaymentResponse, AciRefundRequest, AciRefundResponse,
    AciRepeatPaymentRequest, AciVoidResponse,
use super::macros;
use crate::{types::ResponseRouterData, with_error_response_body};
pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const AUTHORIZATION: &str = "Authorization";
}
// Trait implementations with generic type parameters
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentPreAuthenticateV2<T> for Aci<T>
{
    connector_types::PaymentAuthenticateV2<T> for Aci<T>
    connector_types::PaymentPostAuthenticateV2<T> for Aci<T>
    connector_types::ConnectorServiceTrait<T> for Aci<T>
    connector_types::PaymentAuthorizeV2<T> for Aci<T>
    connector_types::PaymentSyncV2 for Aci<T>
    connector_types::PaymentVoidV2 for Aci<T>
    connector_types::RefundSyncV2 for Aci<T>
    connector_types::RefundV2 for Aci<T>
    connector_types::PaymentCapture for Aci<T>
    connector_types::ValidationTrait for Aci<T>
    connector_types::SetupMandateV2<T> for Aci<T>
    connector_types::RepeatPaymentV2 for Aci<T>
    connector_types::AcceptDispute for Aci<T>
    connector_types::SubmitEvidenceV2 for Aci<T>
    connector_types::DisputeDefend for Aci<T>
    connector_types::IncomingWebhook for Aci<T>
    connector_types::PaymentOrderCreate for Aci<T>
    connector_types::PaymentSessionToken for Aci<T>
    connector_types::PaymentAccessToken for Aci<T>
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::CreateConnectorCustomer for Aci<T>
    connector_types::PaymentTokenV2<T> for Aci<T>
    connector_types::PaymentVoidPostCaptureV2 for Aci<T>
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> ConnectorCommon
    for Aci<T>
    fn id(&self) -> &'static str {
        "aci"
    }
    fn get_currency_unit(&self) -> CurrencyUnit {
        CurrencyUnit::Base
    fn common_get_content_type(&self) -> &'static str {
        "application/x-www-form-urlencoded"
    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.aci.base_url.as_ref()
    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, common_utils::Maskable<String>)>, errors::ConnectorError>
    {
        let auth = aci::AciAuthType::try_from(auth_type)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        Ok(vec![(
            headers::AUTHORIZATION.to_string(),
            format!("Bearer {}", auth.api_key.peek()).into_masked(),
        )])
    fn build_error_response(
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: aci::AciErrorResponse = res
            .response
            .parse_struct("AciErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        with_error_response_body!(event_builder, response);
        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response.result.code,
            message: response.result.description,
            reason: response.result.parameter_errors.map(|errors| {
                errors
                    .into_iter()
                    .map(|error_description| {
                        format!(
                            "Field is {} and the message is {}",
                            error_description.name, error_description.message
                        )
                    })
                    .collect::<Vec<String>>()
                    .join("; ")
            }),
            attempt_status: None,
            connector_transaction_id: None,
            network_advice_code: None,
            network_decline_code: None,
            network_error_message: None,
        })
macros::create_all_prerequisites!(
    connector_name: Aci,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: AciPaymentsRequest<T>,
            response_body: AciPaymentsResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
            flow: SetupMandate,
            request_body: AciMandateRequest<T>,
            response_body: AciMandateResponse,
            router_data: RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>,
            flow: PSync,
            response_body: AciPaymentsSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            flow: Capture,
            request_body: AciCaptureRequest,
            response_body: AciCaptureResponse,
            router_data: RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            flow: Void,
            request_body: AciCancelRequest,
            response_body: AciVoidResponse,
            router_data: RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            flow: Refund,
            request_body: AciRefundRequest,
            response_body: AciRefundResponse,
            router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            flow: RepeatPayment,
            request_body: AciRepeatPaymentRequest<T>,
            response_body: AciRepeatPaymentResponse,
            router_data: RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>,
        )
    ],
    amount_converters: [
        amount_converter: StringMajorUnit
    member_functions: {
        pub fn build_headers<F, FCD, Req, Res>(
            &self,
            req: &RouterDataV2<F, FCD, Req, Res>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError>
        where
            Self: ConnectorIntegrationV2<F, FCD, Req, Res>,
        {
        let mut header = vec![(
            headers::CONTENT_TYPE.to_string(),
            self.common_get_content_type().to_string().into(),
        )];
        let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
        header.append(&mut api_key);
        Ok(header)
        }
        pub fn connector_base_url_payments<'a, F, Req, Res>(
            req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.aci.base_url
        pub fn connector_base_url_refunds<'a, F, Req, Res>(
            req: &'a RouterDataV2<F, RefundFlowData, Req, Res>,
        pub fn extract_mandate_id(
            mandate_reference: &MandateReferenceId,
        ) -> CustomResult<String, errors::ConnectorError> {
            match mandate_reference {
                MandateReferenceId::ConnectorMandateId(connector_mandate_ref) => connector_mandate_ref
                    .get_connector_mandate_id()
                    .ok_or_else(|| {
                        error_stack::report!(errors::ConnectorError::MissingRequiredField {
                            field_name: "connector_mandate_id"
                        })
                    }),
                MandateReferenceId::NetworkMandateId(_) => {
                    Err(error_stack::report!(errors::ConnectorError::NotImplemented(
                        "Network mandate ID not supported for repeat payments in aci"
                            .to_string(),
                    )))
                }
                MandateReferenceId::NetworkTokenWithNTI(_) => {
                        "Network token with NTI not supported for aci".to_string(),
            }
);
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Aci,
    curl_request: FormUrlEncoded(AciPaymentsRequest),
    curl_response: AciPaymentsResponse,
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
             Ok(format!("{}{}", self.connector_base_url_payments(req), "v1/payments"))
    curl_request: FormUrlEncoded(AciMandateRequest<T>),
    curl_response: AciMandateResponse,
    flow_name: SetupMandate,
    flow_request: SetupMandateRequestData<T>,
            req: &RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>,
            Ok(format!("{}v1/registrations", self.connector_base_url_payments(req)))
    curl_response: AciPaymentsSyncResponse,
    flow_name: PSync,
    flow_request: PaymentsSyncData,
    http_method: Get,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        let auth = aci::AciAuthType::try_from(&req.connector_auth_type)?;
        Ok(format!(
            "{}{}{}{}{}",
            self.connector_base_url_payments(req),
            "v1/payments/",
            req.request
                .connector_transaction_id
                .get_connector_transaction_id()
                .change_context(errors::ConnectorError::MissingConnectorTransactionID)?,
            "?entityId=",
            auth.entity_id.peek()
        ))
    curl_request: FormUrlEncoded(AciCaptureRequest),
    curl_response: AciCaptureResponse,
    flow_name: Capture,
    flow_request: PaymentsCaptureData,
            req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            Ok(format!(
            "{}{}{}",
    curl_request: FormUrlEncoded(AciCancelRequest),
    curl_response: AciVoidResponse,
    flow_name: Void,
    flow_request: PaymentVoidData,
            req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            let id = &req.request.connector_transaction_id;
            Ok(format!("{}v1/payments/{}", self.connector_base_url_payments(req), id))
    curl_request: FormUrlEncoded(AciRefundRequest),
    curl_response: AciRefundResponse,
    flow_name: Refund,
    resource_common_data: RefundFlowData,
    flow_request: RefundsData,
    flow_response: RefundsResponseData,
            req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            let connector_payment_id = req.request.connector_transaction_id.clone();
            "{}v1/payments/{}",
            self.connector_base_url_refunds(req),
            connector_payment_id,
    curl_request: FormUrlEncoded(AciRepeatPaymentRequest<T>),
    curl_response: AciRepeatPaymentResponse,
    flow_name: RepeatPayment,
    flow_request: RepeatPaymentData,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
            req: &RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>,
            let mandate_id = self.extract_mandate_id(&req.request.mandate_reference)?;
             Ok(format!("{}v1/registrations/{}/payments",self.connector_base_url_payments(req),mandate_id))
    ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData> for Aci<T>
    ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
    ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
    ConnectorIntegrationV2<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for Aci<T>
        CreateSessionToken,
        SessionTokenRequestData,
        SessionTokenResponseData,
        CreateAccessToken,
        AccessTokenRequestData,
        AccessTokenResponseData,
    >
        PaymentMethodToken,
        PaymentMethodTokenizationData<T>,
        PaymentMethodTokenResponse,
        PreAuthenticate,
        PaymentsPreAuthenticateData<T>,
        PaymentsResponseData,
        Authenticate,
        PaymentsAuthenticateData<T>,
        PostAuthenticate,
        PaymentsPostAuthenticateData<T>,
        CreateConnectorCustomer,
        ConnectorCustomerData,
        ConnectorCustomerResponse,
        VoidPC,
        PaymentsCancelPostCaptureData,
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
        SetupMandate,
        SetupMandateRequestData<T>,
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
