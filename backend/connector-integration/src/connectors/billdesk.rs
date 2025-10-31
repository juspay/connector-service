pub mod transformers;



use common_enums::CurrencyUnit;
use common_utils::{
    errors::CustomResult,
    ext_traits::ByteSliceExt,
    types::StringMinorUnit,
};
use domain_types::{
    connector_flow::{
        Authorize, PSync,
    },
    connector_types::{
        PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, ResponseId,
    },
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
};
use error_stack::ResultExt;
use masking::ExposeInterface;
use hyperswitch_masking::{Mask, Maskable, PeekInterface};
use interfaces::{
    api::ConnectorCommon,
    connector_integration_v2::ConnectorIntegrationV2,
    connector_types,
    events::connector_api_logs::ConnectorEvent,
    verification::{ConnectorSourceVerificationSecrets, SourceVerification},
};
use serde::Serialize;
use transformers::{self as billdesk, BilldeskPaymentsRequest, BilldeskPaymentsResponse, BilldeskPaymentsSyncRequest, BilldeskPaymentsSyncResponse};

use super::macros;
use crate::{types::ResponseRouterData, with_error_response_body};

pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const AUTHORIZATION: &str = "Authorization";
}

// Trait implementations with generic type parameters
impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::ConnectorServiceTrait<T> for Billdesk<T>
{
}
impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::PaymentAuthorizeV2<T> for Billdesk<T>
{
}
impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::PaymentSyncV2 for Billdesk<T>
{
}

// Add all required trait implementations for ConnectorServiceTrait
impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::PaymentPreAuthenticateV2<T> for Billdesk<T>
{
}
impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::PaymentAuthenticateV2<T> for Billdesk<T>
{
}
impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::PaymentPostAuthenticateV2<T> for Billdesk<T>
{
}
impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::PaymentVoidV2 for Billdesk<T>
{
}
impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::PaymentCapture for Billdesk<T>
{
}
impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::RefundV2 for Billdesk<T>
{
}
impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::RefundSyncV2 for Billdesk<T>
{
}
impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::PaymentVoidPostCaptureV2 for Billdesk<T>
{
}
impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::PaymentSessionToken for Billdesk<T>
{
}
impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::PaymentAccessToken for Billdesk<T>
{
}
impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::CreateConnectorCustomer for Billdesk<T>
{
}
impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::PaymentOrderCreate for Billdesk<T>
{
}
impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::ValidationTrait for Billdesk<T>
{
}
impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::RepeatPaymentV2 for Billdesk<T>
{
}
impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::PaymentTokenV2<T> for Billdesk<T>
{
}
impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::SetupMandateV2<T> for Billdesk<T>
{
}
impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::AcceptDispute for Billdesk<T>
{
}
impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::SubmitEvidenceV2 for Billdesk<T>
{
}
impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::DisputeDefend for Billdesk<T>
{
}
impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::IncomingWebhook for Billdesk<T>
{
}




macros::create_all_prerequisites!(
    connector_name: Billdesk,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: BilldeskPaymentsRequest,
            response_body: BilldeskPaymentsResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: PSync,
            request_body: BilldeskPaymentsSyncRequest,
            response_body: BilldeskPaymentsSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        )
    ],
    amount_converters: [
        amount_converter: StringMinorUnit
    ],
    member_functions: {
        pub fn build_headers<F, FCD, Req, Res>(
            &self,
            _req: &RouterDataV2<F, FCD, Req, Res>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError>
        where
            Self: ConnectorIntegrationV2<F, FCD, Req, Res>,
        {
            Ok(vec![(
                headers::CONTENT_TYPE.to_string(),
                self.common_get_content_type().to_string().into(),
            )])
        }

        pub fn connector_base_url_payments<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> &'a str {
            if req.resource_common_data.test_mode.unwrap_or(false) {
                "https://uat.billdesk.com/pgidsk/PGIDirectRequest"
            } else {
                "https://www.billdesk.com/pgidsk/PGIDirectRequest"
            }
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Billdesk,
    curl_request: Json(BilldeskPaymentsRequest),
    curl_response: BilldeskPaymentsResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            let mut header = vec![(
                headers::CONTENT_TYPE.to_string(),
                self.common_get_content_type().to_string().into(),
            )];

            let auth_header = get_billdesk_auth_header(&req.connector_auth_type)?;
            header.push((headers::AUTHORIZATION.to_string(), auth_header));

            Ok(header)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            let base_url = self.connector_base_url_payments(req);
            Ok(format!("{}?reqid=BDRDF011", base_url))
        }
    }
);

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> ConnectorCommon for Billdesk<T>
{
    fn id(&self) -> &'static str {
        "billdesk"
    }

    fn get_currency_unit(&self) -> CurrencyUnit {
        CurrencyUnit::Base
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn base_url<'a>(&self, _connectors: &'a Connectors) -> &'a str {
        "https://www.billdesk.com"
    }

    fn get_auth_header(
        &self,
        _auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        // Billdesk uses custom auth in get_headers
        Ok(vec![])
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: billdesk::BilldeskErrorResponse = res
            .response
            .parse_struct("BilldeskErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        with_error_response_body!(event_builder, response);

        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response.error.to_string(),
            message: response.error_description.clone(),
            reason: Some(response.error_description),
            attempt_status: None,
            connector_transaction_id: None,
            network_advice_code: None,
            network_decline_code: None,
            network_error_message: None,
        })
    }
}



fn get_billdesk_auth_header(
    connector_auth_type: &ConnectorAuthType,
) -> CustomResult<Maskable<String>, errors::ConnectorError> {
    match connector_auth_type {
        ConnectorAuthType::SignatureKey { api_key, .. } => {
            let auth_header = format!("Bearer {}", api_key.peek());
            Ok(auth_header.into_masked())
        }
        _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
    }
}

// Add required ConnectorIntegrationV2 implementations
impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    for Billdesk<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> ConnectorIntegrationV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
    for Billdesk<T>
{
}

// Add the remaining required trait implementations with empty bodies
impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> ConnectorIntegrationV2<domain_types::connector_flow::PreAuthenticate, PaymentFlowData, domain_types::connector_types::PaymentsPreAuthenticateData<T>, PaymentsResponseData>
    for Billdesk<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> ConnectorIntegrationV2<domain_types::connector_flow::Authenticate, PaymentFlowData, domain_types::connector_types::PaymentsAuthenticateData<T>, PaymentsResponseData>
    for Billdesk<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> ConnectorIntegrationV2<domain_types::connector_flow::PostAuthenticate, PaymentFlowData, domain_types::connector_types::PaymentsPostAuthenticateData<T>, PaymentsResponseData>
    for Billdesk<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> ConnectorIntegrationV2<domain_types::connector_flow::Void, PaymentFlowData, domain_types::connector_types::PaymentVoidData, PaymentsResponseData>
    for Billdesk<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> ConnectorIntegrationV2<domain_types::connector_flow::Capture, PaymentFlowData, domain_types::connector_types::PaymentsCaptureData, PaymentsResponseData>
    for Billdesk<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> ConnectorIntegrationV2<domain_types::connector_flow::Refund, domain_types::connector_types::RefundFlowData, domain_types::connector_types::RefundsData, domain_types::connector_types::RefundsResponseData>
    for Billdesk<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> ConnectorIntegrationV2<domain_types::connector_flow::RSync, domain_types::connector_types::RefundFlowData, domain_types::connector_types::RefundSyncData, domain_types::connector_types::RefundsResponseData>
    for Billdesk<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> ConnectorIntegrationV2<domain_types::connector_flow::VoidPC, PaymentFlowData, domain_types::connector_types::PaymentsCancelPostCaptureData, PaymentsResponseData>
    for Billdesk<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> ConnectorIntegrationV2<domain_types::connector_flow::CreateSessionToken, PaymentFlowData, domain_types::connector_types::SessionTokenRequestData, domain_types::connector_types::SessionTokenResponseData>
    for Billdesk<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> ConnectorIntegrationV2<domain_types::connector_flow::CreateAccessToken, PaymentFlowData, domain_types::connector_types::AccessTokenRequestData, domain_types::connector_types::AccessTokenResponseData>
    for Billdesk<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> ConnectorIntegrationV2<domain_types::connector_flow::CreateConnectorCustomer, PaymentFlowData, domain_types::connector_types::ConnectorCustomerData, domain_types::connector_types::ConnectorCustomerResponse>
    for Billdesk<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> ConnectorIntegrationV2<domain_types::connector_flow::CreateOrder, PaymentFlowData, domain_types::connector_types::PaymentCreateOrderData, domain_types::connector_types::PaymentCreateOrderResponse>
    for Billdesk<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> ConnectorIntegrationV2<domain_types::connector_flow::RepeatPayment, PaymentFlowData, domain_types::connector_types::RepeatPaymentData, PaymentsResponseData>
    for Billdesk<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> ConnectorIntegrationV2<domain_types::connector_flow::PaymentMethodToken, PaymentFlowData, domain_types::connector_types::PaymentMethodTokenizationData<T>, domain_types::connector_types::PaymentMethodTokenResponse>
    for Billdesk<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> ConnectorIntegrationV2<domain_types::connector_flow::SetupMandate, PaymentFlowData, domain_types::connector_types::SetupMandateRequestData<T>, PaymentsResponseData>
    for Billdesk<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> ConnectorIntegrationV2<domain_types::connector_flow::Accept, domain_types::connector_types::DisputeFlowData, domain_types::connector_types::AcceptDisputeData, domain_types::connector_types::DisputeResponseData>
    for Billdesk<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> ConnectorIntegrationV2<domain_types::connector_flow::SubmitEvidence, domain_types::connector_types::DisputeFlowData, domain_types::connector_types::SubmitEvidenceData, domain_types::connector_types::DisputeResponseData>
    for Billdesk<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> ConnectorIntegrationV2<domain_types::connector_flow::DefendDispute, domain_types::connector_types::DisputeFlowData, domain_types::connector_types::DisputeDefendData, domain_types::connector_types::DisputeResponseData>
    for Billdesk<T>
{
}

// Add SourceVerification implementations
impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> SourceVerification<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
    for Billdesk<T>
{
    fn get_secrets(
        &self,
        _secrets: ConnectorSourceVerificationSecrets,
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(Vec::new())
    }
    fn get_algorithm(
        &self,
    ) -> CustomResult<
        Box<dyn common_utils::crypto::VerifySignature + Send>,
        errors::ConnectorError,
    > {
        Ok(Box::new(common_utils::crypto::NoAlgorithm))
    }
    fn get_signature(
        &self,
        _payload: &[u8],
        _router_data: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        _secrets: &[u8],
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(Vec::new())
    }
    fn get_message(
        &self,
        payload: &[u8],
        _router_data: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        _secrets: &[u8],
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(payload.to_owned())
    }
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> SourceVerification<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    for Billdesk<T>
{
    fn get_secrets(
        &self,
        _secrets: ConnectorSourceVerificationSecrets,
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(Vec::new())
    }
    fn get_algorithm(
        &self,
    ) -> CustomResult<
        Box<dyn common_utils::crypto::VerifySignature + Send>,
        errors::ConnectorError,
    > {
        Ok(Box::new(common_utils::crypto::NoAlgorithm))
    }
    fn get_signature(
        &self,
        _payload: &[u8],
        _router_data: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        _secrets: &[u8],
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(Vec::new())
    }
    fn get_message(
        &self,
        payload: &[u8],
        _router_data: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        _secrets: &[u8],
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(payload.to_owned())
    }
}

#[cfg(test)]
mod test;