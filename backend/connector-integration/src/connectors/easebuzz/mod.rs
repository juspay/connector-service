pub mod constants;
pub mod transformers;

use std::fmt::Debug;

use common_utils::{
    errors::CustomResult,
    ext_traits::ByteSliceExt,
    request::{Method, RequestBuilder},
    types::StringMinorUnit,
};
use domain_types::{
    connector_flow::{Authorize, PSync, RSync},
    connector_types::{
        ConnectorWebhookSecrets, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData,
        PaymentsSyncData, RefundSyncData, RefundsResponseData, Connectors,
    },
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
};
use error_stack::ResultExt;
use hyperswitch_masking::Maskable;
use interfaces::{
    api::ConnectorCommon,
    connector_integration_v2::ConnectorIntegrationV2,
    connector_types,
    verification::{ConnectorSourceVerificationSecrets, SourceVerification},
};
use serde::Serialize;
use transformers::{self as easebuzz, EaseBuzzPaymentsRequest, EaseBuzzPaymentsResponse};

use crate::types::ResponseRouterData;

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
> connector_types::ConnectorServiceTrait<T> for EaseBuzz<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::PaymentAuthorizeV2<T> for EaseBuzz<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::PaymentSyncV2 for EaseBuzz<T>
{
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> connector_types::RefundSyncV2 for EaseBuzz<T>
{
}

#[derive(Debug, Clone)]
pub struct EaseBuzz<T> {
    pub amount_converter: &'static (dyn common_utils::types::AmountConvertor<Output = String> + Sync),
    pub connector_name: &'static str,
    pub payment_method_data: std::marker::PhantomData<T>,
}

impl<T> EaseBuzz<T> {
    pub fn new() -> Self {
        Self {
            amount_converter: &StringMinorUnit,
            connector_name: "EaseBuzz",
            payment_method_data: std::marker::PhantomData,
        }
    }

    fn get_base_url(&self, test_mode: bool) -> &'static str {
        if test_mode {
            constants::BASE_URL_TEST
        } else {
            constants::BASE_URL_PRODUCTION
        }
    }

    fn get_authorize_endpoint(&self) -> &'static str {
        constants::ENDPOINT_SEAMLESS_TRANSACTION
    }

    fn get_sync_endpoint(&self) -> &'static str {
        constants::ENDPOINT_TXN_SYNC
    }

    fn get_refund_sync_endpoint(&self) -> &'static str {
        constants::ENDPOINT_REFUND_SYNC
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorCommon for EaseBuzz<T>
{
    fn id(&self) -> &'static str {
        "easebuzz"
    }

    fn base_url<'a>(&self, _connectors: &'a Connectors) -> &'a str {
        self.get_base_url(true)
    }

    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth = easebuzz::get_auth_header(auth_type)?;
        Ok(vec![(headers::AUTHORIZATION.to_string(), auth.expose().into())])
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/x-www-form-urlencoded"
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
    for EaseBuzz<T>
{
    fn build_request_v2(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    ) -> CustomResult<Option<common_utils::request::Request>, errors::ConnectorError> {
        let request = EaseBuzzPaymentsRequest::try_from(req)?;
        let url = format!(
            "{}{}",
            self.get_base_url(req.resource_common_data.test_mode.unwrap_or(false)),
            self.get_authorize_endpoint()
        );
        
        let request_builder = RequestBuilder::new()
            .method(Method::Post)
            .url(&url)
            .attach_default_headers()
            .headers(self.get_auth_header(&req.connector_auth_type)?)
            .set_body(common_utils::request::RequestContent::Form(request));
        
        Ok(Some(request_builder.build()))
    }

    fn handle_response_v2(
        &self,
        response: &Response,
        _router_data: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    ) -> CustomResult<PaymentsResponseData, errors::ConnectorError> {
        let response: EaseBuzzPaymentsResponse = response
            .response
            .parse_struct("EaseBuzzPaymentsResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        PaymentsResponseData::try_from(response)
    }

    fn get_error_response_v2(
        &self,
        response: &[u8],
    ) -> CustomResult<easebuzz::EaseBuzzErrorResponse, errors::ConnectorError> {
            let error_response: easebuzz::EaseBuzzErrorResponse = response
                .parse_struct("EaseBuzzErrorResponse")
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
            Ok(error_response)
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    for EaseBuzz<T>
{
    fn build_request_v2(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<Option<common_utils::request::Request>, errors::ConnectorError> {
        let request = easebuzz::EaseBuzzPaymentsSyncRequest::try_from(req)?;
        let url = format!(
            "{}{}",
            self.get_base_url(req.resource_common_data.test_mode.unwrap_or(false)),
            self.get_sync_endpoint()
        );
        
        let request_builder = RequestBuilder::new()
            .method(Method::Post)
            .url(&url)
            .attach_default_headers()
            .headers(self.get_auth_header(&req.connector_auth_type)?)
            .set_body(common_utils::request::RequestContent::Form(request));
        
        Ok(Some(request_builder.build()))
    }

    fn handle_response_v2(
        &self,
        response: &Response,
        _router_data: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<PaymentsResponseData, errors::ConnectorError> {
        let response: easebuzz::EaseBuzzPaymentsSyncResponse = response
            .response
            .parse_struct("EaseBuzzPaymentsSyncResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        PaymentsResponseData::try_from(response)
    }

    fn get_error_response_v2(
        &self,
        response: &[u8],
    ) -> CustomResult<easebuzz::EaseBuzzErrorResponse, errors::ConnectorError> {
            let error_response: easebuzz::EaseBuzzErrorResponse = response
                .parse_struct("EaseBuzzErrorResponse")
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
            Ok(error_response)
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>
    for EaseBuzz<T>
{
    fn build_request_v2(
        &self,
        req: &RouterDataV2<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>,
    ) -> CustomResult<Option<common_utils::request::Request>, errors::ConnectorError> {
        let request = easebuzz::EaseBuzzRefundSyncRequest::try_from(req)?;
        let url = format!(
            "{}{}",
            self.get_base_url(req.resource_common_data.test_mode.unwrap_or(false)),
            self.get_refund_sync_endpoint()
        );
        
        let request_builder = RequestBuilder::new()
            .method(Method::Post)
            .url(&url)
            .attach_default_headers()
            .headers(self.get_auth_header(&req.connector_auth_type)?)
            .set_body(common_utils::request::RequestContent::Form(request));
        
        Ok(Some(request_builder.build()))
    }

    fn handle_response_v2(
        &self,
        response: &Response,
        _router_data: &RouterDataV2<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>,
    ) -> CustomResult<RefundsResponseData, errors::ConnectorError> {
        let response: easebuzz::EaseBuzzRefundSyncResponse = response
            .response
            .parse_struct("EaseBuzzRefundSyncResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        RefundsResponseData::try_from(response)
    }

    fn get_error_response_v2(
        &self,
        response: &[u8],
    ) -> CustomResult<easebuzz::EaseBuzzErrorResponse, errors::ConnectorError> {
            let error_response: easebuzz::EaseBuzzErrorResponse = response
                .parse_struct("EaseBuzzErrorResponse")
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
            Ok(error_response)
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    SourceVerification<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
    for EaseBuzz<T>
{
    fn verify_source_verification_data(
        &self,
        _request: &RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData<T>,
            PaymentsResponseData,
        >,
        _source_verification_secrets: &ConnectorSourceVerificationSecrets,
    ) -> CustomResult<bool, errors::ConnectorError> {
        Ok(true)
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    SourceVerification<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    for EaseBuzz<T>
{
    fn verify_source_verification_data(
        &self,
        _request: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        _source_verification_secrets: &ConnectorSourceVerificationSecrets,
    ) -> CustomResult<bool, errors::ConnectorError> {
        Ok(true)
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    SourceVerification<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>
    for EaseBuzz<T>
{
    fn verify_source_verification_data(
        &self,
        _request: &RouterDataV2<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>,
        _source_verification_secrets: &ConnectorSourceVerificationSecrets,
    ) -> CustomResult<bool, errors::ConnectorError> {
        Ok(true)
    }
}