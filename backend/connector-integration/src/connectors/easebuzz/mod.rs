pub mod constants;
pub mod transformers;

use std::fmt::Debug;

use common_utils::{
    errors::CustomResult,
    ext_traits::ByteSliceExt,
    types::StringMinorUnit,
};
use domain_types::{
    connector_flow::{Authorize, PSync, RSync},
    connector_types::{
        ConnectorWebhookSecrets, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData,
        PaymentsSyncData, RefundSyncData, RefundsResponseData,
    },
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
};
use error_stack::ResultExt;
use hyperswitch_masking::{Mask, Maskable, PeekInterface, Secret};
use interfaces::{
    api::ConnectorCommon,
    connector_integration_v2::ConnectorIntegrationV2,
    connector_types,
    events::connector_api_logs::ConnectorEvent,
    verification::{ConnectorSourceVerificationSecrets, SourceVerification},
};
use serde::Serialize;
use transformers::{self as easebuzz, EaseBuzzPaymentsRequest, EaseBuzzPaymentsResponse};

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
    pub amount_converter: &'static (dyn common_utils::types::AmountConverterTrait<Output = String> + Sync),
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
    fn get_connector_name(&self) -> &'static str {
        "EaseBuzz"
    }

    fn get_connector_version(&self) -> &'static str {
        "1.0.0"
    }

    fn get_webhook_details(&self) -> ConnectorWebhookSecrets {
        ConnectorWebhookSecrets {
            primary_key: None,
            secondary_key: None,
            webhook_url: None,
            webhook_username: None,
            webhook_password: None,
        }
    }

    fn validate_connector(&self) -> CustomResult<(), errors::ConnectorError> {
        Ok(())
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
    for EaseBuzz<T>
{
    fn build_request_v2(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    ) -> CustomResult<Option<interfaces::services::Request>, errors::ConnectorError> {
        let auth = easebuzz::get_auth_header(&req.connector_auth_type)?;
        let request = EaseBuzzPaymentsRequest::try_from(req)?;
        let request_body = common_utils::request::RequestContent::Form(request);
        let request = common_utils::request::build_request(
            &self.get_base_url(req.resource_common_data.test_mode.unwrap_or(false)),
            &self.get_authorize_endpoint(),
            request_body,
            Some(auth),
            vec![],
            None,
            None,
        )?;
        Ok(Some(request))
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
    ) -> CustomResult<Option<interfaces::services::Request>, errors::ConnectorError> {
        let auth = easebuzz::get_auth_header(&req.connector_auth_type)?;
        let request = easebuzz::EaseBuzzPaymentsSyncRequest::try_from(req)?;
        let request_body = common_utils::request::RequestContent::Form(request);
        let request = common_utils::request::build_request(
            &self.get_base_url(req.resource_common_data.test_mode.unwrap_or(false)),
            &self.get_sync_endpoint(),
            request_body,
            Some(auth),
            vec![],
            None,
            None,
        )?;
        Ok(Some(request))
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
    ) -> CustomResult<Option<interfaces::services::Request>, errors::ConnectorError> {
        let auth = easebuzz::get_auth_header(&req.connector_auth_type)?;
        let request = easebuzz::EaseBuzzRefundSyncRequest::try_from(req)?;
        let request_body = common_utils::request::RequestContent::Form(request);
        let request = common_utils::request::build_request(
            &self.get_base_url(req.resource_common_data.test_mode.unwrap_or(false)),
            &self.get_refund_sync_endpoint(),
            request_body,
            Some(auth),
            vec![],
            None,
            None,
        )?;
        Ok(Some(request))
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
    SourceVerification for EaseBuzz<T>
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
    SourceVerification for EaseBuzz<T>
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
    SourceVerification for EaseBuzz<T>
{
    fn verify_source_verification_data(
        &self,
        _request: &RouterDataV2<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>,
        _source_verification_secrets: &ConnectorSourceVerificationSecrets,
    ) -> CustomResult<bool, errors::ConnectorError> {
        Ok(true)
    }
}