// Payu Connector Implementation
pub mod constants;
pub mod transformers;

use std::marker::PhantomData;

use common_enums::{AttemptStatus, PaymentMethodType};
use common_utils::{
    crypto::Sha512,
    errors::CustomResult,
    ext_traits::BytesExt,
    request::RequestContent,
    types::{self, StringMinorUnit},
};
use domain_types::{
    connector_flow::{Authorize, PSync, RSync},
    connector_types::{
        ConnectorSpecifications, ConnectorWebhookSecrets, PaymentFlowData, PaymentsAuthorizeData,
        PaymentsResponseData, PaymentsSyncData, RefundSyncData, RefundsResponseData,
    },
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data_v2::RouterDataV2,
    types as domain_types,
};
use error_stack::ResultExt;
use hyperswitch_masking::Secret;
use masking::ExposeInterface;
use transformers as payu_transformers;

use crate::{
    connector::ConnectorCommon,
    services::{self, ConnectorIntegrationV2},
    utils,
};

#[derive(Debug, Clone)]
pub struct Payu<T> {
    amount_converter: &'static (dyn types::AmountConverterTrait<Output = String> + Sync),
    connector_name: &'static str,
    payment_method_data: PhantomData<T>,
}

impl<T> Payu<T> {
    pub fn new() -> Self {
        Self {
            amount_converter: &StringMinorUnit,
            connector_name: "payu",
            payment_method_data: PhantomData,
        }
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    ConnectorCommon for Payu<T>
{
    fn get_id(&self) -> &'static str {
        self.connector_name
    }

    fn get_name(&self) -> String {
        "Payu".to_string()
    }

    fn get_connector_type(&self) -> domain_types::ConnectorType {
        domain_types::ConnectorType::PaymentGateway
    }

    fn get_connector_version(&self) -> &'static str {
        "1.0.0"
    }

    fn get_base_url(&self) -> &'static str {
        if cfg!(test) {
            "https://test.payu.in"
        } else {
            "https://info.payu.in"
        }
    }

    fn get_webhook_event_type_from_header(&self, _headers: &[(&str, &str)]) -> Result<String, errors::ConnectorError> {
        Ok("webhook".to_string())
    }

    fn get_webhook_object_reference_id(&self, body: &[u8]) -> Result<String, errors::ConnectorError> {
        let response: payu_transformers::PayuWebhookResponse = serde_json::from_slice(body)
            .change_context(errors::ConnectorError::WebhookBodyDecodingFailed)?;
        Ok(response.get_transaction_id())
    }

    fn get_webhook_event_type(&self, body: &[u8]) -> Result<String, errors::ConnectorError> {
        let response: payu_transformers::PayuWebhookResponse = serde_json::from_slice(body)
            .change_context(errors::ConnectorError::WebhookBodyDecodingFailed)?;
        Ok(response.get_event_type())
    }

    fn get_webhook_api_version(&self, _body: &[u8]) -> Result<String, errors::ConnectorError> {
        Ok("1.0".to_string())
    }

    fn get_webhook_response_body(
        &self,
        body: &[u8],
    ) -> Result<serde_json::Value, errors::ConnectorError> {
        let response: payu_transformers::PayuWebhookResponse = serde_json::from_slice(body)
            .change_context(errors::ConnectorError::WebhookBodyDecodingFailed)?;
        serde_json::to_value(response)
            .change_context(errors::ConnectorError::WebhookBodyDecodingFailed)
    }

    fn get_webhook_http_method(&self) -> services::Method {
        services::Method::Post
    }

    fn get_webhook_authentication_type(&self) -> domain_types::ConnectorAuthType {
        domain_types::ConnectorAuthType::SignatureKey {
            api_key: Secret::new("".to_string()),
            key1: None,
            key2: None,
        }
    }

    fn get_webhook_source_verification_algorithm(
        &self,
    ) -> domain_types::WebhookSourceVerificationAlgorithm {
        domain_types::WebhookSourceVerificationAlgorithm::HmacSha512
    }

    fn verify_webhook_source(
        &self,
        body: &[u8],
        headers: &[(&str, &str)],
        connector_webhook_details: &ConnectorWebhookSecrets,
    ) -> Result<bool, errors::ConnectorError> {
        let signature = headers
            .iter()
            .find(|(key, _)| *key == "x-payu-signature")
            .map(|(_, value)| *value)
            .ok_or(errors::ConnectorError::WebhookSignatureNotFound)?;

        let expected_signature = Sha512::sign_with_key(
            body,
            connector_webhook_details
                .secret
                .expose()
                .as_bytes(),
        );

        Ok(signature == expected_signature)
    }

    fn get_error_response(
        &self,
        res: utils::Response,
    ) -> CustomResult<serde_json::Value, errors::ConnectorError> {
        payu_transformers::PayuErrorResponse::get_error_response(res)
    }

    fn get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn get_api_tag(&self) -> String {
        "payments".to_string()
    }

    fn get_connector_specifications(&self) -> ConnectorSpecifications {
        ConnectorSpecifications {
            connector_name: self.get_name(),
            connector_type: self.get_connector_type(),
            supported_payment_methods: vec![
                PaymentMethodType::Upi,
                PaymentMethodType::UpiCollect,
                PaymentMethodType::UpiIntent,
            ],
            supported_flows: vec![
                domain_types::ConnectorFlow::Authorize,
                domain_types::ConnectorFlow::PaymentSync,
                domain_types::ConnectorFlow::RefundSync,
            ],
            supported_currencies: vec![
                domain_types::Currency::INR,
                domain_types::Currency::USD,
                domain_types::Currency::EUR,
            ],
            supported_countries: vec![domain_types::CountryAlpha2::IN],
            connector_metadata: None,
        }
    }
}

// Implement all required traits for the connector
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::PaymentAuthorize for Payu<T>
{
}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::PaymentSync for Payu<T>
{
}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::RefundSync for Payu<T>
{
}

// Stub implementations for unsupported flows
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::PaymentCapture for Payu<T>
{
}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::PaymentVoid for Payu<T>
{
}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::PaymentRefund for Payu<T>
{
}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::PaymentOrderCreate for Payu<T>
{
}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::PaymentSessionToken for Payu<T>
{
}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::PaymentSetupMandate for Payu<T>
{
}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::PaymentRepeatPayment for Payu<T>
{
}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::DisputeAccept for Payu<T>
{
}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::DisputeDefend for Payu<T>
{
}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::DisputeSubmitEvidence for Payu<T>
{
}

// Implement the main integration traits
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    ConnectorIntegrationV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
    for Payu<T>
{
    fn build_request_v2(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    ) -> CustomResult<Option<services::Request>, errors::ConnectorError> {
        let auth = payu_transformers::PayuAuthType::try_from(&req.connector_auth_type)?;
        let request = payu_transformers::PayuPaymentsRequest::try_from(req)?;
        let url = self.get_base_url().to_string() + "/merchant/postservice.php?form=2";
        
        let request = services::RequestBuilder::new()
            .method(services::Method::Post)
            .url(&url)
            .attach_default_headers()
            .headers(vec![
                ("Content-Type", "application/x-www-form-urlencoded"),
                ("Authorization", auth.get_auth_header()),
            ])
            .set_body(RequestContent::FormUrlEncoded(request))
            .build();

        Ok(Some(request))
    }

    fn handle_response_v2(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        res: utils::Response,
    ) -> CustomResult<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, errors::ConnectorError>
    {
        let response: payu_transformers::PayuPaymentsResponse = res
            .response
            .parse_struct("PayuPaymentsResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        
        let response_data = PaymentsResponseData::try_from(response)?;
        Ok(req.get_response_with_data(response_data))
    }

    fn get_error_response_v2(
        &self,
        res: utils::Response,
    ) -> CustomResult<serde_json::Value, errors::ConnectorError> {
        payu_transformers::PayuErrorResponse::get_error_response(res)
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    for Payu<T>
{
    fn build_request_v2(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<Option<services::Request>, errors::ConnectorError> {
        let auth = payu_transformers::PayuAuthType::try_from(&req.connector_auth_type)?;
        let request = payu_transformers::PayuPaymentsSyncRequest::try_from(req)?;
        let url = self.get_base_url().to_string() + "/merchant/postservice.php?form=2";
        
        let request = services::RequestBuilder::new()
            .method(services::Method::Post)
            .url(&url)
            .attach_default_headers()
            .headers(vec![
                ("Content-Type", "application/x-www-form-urlencoded"),
                ("Authorization", auth.get_auth_header()),
            ])
            .set_body(RequestContent::FormUrlEncoded(request))
            .build();

        Ok(Some(request))
    }

    fn handle_response_v2(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        res: utils::Response,
    ) -> CustomResult<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, errors::ConnectorError>
    {
        let response: payu_transformers::PayuPaymentsSyncResponse = res
            .response
            .parse_struct("PayuPaymentsSyncResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        
        let response_data = PaymentsResponseData::try_from(response)?;
        Ok(req.get_response_with_data(response_data))
    }

    fn get_error_response_v2(
        &self,
        res: utils::Response,
    ) -> CustomResult<serde_json::Value, errors::ConnectorError> {
        payu_transformers::PayuErrorResponse::get_error_response(res)
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    ConnectorIntegrationV2<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>
    for Payu<T>
{
    fn build_request_v2(
        &self,
        req: &RouterDataV2<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>,
    ) -> CustomResult<Option<services::Request>, errors::ConnectorError> {
        let auth = payu_transformers::PayuAuthType::try_from(&req.connector_auth_type)?;
        let request = payu_transformers::PayuRefundSyncRequest::try_from(req)?;
        let url = self.get_base_url().to_string() + "/merchant/postservice.php?form=2";
        
        let request = services::RequestBuilder::new()
            .method(services::Method::Post)
            .url(&url)
            .attach_default_headers()
            .headers(vec![
                ("Content-Type", "application/x-www-form-urlencoded"),
                ("Authorization", auth.get_auth_header()),
            ])
            .set_body(RequestContent::FormUrlEncoded(request))
            .build();

        Ok(Some(request))
    }

    fn handle_response_v2(
        &self,
        req: &RouterDataV2<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>,
        res: utils::Response,
    ) -> CustomResult<RouterDataV2<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>, errors::ConnectorError>
    {
        let response: payu_transformers::PayuRefundSyncResponse = res
            .response
            .parse_struct("PayuRefundSyncResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        
        let response_data = RefundsResponseData::try_from(response)?;
        Ok(req.get_response_with_data(response_data))
    }

    fn get_error_response_v2(
        &self,
        res: utils::Response,
    ) -> CustomResult<serde_json::Value, errors::ConnectorError> {
        payu_transformers::PayuErrorResponse::get_error_response(res)
    }
}

// Source verification stubs
macro_rules! impl_source_verification_stub {
    ($flow:ty, $common_data:ty, $req:ty, $resp:ty) => {
        impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
            services::SourceVerificationV2<$flow, $common_data, $req, $resp> for Payu<T>
        {
            fn verify_source(
                &self,
                _request: &RouterDataV2<$flow, $common_data, $req, $resp>,
            ) -> CustomResult<bool, errors::ConnectorError> {
                Ok(true)
            }
        }
    };
}

impl_source_verification_stub!(Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData);
impl_source_verification_stub!(PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData);
impl_source_verification_stub!(RSync, PaymentFlowData, RefundSyncData, RefundsResponseData);