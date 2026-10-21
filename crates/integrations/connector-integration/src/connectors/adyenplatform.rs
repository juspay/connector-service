pub mod transformers;
use super::macros;
use common_enums::CurrencyUnit;
use common_utils::{errors::CustomResult, events};
use domain_types::{
    connector_types::*,
    errors::{ConnectorError, IntegrationError, WebhookError},
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorSpecificConfig, ErrorResponse},
    router_response_types::Response,
    types::Connectors,
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, Mask, Maskable};
use interfaces::{
    api::ConnectorCommon, connector_types, decode::BodyDecoding, verification::SourceVerification,
};
use serde::Serialize;
use std::fmt::Debug;

// Webhook dispatch uses the same connector type as the payout registry.
pub use crate::payout_connectors::adyenplatform::AdyenplatformPayouts as Adyenplatform;
impl<T: PaymentMethodDataTypes + Debug + Send + Sync + 'static + Serialize> ConnectorCommon
    for Adyenplatform<T>
{
    fn id(&self) -> &'static str {
        "adyenplatform"
    }
    fn get_currency_unit(&self) -> CurrencyUnit {
        CurrencyUnit::Minor
    }
    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }
    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        &connectors.adyenplatform.base_url
    }
    fn get_auth_header(
        &self,
        config: &ConnectorSpecificConfig,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, IntegrationError> {
        match config {
            ConnectorSpecificConfig::Adyenplatform { api_key, .. } => Ok(vec![(
                "X-API-Key".into(),
                api_key.clone().expose().into_masked(),
            )]),
            _ => Err(IntegrationError::FailedToObtainAuthType {
                context: Default::default(),
            }
            .into()),
        }
    }
    fn build_error_response(
        &self,
        res: Response,
        event: Option<&mut events::Event>,
        _: &ConnectorSpecificConfig,
    ) -> CustomResult<ErrorResponse, ConnectorError> {
        let response: transformers::AdyenTransferErrorResponse = serde_json::from_slice(
            &res.response,
        )
        .change_context(ConnectorError::ResponseDeserializationFailed {
            context: Default::default(),
        })?;
        event.map(|e| e.set_connector_response(&response));
        let message = if let Some(fields) = &response.invalid_fields {
            format!(
                "{} Invalid fields: {}",
                response.title,
                serde_json::to_value(fields).unwrap_or_default()
            )
        } else if let Some(detail) = &response.detail {
            format!("{} Detail: {}", response.title, detail)
        } else {
            response.title
        };
        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response.error_code,
            message,
            reason: response.detail,
            ..Default::default()
        })
    }
}
impl<T: PaymentMethodDataTypes + Debug + Send + Sync + 'static + Serialize>
    connector_types::ConnectorServiceTrait<T> for Adyenplatform<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Send + Sync + 'static + Serialize>
    connector_types::ValidationTrait for Adyenplatform<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Send + Sync + 'static + Serialize>
    connector_types::VerifyRedirectResponse for Adyenplatform<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Send + Sync + 'static + Serialize> SourceVerification
    for Adyenplatform<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Send + Sync + 'static + Serialize> BodyDecoding
    for Adyenplatform<T>
{
}
macros::macro_connector_flow_status_impls!(
    connector: Adyenplatform, generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    not_supported: [Authorize,PSync,Refund,RSync,SetupMandate,RepeatPayment,VoidPostRefund,Capture,Void,VoidPC,CreateOrder,ServerSessionAuthenticationToken,Accept,DefendDispute,SubmitEvidence,PaymentMethodToken,ServerAuthenticationToken,ClientAuthenticationToken,MandateRevoke,PreAuthenticate,Authenticate,PostAuthenticate,CreateConnectorCustomer,GetConnectorCustomer,IncrementalAuthorization,PaymentMethodEligibility],
);
fn webhook(
    request: &RequestDetails,
) -> Result<transformers::AdyenplatformIncomingWebhook, error_stack::Report<WebhookError>> {
    serde_json::from_slice(&request.body).change_context(WebhookError::WebhookBodyDecodingFailed)
}
impl<T: PaymentMethodDataTypes + Debug + Send + Sync + 'static + Serialize>
    connector_types::IncomingWebhook for Adyenplatform<T>
{
    fn verify_webhook_source(
        &self,
        request: RequestDetails,
        secret: Option<ConnectorWebhookSecrets>,
        _: Option<ConnectorSpecificConfig>,
    ) -> Result<bool, error_stack::Report<WebhookError>> {
        use base64::Engine;
        let secret = secret.ok_or(WebhookError::WebhookVerificationSecretNotFound)?;
        let key = hex::decode(secret.secret)
            .change_context(WebhookError::WebhookVerificationSecretInvalid)?;
        let signature = request
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("hmacsignature"))
            .map(|(_, v)| v)
            .ok_or(WebhookError::WebhookSignatureNotFound)?;
        let signature = base64::engine::general_purpose::STANDARD
            .decode(signature)
            .change_context(WebhookError::WebhookSourceVerificationFailed)?;
        Ok(ring::hmac::verify(
            &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key),
            &request.body,
            &signature,
        )
        .is_ok())
    }
    fn get_event_type(
        &self,
        request: RequestDetails,
    ) -> Result<EventType, error_stack::Report<WebhookError>> {
        let w = webhook(&request)?;
        Ok(transformers::get_adyen_payout_webhook_event(
            w.webhook_type,
            w.data.status,
            w.data.tracking,
        ))
    }
    fn get_webhook_event_reference(
        &self,
        request: RequestDetails,
    ) -> Result<Option<WebhookResourceReference>, error_stack::Report<WebhookError>> {
        Ok(Some(WebhookResourceReference::Payout(
            PayoutWebhookReference {
                connector_payout_id: None,
                merchant_payout_id: Some(webhook(&request)?.data.reference),
            },
        )))
    }
    fn process_payout_webhook(
        &self,
        request: RequestDetails,
        _: Option<ConnectorWebhookSecrets>,
        _: Option<ConnectorSpecificConfig>,
    ) -> Result<PayoutWebhookDetailsResponse, error_stack::Report<WebhookError>> {
        use common_enums::PayoutStatus;
        let w = webhook(&request)?;
        let reason = w
            .data
            .reason
            .or_else(|| w.data.tracking.as_ref().and_then(|t| t.reason.clone()));
        let status = match transformers::get_adyen_payout_webhook_event(
            w.webhook_type,
            w.data.status,
            w.data.tracking,
        ) {
            EventType::PayoutSuccess => PayoutStatus::Success,
            EventType::PayoutFailure => PayoutStatus::Failure,
            EventType::PayoutReversed => PayoutStatus::Reversed,
            EventType::PayoutCreated => PayoutStatus::Initiated,
            _ => PayoutStatus::Pending,
        };
        Ok(PayoutWebhookDetailsResponse {
            connector_payout_id: None,
            merchant_payout_id: Some(w.data.reference),
            status,
            error_code: reason.clone(),
            error_message: reason,
            status_code: 200,
        })
    }
    fn get_webhook_resource_object(
        &self,
        request: RequestDetails,
    ) -> Result<Box<dyn hyperswitch_masking::ErasedMaskSerialize>, error_stack::Report<WebhookError>>
    {
        Ok(Box::new(webhook(&request)?))
    }
    fn get_webhook_api_response(
        &self,
        _request: RequestDetails,
        error_kind: Option<connector_types::IncomingWebhookFlowError>,
        _config: Option<ConnectorSpecificConfig>,
    ) -> Result<interfaces::api::EventAckResponse, error_stack::Report<WebhookError>> {
        // Preserve Hyperswitch's error acknowledgement override.
        Ok(interfaces::api::EventAckResponse {
            status_code: 200,
            headers: if error_kind.is_some() {
                vec![("x-http-code".into(), "404".into())]
            } else {
                vec![]
            },
            body: error_kind.map(|_| b"null".to_vec()),
        })
    }
    fn sample_webhook_body(&self) -> &'static [u8] {
        br#"{"type":"balancePlatform.transfer.created","data":{"reference":"payout_attempt_1","status":"received"}}"#
    }
}

#[cfg(test)]
mod tests;
