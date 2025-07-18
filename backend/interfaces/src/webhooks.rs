use common_utils::{crypto, ext_traits::ValueExt, CustomResult};
use domain_types::connector_types::ConnectorWebhookSecrets;
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, Secret};
use serde::{Deserialize, Serialize};

use crate::api::{ApplicationResponse, ConnectorCommon};

#[derive(Debug)]
pub struct IncomingWebhookRequestDetails<'a> {
    /// method
    pub method: http::Method,
    /// uri
    pub uri: http::Uri,
    /// headers
    pub headers: &'a actix_web::http::header::HeaderMap,
    /// body
    pub body: &'a [u8],
    /// query_params
    pub query_params: String,
}

#[derive(Debug)]
pub enum IncomingWebhookFlowError {
    /// Resource not found for the webhook
    ResourceNotFound,
    /// Internal error for the webhook
    InternalError,
}

/// Trait defining incoming webhook
#[async_trait::async_trait]
pub trait IncomingWebhook: ConnectorCommon + Sync {
    /// fn get_webhook_body_decoding_algorithm
    fn get_webhook_body_decoding_algorithm(
        &self,
        _request: &IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<Box<dyn crypto::DecodeMessage + Send>, domain_types::errors::ConnectorError>
    {
        Ok(Box::new(crypto::NoAlgorithm))
    }

    /// fn get_webhook_body_decoding_message
    fn get_webhook_body_decoding_message(
        &self,
        request: &IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<Vec<u8>, domain_types::errors::ConnectorError> {
        Ok(request.body.to_vec())
    }

    /// fn decode_webhook_body
    async fn decode_webhook_body(
        &self,
        request: &IncomingWebhookRequestDetails<'_>,
        merchant_id: &common_utils::id_type::MerchantId,
        connector_webhook_details: Option<common_utils::pii::SecretSerdeValue>,
        connector_name: &str,
    ) -> CustomResult<Vec<u8>, domain_types::errors::ConnectorError> {
        let algorithm = self.get_webhook_body_decoding_algorithm(request)?;

        let message = self
            .get_webhook_body_decoding_message(request)
            .change_context(domain_types::errors::ConnectorError::WebhookBodyDecodingFailed)?;
        let secret = self
            .get_webhook_source_verification_merchant_secret(
                merchant_id,
                connector_name,
                connector_webhook_details,
            )
            .await
            .change_context(
                domain_types::errors::ConnectorError::WebhookSourceVerificationFailed,
            )?;

        algorithm
            .decode_message(&secret.secret, message.into())
            .change_context(domain_types::errors::ConnectorError::WebhookBodyDecodingFailed)
    }

    /// fn get_webhook_source_verification_algorithm
    fn get_webhook_source_verification_algorithm(
        &self,
        _request: &IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<Box<dyn crypto::VerifySignature + Send>, domain_types::errors::ConnectorError>
    {
        Ok(Box::new(crypto::NoAlgorithm))
    }

    /// fn get_webhook_source_verification_merchant_secret
    async fn get_webhook_source_verification_merchant_secret(
        &self,
        merchant_id: &common_utils::id_type::MerchantId,
        connector_name: &str,
        connector_webhook_details: Option<common_utils::pii::SecretSerdeValue>,
    ) -> CustomResult<ConnectorWebhookSecrets, domain_types::errors::ConnectorError> {
        let debug_suffix =
            format!("For merchant_id: {merchant_id:?}, and connector_name: {connector_name}");
        let default_secret = "default_secret".to_string();
        let merchant_secret = match connector_webhook_details {
            Some(merchant_connector_webhook_details) => {
                let connector_webhook_details = merchant_connector_webhook_details
                    .parse_value::<MerchantConnectorWebhookDetails>(
                        "MerchantConnectorWebhookDetails",
                    )
                    .change_context_lazy(|| {
                        domain_types::errors::ConnectorError::WebhookSourceVerificationFailed
                    })
                    .attach_printable_lazy(|| {
                        format!(
                            "Deserializing MerchantConnectorWebhookDetails failed {debug_suffix}"
                        )
                    })?;
                ConnectorWebhookSecrets {
                    secret: connector_webhook_details
                        .merchant_secret
                        .expose()
                        .into_bytes(),
                    additional_secret: connector_webhook_details.additional_secret,
                }
            }

            None => ConnectorWebhookSecrets {
                secret: default_secret.into_bytes(),
                additional_secret: None,
            },
        };

        //need to fetch merchant secret from config table with caching in future for enhanced performance

        //If merchant has not set the secret for webhook source verification, "default_secret" is returned.
        //So it will fail during verification step and goes to psync flow.
        Ok(merchant_secret)
    }

    /// fn get_webhook_source_verification_signature
    fn get_webhook_source_verification_signature(
        &self,
        _request: &IncomingWebhookRequestDetails<'_>,
        _connector_webhook_secrets: &ConnectorWebhookSecrets,
    ) -> CustomResult<Vec<u8>, domain_types::errors::ConnectorError> {
        Ok(Vec::new())
    }

    /// fn get_webhook_source_verification_message
    fn get_webhook_source_verification_message(
        &self,
        _request: &IncomingWebhookRequestDetails<'_>,
        _merchant_id: &common_utils::id_type::MerchantId,
        _connector_webhook_secrets: &ConnectorWebhookSecrets,
    ) -> CustomResult<Vec<u8>, domain_types::errors::ConnectorError> {
        Ok(Vec::new())
    }

    /// fn verify_webhook_source
    async fn verify_webhook_source(
        &self,
        request: &IncomingWebhookRequestDetails<'_>,
        merchant_id: &common_utils::id_type::MerchantId,
        connector_webhook_details: Option<common_utils::pii::SecretSerdeValue>,
        _connector_account_details: crypto::Encryptable<Secret<serde_json::Value>>,
        connector_name: &str,
    ) -> CustomResult<bool, domain_types::errors::ConnectorError> {
        let algorithm = self
            .get_webhook_source_verification_algorithm(request)
            .change_context(
                domain_types::errors::ConnectorError::WebhookSourceVerificationFailed,
            )?;

        let connector_webhook_secrets = self
            .get_webhook_source_verification_merchant_secret(
                merchant_id,
                connector_name,
                connector_webhook_details,
            )
            .await
            .change_context(
                domain_types::errors::ConnectorError::WebhookSourceVerificationFailed,
            )?;

        let signature = self
            .get_webhook_source_verification_signature(request, &connector_webhook_secrets)
            .change_context(
                domain_types::errors::ConnectorError::WebhookSourceVerificationFailed,
            )?;

        let message = self
            .get_webhook_source_verification_message(
                request,
                merchant_id,
                &connector_webhook_secrets,
            )
            .change_context(
                domain_types::errors::ConnectorError::WebhookSourceVerificationFailed,
            )?;

        algorithm
            .verify_signature(&connector_webhook_secrets.secret, &signature, &message)
            .change_context(domain_types::errors::ConnectorError::WebhookSourceVerificationFailed)
    }

    /// fn get_webhook_event_type
    fn get_webhook_event_type(
        &self,
        _request: &IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<IncomingWebhookEvent, domain_types::errors::ConnectorError>;

    /// fn get_webhook_resource_object
    fn get_webhook_resource_object(
        &self,
        _request: &IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<
        Box<dyn hyperswitch_masking::ErasedMaskSerialize>,
        domain_types::errors::ConnectorError,
    >;

    /// fn get_webhook_api_response
    fn get_webhook_api_response(
        &self,
        _request: &IncomingWebhookRequestDetails<'_>,
        _error_kind: Option<IncomingWebhookFlowError>,
    ) -> CustomResult<ApplicationResponse<serde_json::Value>, domain_types::errors::ConnectorError>
    {
        Ok(ApplicationResponse::StatusOk)
    }

    /// fn get_dispute_details
    fn get_dispute_details(
        &self,
        _request: &IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<crate::disputes::DisputePayload, domain_types::errors::ConnectorError> {
        Err(domain_types::errors::ConnectorError::NotImplemented(
            "get_dispute_details method".to_string(),
        )
        .into())
    }

    /// fn get_external_authentication_details
    fn get_external_authentication_details(
        &self,
        _request: &IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<
        crate::authentication::ExternalAuthenticationPayload,
        domain_types::errors::ConnectorError,
    > {
        Err(domain_types::errors::ConnectorError::NotImplemented(
            "get_external_authentication_details method".to_string(),
        )
        .into())
    }

    /// fn get_mandate_details
    fn get_mandate_details(
        &self,
        _request: &IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<
        Option<domain_types::router_flow_types::ConnectorMandateDetails>,
        domain_types::errors::ConnectorError,
    > {
        Ok(None)
    }

    /// fn get_network_txn_id
    fn get_network_txn_id(
        &self,
        _request: &IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<
        Option<domain_types::router_flow_types::ConnectorNetworkTxnId>,
        domain_types::errors::ConnectorError,
    > {
        Ok(None)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Copy)]
#[serde(rename_all = "snake_case")]
pub enum IncomingWebhookEvent {
    /// Authorization + Capture success
    PaymentIntentFailure,
    /// Authorization + Capture failure
    PaymentIntentSuccess,
    PaymentIntentProcessing,
    PaymentIntentPartiallyFunded,
    PaymentIntentCancelled,
    PaymentIntentCancelFailure,
    PaymentIntentAuthorizationSuccess,
    PaymentIntentAuthorizationFailure,
    PaymentIntentCaptureSuccess,
    PaymentIntentCaptureFailure,
    PaymentActionRequired,
    EventNotSupported,
    SourceChargeable,
    SourceTransactionCreated,
    RefundFailure,
    RefundSuccess,
    DisputeOpened,
    DisputeExpired,
    DisputeAccepted,
    DisputeCancelled,
    DisputeChallenged,
    // dispute has been successfully challenged by the merchant
    DisputeWon,
    // dispute has been unsuccessfully challenged
    DisputeLost,
    MandateActive,
    MandateRevoked,
    EndpointVerification,
    ExternalAuthenticationARes,
    FrmApproved,
    FrmRejected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MerchantConnectorWebhookDetails {
    pub merchant_secret: Secret<String>,
    pub additional_secret: Option<Secret<String>>,
}
