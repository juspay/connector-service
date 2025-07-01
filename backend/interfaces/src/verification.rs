use common_utils::{crypto, CustomResult};
use domain_types::{connector_types::ConnectorWebhookSecrets, router_data::ConnectorAuthType, router_data_v2::RouterDataV2};
use error_stack::ResultExt;

pub enum ConnectorSourceVerificationSecrets {
    AuthHeaders(ConnectorAuthType),
    WebhookSecret(ConnectorWebhookSecrets),
    AuthWithWebHookSecret {
        auth_headers: ConnectorAuthType,
        webhook_secret: ConnectorWebhookSecrets,
    },
}


/// Core trait for source verification
pub trait SourceVerification<Flow, ResourceCommonData, Req, Resp>
{
    fn get_secrets(&self, _secrets: ConnectorSourceVerificationSecrets) -> CustomResult<Vec<u8>, domain_types::errors::ConnectorError> {
       Ok(Vec::new())
    }

    /// Get the verification algorithm being used
    fn get_algorithm(&self) -> CustomResult<Box<dyn crypto::VerifySignature + Send>, domain_types::errors::ConnectorError> {
        Ok(Box::new(crypto::NoAlgorithm))
    }
    
    /// Get the signature/hash value from the payload for verification
    fn get_signature(&self, _payload: &[u8], _router_data: &RouterDataV2<Flow, ResourceCommonData, Req, Resp>, _secrets: &[u8]) -> CustomResult<Vec<u8>, domain_types::errors::ConnectorError> {
        Ok(Vec::new())
    }
    
    /// Get the message/payload that should be verified
    fn get_message(&self, payload: &[u8], _router_data: &RouterDataV2<Flow, ResourceCommonData, Req, Resp>, _secrets: &[u8]) -> CustomResult<Vec<u8>, domain_types::errors::ConnectorError> {
        Ok(payload.to_owned())
    }
    
    /// Perform the verification
    fn verify(&self, router_data: &RouterDataV2<Flow, ResourceCommonData, Req, Resp>, secrets: ConnectorSourceVerificationSecrets, payload: &[u8]) -> CustomResult<bool, domain_types::errors::ConnectorError> {
        let algorithm = self.get_algorithm()?;
        let extracted_secrets = self.get_secrets(secrets)?;
        let signature = self.get_signature(payload, router_data, &extracted_secrets)?;
        let message = self.get_message(payload, router_data,  &extracted_secrets)?;
        
        // Verify the signature against the message
        algorithm.verify_signature(&extracted_secrets, &signature, &message).change_context(domain_types::errors::ConnectorError::SourceVerificationFailed)
    }
}
