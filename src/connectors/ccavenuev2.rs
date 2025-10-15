// CcavenueV2 Connector Implementation
use std::marker::PhantomData;

use common_enums::{AttemptStatus, PaymentMethodType};
use common_utils::{
    consts::BASE_URL,
    crypto::{self, Aes128GcmSiv},
    errors::CustomResult,
    ext_traits::BytesExt,
    request::RequestContent,
    types::{self, StringMinorUnit},
};
use domain_types::{
    connector_flow::{Authorize, PSync, RSync},
    connector_types::{
        ConnectorCommon, ConnectorCommonV2, ConnectorIntegrationV2, ConnectorSpecifications,
        ConnectorWebhookSecrets, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData,
        PaymentsSyncData, RefundSyncData, ResponseId,
    },
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data_v2::RouterDataV2,
};
use error_stack::ResultExt;
use hyperswitch_masking::Secret;
use masking::PeekInterface;
use serde::{Deserialize, Serialize};

use self::transformers::{
    CcavenueV2PaymentsRequest, CcavenueV2PaymentsResponse, CcavenueV2PaymentsSyncRequest,
    CcavenueV2PaymentsSyncResponse,
};

pub mod transformers;

#[derive(Debug, Clone)]
pub struct CcavenueV2<T> {
    amount_converter: &'static (dyn types::AmountConverterTrait<Output = String> + Sync),
    connector_name: &'static str,
    payment_method_data: PhantomData<T>,
}

impl<T> Default for CcavenueV2<T> {
    fn default() -> Self {
        Self {
            amount_converter: &StringMinorUnit,
            connector_name: "ccavenuev2",
            payment_method_data: PhantomData,
        }
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    ConnectorCommon for CcavenueV2<T>
{
    fn get_id(&self) -> &'static str {
        self.connector_name
    }

    fn get_name(&self) -> String {
        "CCAvenue V2".to_string()
    }

    fn get_connector_about(&self) -> String {
        "CCAvenue V2 payment gateway supporting UPI transactions".to_string()
    }

    fn get_connector_specifications(&self) -> ConnectorSpecifications {
        ConnectorSpecifications {
            connector_name: self.get_name(),
            supported_payment_methods: vec![PaymentMethodType::Upi],
            supported_flows: vec!["Authorize", "PSync", "RSync"],
            supported_currencies: vec!["INR"],
            supports_webhook: true,
            supports_refund: true,
            supports_capture: false,
            supports_void: false,
            supports_multiple_capture: false,
            supports_3ds: false,
        }
    }

    fn get_webhook_secret(&self) -> ConnectorWebhookSecrets {
        ConnectorWebhookSecrets {
            api_key: None,
            secret: None,
            merchant_id: None,
            additional_secret: None,
        }
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    ConnectorCommonV2 for CcavenueV2<T>
{
    fn get_base_url(&self) -> &'static str {
        BASE_URL
    }

    fn build_request(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    ) -> CustomResult<common_utils::request::Request, errors::ConnectorError> {
        let request = CcavenueV2PaymentsRequest::try_from(req)?;
        let url = self.get_base_url().to_string() + "/transaction/transaction.do";
        
        Ok(common_utils::request::Request::builder()
            .method(common_utils::request::RequestMethod::Post)
            .url(url)
            .attach_default_headers()
            .body(RequestContent::FormUrlEncoded(request))
            .build())
    }

    fn build_sync_request(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<common_utils::request::Request, errors::ConnectorError> {
        let request = CcavenueV2PaymentsSyncRequest::try_from(req)?;
        let url = self.get_base_url().to_string() + "/apis/servlet/DoWebTrans";
        
        Ok(common_utils::request::Request::builder()
            .method(common_utils::request::RequestMethod::Post)
            .url(url)
            .attach_default_headers()
            .body(RequestContent::FormUrlEncoded(request))
            .build())
    }

    fn build_refund_sync_request(
        &self,
        req: &RouterDataV2<RSync, PaymentFlowData, RefundSyncData, PaymentsResponseData>,
    ) -> CustomResult<common_utils::request::Request, errors::ConnectorError> {
        let request = CcavenueV2PaymentsSyncRequest::try_from(req)?;
        let url = self.get_base_url().to_string() + "/apis/servlet/DoWebTrans";
        
        Ok(common_utils::request::Request::builder()
            .method(common_utils::request::RequestMethod::Post)
            .url(url)
            .attach_default_headers()
            .body(RequestContent::FormUrlEncoded(request))
            .build())
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    ConnectorIntegrationV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
    for CcavenueV2<T>
{
    fn get_headers(
        &self,
        _req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, String)>, errors::ConnectorError> {
        Ok(vec![
            ("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string()),
            ("Accept".to_string(), "application/json".to_string()),
        ])
    }

    fn get_content_type(&self) -> &'static str {
        "application/x-www-form-urlencoded"
    }

    fn get_error_response(
        &self,
        response: &str,
    ) -> CustomResult<transformers::CcavenueV2ErrorResponse, errors::ConnectorError> {
        serde_json::from_str(response)
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    for CcavenueV2<T>
{
    fn get_headers(
        &self,
        _req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, String)>, errors::ConnectorError> {
        Ok(vec![
            ("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string()),
            ("Accept".to_string(), "application/json".to_string()),
        ])
    }

    fn get_content_type(&self) -> &'static str {
        "application/x-www-form-urlencoded"
    }

    fn get_error_response(
        &self,
        response: &str,
    ) -> CustomResult<transformers::CcavenueV2ErrorResponse, errors::ConnectorError> {
        serde_json::from_str(response)
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    ConnectorIntegrationV2<RSync, PaymentFlowData, RefundSyncData, PaymentsResponseData>
    for CcavenueV2<T>
{
    fn get_headers(
        &self,
        _req: &RouterDataV2<RSync, PaymentFlowData, RefundSyncData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, String)>, errors::ConnectorError> {
        Ok(vec![
            ("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string()),
            ("Accept".to_string(), "application/json".to_string()),
        ])
    }

    fn get_content_type(&self) -> &'static str {
        "application/x-www-form-urlencoded"
    }

    fn get_error_response(
        &self,
        response: &str,
    ) -> CustomResult<transformers::CcavenueV2ErrorResponse, errors::ConnectorError> {
        serde_json::from_str(response)
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)
    }
}

// Helper functions for encryption/decryption
pub fn encrypt_request(data: &str, working_key: &str) -> CustomResult<String, errors::ConnectorError> {
    let cipher = Aes128GcmSiv::new_from_slice(working_key.as_bytes())
        .change_context(errors::ConnectorError::EncryptionFailed)?;
    
    let encrypted_data = cipher
        .encrypt(data.as_bytes())
        .change_context(errors::ConnectorError::EncryptionFailed)?;
    
    Ok(hex::encode(encrypted_data))
}

pub fn decrypt_response(encrypted_data: &str, working_key: &str) -> CustomResult<String, errors::ConnectorError> {
    let cipher = Aes128GcmSiv::new_from_slice(working_key.as_bytes())
        .change_context(errors::ConnectorError::DecryptionFailed)?;
    
    let decoded_data = hex::decode(encrypted_data)
        .change_context(errors::ConnectorError::DecryptionFailed)?;
    
    let decrypted_data = cipher
        .decrypt(&decoded_data)
        .change_context(errors::ConnectorError::DecryptionFailed)?;
    
    Ok(String::from_utf8(decrypted_data)
        .change_context(errors::ConnectorError::DecryptionFailed)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let data = "test_data";
        let key = "test_key_16byte";
        
        let encrypted = encrypt_request(data, key).unwrap();
        let decrypted = decrypt_response(&encrypted, key).unwrap();
        
        assert_eq!(data, decrypted);
    }
}