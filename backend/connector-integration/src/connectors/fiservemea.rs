pub mod transformers;

use std::fmt::Debug;

use common_enums::CurrencyUnit;
use common_utils::{errors::CustomResult, events, ext_traits::ByteSliceExt};
use domain_types::{
    connector_flow, connector_types::*, errors, payment_method_data::PaymentMethodDataTypes,
    router_data::ConnectorAuthType, router_response_types::Response, types::Connectors,
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, Maskable};
use interfaces::{
    api::ConnectorCommon, connector_integration_v2::ConnectorIntegrationV2, connector_types,
};
use serde::Serialize;
use transformers as fiservemea;

use crate::with_error_response_body;

pub(crate) mod headers {
    pub(crate) const API_KEY: &str = "Api-Key";
    pub(crate) const CLIENT_REQUEST_ID: &str = "Client-Request-Id";
    pub(crate) const TIMESTAMP: &str = "Timestamp";
    pub(crate) const MESSAGE_SIGNATURE: &str = "Message-Signature";
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const AUTHORIZATION: &str = "Authorization";
}

    fn build_headers_with_signature(
        &self,
        auth: &fiservemea::FiservemeaAuthType,
        request_body_str: &str,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let client_request_id = fiservemea::FiservemeaAuthType::generate_client_request_id();
        let timestamp = fiservemea::FiservemeaAuthType::generate_timestamp();

        let api_key_value = auth.api_key.clone().expose();
        let message_signature = auth.generate_hmac_signature(
            &api_key_value,
            &client_request_id,
            &timestamp,
            request_body_str,
        )?;

        Ok(vec![
            headers::CONTENT_TYPE.to_string(),
            "application/json".to_string().into(),
            headers::API_KEY.to_string(),
            Secret::new(api_key_value).into_masked(),
            headers::CLIENT_REQUEST_ID.to_string(),
            client_request_id.into(),
            headers::TIMESTAMP.to_string(),
            timestamp.into(),
            headers::MESSAGE_SIGNATURE.to_string(),
            message_signature.into(),
        ])
    }
