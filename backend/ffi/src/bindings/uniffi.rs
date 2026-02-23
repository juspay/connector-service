#[cfg(feature = "uniffi")]
mod uniffi_bindings_inner {
    use crate::handlers::payments::{authorize_req_handler, authorize_res_handler};
    use crate::types::{FfiConnectorConfig, FfiRequestData};
    use crate::utils::FfiError;
    use bytes::Bytes;
    use domain_types::router_response_types::Response;
    use domain_types::utils::ForeignTryFrom;
    use external_services::service::extract_raw_connector_request;
    use grpc_api_types::payments::{ConnectorConfig, PaymentServiceAuthorizeRequest};
    use http::header::{HeaderMap, HeaderName, HeaderValue};
    use prost::Message;
    use std::collections::HashMap;

    /// Error type exposed over the UniFFI boundary.
    #[derive(Debug, thiserror::Error, uniffi::Error)]
    pub enum UniffiError {
        #[error("Failed to decode protobuf: {msg}")]
        DecodeError { msg: String },
        #[error("Failed to parse metadata: {msg}")]
        MetadataParseError { msg: String },
        #[error("Handler error: {msg}")]
        HandlerError { msg: String },
        #[error("No connector request generated")]
        NoConnectorRequest,
    }

    impl From<FfiError> for UniffiError {
        fn from(e: FfiError) -> Self {
            Self::MetadataParseError { msg: e.to_string() }
        }
    }

    impl From<error_stack::Report<FfiError>> for UniffiError {
        fn from(e: error_stack::Report<FfiError>) -> Self {
            Self::MetadataParseError { msg: e.to_string() }
        }
    }

    fn parse_metadata(connector_config_bytes: &[u8]) -> Result<FfiConnectorConfig, UniffiError> {
        let config = ConnectorConfig::decode(Bytes::from(connector_config_bytes.to_vec()))
            .map_err(|e| UniffiError::DecodeError {
                msg: format!("connector_config: {e}"),
            })?;
        FfiConnectorConfig::foreign_try_from(config).map_err(UniffiError::from)
    }

    /// Build the connector HTTP request.
    ///
    /// # Arguments
    /// - `request_bytes`:           protobuf-encoded `PaymentServiceAuthorizeRequest`
    /// - `connector_config_bytes`:  protobuf-encoded `ConnectorConfig`
    /// - `_options_bytes`:          reserved for future `CallOptions` config
    ///
    /// # Returns
    /// JSON string: `{"url":"...","method":"POST","headers":{...},"body":{...}}`
    #[uniffi::export]
    pub fn authorize_req_transformer(
        request_bytes: Vec<u8>,
        connector_config_bytes: Vec<u8>,
        _options_bytes: Option<Vec<u8>>,
    ) -> Result<String, UniffiError> {
        let payload = PaymentServiceAuthorizeRequest::decode(Bytes::from(request_bytes))
            .map_err(|e| UniffiError::DecodeError { msg: e.to_string() })?;

        let ffi_metadata = parse_metadata(&connector_config_bytes)?;

        let request = FfiRequestData {
            payload,
            extracted_metadata: ffi_metadata,
            masked_metadata: {
                let mut headers = HashMap::new();
                headers.insert(
                    common_utils::consts::X_MERCHANT_ID.to_string(),
                    "dummy_merchant".to_string(),
                );
                headers.insert(
                    common_utils::consts::X_TENANT_ID.to_string(),
                    "dummy_tenant".to_string(),
                );
                headers.insert(
                    common_utils::consts::X_CONNECTOR_NAME.to_string(),
                    "stripe".to_string(),
                );
                headers.insert(
                    common_utils::consts::X_REQUEST_ID.to_string(),
                    "dummy_request_id".to_string(),
                );
                headers.insert(
                    common_utils::consts::X_AUTH.to_string(),
                    "dummy_auth".to_string(),
                );
                crate::utils::ffi_headers_to_masked_metadata(&headers).ok()
            },
        };

        let result = authorize_req_handler(request).map_err(|e| UniffiError::HandlerError {
            msg: format!("{e:?}"),
        })?;

        let connector_request = result.ok_or(UniffiError::NoConnectorRequest)?;
        Ok(extract_raw_connector_request(&connector_request))
    }

    /// Process the connector HTTP response and produce a structured response.
    ///
    /// # Arguments
    /// - `response_body`:           raw bytes from the connector's HTTP response body
    /// - `status_code`:             HTTP status code from the connector response
    /// - `response_headers`:        HTTP response headers from the connector
    /// - `request_bytes`:           the original protobuf-encoded `PaymentServiceAuthorizeRequest`
    /// - `connector_config_bytes`:  protobuf-encoded `ConnectorConfig`
    /// - `_options_bytes`:          reserved for future `CallOptions` config
    ///
    /// # Returns
    /// protobuf-encoded `PaymentServiceAuthorizeResponse` bytes
    #[uniffi::export]
    pub fn authorize_res_transformer(
        response_body: Vec<u8>,
        status_code: u16,
        response_headers: HashMap<String, String>,
        request_bytes: Vec<u8>,
        connector_config_bytes: Vec<u8>,
        _options_bytes: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, UniffiError> {
        let mut header_map = HeaderMap::new();
        for (key, value) in &response_headers {
            if let (Ok(name), Ok(val)) = (
                HeaderName::from_bytes(key.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                header_map.insert(name, val);
            }
        }

        let response = Response {
            headers: if header_map.is_empty() {
                None
            } else {
                Some(header_map)
            },
            response: Bytes::from(response_body),
            status_code,
        };

        let payload = PaymentServiceAuthorizeRequest::decode(Bytes::from(request_bytes))
            .map_err(|e| UniffiError::DecodeError { msg: e.to_string() })?;

        let ffi_metadata = parse_metadata(&connector_config_bytes)?;

        let request = FfiRequestData {
            payload,
            extracted_metadata: ffi_metadata,
            masked_metadata: {
                let mut headers = HashMap::new();
                headers.insert(
                    common_utils::consts::X_MERCHANT_ID.to_string(),
                    "dummy_merchant".to_string(),
                );
                headers.insert(
                    common_utils::consts::X_TENANT_ID.to_string(),
                    "dummy_tenant".to_string(),
                );
                headers.insert(
                    common_utils::consts::X_CONNECTOR_NAME.to_string(),
                    "stripe".to_string(),
                );
                headers.insert(
                    common_utils::consts::X_REQUEST_ID.to_string(),
                    "dummy_request_id".to_string(),
                );
                headers.insert(
                    common_utils::consts::X_AUTH.to_string(),
                    "dummy_auth".to_string(),
                );
                crate::utils::ffi_headers_to_masked_metadata(&headers).ok()
            },
        };

        let proto_response = authorize_res_handler(request, response)
            .unwrap_or_else(grpc_api_types::payments::PaymentServiceAuthorizeResponse::from);

        Ok(proto_response.encode_to_vec())
    }
}

#[cfg(feature = "uniffi")]
pub use uniffi_bindings_inner::*;
