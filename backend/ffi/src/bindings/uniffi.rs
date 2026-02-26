#[cfg(feature = "uniffi")]
// macro implementation need to implemented
mod uniffi_bindings_inner {
    use crate::errors::{FfiPaymentError, UniffiError};
    use crate::handlers::payments::{
        authorize_req_handler, authorize_res_handler, capture_req_handler, capture_res_handler,
        create_access_token_req_handler, create_access_token_res_handler, get_req_handler,
        get_res_handler, refund_req_handler, refund_res_handler, void_req_handler,
        void_res_handler,
    };
    use crate::types::{FfiMetadataPayload, FfiRequestData};
    use crate::utils::ffi_headers_to_masked_metadata;
    use bytes::Bytes;
    use domain_types::router_response_types::Response;
    use external_services::service::extract_raw_connector_request;
    use grpc_api_types::payments::{
        MerchantAuthenticationServiceCreateAccessTokenRequest, PaymentServiceAuthorizeRequest,
        PaymentServiceCaptureRequest, PaymentServiceGetRequest, PaymentServiceRefundRequest,
        PaymentServiceVoidRequest,
    };
    use http::header::{HeaderMap, HeaderName, HeaderValue};
    use prost::Message;
    use std::collections::HashMap;

    /// Build FfiMetadataPayload from the caller's flat HashMap.
    ///
    /// Expected keys:
    ///   "connector"           — connector name, e.g. "stripe"
    ///   "connector_auth_type" — JSON-encoded ConnectorAuthType, e.g.
    ///                           '{"HeaderKey":{"api_key":"sk_test_..."}}'
    fn parse_metadata(
        metadata: &HashMap<String, String>,
    ) -> Result<FfiMetadataPayload, UniffiError> {
        let connector_val =
            metadata
                .get("connector")
                .ok_or_else(|| UniffiError::MissingMetadata {
                    key: "connector".to_string(),
                })?;
        let auth_val =
            metadata
                .get("connector_auth_type")
                .ok_or_else(|| UniffiError::MissingMetadata {
                    key: "connector_auth_type".to_string(),
                })?;

        let auth_json: serde_json::Value =
            serde_json::from_str(auth_val).map_err(|e| UniffiError::MetadataParseError {
                msg: format!("connector_auth_type is not valid JSON: {e}"),
            })?;

        let obj = serde_json::json!({
            "connector": connector_val,
            "connector_auth_type": auth_json,
        });

        serde_json::from_value(obj)
            .map_err(|e| UniffiError::MetadataParseError { msg: e.to_string() })
    }

    /// Build the connector HTTP request.
    ///
    /// # Arguments
    /// - `request_bytes`: protobuf-encoded `PaymentServiceAuthorizeRequest`
    /// - `metadata`: flat map with keys `connector` and `connector_auth_type`
    ///
    /// # Returns
    /// JSON string: `{"url":"...","method":"POST","headers":{...},"body":{...}}`
    #[uniffi::export]
    pub fn authorize_req_transformer(
        request_bytes: Vec<u8>,
        metadata: HashMap<String, String>,
    ) -> Result<String, UniffiError> {
        let payload = PaymentServiceAuthorizeRequest::decode(Bytes::from(request_bytes))
            .map_err(|e| UniffiError::DecodeError { msg: e.to_string() })?;

        let ffi_metadata = parse_metadata(&metadata)?;
        let masked_metadata = ffi_headers_to_masked_metadata(&metadata)?;

        let request = FfiRequestData {
            payload,
            extracted_metadata: ffi_metadata,
            masked_metadata: Some(masked_metadata),
        };

        let result =
            authorize_req_handler(request, None).map_err(|e| UniffiError::HandlerError {
                msg: format!("{e:?}"),
            })?;

        let connector_request = result.ok_or(UniffiError::NoConnectorRequest)?;

        Ok(extract_raw_connector_request(&connector_request))
    }

    /// Process the connector HTTP response and produce a structured response.
    ///
    /// # Arguments
    /// - `response_body`: raw bytes from the connector's HTTP response body
    /// - `status_code`: HTTP status code from the connector response
    /// - `response_headers`: HTTP response headers from the connector
    /// - `request_bytes`: the original protobuf-encoded `PaymentServiceAuthorizeRequest`
    /// - `metadata`: the original metadata map passed to `authorize_req_transformer`
    ///
    /// # Returns
    /// protobuf-encoded `PaymentServiceAuthorizeResponse` bytes
    #[uniffi::export]
    pub fn authorize_res_transformer(
        response_body: Vec<u8>,
        status_code: u16,
        response_headers: HashMap<String, String>,
        request_bytes: Vec<u8>,
        metadata: HashMap<String, String>,
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

        let ffi_metadata = parse_metadata(&metadata)?;
        let masked_metadata = ffi_headers_to_masked_metadata(&metadata)?;

        let request = FfiRequestData {
            payload,
            extracted_metadata: ffi_metadata,
            masked_metadata: Some(masked_metadata),
        };

        let proto_response =
            authorize_res_handler(request, response, None).map_err(FfiPaymentError::from)?;

        Ok(proto_response.encode_to_vec())
    }

    /// Build the connector HTTP request for capture operation.
    #[uniffi::export]
    pub fn capture_req_transformer(
        request_bytes: Vec<u8>,
        metadata: HashMap<String, String>,
    ) -> Result<String, UniffiError> {
        let payload = PaymentServiceCaptureRequest::decode(Bytes::from(request_bytes))
            .map_err(|e| UniffiError::DecodeError { msg: e.to_string() })?;

        let ffi_metadata = parse_metadata(&metadata)?;
        let masked_metadata = ffi_headers_to_masked_metadata(&metadata)?;

        let request = FfiRequestData {
            payload,
            extracted_metadata: ffi_metadata,
            masked_metadata: Some(masked_metadata),
        };

        let result = capture_req_handler(request, None).map_err(|e| UniffiError::HandlerError {
            msg: format!("{e:?}"),
        })?;

        let connector_request = result.ok_or(UniffiError::NoConnectorRequest)?;

        Ok(extract_raw_connector_request(&connector_request))
    }

    /// Process the connector HTTP response for capture operation.
    #[uniffi::export]
    pub fn capture_res_transformer(
        response_body: Vec<u8>,
        status_code: u16,
        response_headers: HashMap<String, String>,
        request_bytes: Vec<u8>,
        metadata: HashMap<String, String>,
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

        let payload = PaymentServiceCaptureRequest::decode(Bytes::from(request_bytes))
            .map_err(|e| UniffiError::DecodeError { msg: e.to_string() })?;

        let ffi_metadata = parse_metadata(&metadata)?;
        let masked_metadata = ffi_headers_to_masked_metadata(&metadata)?;

        let request = FfiRequestData {
            payload,
            extracted_metadata: ffi_metadata,
            masked_metadata: Some(masked_metadata),
        };

        let proto_response =
            capture_res_handler(request, response, None).map_err(FfiPaymentError::from)?;

        Ok(proto_response.encode_to_vec())
    }

    /// Build the connector HTTP request for void operation.
    #[uniffi::export]
    pub fn void_req_transformer(
        request_bytes: Vec<u8>,
        metadata: HashMap<String, String>,
    ) -> Result<String, UniffiError> {
        let payload = PaymentServiceVoidRequest::decode(Bytes::from(request_bytes))
            .map_err(|e| UniffiError::DecodeError { msg: e.to_string() })?;

        let ffi_metadata = parse_metadata(&metadata)?;
        let masked_metadata = ffi_headers_to_masked_metadata(&metadata)?;

        let request = FfiRequestData {
            payload,
            extracted_metadata: ffi_metadata,
            masked_metadata: Some(masked_metadata),
        };

        let result = void_req_handler(request, None).map_err(|e| UniffiError::HandlerError {
            msg: format!("{e:?}"),
        })?;

        let connector_request = result.ok_or(UniffiError::NoConnectorRequest)?;

        Ok(extract_raw_connector_request(&connector_request))
    }

    /// Process the connector HTTP response for void operation.
    #[uniffi::export]
    pub fn void_res_transformer(
        response_body: Vec<u8>,
        status_code: u16,
        response_headers: HashMap<String, String>,
        request_bytes: Vec<u8>,
        metadata: HashMap<String, String>,
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

        let payload = PaymentServiceVoidRequest::decode(Bytes::from(request_bytes))
            .map_err(|e| UniffiError::DecodeError { msg: e.to_string() })?;

        let ffi_metadata = parse_metadata(&metadata)?;
        let masked_metadata = ffi_headers_to_masked_metadata(&metadata)?;

        let request = FfiRequestData {
            payload,
            extracted_metadata: ffi_metadata,
            masked_metadata: Some(masked_metadata),
        };

        let proto_response =
            void_res_handler(request, response, None).map_err(FfiPaymentError::from)?;

        Ok(proto_response.encode_to_vec())
    }

    /// Build the connector HTTP request for get operation.
    #[uniffi::export]
    pub fn get_req_transformer(
        request_bytes: Vec<u8>,
        metadata: HashMap<String, String>,
    ) -> Result<String, UniffiError> {
        let payload = PaymentServiceGetRequest::decode(Bytes::from(request_bytes))
            .map_err(|e| UniffiError::DecodeError { msg: e.to_string() })?;

        let ffi_metadata = parse_metadata(&metadata)?;
        let masked_metadata = ffi_headers_to_masked_metadata(&metadata)?;

        let request = FfiRequestData {
            payload,
            extracted_metadata: ffi_metadata,
            masked_metadata: Some(masked_metadata),
        };

        let result = get_req_handler(request, None).map_err(|e| UniffiError::HandlerError {
            msg: format!("{e:?}"),
        })?;

        let connector_request = result.ok_or(UniffiError::NoConnectorRequest)?;

        Ok(extract_raw_connector_request(&connector_request))
    }

    /// Process the connector HTTP response for get operation.
    #[uniffi::export]
    pub fn get_res_transformer(
        response_body: Vec<u8>,
        status_code: u16,
        response_headers: HashMap<String, String>,
        request_bytes: Vec<u8>,
        metadata: HashMap<String, String>,
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

        let payload = PaymentServiceGetRequest::decode(Bytes::from(request_bytes))
            .map_err(|e| UniffiError::DecodeError { msg: e.to_string() })?;

        let ffi_metadata = parse_metadata(&metadata)?;
        let masked_metadata = ffi_headers_to_masked_metadata(&metadata)?;

        let request = FfiRequestData {
            payload,
            extracted_metadata: ffi_metadata,
            masked_metadata: Some(masked_metadata),
        };

        let proto_response = get_res_handler(request, response, None)?;

        Ok(proto_response.encode_to_vec())
    }

    /// Build the connector HTTP request for create access token operation.
    #[uniffi::export]
    pub fn create_access_token_req_transformer(
        request_bytes: Vec<u8>,
        metadata: HashMap<String, String>,
    ) -> Result<String, UniffiError> {
        let payload = MerchantAuthenticationServiceCreateAccessTokenRequest::decode(Bytes::from(
            request_bytes,
        ))
        .map_err(|e| UniffiError::DecodeError { msg: e.to_string() })?;

        let ffi_metadata = parse_metadata(&metadata)?;
        let masked_metadata = ffi_headers_to_masked_metadata(&metadata)?;

        let request = FfiRequestData {
            payload,
            extracted_metadata: ffi_metadata,
            masked_metadata: Some(masked_metadata),
        };

        let result = create_access_token_req_handler(request, None).map_err(|e| {
            UniffiError::HandlerError {
                msg: format!("{e:?}"),
            }
        })?;

        let connector_request = result.ok_or(UniffiError::NoConnectorRequest)?;

        Ok(extract_raw_connector_request(&connector_request))
    }

    /// Process the connector HTTP response for create access token operation.
    #[uniffi::export]
    pub fn create_access_token_res_transformer(
        response_body: Vec<u8>,
        status_code: u16,
        response_headers: HashMap<String, String>,
        request_bytes: Vec<u8>,
        metadata: HashMap<String, String>,
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

        let payload = MerchantAuthenticationServiceCreateAccessTokenRequest::decode(Bytes::from(
            request_bytes,
        ))
        .map_err(|e| UniffiError::DecodeError { msg: e.to_string() })?;

        let ffi_metadata = parse_metadata(&metadata)?;
        let masked_metadata = ffi_headers_to_masked_metadata(&metadata)?;

        let request = FfiRequestData {
            payload,
            extracted_metadata: ffi_metadata,
            masked_metadata: Some(masked_metadata),
        };

        let proto_response = create_access_token_res_handler(request, response, None)?;

        Ok(proto_response.encode_to_vec())
    }

    /// Build the connector HTTP request for refund operation.
    #[uniffi::export]
    pub fn refund_req_transformer(
        request_bytes: Vec<u8>,
        metadata: HashMap<String, String>,
    ) -> Result<String, UniffiError> {
        let payload = PaymentServiceRefundRequest::decode(Bytes::from(request_bytes))
            .map_err(|e| UniffiError::DecodeError { msg: e.to_string() })?;

        let ffi_metadata = parse_metadata(&metadata)?;
        let masked_metadata = ffi_headers_to_masked_metadata(&metadata)?;

        let request = FfiRequestData {
            payload,
            extracted_metadata: ffi_metadata,
            masked_metadata: Some(masked_metadata),
        };

        let result = refund_req_handler(request, None).map_err(|e| UniffiError::HandlerError {
            msg: format!("{e:?}"),
        })?;

        let connector_request = result.ok_or(UniffiError::NoConnectorRequest)?;

        Ok(extract_raw_connector_request(&connector_request))
    }

    /// Process the connector HTTP response for refund operation.
    #[uniffi::export]
    pub fn refund_res_transformer(
        response_body: Vec<u8>,
        status_code: u16,
        response_headers: HashMap<String, String>,
        request_bytes: Vec<u8>,
        metadata: HashMap<String, String>,
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

        let payload = PaymentServiceRefundRequest::decode(Bytes::from(request_bytes))
            .map_err(|e| UniffiError::DecodeError { msg: e.to_string() })?;

        let ffi_metadata = parse_metadata(&metadata)?;
        let masked_metadata = ffi_headers_to_masked_metadata(&metadata)?;

        let request = FfiRequestData {
            payload,
            extracted_metadata: ffi_metadata,
            masked_metadata: Some(masked_metadata),
        };

        let proto_response = refund_res_handler(request, response, None)?;

        Ok(proto_response.encode_to_vec())
    }
}

#[cfg(feature = "uniffi")]
// macro implementation need to implemented
pub use uniffi_bindings_inner::*;
