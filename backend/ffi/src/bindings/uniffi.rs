#[cfg(feature = "uniffi")]
// macro implementation need to implemented
mod uniffi_bindings_inner {
    use crate::errors::UniffiError;
    use crate::handlers::payments::{
        authorize_req_handler, authorize_res_handler, capture_req_handler, capture_res_handler,
        create_access_token_req_handler, create_access_token_res_handler, get_req_handler,
        get_res_handler, refund_req_handler, refund_res_handler, void_req_handler,
        void_res_handler,
    };
    use crate::types::{
        FfiConnectorHttpRequest, FfiConnectorHttpResponse, FfiMetadataPayload, FfiRequestData,
    };
    use crate::utils::ffi_headers_to_masked_metadata;
    use bytes::Bytes;
    use common_utils::request::Request;
    use domain_types::router_response_types::Response;
    use grpc_api_types::payments::{
        FfiOptions, MerchantAuthenticationServiceCreateAccessTokenRequest,
        PaymentServiceAuthorizeRequest, PaymentServiceCaptureRequest, PaymentServiceGetRequest,
        PaymentServiceRefundRequest, PaymentServiceVoidRequest,
    };
    use http::header::{HeaderMap, HeaderName, HeaderValue};
    use prost::Message;
    use std::collections::HashMap;

    /// Build FfiMetadataPayload from the caller's flat HashMap.
    ///
    /// Expected keys:
    ///   "connector"        — connector name, e.g. "stripe"
    ///   "x-connector-auth" — JSON-encoded typed auth, e.g.
    ///                        '{"auth_type":{"Stripe":{"api_key":"sk_test_..."}}}'
    fn parse_metadata(
        metadata: &HashMap<String, String>,
    ) -> Result<FfiMetadataPayload, UniffiError> {
        let connector_val = metadata
            .get("connector")
            .or_else(|| metadata.get("x-connector"))
            .ok_or_else(|| UniffiError::MissingMetadata {
                key: "connector".to_string(),
            })?;

        // Support both new x-connector-auth and legacy connector_auth_type
        let auth_val = metadata
            .get("x-connector-auth")
            .or_else(|| metadata.get("connector_auth_type"))
            .ok_or_else(|| UniffiError::MissingMetadata {
                key: "x-connector-auth".to_string(),
            })?;

        let auth_json: serde_json::Value =
            serde_json::from_str(auth_val).map_err(|e| UniffiError::MetadataParseError {
                msg: format!("Authentication JSON is not valid: {e}"),
            })?;

        // FfiMetadataPayload expects { "connector": "Stripe", "connector_auth_type": { "Stripe": { "api_key": "..." } } }
        let obj = serde_json::json!({
            "connector": connector_val,
            "connector_auth_type": auth_json,
        });

        serde_json::from_value(obj)
            .map_err(|e| UniffiError::MetadataParseError { msg: e.to_string() })
    }

    /// Helper to convert internal Request to FfiConnectorHttpRequest (Binary Safe)
    fn build_ffi_request(request: &Request) -> Result<FfiConnectorHttpRequest, UniffiError> {
        let mut headers = request.get_headers_map();
        let (body, boundary) = request
            .body
            .as_ref()
            .map(|b| b.get_body_bytes())
            .transpose()
            .map_err(|e| UniffiError::HandlerError { msg: e.to_string() })?
            .unwrap_or((None, None));

        // Sync the Content-Type header with the generated boundary if applicable
        if let Some(boundary) = boundary {
            headers.insert(
                "content-type".to_string(),
                format!("multipart/form-data; boundary={}", boundary),
            );
        }

        Ok(FfiConnectorHttpRequest {
            url: request.url.clone(),
            method: request.method.to_string(),
            headers,
            body,
        })
    }

    /// Parse FfiOptions from optional bytes and extract test_mode.
    ///
    /// # Arguments
    /// - `options_bytes`: protobuf-encoded `FfiOptions` (optional, can be empty)
    ///
    /// # Returns
    /// `Some(test_mode)` if FfiOptions is provided and parseable, `None` otherwise
    fn parse_ffi_options(options_bytes: Vec<u8>) -> Option<bool> {
        if options_bytes.is_empty() {
            return None;
        }
        let ffi_options = FfiOptions::decode(Bytes::from(options_bytes)).ok()?;
        // Extract test_mode from EnvOptions
        ffi_options.env.as_ref().map(|env| env.test_mode)
    }

    /// Helper to convert FfiConnectorHttpResponse to internal Response
    fn build_domain_response(response: FfiConnectorHttpResponse) -> Response {
        let mut header_map = HeaderMap::new();
        for (key, value) in &response.headers {
            if let (Ok(name), Ok(val)) = (
                HeaderName::from_bytes(key.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                header_map.insert(name, val);
            }
        }

        Response {
            headers: if header_map.is_empty() {
                None
            } else {
                Some(header_map)
            },
            response: Bytes::from(response.body),
            status_code: response.status_code,
        }
    }

    /// Build the connector HTTP request.
    ///
    /// # Arguments
    /// - `request_bytes`: protobuf-encoded `PaymentServiceAuthorizeRequest`
    /// - `metadata`: flat map with keys `connector` and `connector_auth_type`
    /// - `options_bytes`: protobuf-encoded `FfiOptions`
    ///
    /// # Returns
    /// FfiConnectorHttpRequest struct (Binary Safe)
    #[uniffi::export]
    pub fn authorize_req_transformer(
        request_bytes: Vec<u8>,
        metadata: HashMap<String, String>,
        options_bytes: Vec<u8>,
    ) -> Result<FfiConnectorHttpRequest, UniffiError> {
        let payload = PaymentServiceAuthorizeRequest::decode(Bytes::from(request_bytes))
            .map_err(|e| UniffiError::DecodeError { msg: e.to_string() })?;

        let ffi_metadata = parse_metadata(&metadata)?;
        let masked_metadata = ffi_headers_to_masked_metadata(&metadata)?;

        let request = FfiRequestData {
            payload,
            extracted_metadata: ffi_metadata,
            masked_metadata: Some(masked_metadata),
        };

        let ffi_options = parse_ffi_options(options_bytes);

        let result =
            authorize_req_handler(request, ffi_options).map_err(|e| UniffiError::HandlerError {
                msg: format!("{e:?}"),
            })?;

        let connector_request = result.ok_or(UniffiError::NoConnectorRequest)?;

        build_ffi_request(&connector_request)
    }

    /// Process the connector HTTP response and produce a structured response.
    ///
    /// # Arguments
    /// - `response`: `FfiConnectorHttpResponse` record containing raw status, headers, and body
    /// - `request_bytes`: the original protobuf-encoded `PaymentServiceAuthorizeRequest`
    /// - `metadata`: the original metadata map passed to `authorize_req_transformer`
    /// - `options_bytes`: protobuf-encoded `FfiOptions` (optional)
    ///
    /// # Returns
    /// protobuf-encoded `PaymentServiceAuthorizeResponse` bytes
    #[uniffi::export]
    pub fn authorize_res_transformer(
        response: FfiConnectorHttpResponse,
        request_bytes: Vec<u8>,
        metadata: HashMap<String, String>,
        options_bytes: Vec<u8>,
    ) -> Result<Vec<u8>, UniffiError> {
        let domain_response = build_domain_response(response);

        let payload = PaymentServiceAuthorizeRequest::decode(Bytes::from(request_bytes))
            .map_err(|e| UniffiError::DecodeError { msg: e.to_string() })?;

        let ffi_metadata = parse_metadata(&metadata)?;
        let masked_metadata = ffi_headers_to_masked_metadata(&metadata)?;

        let request = FfiRequestData {
            payload,
            extracted_metadata: ffi_metadata,
            masked_metadata: Some(masked_metadata),
        };

        let ffi_options = parse_ffi_options(options_bytes);

        let proto_response =
            authorize_res_handler(request, domain_response, ffi_options).map_err(|e| {
                UniffiError::HandlerError {
                    msg: format!("{e:?}"),
                }
            })?;

        Ok(proto_response.encode_to_vec())
    }

    /// Build the connector HTTP request for capture operation.
    ///
    /// # Arguments
    /// - `request_bytes`: protobuf-encoded `PaymentServiceCaptureRequest`
    /// - `metadata`: flat map with keys `connector` and `connector_auth_type`
    /// - `options_bytes`: protobuf-encoded `FfiOptions` (optional)
    ///
    /// # Returns
    /// FfiConnectorHttpRequest struct (Binary Safe)
    #[uniffi::export]
    pub fn capture_req_transformer(
        request_bytes: Vec<u8>,
        metadata: HashMap<String, String>,
        options_bytes: Vec<u8>,
    ) -> Result<FfiConnectorHttpRequest, UniffiError> {
        let payload = PaymentServiceCaptureRequest::decode(Bytes::from(request_bytes))
            .map_err(|e| UniffiError::DecodeError { msg: e.to_string() })?;

        let ffi_metadata = parse_metadata(&metadata)?;
        let masked_metadata = ffi_headers_to_masked_metadata(&metadata)?;

        let request = FfiRequestData {
            payload,
            extracted_metadata: ffi_metadata,
            masked_metadata: Some(masked_metadata),
        };

        let ffi_options = parse_ffi_options(options_bytes);

        let result =
            capture_req_handler(request, ffi_options).map_err(|e| UniffiError::HandlerError {
                msg: format!("{e:?}"),
            })?;

        let connector_request = result.ok_or(UniffiError::NoConnectorRequest)?;

        build_ffi_request(&connector_request)
    }

    /// Process the connector HTTP response for capture operation.
    ///
    /// # Arguments
    /// - `response`: `FfiConnectorHttpResponse` record
    /// - `request_bytes`: the original protobuf-encoded `PaymentServiceCaptureRequest`
    /// - `metadata`: the original metadata map passed to `capture_req_transformer`
    /// - `options_bytes`: protobuf-encoded `FfiOptions` (optional)
    ///
    /// # Returns
    /// protobuf-encoded `PaymentServiceCaptureResponse` bytes
    #[uniffi::export]
    pub fn capture_res_transformer(
        response: FfiConnectorHttpResponse,
        request_bytes: Vec<u8>,
        metadata: HashMap<String, String>,
        options_bytes: Vec<u8>,
    ) -> Result<Vec<u8>, UniffiError> {
        let domain_response = build_domain_response(response);

        let payload = PaymentServiceCaptureRequest::decode(Bytes::from(request_bytes))
            .map_err(|e| UniffiError::DecodeError { msg: e.to_string() })?;

        let ffi_metadata = parse_metadata(&metadata)?;
        let masked_metadata = ffi_headers_to_masked_metadata(&metadata)?;

        let request = FfiRequestData {
            payload,
            extracted_metadata: ffi_metadata,
            masked_metadata: Some(masked_metadata),
        };

        let ffi_options = parse_ffi_options(options_bytes);

        let proto_response =
            capture_res_handler(request, domain_response, ffi_options).map_err(|e| {
                UniffiError::HandlerError {
                    msg: format!("{e:?}"),
                }
            })?;

        Ok(proto_response.encode_to_vec())
    }

    /// Build the connector HTTP request for void operation.
    ///
    /// # Arguments
    /// - `request_bytes`: protobuf-encoded `PaymentServiceVoidRequest`
    /// - `metadata`: flat map with keys `connector` and `connector_auth_type`
    /// - `options_bytes`: protobuf-encoded `FfiOptions` (optional)
    ///
    /// # Returns
    /// FfiConnectorHttpRequest struct (Binary Safe)
    #[uniffi::export]
    pub fn void_req_transformer(
        request_bytes: Vec<u8>,
        metadata: HashMap<String, String>,
        options_bytes: Vec<u8>,
    ) -> Result<FfiConnectorHttpRequest, UniffiError> {
        let payload = PaymentServiceVoidRequest::decode(Bytes::from(request_bytes))
            .map_err(|e| UniffiError::DecodeError { msg: e.to_string() })?;

        let ffi_metadata = parse_metadata(&metadata)?;
        let masked_metadata = ffi_headers_to_masked_metadata(&metadata)?;

        let request = FfiRequestData {
            payload,
            extracted_metadata: ffi_metadata,
            masked_metadata: Some(masked_metadata),
        };

        let ffi_options = parse_ffi_options(options_bytes);

        let result =
            void_req_handler(request, ffi_options).map_err(|e| UniffiError::HandlerError {
                msg: format!("{e:?}"),
            })?;

        let connector_request = result.ok_or(UniffiError::NoConnectorRequest)?;

        build_ffi_request(&connector_request)
    }

    /// Process the connector HTTP response for void operation.
    ///
    /// # Arguments
    /// - `response`: `FfiConnectorHttpResponse` record
    /// - `request_bytes`: the original protobuf-encoded `PaymentServiceVoidRequest`
    /// - `metadata`: the original metadata map passed to `void_req_transformer`
    /// - `options_bytes`: protobuf-encoded `FfiOptions` (optional)
    ///
    /// # Returns
    /// protobuf-encoded `PaymentServiceVoidResponse` bytes
    #[uniffi::export]
    pub fn void_res_transformer(
        response: FfiConnectorHttpResponse,
        request_bytes: Vec<u8>,
        metadata: HashMap<String, String>,
        options_bytes: Vec<u8>,
    ) -> Result<Vec<u8>, UniffiError> {
        let domain_response = build_domain_response(response);

        let payload = PaymentServiceVoidRequest::decode(Bytes::from(request_bytes))
            .map_err(|e| UniffiError::DecodeError { msg: e.to_string() })?;

        let ffi_metadata = parse_metadata(&metadata)?;
        let masked_metadata = ffi_headers_to_masked_metadata(&metadata)?;

        let request = FfiRequestData {
            payload,
            extracted_metadata: ffi_metadata,
            masked_metadata: Some(masked_metadata),
        };

        let ffi_options = parse_ffi_options(options_bytes);

        let proto_response =
            void_res_handler(request, domain_response, ffi_options).map_err(|e| {
                UniffiError::HandlerError {
                    msg: format!("{e:?}"),
                }
            })?;

        Ok(proto_response.encode_to_vec())
    }

    /// Build the connector HTTP request for get operation.
    ///
    /// # Arguments
    /// - `request_bytes`: protobuf-encoded `PaymentServiceGetRequest`
    /// - `metadata`: flat map with keys `connector` and `connector_auth_type`
    /// - `options_bytes`: protobuf-encoded `FfiOptions` (optional)
    ///
    /// # Returns
    /// FfiConnectorHttpRequest struct (Binary Safe)
    #[uniffi::export]
    pub fn get_req_transformer(
        request_bytes: Vec<u8>,
        metadata: HashMap<String, String>,
        options_bytes: Vec<u8>,
    ) -> Result<FfiConnectorHttpRequest, UniffiError> {
        let payload = PaymentServiceGetRequest::decode(Bytes::from(request_bytes))
            .map_err(|e| UniffiError::DecodeError { msg: e.to_string() })?;

        let ffi_metadata = parse_metadata(&metadata)?;
        let masked_metadata = ffi_headers_to_masked_metadata(&metadata)?;

        let request = FfiRequestData {
            payload,
            extracted_metadata: ffi_metadata,
            masked_metadata: Some(masked_metadata),
        };

        let ffi_options = parse_ffi_options(options_bytes);

        let result =
            get_req_handler(request, ffi_options).map_err(|e| UniffiError::HandlerError {
                msg: format!("{e:?}"),
            })?;

        let connector_request = result.ok_or(UniffiError::NoConnectorRequest)?;

        build_ffi_request(&connector_request)
    }

    /// Process the connector HTTP response for get operation.
    ///
    /// # Arguments
    /// - `response`: `FfiConnectorHttpResponse` record
    /// - `request_bytes`: the original protobuf-encoded `PaymentServiceGetRequest`
    /// - `metadata`: the original metadata map passed to `get_req_transformer`
    /// - `options_bytes`: protobuf-encoded `FfiOptions` (optional)
    ///
    /// # Returns
    /// protobuf-encoded `PaymentServiceGetResponse` bytes
    #[uniffi::export]
    pub fn get_res_transformer(
        response: FfiConnectorHttpResponse,
        request_bytes: Vec<u8>,
        metadata: HashMap<String, String>,
        options_bytes: Vec<u8>,
    ) -> Result<Vec<u8>, UniffiError> {
        let domain_response = build_domain_response(response);

        let payload = PaymentServiceGetRequest::decode(Bytes::from(request_bytes))
            .map_err(|e| UniffiError::DecodeError { msg: e.to_string() })?;

        let ffi_metadata = parse_metadata(&metadata)?;
        let masked_metadata = ffi_headers_to_masked_metadata(&metadata)?;

        let request = FfiRequestData {
            payload,
            extracted_metadata: ffi_metadata,
            masked_metadata: Some(masked_metadata),
        };

        let ffi_options = parse_ffi_options(options_bytes);

        let proto_response =
            get_res_handler(request, domain_response, ffi_options).map_err(|e| {
                UniffiError::HandlerError {
                    msg: format!("{e:?}"),
                }
            })?;

        Ok(proto_response.encode_to_vec())
    }

    /// Build the connector HTTP request for create access token operation.
    ///
    /// # Arguments
    /// - `request_bytes`: protobuf-encoded `MerchantAuthenticationServiceCreateAccessTokenRequest`
    /// - `metadata`: flat map with keys `connector` and `connector_auth_type`
    /// - `options_bytes`: protobuf-encoded `FfiOptions` (optional)
    ///
    /// # Returns
    /// FfiConnectorHttpRequest struct (Binary Safe)
    #[uniffi::export]
    pub fn create_access_token_req_transformer(
        request_bytes: Vec<u8>,
        metadata: HashMap<String, String>,
        options_bytes: Vec<u8>,
    ) -> Result<FfiConnectorHttpRequest, UniffiError> {
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

        let ffi_options = parse_ffi_options(options_bytes);

        let result = create_access_token_req_handler(request, ffi_options).map_err(|e| {
            UniffiError::HandlerError {
                msg: format!("{e:?}"),
            }
        })?;

        let connector_request = result.ok_or(UniffiError::NoConnectorRequest)?;

        build_ffi_request(&connector_request)
    }

    /// Process the connector HTTP response for create access token operation.
    ///
    /// # Arguments
    /// - `response`: `FfiConnectorHttpResponse` record
    /// - `request_bytes`: the original protobuf-encoded `MerchantAuthenticationServiceCreateAccessTokenRequest`
    /// - `metadata`: the original metadata map passed to `create_access_token_req_transformer`
    /// - `options_bytes`: protobuf-encoded `FfiOptions` (optional)
    ///
    /// # Returns
    /// protobuf-encoded `MerchantAuthenticationServiceCreateAccessTokenResponse` bytes
    #[uniffi::export]
    pub fn create_access_token_res_transformer(
        response: FfiConnectorHttpResponse,
        request_bytes: Vec<u8>,
        metadata: HashMap<String, String>,
        options_bytes: Vec<u8>,
    ) -> Result<Vec<u8>, UniffiError> {
        let domain_response = build_domain_response(response);

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

        let ffi_options = parse_ffi_options(options_bytes);

        let proto_response = create_access_token_res_handler(request, domain_response, ffi_options)
            .map_err(|e| UniffiError::HandlerError {
                msg: format!("{e:?}"),
            })?;

        Ok(proto_response.encode_to_vec())
    }

    /// Build the connector HTTP request for refund operation.
    ///
    /// # Arguments
    /// - `request_bytes`: protobuf-encoded `PaymentServiceRefundRequest`
    /// - `metadata`: flat map with keys `connector` and `connector_auth_type`
    /// - `options_bytes`: protobuf-encoded `FfiOptions` (optional)
    ///
    /// # Returns
    /// FfiConnectorHttpRequest struct (Binary Safe)
    #[uniffi::export]
    pub fn refund_req_transformer(
        request_bytes: Vec<u8>,
        metadata: HashMap<String, String>,
        options_bytes: Vec<u8>,
    ) -> Result<FfiConnectorHttpRequest, UniffiError> {
        let payload = PaymentServiceRefundRequest::decode(Bytes::from(request_bytes))
            .map_err(|e| UniffiError::DecodeError { msg: e.to_string() })?;

        let ffi_metadata = parse_metadata(&metadata)?;
        let masked_metadata = ffi_headers_to_masked_metadata(&metadata)?;

        let request = FfiRequestData {
            payload,
            extracted_metadata: ffi_metadata,
            masked_metadata: Some(masked_metadata),
        };

        let ffi_options = parse_ffi_options(options_bytes);

        let result =
            refund_req_handler(request, ffi_options).map_err(|e| UniffiError::HandlerError {
                msg: format!("{e:?}"),
            })?;

        let connector_request = result.ok_or(UniffiError::NoConnectorRequest)?;

        build_ffi_request(&connector_request)
    }

    /// Process the connector HTTP response for refund operation.
    ///
    /// # Arguments
    /// - `response`: `FfiConnectorHttpResponse` record
    /// - `request_bytes`: the original protobuf-encoded `PaymentServiceRefundRequest`
    /// - `metadata`: the original metadata map passed to `refund_req_transformer`
    /// - `options_bytes`: protobuf-encoded `FfiOptions` (optional)
    ///
    /// # Returns
    /// protobuf-encoded `PaymentServiceRefundResponse` bytes
    #[uniffi::export]
    pub fn refund_res_transformer(
        response: FfiConnectorHttpResponse,
        request_bytes: Vec<u8>,
        metadata: HashMap<String, String>,
        options_bytes: Vec<u8>,
    ) -> Result<Vec<u8>, UniffiError> {
        let domain_response = build_domain_response(response);

        let payload = PaymentServiceRefundRequest::decode(Bytes::from(request_bytes))
            .map_err(|e| UniffiError::DecodeError { msg: e.to_string() })?;

        let ffi_metadata = parse_metadata(&metadata)?;
        let masked_metadata = ffi_headers_to_masked_metadata(&metadata)?;

        let request = FfiRequestData {
            payload,
            extracted_metadata: ffi_metadata,
            masked_metadata: Some(masked_metadata),
        };

        let ffi_options = parse_ffi_options(options_bytes);

        let proto_response =
            refund_res_handler(request, domain_response, ffi_options).map_err(|e| {
                UniffiError::HandlerError {
                    msg: format!("{e:?}"),
                }
            })?;

        Ok(proto_response.encode_to_vec())
    }
}

#[cfg(feature = "uniffi")]
// macro implementation need to implemented
pub use uniffi_bindings_inner::*;
