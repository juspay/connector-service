#[cfg(feature = "uniffi")]
mod uniffi_bindings_inner {
    use crate::errors::UniffiError;
    use crate::utils::ffi_headers_to_masked_metadata;
    use bytes::Bytes;
    use common_utils::request::Request;
    use domain_types::router_response_types::Response;
    use grpc_api_types::payments::{FfiConnectorHttpRequest, FfiConnectorHttpResponse, FfiOptions};
    use http::header::{HeaderMap, HeaderName, HeaderValue};
    use prost::Message;
    use std::collections::HashMap;

    // ── Shared helpers ────────────────────────────────────────────────────────

    /// Build FfiMetadataPayload from the caller's flat HashMap.
    ///
    /// Expected keys:
    ///   "connector"           — connector name, e.g. "Stripe"
    ///   "connector_auth_type" — JSON-encoded typed auth, e.g.
    ///                           '{"Stripe":{"api_key":"sk_test_..."}}'
    fn parse_metadata(
        metadata: &HashMap<String, String>,
    ) -> Result<crate::types::FfiMetadataPayload, UniffiError> {
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

    /// Helper to convert internal Request to Protobuf FfiConnectorHttpRequest bytes.
    fn build_ffi_request_bytes(request: &Request) -> Result<Vec<u8>, UniffiError> {
        let mut headers = request.get_headers_map();
        let (body, boundary) = request
            .body
            .as_ref()
            .map(|b| b.get_body_bytes())
            .transpose()
            .map_err(|e| UniffiError::HandlerError { msg: e.to_string() })?
            .unwrap_or((None, None));

        if let Some(boundary) = boundary {
            headers.insert(
                "content-type".to_string(),
                format!("multipart/form-data; boundary={}", boundary),
            );
        }

        let proto = FfiConnectorHttpRequest {
            url: request.url.clone(),
            method: request.method.to_string(),
            headers,
            body,
        };

        Ok(proto.encode_to_vec())
    }

    /// Helper to convert Protobuf FfiConnectorHttpResponse bytes to internal Response.
    fn build_domain_response(response_bytes: Vec<u8>) -> Result<Response, UniffiError> {
        let response = FfiConnectorHttpResponse::decode(Bytes::from(response_bytes))
            .map_err(|e| UniffiError::DecodeError { msg: e.to_string() })?;

        let mut header_map = HeaderMap::new();
        for (key, value) in &response.headers {
            if let (Ok(name), Ok(val)) = (
                HeaderName::from_bytes(key.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                header_map.insert(name, val);
            }
        }

        Ok(Response {
            headers: if header_map.is_empty() {
                None
            } else {
                Some(header_map)
            },
            response: Bytes::from(response.body),
            status_code: response
                .status_code
                .try_into()
                .map_err(|e| UniffiError::DecodeError {
                    msg: format!("Invalid HTTP status code: {e}"),
                })?,
        })
    }

    /// Parse FfiOptions from optional bytes and extract test_mode.
    fn parse_ffi_options(options_bytes: Vec<u8>) -> Option<bool> {
        if options_bytes.is_empty() {
            return None;
        }
        let ffi_options = FfiOptions::decode(Bytes::from(options_bytes)).ok()?;
        ffi_options.env.as_ref().map(|env| env.test_mode)
    }

    // ── Generic transformer runners ───────────────────────────────────────────

    /// Decode `request_bytes` as `Req`, build `FfiRequestData`, call `handler`,
    /// and encode the resulting connector HTTP request as protobuf bytes.
    fn run_req_transformer<Req>(
        request_bytes: Vec<u8>,
        metadata: HashMap<String, String>,
        options_bytes: Vec<u8>,
        handler: impl Fn(
            crate::types::FfiRequestData<Req>,
            Option<bool>,
        ) -> Result<Option<Request>, crate::errors::FfiPaymentError>,
    ) -> Result<Vec<u8>, UniffiError>
    where
        Req: prost::Message + Default,
    {
        let payload = Req::decode(Bytes::from(request_bytes))
            .map_err(|e| UniffiError::DecodeError { msg: e.to_string() })?;

        let ffi_metadata = parse_metadata(&metadata)?;
        let masked_metadata = ffi_headers_to_masked_metadata(&metadata)?;

        let request = crate::types::FfiRequestData {
            payload,
            extracted_metadata: ffi_metadata,
            masked_metadata: Some(masked_metadata),
        };

        let ffi_options = parse_ffi_options(options_bytes);

        let result = handler(request, ffi_options)
            .map_err(|e| UniffiError::HandlerError { msg: format!("{e:?}") })?;
        let connector_request = result.ok_or(UniffiError::NoConnectorRequest)?;
        build_ffi_request_bytes(&connector_request)
    }

    /// Decode `response_bytes` as the domain `Response` and `request_bytes` as `Req`,
    /// call `handler`, and encode the result as protobuf bytes.
    fn run_res_transformer<Req, Res>(
        response_bytes: Vec<u8>,
        request_bytes: Vec<u8>,
        metadata: HashMap<String, String>,
        options_bytes: Vec<u8>,
        handler: impl Fn(
            crate::types::FfiRequestData<Req>,
            Response,
            Option<bool>,
        ) -> Result<Res, crate::errors::FfiPaymentError>,
    ) -> Result<Vec<u8>, UniffiError>
    where
        Req: prost::Message + Default,
        Res: prost::Message,
    {
        let domain_response = build_domain_response(response_bytes)?;

        let payload = Req::decode(Bytes::from(request_bytes))
            .map_err(|e| UniffiError::DecodeError { msg: e.to_string() })?;

        let ffi_metadata = parse_metadata(&metadata)?;
        let masked_metadata = ffi_headers_to_masked_metadata(&metadata)?;

        let request = crate::types::FfiRequestData {
            payload,
            extracted_metadata: ffi_metadata,
            masked_metadata: Some(masked_metadata),
        };

        let ffi_options = parse_ffi_options(options_bytes);

        let proto_response = handler(request, domain_response, ffi_options)
            .map_err(|e| UniffiError::HandlerError { msg: format!("{e:?}") })?;
        Ok(proto_response.encode_to_vec())
    }

    // ── Flow macro ────────────────────────────────────────────────────────────

    /// Generates a `#[uniffi::export]` `{flow}_req_transformer` and
    /// `{flow}_res_transformer` function pair backed by the generic runners.
    ///
    /// # Arguments
    /// - `$flow`        — snake_case flow name (used as identifier prefix)
    /// - `$req_type`    — protobuf request type to decode from bytes
    /// - `$req_handler` — handler fn: `(FfiRequestData<Req>, Option<bool>) -> Result<Option<Request>, _>`
    /// - `$res_handler` — handler fn: `(FfiRequestData<Req>, Response, Option<bool>) -> Result<Res, _>`
    macro_rules! define_ffi_flow {
        ($flow:ident, $req_type:ty, $req_handler:path, $res_handler:path) => {
            paste::paste! {
                #[uniffi::export]
                pub fn [<$flow _req_transformer>](
                    request_bytes: Vec<u8>,
                    metadata: HashMap<String, String>,
                    options_bytes: Vec<u8>,
                ) -> Result<Vec<u8>, UniffiError> {
                    run_req_transformer::<$req_type>(
                        request_bytes,
                        metadata,
                        options_bytes,
                        $req_handler,
                    )
                }

                #[uniffi::export]
                pub fn [<$flow _res_transformer>](
                    response_bytes: Vec<u8>,
                    request_bytes: Vec<u8>,
                    metadata: HashMap<String, String>,
                    options_bytes: Vec<u8>,
                ) -> Result<Vec<u8>, UniffiError> {
                    run_res_transformer::<$req_type, _>(
                        response_bytes,
                        request_bytes,
                        metadata,
                        options_bytes,
                        $res_handler,
                    )
                }
            }
        };
    }

    // ── Flow registrations (auto-generated) ──────────────────────────────────
    // To add a new flow: implement req_transformer!/res_transformer! in
    // services/payments.rs, then run `make generate` to regenerate this file.

    include!("_generated_ffi_flows.rs");
}

#[cfg(feature = "uniffi")]
pub use uniffi_bindings_inner::*;
