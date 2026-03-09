// Package: ffi.bindings
// File: uniffi.rs
//
// Overview:
//   UniFFI bridge implementation for the Connector Service.
//   Provides the top-level FFI entry points for request and response transformations.

#[cfg(feature = "uniffi")]
mod uniffi_bindings_inner {
    use crate::errors::FfiError;
    use bytes::Bytes;
    use common_utils::request::Request;
    use domain_types::connector_types::ConnectorEnum;
    use domain_types::router_data::ConnectorSpecificAuth;
    use domain_types::router_response_types::Response;
    use domain_types::utils::ForeignTryFrom;
    use grpc_api_types::payments::{
        Environment, FfiConnectorHttpRequest, FfiConnectorHttpResponse, FfiOptions,
        FfiRequestError, FfiResponseError,
    };
    use http::header::{HeaderMap, HeaderName, HeaderValue};
    use prost::Message;

    // ── Shared helpers ────────────────────────────────────────────────────────

    /// Build FfiMetadataPayload from FfiOptions.
    fn parse_metadata(options: &FfiOptions) -> Result<crate::types::FfiMetadataPayload, FfiError> {
        // 1. Resolve Connector (Taken from FfiOptions)
        let proto_connector = options.connector(); // Direct enum access via generated method
        let connector = ConnectorEnum::foreign_try_from(proto_connector).map_err(|e| {
            FfiError::MetadataParseError {
                msg: format!("Connector mapping failed: {e}"),
            }
        })?;

        // 2. Resolve Auth (Taken from typed Protobuf in FfiOptions)
        let proto_auth = options
            .auth
            .as_ref()
            .ok_or_else(|| FfiError::MissingMetadata {
                key: "auth".to_string(),
            })?;

        let connector_auth_type = ConnectorSpecificAuth::foreign_try_from(proto_auth.clone())
            .map_err(|e| FfiError::MetadataParseError {
                msg: format!("Typed auth mapping failed: {e}"),
            })?;

        Ok(crate::types::FfiMetadataPayload {
            connector,
            connector_auth_type,
        })
    }

    /// Helper to convert internal Request to Protobuf FfiConnectorHttpRequest bytes.
    fn build_ffi_request_bytes(request: &Request) -> Result<Vec<u8>, FfiError> {
        let mut headers = request.get_headers_map();
        let (body, boundary) = request
            .body
            .as_ref()
            .map(|b| b.get_body_bytes())
            .transpose()
            .map_err(|e| FfiError::HandlerError { msg: e.to_string() })?
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
    fn build_domain_response(response_bytes: Vec<u8>) -> Result<Response, FfiError> {
        let response = FfiConnectorHttpResponse::decode(Bytes::from(response_bytes))
            .map_err(|e| FfiError::DecodeError { msg: e.to_string() })?;
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
                .map_err(|e| FfiError::DecodeError {
                    msg: format!("Invalid HTTP status code: {e}"),
                })?,
        })
    }

    /// Parse FfiOptions from optional bytes.
    fn parse_ffi_options(options_bytes: Vec<u8>) -> Result<FfiOptions, FfiError> {
        if options_bytes.is_empty() {
            return Err(FfiError::DecodeError {
                msg: "FfiOptions bytes are empty".to_string(),
            });
        }
        FfiOptions::decode(Bytes::from(options_bytes))
            .map_err(|e| FfiError::DecodeError { msg: e.to_string() })
    }

    // ── Generic transformer runners ───────────────────────────────────────────

    /// Decode `request_bytes` as `Req`, build `FfiRequestData`, call `handler`,
    /// and encode the resulting connector HTTP request as protobuf bytes.
    /// If the handler returns an error, encode the FfiRequestError to bytes.
    fn run_req_transformer<Req>(
        request_bytes: Vec<u8>,
        options_bytes: Vec<u8>,
        handler: impl Fn(
            crate::types::FfiRequestData<Req>,
            Option<Environment>,
        ) -> Result<Option<Request>, FfiRequestError>,
    ) -> Vec<u8>
    where
        Req: Message + Default,
    {
        let payload = match Req::decode(Bytes::from(request_bytes)) {
            Ok(p) => p,
            Err(e) => {
                return FfiRequestError::from(FfiError::DecodeError { msg: e.to_string() })
                    .encode_to_vec()
            }
        };

        let ffi_options = match parse_ffi_options(options_bytes) {
            Ok(o) => o,
            Err(e) => return FfiRequestError::from(e).encode_to_vec(),
        };
        let ffi_metadata = match parse_metadata(&ffi_options) {
            Ok(m) => m,
            Err(e) => return FfiRequestError::from(e).encode_to_vec(),
        };

        let request = crate::types::FfiRequestData {
            payload,
            extracted_metadata: ffi_metadata,
            masked_metadata: None,
        };

        let environment = Some(ffi_options.environment());

        let result = match handler(request, environment) {
            Ok(r) => r,
            Err(e) => return e.encode_to_vec(),
        };

        let connector_request = match result {
            Some(r) => r,
            None => return FfiRequestError::from(FfiError::NoConnectorRequest).encode_to_vec(),
        };

        match build_ffi_request_bytes(&connector_request) {
            Ok(bytes) => bytes,
            Err(e) => FfiRequestError::from(e).encode_to_vec(),
        }
    }

    /// Decode `response_bytes` as the domain `Response` and `request_bytes` as `Req`,
    /// call `handler`, and encode the result as protobuf bytes.
    /// If the handler returns an error, encode the FfiResponseError to bytes.
    fn run_res_transformer<Req, Res>(
        response_bytes: Vec<u8>,
        request_bytes: Vec<u8>,
        options_bytes: Vec<u8>,
        handler: impl Fn(
            crate::types::FfiRequestData<Req>,
            Response,
            Option<Environment>,
        ) -> Result<Res, FfiResponseError>,
    ) -> Vec<u8>
    where
        Req: Message + Default,
        Res: Message,
    {
        let domain_response = match build_domain_response(response_bytes) {
            Ok(r) => r,
            Err(e) => return FfiResponseError::from(e).encode_to_vec(),
        };

        let payload = match Req::decode(Bytes::from(request_bytes)) {
            Ok(p) => p,
            Err(e) => {
                return FfiResponseError::from(FfiError::DecodeError { msg: e.to_string() })
                    .encode_to_vec()
            }
        };

        let ffi_options = match parse_ffi_options(options_bytes) {
            Ok(o) => o,
            Err(e) => return FfiResponseError::from(e).encode_to_vec(),
        };
        let ffi_metadata = match parse_metadata(&ffi_options) {
            Ok(m) => m,
            Err(e) => return FfiResponseError::from(e).encode_to_vec(),
        };

        let request = crate::types::FfiRequestData {
            payload,
            extracted_metadata: ffi_metadata,
            masked_metadata: None,
        };

        let environment = Some(ffi_options.environment());

        match handler(request, domain_response, environment) {
            Ok(proto_response) => proto_response.encode_to_vec(),
            Err(e) => e.encode_to_vec(),
        }
    }

    // ── Flow macro ────────────────────────────────────────────────────────────

    /// Generates a `#[uniffi::export]` `{flow}_req_transformer` and
    /// `{flow}_res_transformer` function pair backed by the generic runners.
    ///
    /// # Arguments
    /// - `$flow`        — snake_case flow name (used as identifier prefix)
    /// - `$req_type`    — protobuf request type to decode from bytes
    /// - `$req_handler` — handler fn: `(FfiRequestData<Req>, Option<Environment>) -> Result<Option<Request>, FfiRequestError>`
    /// - `$res_handler` — handler fn: `(FfiRequestData<Req>, Response, Option<Environment>) -> Result<Res, FfiResponseError>`
    macro_rules! define_ffi_flow {
        ($flow:ident, $req_type:ty, $req_handler:path, $res_handler:path) => {
            paste::paste! {
                #[uniffi::export]
                pub fn [<$flow _req_transformer>](
                    request_bytes: Vec<u8>,
                    options_bytes: Vec<u8>,
                ) -> Vec<u8> {
                    run_req_transformer::<$req_type>(
                        request_bytes,
                        options_bytes,
                        $req_handler,
                    )
                }

                #[uniffi::export]
                pub fn [<$flow _res_transformer>](
                    response_bytes: Vec<u8>,
                    request_bytes: Vec<u8>,
                    options_bytes: Vec<u8>,
                ) -> Vec<u8> {
                    run_res_transformer::<$req_type, _>(
                        response_bytes,
                        request_bytes,
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

    // ── Hand-written exports (not auto-generated) ─────────────────────────────

    /// handle_event — synchronous webhook processing (single-step, no outgoing HTTP).
    ///
    /// Unlike req/res flows there is no split: the caller passes raw
    /// `EventServiceHandleRequest` proto bytes and receives encoded
    /// `EventServiceHandleResponse` bytes directly.
    #[uniffi::export]
    pub fn handle_event_transformer(request_bytes: Vec<u8>, options_bytes: Vec<u8>) -> Vec<u8> {
        use prost::Message as _;

        let payload = match grpc_api_types::payments::EventServiceHandleRequest::decode(
            Bytes::from(request_bytes),
        ) {
            Ok(p) => p,
            Err(e) => {
                return FfiResponseError::from(FfiError::DecodeError { msg: e.to_string() })
                    .encode_to_vec()
            }
        };

        let ffi_options = match parse_ffi_options(options_bytes) {
            Ok(o) => o,
            Err(e) => return FfiResponseError::from(e).encode_to_vec(),
        };
        let ffi_metadata = match parse_metadata(&ffi_options) {
            Ok(m) => m,
            Err(e) => return FfiResponseError::from(e).encode_to_vec(),
        };

        let request = crate::types::FfiRequestData {
            payload,
            extracted_metadata: ffi_metadata,
            masked_metadata: None,
        };

        let environment = Some(ffi_options.environment());

        match crate::handlers::payments::handle_event_handler(request, environment) {
            Ok(response) => response.encode_to_vec(),
            Err(e) => e.encode_to_vec(),
        }
    }
}

#[cfg(feature = "uniffi")]
pub use uniffi_bindings_inner::*;
