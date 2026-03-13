// Package: ffi.bindings
// File: uniffi.rs
//
// Overview:
//   UniFFI bridge implementation for the Connector Service.
//   Provides the top-level FFI entry points for request and response transformations.

#[cfg(feature = "uniffi")]
mod uniffi_bindings_inner {
    use crate::errors::UniffiError;
    use bytes::Bytes;
    use common_utils::request::Request;
    use domain_types::connector_types::ConnectorEnum;
    use domain_types::router_data::ConnectorSpecificConfig;
    use domain_types::router_response_types::Response;
    use domain_types::utils::ForeignTryFrom;
    use grpc_api_types::payments::{
        Environment, FfiConnectorHttpRequest, FfiConnectorHttpResponse, FfiOptions,
    };
    use http::header::{HeaderMap, HeaderName, HeaderValue};
    use prost::Message;

    // ── Shared helpers ────────────────────────────────────────────────────────

    /// Build FfiMetadataPayload from FfiOptions.
    /// The connector identity is inferred from which ConnectorSpecificConfig variant is set.
    fn parse_metadata(
        options: &FfiOptions,
    ) -> Result<crate::types::FfiMetadataPayload, UniffiError> {
        // 1. Resolve ConnectorSpecificConfig from FfiOptions
        let proto_config =
            options
                .connector_config
                .as_ref()
                .ok_or_else(|| UniffiError::MissingMetadata {
                    key: "connector_config".to_string(),
                })?;

        // 2. Infer connector from which oneof variant is set
        let config_variant =
            proto_config
                .config
                .as_ref()
                .ok_or_else(|| UniffiError::MissingMetadata {
                    key: "connector_config.config".to_string(),
                })?;

        let connector = ConnectorEnum::foreign_try_from(config_variant.clone()).map_err(|e| {
            UniffiError::MetadataParseError {
                msg: format!("Connector mapping failed: {e}"),
            }
        })?;

        // 3. Convert proto config to domain ConnectorSpecificConfig
        let connector_config = ConnectorSpecificConfig::foreign_try_from(proto_config.clone())
            .map_err(|e| UniffiError::MetadataParseError {
                msg: format!("Typed connector config mapping failed: {e}"),
            })?;

        Ok(crate::types::FfiMetadataPayload {
            connector,
            connector_config,
        })
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

    /// Parse FfiOptions from optional bytes.
    fn parse_ffi_options(options_bytes: Vec<u8>) -> Result<FfiOptions, UniffiError> {
        if options_bytes.is_empty() {
            return Err(UniffiError::DecodeError {
                msg: "FfiOptions bytes are empty".to_string(),
            });
        }
        FfiOptions::decode(Bytes::from(options_bytes))
            .map_err(|e| UniffiError::DecodeError { msg: e.to_string() })
    }

    // ── Generic transformer runners ───────────────────────────────────────────

    /// Decode `request_bytes` as `Req`, build `FfiRequestData`, call `handler`,
    /// and encode the resulting connector HTTP request as protobuf bytes.
    fn run_req_transformer<Req>(
        request_bytes: Vec<u8>,
        options_bytes: Vec<u8>,
        handler: impl Fn(
            crate::types::FfiRequestData<Req>,
            Option<Environment>,
        ) -> Result<Option<Request>, grpc_api_types::payments::RequestError>,
    ) -> Result<Vec<u8>, UniffiError>
    where
        Req: Message + Default,
    {
        let payload = Req::decode(Bytes::from(request_bytes))
            .map_err(|e| UniffiError::DecodeError { msg: e.to_string() })?;

        let ffi_options = parse_ffi_options(options_bytes)?;
        let ffi_metadata = parse_metadata(&ffi_options)?;

        let request = crate::types::FfiRequestData {
            payload,
            extracted_metadata: ffi_metadata,
            masked_metadata: None,
        };

        let environment = Some(ffi_options.environment());

        let result = handler(request, environment).map_err(|e| UniffiError::HandlerError {
            msg: format!("{e:?}"),
        })?;
        let connector_request = result.ok_or(UniffiError::NoConnectorRequest)?;
        build_ffi_request_bytes(&connector_request)
    }

    /// Decode `response_bytes` as the domain `Response` and `request_bytes` as `Req`,
    /// call `handler`, and encode the result as protobuf bytes.
    fn run_res_transformer<Req, Res>(
        response_bytes: Vec<u8>,
        request_bytes: Vec<u8>,
        options_bytes: Vec<u8>,
        handler: impl Fn(
            crate::types::FfiRequestData<Req>,
            Response,
            Option<Environment>,
        ) -> Result<Res, grpc_api_types::payments::ResponseError>,
    ) -> Result<Vec<u8>, UniffiError>
    where
        Req: Message + Default,
        Res: Message,
    {
        let domain_response = build_domain_response(response_bytes)?;

        let payload = Req::decode(Bytes::from(request_bytes))
            .map_err(|e| UniffiError::DecodeError { msg: e.to_string() })?;

        let ffi_options = parse_ffi_options(options_bytes)?;
        let ffi_metadata = parse_metadata(&ffi_options)?;

        let request = crate::types::FfiRequestData {
            payload,
            extracted_metadata: ffi_metadata,
            masked_metadata: None,
        };

        let environment = Some(ffi_options.environment());

        let proto_response = handler(request, domain_response, environment).map_err(|e| {
            UniffiError::HandlerError {
                msg: format!("{e:?}"),
            }
        })?;
        Ok(proto_response.encode_to_vec())
    }

    // ── Flow macro ────────────────────────────────────────────────────────────

    /// Generates a `#[uniffi::export]` `{flow}_req_transformer` and
    /// `{flow}_res_transformer` function pair backed by the generic runners.
    ///
    /// # Arguments
    /// - `$flow`        — snake_case flow name (used as identifier prefix)
    /// - `$req_type`    — protobuf request type to decode from bytes
    /// - `$req_handler` — handler fn: `(FfiRequestData<Req>, Option<Environment>) -> Result<Option<Request>, _>`
    /// - `$res_handler` — handler fn: `(FfiRequestData<Req>, Response, Option<Environment>) -> Result<Res, _>`
    macro_rules! define_ffi_flow {
        ($flow:ident, $req_type:ty, $req_handler:path, $res_handler:path) => {
            paste::paste! {
                #[uniffi::export]
                pub fn [<$flow _req_transformer>](
                    request_bytes: Vec<u8>,
                    options_bytes: Vec<u8>,
                ) -> Result<Vec<u8>, UniffiError> {
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
                ) -> Result<Vec<u8>, UniffiError> {
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
    pub fn handle_event_transformer(
        request_bytes: Vec<u8>,
        options_bytes: Vec<u8>,
    ) -> Result<Vec<u8>, UniffiError> {
        use prost::Message as _;
        let payload =
            grpc_api_types::payments::EventServiceHandleRequest::decode(Bytes::from(request_bytes))
                .map_err(|e| UniffiError::DecodeError { msg: e.to_string() })?;

        let ffi_options = parse_ffi_options(options_bytes)?;
        let ffi_metadata = parse_metadata(&ffi_options)?;

        let request = crate::types::FfiRequestData {
            payload,
            extracted_metadata: ffi_metadata,
            masked_metadata: None,
        };

        let environment = Some(ffi_options.environment());

        let response = crate::handlers::payments::handle_event_handler(request, environment)
            .map_err(|e| UniffiError::HandlerError {
                msg: format!("{e:?}"),
            })?;

        Ok(response.encode_to_vec())
    }
}

#[cfg(feature = "uniffi")]
pub use uniffi_bindings_inner::*;
