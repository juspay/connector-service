// use crate::flows::payments::{self, MetadataPayload, RequestData};
use crate::flows::payments::{authorize_req_flow, authorize_res_flow, capture_req_flow};
use crate::macros::napi_handler;
use crate::types::{MetadataPayload, RequestData};
use crate::utils::create_hardcoded_masked_metadata;
use external_services;
use grpc_api_types::payments::{
    PaymentServiceAuthorizeRequest, PaymentServiceAuthorizeResponse, PaymentServiceCaptureRequest,
};
#[cfg(feature = "napi")]
mod napi_bindings {
    use super::*;
    use std::collections::HashMap;

    napi_handler!(
        authorize_req,
        PaymentServiceAuthorizeRequest,
        JsRequest,
        authorize_req_flow
    );

    napi_handler!(
        capture_req,
        PaymentServiceCaptureRequest,
        JsRequest,
        capture_req_flow
    );

    /// Intermediate structure for deserializing Node.js API response
    #[derive(Debug, serde::Deserialize)]
    struct NodeApiResponse {
        status: u16,
        headers: HashMap<String, String>,
        body: String,
    }

    #[::napi_derive::napi]
    pub fn authorize_res(
        response: String,
        payload: String,
        extracted_metadata: String,
    ) -> napi::Result<String> {
        // Parse the JSON response from Node.js
        let api_response: NodeApiResponse = serde_json::from_str(&response).map_err(|e| {
            napi::Error::from_reason(format!("Failed to parse response JSON: {}", e))
        })?;

        // Convert headers to http::HeaderMap
        let mut header_map = http::HeaderMap::new();
        for (key, value) in api_response.headers {
            if let (Ok(header_name), Ok(header_value)) = (
                http::header::HeaderName::from_bytes(key.as_bytes()),
                http::header::HeaderValue::from_str(&value),
            ) {
                header_map.insert(header_name, header_value);
            }
        }

        // Convert body to bytes::Bytes
        let response_bytes = api_response.body.into_bytes().into();

        // Create Response struct
        let response = domain_types::router_response_types::Response {
            headers: if header_map.is_empty() {
                None
            } else {
                Some(header_map)
            },
            response: response_bytes,
            status_code: api_response.status,
        };
        if payload.trim().is_empty() {
            return Err(napi::Error::from_reason(
                "Payload cannot be empty".to_string(),
            ));
        }

        // Validate extracted_metadata is not empty
        if extracted_metadata.trim().is_empty() {
            return Err(napi::Error::from_reason(
                "Extracted metadata cannot be empty".to_string(),
            ));
        }

        // Parse JSON payload into PaymentServiceAuthorizeRequest
        let payload_data: PaymentServiceAuthorizeRequest = serde_json::from_str(&payload)
            .map_err(|e| napi::Error::from_reason(format!("Failed to parse payload: {}", e)))?;

        // Parse JSON extracted_metadata into MetadataPayload
        let extracted_metadata_data: MetadataPayload = serde_json::from_str(&extracted_metadata)
            .map_err(|e| {
                napi::Error::from_reason(format!("Failed to parse extracted metadata: {}", e))
            })?;

        // Use hardcoded values for masked_metadata (can also be made configurable)
        let masked_metadata = create_hardcoded_masked_metadata();

        let request = RequestData {
            payload: payload_data,
            extracted_metadata: extracted_metadata_data,
            masked_metadata,
        };
        authorize_res_flow(request, response)
            .map_err(|e| napi::Error::from_reason(format!("{:?}", e)))
            .and_then(|response| {
                serde_json::to_string(&response).map_err(|e| {
                    napi::Error::from_reason(format!("Failed to serialize response: {}", e))
                })
            })
    }
}

#[cfg(feature = "napi")]
pub use napi_bindings::*;
