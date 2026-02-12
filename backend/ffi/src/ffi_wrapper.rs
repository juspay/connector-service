use crate::flows::payments::{self, MetadataPayload, RequestData};
use crate::utils::create_hardcoded_masked_metadata;

use common_utils::Request;
use external_services;
use grpc_api_types::payments::PaymentServiceAuthorizeRequest;

#[cfg(feature = "napi")]
mod napi_bindings {
    use super::*;
    use napi_derive::napi;

    /// Authorize a payment
    ///
    /// @param payload - JSON string of PaymentServiceAuthorizeRequest
    /// @param extracted_metadata - JSON string of MetadataPayload
    /// @returns JSON string of JsRequest | null
    #[napi]
    pub fn authorize(payload: String, extracted_metadata: String) -> napi::Result<String> {
        if payload.trim().is_empty() {
            return Err(napi::Error::from_reason("Payload cannot be empty"));
        }

        if extracted_metadata.trim().is_empty() {
            return Err(napi::Error::from_reason(
                "Extracted metadata cannot be empty",
            ));
        }

        // Parse payload
        let payload_data: PaymentServiceAuthorizeRequest = serde_json::from_str(&payload)
            .map_err(|e| napi::Error::from_reason(format!("Invalid payload JSON: {e}")))?;

        // Parse metadata
        let extracted_metadata_data: MetadataPayload = serde_json::from_str(&extracted_metadata)
            .map_err(|e| napi::Error::from_reason(format!("Invalid metadata JSON: {e}")))?;

        let masked_metadata = create_hardcoded_masked_metadata();

        let request_data = RequestData {
            payload: payload_data,
            extracted_metadata: extracted_metadata_data,
            masked_metadata,
        };

        // Domain call
        let result: Option<Request> = payments::authorize_flow(request_data)
            .map_err(|e| napi::Error::from_reason(format!("{:?}", e)))?;

        let request =
            result.ok_or_else(|| napi::Error::from_reason("No connector request generated"))?;

        let t = external_services::service::extract_raw_connector_request(&request);

        // Return JSON
        serde_json::to_string(&t).map_err(|e| napi::Error::from_reason(e.to_string()))
    }
}

#[cfg(feature = "napi")]
pub use napi_bindings::*;
