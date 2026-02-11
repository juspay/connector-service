use crate::flows::payments::{self, MetadataPayload, RequestData};
use crate::utils::create_hardcoded_masked_metadata;
use grpc_api_types::payments::PaymentServiceAuthorizeRequest;

#[cfg(feature = "napi")]
mod napi_bindings {
    use super::*;
    use napi_derive::napi;

    #[napi]
    /// Authorize a payment with the provided payload and extracted metadata
    /// @param payload - JSON string containing PaymentServiceAuthorizeRequest
    /// @param extracted_metadata - JSON string containing MetadataPayload with connector and auth info
    /// @returns JSON string containing the response
    /// @throws Error if payload or extracted_metadata is empty or invalid
    pub fn authorize(payload: String, extracted_metadata: String) -> napi::Result<String> {
        // Validate payload is not empty
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

        let request_data = RequestData {
            payload: payload_data,
            extracted_metadata: extracted_metadata_data,
            masked_metadata,
        };

        let result: Option<common_utils::Request> = payments::authorize_flow(request_data)
            .map_err(|e| napi::Error::from_reason(format!("{:?}", e)))?;

        // Convert the result to JSON (return null if None)
        serde_json::to_string(&result).map_err(|e| napi::Error::from_reason(e.to_string()))
    }
}

#[cfg(feature = "napi")]
pub use napi_bindings::*;
