use axum::{
    extract::{FromRequest, Request},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use common_utils::consts;
use serde::de::DeserializeOwned;
use std::sync::Arc;
use tonic::metadata::{Ascii, MetadataMap, MetadataValue};

use super::error::HttpError;
use ucs_env::configs::Config;

/// Converts HTTP headers to gRPC metadata
/// Extracts relevant headers and adds them to the gRPC metadata map
pub fn http_headers_to_grpc_metadata(
    http_headers: &HeaderMap,
) -> Result<MetadataMap, Box<tonic::Status>> {
    let mut metadata = MetadataMap::new();

    // Required headers - these must be present
    let required_headers = [
        consts::X_CONNECTOR_NAME,
        consts::X_MERCHANT_ID,
        consts::X_REQUEST_ID,
        consts::X_TENANT_ID,
        consts::X_AUTH,
    ];

    // Optional headers - these may or may not be present
    let optional_headers = [
        consts::X_REFERENCE_ID,
        consts::X_API_KEY,
        consts::X_API_SECRET,
        consts::X_KEY1,
        consts::X_KEY2,
        consts::X_AUTH_KEY_MAP,
        consts::X_SHADOW_MODE,
    ];

    // Process required headers - fail if missing
    for header_name in required_headers {
        let header_value = http_headers.get(header_name).ok_or_else(|| {
            tonic::Status::invalid_argument(format!("Missing required header: {header_name}"))
        })?;

        let metadata_value = convert_header_to_metadata(header_name, header_value)?;
        metadata.insert(header_name, metadata_value);
    }

    // Process optional headers - skip if missing
    for header_name in optional_headers {
        if let Some(header_value) = http_headers.get(header_name) {
            let metadata_value = convert_header_to_metadata(header_name, header_value)?;
            metadata.insert(header_name, metadata_value);
        }
    }

    Ok(metadata)
}

fn convert_header_to_metadata(
    header_name: &str,
    header_value: &HeaderValue,
) -> Result<MetadataValue<Ascii>, Box<tonic::Status>> {
    header_value
        .to_str()
        .map_err(|e| {
            Box::new(tonic::Status::invalid_argument(format!(
                "Invalid header value for {header_name}: {e}"
            )))
        })
        .and_then(|s| {
            MetadataValue::try_from(s).map_err(|e| {
                Box::new(tonic::Status::invalid_argument(format!(
                    "Cannot convert header {header_name} to metadata: {e}"
                )))
            })
        })
}

/// Transfers config from Axum Extension to gRPC request
/// Copies the Arc<Config> from Axum Extension to gRPC request extensions
pub fn transfer_config_to_grpc_request<T>(
    config: &Arc<Config>,
    grpc_request: &mut tonic::Request<T>,
) {
    grpc_request.extensions_mut().insert(config.clone());
}

/// Custom JSON extractor that converts 422 errors to 400 with original error messages
pub struct ValidatedJson<T>(pub T);

impl<T, S> FromRequest<S> for ValidatedJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(value)) => Ok(Self(value)),
            Err(rejection) => {
                Err(HttpError {
                    status: StatusCode::BAD_REQUEST,
                    message: rejection.to_string(), // Use default message
                }
                .into_response())
            }
        }
    }
}
