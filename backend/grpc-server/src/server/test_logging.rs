use axum::{http, Json};
use serde::{Deserialize, Serialize};
use std::time::Instant;

#[derive(Debug, Serialize, Deserialize)]
pub struct TestLoggingRequest {
    pub log_count: usize,
    pub log_level: String,
    pub include_fields: bool,
    #[serde(default)]
    pub request_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TestLoggingResponse {
    pub logs_generated: usize,
    pub time_taken_ms: u128,
    pub request_id: Option<String>,
}

pub async fn test_logging_handler(
    Json(payload): Json<TestLoggingRequest>,
) -> Result<Json<TestLoggingResponse>, (http::StatusCode, String)> {
    let start = Instant::now();
    let request_id = payload.request_id.clone();

    // Generate logs based on the request
    for i in 0..payload.log_count {
        match payload.log_level.as_str() {
            "trace" => {
                if payload.include_fields {
                    tracing::trace!(
                        iteration = i,
                        test_field = "test_value",
                        numeric_field = i * 2,
                        request_id = ?request_id,
                        "Test trace log with fields"
                    );
                } else {
                    tracing::trace!(request_id = ?request_id, "Test trace log {}", i);
                }
            }
            "debug" => {
                if payload.include_fields {
                    tracing::debug!(
                        iteration = i,
                        test_field = "test_value",
                        numeric_field = i * 2,
                        request_id = ?request_id,
                        "Test debug log with fields"
                    );
                } else {
                    tracing::debug!(request_id = ?request_id, "Test debug log {}", i);
                }
            }
            "info" => {
                if payload.include_fields {
                    tracing::info!(
                        iteration = i,
                        test_field = "test_value",
                        numeric_field = i * 2,
                        request_id = ?request_id,
                        "Test info log with fields"
                    );
                } else {
                    tracing::info!(request_id = ?request_id, "Test info log {}", i);
                }
            }
            "warn" => {
                if payload.include_fields {
                    tracing::warn!(
                        iteration = i,
                        test_field = "test_value",
                        numeric_field = i * 2,
                        request_id = ?request_id,
                        "Test warn log with fields"
                    );
                } else {
                    tracing::warn!(request_id = ?request_id, "Test warn log {}", i);
                }
            }
            "error" => {
                if payload.include_fields {
                    tracing::error!(
                        iteration = i,
                        test_field = "test_value",
                        numeric_field = i * 2,
                        request_id = ?request_id,
                        "Test error log with fields"
                    );
                } else {
                    tracing::error!(request_id = ?request_id, "Test error log {}", i);
                }
            }
            _ => {
                return Err((
                    http::StatusCode::BAD_REQUEST,
                    format!("Invalid log level: {}", payload.log_level),
                ));
            }
        }
    }

    let elapsed = start.elapsed();

    Ok(Json(TestLoggingResponse {
        logs_generated: payload.log_count,
        time_taken_ms: elapsed.as_millis(),
        request_id,
    }))
}
