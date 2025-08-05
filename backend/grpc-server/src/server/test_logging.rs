use crate::metrics::TRACING_EVENTS_GENERATED;
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
    #[serde(default)]
    pub test_scenario: Option<String>,
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
        let log_generation_timestamp_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let payment_id = format!("pay_{}_{}", log_generation_timestamp_ms, i);
        let merchant_id = format!("merchant_{}", i % 100);
        let latency_ms = 10 + (i % 150);

        match payload.log_level.as_str() {
            "trace" => {
                if payload.include_fields {
                    tracing::trace!(
                        payment_id,
                        merchant_id,
                        latency_ms,
                        flow = "PaymentsConfirm",
                        request_id = ?request_id,
                        log_generation_timestamp_ms,
                        "API request completed"
                    );
                } else {
                    tracing::trace!(request_id = ?request_id, "Test trace log {}", i);
                }
                TRACING_EVENTS_GENERATED.inc();
            }
            "debug" => {
                if payload.include_fields {
                    tracing::debug!(
                        payment_id,
                        merchant_id,
                        latency_ms,
                        flow = "PaymentsConfirm",
                        request_id = ?request_id,
                        log_generation_timestamp_ms,
                        "API request completed"
                    );
                } else {
                    tracing::debug!(request_id = ?request_id, "Test debug log {}", i);
                }
                TRACING_EVENTS_GENERATED.inc();
            }
            "info" => {
                if payload.include_fields {
                    tracing::info!(
                        payment_id,
                        merchant_id,
                        latency_ms,
                        flow = "PaymentsConfirm",
                        request_id = ?request_id,
                        log_generation_timestamp_ms,
                        "API request completed"
                    );
                } else {
                    tracing::info!(request_id = ?request_id, "Test info log {}", i);
                }
                TRACING_EVENTS_GENERATED.inc();
            }
            "warn" => {
                if payload.include_fields {
                    tracing::warn!(
                        payment_id,
                        merchant_id,
                        latency_ms,
                        flow = "PaymentsConfirm",
                        request_id = ?request_id,
                        log_generation_timestamp_ms,
                        "API request completed"
                    );
                } else {
                    tracing::warn!(request_id = ?request_id, "Test warn log {}", i);
                }
                TRACING_EVENTS_GENERATED.inc();
            }
            "error" => {
                if payload.include_fields {
                    tracing::error!(
                        payment_id,
                        merchant_id,
                        latency_ms,
                        flow = "PaymentsConfirm",
                        request_id = ?request_id,
                        log_generation_timestamp_ms,
                        "API request completed"
                    );
                } else {
                    tracing::error!(request_id = ?request_id, "Test error log {}", i);
                }
                TRACING_EVENTS_GENERATED.inc();
            }
            "many_fields" => {
                // Test scenario with 50+ fields
                tracing::info!(
                    payment_id,
                    merchant_id,
                    latency_ms,
                    request_id = ?request_id,
                    field1 = "value1",
                    field2 = "value2",
                    field3 = "value3",
                    field4 = "value4",
                    field5 = "value5",
                    field6 = "value6",
                    field7 = "value7",
                    field8 = "value8",
                    field9 = "value9",
                    field10 = "value10",
                    field11 = "value11",
                    field12 = "value12",
                    field13 = "value13",
                    field14 = "value14",
                    field15 = "value15",
                    field16 = "value16",
                    field17 = "value17",
                    field18 = "value18",
                    field19 = "value19",
                    field20 = "value20",
                    field21 = "value21",
                    field22 = "value22",
                    field23 = "value23",
                    field24 = "value24",
                    field25 = "value25",
                    field26 = "value26",
                    field27 = "value27",
                    field28 = "value28",
                    field29 = "value29",
                    field30 = "value30",
                    field31 = "value31",
                    field32 = "value32",
                    field33 = "value33",
                    field34 = "value34",
                    field35 = "value35",
                    field36 = "value36",
                    field37 = "value37",
                    field38 = "value38",
                    field39 = "value39",
                    field40 = "value40",
                    field41 = "value41",
                    field42 = "value42",
                    field43 = "value43",
                    field44 = "value44",
                    field45 = "value45",
                    field46 = "value46",
                    field47 = "value47",
                    field48 = "value48",
                    field49 = "value49",
                    field50 = "value50",
                    extra_data = format!("Additional data for log {}", i),
                    scenario = "many_fields",
                    "Test log with 50+ fields"
                );
                TRACING_EVENTS_GENERATED.inc();
            }
            "large_message" => {
                // Test scenario with large message (10KB)
                let large_data = "x".repeat(10_000);
                tracing::info!(
                    payment_id,
                    merchant_id,
                    latency_ms,
                    request_id = ?request_id,
                    large_field = %large_data,
                    data_size_bytes = 10000,
                    scenario = "large_message",
                    "Test log with large message content"
                );
                TRACING_EVENTS_GENERATED.inc();
            }
            "special_chars" => {
                // Test scenario with special characters
                let special_content = r#"Unicode: 你好世界 🚀🎉 العربية עברית
Newlines:
Line1
Line2	Tab	Separated
Quotes: "double" 'single' `backticks`
JSON: {"nested": {"json": true}}
Special: <>&'"`;
SQL: '; DROP TABLE logs;--"#;
                
                tracing::info!(
                    payment_id,
                    merchant_id,
                    latency_ms,
                    request_id = ?request_id,
                    special_content = %special_content,
                    unicode_test = "测试 テスト 테ス",
                    emoji_test = "🚀💻🔥🎯🏆",
                    json_in_string = r#"{"key": "value"}"#,
                    scenario = "special_chars",
                    "Test log with special characters"
                );
                TRACING_EVENTS_GENERATED.inc();
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
