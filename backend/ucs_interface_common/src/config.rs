use base64::{engine::general_purpose, Engine as _};
use common_utils::errors::CustomResult;
use domain_types::errors::{ApiError, ApplicationErrorResponse};
use error_stack::Report;
use serde_json::Value;
use std::sync::Arc;
use ucs_env::configs::{self, ConfigPatch};

use common_utils::config_patch::Patch;

pub fn merge_config_with_override(
    config_override: String,
    config: configs::Config,
) -> CustomResult<Arc<configs::Config>, ApplicationErrorResponse> {
    match config_override.trim().is_empty() {
        true => Ok(Arc::new(config)),
        false => {
            let mut override_patch: ConfigPatch = serde_json::from_str(config_override.trim())
                .map_err(|e| {
                    Report::new(ApplicationErrorResponse::BadRequest(ApiError {
                        sub_code: "CANNOT_CONVERT_TO_JSON".into(),
                        error_identifier: 400,
                        error_message: format!("Cannot convert override config to JSON: {e}"),
                        error_object: None,
                    }))
                })?;

            if let Some(proxy_patch) = override_patch.proxy.as_mut() {
                if let Some(cert_input) = proxy_patch
                    .mitm_ca_cert
                    .as_ref()
                    .and_then(|value| value.as_ref())
                {
                    let cert_trimmed = cert_input.trim();

                    let cert = if cert_trimmed.is_empty() {
                        Err(Report::new(ApplicationErrorResponse::BadRequest(
                            ApiError {
                                sub_code: "INVALID_MITM_CA_CERT_BASE64".into(),
                                error_identifier: 400,
                                error_message: "proxy.mitm_ca_cert must be base64-encoded"
                                    .to_string(),
                                error_object: None,
                            },
                        )))
                    } else {
                        let sanitized: String = cert_trimmed.split_whitespace().collect();
                        let decoded = general_purpose::STANDARD
                            .decode(sanitized.as_bytes())
                            .map_err(|e| {
                                Report::new(ApplicationErrorResponse::BadRequest(ApiError {
                                    sub_code: "INVALID_MITM_CA_CERT_BASE64".into(),
                                    error_identifier: 400,
                                    error_message: format!(
                                        "Invalid base64 for proxy.mitm_ca_cert: {e}"
                                    ),
                                    error_object: None,
                                }))
                            })?;

                        String::from_utf8(decoded).map_err(|e| {
                            Report::new(ApplicationErrorResponse::BadRequest(ApiError {
                                sub_code: "INVALID_MITM_CA_CERT_UTF8".into(),
                                error_identifier: 400,
                                error_message: format!(
                                    "Decoded proxy.mitm_ca_cert is not valid UTF-8: {e}"
                                ),
                                error_object: None,
                            }))
                        })
                    }?;

                    proxy_patch.mitm_ca_cert = Some(Some(cert));
                }
            }

            let mut merged_config = config;
            merged_config.apply(override_patch);

            tracing::info!("Config override applied successfully");

            Ok(Arc::new(merged_config))
        }
    }
}

pub fn merge_configs(override_val: &Value, base_val: &Value) -> Value {
    match (base_val, override_val) {
        (Value::Object(base_map), Value::Object(override_map)) => {
            let mut merged = base_map.clone();
            for (key, override_value) in override_map {
                let base_value = base_map.get(key).unwrap_or(&Value::Null);
                merged.insert(key.clone(), merge_configs(override_value, base_value));
            }
            Value::Object(merged)
        }
        // override replaces base for primitive, null, or array
        (_, override_val) => override_val.clone(),
    }
}
