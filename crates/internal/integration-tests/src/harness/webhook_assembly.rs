//! Webhook scenario assembly for the `handle_event` suite.
//!
//! The generic `handle_event_suite/scenario.json` contains only assertions and
//! display metadata — it intentionally omits `grpc_req` because the request
//! body, headers, and signature differ per connector.
//!
//! This module reads per-connector payload files from
//! `handle_event_suite/payloads/{connector}.json`, computes HMAC signatures
//! at runtime, and assembles a full `EventServiceHandleRequest` JSON value
//! that the execution engine can pass directly to grpcurl/tonic.

use std::fs;

use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::Value;

use crate::harness::scenario_loader::scenario_root;
use crate::harness::scenario_types::ScenarioError;
use crate::webhook_signatures;

/// Suite name that triggers webhook assembly.
pub const WEBHOOK_SUITE: &str = "handle_event";

/// Loads the per-connector webhook payload file.
///
/// Path: `<scenario_root>/handle_event_suite/payloads/{connector}.json`
fn load_connector_payload(connector: &str) -> Result<Value, ScenarioError> {
    let path = scenario_root()
        .join("handle_event_suite")
        .join("payloads")
        .join(format!("{connector}.json"));

    let content = fs::read_to_string(&path).map_err(|source| ScenarioError::ScenarioFileRead {
        path: path.clone(),
        source,
    })?;

    serde_json::from_str(&content)
        .map_err(|source| ScenarioError::ScenarioFileParse { path, source })
}

/// Extracts the webhook secret from the connector credentials file.
///
/// Reads the creds file and looks for `webhook_secret` (or the key named in
/// `webhook_config.webhook_secret_key`) under the connector's entry.
fn load_webhook_secret(connector: &str, secret_key: &str) -> Option<String> {
    let creds_path = crate::harness::credentials::creds_file_path();
    let content = fs::read_to_string(&creds_path).ok()?;
    let json: Value = serde_json::from_str(&content).ok()?;

    let connector_block = json.get(connector)?;

    // Handle array-valued connector entries (pick first).
    let block = match connector_block {
        Value::Array(arr) => arr.first()?,
        other => other,
    };

    block
        .get(secret_key)
        .and_then(|v| {
            // Handle {"value": "..."} wrapper format.
            if let Some(obj) = v.as_object() {
                if obj.len() == 1 {
                    return obj.get("value").and_then(|inner| inner.as_str());
                }
            }
            v.as_str()
        })
        .map(ToString::to_string)
}

/// Assembles a complete `EventServiceHandleRequest` JSON for a webhook scenario.
///
/// This is the core function that bridges the generic scenario definition
/// (assertions only) with connector-specific webhook bodies and signatures.
///
/// # Arguments
/// * `connector` - Connector name (e.g. "authorizedotnet", "adyen")
/// * `scenario` - Scenario name (e.g. "payment_succeeded", "invalid_signature")
///
/// # Returns
/// A `serde_json::Value` representing the full `EventServiceHandleRequest`:
/// ```json
/// {
///   "merchant_event_id": "...",
///   "request_details": {
///     "method": "HTTP_METHOD_POST",
///     "headers": { "X-ANET-Signature": "sha512=..." },
///     "body": "<base64-encoded-body>"
///   },
///   "webhook_secrets": {
///     "secret": "..."
///   }
/// }
/// ```
pub fn assemble_webhook_grpc_req(connector: &str, scenario: &str) -> Result<Value, ScenarioError> {
    let payload_file = load_connector_payload(connector)?;

    // Extract the scenario-specific data from the connector payload file.
    let scenarios =
        payload_file
            .get("scenarios")
            .ok_or_else(|| ScenarioError::ScenarioNotFound {
                suite: WEBHOOK_SUITE.to_string(),
                scenario: format!("{connector}: missing 'scenarios' object"),
            })?;

    let scenario_data = scenarios
        .get(scenario)
        .ok_or_else(|| ScenarioError::ScenarioNotFound {
            suite: WEBHOOK_SUITE.to_string(),
            scenario: format!("{connector}/{scenario}"),
        })?;

    // Extract the webhook body JSON.
    let body_value = scenario_data
        .get("body")
        .ok_or_else(|| ScenarioError::ScenarioNotFound {
            suite: WEBHOOK_SUITE.to_string(),
            scenario: format!("{connector}/{scenario}: missing 'body'"),
        })?;

    let body_json_string = serde_json::to_string(body_value)
        .map_err(|source| ScenarioError::JsonSerialize { source })?;

    // Base64-encode the body (proto `bytes` field requires base64 in JSON).
    let body_base64 = STANDARD.encode(body_json_string.as_bytes());

    // Extract webhook config from the payload file.
    let webhook_config = payload_file.get("webhook_config");

    // Determine the webhook secret.
    let secret_key = webhook_config
        .and_then(|c| c.get("webhook_secret_key"))
        .and_then(|v| v.as_str())
        .unwrap_or("webhook_secret");

    let webhook_secret = load_webhook_secret(connector, secret_key);

    // Build request headers with signature.
    let mut headers = serde_json::Map::new();

    // Check if there's a signature override for this scenario (e.g., invalid_signature tests).
    let signature_override = scenario_data
        .get("signature_override")
        .and_then(|v| v.as_str());

    let signature_header = webhook_config
        .and_then(|c| c.get("signature_header"))
        .and_then(|v| v.as_str());

    // Determine if signature is in body (Adyen) or header (most others).
    let _signature_in_body = webhook_config
        .and_then(|c| c.get("signature_location"))
        .and_then(|v| v.as_str())
        == Some("body");

    if let Some(header_name) = signature_header {
        if let Some(sig_override) = signature_override {
            // Use the override signature directly.
            headers.insert(
                header_name.to_string(),
                Value::String(sig_override.to_string()),
            );
        } else if let Some(ref secret) = webhook_secret {
            // Compute signature dynamically.
            match webhook_signatures::generate_signature(
                connector,
                body_json_string.as_bytes(),
                secret,
                None,
            ) {
                Ok(sig) => {
                    headers.insert(header_name.to_string(), Value::String(sig));
                }
                Err(err) => {
                    eprintln!(
                        "warning: failed to compute webhook signature for {connector}/{scenario}: {err}"
                    );
                }
            }
        }
        // If no secret and no override, headers remain empty (connector may not verify).
    }

    // For Adyen: signature is embedded in the body itself; we trust the pre-computed
    // value in the payload file. No header manipulation needed.
    // The body JSON already contains `additionalData.hmacSignature`.

    // Extract merchant_event_id.
    let merchant_event_id = scenario_data
        .get("merchant_event_id")
        .and_then(|v| v.as_str())
        .unwrap_or_default();

    // Build the full EventServiceHandleRequest.
    let mut request = serde_json::json!({
        "request_details": {
            "method": "HTTP_METHOD_POST",
            "headers": headers,
            "body": body_base64
        }
    });

    // Only include merchant_event_id if non-empty.
    if !merchant_event_id.is_empty() {
        request.as_object_mut().unwrap().insert(
            "merchant_event_id".to_string(),
            Value::String(merchant_event_id.to_string()),
        );
    }

    // Add webhook_secrets if we have a secret.
    if let Some(secret) = &webhook_secret {
        request.as_object_mut().unwrap().insert(
            "webhook_secrets".to_string(),
            serde_json::json!({ "secret": secret }),
        );
    }

    Ok(request)
}

/// Returns `true` if the suite uses webhook assembly (payload files) instead
/// of inline `grpc_req` templates.
pub fn is_webhook_suite(suite: &str) -> bool {
    suite == WEBHOOK_SUITE
}

/// Checks if a connector has a payload file for the handle_event suite.
pub fn has_connector_payload(connector: &str) -> bool {
    let path = scenario_root()
        .join("handle_event_suite")
        .join("payloads")
        .join(format!("{connector}.json"));
    path.exists()
}

/// Lists scenario names available in a connector's payload file.
///
/// Returns an empty Vec if the payload file doesn't exist or can't be parsed.
pub fn available_connector_scenarios(connector: &str) -> Vec<String> {
    let Ok(payload_file) = load_connector_payload(connector) else {
        return Vec::new();
    };

    payload_file
        .get("scenarios")
        .and_then(|s| s.as_object())
        .map(|obj| obj.keys().cloned().collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_webhook_suite_matches_handle_event() {
        assert!(is_webhook_suite("handle_event"));
        assert!(!is_webhook_suite("authorize"));
        assert!(!is_webhook_suite("capture"));
    }

    #[test]
    fn authorizedotnet_payment_succeeded_assembles_valid_request() {
        if !has_connector_payload("authorizedotnet") {
            return; // Skip if payload file missing.
        }

        let grpc_req = assemble_webhook_grpc_req("authorizedotnet", "payment_succeeded")
            .expect("should assemble authorizedotnet payment_succeeded");

        // Verify structure.
        assert!(grpc_req.get("request_details").is_some());
        let details = grpc_req.get("request_details").unwrap();
        assert_eq!(details.get("method").unwrap(), "HTTP_METHOD_POST");
        assert!(details.get("body").is_some());

        // Body should be base64 encoded.
        let body_b64 = details.get("body").unwrap().as_str().unwrap();
        let decoded = STANDARD
            .decode(body_b64)
            .expect("body should be valid base64");
        let body_str = String::from_utf8(decoded).expect("body should be valid UTF-8");
        let body_json: Value = serde_json::from_str(&body_str).expect("body should be valid JSON");
        assert_eq!(
            body_json.get("eventType").unwrap(),
            "net.authorize.payment.authcapture.created"
        );

        // merchant_event_id should be present.
        assert_eq!(
            grpc_req.get("merchant_event_id").unwrap(),
            "anet_webhook_authcapture_001"
        );
    }

    #[test]
    fn adyen_payment_succeeded_has_body_embedded_signature() {
        if !has_connector_payload("adyen") {
            return;
        }

        let grpc_req = assemble_webhook_grpc_req("adyen", "payment_succeeded")
            .expect("should assemble adyen payment_succeeded");

        let details = grpc_req.get("request_details").unwrap();
        let body_b64 = details.get("body").unwrap().as_str().unwrap();
        let decoded = STANDARD
            .decode(body_b64)
            .expect("body should be valid base64");
        let body_str = String::from_utf8(decoded).expect("body should be valid UTF-8");
        let body_json: Value = serde_json::from_str(&body_str).expect("body should be valid JSON");

        // Adyen's signature should be in the body.
        let hmac_sig = body_json
            .pointer("/notificationItems/0/NotificationRequestItem/additionalData/hmacSignature");
        assert!(
            hmac_sig.is_some(),
            "Adyen body should contain hmacSignature"
        );
    }

    #[test]
    fn invalid_signature_scenario_uses_override() {
        if !has_connector_payload("authorizedotnet") {
            return;
        }

        let grpc_req = assemble_webhook_grpc_req("authorizedotnet", "invalid_signature")
            .expect("should assemble authorizedotnet invalid_signature");

        let headers = grpc_req
            .pointer("/request_details/headers")
            .unwrap()
            .as_object()
            .unwrap();

        let sig = headers.get("X-ANET-Signature").unwrap().as_str().unwrap();
        assert!(
            sig.starts_with("sha512=000"),
            "invalid_signature should use the override"
        );
    }

    #[test]
    fn available_scenarios_returns_expected_names() {
        if !has_connector_payload("authorizedotnet") {
            return;
        }
        let names = available_connector_scenarios("authorizedotnet");
        assert!(names.contains(&"payment_succeeded".to_string()));
        assert!(names.contains(&"refund_succeeded".to_string()));
        assert!(names.contains(&"invalid_signature".to_string()));
    }
}
