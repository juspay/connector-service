//! Python SDK executor — runs Python SDK flows via subprocess.
//!
//! This module spawns `sdk/python/tests/run_flow.py` as a child process,
//! passing the scenario payload via stdin and reading the result from stdout.
//! It bridges the Rust integration-test harness with the Python SDK so that
//! every scenario that can be tested via the Rust FFI path can also be
//! validated end-to-end through the Python SDK.

use std::io::Write;
use std::process::{Command, Stdio};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::harness::{credentials::load_connector_config, scenario_types::ScenarioError};

/// Suite name → (Python client class, Python flow method) mapping.
///
/// This maps integration-test suite names to the Python SDK client/method
/// pair that implements the corresponding flow.
fn suite_to_python_client_flow(suite: &str) -> Option<(&'static str, &'static str)> {
    Some(match suite {
        // MerchantAuthenticationService
        "server_authentication_token" => (
            "MerchantAuthenticationClient",
            "create_server_authentication_token",
        ),
        "server_session_authentication_token" => (
            "MerchantAuthenticationClient",
            "create_server_session_authentication_token",
        ),
        "client_authentication_token" => (
            "MerchantAuthenticationClient",
            "create_client_authentication_token",
        ),
        // CustomerService
        "create_customer" => ("CustomerClient", "create"),
        // PaymentService
        "authorize" => ("PaymentClient", "authorize"),
        "capture" => ("PaymentClient", "capture"),
        "void" => ("PaymentClient", "void"),
        "refund" => ("PaymentClient", "refund"),
        "get" => ("PaymentClient", "get"),
        "setup_recurring" => ("PaymentClient", "setup_recurring"),
        "create_order" => ("PaymentClient", "create_order"),
        "reverse" => ("PaymentClient", "reverse"),
        "proxy_authorize" => ("PaymentClient", "proxy_authorize"),
        "proxy_setup_recurring" => ("PaymentClient", "proxy_setup_recurring"),
        "token_authorize" => ("PaymentClient", "token_authorize"),
        "token_setup_recurring" => ("PaymentClient", "token_setup_recurring"),
        // RecurringPaymentService
        "recurring_charge" => ("RecurringPaymentClient", "charge"),
        // PaymentMethodAuthenticationService
        "authenticate" => ("PaymentMethodAuthenticationClient", "authenticate"),
        "pre_authenticate" => ("PaymentMethodAuthenticationClient", "pre_authenticate"),
        "post_authenticate" => ("PaymentMethodAuthenticationClient", "post_authenticate"),
        // PaymentMethodService
        "tokenize_payment_method" => ("PaymentMethodClient", "tokenize"),
        // DisputeService
        "accept" => ("DisputeClient", "accept"),
        "defend" => ("DisputeClient", "defend"),
        "submit_evidence" => ("DisputeClient", "submit_evidence"),
        // PayoutService
        "payout_create" => ("PayoutClient", "payout_create"),
        "payout_create_link" => ("PayoutClient", "payout_create_link"),
        "payout_create_recipient" => ("PayoutClient", "payout_create_recipient"),
        "payout_enroll_disburse_account" => ("PayoutClient", "payout_enroll_disburse_account"),
        "payout_get" => ("PayoutClient", "payout_get"),
        "payout_stage" => ("PayoutClient", "payout_stage"),
        "payout_transfer" => ("PayoutClient", "payout_transfer"),
        "payout_void" => ("PayoutClient", "payout_void"),
        _ => return None,
    })
}

/// Returns whether a suite can be executed through the Python SDK executor.
pub fn supports_python_sdk_suite(suite: &str) -> bool {
    suite_to_python_client_flow(suite).is_some()
}

/// Input payload sent to the Python `run_flow.py` script via stdin.
#[derive(Debug, Serialize)]
struct PythonFlowInput {
    client: String,
    flow: String,
    request: Value,
    connector: String,
    credentials: Value,
    environment: String,
}

/// Output payload read from the Python `run_flow.py` script via stdout.
#[derive(Debug, Deserialize)]
struct PythonFlowOutput {
    status: String,
    #[serde(default)]
    response: Option<Value>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    traceback: Option<String>,
}

/// Path to the Python flow runner script, relative to the workspace root.
fn python_runner_path() -> std::path::PathBuf {
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // integration-tests is at crates/internal/integration-tests
    // runner is at sdk/python/tests/run_flow.py
    manifest_dir
        .join("..")
        .join("..")
        .join("..")
        .join("sdk")
        .join("python")
        .join("tests")
        .join("run_flow.py")
}

/// Executes a scenario through the Python SDK by spawning `run_flow.py`.
///
/// The function:
/// 1. Maps the suite name to a Python client class and flow method
/// 2. Loads connector credentials
/// 3. Sends JSON payload to the Python subprocess via stdin
/// 4. Reads and parses the JSON result from stdout
/// 5. Returns the response JSON or an error
pub fn execute_python_sdk_request(
    suite: &str,
    scenario: &str,
    grpc_req: &Value,
    connector: &str,
) -> Result<String, ScenarioError> {
    let (client_name, flow_name) =
        suite_to_python_client_flow(suite).ok_or_else(|| ScenarioError::UnsupportedSuite {
            suite: suite.to_string(),
        })?;

    // Load connector credentials
    let config =
        load_connector_config(connector).map_err(|error| ScenarioError::CredentialLoad {
            connector: connector.to_string(),
            message: error.to_string(),
        })?;

    let credentials: Value = serde_json::from_str(config.header_value()).unwrap_or(Value::Null);
    let cred_obj = credentials
        .get("config")
        .and_then(|c| {
            // Find the connector-specific config by pascal-cased name
            let pascal = {
                let mut chars = connector.chars();
                match chars.next() {
                    None => String::new(),
                    Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                }
            };
            c.get(&pascal)
        })
        .cloned()
        .unwrap_or(Value::Null);

    let environment = std::env::var("UCS_SDK_ENVIRONMENT")
        .unwrap_or_else(|_| "sandbox".to_string())
        .to_ascii_lowercase();

    let input = PythonFlowInput {
        client: client_name.to_string(),
        flow: flow_name.to_string(),
        request: grpc_req.clone(),
        connector: connector.to_string(),
        credentials: cred_obj,
        environment,
    };

    let input_json =
        serde_json::to_string(&input).map_err(|source| ScenarioError::SdkExecution {
            message: format!(
                "python sdk: failed to serialize input for '{}/{}': {}",
                suite, scenario, source
            ),
        })?;

    let runner_path = python_runner_path();
    if !runner_path.exists() {
        return Err(ScenarioError::SdkExecution {
            message: format!(
                "python sdk: runner script not found at {}",
                runner_path.display()
            ),
        });
    }

    // Determine Python interpreter
    let python = std::env::var("PYTHON_SDK_INTERPRETER").unwrap_or_else(|_| "python3".to_string());

    let mut child = Command::new(&python)
        .arg(&runner_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| ScenarioError::SdkExecution {
            message: format!(
                "python sdk: failed to spawn '{}' for '{}/{}': {}",
                python, suite, scenario, error
            ),
        })?;

    // Write input to stdin
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(input_json.as_bytes())
            .map_err(|error| ScenarioError::SdkExecution {
                message: format!(
                    "python sdk: failed to write stdin for '{}/{}': {}",
                    suite, scenario, error
                ),
            })?;
    }

    let output = child
        .wait_with_output()
        .map_err(|error| ScenarioError::SdkExecution {
            message: format!(
                "python sdk: process error for '{}/{}': {}",
                suite, scenario, error
            ),
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ScenarioError::SdkExecution {
            message: format!(
                "python sdk: process exited with {} for '{}/{}': {}",
                output.status, suite, scenario, stderr
            ),
        });
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let result: PythonFlowOutput =
        serde_json::from_str(&stdout).map_err(|error| ScenarioError::SdkExecution {
            message: format!(
                "python sdk: invalid JSON output for '{}/{}': {} (raw: {})",
                suite,
                scenario,
                error,
                &stdout[..stdout.len().min(500)]
            ),
        })?;

    match result.status.as_str() {
        "ok" => {
            let response = result.response.unwrap_or(Value::Null);
            serde_json::to_string_pretty(&response)
                .map_err(|source| ScenarioError::JsonSerialize { source })
        }
        "connector_error" => {
            // Connector rejected the request — this is a valid SDK round-trip
            let error_detail = result.error.unwrap_or_else(|| "unknown".to_string());
            Err(ScenarioError::SdkExecution {
                message: format!(
                    "python sdk: connector error for '{}/{}': {}",
                    suite, scenario, error_detail
                ),
            })
        }
        "sdk_error" => {
            let error_detail = result.error.unwrap_or_else(|| "unknown".to_string());
            let traceback = result
                .traceback
                .map(|tb| format!("\n--- traceback ---\n{}", tb))
                .unwrap_or_default();
            Err(ScenarioError::SdkExecution {
                message: format!(
                    "python sdk: SDK error for '{}/{}': {}{}",
                    suite, scenario, error_detail, traceback
                ),
            })
        }
        other => Err(ScenarioError::SdkExecution {
            message: format!(
                "python sdk: unexpected status '{}' for '{}/{}'",
                other, suite, scenario
            ),
        }),
    }
}

/// Python SDK coverage report: which suites can be executed through Python.
pub struct PythonSdkCoverageReport {
    /// Suites that the Python SDK can execute.
    pub supported: Vec<&'static str>,
    /// Suites that exist in the harness but cannot be run through Python SDK.
    pub not_supported: Vec<&'static str>,
}

/// Returns Python SDK coverage report relative to the full proto suite list.
pub fn python_sdk_coverage_report() -> PythonSdkCoverageReport {
    let mut supported = Vec::new();
    let mut not_supported = Vec::new();
    for &suite in crate::harness::scenario_api::all_known_suites() {
        if supports_python_sdk_suite(suite) {
            supported.push(suite);
        } else {
            not_supported.push(suite);
        }
    }
    PythonSdkCoverageReport {
        supported,
        not_supported,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_suite_mapping_covers_all_sdk_flows() {
        // Verify that every suite supported by the Rust FFI executor is also
        // supported by the Python SDK executor.
        let rust_supported: Vec<&str> = crate::harness::scenario_api::all_known_suites()
            .iter()
            .copied()
            .filter(|s| crate::harness::sdk_executor::supports_sdk_suite(s))
            .collect();

        for suite in &rust_supported {
            assert!(
                supports_python_sdk_suite(suite),
                "Suite '{}' is supported by Rust FFI but not Python SDK executor",
                suite
            );
        }
    }

    #[test]
    fn python_runner_path_exists_in_repo() {
        let path = python_runner_path();
        assert!(
            path.exists(),
            "Python runner script not found: {}",
            path.display()
        );
    }

    #[test]
    fn suite_to_python_mapping_returns_none_for_unknown() {
        assert!(suite_to_python_client_flow("nonexistent_suite").is_none());
        assert!(suite_to_python_client_flow("refund_sync").is_none());
        assert!(suite_to_python_client_flow("complete_authorize").is_none());
    }

    #[test]
    fn suite_to_python_mapping_returns_correct_clients() {
        assert_eq!(
            suite_to_python_client_flow("authorize"),
            Some(("PaymentClient", "authorize"))
        );
        assert_eq!(
            suite_to_python_client_flow("create_customer"),
            Some(("CustomerClient", "create"))
        );
        assert_eq!(
            suite_to_python_client_flow("recurring_charge"),
            Some(("RecurringPaymentClient", "charge"))
        );
        assert_eq!(
            suite_to_python_client_flow("tokenize_payment_method"),
            Some(("PaymentMethodClient", "tokenize"))
        );
        assert_eq!(
            suite_to_python_client_flow("payout_create"),
            Some(("PayoutClient", "payout_create"))
        );
        assert_eq!(
            suite_to_python_client_flow("accept"),
            Some(("DisputeClient", "accept"))
        );
    }
}
