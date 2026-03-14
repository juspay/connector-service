#![allow(clippy::print_stderr, clippy::too_many_arguments)]

//! Core orchestration layer for UCS scenario execution.
//!
//! Responsibilities include loading scenario templates, applying connector
//! overrides, resolving dependency context, building grpcurl/tonic payloads,
//! dispatching RPC calls, and returning structured per-scenario results.

use std::collections::BTreeMap;

use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;
use tonic::transport::Channel;

use crate::harness::{
    auto_gen::resolve_auto_generate,
    connector_override::{
        apply_connector_overrides, context_deferred_paths_for_connector,
        normalize_tonic_request_for_connector, should_skip_scenario_for_connector,
        transform_response_for_connector,
    },
    credentials::{load_connector_auth, ConnectorAuth},
    metadata::add_connector_metadata,
    scenario_assert::do_assertion as do_assertion_impl,
    scenario_loader::{
        configured_all_connectors, get_the_assertion as get_the_assertion_impl,
        get_the_grpc_req as get_the_grpc_req_impl, is_suite_supported_for_connector,
        load_default_scenario_name, load_scenario, load_suite_scenarios, load_suite_spec,
        load_supported_suites_for_connector,
    },
    scenario_types::{ContextMap, DependencyScope, FieldAssert, ScenarioError, SuiteDependency},
    sdk_executor::execute_sdk_request_from_payload,
};

/// Loads raw request template for `(suite, scenario)` without connector override.
pub fn get_the_grpc_req(suite: &str, scenario: &str) -> Result<Value, ScenarioError> {
    get_the_grpc_req_impl(suite, scenario)
}

/// Loads assertion rules for `(suite, scenario)` without connector override.
pub fn get_the_assertion(
    suite: &str,
    scenario: &str,
) -> Result<BTreeMap<String, FieldAssert>, ScenarioError> {
    get_the_assertion_impl(suite, scenario)
}

/// Loads scenario and applies connector-specific request/assertion patches.
fn load_effective_scenario_for_connector(
    suite: &str,
    scenario: &str,
    connector: &str,
) -> Result<(Value, BTreeMap<String, FieldAssert>), ScenarioError> {
    let base_scenario = load_scenario(suite, scenario)?;
    let mut grpc_req = base_scenario.grpc_req;
    let mut assertions = base_scenario.assert_rules;
    apply_connector_overrides(connector, suite, scenario, &mut grpc_req, &mut assertions)?;
    Ok((grpc_req, assertions))
}

/// Loads request template after applying connector-specific overrides.
pub fn get_the_grpc_req_for_connector(
    suite: &str,
    scenario: &str,
    connector: &str,
) -> Result<Value, ScenarioError> {
    let (grpc_req, _assertions) =
        load_effective_scenario_for_connector(suite, scenario, connector)?;
    Ok(grpc_req)
}

/// Loads assertion rules after applying connector-specific overrides.
pub fn get_the_assertion_for_connector(
    suite: &str,
    scenario: &str,
    connector: &str,
) -> Result<BTreeMap<String, FieldAssert>, ScenarioError> {
    let (_grpc_req, assertions) =
        load_effective_scenario_for_connector(suite, scenario, connector)?;
    Ok(assertions)
}

/// Public assertion entrypoint used by runners.
pub fn do_assertion(
    assertions_for_that_req: &BTreeMap<String, FieldAssert>,
    response_json: &Value,
    grpc_req: &Value,
) -> Result<(), ScenarioError> {
    do_assertion_impl(assertions_for_that_req, response_json, grpc_req)
}

pub const DEFAULT_SUITE: &str = "authorize";
pub const DEFAULT_SCENARIO: &str = "no3ds_auto_capture_credit_card";
pub const DEFAULT_ENDPOINT: &str = "localhost:50051";
pub const DEFAULT_CONNECTOR: &str = "stripe";
pub const DEFAULT_MERCHANT_ID: &str = "test_merchant";
pub const DEFAULT_TENANT_ID: &str = "default";

/// Materialized grpcurl command pieces used by CLI output and execution.
#[derive(Debug, Clone)]
pub struct GrpcurlRequest {
    pub endpoint: String,
    pub method: String,
    pub payload: String,
    pub headers: Vec<String>,
    pub plaintext: bool,
}

#[derive(Debug, Clone)]
pub struct GrpcExecutionResult {
    pub response_body: String,
    pub request_command: String,
    pub response_output: String,
    pub success: bool,
}

type ExplicitContextEntry = (ContextMap, Value, Value);
type DependencyContext = (
    Vec<Value>,
    Vec<Value>,
    Vec<String>,
    Vec<ExplicitContextEntry>,
);

impl GrpcurlRequest {
    /// Renders a shell-friendly multi-line grpcurl command.
    pub fn to_command_string(&self) -> String {
        let mut cmd = String::new();
        cmd.push_str("grpcurl");
        if self.plaintext {
            cmd.push_str(" -plaintext");
        }
        cmd.push_str(" \\\n");

        for header in &self.headers {
            cmd.push_str(&format!("  -H \"{header}\" \\\n"));
        }

        cmd.push_str(&format!(
            "  -d @ {} {} <<'JSON'\n",
            self.endpoint, self.method
        ));
        cmd.push_str(&self.payload);
        cmd.push_str("\nJSON");
        cmd
    }
}

/// Validates request template loading for one scenario target.
pub fn run_test(
    suite: Option<&str>,
    scenario: Option<&str>,
    connector: Option<&str>,
) -> Result<(), ScenarioError> {
    let suite = suite.unwrap_or(DEFAULT_SUITE);
    let scenario = scenario.unwrap_or(DEFAULT_SCENARIO);
    let connector = connector.unwrap_or(DEFAULT_CONNECTOR);

    let _ = get_the_grpc_req_for_connector(suite, scenario, connector)?;
    Ok(())
}

/// Applies implicit context propagation by matching similarly-named fields from
/// previously executed requests/responses.
pub fn add_context(
    prev_grpc_reqs: &[Value],
    prev_grpc_res: &[Value],
    current_grpc_req: &mut Value,
) {
    let mut paths = Vec::new();
    collect_leaf_paths(current_grpc_req, String::new(), &mut paths);

    for path in paths {
        let mut selected: Option<Value> = None;
        let source_paths = source_path_candidates(&path);
        let max_len = prev_grpc_reqs.len().max(prev_grpc_res.len());
        for index in 0..max_len {
            if let Some(req) = prev_grpc_reqs.get(index) {
                if let Some(value) = lookup_first_non_null_path(req, &source_paths) {
                    selected = Some(value.clone());
                }
            }
            if let Some(res) = prev_grpc_res.get(index) {
                if let Some(value) = lookup_first_non_null_path(res, &source_paths) {
                    selected = Some(value.clone());
                }
            }
        }

        if let Some(value) = selected {
            let value_to_set = if path.ends_with(".value") {
                value.get("value").cloned().unwrap_or_else(|| value.clone())
            } else {
                value
            };
            let _ = set_json_path_value(current_grpc_req, &path, value_to_set);
        }
    }
}

pub fn prepare_context_placeholders(suite: &str, connector: &str, current_grpc_req: &mut Value) {
    // Ensure metadata target exists for flows that need dependency-carried connector metadata.
    if matches!(suite, "capture" | "void" | "refund" | "get" | "refund_sync")
        && lookup_json_path_with_case_fallback(current_grpc_req, "connector_feature_data.value")
            .is_none()
    {
        let _ = deep_set_json_path(
            current_grpc_req,
            "connector_feature_data.value",
            Value::String("auto_generate".to_string()),
        );
    }

    for path in context_deferred_paths(connector) {
        if let Some(value) = lookup_json_path_with_case_fallback(current_grpc_req, &path) {
            if is_empty_context_placeholder(&path, value) {
                let _ = deep_set_json_path(
                    current_grpc_req,
                    &path,
                    Value::String("auto_generate".to_string()),
                );
            }
        }
    }
}

pub fn prune_unresolved_context_fields(connector: &str, current_grpc_req: &mut Value) {
    for path in context_deferred_paths(connector) {
        let should_remove = lookup_json_path_with_case_fallback(current_grpc_req, &path)
            .map(|value| is_unresolved_context_value(&path, value))
            .unwrap_or(false);
        if should_remove {
            let _ = remove_json_path(current_grpc_req, &path);
        }
    }

    let should_remove_connector_feature =
        lookup_json_path_with_case_fallback(current_grpc_req, "connector_feature_data")
            .map(is_unresolved_connector_feature_data)
            .unwrap_or(false);
    if should_remove_connector_feature {
        let _ = remove_json_path(current_grpc_req, "connector_feature_data");
    }

    // Cleanup optional empty wrappers after field-level pruning.
    let _ = remove_json_path_if_empty_object(current_grpc_req, "state.access_token.token");
    let _ = remove_json_path_if_empty_object(current_grpc_req, "state.access_token");
    let _ = remove_json_path_if_empty_object(current_grpc_req, "state");
    let _ = remove_json_path_if_empty_object(current_grpc_req, "connector_feature_data");
}

fn context_deferred_paths(connector: &str) -> Vec<String> {
    let mut base_paths = vec![
        "customer.connector_customer_id".to_string(),
        "state.connector_customer_id".to_string(),
        "state.access_token.token.value".to_string(),
        "state.access_token.token_type".to_string(),
        "state.access_token.expires_in_seconds".to_string(),
        "connector_feature_data.value".to_string(),
        "connector_transaction_id.id".to_string(),
        "refund_id".to_string(),
    ];
    base_paths.extend(context_deferred_paths_for_connector(connector));
    base_paths.sort();
    base_paths.dedup();
    base_paths
}

fn is_empty_context_placeholder(path: &str, value: &Value) -> bool {
    if value.is_null() {
        return true;
    }

    if let Some(text) = value.as_str() {
        return text.trim().is_empty();
    }

    // Historical placeholder for access token expiry.
    if path == "state.access_token.expires_in_seconds" {
        return value.as_i64() == Some(0);
    }

    false
}

fn is_unresolved_context_value(path: &str, value: &Value) -> bool {
    if value.is_null() {
        return true;
    }

    if let Some(text) = value.as_str() {
        let normalized = text.trim().to_ascii_lowercase();
        return normalized.is_empty() || normalized.contains("auto_generate");
    }

    if path == "state.access_token.expires_in_seconds" {
        return value.as_i64() == Some(0);
    }

    false
}

fn is_unresolved_connector_feature_data(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::String(text) => {
            let normalized = text.trim().to_ascii_lowercase();
            normalized.is_empty() || normalized.contains("auto_generate")
        }
        Value::Object(map) => map
            .get("value")
            .map(|inner| is_unresolved_context_value("connector_feature_data.value", inner))
            .unwrap_or(true),
        _ => false,
    }
}

/// Applies explicit context mappings from dependency results into the target request.
///
/// Each entry in `collected_context` is a `(context_map, dependency_req, dependency_res)` tuple
/// from one dependency suite. The `context_map` declares exactly which fields flow where:
///
/// ```json
/// { "state.access_token.token.value": "res.access_token" }
/// ```
///
/// - Left side (key) = target path in `current_grpc_req`
/// - Right side (value) = source reference prefixed with `res.` or `req.`
///   (if no prefix, `res.` is assumed)
///
/// Missing intermediate objects are created automatically (deep-set).
pub fn apply_context_map(
    collected_context: &[(ContextMap, Value, Value)],
    current_grpc_req: &mut Value,
) {
    for (context_map, dep_req, dep_res) in collected_context {
        for (target_path, source_ref) in context_map {
            let (source_json, source_path) = if let Some(path) = source_ref.strip_prefix("req.") {
                (dep_req, path)
            } else if let Some(path) = source_ref.strip_prefix("res.") {
                (dep_res, path)
            } else {
                // Default to response if no prefix
                (dep_res, source_ref.as_str())
            };

            // Try direct path, then with .id_type.id unwrapping for Identifier fields
            let source_value = lookup_json_path_with_case_fallback(source_json, source_path)
                .or_else(|| {
                    // If source path ends with .id, also try .id_type.id
                    if source_path.ends_with(".id") {
                        let alt = format!(
                            "{}.id_type.id",
                            source_path.strip_suffix(".id").unwrap_or(source_path)
                        );
                        lookup_json_path_with_case_fallback(source_json, &alt)
                    } else {
                        None
                    }
                })
                .or_else(|| {
                    // Try camelCase version of source path
                    let camel = source_path
                        .split('.')
                        .map(snake_to_camel_case)
                        .collect::<Vec<_>>()
                        .join(".");
                    lookup_json_path_with_case_fallback(source_json, &camel)
                });

            if let Some(value) = source_value {
                if !value.is_null() {
                    let _ = deep_set_json_path(current_grpc_req, target_path, value.clone());
                }
            }
        }
    }
}

/// Like `set_json_path_value` but creates intermediate objects if they don't exist.
pub fn deep_set_json_path(root: &mut Value, path: &str, value: Value) -> bool {
    let segments: Vec<&str> = path.split('.').collect();
    let mut current = root;

    for (i, segment) in segments.iter().enumerate() {
        let is_last = i == segments.len() - 1;

        if is_last {
            if let Some(map) = current.as_object_mut() {
                map.insert(segment.to_string(), value);
                return true;
            }
            return false;
        }

        // Navigate or create intermediate object
        if current.is_object() {
            let Some(map) = current.as_object_mut() else {
                return false;
            };
            if !map.contains_key(*segment) {
                map.insert(segment.to_string(), Value::Object(serde_json::Map::new()));
            }
            let Some(next) = map.get_mut(*segment) else {
                return false;
            };
            current = next;
        } else {
            return false;
        }
    }

    false
}

fn lookup_first_non_null_path<'a>(value: &'a Value, paths: &[String]) -> Option<&'a Value> {
    for path in paths {
        if let Some(found) = lookup_json_path_with_case_fallback(value, path) {
            if !found.is_null() {
                return Some(found);
            }
        }
    }
    None
}

fn source_path_candidates(path: &str) -> Vec<String> {
    let mut candidates = vec![path.to_string()];

    if path.ends_with(".connector_customer_id") {
        candidates.push("connector_customer_id".to_string());
    }

    if path == "state.access_token.token.value" {
        candidates.push("access_token.value".to_string());
        candidates.push("access_token".to_string());
    }

    if path == "state.access_token.token_type" {
        candidates.push("token_type".to_string());
    }

    if path == "state.access_token.expires_in_seconds" {
        candidates.push("expires_in_seconds".to_string());
    }

    if let Some(rest) = path.strip_prefix("state.") {
        candidates.push(rest.to_string());
    }

    if path == "connector_feature_data.value" {
        candidates.push("connector_feature_data".to_string());
    }

    if path == "refund_id" {
        candidates.push("connector_refund_id".to_string());
    }

    if let Some(rest) = path.strip_prefix("mandate_reference_id.") {
        candidates.push(format!("mandate_reference.{rest}"));
    }

    if let Some(prefix) = path.strip_suffix(".id") {
        candidates.push(format!("{prefix}.id_type.id"));
        candidates.push(format!("{prefix}.id_type.encoded_data"));
    }

    let mut deduped = Vec::new();
    for candidate in candidates {
        if !deduped.contains(&candidate) {
            deduped.push(candidate);
        }
    }
    deduped
}

fn collect_leaf_paths(value: &Value, current: String, paths: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let next = if current.is_empty() {
                    key.to_string()
                } else {
                    format!("{current}.{key}")
                };
                collect_leaf_paths(child, next, paths);
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                let next = if current.is_empty() {
                    index.to_string()
                } else {
                    format!("{current}.{index}")
                };
                collect_leaf_paths(child, next, paths);
            }
        }
        _ => paths.push(current),
    }
}

fn lookup_json_path_with_case_fallback<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    if path.is_empty() {
        return Some(value);
    }

    let mut current = value;
    for segment in path.split('.') {
        if segment.is_empty() {
            return None;
        }

        current = if let Ok(index) = segment.parse::<usize>() {
            current.get(index)?
        } else {
            current
                .get(segment)
                .or_else(|| current.get(snake_to_camel_case(segment)))
                .or_else(|| current.get(camel_to_snake_case(segment)))
                .or_else(|| current.get(to_pascal_case(segment)))?
        };
    }

    Some(current)
}

fn set_json_path_value(root: &mut Value, path: &str, value: Value) -> bool {
    let mut segments = path.split('.').peekable();
    let mut current = root;

    while let Some(segment) = segments.next() {
        let is_last = segments.peek().is_none();

        if let Ok(index) = segment.parse::<usize>() {
            let Some(items) = current.as_array_mut() else {
                return false;
            };
            let Some(next) = items.get_mut(index) else {
                return false;
            };
            if is_last {
                *next = value;
                return true;
            }
            current = next;
            continue;
        }

        let Some(map) = current.as_object_mut() else {
            return false;
        };

        if is_last {
            if map.contains_key(segment) {
                map.insert(segment.to_string(), value);
                return true;
            }
            let camel = snake_to_camel_case(segment);
            if map.contains_key(&camel) {
                map.insert(camel, value);
                return true;
            }
            let snake = camel_to_snake_case(segment);
            if map.contains_key(&snake) {
                map.insert(snake, value);
                return true;
            }
            return false;
        }

        let next_key = if map.contains_key(segment) {
            segment.to_string()
        } else {
            let camel = snake_to_camel_case(segment);
            if map.contains_key(&camel) {
                camel
            } else {
                let snake = camel_to_snake_case(segment);
                if map.contains_key(&snake) {
                    snake
                } else {
                    return false;
                }
            }
        };

        let Some(next) = map.get_mut(&next_key) else {
            return false;
        };
        current = next;
    }

    false
}

fn remove_json_path(root: &mut Value, path: &str) -> bool {
    let mut segments = path.split('.').peekable();
    let mut current = root;

    while let Some(segment) = segments.next() {
        let is_last = segments.peek().is_none();

        if is_last {
            if let Ok(index) = segment.parse::<usize>() {
                if let Some(items) = current.as_array_mut() {
                    if let Some(target) = items.get_mut(index) {
                        *target = Value::Null;
                        return true;
                    }
                }
                return false;
            }

            if let Some(map) = current.as_object_mut() {
                return map.remove(segment).is_some();
            }
            return false;
        }

        if let Ok(index) = segment.parse::<usize>() {
            let Some(items) = current.as_array_mut() else {
                return false;
            };
            let Some(next) = items.get_mut(index) else {
                return false;
            };
            current = next;
            continue;
        }

        let Some(map) = current.as_object_mut() else {
            return false;
        };
        let Some(next) = map.get_mut(segment) else {
            return false;
        };
        current = next;
    }

    false
}

fn remove_json_path_if_empty_object(root: &mut Value, path: &str) -> bool {
    let should_remove = lookup_json_path_with_case_fallback(root, path)
        .and_then(Value::as_object)
        .map(|object| object.is_empty())
        .unwrap_or(false);
    if should_remove {
        return remove_json_path(root, path);
    }
    false
}

fn snake_to_camel_case(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut uppercase_next = false;
    for ch in input.chars() {
        if ch == '_' {
            uppercase_next = true;
            continue;
        }

        if uppercase_next {
            out.push(ch.to_ascii_uppercase());
            uppercase_next = false;
        } else {
            out.push(ch);
        }
    }
    out
}

fn camel_to_snake_case(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 4);
    for (idx, ch) in input.chars().enumerate() {
        if ch.is_ascii_uppercase() && idx > 0 {
            out.push('_');
        }
        out.push(ch.to_ascii_lowercase());
    }
    out
}

/// Builds a grpcurl request by loading payload from suite/scenario templates.
pub fn build_grpcurl_request(
    suite: Option<&str>,
    scenario: Option<&str>,
    endpoint: Option<&str>,
    connector: Option<&str>,
    merchant_id: Option<&str>,
    tenant_id: Option<&str>,
    plaintext: bool,
    require_auth: bool,
) -> Result<GrpcurlRequest, ScenarioError> {
    let suite = suite.unwrap_or(DEFAULT_SUITE);
    let scenario = scenario.unwrap_or(DEFAULT_SCENARIO);
    let connector = connector.unwrap_or(DEFAULT_CONNECTOR);
    let mut grpc_req = get_the_grpc_req_for_connector(suite, scenario, connector)?;
    resolve_auto_generate(&mut grpc_req)?;
    build_grpcurl_request_from_payload(
        suite,
        scenario,
        &grpc_req,
        endpoint,
        Some(connector),
        merchant_id,
        tenant_id,
        plaintext,
        require_auth,
    )
}

/// Builds a grpcurl request from an already materialized JSON payload.
pub fn build_grpcurl_request_from_payload(
    suite: &str,
    scenario: &str,
    grpc_req: &Value,
    endpoint: Option<&str>,
    connector: Option<&str>,
    merchant_id: Option<&str>,
    tenant_id: Option<&str>,
    plaintext: bool,
    require_auth: bool,
) -> Result<GrpcurlRequest, ScenarioError> {
    let endpoint = endpoint.unwrap_or(DEFAULT_ENDPOINT);
    let connector = connector.unwrap_or(DEFAULT_CONNECTOR);
    let merchant_id = merchant_id.unwrap_or(DEFAULT_MERCHANT_ID);
    let tenant_id = tenant_id.unwrap_or(DEFAULT_TENANT_ID);

    let payload = serde_json::to_string_pretty(grpc_req)
        .map_err(|source| ScenarioError::JsonSerialize { source })?;

    let auth = load_connector_auth(connector).map_or_else(
        |error| {
            if require_auth {
                Err(ScenarioError::CredentialLoad {
                    connector: connector.to_string(),
                    message: error.to_string(),
                })
            } else {
                Ok(None)
            }
        },
        |auth| Ok(Some(auth)),
    )?;

    let request_id = format!("{suite}_{scenario}_req");
    let connector_request_reference_id = format!("{suite}_{scenario}_ref");
    let method = grpc_method_for_suite(suite)?;

    let mut headers = vec![
        format!("x-connector: {connector}"),
        format!("x-merchant-id: {merchant_id}"),
        format!("x-tenant-id: {tenant_id}"),
        format!("x-request-id: {request_id}"),
        format!("x-connector-request-reference-id: {connector_request_reference_id}"),
    ];

    if let Some(auth) = auth.as_ref() {
        headers.extend(auth_headers(auth));
    } else {
        headers.push("x-auth: <header-key|body-key|signature-key>".to_string());
        headers.push("x-api-key: <api_key>".to_string());
    }

    Ok(GrpcurlRequest {
        endpoint: endpoint.to_string(),
        method: method.to_string(),
        payload,
        headers,
        plaintext,
    })
}

/// Convenience helper that returns only the shell command string.
pub fn build_grpcurl_command(
    suite: Option<&str>,
    scenario: Option<&str>,
    endpoint: Option<&str>,
    connector: Option<&str>,
    merchant_id: Option<&str>,
    tenant_id: Option<&str>,
    plaintext: bool,
) -> Result<String, ScenarioError> {
    let request = build_grpcurl_request(
        suite,
        scenario,
        endpoint,
        connector,
        merchant_id,
        tenant_id,
        plaintext,
        false,
    )?;
    Ok(request.to_command_string())
}

/// Executes grpcurl by resolving payload from suite/scenario templates.
pub fn execute_grpcurl_request(
    suite: Option<&str>,
    scenario: Option<&str>,
    endpoint: Option<&str>,
    connector: Option<&str>,
    merchant_id: Option<&str>,
    tenant_id: Option<&str>,
    plaintext: bool,
) -> Result<String, ScenarioError> {
    let result = execute_grpcurl_request_with_trace(
        suite,
        scenario,
        endpoint,
        connector,
        merchant_id,
        tenant_id,
        plaintext,
    )?;
    if !result.success {
        return Err(ScenarioError::GrpcurlExecution {
            message: result.response_output,
        });
    }
    Ok(result.response_body)
}

/// Executes grpcurl by resolving payload from suite/scenario templates and
/// returns full request/response trace.
pub fn execute_grpcurl_request_with_trace(
    suite: Option<&str>,
    scenario: Option<&str>,
    endpoint: Option<&str>,
    connector: Option<&str>,
    merchant_id: Option<&str>,
    tenant_id: Option<&str>,
    plaintext: bool,
) -> Result<GrpcExecutionResult, ScenarioError> {
    let suite = suite.unwrap_or(DEFAULT_SUITE);
    let scenario = scenario.unwrap_or(DEFAULT_SCENARIO);
    let connector = connector.unwrap_or(DEFAULT_CONNECTOR);
    let mut grpc_req = get_the_grpc_req_for_connector(suite, scenario, connector)?;
    resolve_auto_generate(&mut grpc_req)?;
    execute_grpcurl_request_from_payload_with_trace(
        suite,
        scenario,
        &grpc_req,
        endpoint,
        Some(connector),
        merchant_id,
        tenant_id,
        plaintext,
    )
}

/// Executes grpcurl with a prepared payload.
pub fn execute_grpcurl_request_from_payload(
    suite: &str,
    scenario: &str,
    grpc_req: &Value,
    endpoint: Option<&str>,
    connector: Option<&str>,
    merchant_id: Option<&str>,
    tenant_id: Option<&str>,
    plaintext: bool,
) -> Result<String, ScenarioError> {
    let result = execute_grpcurl_request_from_payload_with_trace(
        suite,
        scenario,
        grpc_req,
        endpoint,
        connector,
        merchant_id,
        tenant_id,
        plaintext,
    )?;
    if !result.success {
        return Err(ScenarioError::GrpcurlExecution {
            message: result.response_output,
        });
    }
    Ok(result.response_body)
}

/// Executes grpcurl with a prepared payload and returns full request/response
/// trace (including verbose header/trailer output).
pub fn execute_grpcurl_request_from_payload_with_trace(
    suite: &str,
    scenario: &str,
    grpc_req: &Value,
    endpoint: Option<&str>,
    connector: Option<&str>,
    merchant_id: Option<&str>,
    tenant_id: Option<&str>,
    plaintext: bool,
) -> Result<GrpcExecutionResult, ScenarioError> {
    let request = build_grpcurl_request_from_payload(
        suite,
        scenario,
        grpc_req,
        endpoint,
        connector,
        merchant_id,
        tenant_id,
        plaintext,
        true,
    )?;
    execute_grpcurl_from_request(request)
}

fn execute_grpcurl_from_request(
    request: GrpcurlRequest,
) -> Result<GrpcExecutionResult, ScenarioError> {
    let request_command = request.to_command_string();
    let mut args = Vec::new();
    args.push("-v".to_string());
    if request.plaintext {
        args.push("-plaintext".to_string());
    }

    for header in &request.headers {
        args.push("-H".to_string());
        args.push(header.clone());
    }

    args.push("-d".to_string());
    args.push(request.payload.clone());
    args.push(request.endpoint.clone());
    args.push(request.method.clone());

    let output = std::process::Command::new("grpcurl")
        .args(&args)
        .output()
        .map_err(|error| ScenarioError::GrpcurlExecution {
            message: format!("failed to spawn grpcurl: {error}"),
        })?;

    let stdout_output = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr_output = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let response_output = build_grpc_response_output(&stdout_output, &stderr_output);

    let response_body = extract_json_body_from_grpc_output(&stdout_output, &stderr_output)
        .unwrap_or_else(|| stdout_output.clone());

    Ok(GrpcExecutionResult {
        response_body,
        request_command,
        response_output,
        success: output.status.success(),
    })
}

fn build_grpc_response_output(stdout_output: &str, stderr_output: &str) -> String {
    if !stdout_output.is_empty() && !stderr_output.is_empty() {
        format!("{stdout_output}\n\n{stderr_output}")
    } else if !stdout_output.is_empty() {
        stdout_output.to_string()
    } else {
        stderr_output.to_string()
    }
}

pub fn extract_json_body_from_grpc_output(stdout_output: &str, stderr_output: &str) -> Option<String> {
    for source in [stdout_output, stderr_output] {
        let trimmed = source.trim();
        if trimmed.is_empty() {
            continue;
        }

        if serde_json::from_str::<Value>(trimmed).is_ok() {
            return Some(trimmed.to_string());
        }

        if let Some(marker_offset) = trimmed.find("Response contents:") {
            let marker_tail = &trimmed[(marker_offset + "Response contents:".len())..];
            if let Some(extracted) = extract_first_json_value(marker_tail) {
                return Some(extracted);
            }
        }

        if let Some(extracted) = extract_best_json_value(trimmed) {
            return Some(extracted);
        }
    }

    None
}

fn extract_first_json_value(text: &str) -> Option<String> {
    for (start_index, ch) in text.char_indices() {
        if ch != '{' && ch != '[' {
            continue;
        }

        let Some(end_index) = find_json_value_end(text, start_index) else {
            continue;
        };

        let candidate = text[start_index..end_index].trim();
        if serde_json::from_str::<Value>(candidate).is_ok() {
            return Some(candidate.to_string());
        }
    }

    None
}

fn extract_best_json_value(text: &str) -> Option<String> {
    let mut best: Option<&str> = None;

    for (start_index, ch) in text.char_indices() {
        if ch != '{' && ch != '[' {
            continue;
        }

        let Some(end_index) = find_json_value_end(text, start_index) else {
            continue;
        };

        let candidate = text[start_index..end_index].trim();
        if serde_json::from_str::<Value>(candidate).is_ok() {
            let replace = best.is_none_or(|existing| candidate.len() > existing.len());
            if replace {
                best = Some(candidate);
            }
        }
    }

    best.map(ToString::to_string)
}

fn find_json_value_end(text: &str, start_index: usize) -> Option<usize> {
    let mut stack: Vec<char> = Vec::new();
    let mut in_string = false;
    let mut escaped = false;

    for (offset, ch) in text[start_index..].char_indices() {
        let index = start_index + offset;

        if in_string {
            if escaped {
                escaped = false;
                continue;
            }

            if ch == '\\' {
                escaped = true;
                continue;
            }

            if ch == '"' {
                in_string = false;
            }
            continue;
        }

        match ch {
            '"' => in_string = true,
            '{' | '[' => stack.push(ch),
            '}' => {
                if stack.pop() != Some('{') {
                    return None;
                }
                if stack.is_empty() {
                    return Some(index + ch.len_utf8());
                }
            }
            ']' => {
                if stack.pop() != Some('[') {
                    return None;
                }
                if stack.is_empty() {
                    return Some(index + ch.len_utf8());
                }
            }
            _ => {}
        }
    }

    None
}

/// Executes one request through tonic backend using template payload.
pub fn execute_tonic_request(
    suite: Option<&str>,
    scenario: Option<&str>,
    endpoint: Option<&str>,
    connector: Option<&str>,
    merchant_id: Option<&str>,
    tenant_id: Option<&str>,
    plaintext: bool,
) -> Result<String, ScenarioError> {
    let suite = suite.unwrap_or(DEFAULT_SUITE);
    let scenario = scenario.unwrap_or(DEFAULT_SCENARIO);
    let connector = connector.unwrap_or(DEFAULT_CONNECTOR);
    let mut grpc_req = get_the_grpc_req_for_connector(suite, scenario, connector)?;
    resolve_auto_generate(&mut grpc_req)?;
    execute_tonic_request_from_payload(
        suite,
        scenario,
        &grpc_req,
        endpoint,
        Some(connector),
        merchant_id,
        tenant_id,
        plaintext,
    )
}

/// Executes one request through tonic backend using prepared payload.
pub fn execute_tonic_request_from_payload(
    suite: &str,
    scenario: &str,
    grpc_req: &Value,
    endpoint: Option<&str>,
    connector: Option<&str>,
    merchant_id: Option<&str>,
    tenant_id: Option<&str>,
    plaintext: bool,
) -> Result<String, ScenarioError> {
    let connector = connector.unwrap_or(DEFAULT_CONNECTOR).to_string();
    let merchant_id = merchant_id.unwrap_or(DEFAULT_MERCHANT_ID).to_string();
    let tenant_id = tenant_id.unwrap_or(DEFAULT_TENANT_ID).to_string();
    let endpoint = endpoint.unwrap_or(DEFAULT_ENDPOINT).to_string();
    let auth = load_connector_auth(&connector).map_err(|error| ScenarioError::CredentialLoad {
        connector: connector.clone(),
        message: error.to_string(),
    })?;

    let request_id = format!("{suite}_{scenario}_req");
    let connector_request_reference_id = format!("{suite}_{scenario}_ref");
    let grpc_req = grpc_req.clone();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| ScenarioError::GrpcurlExecution {
            message: format!("failed to initialize tonic runtime: {error}"),
        })?;

    runtime.block_on(async move {
        let channel = Channel::from_shared(to_tonic_endpoint(&endpoint, plaintext))
            .map_err(|error| ScenarioError::GrpcurlExecution {
                message: format!("failed to prepare tonic endpoint '{endpoint}': {error}"),
            })?
            .connect()
            .await
            .map_err(|error| ScenarioError::GrpcurlExecution {
                message: format!("failed to connect to endpoint '{endpoint}': {error}"),
            })?;

        match suite {
            "create_access_token" => {
                let payload: grpc_api_types::payments::MerchantAuthenticationServiceCreateAccessTokenRequest =
                    parse_tonic_payload(suite, scenario, &connector, &grpc_req)?;
                let mut request = tonic::Request::new(payload);
                add_connector_metadata(
                    &mut request,
                    &connector,
                    &auth,
                    &merchant_id,
                    &tenant_id,
                    &request_id,
                    &connector_request_reference_id,
                );
                let mut client = grpc_api_types::payments::merchant_authentication_service_client::MerchantAuthenticationServiceClient::new(channel.clone());
                let response = client.create_access_token(request).await.map_err(|error| {
                    ScenarioError::GrpcurlExecution {
                        message: format!(
                            "tonic execution failed for '{suite}/{scenario}': {error}"
                        ),
                    }
                })?;
                serialize_tonic_response(&response.into_inner())
            }
            "create_customer" => {
                let payload: grpc_api_types::payments::CustomerServiceCreateRequest =
                    parse_tonic_payload(suite, scenario, &connector, &grpc_req)?;
                let mut request = tonic::Request::new(payload);
                add_connector_metadata(
                    &mut request,
                    &connector,
                    &auth,
                    &merchant_id,
                    &tenant_id,
                    &request_id,
                    &connector_request_reference_id,
                );
                let mut client = grpc_api_types::payments::customer_service_client::CustomerServiceClient::new(channel.clone());
                let response = client.create(request).await.map_err(|error| {
                    ScenarioError::GrpcurlExecution {
                        message: format!(
                            "tonic execution failed for '{suite}/{scenario}': {error}"
                        ),
                    }
                })?;
                serialize_tonic_response(&response.into_inner())
            }
            "authorize" => {
                let payload: grpc_api_types::payments::PaymentServiceAuthorizeRequest =
                    parse_tonic_payload(suite, scenario, &connector, &grpc_req)?;
                let mut request = tonic::Request::new(payload);
                add_connector_metadata(
                    &mut request,
                    &connector,
                    &auth,
                    &merchant_id,
                    &tenant_id,
                    &request_id,
                    &connector_request_reference_id,
                );
                let mut client = grpc_api_types::payments::payment_service_client::PaymentServiceClient::new(channel.clone());
                let response = client.authorize(request).await.map_err(|error| {
                    ScenarioError::GrpcurlExecution {
                        message: format!(
                            "tonic execution failed for '{suite}/{scenario}': {error}"
                        ),
                    }
                })?;
                serialize_tonic_response(&response.into_inner())
            }
            "capture" => {
                let payload: grpc_api_types::payments::PaymentServiceCaptureRequest =
                    parse_tonic_payload(suite, scenario, &connector, &grpc_req)?;
                let mut request = tonic::Request::new(payload);
                add_connector_metadata(
                    &mut request,
                    &connector,
                    &auth,
                    &merchant_id,
                    &tenant_id,
                    &request_id,
                    &connector_request_reference_id,
                );
                let mut client = grpc_api_types::payments::payment_service_client::PaymentServiceClient::new(channel.clone());
                let response = client.capture(request).await.map_err(|error| {
                    ScenarioError::GrpcurlExecution {
                        message: format!(
                            "tonic execution failed for '{suite}/{scenario}': {error}"
                        ),
                    }
                })?;
                serialize_tonic_response(&response.into_inner())
            }
            "refund" => {
                let payload: grpc_api_types::payments::PaymentServiceRefundRequest =
                    parse_tonic_payload(suite, scenario, &connector, &grpc_req)?;
                let mut request = tonic::Request::new(payload);
                add_connector_metadata(
                    &mut request,
                    &connector,
                    &auth,
                    &merchant_id,
                    &tenant_id,
                    &request_id,
                    &connector_request_reference_id,
                );
                let mut client = grpc_api_types::payments::payment_service_client::PaymentServiceClient::new(channel.clone());
                let response = client.refund(request).await.map_err(|error| {
                    ScenarioError::GrpcurlExecution {
                        message: format!(
                            "tonic execution failed for '{suite}/{scenario}': {error}"
                        ),
                    }
                })?;
                serialize_tonic_response(&response.into_inner())
            }
            "void" => {
                let payload: grpc_api_types::payments::PaymentServiceVoidRequest =
                    parse_tonic_payload(suite, scenario, &connector, &grpc_req)?;
                let mut request = tonic::Request::new(payload);
                add_connector_metadata(
                    &mut request,
                    &connector,
                    &auth,
                    &merchant_id,
                    &tenant_id,
                    &request_id,
                    &connector_request_reference_id,
                );
                let mut client = grpc_api_types::payments::payment_service_client::PaymentServiceClient::new(channel.clone());
                let response = client.void(request).await.map_err(|error| {
                    ScenarioError::GrpcurlExecution {
                        message: format!(
                            "tonic execution failed for '{suite}/{scenario}': {error}"
                        ),
                    }
                })?;
                serialize_tonic_response(&response.into_inner())
            }
            "get" => {
                let payload: grpc_api_types::payments::PaymentServiceGetRequest =
                    parse_tonic_payload(suite, scenario, &connector, &grpc_req)?;
                let mut request = tonic::Request::new(payload);
                add_connector_metadata(
                    &mut request,
                    &connector,
                    &auth,
                    &merchant_id,
                    &tenant_id,
                    &request_id,
                    &connector_request_reference_id,
                );
                let mut client = grpc_api_types::payments::payment_service_client::PaymentServiceClient::new(channel.clone());
                let response = client.get(request).await.map_err(|error| {
                    ScenarioError::GrpcurlExecution {
                        message: format!(
                            "tonic execution failed for '{suite}/{scenario}': {error}"
                        ),
                    }
                })?;
                serialize_tonic_response(&response.into_inner())
            }
            "refund_sync" => {
                let payload: grpc_api_types::payments::RefundServiceGetRequest =
                    parse_tonic_payload(suite, scenario, &connector, &grpc_req)?;
                let mut request = tonic::Request::new(payload);
                add_connector_metadata(
                    &mut request,
                    &connector,
                    &auth,
                    &merchant_id,
                    &tenant_id,
                    &request_id,
                    &connector_request_reference_id,
                );
                let mut client = grpc_api_types::payments::refund_service_client::RefundServiceClient::new(channel.clone());
                let response = client.get(request).await.map_err(|error| {
                    ScenarioError::GrpcurlExecution {
                        message: format!(
                            "tonic execution failed for '{suite}/{scenario}': {error}"
                        ),
                    }
                })?;
                serialize_tonic_response(&response.into_inner())
            }
            "setup_recurring" => {
                let payload: grpc_api_types::payments::PaymentServiceSetupRecurringRequest =
                    parse_tonic_payload(suite, scenario, &connector, &grpc_req)?;
                let mut request = tonic::Request::new(payload);
                add_connector_metadata(
                    &mut request,
                    &connector,
                    &auth,
                    &merchant_id,
                    &tenant_id,
                    &request_id,
                    &connector_request_reference_id,
                );
                let mut client = grpc_api_types::payments::payment_service_client::PaymentServiceClient::new(channel.clone());
                let response = client.setup_recurring(request).await.map_err(|error| {
                    ScenarioError::GrpcurlExecution {
                        message: format!(
                            "tonic execution failed for '{suite}/{scenario}': {error}"
                        ),
                    }
                })?;
                serialize_tonic_response(&response.into_inner())
            }
            "recurring_charge" => {
                let payload: grpc_api_types::payments::RecurringPaymentServiceChargeRequest =
                    parse_tonic_payload(suite, scenario, &connector, &grpc_req)?;
                let mut request = tonic::Request::new(payload);
                add_connector_metadata(
                    &mut request,
                    &connector,
                    &auth,
                    &merchant_id,
                    &tenant_id,
                    &request_id,
                    &connector_request_reference_id,
                );
                let mut client = grpc_api_types::payments::recurring_payment_service_client::RecurringPaymentServiceClient::new(channel.clone());
                let response = client.charge(request).await.map_err(|error| {
                    ScenarioError::GrpcurlExecution {
                        message: format!(
                            "tonic execution failed for '{suite}/{scenario}': {error}"
                        ),
                    }
                })?;
                serialize_tonic_response(&response.into_inner())
            }
            _ => Err(ScenarioError::UnsupportedSuite {
                suite: suite.to_string(),
            }),
        }
    })
}

pub(crate) fn parse_tonic_payload<T: DeserializeOwned>(
    suite: &str,
    scenario: &str,
    connector: &str,
    grpc_req: &Value,
) -> Result<T, ScenarioError> {
    let normalized = normalize_tonic_request_json(connector, suite, scenario, grpc_req.clone());
    serde_json::from_value(normalized).map_err(|error| ScenarioError::GrpcurlExecution {
        message: format!(
            "failed to parse request JSON into tonic payload for '{suite}/{scenario}': {error}"
        ),
    })
}

pub fn normalize_tonic_request_json(
    connector: &str,
    suite: &str,
    scenario: &str,
    mut value: Value,
) -> Value {
    normalize_value_wrappers(&mut value);
    normalize_proto_oneof_shapes(&mut value);

    // Legacy scenario payloads used in grpcurl contain fields that do not map
    // directly to current proto request shapes used by tonic serde.
    // Drop or adjust known mismatches here so scenarios remain unchanged.
    if let Value::Object(map) = &mut value {
        if suite == "authorize" {
            map.entry("order_details".to_string())
                .or_insert_with(|| Value::Array(Vec::new()));
        }

        if matches!(suite, "authorize" | "setup_recurring") {
            if let Some(Value::Object(customer_acceptance)) = map.get_mut("customer_acceptance") {
                if !customer_acceptance.contains_key("accepted_at") {
                    let accepted_at = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
                        .unwrap_or(0);
                    customer_acceptance.insert("accepted_at".to_string(), Value::from(accepted_at));
                }
            }
        }

        if suite == "setup_recurring" {
            map.entry("request_incremental_authorization".to_string())
                .or_insert_with(|| Value::Bool(false));
        }

        if suite == "get" {
            if let Some(handle_response) = map.get("handle_response") {
                if handle_response.is_boolean() {
                    map.remove("handle_response");
                }
            }
        }
    }

    normalize_tonic_request_for_connector(connector, suite, scenario, &mut value);
    value
}

fn normalize_proto_oneof_shapes(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for child in map.values_mut() {
                normalize_proto_oneof_shapes(child);
            }

            normalize_payment_method_oneof(map);
            normalize_mandate_reference_oneofs(map);
        }
        Value::Array(items) => {
            for item in items {
                normalize_proto_oneof_shapes(item);
            }
        }
        _ => {}
    }
}

fn normalize_payment_method_oneof(map: &mut serde_json::Map<String, Value>) {
    let Some(Value::Object(payment_method_obj)) = map.get_mut("payment_method") else {
        return;
    };

    if payment_method_obj.contains_key("payment_method") {
        return;
    }

    if payment_method_obj.len() != 1 {
        return;
    }

    let original = std::mem::take(payment_method_obj);
    let Some((variant, payload)) = original.into_iter().next() else {
        return;
    };

    let mut oneof_obj = serde_json::Map::new();
    oneof_obj.insert(normalize_oneof_variant_key(&variant), payload);

    payment_method_obj.insert("payment_method".to_string(), Value::Object(oneof_obj));
}

fn normalize_mandate_reference_oneofs(map: &mut serde_json::Map<String, Value>) {
    let Some(Value::Object(mandate_reference_obj)) = map.get_mut("connector_recurring_payment_id")
    else {
        return;
    };

    if mandate_reference_obj.contains_key("mandate_id_type") {
        return;
    }

    if mandate_reference_obj.len() != 1 {
        return;
    }

    let original = std::mem::take(mandate_reference_obj);
    let Some((variant, payload)) = original.into_iter().next() else {
        return;
    };

    let mut wrapped_variant = serde_json::Map::new();
    wrapped_variant.insert(to_pascal_case(&variant), payload);

    mandate_reference_obj.insert(
        "mandate_id_type".to_string(),
        Value::Object(wrapped_variant),
    );
}

fn to_pascal_case(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut capitalize_next = true;

    for ch in value.chars() {
        if ch == '_' || ch == '-' {
            capitalize_next = true;
            continue;
        }

        if capitalize_next {
            out.extend(ch.to_uppercase());
            capitalize_next = false;
        } else {
            out.push(ch);
        }
    }

    out
}

fn normalize_oneof_variant_key(value: &str) -> String {
    if value
        .chars()
        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_')
    {
        return value.to_string();
    }

    let mut out = String::with_capacity(value.len() + 8);
    let mut previous_was_lower_or_digit = false;

    for ch in value.chars() {
        if ch == '-' || ch == ' ' {
            if !out.ends_with('_') {
                out.push('_');
            }
            previous_was_lower_or_digit = false;
            continue;
        }

        if ch.is_ascii_uppercase() {
            if previous_was_lower_or_digit && !out.ends_with('_') {
                out.push('_');
            }
            out.push(ch.to_ascii_lowercase());
            previous_was_lower_or_digit = false;
            continue;
        }

        out.push(ch);
        previous_was_lower_or_digit = ch.is_ascii_lowercase() || ch.is_ascii_digit();
    }

    while out.ends_with('_') {
        out.pop();
    }

    if out.is_empty() {
        value.to_string()
    } else {
        out
    }
}

fn normalize_value_wrappers(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for child in map.values_mut() {
                normalize_value_wrappers(child);
            }

            if map.len() == 1 {
                if let Some(inner) = map.get("value") {
                    *value = inner.clone();
                    normalize_value_wrappers(value);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                normalize_value_wrappers(item);
            }
        }
        _ => {}
    }
}

fn serialize_tonic_response<T: Serialize>(response: &T) -> Result<String, ScenarioError> {
    serde_json::to_string_pretty(response).map_err(|source| ScenarioError::JsonSerialize { source })
}

fn to_tonic_endpoint(endpoint: &str, plaintext: bool) -> String {
    if endpoint.starts_with("http://") || endpoint.starts_with("https://") {
        return endpoint.to_string();
    }

    if plaintext {
        format!("http://{endpoint}")
    } else {
        format!("https://{endpoint}")
    }
}

#[derive(Debug, Clone)]
pub struct SuiteScenarioResult {
    pub suite: String,
    pub scenario: String,
    pub is_dependency: bool,
    pub passed: bool,
    pub error: Option<String>,
    pub dependency: Vec<String>,
    pub req_body: Option<Value>,
    pub res_body: Option<Value>,
    pub grpc_request: Option<String>,
    pub grpc_response: Option<String>,
}

#[derive(Debug, Clone)]
struct ExecutedScenario {
    effective_req: Value,
    response_json: Value,
    assertions: BTreeMap<String, FieldAssert>,
    grpc_request: Option<String>,
    grpc_response: Option<String>,
    execution_error: Option<String>,
}

fn dependency_label(suite: &str, scenario: &str) -> String {
    format!("{suite}({scenario})")
}

#[derive(Debug, Clone)]
pub struct SuiteRunSummary {
    pub suite: String,
    pub connector: String,
    pub passed: usize,
    pub failed: usize,
    pub results: Vec<SuiteScenarioResult>,
}

#[derive(Debug, Clone)]
pub struct AllSuitesRunSummary {
    pub connector: String,
    pub passed: usize,
    pub failed: usize,
    pub suites: Vec<SuiteRunSummary>,
}

#[derive(Debug, Clone)]
pub struct AllConnectorsRunSummary {
    pub passed: usize,
    pub failed: usize,
    pub connectors: Vec<AllSuitesRunSummary>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionBackend {
    Grpcurl,
    SdkFfi,
}

#[derive(Debug, Clone, Copy)]
pub struct SuiteRunOptions<'a> {
    pub endpoint: Option<&'a str>,
    pub merchant_id: Option<&'a str>,
    pub tenant_id: Option<&'a str>,
    pub plaintext: bool,
    pub backend: ExecutionBackend,
    pub report: bool,
}

impl Default for SuiteRunOptions<'_> {
    fn default() -> Self {
        Self {
            endpoint: None,
            merchant_id: None,
            tenant_id: None,
            plaintext: true,
            backend: ExecutionBackend::Grpcurl,
            report: false,
        }
    }
}

/// Runs all scenarios in one suite using default execution options.
pub fn run_suite_test(
    suite: &str,
    connector: Option<&str>,
) -> Result<SuiteRunSummary, ScenarioError> {
    run_suite_test_with_options(suite, connector, SuiteRunOptions::default())
}

/// Runs one specific scenario with explicit execution options.
pub fn run_scenario_test_with_options(
    suite: &str,
    scenario: &str,
    connector: Option<&str>,
    options: SuiteRunOptions<'_>,
) -> Result<SuiteRunSummary, ScenarioError> {
    let connector = connector.unwrap_or(DEFAULT_CONNECTOR);
    let target_suite_spec = load_suite_spec(suite)?;
    let scenarios = load_suite_scenarios(suite)?;

    if !scenarios.contains_key(scenario) {
        return Err(ScenarioError::ScenarioNotFound {
            suite: suite.to_string(),
            scenario: scenario.to_string(),
        });
    }

    let mut results = Vec::new();
    let mut passed = 0usize;
    let mut failed = 0usize;

    let dependency_chain = execute_dependency_chain(
        &target_suite_spec.depends_on,
        connector,
        options,
        target_suite_spec.strict_dependencies,
        &mut passed,
        &mut failed,
        &mut results,
    )?;

    let Some((dependency_reqs, dependency_res, dependency_labels, explicit_context_entries)) =
        dependency_chain
    else {
        return Ok(SuiteRunSummary {
            suite: suite.to_string(),
            connector: connector.to_string(),
            passed,
            failed,
            results,
        });
    };

    if should_skip_scenario_for_connector(connector, suite, scenario) {
        return Ok(SuiteRunSummary {
            suite: suite.to_string(),
            connector: connector.to_string(),
            passed,
            failed,
            results,
        });
    }

    match execute_single_scenario_with_context(
        suite,
        scenario,
        connector,
        options,
        &dependency_reqs,
        &dependency_res,
        &explicit_context_entries,
    ) {
        Ok(executed) => {
            match do_assertion(
                &executed.assertions,
                &executed.response_json,
                &executed.effective_req,
            ) {
                Ok(()) => {
                    passed += 1;
                    results.push(SuiteScenarioResult {
                        suite: suite.to_string(),
                        scenario: scenario.to_string(),
                        is_dependency: false,
                        passed: true,
                        error: None,
                        dependency: dependency_labels,
                        req_body: Some(executed.effective_req),
                        res_body: Some(executed.response_json),
                        grpc_request: executed.grpc_request,
                        grpc_response: executed.grpc_response,
                    });
                }
                Err(error) => {
                    failed += 1;
                    results.push(SuiteScenarioResult {
                        suite: suite.to_string(),
                        scenario: scenario.to_string(),
                        is_dependency: false,
                        passed: false,
                        error: Some(error.to_string()),
                        dependency: dependency_labels,
                        req_body: Some(executed.effective_req),
                        res_body: Some(executed.response_json),
                        grpc_request: executed.grpc_request,
                        grpc_response: executed.grpc_response,
                    });
                }
            }
        }
        Err(error) => {
            failed += 1;
            results.push(SuiteScenarioResult {
                suite: suite.to_string(),
                scenario: scenario.to_string(),
                is_dependency: false,
                passed: false,
                error: Some(error.to_string()),
                dependency: dependency_labels,
                req_body: None,
                res_body: None,
                grpc_request: None,
                grpc_response: None,
            });
        }
    }

    Ok(SuiteRunSummary {
        suite: suite.to_string(),
        connector: connector.to_string(),
        passed,
        failed,
        results,
    })
}

/// Runs all supported suites for one connector using default options.
pub fn run_all_suites(connector: Option<&str>) -> Result<AllSuitesRunSummary, ScenarioError> {
    run_all_suites_with_options(connector, SuiteRunOptions::default())
}

/// Runs all supported suites for one connector using explicit options.
pub fn run_all_suites_with_options(
    connector: Option<&str>,
    options: SuiteRunOptions<'_>,
) -> Result<AllSuitesRunSummary, ScenarioError> {
    let connector = connector.unwrap_or(DEFAULT_CONNECTOR);
    let supported_suites = load_supported_suites_for_connector(connector)?;

    let mut suite_summaries = Vec::new();
    let mut passed = 0usize;
    let mut failed = 0usize;

    for suite in supported_suites {
        let summary = run_suite_test_with_options(&suite, Some(connector), options)?;
        passed += summary.passed;
        failed += summary.failed;
        suite_summaries.push(summary);
    }

    Ok(AllSuitesRunSummary {
        connector: connector.to_string(),
        passed,
        failed,
        suites: suite_summaries,
    })
}

/// Runs all configured connectors using default options.
pub fn run_all_connectors() -> Result<AllConnectorsRunSummary, ScenarioError> {
    run_all_connectors_with_options(SuiteRunOptions::default())
}

/// Runs all configured connectors using explicit execution options.
pub fn run_all_connectors_with_options(
    options: SuiteRunOptions<'_>,
) -> Result<AllConnectorsRunSummary, ScenarioError> {
    let all_connectors = configured_all_connectors();
    let mut runnable_connectors = Vec::new();

    for connector in all_connectors {
        match load_connector_auth(&connector) {
            Ok(_) => runnable_connectors.push(connector),
            Err(error) => {
                eprintln!(
                    "[suite_run_test] skipping connector '{}' due to missing/invalid credentials: {}",
                    connector, error
                );
            }
        }
    }

    let mut connector_summaries = Vec::new();
    let mut passed = 0usize;
    let mut failed = 0usize;

    for connector in runnable_connectors {
        let summary = run_all_suites_with_options(Some(&connector), options)?;
        passed += summary.passed;
        failed += summary.failed;
        connector_summaries.push(summary);
    }

    Ok(AllConnectorsRunSummary {
        passed,
        failed,
        connectors: connector_summaries,
    })
}

/// Runs one suite with explicit execution options.
pub fn run_suite_test_with_options(
    suite: &str,
    connector: Option<&str>,
    options: SuiteRunOptions<'_>,
) -> Result<SuiteRunSummary, ScenarioError> {
    let connector = connector.unwrap_or(DEFAULT_CONNECTOR);
    let target_suite_spec = load_suite_spec(suite)?;
    let scenarios = load_suite_scenarios(suite)?;

    let mut results = Vec::new();
    let mut passed = 0usize;
    let mut failed = 0usize;

    match target_suite_spec.dependency_scope {
        DependencyScope::Suite => {
            let dependency_chain = execute_dependency_chain(
                &target_suite_spec.depends_on,
                connector,
                options,
                target_suite_spec.strict_dependencies,
                &mut passed,
                &mut failed,
                &mut results,
            )?;
            let Some((
                dependency_reqs,
                dependency_res,
                dependency_labels,
                explicit_context_entries,
            )) = dependency_chain
            else {
                return Ok(SuiteRunSummary {
                    suite: suite.to_string(),
                    connector: connector.to_string(),
                    passed,
                    failed,
                    results,
                });
            };

            for scenario in scenarios.keys() {
                if should_skip_scenario_for_connector(connector, suite, scenario) {
                    continue;
                }
                match execute_single_scenario_with_context(
                    suite,
                    scenario,
                    connector,
                    options,
                    &dependency_reqs,
                    &dependency_res,
                    &explicit_context_entries,
                ) {
                    Ok(executed) => {
                        if let Some(execution_error) = executed.execution_error.clone() {
                            failed += 1;
                            results.push(SuiteScenarioResult {
                                suite: suite.to_string(),
                                scenario: scenario.to_string(),
                                is_dependency: false,
                                passed: false,
                                error: Some(execution_error),
                                dependency: dependency_labels.clone(),
                                req_body: Some(executed.effective_req),
                                res_body: Some(executed.response_json),
                                grpc_request: executed.grpc_request,
                                grpc_response: executed.grpc_response,
                            });
                            continue;
                        }

                        match do_assertion(
                            &executed.assertions,
                            &executed.response_json,
                            &executed.effective_req,
                        ) {
                            Ok(()) => {
                                passed += 1;
                                results.push(SuiteScenarioResult {
                                    suite: suite.to_string(),
                                    scenario: scenario.to_string(),
                                    is_dependency: false,
                                    passed: true,
                                    error: None,
                                    dependency: dependency_labels.clone(),
                                    req_body: Some(executed.effective_req),
                                    res_body: Some(executed.response_json),
                                    grpc_request: executed.grpc_request,
                                    grpc_response: executed.grpc_response,
                                });
                            }
                            Err(error) => {
                                failed += 1;
                                results.push(SuiteScenarioResult {
                                    suite: suite.to_string(),
                                    scenario: scenario.to_string(),
                                    is_dependency: false,
                                    passed: false,
                                    error: Some(error.to_string()),
                                    dependency: dependency_labels.clone(),
                                    req_body: Some(executed.effective_req),
                                    res_body: Some(executed.response_json),
                                    grpc_request: executed.grpc_request,
                                    grpc_response: executed.grpc_response,
                                });
                            }
                        }
                    }
                    Err(error) => {
                        failed += 1;
                        results.push(SuiteScenarioResult {
                            suite: suite.to_string(),
                            scenario: scenario.to_string(),
                            is_dependency: false,
                            passed: false,
                            error: Some(error.to_string()),
                            dependency: dependency_labels.clone(),
                            req_body: None,
                            res_body: None,
                            grpc_request: None,
                            grpc_response: None,
                        });
                    }
                }
            }
        }
        DependencyScope::Scenario => {
            for scenario in scenarios.keys() {
                if should_skip_scenario_for_connector(connector, suite, scenario) {
                    continue;
                }
                let dependency_chain = execute_dependency_chain(
                    &target_suite_spec.depends_on,
                    connector,
                    options,
                    target_suite_spec.strict_dependencies,
                    &mut passed,
                    &mut failed,
                    &mut results,
                )?;
                let Some((
                    dependency_reqs,
                    dependency_res,
                    dependency_labels,
                    explicit_context_entries,
                )) = dependency_chain
                else {
                    return Ok(SuiteRunSummary {
                        suite: suite.to_string(),
                        connector: connector.to_string(),
                        passed,
                        failed,
                        results,
                    });
                };

                match execute_single_scenario_with_context(
                    suite,
                    scenario,
                    connector,
                    options,
                    &dependency_reqs,
                    &dependency_res,
                    &explicit_context_entries,
                ) {
                    Ok(executed) => {
                        if let Some(execution_error) = executed.execution_error.clone() {
                            failed += 1;
                            results.push(SuiteScenarioResult {
                                suite: suite.to_string(),
                                scenario: scenario.to_string(),
                                is_dependency: false,
                                passed: false,
                                error: Some(execution_error),
                                dependency: dependency_labels,
                                req_body: Some(executed.effective_req),
                                res_body: Some(executed.response_json),
                                grpc_request: executed.grpc_request,
                                grpc_response: executed.grpc_response,
                            });
                            continue;
                        }

                        match do_assertion(
                            &executed.assertions,
                            &executed.response_json,
                            &executed.effective_req,
                        ) {
                            Ok(()) => {
                                passed += 1;
                                results.push(SuiteScenarioResult {
                                    suite: suite.to_string(),
                                    scenario: scenario.to_string(),
                                    is_dependency: false,
                                    passed: true,
                                    error: None,
                                    dependency: dependency_labels,
                                    req_body: Some(executed.effective_req),
                                    res_body: Some(executed.response_json),
                                    grpc_request: executed.grpc_request,
                                    grpc_response: executed.grpc_response,
                                });
                            }
                            Err(error) => {
                                failed += 1;
                                results.push(SuiteScenarioResult {
                                    suite: suite.to_string(),
                                    scenario: scenario.to_string(),
                                    is_dependency: false,
                                    passed: false,
                                    error: Some(error.to_string()),
                                    dependency: dependency_labels,
                                    req_body: Some(executed.effective_req),
                                    res_body: Some(executed.response_json),
                                    grpc_request: executed.grpc_request,
                                    grpc_response: executed.grpc_response,
                                });
                            }
                        }
                    }
                    Err(error) => {
                        failed += 1;
                        results.push(SuiteScenarioResult {
                            suite: suite.to_string(),
                            scenario: scenario.to_string(),
                            is_dependency: false,
                            passed: false,
                            error: Some(error.to_string()),
                            dependency: dependency_labels,
                            req_body: None,
                            res_body: None,
                            grpc_request: None,
                            grpc_response: None,
                        });
                    }
                }
            }
        }
    }

    Ok(SuiteRunSummary {
        suite: suite.to_string(),
        connector: connector.to_string(),
        passed,
        failed,
        results,
    })
}

fn execute_dependency_chain(
    dependencies: &[SuiteDependency],
    connector: &str,
    options: SuiteRunOptions<'_>,
    strict_dependencies: bool,
    passed: &mut usize,
    failed: &mut usize,
    results: &mut Vec<SuiteScenarioResult>,
) -> Result<Option<DependencyContext>, ScenarioError> {
    let mut dependency_reqs = Vec::new();
    let mut dependency_res = Vec::new();
    let mut dependency_labels = Vec::new();
    let mut explicit_context_entries = Vec::new();

    for dependency in dependencies {
        let dependency_suite = dependency.suite();
        let is_supported = is_suite_supported_for_connector(connector, dependency_suite)?;
        if !is_supported {
            continue;
        }

        let dependency_scenario = if let Some(scenario) = dependency.scenario() {
            scenario.to_string()
        } else {
            load_default_scenario_name(dependency_suite)?
        };
        let current_label = dependency_label(dependency_suite, &dependency_scenario);

        if should_skip_scenario_for_connector(connector, dependency_suite, &dependency_scenario) {
            continue;
        }

        let dep_result = execute_single_scenario_with_context(
            dependency_suite,
            &dependency_scenario,
            connector,
            options,
            &dependency_reqs,
            &dependency_res,
            &[],
        );

        match dep_result {
            Ok(executed) => {
                if let Some(execution_error) = executed.execution_error.clone() {
                    *failed += 1;
                    results.push(SuiteScenarioResult {
                        suite: dependency_suite.to_string(),
                        scenario: dependency_scenario,
                        is_dependency: true,
                        passed: false,
                        error: Some(execution_error),
                        dependency: dependency_labels.clone(),
                        req_body: Some(executed.effective_req),
                        res_body: Some(executed.response_json),
                        grpc_request: executed.grpc_request,
                        grpc_response: executed.grpc_response,
                    });
                    dependency_labels.push(current_label);

                    if strict_dependencies {
                        return Ok(None);
                    }
                    continue;
                }

                match do_assertion(
                    &executed.assertions,
                    &executed.response_json,
                    &executed.effective_req,
                ) {
                    Ok(()) => {
                        *passed += 1;
                        if let Some(context_map) = dependency.context_map() {
                            if !context_map.is_empty() {
                                explicit_context_entries.push((
                                    context_map.clone(),
                                    executed.effective_req.clone(),
                                    executed.response_json.clone(),
                                ));
                            }
                        }
                        dependency_reqs.push(executed.effective_req.clone());
                        dependency_res.push(executed.response_json.clone());
                        results.push(SuiteScenarioResult {
                            suite: dependency_suite.to_string(),
                            scenario: dependency_scenario,
                            is_dependency: true,
                            passed: true,
                            error: None,
                            dependency: dependency_labels.clone(),
                            req_body: Some(executed.effective_req),
                            res_body: Some(executed.response_json),
                            grpc_request: executed.grpc_request,
                            grpc_response: executed.grpc_response,
                        });
                        dependency_labels.push(current_label);
                    }
                    Err(error) => {
                        *failed += 1;
                        results.push(SuiteScenarioResult {
                            suite: dependency_suite.to_string(),
                            scenario: dependency_scenario,
                            is_dependency: true,
                            passed: false,
                            error: Some(error.to_string()),
                            dependency: dependency_labels.clone(),
                            req_body: Some(executed.effective_req),
                            res_body: Some(executed.response_json),
                            grpc_request: executed.grpc_request,
                            grpc_response: executed.grpc_response,
                        });
                        dependency_labels.push(current_label);

                        if strict_dependencies {
                            return Ok(None);
                        }
                    }
                }
            }
            Err(error) => {
                *failed += 1;
                results.push(SuiteScenarioResult {
                    suite: dependency_suite.to_string(),
                    scenario: dependency_scenario,
                    is_dependency: true,
                    passed: false,
                    error: Some(error.to_string()),
                    dependency: dependency_labels.clone(),
                    req_body: None,
                    res_body: None,
                    grpc_request: None,
                    grpc_response: None,
                });
                dependency_labels.push(current_label);

                if strict_dependencies {
                    return Ok(None);
                }
            }
        }
    }

    Ok(Some((
        dependency_reqs,
        dependency_res,
        dependency_labels,
        explicit_context_entries,
    )))
}

#[allow(clippy::print_stdout)]
fn execute_single_scenario_with_context(
    suite: &str,
    scenario: &str,
    connector: &str,
    options: SuiteRunOptions<'_>,
    dependency_reqs: &[Value],
    dependency_res: &[Value],
    explicit_context_entries: &[ExplicitContextEntry],
) -> Result<ExecutedScenario, ScenarioError> {
    run_test(Some(suite), Some(scenario), Some(connector))?;

    let (mut effective_req, assertions) =
        load_effective_scenario_for_connector(suite, scenario, connector)?;

    // Normalize legacy empty placeholders to auto_generate sentinels where needed.
    prepare_context_placeholders(suite, connector, &mut effective_req);

    // Context first.
    add_context(dependency_reqs, dependency_res, &mut effective_req);

    // Apply any explicit dependency path mappings from suite_spec.json.
    apply_context_map(explicit_context_entries, &mut effective_req);

    // Fallback generation for unresolved non-context placeholders.
    resolve_auto_generate(&mut effective_req)?;

    // Drop unresolved context-only fields instead of sending invalid placeholders.
    prune_unresolved_context_fields(connector, &mut effective_req);

    if std::env::var("UCS_DEBUG_EFFECTIVE_REQ").as_deref() == Ok("1") {
        if let Ok(request_json) = serde_json::to_string_pretty(&effective_req) {
            println!(
                "[suite_run_test] effective_grpc_req suite={suite} scenario={scenario}:\n{request_json}"
            );
        }
    }

    let (response, grpc_request, grpc_response) = match options.backend {
        ExecutionBackend::Grpcurl => {
            let trace = execute_grpcurl_request_from_payload_with_trace(
                suite,
                scenario,
                &effective_req,
                options.endpoint,
                Some(connector),
                options.merchant_id,
                options.tenant_id,
                options.plaintext,
            )?;

            if !trace.success {
                let response_output = trace.response_output;
                let response_json = serde_json::from_str::<Value>(&trace.response_body)
                    .unwrap_or_else(|_| {
                        serde_json::json!({
                            "raw_response": response_output.clone(),
                        })
                    });

                return Ok(ExecutedScenario {
                    effective_req,
                    response_json,
                    assertions,
                    grpc_request: Some(trace.request_command),
                    grpc_response: Some(response_output.clone()),
                    execution_error: Some(response_output),
                });
            }

            (
                trace.response_body,
                Some(trace.request_command),
                Some(trace.response_output),
            )
        }
        ExecutionBackend::SdkFfi => (
            execute_sdk_request_from_payload(suite, scenario, &effective_req, connector)?,
            None,
            None,
        ),
    };

    let mut response_json: Value = serde_json::from_str(&response).map_err(|error| {
        let mut message = format!("failed to parse grpc response JSON: {error}");
        if let Some(trace) = grpc_response.as_deref() {
            message.push_str("\n\n");
            message.push_str(trace);
        }
        ScenarioError::GrpcurlExecution { message }
    })?;

    transform_response_for_connector(connector, suite, scenario, &mut response_json);

    Ok(ExecutedScenario {
        effective_req,
        response_json,
        assertions,
        grpc_request,
        grpc_response,
        execution_error: None,
    })
}

fn grpc_method_for_suite(suite: &str) -> Result<&'static str, ScenarioError> {
    match suite {
        "create_access_token" => Ok("types.MerchantAuthenticationService/CreateAccessToken"),
        "create_customer" => Ok("types.CustomerService/Create"),
        "authorize" => Ok("types.PaymentService/Authorize"),
        "capture" => Ok("types.PaymentService/Capture"),
        "refund" => Ok("types.PaymentService/Refund"),
        "void" => Ok("types.PaymentService/Void"),
        "get" => Ok("types.PaymentService/Get"),
        "refund_sync" => Ok("types.RefundService/Get"),
        "setup_recurring" => Ok("types.PaymentService/SetupRecurring"),
        "recurring_charge" => Ok("types.RecurringPaymentService/Charge"),
        _ => Err(ScenarioError::UnsupportedSuite {
            suite: suite.to_string(),
        }),
    }
}

fn auth_headers(auth: &ConnectorAuth) -> Vec<String> {
    match auth {
        ConnectorAuth::HeaderKey { api_key } => vec![
            "x-auth: header-key".to_string(),
            format!("x-api-key: {api_key}"),
        ],
        ConnectorAuth::BodyKey { api_key, key1 } => vec![
            "x-auth: body-key".to_string(),
            format!("x-api-key: {api_key}"),
            format!("x-key1: {key1}"),
        ],
        ConnectorAuth::SignatureKey {
            api_key,
            key1,
            api_secret,
        } => vec![
            "x-auth: signature-key".to_string(),
            format!("x-api-key: {api_key}"),
            format!("x-key1: {key1}"),
            format!("x-api-secret: {api_secret}"),
        ],
    }
}
