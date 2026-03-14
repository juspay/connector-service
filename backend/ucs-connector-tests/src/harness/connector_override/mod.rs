use std::collections::BTreeMap;

use serde_json::Value;

use crate::harness::scenario_types::{FieldAssert, ScenarioError};

mod default;
pub mod json_merge;
pub mod loader;

/// Connector-specific behavior extension points.
///
/// The default implementation is file-driven via JSON patches, but this trait
/// also allows richer connector logic (request normalization, response shaping,
/// scenario skipping, and deferred context paths).
pub trait ConnectorOverride: Send + Sync {
    fn connector_name(&self) -> &str;

    fn apply_overrides(
        &self,
        suite: &str,
        scenario: &str,
        grpc_req: &mut Value,
        assertions: &mut BTreeMap<String, FieldAssert>,
    ) -> Result<(), ScenarioError> {
        let Some(scenario_patch) =
            loader::load_scenario_override_patch(self.connector_name(), suite, scenario)?
        else {
            return Ok(());
        };

        if let Some(req_patch) = scenario_patch.grpc_req.as_ref() {
            json_merge::json_merge_patch(grpc_req, req_patch);
        }

        if let Some(assertion_patch) = scenario_patch.assert_rules.as_ref() {
            apply_assertion_patch(assertions, assertion_patch)?;
        }

        Ok(())
    }

    fn normalize_tonic_request(&self, _suite: &str, _scenario: &str, _req: &mut Value) {}

    fn transform_response(&self, _suite: &str, _scenario: &str, _response: &mut Value) {}

    fn should_skip_scenario(&self, _suite: &str, _scenario: &str) -> bool {
        false
    }

    fn extra_context_deferred_paths(&self) -> Vec<String> {
        Vec::new()
    }
}

/// Minimal registry wrapper used to resolve override strategy by connector.
#[derive(Debug, Default)]
pub struct OverrideRegistry;

impl OverrideRegistry {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Returns currently configured strategy for a connector.
    ///
    /// At the moment all connectors use the default file-backed strategy.
    pub fn resolve(&self, connector: &str) -> Box<dyn ConnectorOverride> {
        Box::new(default::DefaultConnectorOverride::new(
            connector.to_string(),
        ))
    }
}

/// Applies connector override patches to request payload and assertions.
pub fn apply_connector_overrides(
    connector: &str,
    suite: &str,
    scenario: &str,
    grpc_req: &mut Value,
    assertions: &mut BTreeMap<String, FieldAssert>,
) -> Result<(), ScenarioError> {
    let strategy = OverrideRegistry::new().resolve(connector);
    strategy.apply_overrides(suite, scenario, grpc_req, assertions)
}

/// Applies optional connector-level request normalization before tonic decoding.
pub fn normalize_tonic_request_for_connector(
    connector: &str,
    suite: &str,
    scenario: &str,
    grpc_req: &mut Value,
) {
    let strategy = OverrideRegistry::new().resolve(connector);
    strategy.normalize_tonic_request(suite, scenario, grpc_req);
}

/// Applies optional connector-level response normalization before assertions.
pub fn transform_response_for_connector(
    connector: &str,
    suite: &str,
    scenario: &str,
    response: &mut Value,
) {
    let strategy = OverrideRegistry::new().resolve(connector);
    strategy.transform_response(suite, scenario, response);
}

/// Returns whether a scenario should be skipped for a connector.
pub fn should_skip_scenario_for_connector(connector: &str, suite: &str, scenario: &str) -> bool {
    let strategy = OverrideRegistry::new().resolve(connector);
    strategy.should_skip_scenario(suite, scenario)
}

/// Returns request paths that should defer auto-generation until dependency
/// context propagation.
pub fn context_deferred_paths_for_connector(connector: &str) -> Vec<String> {
    let strategy = OverrideRegistry::new().resolve(connector);
    strategy.extra_context_deferred_paths()
}

/// Merges assertion patches:
/// - `null` removes a rule
/// - object value replaces/adds a rule
pub fn apply_assertion_patch(
    assertions: &mut BTreeMap<String, FieldAssert>,
    assertion_patch: &BTreeMap<String, Value>,
) -> Result<(), ScenarioError> {
    for (field, patch_value) in assertion_patch {
        if patch_value.is_null() {
            assertions.remove(field);
            continue;
        }

        let patched_rule =
            serde_json::from_value::<FieldAssert>(patch_value.clone()).map_err(|source| {
                ScenarioError::InvalidAssertionRule {
                    field: field.clone(),
                    message: format!(
                        "invalid connector override assertion patch for field '{field}': {source}"
                    ),
                }
            })?;
        assertions.insert(field.clone(), patched_rule);
    }

    Ok(())
}