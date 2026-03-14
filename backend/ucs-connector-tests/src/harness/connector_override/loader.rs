use std::{collections::BTreeMap, fs, path::PathBuf};

use serde::Deserialize;
use serde_json::Value;

use crate::harness::{scenario_loader::connector_specs_root, scenario_types::ScenarioError};

/// Override patch payload for one specific `(suite, scenario)` pair.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ScenarioOverridePatch {
    #[serde(default)]
    pub grpc_req: Option<Value>,
    #[serde(rename = "assert", default)]
    pub assert_rules: Option<BTreeMap<String, Value>>,
}

type SuiteOverrideFile = BTreeMap<String, ScenarioOverridePatch>;
type ConnectorOverrideFile = BTreeMap<String, SuiteOverrideFile>;

/// Path to `<connector>/override.json` under connector override root.
pub fn connector_override_file_path(connector: &str) -> PathBuf {
    connector_override_root()
        .join(connector)
        .join("override.json")
}

/// Override root path, configurable independently from connector specs root.
fn connector_override_root() -> PathBuf {
    std::env::var("UCS_CONNECTOR_OVERRIDE_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| connector_specs_root())
}

/// Legacy path used by older suite-level override file layouts.
fn legacy_connector_suite_override_file_path(connector: &str, suite: &str) -> PathBuf {
    connector_override_root()
        .join(connector)
        .join("overrides")
        .join(format!("{suite}.overrides.json"))
}

/// Loads optional override patch for one connector/suite/scenario.
///
/// Resolution order:
/// 1. New unified connector override file (`<connector>/override.json`)
/// 2. Legacy suite-level override file (`<connector>/overrides/<suite>.overrides.json`)
pub fn load_scenario_override_patch(
    connector: &str,
    suite: &str,
    scenario: &str,
) -> Result<Option<ScenarioOverridePatch>, ScenarioError> {
    if let Some(connector_patch) = load_connector_override_file(connector)? {
        return Ok(connector_patch
            .get(suite)
            .and_then(|suite_patch| suite_patch.get(scenario))
            .cloned());
    }

    // Backward-compatible fallback for suite-level override files.
    if let Some(suite_patch) = load_legacy_suite_override_file(connector, suite)? {
        return Ok(suite_patch.get(scenario).cloned());
    }

    Ok(None)
}

/// Loads and parses the unified connector override file if present.
fn load_connector_override_file(
    connector: &str,
) -> Result<Option<ConnectorOverrideFile>, ScenarioError> {
    let path = connector_override_file_path(connector);
    if !path.exists() {
        return Ok(None);
    }

    let content =
        fs::read_to_string(&path).map_err(|source| ScenarioError::ConnectorOverrideRead {
            path: path.clone(),
            source,
        })?;

    let parsed = serde_json::from_str::<ConnectorOverrideFile>(&content).map_err(|source| {
        ScenarioError::ConnectorOverrideParse {
            path: path.clone(),
            source,
        }
    })?;

    Ok(Some(parsed))
}

/// Loads and parses legacy suite override file if present.
fn load_legacy_suite_override_file(
    connector: &str,
    suite: &str,
) -> Result<Option<SuiteOverrideFile>, ScenarioError> {
    let path = legacy_connector_suite_override_file_path(connector, suite);
    if !path.exists() {
        return Ok(None);
    }

    let content =
        fs::read_to_string(&path).map_err(|source| ScenarioError::ConnectorOverrideRead {
            path: path.clone(),
            source,
        })?;

    let parsed = serde_json::from_str::<SuiteOverrideFile>(&content).map_err(|source| {
        ScenarioError::ConnectorOverrideParse {
            path: path.clone(),
            source,
        }
    })?;

    Ok(Some(parsed))
}