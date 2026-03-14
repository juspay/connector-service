use std::{collections::BTreeSet, fs, path::PathBuf};

use serde_json::Value;

use crate::harness::scenario_types::{
    ConnectorSuiteSpec, FieldAssert, ScenarioDef, ScenarioError, ScenarioFile, SuiteSpec,
};

/// Fallback connector set used by `--all-connectors` when env override is not set.
const ALL_CONNECTORS_RUN_LIST: &[&str] = &["authorizedotnet", "paypal", "stripe"];

/// Root directory containing `<suite>_suite/scenario.json` and `suite_spec.json`.
pub fn scenario_root() -> PathBuf {
    std::env::var("UCS_SCENARIO_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/global_suites"))
}

/// Root directory containing per-connector `specs.json` and `override.json`.
pub fn connector_specs_root() -> PathBuf {
    std::env::var("UCS_CONNECTOR_SPECS_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            scenario_root()
                .parent()
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src"))
                .join("connector_specs")
        })
}

/// Connector-specific directory under `connector_specs/`.
pub fn connector_spec_dir(connector: &str) -> PathBuf {
    connector_specs_root().join(connector)
}

/// Absolute path to the suite scenario file.
pub fn scenario_file_path(suite: &str) -> PathBuf {
    scenario_root()
        .join(format!("{suite}_suite"))
        .join("scenario.json")
}

/// Absolute path to the suite specification file.
pub fn suite_spec_file_path(suite: &str) -> PathBuf {
    scenario_root()
        .join(format!("{suite}_suite"))
        .join("suite_spec.json")
}

/// Resolves connector spec path, preferring `<connector>/specs.json` and falling
/// back to legacy `<connector>.json` location.
pub fn connector_spec_file_path(connector: &str) -> PathBuf {
    let directory_spec_path = connector_spec_dir(connector).join("specs.json");
    if directory_spec_path.exists() {
        directory_spec_path
    } else {
        connector_specs_root().join(format!("{connector}.json"))
    }
}

/// Loads all scenarios for a suite from `scenario.json`.
pub fn load_suite_scenarios(suite: &str) -> Result<ScenarioFile, ScenarioError> {
    let path = scenario_file_path(suite);
    let content = fs::read_to_string(&path).map_err(|source| ScenarioError::ScenarioFileRead {
        path: path.clone(),
        source,
    })?;

    serde_json::from_str::<ScenarioFile>(&content)
        .map_err(|source| ScenarioError::ScenarioFileParse { path, source })
}

/// Loads one named scenario definition from the suite file.
pub fn load_scenario(suite: &str, scenario: &str) -> Result<ScenarioDef, ScenarioError> {
    load_suite_scenarios(suite)?
        .get(scenario)
        .cloned()
        .ok_or_else(|| ScenarioError::ScenarioNotFound {
            suite: suite.to_string(),
            scenario: scenario.to_string(),
        })
}

/// Loads suite execution metadata including dependency graph and scope.
pub fn load_suite_spec(suite: &str) -> Result<SuiteSpec, ScenarioError> {
    let path = suite_spec_file_path(suite);
    if !path.exists() {
        return Err(ScenarioError::SuiteSpecMissing { path });
    }

    let content = fs::read_to_string(&path).map_err(|source| ScenarioError::SuiteSpecRead {
        path: path.clone(),
        source,
    })?;

    serde_json::from_str::<SuiteSpec>(&content)
        .map_err(|source| ScenarioError::SuiteSpecParse { path, source })
}

/// Returns the unique default scenario name for a suite.
pub fn load_default_scenario_name(suite: &str) -> Result<String, ScenarioError> {
    let scenarios = load_suite_scenarios(suite)?;
    let defaults = scenarios
        .iter()
        .filter_map(|(name, def)| def.is_default.then_some(name.clone()))
        .collect::<Vec<_>>();

    match defaults.as_slice() {
        [] => Err(ScenarioError::DefaultScenarioMissing {
            suite: suite.to_string(),
        }),
        [single] => Ok(single.clone()),
        _ => Err(ScenarioError::MultipleDefaultScenarios {
            suite: suite.to_string(),
            scenarios: defaults.join(", "),
        }),
    }
}

/// Checks whether a connector explicitly supports a suite.
///
/// If connector specs are absent, this falls back to checking suite presence on disk.
pub fn is_suite_supported_for_connector(
    connector: &str,
    suite: &str,
) -> Result<bool, ScenarioError> {
    let path = connector_spec_file_path(connector);
    if path.exists() {
        let content =
            fs::read_to_string(&path).map_err(|source| ScenarioError::ConnectorSpecRead {
                path: path.clone(),
                source,
            })?;
        let spec = serde_json::from_str::<ConnectorSuiteSpec>(&content).map_err(|source| {
            ScenarioError::ConnectorSpecParse {
                path: path.clone(),
                source,
            }
        })?;
        return Ok(spec
            .supported_suites
            .iter()
            .any(|supported| supported == suite));
    }

    Ok(scenario_file_path(suite).exists())
}

/// Lists all suites supported by a connector, preserving order from connector
/// spec and removing duplicates.
pub fn load_supported_suites_for_connector(connector: &str) -> Result<Vec<String>, ScenarioError> {
    let path = connector_spec_file_path(connector);
    if path.exists() {
        let content =
            fs::read_to_string(&path).map_err(|source| ScenarioError::ConnectorSpecRead {
                path: path.clone(),
                source,
            })?;
        let spec = serde_json::from_str::<ConnectorSuiteSpec>(&content).map_err(|source| {
            ScenarioError::ConnectorSpecParse {
                path: path.clone(),
                source,
            }
        })?;

        let mut suites = Vec::new();
        for suite in spec.supported_suites {
            if !suites.contains(&suite) {
                suites.push(suite);
            }
        }
        return Ok(suites);
    }

    let mut suites = BTreeSet::new();
    for entry in
        fs::read_dir(scenario_root()).map_err(|source| ScenarioError::ScenarioFileRead {
            path: scenario_root(),
            source,
        })?
    {
        let entry = entry.map_err(|source| ScenarioError::ScenarioFileRead {
            path: scenario_root(),
            source,
        })?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        let Some(dir_name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !dir_name.ends_with("_suite") {
            continue;
        }
        if !path.join("scenario.json").exists() {
            continue;
        }

        suites.insert(dir_name.trim_end_matches("_suite").to_string());
    }

    Ok(suites.into_iter().collect())
}

/// Discovers connector names by scanning `connector_specs/`.
pub fn discover_all_connectors() -> Result<Vec<String>, ScenarioError> {
    let specs_dir = connector_specs_root();

    if !specs_dir.exists() {
        return Ok(Vec::new());
    }

    let mut connectors = BTreeSet::new();
    for entry in fs::read_dir(&specs_dir).map_err(|source| ScenarioError::ScenarioFileRead {
        path: specs_dir.clone(),
        source,
    })? {
        let entry = entry.map_err(|source| ScenarioError::ScenarioFileRead {
            path: specs_dir.clone(),
            source,
        })?;
        let path = entry.path();

        if path.is_dir() {
            let has_specs_file = path.join("specs.json").is_file();
            if has_specs_file {
                if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
                    connectors.insert(name.to_string());
                }
            }
            continue;
        }

        if !path.is_file() {
            continue;
        }

        let Some(name) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        let Some(ext) = path.extension().and_then(|s| s.to_str()) else {
            continue;
        };
        if ext == "json" {
            connectors.insert(name.to_string());
        }
    }

    Ok(connectors.into_iter().collect())
}

/// Resolves connector list for all-connector runs.
///
/// Environment override format: `UCS_ALL_CONNECTORS=stripe,paypal,authorizedotnet`.
pub fn configured_all_connectors() -> Vec<String> {
    if let Ok(raw) = std::env::var("UCS_ALL_CONNECTORS") {
        let connectors = raw
            .split(',')
            .map(str::trim)
            .filter(|connector| !connector.is_empty())
            .map(ToString::to_string)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();

        if !connectors.is_empty() {
            return connectors;
        }
    }

    ALL_CONNECTORS_RUN_LIST
        .iter()
        .map(|connector| connector.to_string())
        .collect()
}

/// Convenience accessor used by runners to load request template JSON.
pub fn get_the_grpc_req(suite: &str, scenario: &str) -> Result<Value, ScenarioError> {
    Ok(load_scenario(suite, scenario)?.grpc_req)
}

/// Convenience accessor used by runners to load assertion rules.
pub fn get_the_assertion(
    suite: &str,
    scenario: &str,
) -> Result<std::collections::BTreeMap<String, FieldAssert>, ScenarioError> {
    Ok(load_scenario(suite, scenario)?.assert_rules)
}
