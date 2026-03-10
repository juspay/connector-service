use std::{collections::BTreeSet, fs, path::PathBuf};

use serde_json::Value;

use crate::harness::scenario_types::{
    ConnectorSuiteSpec, FieldAssert, ScenarioDef, ScenarioError, ScenarioFile, SuiteSpec,
};

const ALL_CONNECTORS_RUN_LIST: &[&str] = &["authorizedotnet", "paypal", "stripe"];

pub fn scenario_root() -> PathBuf {
    std::env::var("UCS_SCENARIO_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/global_suites"))
}

pub fn scenario_file_path(suite: &str) -> PathBuf {
    scenario_root()
        .join(format!("{suite}_suite"))
        .join("scenario.json")
}

pub fn suite_spec_file_path(suite: &str) -> PathBuf {
    scenario_root()
        .join(format!("{suite}_suite"))
        .join("suite_spec.json")
}

pub fn connector_spec_file_path(connector: &str) -> PathBuf {
    scenario_root()
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src"))
        .join("connector_specs")
        .join(format!("{connector}.json"))
}

pub fn load_suite_scenarios(suite: &str) -> Result<ScenarioFile, ScenarioError> {
    let path = scenario_file_path(suite);
    let content = fs::read_to_string(&path).map_err(|source| ScenarioError::ScenarioFileRead {
        path: path.clone(),
        source,
    })?;

    serde_json::from_str::<ScenarioFile>(&content)
        .map_err(|source| ScenarioError::ScenarioFileParse { path, source })
}

pub fn load_scenario(suite: &str, scenario: &str) -> Result<ScenarioDef, ScenarioError> {
    load_suite_scenarios(suite)?
        .get(scenario)
        .cloned()
        .ok_or_else(|| ScenarioError::ScenarioNotFound {
            suite: suite.to_string(),
            scenario: scenario.to_string(),
        })
}

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

pub fn discover_all_connectors() -> Result<Vec<String>, ScenarioError> {
    let specs_dir = connector_spec_file_path("_dummy")
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("src")
                .join("connector_specs")
        });

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
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        let Some(ext) = path.extension().and_then(|s| s.to_str()) else {
            continue;
        };
        if ext != "json" {
            continue;
        }
        connectors.insert(name.to_string());
    }

    Ok(connectors.into_iter().collect())
}

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

pub fn get_the_grpc_req(suite: &str, scenario: &str) -> Result<Value, ScenarioError> {
    Ok(load_scenario(suite, scenario)?.grpc_req)
}

pub fn get_the_assertion(
    suite: &str,
    scenario: &str,
) -> Result<std::collections::BTreeMap<String, FieldAssert>, ScenarioError> {
    Ok(load_scenario(suite, scenario)?.assert_rules)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::harness::scenario_types::DependencyScope;

    use crate::harness::scenario_loader::{
        configured_all_connectors, discover_all_connectors, get_the_assertion, get_the_grpc_req,
        load_scenario, load_suite_scenarios, load_suite_spec, load_supported_suites_for_connector,
        scenario_root,
    };

    fn discover_suites() -> Vec<String> {
        fs::read_dir(scenario_root())
            .expect("scenario root should be readable")
            .filter_map(Result::ok)
            .filter(|entry| entry.path().is_dir())
            .filter_map(|entry| {
                let path = entry.path();
                let has_scenario_file = path.join("scenario.json").is_file();
                let dir_name = path.file_name()?.to_str()?;
                if !has_scenario_file || !dir_name.ends_with("_suite") {
                    return None;
                }
                Some(dir_name.trim_end_matches("_suite").to_string())
            })
            .collect()
    }

    #[test]
    fn can_load_any_scenario_by_name_if_present() {
        let suites = discover_suites();
        assert!(!suites.is_empty(), "at least one suite should exist");

        for suite in suites {
            let scenarios =
                load_suite_scenarios(&suite).expect("suite scenarios should be readable");
            assert!(
                !scenarios.is_empty(),
                "suite '{suite}' should contain at least one scenario"
            );

            for scenario_name in scenarios.keys() {
                let scenario =
                    load_scenario(&suite, scenario_name).expect("scenario should be loadable");
                assert!(
                    scenario.grpc_req.is_object(),
                    "scenario '{scenario_name}' in suite '{suite}' should have object grpc_req"
                );
                assert!(
                    !scenario.assert_rules.is_empty(),
                    "scenario '{scenario_name}' in suite '{suite}' should have assertion rules"
                );
            }
        }
    }

    #[test]
    fn can_get_grpc_req_and_assertions_for_any_existing_scenario() {
        let suites = discover_suites();
        assert!(!suites.is_empty(), "at least one suite should exist");

        for suite in suites {
            let scenarios =
                load_suite_scenarios(&suite).expect("suite scenarios should be readable");
            for scenario_name in scenarios.keys() {
                let req = get_the_grpc_req(&suite, scenario_name)
                    .expect("grpc request should be available for scenario");
                let assertions = get_the_assertion(&suite, scenario_name)
                    .expect("assertions should be available for scenario");

                assert!(
                    req.is_object(),
                    "grpc_req should be object for '{suite}/{scenario_name}'"
                );
                assert!(
                    !assertions.is_empty(),
                    "assertions should be present for '{suite}/{scenario_name}'"
                );
            }
        }
    }

    #[test]
    fn can_load_suite_specs_for_all_suites() {
        let suites = discover_suites();
        assert!(!suites.is_empty(), "at least one suite should exist");

        for suite in suites {
            let spec = load_suite_spec(&suite).expect("suite spec should be readable");
            assert_eq!(
                spec.suite, suite,
                "suite spec name should match folder name"
            );
            for dependency in &spec.depends_on {
                let dependency_suite = dependency.suite();
                assert!(
                    !dependency_suite.is_empty(),
                    "dependency suite name should not be empty"
                );

                if let Some(dependency_scenario) = dependency.scenario() {
                    load_scenario(dependency_suite, dependency_scenario)
                        .expect("dependency override scenario should exist");
                }
            }
        }
    }

    #[test]
    fn dependency_scope_defaults_and_overrides_are_loaded() {
        let authorize_spec = load_suite_spec("authorize").expect("authorize spec should load");
        assert_eq!(authorize_spec.dependency_scope, DependencyScope::Suite);

        for suite in ["capture", "void", "refund", "get", "refund_sync"] {
            let spec = load_suite_spec(suite).expect("suite spec should load");
            assert_eq!(
                spec.dependency_scope,
                DependencyScope::Scenario,
                "suite '{suite}' should run dependencies per scenario"
            );
        }
    }

    #[test]
    fn can_load_supported_suites_for_known_connector() {
        let suites = load_supported_suites_for_connector("stripe")
            .expect("supported suites should load for stripe connector");
        assert!(
            suites.iter().any(|suite| suite == "authorize"),
            "stripe should support authorize suite"
        );
    }

    #[test]
    fn can_discover_all_connectors() {
        let connectors =
            discover_all_connectors().expect("should discover connectors from connector_specs/");
        assert!(
            !connectors.is_empty(),
            "at least one connector spec should exist"
        );
        assert!(
            connectors.iter().any(|c| c == "stripe"),
            "stripe connector spec should be discoverable"
        );
        // Should be sorted
        let mut sorted = connectors.clone();
        sorted.sort();
        assert_eq!(connectors, sorted, "connectors should be sorted");
    }

    #[test]
    fn configured_connectors_defaults_to_static_run_list() {
        let previous = std::env::var("UCS_ALL_CONNECTORS").ok();
        std::env::remove_var("UCS_ALL_CONNECTORS");

        let connectors = configured_all_connectors();

        match previous {
            Some(value) => std::env::set_var("UCS_ALL_CONNECTORS", value),
            None => std::env::remove_var("UCS_ALL_CONNECTORS"),
        }

        assert!(connectors.iter().any(|connector| connector == "stripe"));
        assert!(connectors
            .iter()
            .any(|connector| connector == "authorizedotnet"));
        assert!(connectors.iter().any(|connector| connector == "paypal"));
        assert!(!connectors.is_empty());
    }

    #[test]
    fn configured_connectors_supports_env_override() {
        let previous = std::env::var("UCS_ALL_CONNECTORS").ok();
        std::env::set_var("UCS_ALL_CONNECTORS", "stripe, adyen, stripe, ,rapyd");

        let connectors = configured_all_connectors();

        match previous {
            Some(value) => std::env::set_var("UCS_ALL_CONNECTORS", value),
            None => std::env::remove_var("UCS_ALL_CONNECTORS"),
        }

        assert_eq!(connectors, vec!["adyen", "rapyd", "stripe"]);
    }
}
