use cucumber::{given, then, when};

use crate::TestWorld;
use ucs_connector_tests::harness::scenario_loader::{
    configured_all_connectors, discover_all_connectors, get_the_assertion, get_the_grpc_req,
    load_scenario, load_suite_scenarios, load_suite_spec, load_supported_suites_for_connector,
    scenario_root,
};
use ucs_connector_tests::harness::scenario_types::DependencyScope;

fn discover_suites() -> Vec<String> {
    std::fs::read_dir(scenario_root())
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

// ---------------------------------------------------------------------------
// Scenario: All scenario files can be loaded by name
// ---------------------------------------------------------------------------

#[allow(clippy::needless_pass_by_ref_mut)]
#[given("the scenario root directory exists with at least one suite")]
fn given_scenario_root_exists(_world: &mut TestWorld) {
    let suites = discover_suites();
    assert!(!suites.is_empty(), "at least one suite should exist");
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then("every suite contains at least one scenario")]
fn then_every_suite_has_scenarios(_world: &mut TestWorld) {
    let suites = discover_suites();
    for suite in suites {
        let scenarios =
            load_suite_scenarios(&suite).expect("suite scenarios should be readable");
        assert!(
            !scenarios.is_empty(),
            "suite '{suite}' should contain at least one scenario"
        );
    }
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then("every scenario has an object grpc_req and non-empty assertion rules")]
fn then_every_scenario_has_grpc_req_and_assertions(_world: &mut TestWorld) {
    let suites = discover_suites();
    for suite in suites {
        let scenarios =
            load_suite_scenarios(&suite).expect("suite scenarios should be readable");
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

// ---------------------------------------------------------------------------
// Scenario: gRPC request and assertions are accessible for all scenarios
// ---------------------------------------------------------------------------

#[allow(clippy::needless_pass_by_ref_mut)]
#[then("every scenario has an accessible grpc_req that is an object")]
fn then_every_scenario_grpc_req_is_object(_world: &mut TestWorld) {
    let suites = discover_suites();
    for suite in suites {
        let scenarios =
            load_suite_scenarios(&suite).expect("suite scenarios should be readable");
        for scenario_name in scenarios.keys() {
            let req = get_the_grpc_req(&suite, scenario_name)
                .expect("grpc request should be available for scenario");
            assert!(
                req.is_object(),
                "grpc_req should be object for '{suite}/{scenario_name}'"
            );
        }
    }
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then("every scenario has accessible non-empty assertions")]
fn then_every_scenario_has_assertions(_world: &mut TestWorld) {
    let suites = discover_suites();
    for suite in suites {
        let scenarios =
            load_suite_scenarios(&suite).expect("suite scenarios should be readable");
        for scenario_name in scenarios.keys() {
            let assertions = get_the_assertion(&suite, scenario_name)
                .expect("assertions should be available for scenario");
            assert!(
                !assertions.is_empty(),
                "assertions should be present for '{suite}/{scenario_name}'"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Scenario: Suite specs can be loaded for all suites
// ---------------------------------------------------------------------------

#[allow(clippy::needless_pass_by_ref_mut)]
#[then("every suite spec name matches its folder name")]
fn then_suite_spec_name_matches_folder(_world: &mut TestWorld) {
    let suites = discover_suites();
    for suite in suites {
        let spec = load_suite_spec(&suite).expect("suite spec should be readable");
        assert_eq!(
            spec.suite, suite,
            "suite spec name should match folder name"
        );
    }
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then("every dependency suite name is non-empty")]
fn then_every_dependency_suite_name_non_empty(_world: &mut TestWorld) {
    let suites = discover_suites();
    for suite in suites {
        let spec = load_suite_spec(&suite).expect("suite spec should be readable");
        for dependency in &spec.depends_on {
            let dependency_suite = dependency.suite();
            assert!(
                !dependency_suite.is_empty(),
                "dependency suite name should not be empty"
            );
        }
    }
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then("every dependency override scenario exists")]
fn then_every_dependency_override_scenario_exists(_world: &mut TestWorld) {
    let suites = discover_suites();
    for suite in suites {
        let spec = load_suite_spec(&suite).expect("suite spec should be readable");
        for dependency in &spec.depends_on {
            if let Some(dependency_scenario) = dependency.scenario() {
                load_scenario(dependency.suite(), dependency_scenario)
                    .expect("dependency override scenario should exist");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Scenario: Dependency scope defaults and overrides are loaded
// ---------------------------------------------------------------------------

#[allow(clippy::needless_pass_by_ref_mut)]
#[then(expr = "the authorize suite has dependency scope {string}")]
fn then_authorize_has_dependency_scope(_world: &mut TestWorld, scope: String) {
    let spec = load_suite_spec("authorize").expect("authorize spec should load");
    let expected = match scope.as_str() {
        "Suite" => DependencyScope::Suite,
        "Scenario" => DependencyScope::Scenario,
        other => panic!("unknown dependency scope: {other}"),
    };
    assert_eq!(spec.dependency_scope, expected);
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then(expr = "suites {string} have dependency scope {string}")]
fn then_suites_have_dependency_scope(
    _world: &mut TestWorld,
    suites_csv: String,
    scope: String,
) {
    let expected = match scope.as_str() {
        "Suite" => DependencyScope::Suite,
        "Scenario" => DependencyScope::Scenario,
        other => panic!("unknown dependency scope: {other}"),
    };
    for suite in suites_csv.split(',').map(str::trim) {
        let spec = load_suite_spec(suite).expect("suite spec should load");
        assert_eq!(
            spec.dependency_scope, expected,
            "suite '{suite}' should run dependencies per scenario"
        );
    }
}

// ---------------------------------------------------------------------------
// Scenario: Explicit context maps exist for name-mismatch dependencies
// ---------------------------------------------------------------------------

#[allow(clippy::needless_pass_by_ref_mut)]
#[then("the recurring_charge suite has a mandate_reference context map entry")]
fn then_recurring_charge_has_mandate_reference_context_map(_world: &mut TestWorld) {
    let spec = load_suite_spec("recurring_charge").expect("recurring_charge spec should load");
    let has_mandate_mapping = spec.depends_on.iter().any(|dependency| {
        dependency
            .context_map()
            .and_then(|map| {
                map.get(
                    "connector_recurring_payment_id.connector_mandate_id.connector_mandate_id",
                )
            })
            .map(|source| {
                source == "res.mandate_reference.connector_mandate_id.connector_mandate_id"
            })
            .unwrap_or(false)
    });
    assert!(
        has_mandate_mapping,
        "recurring_charge should explicitly map mandate reference into connector recurring id"
    );
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then("the refund_sync suite has a refund_id context map entry")]
fn then_refund_sync_has_refund_id_context_map(_world: &mut TestWorld) {
    let spec = load_suite_spec("refund_sync").expect("refund_sync spec should load");
    let has_refund_mapping = spec.depends_on.iter().any(|dependency| {
        dependency
            .context_map()
            .and_then(|map| map.get("refund_id"))
            .map(|source| source == "res.connector_refund_id")
            .unwrap_or(false)
    });
    assert!(
        has_refund_mapping,
        "refund_sync should explicitly map refund_id from connector_refund_id"
    );
}

// ---------------------------------------------------------------------------
// Scenario: Supported suites can be loaded for known connectors
// ---------------------------------------------------------------------------

#[allow(clippy::needless_pass_by_ref_mut)]
#[then(expr = "the stripe connector supports the {string} suite")]
fn then_stripe_supports_suite(_world: &mut TestWorld, suite: String) {
    let suites = load_supported_suites_for_connector("stripe")
        .expect("supported suites should load for stripe connector");
    assert!(
        suites.iter().any(|s| s == &suite),
        "stripe should support {suite} suite"
    );
}

// ---------------------------------------------------------------------------
// Scenario: All connectors can be discovered
// ---------------------------------------------------------------------------

#[allow(clippy::needless_pass_by_ref_mut)]
#[then("at least one connector spec exists")]
fn then_at_least_one_connector_spec(_world: &mut TestWorld) {
    let connectors =
        discover_all_connectors().expect("should discover connectors from connector_specs/");
    assert!(
        !connectors.is_empty(),
        "at least one connector spec should exist"
    );
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then(expr = "the {string} connector is discoverable")]
fn then_connector_is_discoverable(_world: &mut TestWorld, connector: String) {
    let connectors =
        discover_all_connectors().expect("should discover connectors from connector_specs/");
    assert!(
        connectors.iter().any(|c| c == &connector),
        "{connector} connector spec should be discoverable"
    );
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then("the connector list is sorted")]
fn then_connector_list_is_sorted(_world: &mut TestWorld) {
    let connectors =
        discover_all_connectors().expect("should discover connectors from connector_specs/");
    let mut sorted = connectors.clone();
    sorted.sort();
    assert_eq!(connectors, sorted, "connectors should be sorted");
}

// ---------------------------------------------------------------------------
// Scenario: Configured connectors default to static run list
// ---------------------------------------------------------------------------

#[allow(clippy::needless_pass_by_ref_mut)]
#[then(expr = "the default configured connectors include {string}, {string}, and {string}")]
fn then_default_configured_connectors_include(
    _world: &mut TestWorld,
    a: String,
    b: String,
    c: String,
) {
    let previous = std::env::var("UCS_ALL_CONNECTORS").ok();
    std::env::remove_var("UCS_ALL_CONNECTORS");

    let connectors = configured_all_connectors();

    match previous {
        Some(value) => std::env::set_var("UCS_ALL_CONNECTORS", value),
        None => std::env::remove_var("UCS_ALL_CONNECTORS"),
    }

    assert!(connectors.iter().any(|c| c == &a), "should include {a}");
    assert!(connectors.iter().any(|c| c == &b), "should include {b}");
    assert!(connectors.iter().any(|x| x == &c), "should include {c}");
    assert!(!connectors.is_empty());
}

// ---------------------------------------------------------------------------
// Scenario: Configured connectors support env override
// ---------------------------------------------------------------------------

#[when(expr = "UCS_ALL_CONNECTORS is set to {string}")]
fn when_env_all_connectors_set(world: &mut TestWorld, value: String) {
    world.prev_env_all_connectors = Some(std::env::var("UCS_ALL_CONNECTORS").ok());
    std::env::set_var("UCS_ALL_CONNECTORS", &value);
}

#[then(expr = "the configured connectors are {string}, {string}, {string}")]
fn then_configured_connectors_are(world: &mut TestWorld, a: String, b: String, c: String) {
    let connectors = configured_all_connectors();

    // Restore env
    if let Some(ref prev) = world.prev_env_all_connectors {
        match prev {
            Some(value) => std::env::set_var("UCS_ALL_CONNECTORS", value),
            None => std::env::remove_var("UCS_ALL_CONNECTORS"),
        }
        world.prev_env_all_connectors = None;
    }

    assert_eq!(connectors, vec![a, b, c]);
}

// ---------------------------------------------------------------------------
// Scenario: Recurring charge scenarios exclude unsupported connector_transaction_id field
// ---------------------------------------------------------------------------

#[allow(clippy::needless_pass_by_ref_mut)]
#[then(expr = "recurring_charge scenarios {string} do not include connector_transaction_id")]
fn then_recurring_charge_scenarios_exclude_field(
    _world: &mut TestWorld,
    scenarios_csv: String,
) {
    for scenario_name in scenarios_csv.split(',').map(str::trim) {
        let req = get_the_grpc_req("recurring_charge", scenario_name)
            .expect("recurring charge grpc_req should be loadable");
        assert!(
            req.get("connector_transaction_id").is_none(),
            "recurring_charge/{scenario_name} should not include connector_transaction_id"
        );
    }
}

// ---------------------------------------------------------------------------
// Scenario: Setup recurring extended scenarios have billing address
// ---------------------------------------------------------------------------

#[allow(clippy::needless_pass_by_ref_mut)]
#[then(expr = "setup_recurring scenarios {string} include address.billing_address")]
fn then_setup_recurring_scenarios_have_billing_address(
    _world: &mut TestWorld,
    scenarios_csv: String,
) {
    for scenario_name in scenarios_csv.split(',').map(str::trim) {
        let req = get_the_grpc_req("setup_recurring", scenario_name)
            .expect("setup_recurring grpc_req should be loadable");
        let has_billing_address = req
            .get("address")
            .and_then(|address| address.get("billing_address"))
            .is_some();
        assert!(
            has_billing_address,
            "setup_recurring/{scenario_name} should include address.billing_address"
        );
    }
}

// ---------------------------------------------------------------------------
// Scenario: Three-connector suite coverage includes recurring flows
// ---------------------------------------------------------------------------

#[allow(clippy::needless_pass_by_ref_mut)]
#[then("authorizedotnet supports setup_recurring and recurring_charge suites")]
fn then_authorizedotnet_supports_recurring(_world: &mut TestWorld) {
    let suites = load_supported_suites_for_connector("authorizedotnet")
        .expect("authorizedotnet supported suites should load");
    assert!(
        suites.contains(&"setup_recurring".to_string())
            && suites.contains(&"recurring_charge".to_string()),
        "authorizedotnet should cover recurring suites"
    );
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then("stripe supports create_customer, setup_recurring, and recurring_charge suites")]
fn then_stripe_supports_recurring(_world: &mut TestWorld) {
    let suites =
        load_supported_suites_for_connector("stripe").expect("stripe suites should load");
    assert!(
        suites.contains(&"create_customer".to_string())
            && suites.contains(&"setup_recurring".to_string())
            && suites.contains(&"recurring_charge".to_string()),
        "stripe should include create_customer + recurring suites"
    );
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then("paypal supports create_access_token, setup_recurring, and recurring_charge suites")]
fn then_paypal_supports_recurring(_world: &mut TestWorld) {
    let suites =
        load_supported_suites_for_connector("paypal").expect("paypal suites should load");
    assert!(
        suites.contains(&"create_access_token".to_string())
            && suites.contains(&"setup_recurring".to_string())
            && suites.contains(&"recurring_charge".to_string()),
        "paypal should include token + recurring suites"
    );
}
