use std::fs;

use cucumber::{given, then, when};
use serde_json::{json, Value};

use crate::TestWorld;
use ucs_connector_tests::harness::connector_override::{
    apply_assertion_patch,
    loader::load_scenario_override_patch,
};
use ucs_connector_tests::harness::scenario_types::FieldAssert;

fn unique_temp_dir() -> std::path::PathBuf {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("ucs_cucumber_override_{nanos}"))
}

#[given("a temporary override root directory with no override files")]
fn given_empty_override_root(world: &mut TestWorld) {
    let temp_root = unique_temp_dir();
    fs::create_dir_all(&temp_root).expect("temp root should be created");
    world.prev_env_override_root = Some(std::env::var("UCS_CONNECTOR_OVERRIDE_ROOT").ok());
    std::env::set_var("UCS_CONNECTOR_OVERRIDE_ROOT", &temp_root);
    world.temp_dir = Some(temp_root);
}

#[given("a temporary override root directory with a stripe override file for authorize/no3ds_fail_payment")]
fn given_override_file(world: &mut TestWorld) {
    let temp_root = unique_temp_dir();
    let connector_dir = temp_root.join("stripe");
    fs::create_dir_all(&connector_dir).expect("connector directory should be created");

    let file_content = json!({
        "authorize": {
            "no3ds_fail_payment": {
                "grpc_req": {
                    "payment_method": {
                        "card": {
                            "card_number": {
                                "value": "4000000000000002"
                            }
                        }
                    }
                },
                "assert": {
                    "status": {
                        "one_of": ["FAILURE"]
                    }
                }
            }
        }
    });
    fs::write(
        connector_dir.join("override.json"),
        serde_json::to_string_pretty(&file_content).expect("should serialize"),
    )
    .expect("override file should be written");

    world.prev_env_override_root = Some(std::env::var("UCS_CONNECTOR_OVERRIDE_ROOT").ok());
    std::env::set_var("UCS_CONNECTOR_OVERRIDE_ROOT", &temp_root);
    world.temp_dir = Some(temp_root);
}

#[when(expr = "loading a scenario override patch for {string} suite {string} scenario {string}")]
fn when_load_override(world: &mut TestWorld, connector: String, suite: String, scenario: String) {
    let loaded = load_scenario_override_patch(&connector, &suite, &scenario)
        .expect("loading override should not fail");
    world.override_patch = loaded;

    // Cleanup env
    if let Some(prev) = world.prev_env_override_root.take() {
        match prev {
            Some(value) => std::env::set_var("UCS_CONNECTOR_OVERRIDE_ROOT", value),
            None => std::env::remove_var("UCS_CONNECTOR_OVERRIDE_ROOT"),
        }
    }
    if let Some(temp_dir) = world.temp_dir.take() {
        let _ = fs::remove_dir_all(temp_dir);
    }
}

#[then("the loaded override patch is None")]
fn then_patch_is_none(world: &mut TestWorld) {
    assert!(world.override_patch.is_none());
}

#[then(expr = "the loaded override patch contains a grpc_req patch with card_number {string}")]
fn then_patch_has_card(world: &mut TestWorld, expected_card: String) {
    let patch = world.override_patch.as_ref().expect("patch should exist");
    let card_number = patch
        .grpc_req
        .as_ref()
        .expect("grpc_req should exist")
        .pointer("/payment_method/card/card_number/value")
        .and_then(Value::as_str)
        .expect("card_number should exist");
    assert_eq!(card_number, expected_card);
}

#[then("the loaded override patch contains assertion rules")]
fn then_patch_has_assertions(world: &mut TestWorld) {
    let patch = world.override_patch.as_ref().expect("patch should exist");
    assert!(patch.assert_rules.is_some());
}

// --- Assertion patch tests ---

#[given(expr = "an assertions map with status {string} and error must_not_exist")]
fn given_assertions_map(world: &mut TestWorld, status: String) {
    world.assertions_map.insert(
        "status".to_string(),
        FieldAssert::OneOf {
            one_of: vec![Value::String(status)],
        },
    );
    world.assertions_map.insert(
        "error".to_string(),
        FieldAssert::MustNotExist {
            must_not_exist: true,
        },
    );
}

#[when(expr = "an assertion patch is applied that changes status to {string}, removes error, and adds connector_transaction_id")]
fn when_assertion_patch(world: &mut TestWorld, new_status: String) {
    let patch = std::collections::BTreeMap::from([
        (
            "status".to_string(),
            json!({"one_of": [new_status]}),
        ),
        ("error".to_string(), Value::Null),
        (
            "connector_transaction_id".to_string(),
            json!({"must_exist": true}),
        ),
    ]);
    apply_assertion_patch(&mut world.assertions_map, &patch).expect("patch should succeed");
}

#[then(expr = "the status assertion is one_of {string}")]
fn then_status_one_of(world: &mut TestWorld, expected: String) {
    assert!(matches!(
        world.assertions_map.get("status"),
        Some(FieldAssert::OneOf { one_of }) if one_of == &vec![Value::String(expected)]
    ));
}

#[then("the error assertion is removed")]
fn then_error_removed(world: &mut TestWorld) {
    assert!(!world.assertions_map.contains_key("error"));
}

#[then("the connector_transaction_id assertion is must_exist true")]
fn then_txn_id_must_exist(world: &mut TestWorld) {
    assert!(matches!(
        world.assertions_map.get("connector_transaction_id"),
        Some(FieldAssert::MustExist { must_exist: true })
    ));
}
