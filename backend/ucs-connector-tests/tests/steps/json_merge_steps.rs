use cucumber::{given, then, when};
use serde_json::json;

use crate::TestWorld;
use ucs_connector_tests::harness::connector_override::json_merge::json_merge_patch;

#[given("a JSON object with amount and customer fields")]
fn given_amount_customer(world: &mut TestWorld) {
    world.json_target = json!({
        "amount": {
            "minor_amount": 1000,
            "currency": "USD"
        },
        "customer": {
            "id": "cust_123",
            "email": "john@example.com"
        }
    });
}

#[when("a merge patch is applied that changes currency, removes email, and adds connector_feature_data")]
fn when_merge_patch(world: &mut TestWorld) {
    let patch = json!({
        "amount": {
            "currency": "EUR"
        },
        "customer": {
            "email": null
        },
        "connector_feature_data": {
            "value": "{\"auth_id\":\"a_1\"}"
        }
    });
    json_merge_patch(&mut world.json_target, &patch);
}

#[then("the amount minor_amount is preserved as 1000")]
fn then_minor_amount_preserved(world: &mut TestWorld) {
    assert_eq!(world.json_target["amount"]["minor_amount"], json!(1000));
}

#[then(expr = "the amount currency is changed to {string}")]
fn then_currency_changed(world: &mut TestWorld, expected: String) {
    assert_eq!(world.json_target["amount"]["currency"], json!(expected));
}

#[then(expr = "the customer id is preserved as {string}")]
fn then_customer_id_preserved(world: &mut TestWorld, expected: String) {
    assert_eq!(world.json_target["customer"]["id"], json!(expected));
}

#[then("the customer email field is removed")]
fn then_email_removed(world: &mut TestWorld) {
    assert!(world.json_target["customer"].get("email").is_none());
}

#[then("the connector_feature_data value is set")]
fn then_feature_data_set(world: &mut TestWorld) {
    assert_eq!(
        world.json_target["connector_feature_data"]["value"],
        json!("{\"auth_id\":\"a_1\"}")
    );
}

#[given(expr = "a JSON object with capture_method set to {string}")]
fn given_capture_method(world: &mut TestWorld, value: String) {
    world.json_target = json!({"capture_method": value});
}

#[when(expr = "a merge patch replaces capture_method with an object containing value {string}")]
fn when_merge_patch_replaces(world: &mut TestWorld, value: String) {
    let patch = json!({"capture_method": {"value": value}});
    json_merge_patch(&mut world.json_target, &patch);
}

#[then(expr = "the capture_method is an object with value {string}")]
fn then_capture_method_object(world: &mut TestWorld, expected: String) {
    assert_eq!(world.json_target["capture_method"]["value"], json!(expected));
}
