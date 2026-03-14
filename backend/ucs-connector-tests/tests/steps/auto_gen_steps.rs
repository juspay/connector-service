use cucumber::{given, then, when};
use serde_json::json;

use crate::TestWorld;
use ucs_connector_tests::harness::auto_gen::{
    id_prefix_for_leaf_path, id_prefix_for_path, is_auto_generate_sentinel,
    is_context_deferred_path, resolve_auto_generate,
};

// --- Sentinel detection ---

#[then(expr = "{string} is detected as an auto_generate sentinel")]
fn then_is_sentinel(_world: &mut TestWorld, value: String) {
    assert!(is_auto_generate_sentinel(&json!(value)));
}

#[then(expr = "{string} is not detected as an auto_generate sentinel")]
fn then_is_not_sentinel(_world: &mut TestWorld, value: String) {
    assert!(!is_auto_generate_sentinel(&json!(value)));
}

// --- ID prefix mapping ---

#[then(expr = "the id prefix for path {string} is {string}")]
fn then_id_prefix(_world: &mut TestWorld, path: String, expected: String) {
    assert_eq!(id_prefix_for_path(&path), expected);
}

#[then(expr = "the leaf id prefix for {string} is {string}")]
fn then_leaf_prefix(_world: &mut TestWorld, path: String, expected: String) {
    assert_eq!(id_prefix_for_leaf_path(&path), Some(expected.as_str()));
}

#[then(expr = "the leaf id prefix for {string} is None")]
fn then_leaf_prefix_none(_world: &mut TestWorld, path: String) {
    assert_eq!(id_prefix_for_leaf_path(&path), None);
}

// --- Auto-generate resolution ---

#[given("a request payload with auto_generate placeholders for merchant_transaction_id, customer, address, and payment_method")]
fn given_auto_gen_payload(world: &mut TestWorld) {
    world.auto_gen_req = json!({
        "merchant_transaction_id": "auto_generate",
        "customer": {
            "name": "auto_generate",
            "email": {"value": "auto_generate"},
            "phone_number": "auto_generate"
        },
        "address": {
            "shipping_address": {
                "first_name": {"value": "auto_generate"},
                "last_name": {"value": "auto_generate"},
                "line1": {"value": "auto_generate"},
                "city": {"value": "auto_generate"},
                "zip_code": {"value": "auto_generate"},
                "phone_number": {"value": "auto_generate"}
            }
        },
        "payment_method": {
            "card": {
                "card_holder_name": {"value": "auto_generate"},
                "card_number": {"value": "4111111111111111"}
            }
        }
    });
}

#[when("auto-generate placeholders are resolved")]
fn when_resolve_auto_gen(world: &mut TestWorld) {
    resolve_auto_generate(&mut world.auto_gen_req).expect("auto generation should succeed");
}

#[then(expr = "the merchant_transaction_id starts with {string}")]
fn then_mti_starts_with(world: &mut TestWorld, prefix: String) {
    let id = world.auto_gen_req["merchant_transaction_id"]
        .as_str()
        .expect("id should be string");
    assert!(id.starts_with(&prefix));
}

#[then(expr = "the customer name is no longer {string}")]
fn then_customer_name_changed(world: &mut TestWorld, old_value: String) {
    assert_ne!(world.auto_gen_req["customer"]["name"], json!(old_value));
}

#[then(expr = "the customer email value is no longer {string}")]
fn then_customer_email_changed(world: &mut TestWorld, old_value: String) {
    assert_ne!(
        world.auto_gen_req["customer"]["email"]["value"],
        json!(old_value)
    );
}

#[then(expr = "the card_number value remains {string}")]
fn then_card_number_unchanged(world: &mut TestWorld, expected: String) {
    assert_eq!(
        world.auto_gen_req["payment_method"]["card"]["card_number"]["value"],
        json!(expected)
    );
}

// --- Context-deferred fields ---

#[given("a request payload with context-deferred fields like connector_customer_id and access_token")]
fn given_context_deferred_payload(world: &mut TestWorld) {
    world.auto_gen_req = json!({
        "customer": { "connector_customer_id": "auto_generate" },
        "state": {
            "connector_customer_id": "auto_generate",
            "access_token": {
                "token": { "value": "auto_generate" },
                "token_type": "auto_generate",
                "expires_in_seconds": "auto_generate"
            }
        },
        "connector_feature_data": { "value": "auto_generate" },
        "connector_transaction_id": "auto_generate",
        "refund_id": "auto_generate",
        "merchant_transaction_id": "auto_generate"
    });
}

#[then(expr = "the connector_customer_id remains {string}")]
fn then_connector_customer_id_deferred(world: &mut TestWorld, expected: String) {
    assert_eq!(
        world.auto_gen_req["customer"]["connector_customer_id"],
        json!(expected)
    );
}

#[then(expr = "the state access_token token value remains {string}")]
fn then_token_deferred(world: &mut TestWorld, expected: String) {
    assert_eq!(
        world.auto_gen_req["state"]["access_token"]["token"]["value"],
        json!(expected)
    );
}

#[then(expr = "the connector_transaction_id remains {string}")]
fn then_txn_id_deferred(world: &mut TestWorld, expected: String) {
    assert_eq!(
        world.auto_gen_req["connector_transaction_id"],
        json!(expected)
    );
}

#[then(expr = "the refund_id remains {string}")]
fn then_refund_id_deferred(world: &mut TestWorld, expected: String) {
    assert_eq!(world.auto_gen_req["refund_id"], json!(expected));
}

#[then(expr = "the merchant_transaction_id is generated with prefix {string}")]
fn then_mti_generated(world: &mut TestWorld, prefix: String) {
    let id = world.auto_gen_req["merchant_transaction_id"]
        .as_str()
        .expect("merchant_transaction_id should be generated");
    assert!(id.starts_with(&prefix));
}

// --- Context-deferred path matching ---

#[then(expr = "{string} is a context-deferred path")]
fn then_is_deferred_path(_world: &mut TestWorld, path: String) {
    assert!(is_context_deferred_path(&path));
}

#[then(expr = "{string} is not a context-deferred path")]
fn then_is_not_deferred_path(_world: &mut TestWorld, path: String) {
    assert!(!is_context_deferred_path(&path));
}
