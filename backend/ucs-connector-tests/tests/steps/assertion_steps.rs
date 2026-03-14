use std::collections::BTreeMap;

use cucumber::{given, then, when};
use serde_json::json;

use crate::TestWorld;
use ucs_connector_tests::harness::scenario_assert::do_assertion;
use ucs_connector_tests::harness::scenario_types::FieldAssert;

#[given(expr = "a response with status {string}, connectorTransactionId {string}, null error, captured_amount 6000, and details message {string}")]
fn given_response(world: &mut TestWorld, status: String, txn_id: String, message: String) {
    world.assertion_response = json!({
        "status": status,
        "connectorTransactionId": { "id": txn_id },
        "error": null,
        "captured_amount": 6000,
        "details": { "message": message }
    });
}

#[given("a request with amount minor_amount 6000")]
fn given_request_amount(world: &mut TestWorld) {
    world.assertion_request = json!({
        "amount": { "minor_amount": 6000 }
    });
}

#[when(expr = "assertions are checked for one_of status, must_exist connector_transaction_id, must_not_exist error, echo captured_amount, and contains {string} in details.message")]
fn when_check_assertions(world: &mut TestWorld, contains_text: String) {
    let mut rules = BTreeMap::new();
    rules.insert(
        "status".to_string(),
        FieldAssert::OneOf {
            one_of: vec![json!("CHARGED"), json!("AUTHORIZED")],
        },
    );
    rules.insert(
        "connector_transaction_id".to_string(),
        FieldAssert::MustExist { must_exist: true },
    );
    rules.insert(
        "error".to_string(),
        FieldAssert::MustNotExist {
            must_not_exist: true,
        },
    );
    rules.insert(
        "captured_amount".to_string(),
        FieldAssert::Echo {
            echo: "amount.minor_amount".to_string(),
        },
    );
    rules.insert(
        "details.message".to_string(),
        FieldAssert::Contains {
            contains: contains_text,
        },
    );

    world.assertion_result = Some(do_assertion(
        &rules,
        &world.assertion_response,
        &world.assertion_request,
    ));
}

#[then("all assertions pass")]
fn then_all_pass(world: &mut TestWorld) {
    world
        .assertion_result
        .take()
        .expect("assertion result should exist")
        .expect("assertions should pass");
}
