use cucumber::{given, then, when};

use crate::TestWorld;
use grpc_api_types::payments::{
    connector_specific_config, identifier, payment_method, CardDetails,
    Identifier, PaymentMethod, PaymentServiceAuthorizeRequest,
};
use ucs_connector_tests::harness::credentials::ConnectorAuth;
use ucs_connector_tests::harness::scenario_api::get_the_grpc_req_for_connector;
use ucs_connector_tests::harness::sdk_executor::{
    build_proto_connector_config, parse_sdk_payload, supports_sdk_connector, supports_sdk_suite,
};

// --- SDK support matrix ---

#[allow(clippy::needless_pass_by_ref_mut)]
#[then(expr = "{string} is a supported SDK connector")]
fn then_is_supported_connector(_world: &mut TestWorld, connector: String) {
    assert!(
        supports_sdk_connector(&connector),
        "{connector} should be a supported SDK connector"
    );
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then(expr = "{string} is not a supported SDK connector")]
fn then_is_not_supported_connector(_world: &mut TestWorld, connector: String) {
    assert!(
        !supports_sdk_connector(&connector),
        "{connector} should not be a supported SDK connector"
    );
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then(expr = "{string} is a supported SDK suite")]
fn then_is_supported_suite(_world: &mut TestWorld, suite: String) {
    assert!(
        supports_sdk_suite(&suite),
        "{suite} should be a supported SDK suite"
    );
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then(expr = "{string} is not a supported SDK suite")]
fn then_is_not_supported_suite(_world: &mut TestWorld, suite: String) {
    assert!(
        !supports_sdk_suite(&suite),
        "{suite} should not be a supported SDK suite"
    );
}

// --- Auth config construction ---

#[given(expr = "a header key auth with api_key {string}")]
fn given_header_key_auth(world: &mut TestWorld, api_key: String) {
    world.sdk_auth = Some(ConnectorAuth::HeaderKey { api_key });
}

#[given(expr = "a body key auth with api_key {string} and key1 {string}")]
fn given_body_key_auth(world: &mut TestWorld, api_key: String, key1: String) {
    world.sdk_auth = Some(ConnectorAuth::BodyKey { api_key, key1 });
}

#[given(expr = "a signature key auth with api_key {string}, key1 {string}, and api_secret {string}")]
fn given_signature_key_auth(world: &mut TestWorld, api_key: String, key1: String, api_secret: String) {
    world.sdk_auth = Some(ConnectorAuth::SignatureKey {
        api_key,
        key1,
        api_secret,
    });
}

#[when(expr = "building proto connector config for {string}")]
fn when_building_proto_config(world: &mut TestWorld, connector: String) {
    let auth = world.sdk_auth.as_ref().expect("sdk_auth should be set before building config");
    world.sdk_connector_config = Some(build_proto_connector_config(&connector, auth));
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then("the config contains a Stripe variant")]
fn then_config_is_stripe(world: &mut TestWorld) {
    let config = world
        .sdk_connector_config
        .as_ref()
        .expect("sdk_connector_config should be set")
        .as_ref()
        .expect("sdk_connector_config should be Ok");
    assert!(
        matches!(config.config, Some(connector_specific_config::Config::Stripe(_))),
        "expected Stripe variant, got: {:?}",
        config.config
    );
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then("the config contains a Paypal variant")]
fn then_config_is_paypal(world: &mut TestWorld) {
    let config = world
        .sdk_connector_config
        .as_ref()
        .expect("sdk_connector_config should be set")
        .as_ref()
        .expect("sdk_connector_config should be Ok");
    assert!(
        matches!(config.config, Some(connector_specific_config::Config::Paypal(_))),
        "expected Paypal variant, got: {:?}",
        config.config
    );
}

// --- Authorize scenario parsing ---

#[given(expr = "the authorize scenario {string} loaded for {string}")]
fn given_authorize_scenario_loaded(world: &mut TestWorld, scenario: String, connector: String) {
    let req = get_the_grpc_req_for_connector("authorize", &scenario, &connector)
        .expect("authorize scenario should load");
    world.auto_gen_req = req;
}

#[when("the SDK payload is parsed as an authorize request")]
fn when_sdk_payload_parsed(world: &mut TestWorld) {
    let parsed: PaymentServiceAuthorizeRequest = parse_sdk_payload(
        "authorize",
        "no3ds_auto_capture_credit_card",
        "authorizedotnet",
        &world.auto_gen_req,
    )
    .expect("sdk payload parse should succeed");
    world.auto_gen_req = serde_json::to_value(parsed).expect("parsed request should serialize");
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then("the payment method is a Card variant")]
fn then_payment_method_is_card(world: &mut TestWorld) {
    let parsed: PaymentServiceAuthorizeRequest =
        serde_json::from_value(world.auto_gen_req.clone())
            .expect("auto_gen_req should deserialize to PaymentServiceAuthorizeRequest");
    let payment_method = parsed
        .payment_method
        .expect("payment_method should be present after parsing");
    assert!(
        matches!(
            payment_method.payment_method,
            Some(payment_method::PaymentMethod::Card(_))
        ),
        "unexpected payment_method variant: {:?}",
        payment_method.payment_method
    );
}

// --- Serde shapes for oneof wrappers ---

#[when("a PaymentMethod with Card variant is serialized")]
fn when_payment_method_serialized(world: &mut TestWorld) {
    let pm = PaymentMethod {
        payment_method: Some(payment_method::PaymentMethod::Card(
            CardDetails::default(),
        )),
    };
    world.sdk_serialized_json =
        serde_json::to_value(pm).expect("payment method should serialize");
}

#[when("an Identifier with Id variant is serialized")]
fn when_identifier_serialized(world: &mut TestWorld) {
    let id = Identifier {
        id_type: Some(identifier::IdType::Id("id_123".to_string())),
    };
    world.sdk_serialized_json =
        serde_json::to_value(id).expect("identifier should serialize");
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then(expr = "the JSON has a {string} key")]
fn then_json_has_key(world: &mut TestWorld, key: String) {
    assert!(
        world.sdk_serialized_json.get(&key).is_some(),
        "expected JSON to have key \"{key}\", got: {}",
        world.sdk_serialized_json
    );
}
