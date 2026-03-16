use std::collections::BTreeMap;

use domain_types::connector_types::ConnectorEnum;

use crate::auth::{dummy_auth, load_config, make_masked_metadata};
use crate::config::get_config;
use crate::flow_runners::*;
use crate::types::*;

pub(crate) fn probe_connector(connector: &ConnectorEnum) -> ConnectorResult {
    let name = format!("{connector:?}").to_lowercase();
    let config = load_config();
    let metadata = make_masked_metadata();
    // Use enabled payment methods from config
    let pm_variants = get_config().get_enabled_payment_methods();

    let mut flows: BTreeMap<String, BTreeMap<String, FlowResult>> = BTreeMap::new();

    // --- authorize ---
    let mut authorize_results: BTreeMap<String, FlowResult> = BTreeMap::new();
    for (pm_name, pm_fn) in &pm_variants {
        let auth = dummy_auth(connector);
        let result = probe_authorize(connector, pm_name, pm_fn(), &config, auth, &metadata);
        authorize_results.insert(pm_name.to_string(), result);
    }
    flows.insert("authorize".to_string(), authorize_results);

    // --- capture ---
    {
        let auth = dummy_auth(connector);
        let result = probe_capture(connector, &config, auth, &metadata);
        let mut m = BTreeMap::new();
        m.insert("default".to_string(), result);
        flows.insert("capture".to_string(), m);
    }

    // --- refund ---
    {
        let auth = dummy_auth(connector);
        let result = probe_refund(connector, &config, auth, &metadata);
        let mut m = BTreeMap::new();
        m.insert("default".to_string(), result);
        flows.insert("refund".to_string(), m);
    }

    // --- void ---
    {
        let auth = dummy_auth(connector);
        let result = probe_void(connector, &config, auth, &metadata);
        let mut m = BTreeMap::new();
        m.insert("default".to_string(), result);
        flows.insert("void".to_string(), m);
    }

    // --- get (psync) ---
    {
        let auth = dummy_auth(connector);
        let result = probe_get(connector, &config, auth, &metadata);
        let mut m = BTreeMap::new();
        m.insert("default".to_string(), result);
        flows.insert("get".to_string(), m);
    }

    // --- reverse (void post-capture) ---
    {
        let auth = dummy_auth(connector);
        let result = probe_reverse(connector, &config, auth, &metadata);
        let mut m = BTreeMap::new();
        m.insert("default".to_string(), result);
        flows.insert("reverse".to_string(), m);
    }

    // --- create_order ---
    {
        let auth = dummy_auth(connector);
        let result = probe_create_order(connector, &config, auth, &metadata);
        let mut m = BTreeMap::new();
        m.insert("default".to_string(), result);
        flows.insert("create_order".to_string(), m);
    }

    // --- setup_recurring ---
    {
        let auth = dummy_auth(connector);
        let result = probe_setup_recurring(connector, &config, auth, &metadata);
        let mut m = BTreeMap::new();
        m.insert("default".to_string(), result);
        flows.insert("setup_recurring".to_string(), m);
    }

    // --- recurring_charge ---
    {
        let auth = dummy_auth(connector);
        let result = probe_recurring_charge(connector, &config, auth, &metadata);
        let mut m = BTreeMap::new();
        m.insert("default".to_string(), result);
        flows.insert("recurring_charge".to_string(), m);
    }

    // --- create_customer ---
    {
        let auth = dummy_auth(connector);
        let result = probe_create_customer(connector, &config, auth, &metadata);
        let mut m = BTreeMap::new();
        m.insert("default".to_string(), result);
        flows.insert("create_customer".to_string(), m);
    }

    // --- tokenize ---
    {
        let auth = dummy_auth(connector);
        let result = probe_tokenize(connector, &config, auth, &metadata);
        let mut m = BTreeMap::new();
        m.insert("default".to_string(), result);
        flows.insert("tokenize".to_string(), m);
    }

    // --- create_access_token ---
    {
        let auth = dummy_auth(connector);
        let result = probe_create_access_token(connector, &config, auth, &metadata);
        let mut m = BTreeMap::new();
        m.insert("default".to_string(), result);
        flows.insert("create_access_token".to_string(), m);
    }

    // --- create_session_token ---
    {
        let auth = dummy_auth(connector);
        let result = probe_create_session_token(connector, &config, auth, &metadata);
        let mut m = BTreeMap::new();
        m.insert("default".to_string(), result);
        flows.insert("create_session_token".to_string(), m);
    }

    // --- pre_authenticate ---
    {
        let auth = dummy_auth(connector);
        let result = probe_pre_authenticate(connector, &config, auth, &metadata);
        let mut m = BTreeMap::new();
        m.insert("default".to_string(), result);
        flows.insert("pre_authenticate".to_string(), m);
    }

    // --- authenticate ---
    {
        let auth = dummy_auth(connector);
        let result = probe_authenticate(connector, &config, auth, &metadata);
        let mut m = BTreeMap::new();
        m.insert("default".to_string(), result);
        flows.insert("authenticate".to_string(), m);
    }

    // --- post_authenticate ---
    {
        let auth = dummy_auth(connector);
        let result = probe_post_authenticate(connector, &config, auth, &metadata);
        let mut m = BTreeMap::new();
        m.insert("default".to_string(), result);
        flows.insert("post_authenticate".to_string(), m);
    }

    // --- dispute_accept ---
    {
        let auth = dummy_auth(connector);
        let result = probe_accept_dispute(connector, &config, auth, &metadata);
        let mut m = BTreeMap::new();
        m.insert("default".to_string(), result);
        flows.insert("dispute_accept".to_string(), m);
    }

    // --- dispute_submit_evidence ---
    {
        let auth = dummy_auth(connector);
        let result = probe_submit_evidence(connector, &config, auth, &metadata);
        let mut m = BTreeMap::new();
        m.insert("default".to_string(), result);
        flows.insert("dispute_submit_evidence".to_string(), m);
    }

    // --- dispute_defend ---
    {
        let auth = dummy_auth(connector);
        let result = probe_defend_dispute(connector, &config, auth, &metadata);
        let mut m = BTreeMap::new();
        m.insert("default".to_string(), result);
        flows.insert("dispute_defend".to_string(), m);
    }

    ConnectorResult {
        connector: name,
        flows,
    }
}
