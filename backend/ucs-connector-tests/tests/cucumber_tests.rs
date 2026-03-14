#![allow(
    clippy::expect_used,
    clippy::missing_panics_doc,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::print_stdout,
    clippy::print_stderr
)]

//! Cucumber Gherkin test runner for the UCS connector test harness.
//!
//! This binary replaces the inline `#[cfg(test)]` modules with BDD-style
//! `.feature` files and Rust step definitions.

mod steps;

use cucumber::World;

#[derive(Debug, Default, World)]
pub struct TestWorld {
    // --- JSON merge patch state ---
    pub json_target: serde_json::Value,

    // --- Connector override state ---
    pub override_patch: Option<ucs_connector_tests::harness::connector_override::loader::ScenarioOverridePatch>,
    pub temp_dir: Option<std::path::PathBuf>,
    pub prev_env_override_root: Option<Option<String>>,
    pub assertions_map: std::collections::BTreeMap<String, ucs_connector_tests::harness::scenario_types::FieldAssert>,

    // --- Auto-gen state ---
    pub auto_gen_req: serde_json::Value,

    // --- Assertion state ---
    pub assertion_response: serde_json::Value,
    pub assertion_request: serde_json::Value,
    pub assertion_result: Option<Result<(), ucs_connector_tests::harness::scenario_types::ScenarioError>>,

    // --- Report state ---
    pub report_pm: Option<String>,
    pub report_pmt: Option<String>,
    pub report_temp_root: Option<std::path::PathBuf>,
    pub report_entry: Option<ucs_connector_tests::harness::report::ReportEntry>,
    pub bearer_masked_once: String,
    pub bearer_masked_twice: String,

    // --- SDK state ---
    pub sdk_connector_config: Option<Result<grpc_api_types::payments::ConnectorSpecificConfig, ucs_connector_tests::harness::scenario_types::ScenarioError>>,
    pub sdk_auth: Option<ucs_connector_tests::harness::credentials::ConnectorAuth>,
    pub sdk_serialized_json: serde_json::Value,

    // --- Scenario API state ---
    pub run_test_result: Option<Result<(), ucs_connector_tests::harness::scenario_types::ScenarioError>>,
    pub base_assertions: std::collections::BTreeMap<String, ucs_connector_tests::harness::scenario_types::FieldAssert>,
    pub overridden_assertions: std::collections::BTreeMap<String, ucs_connector_tests::harness::scenario_types::FieldAssert>,
    pub grpcurl_command: String,
    pub grpcurl_request: Option<ucs_connector_tests::harness::scenario_api::GrpcurlRequest>,
    pub extracted_json_body: String,
    pub current_req: serde_json::Value,
    pub prev_reqs: Vec<serde_json::Value>,
    pub prev_res: Vec<serde_json::Value>,
    pub context_map_collected: Vec<(
        std::collections::HashMap<String, String>,
        serde_json::Value,
        serde_json::Value,
    )>,

    // --- Env state for cleanup ---
    pub prev_env_all_connectors: Option<Option<String>>,
}

fn main() {
    futures::executor::block_on(TestWorld::run("tests/features"));
}
