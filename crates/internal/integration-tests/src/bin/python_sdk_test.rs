#![allow(clippy::print_stderr, clippy::print_stdout, clippy::too_many_arguments)]

//! Python SDK test runner.
//!
//! Executes integration-test scenarios through the Python SDK via subprocess,
//! mirroring the `sdk_run_test` binary but using `python_executor` instead of
//! the Rust FFI path.  This validates end-to-end correctness of the Python SDK
//! for every supported flow.

use std::{fs, path::PathBuf};

use integration_tests::harness::{
    python_executor::{
        execute_python_sdk_request, python_sdk_coverage_report, supports_python_sdk_suite,
    },
    report::{append_report_best_effort, extract_pm_and_pmt, now_epoch_ms, ReportEntry},
    scenario_api::{get_the_grpc_req_for_connector, DEFAULT_CONNECTOR, DEFAULT_ENDPOINT},
    scenario_loader::{load_connector_spec, load_suite_scenarios},
};
use serde::Deserialize;
use serde_json::Value;

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    let args = match parse_args(std::env::args().skip(1)) {
        Ok(args) => args,
        Err(message) => {
            eprintln!("{message}");
            print_usage();
            std::process::exit(2);
        }
    };

    if args.help {
        print_usage();
        return;
    }

    if args.coverage_only {
        print_python_sdk_coverage();
        return;
    }

    if args.all && args.suite.is_some() {
        eprintln!("cannot combine --all with --suite or positional suite");
        print_usage();
        std::process::exit(2);
    }

    // Always print coverage summary at start.
    print_python_sdk_coverage();

    let connector = args
        .connector
        .clone()
        .unwrap_or_else(|| DEFAULT_CONNECTOR.to_string());

    let defaults = load_defaults();

    let endpoint = args
        .endpoint
        .as_deref()
        .map(ToString::to_string)
        .or(defaults.endpoint)
        .unwrap_or_else(|| DEFAULT_ENDPOINT.to_string());

    let creds_file = args
        .creds_file
        .as_deref()
        .map(ToString::to_string)
        .or_else(|| std::env::var("CONNECTOR_AUTH_FILE_PATH").ok())
        .or_else(|| std::env::var("UCS_CREDS_PATH").ok())
        .or(defaults.creds_file);

    if let Some(creds_file) = creds_file.as_deref() {
        std::env::set_var("CONNECTOR_AUTH_FILE_PATH", creds_file);
    }

    if args.all {
        run_all_suites(&connector, &endpoint, args.report);
    } else if let Some(suite) = args.suite.as_deref() {
        run_single_suite(suite, &connector, &endpoint, args.report);
    } else {
        eprintln!("missing required argument: --suite <suite> (or use --all / --coverage)");
        print_usage();
        std::process::exit(2);
    }
}

// ---------------------------------------------------------------------------
// Suite execution
// ---------------------------------------------------------------------------

fn run_all_suites(connector: &str, endpoint: &str, report: bool) {
    let suites = discover_python_sdk_suites_for_connector(connector);

    if suites.is_empty() {
        eprintln!("[python_sdk_test] no Python SDK suites found for connector '{connector}'");
        std::process::exit(1);
    }

    let mut total_passed = 0usize;
    let mut total_failed = 0usize;

    for suite in &suites {
        let (passed, failed) = run_suite(suite, connector, endpoint, report);
        total_passed += passed;
        total_failed += failed;
    }

    println!(
        "\n[python_sdk_test] grand summary connector={connector} suites={} passed={total_passed} failed={total_failed}",
        suites.len()
    );

    if total_failed > 0 {
        std::process::exit(1);
    }
}

fn run_single_suite(suite: &str, connector: &str, endpoint: &str, report: bool) {
    if !supports_python_sdk_suite(suite) {
        eprintln!("[python_sdk_test] suite '{suite}' is not supported by Python SDK executor");
        std::process::exit(2);
    }

    let (passed, failed) = run_suite(suite, connector, endpoint, report);

    println!(
        "\n[python_sdk_test] summary suite={suite} connector={connector} passed={passed} failed={failed}"
    );

    if failed > 0 {
        std::process::exit(1);
    }
}

/// Runs all scenarios in a suite through the Python SDK executor.
/// Returns (passed, failed) counts.
fn run_suite(suite: &str, connector: &str, endpoint: &str, report: bool) -> (usize, usize) {
    let scenarios = match load_suite_scenarios(suite) {
        Ok(scenarios) => scenarios,
        Err(error) => {
            eprintln!("[python_sdk_test] failed to load scenarios for suite '{suite}': {error}");
            return (0, 1);
        }
    };

    if scenarios.is_empty() {
        eprintln!("[python_sdk_test] no scenarios found for suite '{suite}'");
        return (0, 0);
    }

    let mut passed = 0usize;
    let mut failed = 0usize;

    for scenario_name in scenarios.keys() {
        let grpc_req = match get_the_grpc_req_for_connector(suite, scenario_name, connector) {
            Ok(req) => req,
            Err(error) => {
                println!("[python_sdk_test] SKIP '{suite}/{scenario_name}': {error}");
                continue;
            }
        };

        let (pm, pmt) = extract_pm_and_pmt(Some(&grpc_req));

        match execute_python_sdk_request(suite, scenario_name, &grpc_req, connector) {
            Ok(response_json) => {
                println!("[python_sdk_test] assertion result for '{suite}/{scenario_name}': PASS");
                passed += 1;

                if report {
                    let res_body: Option<Value> = serde_json::from_str(&response_json).ok();
                    write_report_entry(
                        suite,
                        scenario_name,
                        connector,
                        endpoint,
                        pm.as_deref(),
                        pmt.as_deref(),
                        "PASS",
                        None,
                        Some(grpc_req),
                        res_body,
                    );
                }
            }
            Err(error) => {
                let error_msg = error.to_string();
                println!(
                    "[python_sdk_test] assertion result for '{suite}/{scenario_name}': FAIL ({})",
                    truncate_for_console(&error_msg, 220)
                );
                failed += 1;

                if report {
                    write_report_entry(
                        suite,
                        scenario_name,
                        connector,
                        endpoint,
                        pm.as_deref(),
                        pmt.as_deref(),
                        "FAIL",
                        Some(error_msg),
                        Some(grpc_req),
                        None,
                    );
                }
            }
        }
    }

    println!(
        "[python_sdk_test] suite={suite} connector={connector} passed={passed} failed={failed}"
    );

    (passed, failed)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Discovers Python SDK–supported suites for a connector by intersecting
/// the connector's `specs.json` supported_suites with Python executor support.
fn discover_python_sdk_suites_for_connector(connector: &str) -> Vec<String> {
    if let Some(spec) = load_connector_spec(connector) {
        spec.supported_suites
            .into_iter()
            .filter(|suite| supports_python_sdk_suite(suite))
            .collect()
    } else {
        // Fallback: try all known Python SDK suites
        let report = python_sdk_coverage_report();
        report.supported.iter().map(|s| s.to_string()).collect()
    }
}

fn print_python_sdk_coverage() {
    let report = python_sdk_coverage_report();

    eprintln!(
        "[python_sdk_test] interface=PythonSDK  total_suites={}  supported={}  not_supported={}",
        report.supported.len() + report.not_supported.len(),
        report.supported.len(),
        report.not_supported.len(),
    );
    eprintln!(
        "[python_sdk_test]   supported suites    : {}",
        report.supported.join(", ")
    );
    eprintln!(
        "[python_sdk_test]   not yet supported   : {}",
        report.not_supported.join(", ")
    );
}

fn truncate_for_console(text: &str, max_chars: usize) -> String {
    let mut chars = text.chars();
    let truncated: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        format!("{truncated}...")
    } else {
        truncated
    }
}

fn write_report_entry(
    suite: &str,
    scenario: &str,
    connector: &str,
    endpoint: &str,
    pm: Option<&str>,
    pmt: Option<&str>,
    assertion_result: &str,
    error: Option<String>,
    req_body: Option<Value>,
    res_body: Option<Value>,
) {
    let scenario_display_name = load_suite_scenarios(suite)
        .ok()
        .and_then(|scenarios| scenarios.get(scenario).cloned())
        .and_then(|scenario_def| scenario_def.display_name);

    append_report_best_effort(ReportEntry {
        run_at_epoch_ms: now_epoch_ms(),
        suite: suite.to_string(),
        scenario: scenario.to_string(),
        scenario_display_name,
        connector: connector.to_string(),
        pm: pm.map(ToString::to_string),
        pmt: pmt.map(ToString::to_string),
        endpoint: endpoint.to_string(),
        is_dependency: false,
        assertion_result: assertion_result.to_string(),
        response_status: None,
        error,
        dependency: vec![],
        req_body,
        res_body,
        grpc_request: None,
        grpc_response: None,
    });
}

// ---------------------------------------------------------------------------
// CLI parsing
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct CliArgs {
    suite: Option<String>,
    all: bool,
    connector: Option<String>,
    endpoint: Option<String>,
    creds_file: Option<String>,
    merchant_id: Option<String>,
    tenant_id: Option<String>,
    report: bool,
    coverage_only: bool,
    help: bool,
}

fn parse_args(args: impl Iterator<Item = String>) -> Result<CliArgs, String> {
    let mut cli = CliArgs::default();
    let mut positionals = Vec::new();
    let mut it = args.peekable();

    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-h" | "--help" => cli.help = true,
            "--all" => cli.all = true,
            "--coverage" => cli.coverage_only = true,
            "--suite" | "-s" => {
                let value = it
                    .next()
                    .ok_or_else(|| "missing value for --suite".to_string())?;
                cli.suite = Some(value);
            }
            "--connector" => {
                let value = it
                    .next()
                    .ok_or_else(|| "missing value for --connector".to_string())?;
                cli.connector = Some(value);
            }
            "--endpoint" => {
                let value = it
                    .next()
                    .ok_or_else(|| "missing value for --endpoint".to_string())?;
                cli.endpoint = Some(value);
            }
            "--creds-file" => {
                let value = it
                    .next()
                    .ok_or_else(|| "missing value for --creds-file".to_string())?;
                cli.creds_file = Some(value);
            }
            "--merchant-id" => {
                let value = it
                    .next()
                    .ok_or_else(|| "missing value for --merchant-id".to_string())?;
                cli.merchant_id = Some(value);
            }
            "--tenant-id" => {
                let value = it
                    .next()
                    .ok_or_else(|| "missing value for --tenant-id".to_string())?;
                cli.tenant_id = Some(value);
            }
            "--report" => cli.report = true,
            _ if arg.starts_with('-') => return Err(format!("unknown argument '{arg}'")),
            _ => positionals.push(arg),
        }
    }

    if !positionals.is_empty() {
        if cli.suite.is_some() {
            return Err("cannot mix positional suite with --suite".to_string());
        }
        if cli.all {
            return Err("cannot use positional suite with --all".to_string());
        }
        cli.suite = positionals.first().cloned();
        if positionals.len() > 1 {
            return Err("too many positional arguments; expected: [suite]".to_string());
        }
    }

    Ok(cli)
}

// ---------------------------------------------------------------------------
// Stored defaults
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Clone, Deserialize)]
struct StoredDefaults {
    endpoint: Option<String>,
    creds_file: Option<String>,
}

fn defaults_path() -> PathBuf {
    if let Ok(path) = std::env::var("UCS_RUN_TEST_DEFAULTS_PATH") {
        return PathBuf::from(path);
    }

    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home)
            .join(".config")
            .join("integration-tests")
            .join("run_test_defaults.json");
    }

    PathBuf::from(".ucs_run_test_defaults.json")
}

fn load_defaults() -> StoredDefaults {
    let path = defaults_path();
    let Ok(content) = fs::read_to_string(path) else {
        return StoredDefaults::default();
    };

    serde_json::from_str(&content).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Usage
// ---------------------------------------------------------------------------

fn print_usage() {
    eprintln!(
        "Usage:\n  cargo run -p integration-tests --bin python_sdk_test -- --suite <suite> [--connector <name>] [options]\n  cargo run -p integration-tests --bin python_sdk_test -- --all [--connector <name>] [options]\n  cargo run -p integration-tests --bin python_sdk_test -- --coverage\n  cargo run -p integration-tests --bin python_sdk_test -- <suite>\n\nOptions:\n  --connector <name>       Connector to test (default: {DEFAULT_CONNECTOR})\n  --endpoint <host:port>   Endpoint for report metadata (default: {DEFAULT_ENDPOINT})\n  --creds-file <path>      Connector credentials file\n  --merchant-id <id>       Merchant ID\n  --tenant-id <id>         Tenant ID\n  --report                 Generate report.json and test_report/ markdown files\n  --coverage               Print Python SDK coverage report and exit\n\nBehavior:\n  - Executes scenarios through the Python SDK via subprocess\n  - Report files are generated only when --report is passed\n  - Fails with exit code 1 if any scenario fails",
        DEFAULT_CONNECTOR = DEFAULT_CONNECTOR,
        DEFAULT_ENDPOINT = DEFAULT_ENDPOINT,
    );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::parse_args;

    #[test]
    fn parses_suite_and_connector() {
        let args = vec!["--suite", "authorize", "--connector", "stripe"]
            .into_iter()
            .map(str::to_string);

        let parsed = parse_args(args).expect("args should parse");
        assert_eq!(parsed.suite.as_deref(), Some("authorize"));
        assert_eq!(parsed.connector.as_deref(), Some("stripe"));
    }

    #[test]
    fn parses_all_flag() {
        let args = vec!["--all", "--connector", "stripe"]
            .into_iter()
            .map(str::to_string);

        let parsed = parse_args(args).expect("args should parse");
        assert!(parsed.all);
        assert_eq!(parsed.connector.as_deref(), Some("stripe"));
    }

    #[test]
    fn parses_coverage_flag() {
        let args = vec!["--coverage"].into_iter().map(str::to_string);

        let parsed = parse_args(args).expect("args should parse");
        assert!(parsed.coverage_only);
    }

    #[test]
    fn parses_report_flag() {
        let args = vec!["--suite", "authorize", "--report"]
            .into_iter()
            .map(str::to_string);

        let parsed = parse_args(args).expect("args should parse");
        assert!(parsed.report);
    }

    #[test]
    fn parses_positional_suite() {
        let args = vec!["authorize"].into_iter().map(str::to_string);

        let parsed = parse_args(args).expect("args should parse");
        assert_eq!(parsed.suite.as_deref(), Some("authorize"));
    }

    #[test]
    fn rejects_mixed_positional_and_suite_flag() {
        let args = vec!["authorize", "--suite", "capture"]
            .into_iter()
            .map(str::to_string);

        assert!(parse_args(args).is_err());
    }
}
