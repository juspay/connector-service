#![allow(clippy::print_stderr, clippy::print_stdout, clippy::too_many_arguments)]

use std::{fs, path::PathBuf};

use serde::Deserialize;
use ucs_connector_tests::harness::{
    report::{
        append_report_best_effort, clear_report, extract_pm_and_pmt, now_epoch_ms, ReportEntry,
    },
    scenario_api::{
        get_the_grpc_req, run_all_connectors_with_options, run_all_suites_with_options,
        run_suite_test_with_options, SuiteRunOptions, SuiteRunSummary, DEFAULT_CONNECTOR,
        DEFAULT_ENDPOINT,
    },
};

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

    if args.all_connectors && (args.suite.is_some() || args.all || args.connector.is_some()) {
        eprintln!("cannot combine --all-connectors with --suite, --all, or --connector");
        print_usage();
        std::process::exit(2);
    }

    if args.all && args.suite.is_some() {
        eprintln!("cannot combine --all with --suite or positional suite");
        print_usage();
        std::process::exit(2);
    }

    let suite = args.suite.as_deref();

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

    let options = SuiteRunOptions {
        endpoint: Some(&endpoint),
        merchant_id: args.merchant_id.as_deref(),
        tenant_id: args.tenant_id.as_deref(),
        plaintext: args.plaintext,
    };

    // Clear report at start of every run
    clear_report();

    // --all-connectors: run all suites for all connectors
    if args.all_connectors {
        let summary = match run_all_connectors_with_options(options) {
            Ok(summary) => summary,
            Err(error) => {
                eprintln!("[suite_run_test] failed to run all connectors: {error}");
                std::process::exit(1);
            }
        };

        for connector_summary in &summary.connectors {
            println!("\n--- Connector: {} ---", connector_summary.connector);
            for suite_summary in &connector_summary.suites {
                print_suite_results(suite_summary, &endpoint);
            }
        }

        println!(
            "\n[suite_run_test] grand total: connectors={} passed={} failed={}",
            summary.connectors.len(),
            summary.passed,
            summary.failed
        );

        if summary.failed > 0 {
            std::process::exit(1);
        }
        return;
    }

    // --all: run all suites for one connector
    if args.all {
        let summary = match run_all_suites_with_options(Some(&connector), options) {
            Ok(summary) => summary,
            Err(error) => {
                eprintln!("[suite_run_test] failed to run all suites for '{connector}': {error}");
                std::process::exit(1);
            }
        };

        for suite_summary in &summary.suites {
            print_suite_results(suite_summary, &endpoint);
        }

        println!(
            "\n[suite_run_test] summary mode=all connector={} suites={} passed={} failed={}",
            summary.connector,
            summary.suites.len(),
            summary.passed,
            summary.failed
        );

        if summary.failed > 0 {
            std::process::exit(1);
        }
        return;
    }

    // Single suite mode
    let Some(suite) = suite else {
        eprintln!("missing required argument: --suite <suite> (or use --all / --all-connectors)");
        print_usage();
        std::process::exit(2);
    };

    let summary = match run_suite_test_with_options(suite, Some(&connector), options) {
        Ok(summary) => summary,
        Err(error) => {
            eprintln!("[suite_run_test] failed to run suite '{suite}': {error}");
            std::process::exit(1);
        }
    };

    print_suite_results(&summary, &endpoint);

    if summary.failed > 0 {
        std::process::exit(1);
    }
}

fn print_suite_results(summary: &SuiteRunSummary, endpoint: &str) {
    for result in &summary.results {
        let req_for_report = get_the_grpc_req(&result.suite, &result.scenario).ok();
        let (pm, pmt) = extract_pm_and_pmt(req_for_report.as_ref());
        write_report_entry(
            &result.suite,
            &result.scenario,
            &summary.connector,
            endpoint,
            pm.as_deref(),
            pmt.as_deref(),
            result.is_dependency,
            if result.passed { "PASS" } else { "FAIL" },
            None,
            result.error.clone(),
        );

        if result.passed {
            println!(
                "[suite_run_test] assertion result for '{}': PASS",
                result.scenario
            );
        } else {
            println!(
                "[suite_run_test] assertion result for '{}': FAIL ({})",
                result.scenario,
                result.error.as_deref().unwrap_or("unknown error")
            );
        }
    }

    println!(
        "\n[suite_run_test] summary suite={} connector={} passed={} failed={}",
        summary.suite, summary.connector, summary.passed, summary.failed
    );

    let failed_scenarios = summary
        .results
        .iter()
        .filter(|result| !result.passed)
        .map(|result| result.scenario.clone())
        .collect::<Vec<_>>();
    if !failed_scenarios.is_empty() {
        println!(
            "[suite_run_test] failed_scenarios={}",
            failed_scenarios.join(", ")
        );
    }
}

fn write_report_entry(
    suite: &str,
    scenario: &str,
    connector: &str,
    endpoint: &str,
    pm: Option<&str>,
    pmt: Option<&str>,
    is_dependency: bool,
    assertion_result: &str,
    response_status: Option<String>,
    error: Option<String>,
) {
    append_report_best_effort(ReportEntry {
        run_at_epoch_ms: now_epoch_ms(),
        suite: suite.to_string(),
        scenario: scenario.to_string(),
        connector: connector.to_string(),
        pm: pm.map(ToString::to_string),
        pmt: pmt.map(ToString::to_string),
        endpoint: endpoint.to_string(),
        is_dependency,
        assertion_result: assertion_result.to_string(),
        response_status,
        error,
    });
}

#[derive(Debug, Default)]
struct CliArgs {
    suite: Option<String>,
    all: bool,
    all_connectors: bool,
    connector: Option<String>,
    endpoint: Option<String>,
    creds_file: Option<String>,
    merchant_id: Option<String>,
    tenant_id: Option<String>,
    plaintext: bool,
    help: bool,
}

fn parse_args(args: impl Iterator<Item = String>) -> Result<CliArgs, String> {
    let mut cli = CliArgs {
        plaintext: true,
        ..CliArgs::default()
    };
    let mut positionals = Vec::new();
    let mut it = args.peekable();

    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-h" | "--help" => cli.help = true,
            "--all" => cli.all = true,
            "--all-connectors" => cli.all_connectors = true,
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
            "--tls" => cli.plaintext = false,
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
        if cli.all_connectors {
            return Err("cannot use positional suite with --all-connectors".to_string());
        }
        cli.suite = positionals.first().cloned();
        if positionals.len() > 1 {
            return Err("too many positional arguments; expected: [suite]".to_string());
        }
    }

    Ok(cli)
}

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
            .join("ucs-connector-tests")
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

fn print_usage() {
    eprintln!(
        "Usage:\n  cargo run -p ucs-connector-tests --bin suite_run_test -- --suite <suite> [--connector <name>] [options]\n  cargo run -p ucs-connector-tests --bin suite_run_test -- --all [--connector <name>] [options]\n  cargo run -p ucs-connector-tests --bin suite_run_test -- --all-connectors [options]\n  cargo run -p ucs-connector-tests --bin suite_run_test -- <suite>\n\nOptions:\n  --endpoint <host:port>   gRPC server endpoint\n  --creds-file <path>      Connector credentials file\n  --merchant-id <id>       Merchant ID\n  --tenant-id <id>         Tenant ID\n  --tls                    Use TLS instead of plaintext\n\nBehavior:\n  - --suite: Runs all scenarios from <suite>_suite/scenario.json\n  - --all: Runs all suites supported by the selected connector\n  - --all-connectors: Runs all suites for all connectors (zero args needed)\n  - Clears report.json at start, auto-generates test_report.md on each write\n  - Fails with exit code 1 if any scenario fails"
    );
}

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
    fn parses_positional_suite() {
        let args = vec!["authorize"].into_iter().map(str::to_string);
        let parsed = parse_args(args).expect("args should parse");
        assert_eq!(parsed.suite.as_deref(), Some("authorize"));
    }

    #[test]
    fn parses_all_flag() {
        let args = vec!["--all", "--connector", "stripe"]
            .into_iter()
            .map(str::to_string);
        let parsed = parse_args(args).expect("args should parse");
        assert!(parsed.all);
        assert_eq!(parsed.connector.as_deref(), Some("stripe"));
        assert!(parsed.suite.is_none());
    }

    #[test]
    fn parses_all_connectors_flag() {
        let args = vec!["--all-connectors"].into_iter().map(str::to_string);
        let parsed = parse_args(args).expect("args should parse");
        assert!(parsed.all_connectors);
        assert!(parsed.suite.is_none());
        assert!(parsed.connector.is_none());
    }

    #[test]
    fn rejects_all_connectors_with_connector() {
        let args = vec!["--all-connectors", "--connector", "stripe"]
            .into_iter()
            .map(str::to_string);
        // This should parse fine at arg level; conflict is checked in main()
        let parsed = parse_args(args).expect("args should parse at arg level");
        assert!(parsed.all_connectors);
        assert!(parsed.connector.is_some());
    }
}
