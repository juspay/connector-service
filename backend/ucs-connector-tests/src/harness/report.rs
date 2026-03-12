#![allow(clippy::print_stderr)]

//! Report persistence and markdown rendering for harness runs.
//!
//! This module appends `ReportEntry` rows into `report.json` and regenerates
//! `test_report.md` after each write so the latest execution state is always
//! available in both machine-readable and human-readable formats.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportEntry {
    /// Execution timestamp in epoch milliseconds.
    pub run_at_epoch_ms: u128,
    /// Suite name (e.g. `authorize`).
    pub suite: String,
    /// Scenario name inside the suite.
    pub scenario: String,
    /// Connector slug used for execution.
    pub connector: String,
    /// Payment method extracted from request template, when available.
    pub pm: Option<String>,
    /// Payment method type extracted from request template, when available.
    pub pmt: Option<String>,
    /// Endpoint used by execution backend.
    pub endpoint: String,
    /// Marks whether this row is from dependency execution.
    #[serde(default)]
    pub is_dependency: bool,
    /// Assertion outcome (`PASS`/`FAIL`).
    pub assertion_result: String,
    /// Optional response status extracted from response JSON.
    pub response_status: Option<String>,
    /// Optional failure reason / assertion error text.
    pub error: Option<String>,
    /// Dependency chain captured at execution time.
    #[serde(default)]
    pub dependency: Vec<String>,
    /// Effective request payload used for execution.
    pub req_body: Option<Value>,
    /// Parsed response payload captured for reporting/debugging.
    pub res_body: Option<Value>,
    /// Full grpc request trace (command + headers + payload), when available.
    #[serde(default)]
    pub grpc_request: Option<String>,
    /// Full grpc response trace (headers/trailers + body), when available.
    #[serde(default)]
    pub grpc_response: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ScenarioRunReport {
    /// Chronological list of all run entries in current report file.
    pub runs: Vec<ReportEntry>,
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

pub fn report_path() -> PathBuf {
    if let Ok(path) = std::env::var("UCS_RUN_TEST_REPORT_PATH") {
        return PathBuf::from(path);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("report.json")
}

fn md_path(json_path: &Path) -> PathBuf {
    json_path.with_file_name("test_report.md")
}

// ---------------------------------------------------------------------------
// Report operations
// ---------------------------------------------------------------------------

/// Resets report artifacts (`report.json` and `test_report.md`).
pub fn clear_report() {
    let path = report_path();
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(&path, "{\"runs\":[]}");

    // Also clear the md file so it stays in sync
    let md = md_path(&path);
    if md.exists() {
        let _ = fs::remove_file(&md);
    }
}

/// Appends one report entry and regenerates markdown output.
pub fn append_report(entry: ReportEntry) -> Result<(), String> {
    append_report_batch(vec![entry])
}

/// Appends many report entries and regenerates markdown output once.
pub fn append_report_batch(entries: Vec<ReportEntry>) -> Result<(), String> {
    if entries.is_empty() {
        return Ok(());
    }

    let path = report_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            format!(
                "failed to create report directory '{}': {e}",
                parent.display()
            )
        })?;
    }

    let mut report = if path.exists() {
        match fs::read_to_string(&path) {
            Ok(content) => serde_json::from_str::<ScenarioRunReport>(&content).unwrap_or_default(),
            Err(_) => ScenarioRunReport::default(),
        }
    } else {
        ScenarioRunReport::default()
    };

    let sanitized_entries = entries.into_iter().map(|mut entry| {
        sanitize_report_entry_in_place(&mut entry);
        entry
    });
    report.runs.extend(sanitized_entries);

    let serialized = serde_json::to_string_pretty(&report)
        .map_err(|e| format!("failed to serialize report: {e}"))?;
    fs::write(&path, &serialized)
        .map_err(|e| format!("failed to write report '{}': {e}", path.display()))?;

    // Auto-generate markdown after every write
    if let Err(e) = generate_md(&path, &report) {
        eprintln!("[report] failed to generate markdown: {e}");
    }

    Ok(())
}

/// Best-effort wrapper around `append_report` that logs failures instead of
/// bubbling them.
pub fn append_report_best_effort(entry: ReportEntry) {
    if let Err(e) = append_report(entry) {
        eprintln!("[report] write failed: {e}");
    }
}

/// Best-effort wrapper around `append_report_batch`.
pub fn append_report_batch_best_effort(entries: Vec<ReportEntry>) {
    if let Err(e) = append_report_batch(entries) {
        eprintln!("[report] batch write failed: {e}");
    }
}

// ---------------------------------------------------------------------------
// Helpers shared by binaries
// ---------------------------------------------------------------------------

/// Returns current timestamp in epoch milliseconds.
pub fn now_epoch_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// Best-effort extraction of payment method and payment method type from a
/// request payload, used by report tables.
pub fn extract_pm_and_pmt(grpc_req: Option<&Value>) -> (Option<String>, Option<String>) {
    let Some(grpc_req) = grpc_req else {
        return (None, None);
    };
    let Some(payment_method_obj) = grpc_req.get("payment_method").and_then(Value::as_object) else {
        return (None, None);
    };
    let Some((pm, pm_value)) = payment_method_obj.iter().next() else {
        return (None, None);
    };

    let pmt = pm_value
        .get("card_type")
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .or_else(|| {
            pm_value
                .get("type")
                .and_then(Value::as_str)
                .map(ToString::to_string)
        });

    (Some(pm.clone()), pmt)
}

// ---------------------------------------------------------------------------
// Markdown generation
// ---------------------------------------------------------------------------

/// Canonical suite ordering for table rows.
const SUITE_ORDER: &[&str] = &[
    "create_access_token",
    "create_customer",
    "authorize",
    "capture",
    "void",
    "refund",
    "get",
    "refund_sync",
    "setup_recurring",
    "recurring_charge",
];

fn suite_service_name(suite: &str) -> &'static str {
    match suite {
        "create_access_token" => "MerchantAuthenticationService/CreateAccessToken",
        "create_customer" => "CustomerService/Create",
        "authorize" => "PaymentService/Authorize",
        "capture" => "PaymentService/Capture",
        "refund" => "PaymentService/Refund",
        "void" => "PaymentService/Void",
        "get" => "PaymentService/Get",
        "refund_sync" => "RefundService/Get",
        "setup_recurring" => "PaymentService/SetupRecurring",
        "recurring_charge" => "RecurringPaymentService/Charge",
        _ => "Unknown",
    }
}

fn suite_sort_key(suite: &str) -> usize {
    SUITE_ORDER
        .iter()
        .position(|&s| s == suite)
        .unwrap_or(usize::MAX)
}

/// Deduplicated, non-dependency entry keyed by (suite, scenario, connector).
#[derive(Debug, Clone)]
struct MatrixEntry {
    suite: String,
    scenario: String,
    connector: String,
    pm: String,
    pmt: String,
    result: String,
    error: Option<String>,
    response_status: Option<String>,
    run_at: u128,
    run_index: usize,
    dependency: Vec<String>,
    req_body: Option<Value>,
    res_body: Option<Value>,
    grpc_request: Option<String>,
    grpc_response: Option<String>,
}

const MASKED_VALUE: &str = "***MASKED***";

fn sanitize_report_entry_in_place(entry: &mut ReportEntry) {
    if let Some(error) = entry.error.as_mut() {
        *error = mask_sensitive_text(error);
    }

    if let Some(grpc_request) = entry.grpc_request.as_mut() {
        *grpc_request = mask_sensitive_text(grpc_request);
    }

    if let Some(grpc_response) = entry.grpc_response.as_mut() {
        *grpc_response = mask_sensitive_text(grpc_response);
    }

    if let Some(req_body) = entry.req_body.as_mut() {
        mask_json_value(req_body);
    }

    if let Some(res_body) = entry.res_body.as_mut() {
        mask_json_value(res_body);
    }
}

fn normalize_sensitive_key(key: &str) -> String {
    key.chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .map(|ch| ch.to_ascii_lowercase())
        .collect()
}

fn is_sensitive_key(key: &str) -> bool {
    let key = normalize_sensitive_key(key);
    key.contains("secret")
        || key.contains("token")
        || key.contains("password")
        || key.contains("authorization")
        || key == "apikey"
        || key == "xapikey"
        || key == "xauth"
        || key == "key1"
        || key == "xkey1"
        || key == "key2"
        || key == "xkey2"
        || key.contains("signature")
        || key.contains("cardnumber")
        || key.contains("cvv")
        || key.contains("cvc")
        || key == "expmonth"
        || key == "expyear"
}

fn mask_json_value(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                if is_sensitive_key(key) {
                    *child = Value::String(MASKED_VALUE.to_string());
                } else {
                    mask_json_value(child);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                mask_json_value(item);
            }
        }
        Value::String(text) => {
            *text = mask_sensitive_text(text);
        }
        _ => {}
    }
}

fn mask_sensitive_text(text: &str) -> String {
    let mut masked_lines = Vec::new();
    for line in text.lines() {
        let line = mask_sensitive_header_line(line);
        masked_lines.push(mask_bearer_tokens(&line));
    }
    masked_lines.join("\n")
}

fn mask_sensitive_header_line(line: &str) -> String {
    let Some(colon_index) = line.find(':') else {
        return line.to_string();
    };

    let key_candidate = line[..colon_index]
        .split_whitespace()
        .last()
        .unwrap_or_default()
        .trim_matches('"')
        .trim_matches('>')
        .trim_matches('<');

    if !is_sensitive_key(key_candidate) {
        return line.to_string();
    }

    let mut masked = format!("{} {}", &line[..=colon_index], MASKED_VALUE);
    if line[colon_index + 1..].contains('"') {
        masked.push('"');
    }
    if line.trim_end().ends_with('\\') {
        masked.push_str(" \\");
    }
    masked
}

fn mask_bearer_tokens(line: &str) -> String {
    let mut masked = line.to_string();
    let mut search_start = 0usize;

    loop {
        if search_start >= masked.len() {
            break;
        }

        let lowercase = masked.to_ascii_lowercase();
        let Some(relative_start) = lowercase[search_start..].find("bearer ") else {
            break;
        };

        let start = search_start + relative_start;

        let token_start = start + "bearer ".len();
        let token_end = masked[token_start..]
            .find(|ch: char| ch.is_whitespace() || ch == '"' || ch == '\'' || ch == ',')
            .map(|offset| token_start + offset)
            .unwrap_or(masked.len());

        if &masked[token_start..token_end] != MASKED_VALUE {
            masked.replace_range(token_start..token_end, MASKED_VALUE);
            search_start = token_start + MASKED_VALUE.len();
        } else {
            search_start = token_end;
        }
    }
    masked
}

#[derive(Debug, Clone)]
struct ConnectorResult {
    result: String,
}

fn scenario_detail_anchor(suite: &str, scenario: &str) -> String {
    format!(
        "scenario-detail-{}-{}",
        sanitize_anchor(suite),
        sanitize_anchor(scenario)
    )
}

fn scenario_detail_link(suite: &str, scenario: &str) -> String {
    let anchor = scenario_detail_anchor(suite, scenario);
    format!("[`{scenario}`](#{anchor})")
}

fn sanitize_anchor(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut last_was_hyphen = false;

    for ch in value.chars().flat_map(char::to_lowercase) {
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
            last_was_hyphen = false;
        } else if !last_was_hyphen {
            out.push('-');
            last_was_hyphen = true;
        }
    }

    while out.ends_with('-') {
        out.pop();
    }

    if out.is_empty() {
        "section".to_string()
    } else {
        out
    }
}

fn connector_anchor(connector: &str) -> String {
    format!("connector-{}", sanitize_anchor(connector))
}

fn scenario_connector_detail_anchor(suite: &str, scenario: &str, connector: &str) -> String {
    format!(
        "scenario-connector-detail-{}-{}-{}",
        sanitize_anchor(suite),
        sanitize_anchor(scenario),
        sanitize_anchor(connector)
    )
}

fn linked_result_cell(suite: &str, scenario: &str, connector: &str, result: &str) -> String {
    let anchor = scenario_connector_detail_anchor(suite, scenario, connector);
    format!("[{result}](#{anchor})")
}

fn split_dependency_label(label: &str) -> Option<(&str, &str)> {
    if !label.ends_with(')') {
        return None;
    }

    let open = label.rfind('(')?;
    if open == 0 {
        return None;
    }

    let suite = &label[..open];
    let scenario = &label[(open + 1)..(label.len() - 1)];
    if suite.is_empty() || scenario.is_empty() {
        return None;
    }

    Some((suite, scenario))
}

fn latest_dependency_entry_before(
    report: &ScenarioRunReport,
    main: &MatrixEntry,
    dependency_label: &str,
) -> Option<ReportEntry> {
    let (dep_suite, dep_scenario) = split_dependency_label(dependency_label)?;

    report.runs[..main.run_index]
        .iter()
        .rev()
        .find(|entry| {
            entry.is_dependency
                && entry.connector == main.connector
                && entry.suite == dep_suite
                && entry.scenario == dep_scenario
        })
        .cloned()
}

fn dependency_chain_summary(report: &ScenarioRunReport, main: &MatrixEntry) -> String {
    if main.dependency.is_empty() {
        return "None".to_string();
    }

    let mut chain = Vec::with_capacity(main.dependency.len());
    for dependency_label in &main.dependency {
        let status = latest_dependency_entry_before(report, main, dependency_label)
            .map(|entry| entry.assertion_result)
            .unwrap_or_else(|| "NOT_FOUND".to_string());
        chain.push(format!("`{dependency_label}` ({status})"));
    }

    chain.join(" -> ")
}

fn generate_md(json_path: &Path, report: &ScenarioRunReport) -> Result<(), String> {
    // 1. Filter out dependency entries and deduplicate by (suite, scenario, connector).
    //    When duplicates exist, keep the latest by run_at_epoch_ms.
    let mut deduped: BTreeMap<(String, String, String), MatrixEntry> = BTreeMap::new();

    for (run_index, entry) in report.runs.iter().enumerate() {
        if entry.is_dependency {
            continue;
        }

        let key = (
            entry.suite.clone(),
            entry.scenario.clone(),
            entry.connector.clone(),
        );

        let candidate = MatrixEntry {
            suite: entry.suite.clone(),
            scenario: entry.scenario.clone(),
            connector: entry.connector.clone(),
            pm: entry.pm.clone().unwrap_or_else(|| "-".to_string()),
            pmt: entry.pmt.clone().unwrap_or_else(|| "-".to_string()),
            result: entry.assertion_result.clone(),
            error: entry.error.clone(),
            response_status: entry.response_status.clone(),
            run_at: entry.run_at_epoch_ms,
            run_index,
            dependency: entry.dependency.clone(),
            req_body: entry.req_body.clone(),
            res_body: entry.res_body.clone(),
            grpc_request: entry.grpc_request.clone(),
            grpc_response: entry.grpc_response.clone(),
        };

        let should_insert = deduped
            .get(&key)
            // Keep latest result; if timestamps are equal (same millisecond),
            // prefer the later entry from report order by replacing on equality.
            .is_none_or(|existing| {
                candidate.run_at > existing.run_at
                    || (candidate.run_at == existing.run_at
                        && candidate.run_index >= existing.run_index)
            });

        if should_insert {
            deduped.insert(key, candidate);
        }
    }

    if deduped.is_empty() {
        let md = md_path(json_path);
        let _ = fs::write(
            &md,
            "# UCS Connector Test Report\n\n> No test results found.\n",
        );
        return Ok(());
    }

    // 2. Collect connectors (sorted) and unique rows keyed by (suite, scenario).
    let connectors: Vec<String> = {
        let mut set = BTreeSet::new();
        for entry in deduped.values() {
            set.insert(entry.connector.clone());
        }
        set.into_iter().collect()
    };

    // Row key = (suite_sort_key, scenario) for ordering.
    // We need (suite, scenario) -> { pm, pmt, per-connector result }.
    struct RowData {
        suite: String,
        scenario: String,
        pm: String,
        pmt: String,
        results: BTreeMap<String, ConnectorResult>,
    }

    let mut rows_map: BTreeMap<(usize, String, String), RowData> = BTreeMap::new();

    for entry in deduped.values() {
        let sort_key = suite_sort_key(&entry.suite);
        let row_key = (sort_key, entry.suite.clone(), entry.scenario.clone());

        let row = rows_map.entry(row_key).or_insert_with(|| RowData {
            suite: entry.suite.clone(),
            scenario: entry.scenario.clone(),
            pm: entry.pm.clone(),
            pmt: entry.pmt.clone(),
            results: BTreeMap::new(),
        });

        row.results.insert(
            entry.connector.clone(),
            ConnectorResult {
                result: entry.result.clone(),
            },
        );
    }

    // 3. Compute summary stats.
    let total_scenarios = rows_map.len();
    let total_connectors = connectors.len();
    let mut total_pass = 0usize;
    let mut total_fail = 0usize;
    for row in rows_map.values() {
        for result in row.results.values() {
            match result.result.as_str() {
                "PASS" => total_pass += 1,
                _ => total_fail += 1,
            }
        }
    }
    let total_cells = total_pass + total_fail;
    let pass_rate = percent(total_pass, total_cells);

    // 4. Build markdown string.
    let mut md = String::with_capacity(4096);

    // Header
    md.push_str("# UCS Connector Test Report\n\n");

    // Timestamp
    let epoch_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    md.push_str(&format!("> Generated: epoch {epoch_secs}\n\n"));

    // Table of contents
    md.push_str("## Table of Contents\n\n");
    md.push_str("- [Summary](#summary)\n");
    md.push_str("- [Scenario Performance Matrix](#scenario-performance-matrix)\n");
    md.push_str("- [Test Matrix](#test-matrix)\n");
    md.push_str("- [Scenario Details](#scenario-details)\n");
    md.push_str("- [Scenario Connector Details](#scenario-connector-details)\n");
    if total_fail > 0 {
        md.push_str("- [Failed Scenarios](#failed-scenarios)\n");
    }
    md.push_str("- [Results by Connector](#results-by-connector)\n");
    for connector in &connectors {
        let anchor = connector_anchor(connector);
        md.push_str(&format!("  - [{connector}](#{anchor})\n"));
    }
    md.push('\n');

    // Summary table
    md.push_str("## Summary\n\n");
    md.push_str("| Metric | Count |\n");
    md.push_str("|--------|------:|\n");
    md.push_str(&format!("| Connectors Tested | {total_connectors} |\n"));
    md.push_str(&format!("| Total Scenarios | {total_scenarios} |\n"));
    md.push_str(&format!("| Passed | {total_pass} |\n"));
    md.push_str(&format!("| Failed | {total_fail} |\n"));
    md.push_str(&format!("| Pass Rate | {pass_rate:.1}% |\n"));
    md.push_str("\n[Back to Table of Contents](#table-of-contents)\n");
    md.push_str("\n---\n\n");

    // Scenario Performance Matrix
    md.push_str("## Scenario Performance Matrix\n\n");
    md.push_str("<details>\n");
    md.push_str("<summary><strong>Show/Hide Scenario Performance Matrix</strong></summary>\n\n");
    md.push_str("| Scenario | PM | PMT | Connectors Tested | Passed | Failed | Pass Rate |\n");
    md.push_str("|:---------|:--:|:---:|------------------:|------:|------:|---------:|\n");

    for row in rows_map.values() {
        let scenario_cell = scenario_detail_link(&row.suite, &row.scenario);
        let tested_connectors = row.results.len();
        let passed_connectors = row
            .results
            .values()
            .filter(|result| result.result.as_str() == "PASS")
            .count();
        let scenario_pass_rate = percent(passed_connectors, tested_connectors);
        md.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {:.1}% |\n",
            scenario_cell,
            row.pm,
            row.pmt,
            tested_connectors,
            passed_connectors,
            tested_connectors.saturating_sub(passed_connectors),
            scenario_pass_rate
        ));
    }

    md.push_str("\n</details>\n\n");
    md.push_str("[Back to Table of Contents](#table-of-contents)\n\n");
    md.push_str("\n---\n\n");

    // Test Matrix — one flat table
    md.push_str("## Test Matrix\n\n");
    md.push_str("<details open>\n");
    md.push_str("<summary><strong>Show/Hide Test Matrix</strong></summary>\n\n");

    // Header row
    md.push_str("| Scenario | PM | PMT |");
    for connector in &connectors {
        md.push_str(&format!(" {} |", connector));
    }
    md.push('\n');

    // Alignment row
    md.push_str("|:---------|:--:|:---:|");
    for _ in &connectors {
        md.push_str(":------:|");
    }
    md.push('\n');

    // Data rows (already sorted by suite_sort_key then scenario)
    for row in rows_map.values() {
        let scenario_cell = scenario_detail_link(&row.suite, &row.scenario);
        md.push_str(&format!("| {} | {} | {} |", scenario_cell, row.pm, row.pmt));
        for connector in &connectors {
            if let Some(cell) = row.results.get(connector) {
                let linked = linked_result_cell(&row.suite, &row.scenario, connector, &cell.result);
                md.push_str(&format!(" {} |", linked));
            } else {
                md.push_str(" - |");
            }
        }
        md.push('\n');
    }

    md.push_str("\n</details>\n\n");
    md.push_str("[Back to Scenario Performance Matrix](#scenario-performance-matrix) | [Back to Table of Contents](#table-of-contents)\n\n");

    // Results grouped by connector
    md.push_str("## Results by Connector\n\n");
    for connector in &connectors {
        let anchor = connector_anchor(connector);

        let mut connector_total = 0usize;
        let mut connector_pass = 0usize;
        for row in rows_map.values() {
            if let Some(cell) = row.results.get(connector) {
                connector_total += 1;
                if cell.result == "PASS" {
                    connector_pass += 1;
                }
            }
        }
        let connector_fail = connector_total.saturating_sub(connector_pass);
        let connector_pass_rate = percent(connector_pass, connector_total);

        md.push_str(&format!("<a id=\"{anchor}\"></a>\n"));
        md.push_str("<details>\n");
        md.push_str(&format!(
            "<summary><strong>{connector}</strong> • Passed: {connector_pass}/{connector_total} • Failed: {connector_fail} • Pass Rate: {connector_pass_rate:.1}%</summary>\n\n"
        ));

        md.push_str("| Scenario | PM | PMT | Result |\n");
        md.push_str("|:---------|:--:|:---:|:------:|\n");

        for row in rows_map.values() {
            if let Some(cell) = row.results.get(connector) {
                let result_cell =
                    linked_result_cell(&row.suite, &row.scenario, connector, &cell.result);
                md.push_str(&format!(
                    "| {} | {} | {} | {} |\n",
                    scenario_detail_link(&row.suite, &row.scenario),
                    row.pm,
                    row.pmt,
                    result_cell,
                ));
            }
        }

        md.push_str("[Back to Results by Connector](#results-by-connector) | [Back to Table of Contents](#table-of-contents)\n\n");
        md.push_str("\n</details>\n\n");
    }

    md.push_str("[Back to Table of Contents](#table-of-contents)\n\n");

    md.push_str("## Scenario Details\n\n");
    for row in rows_map.values() {
        let detail_anchor = scenario_detail_anchor(&row.suite, &row.scenario);

        md.push_str(&format!("<a id=\"{detail_anchor}\"></a>\n"));
        md.push_str(&format!("### `{}`\n\n", row.scenario));
        md.push_str("| Property | Value |\n");
        md.push_str("|:---------|:------|\n");
        md.push_str(&format!("| Suite | `{}` |\n", row.suite));
        md.push_str(&format!(
            "| Service | `{}` |\n",
            suite_service_name(&row.suite)
        ));
        md.push_str(&format!("| PM / PMT | `{}` / `{}` |\n", row.pm, row.pmt));

        md.push_str("\n| Connector | Result | Prerequisites |\n");
        md.push_str("|:----------|:------:|:--------------|\n");
        for connector in &connectors {
            let key = (row.suite.clone(), row.scenario.clone(), connector.clone());
            if let Some(entry) = deduped.get(&key) {
                let linked_result =
                    linked_result_cell(&row.suite, &row.scenario, connector, &entry.result);
                let prerequisites = dependency_chain_summary(report, entry);
                md.push_str(&format!(
                    "| `{}` | {} | {} |\n",
                    connector, linked_result, prerequisites
                ));
            }
        }

        md.push_str(
            "\n[Back to Scenario Performance Matrix](#scenario-performance-matrix) | [Back to Test Matrix](#test-matrix) | [Back to Table of Contents](#table-of-contents)\n\n",
        );
    }

    md.push_str("[Back to Table of Contents](#table-of-contents)\n\n");

    md.push_str("---\n\n");
    md.push_str("## Scenario Connector Details\n\n");
    for row in rows_map.values() {
        for connector in &connectors {
            let key = (row.suite.clone(), row.scenario.clone(), connector.clone());
            let Some(entry) = deduped.get(&key) else {
                continue;
            };

            let detail_anchor =
                scenario_connector_detail_anchor(&row.suite, &row.scenario, connector);
            md.push_str(&format!("<a id=\"{detail_anchor}\"></a>\n"));
            md.push_str(&format!(
                "#### {} `{}` - connector `{}`\n\n",
                entry.result, row.scenario, connector
            ));
            md.push_str(&format!(
                "- Scenario: {}\n",
                scenario_detail_link(&row.suite, &row.scenario)
            ));
            md.push_str(&format!("- Suite: `{}`\n", row.suite));
            md.push_str(&format!(
                "- Service: `{}`\n",
                suite_service_name(&row.suite)
            ));
            md.push_str(&format!("- Connector: `{}`\n", connector));
            md.push_str(&format!("- PM / PMT: `{}` / `{}`\n", row.pm, row.pmt));
            md.push_str(&format!("- Result: `{}`\n", entry.result));
            if let Some(status) = &entry.response_status {
                md.push_str(&format!("- Response Status: `{status}`\n"));
            }
            if let Some(error) = &entry.error {
                md.push_str("\n**Error**\n\n");
                md.push_str("```text\n");
                md.push_str(error);
                md.push_str("\n```\n");
            }

            md.push_str("\n**Pre Requisites Executed**\n\n");
            if entry.dependency.is_empty() {
                md.push_str("- None\n");
            } else {
                for (index, dependency_label) in entry.dependency.iter().enumerate() {
                    if let Some(dep_entry) =
                        latest_dependency_entry_before(report, entry, dependency_label)
                    {
                        md.push_str("<details>\n");
                        md.push_str(&format!(
                            "<summary>{}. {} — {}</summary>\n\n",
                            index + 1,
                            dependency_label,
                            dep_entry.assertion_result
                        ));
                        if let Some(dep_error) = dep_entry.error.as_deref() {
                            md.push_str("**Dependency Error**\n\n");
                            md.push_str("```text\n");
                            md.push_str(dep_error);
                            md.push_str("\n```\n\n");
                        }
                        md.push_str("**gRPC Request (masked)**\n\n");
                        if let Some(grpc_request) = dep_entry.grpc_request.as_deref() {
                            md.push_str("```bash\n");
                            md.push_str(grpc_request);
                            md.push_str("\n```\n\n");
                        } else {
                            md.push_str("_gRPC request trace not available._\n\n");
                        }
                        md.push_str("**gRPC Response (masked)**\n\n");
                        if let Some(grpc_response) = dep_entry.grpc_response.as_deref() {
                            md.push_str("```text\n");
                            md.push_str(grpc_response);
                            md.push_str("\n```\n\n");
                        } else {
                            md.push_str("_gRPC response trace not available._\n\n");
                        }
                        md.push_str("**Request Body**\n\n");
                        if let Some(req_body) = dep_entry.req_body.as_ref() {
                            if let Ok(pretty) = serde_json::to_string_pretty(req_body) {
                                md.push_str("```json\n");
                                md.push_str(&pretty);
                                md.push_str("\n```\n\n");
                            } else {
                                md.push_str("_Request body serialization failed._\n\n");
                            }
                        } else {
                            md.push_str("_Request body not available._\n\n");
                        }
                        md.push_str("**Response Body**\n\n");
                        if let Some(res_body) = dep_entry.res_body.as_ref() {
                            if let Ok(pretty) = serde_json::to_string_pretty(res_body) {
                                md.push_str("```json\n");
                                md.push_str(&pretty);
                                md.push_str("\n```\n\n");
                            } else {
                                md.push_str("_Response body serialization failed._\n\n");
                            }
                        } else {
                            md.push_str("_Response body not available._\n\n");
                        }
                        md.push_str("</details>\n");
                    } else {
                        md.push_str(&format!(
                            "- {}. {} — NOT_FOUND\n",
                            index + 1,
                            dependency_label
                        ));
                    }
                }
            }

            md.push_str("\n<details>\n");
            md.push_str("<summary>Show Details (Main Scenario Request/Response)</summary>\n\n");
            md.push_str("**gRPC Request (masked)**\n\n");
            if let Some(grpc_request) = entry.grpc_request.as_deref() {
                md.push_str("```bash\n");
                md.push_str(grpc_request);
                md.push_str("\n```\n\n");
            } else {
                md.push_str("_gRPC request trace not available._\n\n");
            }
            md.push_str("**gRPC Response (masked)**\n\n");
            if let Some(grpc_response) = entry.grpc_response.as_deref() {
                md.push_str("```text\n");
                md.push_str(grpc_response);
                md.push_str("\n```\n\n");
            } else {
                md.push_str("_gRPC response trace not available._\n\n");
            }
            md.push_str("**Request Body**\n\n");
            if let Some(req_body) = entry.req_body.as_ref() {
                if let Ok(pretty) = serde_json::to_string_pretty(req_body) {
                    md.push_str("```json\n");
                    md.push_str(&pretty);
                    md.push_str("\n```\n\n");
                } else {
                    md.push_str("_Request body serialization failed._\n\n");
                }
            } else {
                md.push_str("_Request body not available._\n\n");
            }
            md.push_str("**Response Body**\n\n");
            if let Some(res_body) = entry.res_body.as_ref() {
                if let Ok(pretty) = serde_json::to_string_pretty(res_body) {
                    md.push_str("```json\n");
                    md.push_str(&pretty);
                    md.push_str("\n```\n\n");
                } else {
                    md.push_str("_Response body serialization failed._\n\n");
                }
            } else {
                md.push_str("_Response body not available._\n\n");
            }
            md.push_str("</details>\n\n");
            let scenario_anchor = scenario_detail_anchor(&row.suite, &row.scenario);
            md.push_str(&format!(
                "[Back to Scenario Detail](#{scenario_anchor}) | [Back to Scenario Performance Matrix](#scenario-performance-matrix) | [Back to Test Matrix](#test-matrix) | [Back to Table of Contents](#table-of-contents)\n\n"
            ));
            md.push_str("---\n\n");
        }
    }

    md.push_str("[Back to Table of Contents](#table-of-contents)\n\n");

    let mut failures: Vec<(String, String, String)> = Vec::new();
    for row in rows_map.values() {
        for connector in &connectors {
            if let Some(cell) = row.results.get(connector) {
                if cell.result != "PASS" {
                    failures.push((row.suite.clone(), row.scenario.clone(), connector.clone()));
                }
            }
        }
    }

    if !failures.is_empty() {
        md.push_str("## Failed Scenarios\n\n");
        for (suite, scenario, connector) in failures {
            let anchor = scenario_connector_detail_anchor(&suite, &scenario, &connector);
            md.push_str(&format!(
                "- [{} / {} / {}](#{})\n",
                suite, scenario, connector, anchor
            ));
        }
        md.push_str("\n[Back to Table of Contents](#table-of-contents)\n\n");
    }

    // 5. Write
    let out_path = md_path(json_path);
    fs::write(&out_path, &md)
        .map_err(|e| format!("failed to write markdown '{}': {e}", out_path.display()))
}

fn percent(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        return 0.0;
    }

    let safe_num = u32::try_from(numerator).unwrap_or(u32::MAX);
    let safe_den = u32::try_from(denominator).unwrap_or(u32::MAX);

    (f64::from(safe_num) / f64::from(safe_den)) * 100.0
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn extract_pm_and_pmt_from_card_request() {
        let req = serde_json::json!({
            "payment_method": {
                "card": {
                    "card_type": "credit",
                    "card_number": {"value": "4111111111111111"}
                }
            }
        });
        let (pm, pmt) = extract_pm_and_pmt(Some(&req));
        assert_eq!(pm.as_deref(), Some("card"));
        assert_eq!(pmt.as_deref(), Some("credit"));
    }

    #[test]
    fn extract_pm_and_pmt_missing() {
        let req = serde_json::json!({"amount": 1000});
        let (pm, pmt) = extract_pm_and_pmt(Some(&req));
        assert!(pm.is_none());
        assert!(pmt.is_none());
    }

    #[test]
    fn suite_ordering_is_consistent() {
        assert!(suite_sort_key("create_access_token") < suite_sort_key("authorize"));
        assert!(suite_sort_key("authorize") < suite_sort_key("capture"));
        assert!(suite_sort_key("capture") < suite_sort_key("refund"));
        assert!(suite_sort_key("refund") < suite_sort_key("get"));
        assert!(suite_sort_key("get") < suite_sort_key("refund_sync"));
        assert!(suite_sort_key("refund_sync") < suite_sort_key("setup_recurring"));
        assert!(suite_sort_key("setup_recurring") < suite_sort_key("recurring_charge"));
    }

    #[test]
    fn generated_markdown_uses_plain_status_without_badges() {
        let temp_root = std::env::temp_dir().join(format!("ucs-report-{}", now_epoch_ms()));
        fs::create_dir_all(&temp_root).expect("temp dir should be creatable");
        let json_path = temp_root.join("report.json");

        let report = ScenarioRunReport {
            runs: vec![
                ReportEntry {
                    run_at_epoch_ms: now_epoch_ms(),
                    suite: "authorize".to_string(),
                    scenario: "no3ds_auto_capture_credit_card".to_string(),
                    connector: "stripe".to_string(),
                    pm: Some("card".to_string()),
                    pmt: Some("credit".to_string()),
                    endpoint: "localhost:8000".to_string(),
                    is_dependency: false,
                    assertion_result: "PASS".to_string(),
                    response_status: None,
                    error: None,
                    dependency: vec![],
                    req_body: Some(serde_json::json!({"field": "value"})),
                    res_body: Some(serde_json::json!({"status": "CHARGED"})),
                    grpc_request: None,
                    grpc_response: None,
                },
                ReportEntry {
                    run_at_epoch_ms: now_epoch_ms(),
                    suite: "authorize".to_string(),
                    scenario: "no3ds_auto_capture_credit_card".to_string(),
                    connector: "paypal".to_string(),
                    pm: Some("card".to_string()),
                    pmt: Some("credit".to_string()),
                    endpoint: "localhost:8000".to_string(),
                    is_dependency: false,
                    assertion_result: "FAIL".to_string(),
                    response_status: None,
                    error: Some("forced failure".to_string()),
                    dependency: vec!["create_customer(create_customer)".to_string()],
                    req_body: Some(serde_json::json!({"field": "value"})),
                    res_body: Some(serde_json::json!({"error": "forced failure"})),
                    grpc_request: None,
                    grpc_response: None,
                },
            ],
        };

        generate_md(&json_path, &report).expect("markdown generation should succeed");

        let md_path = md_path(&json_path);
        let content = fs::read_to_string(&md_path).expect("generated markdown should be readable");

        assert!(!content.contains("img.shields.io"));
        assert!(!content.contains("![Result]"));
        assert!(!content.contains("![Pass Rate]"));
        assert!(!content.contains("![Passed]"));
        assert!(!content.contains("![Failed]"));

        assert!(content.contains("| Passed | 1 |"));
        assert!(content.contains("| Failed | 1 |"));
        assert!(content.contains("| Pass Rate | 50.0% |"));
        assert!(content.contains(
            "[PASS](#scenario-connector-detail-authorize-no3ds-auto-capture-credit-card-stripe)"
        ));
        assert!(content.contains(
            "[FAIL](#scenario-connector-detail-authorize-no3ds-auto-capture-credit-card-paypal)"
        ));

        let _ = fs::remove_file(md_path);
        let _ = fs::remove_dir_all(temp_root);
    }

    #[test]
    fn sanitization_masks_sensitive_grpc_trace_and_json_fields() {
        let mut entry = ReportEntry {
            run_at_epoch_ms: now_epoch_ms(),
            suite: "authorize".to_string(),
            scenario: "no3ds_auto_capture_credit_card".to_string(),
            connector: "stripe".to_string(),
            pm: Some("card".to_string()),
            pmt: Some("credit".to_string()),
            endpoint: "localhost:50051".to_string(),
            is_dependency: false,
            assertion_result: "PASS".to_string(),
            response_status: None,
            error: Some("Authorization: Bearer token123".to_string()),
            dependency: vec![],
            req_body: Some(serde_json::json!({
                "api_key": "sk_test_123",
                "payment_method": {
                    "card": {
                        "card_number": {"value": "4111111111111111"},
                        "card_cvc": "123"
                    }
                }
            })),
            res_body: Some(serde_json::json!({
                "access_token": "access_token_value"
            })),
            grpc_request: Some(
                "grpcurl -plaintext \\\n+  -H \"x-api-key: sk_test_123\" \\\n+  -H \"authorization: Bearer token123\" \\\n+  -d @ localhost:50051 types.PaymentService/Authorize <<'JSON'"
                    .to_string(),
            ),
            grpc_response: Some(
                "Response headers received:\nauthorization: Bearer token123\nx-api-key: sk_test_123"
                    .to_string(),
            ),
        };

        sanitize_report_entry_in_place(&mut entry);

        let grpc_request = entry.grpc_request.expect("grpc request should exist");
        let grpc_response = entry.grpc_response.expect("grpc response should exist");
        let error = entry.error.expect("error should exist");

        assert!(!grpc_request.contains("sk_test_123"));
        assert!(!grpc_request.contains("token123"));
        assert!(!grpc_response.contains("sk_test_123"));
        assert!(!grpc_response.contains("token123"));
        assert!(!error.contains("token123"));
        assert!(grpc_request.contains(MASKED_VALUE));
        assert!(grpc_response.contains(MASKED_VALUE));
        assert!(error.contains(MASKED_VALUE));

        let req_body = entry.req_body.expect("request body should exist");
        let res_body = entry.res_body.expect("response body should exist");

        assert_eq!(req_body["api_key"], MASKED_VALUE);
        assert_eq!(
            req_body["payment_method"]["card"]["card_number"],
            MASKED_VALUE
        );
        assert_eq!(req_body["payment_method"]["card"]["card_cvc"], MASKED_VALUE);
        assert_eq!(res_body["access_token"], MASKED_VALUE);
    }

    #[test]
    fn bearer_masking_is_idempotent_and_masks_multiple_tokens() {
        let line = "authorization: Bearer abc123 Bearer ***MASKED*** Bearer def456";
        let masked_once = mask_bearer_tokens(line);
        let masked_twice = mask_bearer_tokens(&masked_once);

        assert_eq!(masked_once, masked_twice);
        assert!(!masked_once.contains("abc123"));
        assert!(!masked_once.contains("def456"));
    }
}
