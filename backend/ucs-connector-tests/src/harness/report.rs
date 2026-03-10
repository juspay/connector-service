#![allow(clippy::print_stderr)]

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
    pub run_at_epoch_ms: u128,
    pub suite: String,
    pub scenario: String,
    pub connector: String,
    pub pm: Option<String>,
    pub pmt: Option<String>,
    pub endpoint: String,
    #[serde(default)]
    pub is_dependency: bool,
    pub assertion_result: String,
    pub response_status: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ScenarioRunReport {
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

pub fn append_report(entry: ReportEntry) -> Result<(), String> {
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

    report.runs.push(entry);

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

pub fn append_report_best_effort(entry: ReportEntry) {
    if let Err(e) = append_report(entry) {
        eprintln!("[report] write failed: {e}");
    }
}

// ---------------------------------------------------------------------------
// Helpers shared by binaries
// ---------------------------------------------------------------------------

pub fn now_epoch_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

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
    run_at: u128,
}

fn generate_md(json_path: &Path, report: &ScenarioRunReport) -> Result<(), String> {
    // 1. Filter out dependency entries and deduplicate by (suite, scenario, connector).
    //    When duplicates exist, keep the latest by run_at_epoch_ms.
    let mut deduped: BTreeMap<(String, String, String), MatrixEntry> = BTreeMap::new();

    for entry in &report.runs {
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
            run_at: entry.run_at_epoch_ms,
        };

        let should_insert = deduped
            .get(&key)
            .is_none_or(|existing| candidate.run_at > existing.run_at);

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
        results: BTreeMap<String, String>, // connector -> PASS/FAIL
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

        row.results
            .insert(entry.connector.clone(), entry.result.clone());
    }

    // 3. Compute summary stats.
    let total_scenarios = rows_map.len();
    let total_connectors = connectors.len();
    let mut total_pass = 0usize;
    let mut total_fail = 0usize;
    for row in rows_map.values() {
        for result in row.results.values() {
            match result.as_str() {
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

    // Summary table
    md.push_str("## Summary\n\n");
    md.push_str("| Metric | Count |\n");
    md.push_str("|--------|------:|\n");
    md.push_str(&format!("| Connectors Tested | {total_connectors} |\n"));
    md.push_str(&format!("| Total Scenarios | {total_scenarios} |\n"));
    md.push_str(&format!("| Passed | {total_pass} |\n"));
    md.push_str(&format!("| Failed | {total_fail} |\n"));
    md.push_str(&format!("| Pass Rate | {pass_rate:.1}% |\n"));
    md.push_str("\n---\n\n");

    // Scenario Performance Matrix
    md.push_str("## Scenario Performance Matrix\n\n");
    md.push_str(
        "| Scenario | Suite | Service | PM | PMT | Connectors Tested | Passed | Failed | Pass Rate |\n",
    );
    md.push_str(
        "|:---------|:------|:--------|:--:|:---:|------------------:|------:|------:|---------:|\n",
    );

    for row in rows_map.values() {
        let service = suite_service_name(&row.suite);
        let tested_connectors = row.results.len();
        let passed_connectors = row
            .results
            .values()
            .filter(|result| result.as_str() == "PASS")
            .count();
        let scenario_pass_rate = percent(passed_connectors, tested_connectors);
        md.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {:.1}% |\n",
            row.scenario,
            row.suite,
            service,
            row.pm,
            row.pmt,
            tested_connectors,
            passed_connectors,
            tested_connectors.saturating_sub(passed_connectors),
            scenario_pass_rate
        ));
    }

    md.push_str("\n---\n\n");

    // Test Matrix — one flat table
    md.push_str("## Test Matrix\n\n");

    // Header row
    md.push_str("| Scenario | Suite | Service | PM | PMT |");
    for connector in &connectors {
        md.push_str(&format!(" {} |", connector));
    }
    md.push('\n');

    // Alignment row
    md.push_str("|:---------|:------|:--------|:--:|:---:|");
    for _ in &connectors {
        md.push_str(":------:|");
    }
    md.push('\n');

    // Data rows (already sorted by suite_sort_key then scenario)
    for row in rows_map.values() {
        let service = suite_service_name(&row.suite);
        md.push_str(&format!(
            "| {} | {} | {} | {} | {} |",
            row.scenario, row.suite, service, row.pm, row.pmt
        ));
        for connector in &connectors {
            let cell = row
                .results
                .get(connector)
                .map(|s| s.as_str())
                .unwrap_or("-");
            md.push_str(&format!(" {} |", cell));
        }
        md.push('\n');
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
}
