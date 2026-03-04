use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use crate::summary::schema::CapabilityRow;

const REQUIRED_KEYS: [&str; 8] = [
    "capability_id",
    "connector",
    "layer",
    "flow",
    "payment_method",
    "scenario",
    "support",
    "expected",
];

pub fn load_rows_from_test_annotations() -> Result<Vec<CapabilityRow>, String> {
    let tests_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut rows = Vec::new();
    let mut errors = Vec::new();

    let connectors = fs::read_dir(&tests_root)
        .map_err(|err| format!("failed to read tests directory '{tests_root:?}': {err}"))?;

    for connector_entry in connectors.flatten() {
        let connector_path = connector_entry.path();
        if !connector_path.is_dir() {
            continue;
        }

        let connector = connector_entry.file_name().to_string_lossy().to_string();
        let suites_dir = connector_path.join("suites");
        if !suites_dir.exists() || !suites_dir.is_dir() {
            continue;
        }

        let suite_files = match fs::read_dir(&suites_dir) {
            Ok(dir) => dir,
            Err(err) => {
                errors.push(format!(
                    "failed to read suites directory '{suites_dir:?}': {err}"
                ));
                continue;
            }
        };

        for suite_file_entry in suite_files.flatten() {
            let suite_file_path = suite_file_entry.path();
            let is_rs = suite_file_path.extension().is_some_and(|ext| ext == "rs");
            if !is_rs {
                continue;
            }

            parse_suite_file(&suite_file_path, &connector, &mut rows, &mut errors);
        }
    }

    let mut capability_id_to_test_name = BTreeMap::new();
    for row in &rows {
        if let Some(previous) =
            capability_id_to_test_name.insert(row.capability_id.clone(), row.test_name.clone())
        {
            errors.push(format!(
                "duplicate capability_id '{}' for tests '{}' and '{}'",
                row.capability_id, previous, row.test_name
            ));
        }
    }

    if !errors.is_empty() {
        return Err(errors.join("\n"));
    }

    rows.sort_by(|a, b| a.test_name.cmp(&b.test_name));
    if rows.is_empty() {
        return Err("no capability annotations found in tests".to_string());
    }

    Ok(rows)
}

fn parse_suite_file(
    suite_file_path: &Path,
    connector: &str,
    rows: &mut Vec<CapabilityRow>,
    errors: &mut Vec<String>,
) {
    let contents = match fs::read_to_string(suite_file_path) {
        Ok(value) => value,
        Err(err) => {
            errors.push(format!("failed to read file '{suite_file_path:?}': {err}"));
            return;
        }
    };

    let module_name = suite_file_path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("unknown");

    let mut pending: BTreeMap<String, String> = BTreeMap::new();

    for (line_index, line) in contents.lines().enumerate() {
        let line_no = line_index + 1;
        let trimmed = line.trim();

        if let Some(rest) = trimmed.strip_prefix("/// @capability ") {
            let mut parts = rest.splitn(2, '=');
            let key = parts.next().unwrap_or_default().trim();
            let value = parts.next().unwrap_or_default().trim();
            if key.is_empty() || value.is_empty() {
                errors.push(format!(
                    "{}:{} invalid capability annotation '{trimmed}'",
                    suite_file_path.display(),
                    line_no
                ));
            } else {
                pending.insert(key.to_string(), value.to_string());
            }
            continue;
        }

        let Some(function_name) = extract_test_function_name(trimmed) else {
            continue;
        };

        if pending.is_empty() {
            errors.push(format!(
                "{}:{} test '{}' missing capability annotations",
                suite_file_path.display(),
                line_no,
                function_name
            ));
            continue;
        }

        let mut missing_keys = Vec::new();
        for required_key in REQUIRED_KEYS {
            if !pending.contains_key(required_key) {
                missing_keys.push(required_key);
            }
        }
        if !missing_keys.is_empty() {
            errors.push(format!(
                "{}:{} test '{}' missing capability keys: {}",
                suite_file_path.display(),
                line_no,
                function_name,
                missing_keys.join(",")
            ));
            pending.clear();
            continue;
        }

        let annotation_connector = pending
            .get("connector")
            .expect("validated required key connector");
        if annotation_connector != connector {
            errors.push(format!(
                "{}:{} test '{}' has connector '{}' but file connector is '{}'",
                suite_file_path.display(),
                line_no,
                function_name,
                annotation_connector,
                connector
            ));
            pending.clear();
            continue;
        }

        rows.push(CapabilityRow {
            capability_id: pending
                .get("capability_id")
                .expect("validated required key capability_id")
                .clone(),
            connector: annotation_connector.clone(),
            layer: pending
                .get("layer")
                .expect("validated required key layer")
                .clone(),
            flow: pending
                .get("flow")
                .expect("validated required key flow")
                .clone(),
            payment_method: pending
                .get("payment_method")
                .expect("validated required key payment_method")
                .clone(),
            payment_method_subtype: pending.get("payment_method_subtype").cloned(),
            scenario: pending
                .get("scenario")
                .expect("validated required key scenario")
                .clone(),
            support: pending
                .get("support")
                .expect("validated required key support")
                .clone(),
            expected: pending
                .get("expected")
                .expect("validated required key expected")
                .clone(),
            fallback: pending.get("fallback").cloned(),
            test_name: format!("{connector}::suites::{module_name}::{function_name}"),
        });

        let last_row = rows.last().expect("row was just pushed");
        if last_row.payment_method == "card" && last_row.payment_method_subtype.is_none() {
            errors.push(format!(
                "{}:{} test '{}' must define payment_method_subtype for card scenarios",
                suite_file_path.display(),
                line_no,
                function_name
            ));
            rows.pop();
            pending.clear();
            continue;
        }

        pending.clear();
    }
}

fn extract_test_function_name(line: &str) -> Option<String> {
    if !line.contains("async fn test_") {
        return None;
    }

    let start = line.find("async fn ")? + "async fn ".len();
    let rest = &line[start..];
    let end = rest
        .find(|c: char| c == '(' || c.is_whitespace())
        .unwrap_or(rest.len());
    let function_name = &rest[..end];

    if function_name.starts_with("test_") {
        Some(function_name.to_string())
    } else {
        None
    }
}
