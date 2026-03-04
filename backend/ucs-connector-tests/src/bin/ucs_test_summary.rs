use std::collections::{BTreeMap, BTreeSet};

use ucs_connector_tests::summary::{parser, schema::CapabilityRow};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OutputFormat {
    Table,
    Markdown,
    Json,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TestNameView {
    None,
    Section,
    Inline,
}

#[derive(Debug)]
struct CliArgs {
    connector: Option<String>,
    flow: Option<String>,
    format: OutputFormat,
    capabilities_only: bool,
    show_test_names: bool,
    test_name_view: TestNameView,
}

fn parse_args() -> Result<CliArgs, String> {
    let mut connector = None;
    let mut flow = None;
    let mut format = OutputFormat::Table;
    let mut capabilities_only = false;
    let mut show_test_names = false;
    let mut test_name_view = TestNameView::None;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--connector" => {
                connector = Some(args.next().ok_or("missing value for --connector")?);
            }
            "--flow" => {
                flow = Some(args.next().ok_or("missing value for --flow")?);
            }
            "--format" => {
                let value = args.next().ok_or("missing value for --format")?;
                format = match value.as_str() {
                    "table" => OutputFormat::Table,
                    "markdown" => OutputFormat::Markdown,
                    "json" => OutputFormat::Json,
                    _ => return Err(format!("unsupported format: {value}")),
                };
            }
            "--capabilities-only" => {
                capabilities_only = true;
            }
            "--show-test-names" => {
                show_test_names = true;
                test_name_view = TestNameView::Section;
            }
            "--test-name-view" => {
                let value = args.next().ok_or("missing value for --test-name-view")?;
                test_name_view = match value.as_str() {
                    "none" => TestNameView::None,
                    "section" => TestNameView::Section,
                    "inline" => TestNameView::Inline,
                    _ => return Err(format!("unsupported test-name-view: {value}")),
                };
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            _ => {
                return Err(format!("unknown arg: {arg}"));
            }
        }
    }

    Ok(CliArgs {
        connector,
        flow,
        format,
        capabilities_only,
        show_test_names,
        test_name_view,
    })
}

fn print_help() {
    println!(
        "ucs-test-summary\n\
         Reads @capability annotations from tests/*/suites/*.rs\n\
         Usage:\n\
           cargo run -p ucs-connector-tests --bin ucs_test_summary -- [options]\n\n\
         Options:\n\
            --connector <name>       Filter by connector (e.g. authorizedotnet)\n\
            --flow <name>            Filter by flow (e.g. authorize, capture, refund)\n\
            --format <table|markdown|json>  Output format (default: table)\n\
            --capabilities-only      Print aggregated capability view\n\
           --show-test-names        Include mapped test names as a section (legacy shortcut)\n\
           --test-name-view <none|section|inline>  Test-name rendering in capability output\n\
            --help                   Show this help\n"
    );
}

fn all_rows() -> Result<Vec<CapabilityRow>, String> {
    parser::load_rows_from_test_annotations()
}

fn filter_rows(rows: Vec<CapabilityRow>, args: &CliArgs) -> Vec<CapabilityRow> {
    rows.into_iter()
        .filter(|row| {
            args.connector
                .as_ref()
                .map_or(true, |connector| row.connector == *connector)
        })
        .filter(|row| args.flow.as_ref().map_or(true, |flow| row.flow == *flow))
        .collect()
}

fn method_profile(row: &CapabilityRow) -> String {
    match row.payment_method_subtype.as_ref() {
        Some(subtype) => format!("{}/{}", row.payment_method, subtype),
        None => row.payment_method.clone(),
    }
}

fn print_table(rows: &[CapabilityRow]) {
    let headers = [
        "capability_id",
        "connector",
        "flow",
        "method_profile",
        "scenario",
        "support",
        "expected",
        "fallback",
        "test_name",
    ];

    let mut widths = headers.map(|h| h.len());
    for row in rows {
        widths[0] = widths[0].max(row.capability_id.len());
        widths[1] = widths[1].max(row.connector.len());
        widths[2] = widths[2].max(row.flow.len());
        widths[3] = widths[3].max(method_profile(row).len());
        widths[4] = widths[4].max(row.scenario.len());
        widths[5] = widths[5].max(row.support.len());
        widths[6] = widths[6].max(row.expected.len());
        widths[7] = widths[7].max(row.fallback.as_deref().unwrap_or("-").len());
        widths[8] = widths[8].max(row.test_name.len());
    }

    println!(
        "{:<w0$}  {:<w1$}  {:<w2$}  {:<w3$}  {:<w4$}  {:<w5$}  {:<w6$}  {:<w7$}  {:<w8$}",
        headers[0],
        headers[1],
        headers[2],
        headers[3],
        headers[4],
        headers[5],
        headers[6],
        headers[7],
        headers[8],
        w0 = widths[0],
        w1 = widths[1],
        w2 = widths[2],
        w3 = widths[3],
        w4 = widths[4],
        w5 = widths[5],
        w6 = widths[6],
        w7 = widths[7],
        w8 = widths[8],
    );

    for row in rows {
        println!(
            "{:<w0$}  {:<w1$}  {:<w2$}  {:<w3$}  {:<w4$}  {:<w5$}  {:<w6$}  {:<w7$}  {:<w8$}",
            row.capability_id,
            row.connector,
            row.flow,
            method_profile(row),
            row.scenario,
            row.support,
            row.expected,
            row.fallback.as_deref().unwrap_or("-"),
            row.test_name,
            w0 = widths[0],
            w1 = widths[1],
            w2 = widths[2],
            w3 = widths[3],
            w4 = widths[4],
            w5 = widths[5],
            w6 = widths[6],
            w7 = widths[7],
            w8 = widths[8],
        );
    }
}

fn print_rows_markdown(rows: &[CapabilityRow]) {
    println!("| capability_id | connector | flow | method_profile | scenario | support | expected | fallback | test_name |");
    println!("|---|---|---|---|---|---|---|---|---|");
    for row in rows {
        println!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | `{}` |",
            row.capability_id,
            row.connector,
            row.flow,
            method_profile(row),
            row.scenario,
            row.support,
            row.expected,
            row.fallback.as_deref().unwrap_or("-"),
            row.test_name
        );
    }
}

fn print_capabilities_table(rows: &[CapabilityRow], test_name_view: TestNameView) {
    let mut grouped: BTreeMap<(String, String, String), Vec<&CapabilityRow>> = BTreeMap::new();
    for row in rows {
        grouped
            .entry((row.connector.clone(), row.flow.clone(), method_profile(row)))
            .or_default()
            .push(row);
    }

    println!("connector        flow           method_profile  supports                               test_count  refs");
    for ((connector, flow, method_profile), variants) in grouped {
        let supports = variants
            .iter()
            .map(|r| r.support.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .join(",");

        let tests = variants
            .iter()
            .map(|r| r.test_name.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();

        let refs = variants
            .iter()
            .map(|r| r.capability_id.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .join(",");

        println!(
            "{connector:<15}  {flow:<13}  {method_profile:<14}  {supports:<37}  {:<10}  {refs}",
            tests.len(),
        );

        match test_name_view {
            TestNameView::None => {}
            TestNameView::Inline => {
                let mut refs_with_names = variants
                    .iter()
                    .map(|r| (r.capability_id.clone(), r.test_name.clone()))
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>();
                refs_with_names.sort_by(|a, b| a.0.cmp(&b.0));

                for (capability_id, test_name) in refs_with_names {
                    println!("  - {capability_id} {test_name}");
                }
            }
            TestNameView::Section => {
                println!("\n  references for {connector}/{flow}/{method_profile}:");
                let mut refs_with_names = variants
                    .iter()
                    .map(|r| (r.capability_id.clone(), r.test_name.clone()))
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>();
                refs_with_names.sort_by(|a, b| a.0.cmp(&b.0));

                for (capability_id, test_name) in refs_with_names {
                    println!("    {capability_id} {test_name}");
                }
                println!();
            }
        }
    }
}

fn print_capabilities_markdown(rows: &[CapabilityRow], test_name_view: TestNameView) {
    let mut grouped: BTreeMap<(String, String, String), Vec<&CapabilityRow>> = BTreeMap::new();
    for row in rows {
        grouped
            .entry((row.connector.clone(), row.flow.clone(), method_profile(row)))
            .or_default()
            .push(row);
    }

    println!("| connector | flow | method_profile | supports | test_count | refs |");
    println!("|---|---|---|---|---:|---|");
    for ((connector, flow, method_profile), variants) in &grouped {
        let supports = variants
            .iter()
            .map(|r| r.support.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .join(",");
        let tests = variants
            .iter()
            .map(|r| r.test_name.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let refs = variants
            .iter()
            .map(|r| r.capability_id.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .join(",");

        println!(
            "| {} | {} | {} | {} | {} | {} |",
            connector,
            flow,
            method_profile,
            supports,
            tests.len(),
            refs
        );
    }

    if test_name_view == TestNameView::Section {
        println!("\n### Test References");
        for ((connector, flow, method_profile), variants) in grouped {
            let mut tests = variants
                .iter()
                .map(|r| (r.capability_id.clone(), r.test_name.clone()))
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            tests.sort_by(|a, b| a.0.cmp(&b.0));
            println!("- `{}/{}/{}`", connector, flow, method_profile);
            for (capability_id, test_name) in tests {
                println!("  - {} `{}`", capability_id, test_name);
            }
        }
    }
}

fn main() {
    let args = match parse_args() {
        Ok(value) => value,
        Err(err) => {
            eprintln!("Argument error: {err}");
            eprintln!("Use --help for usage");
            std::process::exit(2);
        }
    };

    let all_rows = match all_rows() {
        Ok(rows) => rows,
        Err(err) => {
            eprintln!("Failed to load capability annotations:\n{err}");
            std::process::exit(2);
        }
    };

    let rows = filter_rows(all_rows, &args);
    if rows.is_empty() {
        eprintln!("No matching summary rows found.");
        std::process::exit(1);
    }

    if args.capabilities_only {
        let name_view = if args.show_test_names {
            TestNameView::Section
        } else {
            args.test_name_view
        };

        match args.format {
            OutputFormat::Table => print_capabilities_table(&rows, name_view),
            OutputFormat::Markdown => print_capabilities_markdown(&rows, name_view),
            OutputFormat::Json => {
                let mut grouped: BTreeMap<(String, String, String), Vec<&CapabilityRow>> =
                    BTreeMap::new();
                for row in &rows {
                    grouped
                        .entry((row.connector.clone(), row.flow.clone(), method_profile(row)))
                        .or_default()
                        .push(row);
                }
                let value = grouped
                    .into_iter()
                    .map(|((connector, flow, method_profile), variants)| {
                        let supports = variants
                            .iter()
                            .map(|r| r.support.clone())
                            .collect::<BTreeSet<_>>()
                            .into_iter()
                            .collect::<Vec<_>>()
                            .join(",");

                        let test_names = variants
                            .iter()
                            .map(|r| r.test_name.clone())
                            .collect::<BTreeSet<_>>()
                            .into_iter()
                            .collect::<Vec<_>>();

                        let refs = variants
                            .iter()
                            .map(|r| r.capability_id.clone())
                            .collect::<BTreeSet<_>>()
                            .into_iter()
                            .collect::<Vec<_>>();

                        serde_json::json!({
                            "connector": connector,
                            "flow": flow,
                            "method_profile": method_profile,
                            "supports": supports,
                            "refs": refs,
                            "test_count": test_names.len(),
                            "test_names": if name_view != TestNameView::None { serde_json::Value::from(test_names) } else { serde_json::Value::Null },
                        })
                    })
                    .collect::<Vec<_>>();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&value)
                        .expect("capabilities json should serialize")
                );
            }
        }
        return;
    }

    match args.format {
        OutputFormat::Table => print_table(&rows),
        OutputFormat::Markdown => print_rows_markdown(&rows),
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&rows).expect("rows json should serialize")
            );
        }
    }
}
