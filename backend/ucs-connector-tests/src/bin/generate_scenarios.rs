//! Scenario Generator CLI
//!
//! Generates scenarios.json from generator_specs.json for one or all suites.
//!
//! Usage:
//!   generate_scenarios <suite> [group1 group2 ...]  -- generate for one suite
//!   generate_scenarios --all                         -- generate for all suites
//!
//! All known suites with a generator_specs.json are processed when --all is used.

use std::env;
use ucs_connector_tests::generator_core::{generate_scenarios, write_scenarios};

/// All suites that have a generator_specs.json
const ALL_SUITES: &[&str] = &[
    "authorize",
    "capture",
    "void",
    "refund",
    "refund_sync",
    "get",
    "setup_recurring",
    "recurring_charge",
    "create_customer",
    "create_access_token",
];

fn run_suite(suite: &str, groups: &[&str]) -> bool {
    println!("\n=== Generating scenarios for suite: {} ===", suite);
    println!("Groups: {:?}", groups);

    match generate_scenarios(suite, groups) {
        Ok(scenarios) => {
            println!("Generated {} scenarios", scenarios.len());
            if let Err(e) = write_scenarios(suite, &scenarios) {
                eprintln!("Error writing scenarios for '{}': {}", suite, e);
                return false;
            }
            true
        }
        Err(e) => {
            eprintln!("Error generating scenarios for '{}': {}", suite, e);
            false
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage:");
        eprintln!("  generate_scenarios <suite> [group1 group2 ...]");
        eprintln!("  generate_scenarios --all");
        eprintln!();
        eprintln!("Known suites: {}", ALL_SUITES.join(", "));
        std::process::exit(1);
    }

    if args[1] == "--all" {
        // Generate for every suite
        let mut failed = Vec::new();
        for suite in ALL_SUITES {
            if !run_suite(suite, &[]) {
                failed.push(*suite);
            }
        }
        println!();
        if failed.is_empty() {
            println!("All suites generated successfully.");
        } else {
            eprintln!("Failed suites: {}", failed.join(", "));
            std::process::exit(1);
        }
    } else {
        let suite = &args[1];
        let groups: Vec<&str> = if args.len() > 2 {
            args[2..].iter().map(|s| s.as_str()).collect()
        } else {
            vec![]
        };
        if !run_suite(suite, &groups) {
            std::process::exit(1);
        }
    }
}
