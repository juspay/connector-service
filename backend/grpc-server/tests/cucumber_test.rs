//! Cucumber BDD Tests for Stripe Connector
//!
//! This test file runs Gherkin feature files using the cucumber-rs framework.
//! Tests are written in plain English and can be found in the `bdd/features/` directory.
//!
//! To run these tests:
//!   cargo test --test cucumber_test
//!
//! To run with output:
//!   cargo test --test cucumber_test -- --nocapture

#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]

use cucumber::World as _;

mod bdd;
mod common;
mod utils;

/// Main entry point for Cucumber tests
///
/// This runs all `.feature` files in the `tests/bdd/features/` directory.
/// The tests use the StripeWorld state management defined in `bdd/world.rs`
/// and step definitions in `bdd/steps/stripe_steps.rs`.
#[tokio::main(flavor = "current_thread")]
async fn main() {
    // Run cucumber tests
    bdd::world::StripeWorld::cucumber()
        // Fail on skipped steps (strict mode)
        .fail_on_skipped()
        // Maximum time for each scenario
        .max_concurrent_scenarios(1)
        // Print output to terminal
        .with_writer(cucumber::writer::Basic::stdout())
        // Run features
        .run("tests/bdd/features")
        .await;
}
