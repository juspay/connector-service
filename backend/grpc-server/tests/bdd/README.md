# Cucumber BDD Tests for Connector Service

This directory contains Behavior-Driven Development (BDD) tests using the Cucumber framework with Gherkin syntax. These tests allow you to write payment flow scenarios in plain English.

## Overview

BDD tests provide a way to describe payment connector behavior using natural language that's understandable by both technical and non-technical stakeholders.

## Directory Structure

```
bdd/
├── features/           # Gherkin feature files (plain English test scenarios)
│   └── stripe_payment_flows.feature
├── steps/              # Step definitions (Rust code that implements Gherkin steps)
│   └── stripe_steps.rs
├── world.rs            # World state management (test context/state)
└── README.md           # This file
```

## Running Tests

### Run all Cucumber tests

```bash
cd backend/grpc-server
cargo test --test cucumber_test
```

### Run with output visible

```bash
cargo test --test cucumber_test -- --nocapture
```

### Run specific scenarios (using tags)

```bash
cargo test --test cucumber_test -- --tags "@critical"
```

## Writing New Scenarios

### 1. Add a Feature File

Create a new `.feature` file in `bdd/features/`:

```gherkin
Feature: My Connector Payment Flows
  As a merchant
  I want to process payments through My Connector
  So that I can accept customer payments

  Background:
    Given I am using the My Connector connector
    And I have a valid merchant account

  Scenario: Successfully authorize a payment
    Given I want to process a payment of 1000 cents in "USD"
    And I want to use manual capture
    When I authorize the payment
    Then I should receive a transaction ID
    And the payment should be "authorized"
```

### 2. Implement Step Definitions

Add step implementations in `bdd/steps/<connector>_steps.rs`:

```rust
#[given("I am using the My Connector connector")]
fn set_connector(world: &mut StripeWorld) {
    world.connector_name = "my_connector".to_string();
    world.auth_type = "header-key".to_string();
}
```

## Available Steps

### Given Steps (Setup)

- `I am using the Stripe connector` - Sets connector to Stripe
- `I have a valid merchant account` - Sets merchant ID
- `I have a test card with number "{string}"` - Sets test card number
- `I want to process a payment of {int} cents in "{string}"` - Sets amount and currency
- `I want to use automatic capture` - Sets capture method to automatic
- `I want to use manual capture` - Sets capture method to manual

### When Steps (Actions)

- `I authorize the payment` - Creates a payment authorization
- `I capture the payment` - Captures an authorized payment
- `I void the payment` - Voids an authorized payment
- `I process a refund` - Creates a refund
- `I sync the payment status` - Syncs payment status with connector
- `I sync the refund status` - Syncs refund status with connector

### Then Steps (Assertions)

- `the payment should be "{string}"` - Asserts payment status (authorized, charged, voided, failed)
- `the refund should be "{string}"` - Asserts refund status (successful, failed)
- `I should receive a transaction ID` - Asserts transaction ID is present
- `I should receive a refund ID` - Asserts refund ID is present
- `no error should occur` - Asserts no errors occurred

## Example Scenarios

### Basic Payment with Auto Capture

```gherkin
Scenario: Successfully process a payment with automatic capture
  Given I want to process a payment of 1000 cents in "USD"
  And I want to use automatic capture
  When I authorize the payment
  Then I should receive a transaction ID
  And the payment should be "charged"
```

### Manual Capture Flow

```gherkin
Scenario: Successfully capture an authorized payment
  Given I want to process a payment of 1000 cents in "USD"
  And I want to use manual capture
  When I authorize the payment
  Then I should receive a transaction ID
  And the payment should be "authorized"
  When I capture the payment
  Then the payment should be "charged"
```

### Full Refund Flow

```gherkin
Scenario: Successfully process a full refund
  Given I want to process a payment of 1000 cents in "USD"
  And I want to use automatic capture
  When I authorize the payment
  Then I should receive a transaction ID
  And the payment should be "charged"
  When I process a refund
  Then I should receive a refund ID
  And the refund should be "successful"
```

## Adding Support for New Connectors

1. Create a new feature file: `bdd/features/<connector>_payment_flows.feature`
2. Create step definitions file: `bdd/steps/<connector>_steps.rs`
3. Add connector-specific metadata handling in `world.rs`
4. Update `mod.rs` files to include new modules

## Troubleshooting

### Credentials Not Found

Ensure credentials are available at `.github/test/creds.json` or set the `CONNECTOR_AUTH_FILE_PATH` environment variable.

### Server Connection Issues

The tests use Unix sockets for gRPC communication. Ensure your system supports Unix domain sockets.

### Step Not Found

If you get "step not found" errors, ensure:
1. The step definition is properly registered with `#[given]`, `#[when]`, or `#[then]`
2. The step text in the feature file exactly matches the macro argument
3. The steps module is properly included in `mod.rs`
