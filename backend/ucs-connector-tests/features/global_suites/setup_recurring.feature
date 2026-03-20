@suite:setup_recurring @dependent
Feature: Setup Recurring Payment (Mandate)
  As a payment service consumer
  I want to set up a recurring payment mandate
  So that I can charge customers on a recurring basis without re-collecting payment details

  The setup_recurring suite depends on create_access_token and create_customer.
  Dependencies run at suite-level scope (once for all scenarios).

  Background:
    Given the dependency "create_access_token" suite default scenario has been executed
    And the dependency "create_customer" suite default scenario has been executed
    And dependency context is propagated to the current request

  @default @scenario:setup_recurring
  Scenario: Setup recurring payment with card
    Given a request is loaded from "setup_recurring" suite scenario "setup_recurring"
    And connector overrides are applied for the current connector
    And context placeholders are prepared for suite "setup_recurring"
    And implicit context from dependency requests and responses is applied
    And auto-generated fields are resolved
    And unresolved context fields are pruned
    When the "setup_recurring" request is sent via gRPC method "types.PaymentService/SetupRecurring"
    Then the response field "mandate_reference.connector_mandate_id.connector_mandate_id" should exist
    And the response field "error" should not exist

  @scenario:setup_recurring_with_webhook
  Scenario: Setup recurring payment with webhook and return URLs
    Given a request is loaded from "setup_recurring" suite scenario "setup_recurring_with_webhook"
    And connector overrides are applied for the current connector
    And context placeholders are prepared for suite "setup_recurring"
    And implicit context from dependency requests and responses is applied
    And auto-generated fields are resolved
    And unresolved context fields are pruned
    When the "setup_recurring" request is sent via gRPC method "types.PaymentService/SetupRecurring"
    Then the response field "mandate_reference.connector_mandate_id.connector_mandate_id" should exist
    And the response field "error" should not exist

  @scenario:setup_recurring_with_order_context
  Scenario: Setup recurring payment with full order context
    Given a request is loaded from "setup_recurring" suite scenario "setup_recurring_with_order_context"
    And connector overrides are applied for the current connector
    And context placeholders are prepared for suite "setup_recurring"
    And implicit context from dependency requests and responses is applied
    And auto-generated fields are resolved
    And unresolved context fields are pruned
    When the "setup_recurring" request is sent via gRPC method "types.PaymentService/SetupRecurring"
    Then the response field "mandate_reference.connector_mandate_id.connector_mandate_id" should exist
    And the response field "error" should not exist
