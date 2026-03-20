@suite:recurring_charge @dependent
Feature: Recurring Charge
  As a payment service consumer
  I want to charge a customer using a previously set up recurring mandate
  So that I can process subscription or repeat payments without re-collecting card details

  The recurring_charge suite depends on create_access_token, create_customer,
  and setup_recurring. The setup_recurring dependency includes a context_map:
    connector_recurring_payment_id.connector_mandate_id.connector_mandate_id
      <- res.mandate_reference.connector_mandate_id.connector_mandate_id
  Dependencies run at suite-level scope (once for all scenarios).

  Background:
    Given the dependency "create_access_token" suite default scenario has been executed
    And the dependency "create_customer" suite default scenario has been executed
    And the dependency "setup_recurring" suite default scenario has been executed with context map:
      | target_path                                                                    | source_path                                                         |
      | connector_recurring_payment_id.connector_mandate_id.connector_mandate_id       | res.mandate_reference.connector_mandate_id.connector_mandate_id     |
    And dependency context is propagated to the current request

  @default @scenario:recurring_charge
  Scenario: Charge using a recurring mandate
    Given a request is loaded from "recurring_charge" suite scenario "recurring_charge"
    And connector overrides are applied for the current connector
    And context placeholders are prepared for suite "recurring_charge"
    And implicit context from dependency requests and responses is applied
    And explicit context map entries are applied
    And auto-generated fields are resolved
    And unresolved context fields are pruned
    When the "recurring_charge" request is sent via gRPC method "types.RecurringPaymentService/Charge"
    Then the response field "connector_transaction_id" should exist
    And the response field "error" should not exist

  @scenario:recurring_charge_low_amount
  Scenario: Charge a low amount using a recurring mandate
    Given a request is loaded from "recurring_charge" suite scenario "recurring_charge_low_amount"
    And connector overrides are applied for the current connector
    And context placeholders are prepared for suite "recurring_charge"
    And implicit context from dependency requests and responses is applied
    And explicit context map entries are applied
    And auto-generated fields are resolved
    And unresolved context fields are pruned
    When the "recurring_charge" request is sent via gRPC method "types.RecurringPaymentService/Charge"
    Then the response field "connector_transaction_id" should exist
    And the response field "error" should not exist

  @scenario:recurring_charge_with_order_context
  Scenario: Charge using a recurring mandate with order context
    Given a request is loaded from "recurring_charge" suite scenario "recurring_charge_with_order_context"
    And connector overrides are applied for the current connector
    And context placeholders are prepared for suite "recurring_charge"
    And implicit context from dependency requests and responses is applied
    And explicit context map entries are applied
    And auto-generated fields are resolved
    And unresolved context fields are pruned
    When the "recurring_charge" request is sent via gRPC method "types.RecurringPaymentService/Charge"
    Then the response field "connector_transaction_id" should exist
    And the response field "error" should not exist
