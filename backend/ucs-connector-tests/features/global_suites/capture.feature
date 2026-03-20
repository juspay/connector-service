@suite:capture @dependent
Feature: Payment Capture
  As a payment service consumer
  I want to capture authorized payments either fully or partially
  So that I can complete the payment settlement process

  The capture suite depends on create_access_token, create_customer, and
  authorize (specifically the no3ds_manual_capture_credit_card scenario).
  Dependencies run per-scenario (scenario-level scope), meaning each
  scenario gets a fresh authorization.

  Background:
    Given the dependency "create_access_token" suite default scenario has been executed
    And the dependency "create_customer" suite default scenario has been executed
    And the dependency "authorize" suite scenario "no3ds_manual_capture_credit_card" has been executed
    And dependency context is propagated to the current request

  @default @scenario:capture_full_amount
  Scenario: Capture the full authorized amount
    Given a request is loaded from "capture" suite scenario "capture_full_amount"
    And connector overrides are applied for the current connector
    And context placeholders are prepared for suite "capture"
    And implicit context from dependency requests and responses is applied
    And auto-generated fields are resolved
    And unresolved context fields are pruned
    When the "capture" request is sent via gRPC method "types.PaymentService/Capture"
    Then the response field "status" should be one of:
      | CHARGED |
      | PENDING |
    And the response field "connector_transaction_id" should exist
    And the response field "error" should not exist

  @scenario:capture_partial_amount
  Scenario: Capture a partial amount of the authorized payment
    Given a request is loaded from "capture" suite scenario "capture_partial_amount"
    And connector overrides are applied for the current connector
    And context placeholders are prepared for suite "capture"
    And implicit context from dependency requests and responses is applied
    And auto-generated fields are resolved
    And unresolved context fields are pruned
    When the "capture" request is sent via gRPC method "types.PaymentService/Capture"
    Then the response field "status" should be one of:
      | CHARGED |
      | PENDING |
    And the response field "connector_transaction_id" should exist
    And the response field "error" should not exist

  @scenario:capture_with_merchant_order_id
  Scenario: Capture with a merchant order ID
    Given a request is loaded from "capture" suite scenario "capture_with_merchant_order_id"
    And connector overrides are applied for the current connector
    And context placeholders are prepared for suite "capture"
    And implicit context from dependency requests and responses is applied
    And auto-generated fields are resolved
    And unresolved context fields are pruned
    When the "capture" request is sent via gRPC method "types.PaymentService/Capture"
    Then the response field "status" should be one of:
      | CHARGED |
      | PENDING |
    And the response field "connector_transaction_id" should exist
    And the response field "error" should not exist
