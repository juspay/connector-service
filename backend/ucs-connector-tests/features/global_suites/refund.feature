@suite:refund @dependent
Feature: Payment Refund
  As a payment service consumer
  I want to refund payments that have been captured
  So that I can return funds to customers

  The refund suite depends on create_access_token, create_customer, and
  authorize (specifically the no3ds_auto_capture_credit_card scenario).
  Dependencies run per-scenario (scenario-level scope).

  Background:
    Given the dependency "create_access_token" suite default scenario has been executed
    And the dependency "create_customer" suite default scenario has been executed
    And the dependency "authorize" suite scenario "no3ds_auto_capture_credit_card" has been executed
    And dependency context is propagated to the current request

  @default @scenario:refund_full_amount
  Scenario: Refund the full payment amount
    Given a request is loaded from "refund" suite scenario "refund_full_amount"
    And connector overrides are applied for the current connector
    And context placeholders are prepared for suite "refund"
    And implicit context from dependency requests and responses is applied
    And auto-generated fields are resolved
    And unresolved context fields are pruned
    When the "refund" request is sent via gRPC method "types.PaymentService/Refund"
    Then the response field "status" should be one of:
      | REFUND_SUCCESS |
      | PENDING        |
    And the response field "connector_refund_id" should exist
    And the response field "error" should not exist

  @scenario:refund_partial_amount
  Scenario: Refund a partial payment amount
    Given a request is loaded from "refund" suite scenario "refund_partial_amount"
    And connector overrides are applied for the current connector
    And context placeholders are prepared for suite "refund"
    And implicit context from dependency requests and responses is applied
    And auto-generated fields are resolved
    And unresolved context fields are pruned
    When the "refund" request is sent via gRPC method "types.PaymentService/Refund"
    Then the response field "status" should be one of:
      | REFUND_SUCCESS |
      | PENDING        |
    And the response field "connector_refund_id" should exist
    And the response field "error" should not exist

  @scenario:refund_with_reason
  Scenario: Refund with a reason
    Given a request is loaded from "refund" suite scenario "refund_with_reason"
    And connector overrides are applied for the current connector
    And context placeholders are prepared for suite "refund"
    And implicit context from dependency requests and responses is applied
    And auto-generated fields are resolved
    And unresolved context fields are pruned
    When the "refund" request is sent via gRPC method "types.PaymentService/Refund"
    Then the response field "status" should be one of:
      | REFUND_SUCCESS |
      | PENDING        |
    And the response field "connector_refund_id" should exist
    And the response field "error" should not exist
