@suite:void @dependent
Feature: Payment Void
  As a payment service consumer
  I want to void authorized payments that have not been captured
  So that I can cancel transactions before settlement

  The void suite depends on create_access_token, create_customer, and
  authorize (specifically the no3ds_manual_capture_credit_card scenario).
  Dependencies run per-scenario (scenario-level scope).

  Background:
    Given the dependency "create_access_token" suite default scenario has been executed
    And the dependency "create_customer" suite default scenario has been executed
    And the dependency "authorize" suite scenario "no3ds_manual_capture_credit_card" has been executed
    And dependency context is propagated to the current request

  @default @scenario:void_authorized_payment
  Scenario: Void an authorized payment with cancellation reason
    Given a request is loaded from "void" suite scenario "void_authorized_payment"
    And connector overrides are applied for the current connector
    And context placeholders are prepared for suite "void"
    And implicit context from dependency requests and responses is applied
    And auto-generated fields are resolved
    And unresolved context fields are pruned
    When the "void" request is sent via gRPC method "types.PaymentService/Void"
    Then the response field "status" should be one of:
      | VOIDED  |
      | PENDING |
    And the response field "connector_transaction_id" should exist
    And the response field "error" should not exist

  @scenario:void_without_cancellation_reason
  Scenario: Void an authorized payment without a cancellation reason
    Given a request is loaded from "void" suite scenario "void_without_cancellation_reason"
    And connector overrides are applied for the current connector
    And context placeholders are prepared for suite "void"
    And implicit context from dependency requests and responses is applied
    And auto-generated fields are resolved
    And unresolved context fields are pruned
    When the "void" request is sent via gRPC method "types.PaymentService/Void"
    Then the response field "status" should be one of:
      | VOIDED  |
      | PENDING |
    And the response field "connector_transaction_id" should exist
    And the response field "error" should not exist

  @scenario:void_with_amount
  Scenario: Void an authorized payment with a specific amount
    Given a request is loaded from "void" suite scenario "void_with_amount"
    And connector overrides are applied for the current connector
    And context placeholders are prepared for suite "void"
    And implicit context from dependency requests and responses is applied
    And auto-generated fields are resolved
    And unresolved context fields are pruned
    When the "void" request is sent via gRPC method "types.PaymentService/Void"
    Then the response field "status" should be one of:
      | VOIDED  |
      | PENDING |
    And the response field "connector_transaction_id" should exist
    And the response field "error" should not exist
