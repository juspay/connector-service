@suite:get @dependent
Feature: Payment Sync (Get)
  As a payment service consumer
  I want to retrieve and synchronize the status of a payment
  So that I can verify the payment state on the connector

  The get suite depends on create_access_token, create_customer, and
  authorize (specifically the no3ds_auto_capture_credit_card scenario).
  Dependencies run per-scenario (scenario-level scope).

  Background:
    Given the dependency "create_access_token" suite default scenario has been executed
    And the dependency "create_customer" suite default scenario has been executed
    And the dependency "authorize" suite scenario "no3ds_auto_capture_credit_card" has been executed
    And dependency context is propagated to the current request

  @default @scenario:sync_payment
  Scenario: Sync a payment status
    Given a request is loaded from "get" suite scenario "sync_payment"
    And connector overrides are applied for the current connector
    And context placeholders are prepared for suite "get"
    And implicit context from dependency requests and responses is applied
    And auto-generated fields are resolved
    And unresolved context fields are pruned
    When the "get" request is sent via gRPC method "types.PaymentService/Get"
    Then the response field "status" should be one of:
      | CHARGED    |
      | AUTHORIZED |
      | VOIDED     |
      | PENDING    |
    And the response field "error" should not exist

  @scenario:sync_payment_with_handle_response
  Scenario: Sync a payment status with handle response
    Given a request is loaded from "get" suite scenario "sync_payment_with_handle_response"
    And connector overrides are applied for the current connector
    And context placeholders are prepared for suite "get"
    And implicit context from dependency requests and responses is applied
    And auto-generated fields are resolved
    And unresolved context fields are pruned
    When the "get" request is sent via gRPC method "types.PaymentService/Get"
    Then the response field "status" should be one of:
      | CHARGED    |
      | AUTHORIZED |
      | VOIDED     |
      | PENDING    |
    And the response field "connector_transaction_id" should exist
    And the response field "error" should not exist
