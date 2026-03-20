@suite:refund_sync @dependent
Feature: Refund Synchronization
  As a payment service consumer
  I want to synchronize the status of a refund
  So that I can verify the refund has been processed by the connector

  The refund_sync suite depends on create_access_token, create_customer,
  authorize (no3ds_auto_capture_credit_card), and refund.
  The refund dependency includes a context_map that maps
  "refund_id" <- "res.connector_refund_id" from the refund response.
  Dependencies run per-scenario (scenario-level scope).

  Background:
    Given the dependency "create_access_token" suite default scenario has been executed
    And the dependency "create_customer" suite default scenario has been executed
    And the dependency "authorize" suite scenario "no3ds_auto_capture_credit_card" has been executed
    And the dependency "refund" suite default scenario has been executed with context map:
      | target_path | source_path            |
      | refund_id   | res.connector_refund_id |
    And dependency context is propagated to the current request

  @default @scenario:refund_sync
  Scenario: Synchronize refund status
    Given a request is loaded from "refund_sync" suite scenario "refund_sync"
    And connector overrides are applied for the current connector
    And context placeholders are prepared for suite "refund_sync"
    And implicit context from dependency requests and responses is applied
    And explicit context map entries are applied
    And auto-generated fields are resolved
    And unresolved context fields are pruned
    When the "refund_sync" request is sent via gRPC method "types.RefundService/Get"
    Then the response field "status" should be one of:
      | REFUND_SUCCESS |
      | PENDING        |
    And the response field "error" should not exist

  @scenario:refund_sync_with_reason
  Scenario: Synchronize refund status with reason
    Given a request is loaded from "refund_sync" suite scenario "refund_sync_with_reason"
    And connector overrides are applied for the current connector
    And context placeholders are prepared for suite "refund_sync"
    And implicit context from dependency requests and responses is applied
    And explicit context map entries are applied
    And auto-generated fields are resolved
    And unresolved context fields are pruned
    When the "refund_sync" request is sent via gRPC method "types.RefundService/Get"
    Then the response field "status" should be one of:
      | REFUND_SUCCESS |
      | PENDING        |
    And the response field "error" should not exist
