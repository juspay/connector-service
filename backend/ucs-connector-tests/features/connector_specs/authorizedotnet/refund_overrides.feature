@connector:authorizedotnet @suite:refund @override
Feature: Authorize.Net - Refund Overrides
  Connector-specific overrides for Authorize.Net refund scenarios.

  Authorize.Net override for all refund scenarios:
    assert patch: status -> one_of [21, "FAILURE", "UNRESOLVED"]
                  connector_refund_id -> null (removed)
                  connector_transaction_id -> must_exist
                  error -> must_exist
                  error.connector_details.message -> contains "criteria for issuing a credit"

  This reflects that Authorize.Net refunds typically fail in sandbox mode
  because the transaction hasn't settled yet.

  Background:
    Given the dependency "create_access_token" suite default scenario has been executed
    And the dependency "create_customer" suite default scenario has been executed
    And the dependency "authorize" suite scenario "no3ds_auto_capture_credit_card" has been executed
    And dependency context is propagated to the current request

  @scenario:refund_full_amount
  Scenario: Refund the full payment amount (Authorize.Net expects failure)
    Given a request is loaded from "refund" suite scenario "refund_full_amount"
    And connector overrides are applied for connector "authorizedotnet"
    And context placeholders are prepared for suite "refund"
    And implicit context from dependency requests and responses is applied
    And auto-generated fields are resolved
    And unresolved context fields are pruned
    When the "refund" request is sent via gRPC method "types.PaymentService/Refund"
    Then the response field "status" should be one of:
      | FAILURE    |
      | UNRESOLVED |
    And the response field "connector_transaction_id" should exist
    And the response field "error" should exist
    And the response field "error.connector_details.message" should contain "criteria for issuing a credit"

  @scenario:refund_partial_amount
  Scenario: Refund a partial payment amount (Authorize.Net expects failure)
    Given a request is loaded from "refund" suite scenario "refund_partial_amount"
    And connector overrides are applied for connector "authorizedotnet"
    And context placeholders are prepared for suite "refund"
    And implicit context from dependency requests and responses is applied
    And auto-generated fields are resolved
    And unresolved context fields are pruned
    When the "refund" request is sent via gRPC method "types.PaymentService/Refund"
    Then the response field "status" should be one of:
      | FAILURE    |
      | UNRESOLVED |
    And the response field "connector_transaction_id" should exist
    And the response field "error" should exist
    And the response field "error.connector_details.message" should contain "criteria for issuing a credit"

  @scenario:refund_with_reason
  Scenario: Refund with a reason (Authorize.Net expects failure)
    Given a request is loaded from "refund" suite scenario "refund_with_reason"
    And connector overrides are applied for connector "authorizedotnet"
    And context placeholders are prepared for suite "refund"
    And implicit context from dependency requests and responses is applied
    And auto-generated fields are resolved
    And unresolved context fields are pruned
    When the "refund" request is sent via gRPC method "types.PaymentService/Refund"
    Then the response field "status" should be one of:
      | FAILURE    |
      | UNRESOLVED |
    And the response field "connector_transaction_id" should exist
    And the response field "error" should exist
    And the response field "error.connector_details.message" should contain "criteria for issuing a credit"
