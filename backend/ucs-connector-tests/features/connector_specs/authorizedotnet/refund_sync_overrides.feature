@connector:authorizedotnet @suite:refund_sync @override
Feature: Authorize.Net - Refund Sync Overrides
  Connector-specific overrides for Authorize.Net refund sync scenarios.

  Authorize.Net override for refund_sync scenarios:
    grpc_req patch: merchant_refund_id -> auto_generate,
                    refund_id -> "authnet_refund_reference" (fixed value)
    assert patch: status -> one_of [21, "PENDING", "REFUND_SUCCESS", "FAILURE", "UNRESOLVED"]
                  error -> null (removed)

  Background:
    Given the dependency "create_access_token" suite default scenario has been executed
    And the dependency "create_customer" suite default scenario has been executed
    And the dependency "authorize" suite scenario "no3ds_auto_capture_credit_card" has been executed
    And the dependency "refund" suite default scenario has been executed with context map:
      | target_path | source_path            |
      | refund_id   | res.connector_refund_id |
    And dependency context is propagated to the current request

  @scenario:refund_sync
  Scenario: Synchronize refund status (Authorize.Net uses fixed refund reference)
    Given a request is loaded from "refund_sync" suite scenario "refund_sync"
    And connector overrides are applied for connector "authorizedotnet"
    # Override sets refund_id to "authnet_refund_reference" and adds merchant_refund_id
    And context placeholders are prepared for suite "refund_sync"
    And implicit context from dependency requests and responses is applied
    And explicit context map entries are applied
    And auto-generated fields are resolved
    And unresolved context fields are pruned
    When the "refund_sync" request is sent via gRPC method "types.RefundService/Get"
    Then the response field "status" should be one of:
      | PENDING        |
      | REFUND_SUCCESS |
      | FAILURE        |
      | UNRESOLVED     |
    # Authorize.Net override removes the error assertion (null patch)

  @scenario:refund_sync_with_reason
  Scenario: Synchronize refund status with reason (Authorize.Net uses fixed refund reference)
    Given a request is loaded from "refund_sync" suite scenario "refund_sync_with_reason"
    And connector overrides are applied for connector "authorizedotnet"
    And context placeholders are prepared for suite "refund_sync"
    And implicit context from dependency requests and responses is applied
    And explicit context map entries are applied
    And auto-generated fields are resolved
    And unresolved context fields are pruned
    When the "refund_sync" request is sent via gRPC method "types.RefundService/Get"
    Then the response field "status" should be one of:
      | PENDING        |
      | REFUND_SUCCESS |
      | FAILURE        |
      | UNRESOLVED     |
    # Authorize.Net override removes the error assertion (null patch)
