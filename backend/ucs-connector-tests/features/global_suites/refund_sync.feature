@suite:refund_sync @dependent
Feature: Refund Synchronization
  As a payment service consumer
  I want to synchronize the status of a refund
  So that I can verify the refund has been processed by the connector

  Background:
    Given the "create_access_token" suite has been executed successfully
    And the "create_customer" suite has been executed successfully
    And a payment has been authorized with scenario "no3ds_auto_capture_credit_card"
    And a refund has been processed successfully
    And the refund ID is mapped from the refund response "res.connector_refund_id"

  # Note: Dependencies are per-scenario (dependency_scope: scenario)
  # Context mapping: refund_id <- res.connector_refund_id from refund suite

  @default @scenario:refund_sync
  Scenario: Synchronize refund status
    Given a refund sync request with:
      | field                    | value          |
      | connector_transaction_id | auto_generate  |
      | refund_id                | auto_generate  |
    And the state includes connector customer ID and access token
    When I send a refund sync request
    Then the response status should be one of "REFUND_SUCCESS", "PENDING"
    And the response should not contain an "error"

  @scenario:refund_sync_with_reason
  Scenario: Synchronize refund status with reason
    Given a refund sync request with:
      | field                    | value              |
      | connector_transaction_id | auto_generate      |
      | refund_id                | auto_generate      |
      | refund_reason            | customer_requested |
    And the state includes connector customer ID and access token
    When I send a refund sync request
    Then the response status should be one of "REFUND_SUCCESS", "PENDING"
    And the response should not contain an "error"
