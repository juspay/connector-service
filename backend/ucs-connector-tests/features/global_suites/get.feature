@suite:get @dependent
Feature: Payment Sync (Get)
  As a payment service consumer
  I want to retrieve and synchronize the status of a payment
  So that I can verify the payment state on the connector

  Background:
    Given the "create_access_token" suite has been executed successfully
    And the "create_customer" suite has been executed successfully
    And a payment has been authorized with scenario "no3ds_auto_capture_credit_card"

  # Note: Dependencies are per-scenario (dependency_scope: scenario)

  @default @scenario:sync_payment
  Scenario: Sync a payment status
    Given a sync payment request with:
      | field                    | value          |
      | connector_transaction_id | auto_generate  |
      | amount                   | 6000 minor units USD |
    And the state includes connector customer ID and access token
    When I send a get payment request
    Then the response status should be one of "CHARGED", "AUTHORIZED", "VOIDED", "PENDING"
    And the response should not contain an "error"

  @scenario:sync_payment_with_handle_response
  Scenario: Sync a payment status with handle response
    Given a sync payment request with:
      | field                    | value          |
      | connector_transaction_id | auto_generate  |
      | amount                   | 6000 minor units USD |
    And the state includes connector customer ID and access token
    When I send a get payment request
    Then the response status should be one of "CHARGED", "AUTHORIZED", "VOIDED", "PENDING"
    And the response should contain a "connector_transaction_id"
    And the response should not contain an "error"
