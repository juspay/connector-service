@suite:void @dependent
Feature: Payment Void
  As a payment service consumer
  I want to void authorized payments that have not been captured
  So that I can cancel transactions before settlement

  Background:
    Given the "create_access_token" suite has been executed successfully
    And the "create_customer" suite has been executed successfully
    And a payment has been authorized with scenario "no3ds_manual_capture_credit_card"

  # Note: Dependencies are per-scenario (dependency_scope: scenario)

  @default @scenario:void_authorized_payment
  Scenario: Void an authorized payment with cancellation reason
    Given a void request with:
      | field                    | value                   |
      | connector_transaction_id | auto_generate           |
      | merchant_void_id         | auto_generate           |
      | cancellation_reason      | requested_by_customer   |
    And the state includes connector customer ID and access token
    When I send a void payment request
    Then the response status should be one of "VOIDED", "PENDING"
    And the response should contain a "connector_transaction_id"
    And the response should not contain an "error"

  @scenario:void_without_cancellation_reason
  Scenario: Void an authorized payment without a cancellation reason
    Given a void request with:
      | field                    | value          |
      | connector_transaction_id | auto_generate  |
      | merchant_void_id         | auto_generate  |
    And the state includes connector customer ID and access token
    When I send a void payment request
    Then the response status should be one of "VOIDED", "PENDING"
    And the response should contain a "connector_transaction_id"
    And the response should not contain an "error"

  @scenario:void_with_amount
  Scenario: Void an authorized payment with a specific amount
    Given a void request with:
      | field                    | value                   |
      | connector_transaction_id | auto_generate           |
      | merchant_void_id         | auto_generate           |
      | amount                   | 6000 minor units USD    |
      | merchant_order_id        | auto_generate           |
      | cancellation_reason      | requested_by_customer   |
    And the state includes connector customer ID and access token
    When I send a void payment request
    Then the response status should be one of "VOIDED", "PENDING"
    And the response should contain a "connector_transaction_id"
    And the response should not contain an "error"
