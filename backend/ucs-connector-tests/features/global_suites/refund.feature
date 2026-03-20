@suite:refund @dependent
Feature: Payment Refund
  As a payment service consumer
  I want to refund payments that have been captured
  So that I can return funds to customers

  Background:
    Given the "create_access_token" suite has been executed successfully
    And the "create_customer" suite has been executed successfully
    And a payment has been authorized with scenario "no3ds_auto_capture_credit_card"

  # Note: Dependencies are per-scenario (dependency_scope: scenario)

  @default @scenario:refund_full_amount
  Scenario: Refund the full payment amount
    Given a refund request with:
      | field                    | value          |
      | merchant_refund_id       | auto_generate  |
      | connector_transaction_id | auto_generate  |
      | payment_amount           | 6000           |
      | refund_amount            | 6000 minor units USD |
    And the state includes connector customer ID and access token
    When I send a refund payment request
    Then the response status should be one of "REFUND_SUCCESS", "PENDING"
    And the response should contain a "connector_refund_id"
    And the response should not contain an "error"

  @scenario:refund_partial_amount
  Scenario: Refund a partial payment amount
    Given a refund request with:
      | field                    | value          |
      | merchant_refund_id       | auto_generate  |
      | connector_transaction_id | auto_generate  |
      | payment_amount           | 6000           |
      | refund_amount            | 3000 minor units USD |
    And the state includes connector customer ID and access token
    When I send a refund payment request
    Then the response status should be one of "REFUND_SUCCESS", "PENDING"
    And the response should contain a "connector_refund_id"
    And the response should not contain an "error"

  @scenario:refund_with_reason
  Scenario: Refund with a reason
    Given a refund request with:
      | field                    | value              |
      | merchant_refund_id       | auto_generate      |
      | connector_transaction_id | auto_generate      |
      | payment_amount           | 6000               |
      | refund_amount            | 6000 minor units USD |
      | reason                   | customer_requested |
    And the state includes connector customer ID and access token
    When I send a refund payment request
    Then the response status should be one of "REFUND_SUCCESS", "PENDING"
    And the response should contain a "connector_refund_id"
    And the response should not contain an "error"
