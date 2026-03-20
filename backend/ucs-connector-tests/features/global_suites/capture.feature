@suite:capture @dependent
Feature: Payment Capture
  As a payment service consumer
  I want to capture authorized payments either fully or partially
  So that I can complete the payment settlement process

  Background:
    Given the "create_access_token" suite has been executed successfully
    And the "create_customer" suite has been executed successfully
    And a payment has been authorized with scenario "no3ds_manual_capture_credit_card"

  # Note: Dependencies are per-scenario (dependency_scope: scenario)
  # Each scenario gets its own fresh authorization

  @default @scenario:capture_full_amount
  Scenario: Capture the full authorized amount
    Given a capture request with:
      | field                    | value          |
      | connector_transaction_id | auto_generate  |
      | amount_to_capture        | 6000 minor units USD |
      | merchant_capture_id      | auto_generate  |
    And the state includes connector customer ID and access token
    When I send a capture payment request
    Then the response status should be one of "CHARGED", "PENDING"
    And the response should contain a "connector_transaction_id"
    And the response should not contain an "error"

  @scenario:capture_partial_amount
  Scenario: Capture a partial amount of the authorized payment
    Given a capture request with:
      | field                    | value          |
      | connector_transaction_id | auto_generate  |
      | amount_to_capture        | 3000 minor units USD |
      | merchant_capture_id      | auto_generate  |
    And the state includes connector customer ID and access token
    When I send a capture payment request
    Then the response status should be one of "CHARGED", "PENDING"
    And the response should contain a "connector_transaction_id"
    And the response should not contain an "error"

  @scenario:capture_with_merchant_order_id
  Scenario: Capture with a merchant order ID
    Given a capture request with:
      | field                    | value          |
      | connector_transaction_id | auto_generate  |
      | amount_to_capture        | 6000 minor units USD |
      | merchant_capture_id      | auto_generate  |
      | merchant_order_id        | auto_generate  |
    And the state includes connector customer ID and access token
    When I send a capture payment request
    Then the response status should be one of "CHARGED", "PENDING"
    And the response should contain a "connector_transaction_id"
    And the response should not contain an "error"
