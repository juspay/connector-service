@suite:recurring_charge @dependent
Feature: Recurring Charge
  As a payment service consumer
  I want to charge a customer using a previously set up recurring mandate
  So that I can process subscription or repeat payments without re-collecting card details

  Background:
    Given the "create_access_token" suite has been executed successfully
    And the "create_customer" suite has been executed successfully
    And a recurring payment mandate has been set up successfully
    And the mandate ID is mapped from the setup recurring response "res.mandate_reference.connector_mandate_id.connector_mandate_id"

  # Context mapping: connector_recurring_payment_id.connector_mandate_id.connector_mandate_id
  #                  <- res.mandate_reference.connector_mandate_id.connector_mandate_id

  @default @scenario:recurring_charge
  Scenario: Charge using a recurring mandate
    Given a recurring charge request with:
      | field                | value          |
      | merchant_charge_id   | auto_generate  |
      | amount               | 6000 minor units USD |
    And the connector mandate ID is provided from the setup recurring response
    And the state includes connector customer ID and access token
    When I send a recurring charge request
    Then the response should contain a "connector_transaction_id"
    And the response should not contain an "error"

  @scenario:recurring_charge_low_amount
  Scenario: Charge a low amount using a recurring mandate
    Given a recurring charge request with:
      | field                | value          |
      | merchant_charge_id   | auto_generate  |
      | amount               | 1000 minor units USD |
    And the connector mandate ID is provided from the setup recurring response
    And the state includes connector customer ID and access token
    When I send a recurring charge request
    Then the response should contain a "connector_transaction_id"
    And the response should not contain an "error"

  @scenario:recurring_charge_with_order_context
  Scenario: Charge using a recurring mandate with order context
    Given a recurring charge request with:
      | field                | value                                |
      | merchant_charge_id   | auto_generate                        |
      | amount               | 2500 minor units USD                 |
      | merchant_order_id    | auto_generate                        |
      | webhook_url          | https://example.com/payment/webhook  |
      | return_url           | https://example.com/payment/return   |
      | description          | Recurring charge with order context  |
      | off_session          | true                                 |
      | test_mode            | true                                 |
    And the connector mandate ID is provided from the setup recurring response
    And the state includes connector customer ID and access token
    When I send a recurring charge request
    Then the response should contain a "connector_transaction_id"
    And the response should not contain an "error"
