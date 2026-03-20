@connector:paypal @suite:recurring_charge @override
Feature: PayPal - Recurring Charge Overrides
  Connector-specific overrides for PayPal recurring charge scenarios.
  PayPal requires payment_method_type to be set to "CREDIT" and removes
  connector_customer_id and customer fields from recurring charge requests.

  # PayPal supports: create_access_token, authorize, capture, void, refund,
  #                   get, refund_sync, setup_recurring, recurring_charge

  @scenario:recurring_charge
  Scenario: Charge using a recurring mandate (PayPal-specific)
    # Override: Adds payment_method_type "CREDIT"
    # Override: Removes connector_customer_id (null)
    # Override: Removes customer (null)
    Given a recurring charge request with:
      | field                | value          |
      | merchant_charge_id   | auto_generate  |
      | amount               | 6000 minor units USD |
      | payment_method_type  | CREDIT         |
    And the connector mandate ID is provided from the setup recurring response
    # Note: connector_customer_id and customer are removed for PayPal
    And the state includes access token
    When I send a recurring charge request
    Then the response should contain a "connector_transaction_id"
    And the response should not contain an "error"

  @scenario:recurring_charge_low_amount
  Scenario: Charge a low amount using a recurring mandate (PayPal-specific)
    # Override: Adds payment_method_type "CREDIT"
    # Override: Removes connector_customer_id (null)
    # Override: Removes customer (null)
    Given a recurring charge request with:
      | field                | value          |
      | merchant_charge_id   | auto_generate  |
      | amount               | 1000 minor units USD |
      | payment_method_type  | CREDIT         |
    And the connector mandate ID is provided from the setup recurring response
    # Note: connector_customer_id and customer are removed for PayPal
    And the state includes access token
    When I send a recurring charge request
    Then the response should contain a "connector_transaction_id"
    And the response should not contain an "error"

  @scenario:recurring_charge_with_order_context
  Scenario: Charge using a recurring mandate with order context (PayPal-specific)
    # Override: Adds payment_method_type "CREDIT"
    # Override: Removes connector_customer_id (null)
    # Override: Removes customer (null)
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
      | payment_method_type  | CREDIT                               |
    And the connector mandate ID is provided from the setup recurring response
    # Note: connector_customer_id and customer are removed for PayPal
    And the state includes access token
    When I send a recurring charge request
    Then the response should contain a "connector_transaction_id"
    And the response should not contain an "error"
