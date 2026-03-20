@suite:setup_recurring @dependent
Feature: Setup Recurring Payment (Mandate)
  As a payment service consumer
  I want to set up a recurring payment mandate
  So that I can charge customers on a recurring basis without re-collecting payment details

  Background:
    Given the "create_access_token" suite has been executed successfully
    And the "create_customer" suite has been executed successfully

  @default @scenario:setup_recurring
  Scenario: Setup recurring payment with card
    Given a setup recurring request with:
      | field                        | value          |
      | merchant_recurring_payment_id| auto_generate  |
      | amount                       | 6000 minor units USD |
      | auth_type                    | NO_THREE_DS    |
      | enrolled_for_3ds             | false          |
      | setup_future_usage           | OFF_SESSION    |
    And the payment method is a credit card:
      | field           | value            |
      | card_number     | 4111111111111111 |
      | card_exp_month  | 08               |
      | card_exp_year   | 30               |
      | card_cvc        | 999              |
      | card_holder_name| auto_generate    |
      | card_type       | credit           |
    And the customer details are auto-generated
    And the billing address is provided
    And customer acceptance type is "OFFLINE"
    When I send a setup recurring payment request
    Then the response should contain a "mandate_reference.connector_mandate_id.connector_mandate_id"
    And the response should not contain an "error"

  @scenario:setup_recurring_with_webhook
  Scenario: Setup recurring payment with webhook and return URLs
    Given a setup recurring request with:
      | field                        | value                              |
      | merchant_recurring_payment_id| auto_generate                      |
      | amount                       | 4500 minor units USD               |
      | auth_type                    | NO_THREE_DS                        |
      | enrolled_for_3ds             | false                              |
      | setup_future_usage           | OFF_SESSION                        |
      | return_url                   | https://example.com/payment/return |
      | webhook_url                  | https://example.com/payment/webhook|
    And the payment method is a credit card:
      | field           | value            |
      | card_number     | 4111111111111111 |
      | card_exp_month  | 08               |
      | card_exp_year   | 30               |
      | card_cvc        | 999              |
      | card_holder_name| auto_generate    |
      | card_type       | credit           |
    And the customer details are auto-generated
    And the billing address is provided
    And customer acceptance type is "OFFLINE"
    When I send a setup recurring payment request
    Then the response should contain a "mandate_reference.connector_mandate_id.connector_mandate_id"
    And the response should not contain an "error"

  @scenario:setup_recurring_with_order_context
  Scenario: Setup recurring payment with full order context
    Given a setup recurring request with:
      | field                        | value                                    |
      | merchant_recurring_payment_id| auto_generate                            |
      | amount                       | 6000 minor units USD                     |
      | auth_type                    | NO_THREE_DS                              |
      | enrolled_for_3ds             | false                                    |
      | setup_future_usage           | OFF_SESSION                              |
      | off_session                  | true                                     |
      | merchant_order_id            | auto_generate                            |
      | order_category               | subscription                             |
      | return_url                   | https://example.com/payment/return       |
      | webhook_url                  | https://example.com/payment/webhook      |
      | complete_authorize_url       | https://example.com/payment/complete     |
    And the payment method is a credit card:
      | field           | value            |
      | card_number     | 4111111111111111 |
      | card_exp_month  | 08               |
      | card_exp_year   | 30               |
      | card_cvc        | 999              |
      | card_holder_name| auto_generate    |
      | card_type       | credit           |
    And the customer details are auto-generated
    And the billing address is provided
    And customer acceptance type is "OFFLINE"
    When I send a setup recurring payment request
    Then the response should contain a "mandate_reference.connector_mandate_id.connector_mandate_id"
    And the response should not contain an "error"
