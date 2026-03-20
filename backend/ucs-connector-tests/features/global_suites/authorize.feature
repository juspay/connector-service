@suite:authorize @dependent
Feature: Payment Authorization
  As a payment service consumer
  I want to authorize payments using various card types and capture methods
  So that I can process payments through the connector

  Background:
    Given the "create_access_token" suite has been executed successfully
    And the "create_customer" suite has been executed successfully

  @scenario:no3ds_auto_capture_credit_card
  Scenario: No3DS auto capture with credit card
    Given a payment request with:
      | field                | value                    |
      | merchant_transaction_id | auto_generate         |
      | amount               | 6000 minor units USD     |
      | capture_method       | AUTOMATIC                |
      | auth_type            | NO_THREE_DS              |
      | enrolled_for_3ds     | false                    |
      | setup_future_usage   | ON_SESSION               |
      | off_session          | false                    |
      | order_category       | physical                 |
      | payment_channel      | ECOMMERCE                |
      | description          | No3DS auto capture card payment (credit) |
    And the payment method is a credit card:
      | field           | value            |
      | card_number     | 4111111111111111 |
      | card_exp_month  | 08               |
      | card_exp_year   | 30               |
      | card_cvc        | 999              |
      | card_holder_name| auto_generate    |
      | card_type       | credit           |
    And the customer details are auto-generated
    And the shipping and billing addresses are provided
    When I send an authorize payment request
    Then the response status should be one of "CHARGED", "AUTHORIZED"
    And the response should contain a "connector_transaction_id"
    And the response should not contain an "error"

  @scenario:no3ds_auto_capture_debit_card
  Scenario: No3DS auto capture with debit card
    Given a payment request with:
      | field                | value                    |
      | merchant_transaction_id | auto_generate         |
      | amount               | 6000 minor units USD     |
      | capture_method       | AUTOMATIC                |
      | auth_type            | NO_THREE_DS              |
      | enrolled_for_3ds     | false                    |
      | setup_future_usage   | ON_SESSION               |
      | off_session          | false                    |
      | order_category       | physical                 |
      | payment_channel      | ECOMMERCE                |
      | description          | No3DS auto capture card payment (debit) |
    And the payment method is a debit card:
      | field           | value            |
      | card_number     | 4111111111111111 |
      | card_exp_month  | 08               |
      | card_exp_year   | 30               |
      | card_cvc        | 999              |
      | card_holder_name| auto_generate    |
      | card_type       | debit            |
    And the customer details are auto-generated
    And the shipping and billing addresses are provided
    When I send an authorize payment request
    Then the response status should be one of "CHARGED", "AUTHORIZED"
    And the response should contain a "connector_transaction_id"
    And the response should not contain an "error"

  @default @scenario:no3ds_manual_capture_credit_card
  Scenario: No3DS manual capture with credit card
    Given a payment request with:
      | field                | value                    |
      | merchant_transaction_id | auto_generate         |
      | amount               | 6000 minor units USD     |
      | capture_method       | MANUAL                   |
      | auth_type            | NO_THREE_DS              |
      | enrolled_for_3ds     | false                    |
      | setup_future_usage   | ON_SESSION               |
      | off_session          | false                    |
      | order_category       | physical                 |
      | payment_channel      | ECOMMERCE                |
      | description          | No3DS manual capture card payment (credit) |
    And the payment method is a credit card:
      | field           | value            |
      | card_number     | 4111111111111111 |
      | card_exp_month  | 08               |
      | card_exp_year   | 30               |
      | card_cvc        | 999              |
      | card_holder_name| auto_generate    |
      | card_type       | credit           |
    And the customer details are auto-generated
    And the shipping and billing addresses are provided
    When I send an authorize payment request
    Then the response status should be one of "AUTHORIZED"
    And the response should contain a "connector_transaction_id"
    And the response should not contain an "error"

  @scenario:no3ds_manual_capture_debit_card
  Scenario: No3DS manual capture with debit card
    Given a payment request with:
      | field                | value                    |
      | merchant_transaction_id | auto_generate         |
      | amount               | 6000 minor units USD     |
      | capture_method       | MANUAL                   |
      | auth_type            | NO_THREE_DS              |
      | enrolled_for_3ds     | false                    |
      | setup_future_usage   | ON_SESSION               |
      | off_session          | false                    |
      | order_category       | physical                 |
      | payment_channel      | ECOMMERCE                |
      | description          | No3DS manual capture card payment (debit) |
    And the payment method is a debit card:
      | field           | value            |
      | card_number     | 4111111111111111 |
      | card_exp_month  | 08               |
      | card_exp_year   | 30               |
      | card_cvc        | 999              |
      | card_holder_name| auto_generate    |
      | card_type       | debit            |
    And the customer details are auto-generated
    And the shipping and billing addresses are provided
    When I send an authorize payment request
    Then the response status should be one of "AUTHORIZED"
    And the response should contain a "connector_transaction_id"
    And the response should not contain an "error"

  @scenario:no3ds_fail_payment
  Scenario: No3DS payment failure with declined card
    Given a payment request with:
      | field                | value                    |
      | merchant_transaction_id | auto_generate         |
      | amount               | 6000 minor units USD     |
      | capture_method       | AUTOMATIC                |
      | auth_type            | NO_THREE_DS              |
      | enrolled_for_3ds     | false                    |
      | setup_future_usage   | ON_SESSION               |
      | off_session          | false                    |
      | order_category       | physical                 |
      | payment_channel      | ECOMMERCE                |
      | description          | No3DS fail payment flow  |
    And the payment method is a credit card:
      | field           | value            |
      | card_number     | 4000000000000002 |
      | card_exp_month  | 01               |
      | card_exp_year   | 35               |
      | card_cvc        | 123              |
      | card_holder_name| auto_generate    |
      | card_type       | credit           |
    And the customer details are auto-generated
    And the shipping and billing addresses are provided
    When I send an authorize payment request
    Then the response status should be one of "FAILURE", "AUTHORIZATION_FAILED", "ROUTER_DECLINED", "UNRESOLVED"
    And the response should contain an "error"
    And the error connector details message should contain "decline"
