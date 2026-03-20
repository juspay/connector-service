@connector:stripe @suite:setup_recurring @override
Feature: Stripe - Setup Recurring Payment Overrides
  Connector-specific overrides for Stripe setup recurring scenarios.

  @scenario:setup_recurring_with_order_context
  Scenario: Setup recurring payment with order context (Stripe-specific)
    # Override: Removes "off_session" field from request (set to null)
    # Stripe does not support off_session during mandate setup
    Given a setup recurring request with:
      | field                        | value                                    |
      | merchant_recurring_payment_id| auto_generate                            |
      | amount                       | 6000 minor units USD                     |
      | auth_type                    | NO_THREE_DS                              |
      | enrolled_for_3ds             | false                                    |
      | setup_future_usage           | OFF_SESSION                              |
      | merchant_order_id            | auto_generate                            |
      | order_category               | subscription                             |
      | return_url                   | https://example.com/payment/return       |
      | webhook_url                  | https://example.com/payment/webhook      |
      | complete_authorize_url       | https://example.com/payment/complete     |
    # Note: "off_session" is explicitly removed for Stripe (null override)
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
