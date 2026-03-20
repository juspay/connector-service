@connector:stripe @suite:authorize @override
Feature: Stripe - Payment Authorization Overrides
  Connector-specific overrides for Stripe payment authorization scenarios.
  These override the global authorize suite scenarios.

  # Stripe supports: create_customer, authorize, capture, void, refund,
  #                   get, refund_sync, setup_recurring, recurring_charge

  @scenario:no3ds_fail_payment
  Scenario: No3DS payment failure with Stripe-specific declined card
    # Override: Uses Stripe's specific decline test card number
    # Override: Removes "status" assertion (set to null)
    # Override: Changes error message assertion to match Stripe's response
    Given a payment request with:
      | field                | value                    |
      | merchant_transaction_id | auto_generate         |
      | amount               | 6000 minor units USD     |
      | capture_method       | AUTOMATIC                |
      | auth_type            | NO_THREE_DS              |
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
    # Note: "status" assertion is removed (null override) for Stripe
    Then the error connector details message should contain "declin"
