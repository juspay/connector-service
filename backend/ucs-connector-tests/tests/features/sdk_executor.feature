Feature: SDK Executor
  SDK support matrix, authentication config mapping, and payload parsing.

  Scenario: SDK support matrix matches current scope
    Then "stripe" is a supported SDK connector
    And "paypal" is a supported SDK connector
    And "authorizedotnet" is a supported SDK connector
    And "adyen" is not a supported SDK connector
    And "authorize" is a supported SDK suite
    And "create_access_token" is a supported SDK suite
    And "refund_sync" is not a supported SDK suite

  Scenario: Stripe auth maps to proto shape
    Given a header key auth with api_key "sk_test_123"
    When building proto connector config for "stripe"
    Then the config contains a Stripe variant

  Scenario: PayPal auth accepts body and signature shapes
    Given a body key auth with api_key "client_secret" and key1 "client_id"
    When building proto connector config for "paypal"
    Then the config contains a Paypal variant
    Given a signature key auth with api_key "client_secret", key1 "client_id", and api_secret "payer_id"
    When building proto connector config for "paypal"
    Then the config contains a Paypal variant

  Scenario: Authorize scenario maps to card payment method
    Given the authorize scenario "no3ds_auto_capture_credit_card" loaded for "authorizedotnet"
    When the SDK payload is parsed as an authorize request
    Then the payment method is a Card variant

  Scenario: Serde shapes for oneof wrappers are nested
    When a PaymentMethod with Card variant is serialized
    Then the JSON has a "payment_method" key
    When an Identifier with Id variant is serialized
    Then the JSON has a "id_type" key
