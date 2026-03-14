Feature: Auto-generation of placeholder values
  Replacing auto_generate sentinel values in request payloads with generated data.

  Scenario: Sentinel detection supports auto_generate variants
    Then "auto_generate" is detected as an auto_generate sentinel
    And "cust_auto_generate" is detected as an auto_generate sentinel
    And "fixed_value" is not detected as an auto_generate sentinel

  Scenario: ID prefix mapping uses expected prefixes
    Then the id prefix for path "merchant_transaction_id.id" is "mti"
    And the id prefix for path "merchant_refund_id.id" is "mri"
    And the id prefix for path "merchant_customer_id.id" is "mcui"
    And the id prefix for path "unknown.id" is "id"
    And the leaf id prefix for "merchant_transaction_id" is "mti"
    And the leaf id prefix for "merchant_capture_id" is "mci"
    And the leaf id prefix for "unknown" is None

  Scenario: Auto-generate placeholders are resolved in request payload
    Given a request payload with auto_generate placeholders for merchant_transaction_id, customer, address, and payment_method
    When auto-generate placeholders are resolved
    Then the merchant_transaction_id starts with "mti_"
    And the customer name is no longer "auto_generate"
    And the customer email value is no longer "auto_generate"
    And the card_number value remains "4111111111111111"

  Scenario: Context-deferred fields remain unresolved
    Given a request payload with context-deferred fields like connector_customer_id and access_token
    When auto-generate placeholders are resolved
    Then the connector_customer_id remains "auto_generate"
    And the state access_token token value remains "auto_generate"
    And the connector_transaction_id remains "auto_generate"
    And the refund_id remains "auto_generate"
    But the merchant_transaction_id is generated with prefix "mti_"

  Scenario: Context-deferred path matching
    Then "customer.connector_customer_id" is a context-deferred path
    And "state.access_token.token.value" is a context-deferred path
    And "connector_feature_data.value" is a context-deferred path
    And "connector_transaction_id" is a context-deferred path
    And "connector_transaction_id.id" is a context-deferred path
    And "merchant_transaction_id.id" is not a context-deferred path
