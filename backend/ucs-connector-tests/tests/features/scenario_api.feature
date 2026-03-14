Feature: Scenario API Orchestration
  Core orchestration for scenario execution, context mapping, grpcurl building, normalization, and schema validation.

  Scenario: Run test accepts explicit suite and scenario
    When run_test is called with suite "authorize", scenario "no3ds_manual_capture_credit_card", connector "stripe"
    Then run_test succeeds

  Scenario: Run test uses default suite and scenario
    Then the default suite is "authorize"
    And the default scenario is "no3ds_auto_capture_credit_card"
    When run_test is called with no arguments
    Then run_test succeeds

  Scenario: Connector override is applied to assertions
    Given base assertions for authorize/no3ds_fail_payment
    And connector-overridden assertions for authorize/no3ds_fail_payment on stripe
    Then the base message assertion contains "decline"
    And the overridden message assertion contains "declin"
    And the base assertions include a status rule
    And the overridden assertions do not include a status rule

  Scenario: Builds grpcurl command
    When a grpcurl command is built for authorize/no3ds_auto_capture_credit_card on stripe at localhost:50051
    Then the command contains "grpcurl -plaintext"
    And the command contains "types.PaymentService/Authorize"
    And the command contains x-connector stripe
    And the command contains auth_type NO_THREE_DS

  Scenario: Builds grpcurl request struct
    When a grpcurl request struct is built for authorize/no3ds_auto_capture_credit_card on stripe at localhost:50051
    Then the request endpoint is "localhost:50051"
    And the request method is "types.PaymentService/Authorize"
    And the request payload contains auth_type NO_THREE_DS
    And the request has non-empty headers

  Scenario: Extracts JSON body from verbose grpc output
    Given verbose grpc output with Response contents containing status "CHARGED" and connector_transaction_id "txn_123"
    When the JSON body is extracted from grpc output
    Then the extracted status is "CHARGED"
    And the extracted connector_transaction_id id is "txn_123"

  Scenario: Extracts plain JSON body without verbose sections
    Given plain grpc output with status "PENDING"
    When the JSON body is extracted from grpc output
    Then the extracted status is "PENDING"

  Scenario: Build grpcurl request resolves auto_generate placeholders
    When a grpcurl request is built for authorize/no3ds_manual_capture_credit_card on stripe
    Then the payload does not contain "auto_generate"
    And the merchant_transaction_id starts with "mti_"
    And the customer id starts with "cust_"

  Scenario: Add context overrides with latest index preference
    Given previous requests with customer ids "cust_old" and "cust_new"
    And previous responses with transaction ids "txn_old" and "txn_new"
    And a current request with default customer id and transaction id
    When context is added from previous requests and responses
    Then the current customer id is "cust_new"
    And the current transaction id is "txn_new"

  Scenario: Add context keeps scenario-specific values when context is dependency-only
    Given dependency requests with customer id "cust_dep"
    And dependency responses with access_token "token_dep"
    When context is added to a scenario with capture_method "AUTOMATIC"
    Then the capture_method remains "AUTOMATIC"
    And the customer id is "cust_dep"
    And the access_token is "token_dep"
    When context is added to a scenario with capture_method "MANUAL"
    Then the capture_method remains "MANUAL"

  Scenario: Add context maps refund_id from connector_refund_id
    Given a previous response with connectorRefundId "rf_123"
    And a current request with refund_id "auto_generate"
    When context is added
    Then the refund_id is "rf_123"

  Scenario: Add context maps identifier PascalCase oneof variant
    Given a previous response with connector_transaction_id id_type Id "txn_sdk_123"
    And a current request with connector_transaction_id id "auto_generate"
    When context is added
    Then the connector_transaction_id id is "txn_sdk_123"

  Scenario: Add context maps mandate reference into mandate_reference_id
    Given a previous response with mandateReference connectorMandateId "mdt_123"
    And a current request with mandate_reference_id connector_mandate_id "auto_generate"
    When context is added
    Then the mandate_reference_id connector_mandate_id is "mdt_123"

  Scenario: Add context does not map mandate reference into connector_recurring_payment_id
    Given a previous response with mandateReference connectorMandateId "mdt_456"
    And a current request with connector_recurring_payment_id connector_mandate_id "auto_generate"
    When context is added
    Then the connector_recurring_payment_id connector_mandate_id remains "auto_generate"

  Scenario: Add context maps access token fields into state.access_token
    Given a previous response with access_token "tok_123", token_type "Bearer", expires_in_seconds 3600
    And a current request with empty state.access_token fields
    When context is added
    Then the state access_token token value is "tok_123"
    And the state access_token token_type is "Bearer"
    And the state access_token expires_in_seconds is 3600

  Scenario: Add context maps connector_customer_id to nested targets
    Given a previous response with connector_customer_id "cust_dep_123"
    When context is added to a request with customer.connector_customer_id
    Then customer.connector_customer_id is "cust_dep_123"
    When context is added to a request with state.connector_customer_id
    Then state.connector_customer_id is "cust_dep_123"

  Scenario: Add context maps connector_feature_data value
    Given a previous response with connectorFeatureData value containing authorize_id
    And a current request with connector_feature_data value "auto_generate"
    When context is added
    Then the connector_feature_data value contains "authorize_id"

  Scenario: Prepare context placeholders converts empty values to auto_generate
    Given a capture request with empty connector_customer_id and access_token fields
    When context placeholders are prepared for "capture" on "stripe"
    Then all context-carried fields are set to "auto_generate"

  Scenario: Prune unresolved context fields drops unresolved values
    Given a request with unresolved auto_generate context fields and a real merchant_transaction_id
    When unresolved context fields are pruned for "stripe"
    Then the unresolved fields are removed or nullified
    And the merchant_transaction_id id is preserved as "mti_real"

  Scenario: Prune unresolved context fields keeps resolved values
    Given a request with fully resolved context fields
    When unresolved context fields are pruned for "stripe"
    Then all resolved fields are preserved

  Scenario: Normalizer unwraps value wrappers
    Given a request with value-wrapped card_number and email fields
    When the request is normalized for tonic for "stripe" "authorize"
    Then the card_number is unwrapped to a plain string
    And the email is unwrapped to a plain string

  Scenario: Normalizer drops legacy get handle_response bool
    Given a get request with handle_response true
    When the request is normalized for tonic for "stripe" "get"
    Then the handle_response field is removed
    And the connector_transaction_id is preserved

  Scenario: Normalizer adds authorize order_details default
    Given an authorize request without order_details
    When the request is normalized for tonic for "stripe" "authorize"
    Then the order_details is set to an empty array

  Scenario: Normalizer adds customer_acceptance accepted_at default
    Given a setup_recurring request with customer_acceptance but no accepted_at
    When the request is normalized for tonic for "stripe" "setup_recurring"
    Then the accepted_at is set to a non-negative integer

  Scenario: Normalizer wraps connector recurring mandate oneof
    Given a recurring_charge request with connector_recurring_payment_id mandate
    When the request is normalized for tonic for "paypal" "recurring_charge"
    Then the mandate is wrapped in mandate_id_type ConnectorMandateId

  Scenario: Deep set creates intermediate objects
    Given an empty JSON object
    When deep_set is called with path "state.access_token.token.value" and value "tok_abc"
    Then the value at state.access_token.token.value is "tok_abc"

  Scenario: Deep set overwrites existing leaf
    Given a JSON object with existing state.access_token.token.value "old"
    When deep_set is called with path "state.access_token.token.value" and value "new"
    Then the value at state.access_token.token.value is "new"

  Scenario: Deep set single segment
    Given a JSON object with foo "bar"
    When deep_set is called with path "baz" and value 42
    Then the value at baz is 42
    And the value at foo is "bar"

  Scenario: Deep set partial existing path
    Given a JSON object with state.existing true
    When deep_set is called with path "state.access_token.token.value" and value "tok_xyz"
    Then the value at state.access_token.token.value is "tok_xyz"
    And the value at state.existing is true

  Scenario: Apply context map maps response field to deep target
    Given a context map entry from "res.access_token" to "state.access_token.token.value"
    And a dependency response with access_token "paypal_tok_123"
    And a request with amount minor_amount 1000
    When the context map is applied
    Then state.access_token.token.value is "paypal_tok_123"
    And amount.minor_amount is 1000

  Scenario: Apply context map maps request field with req prefix
    Given a context map entry from "req.customer.id" to "customer.id"
    And a dependency request with customer id "cust_from_dep"
    And a request with customer id "placeholder"
    When the context map is applied
    Then customer.id is "cust_from_dep"

  Scenario: Apply context map defaults to response when no prefix
    Given a context map entry from "connectorTransactionId.id" to "connector_transaction_id.id"
    And a dependency response with connectorTransactionId id "txn_abc"
    And a request with connector_transaction_id id "placeholder"
    When the context map is applied
    Then connector_transaction_id.id is "txn_abc"

  Scenario: Apply context map skips null source values
    Given a context map entry from "res.missing_field" to "field_a"
    And a dependency response without missing_field
    And a request with field_a "original"
    When the context map is applied
    Then field_a is "original"

  Scenario: Apply context map with multiple dependencies
    Given two context maps with access_token and customer_id mappings
    And dependency responses with access_token "tok_paypal" and customer_id "cust_stripe_123"
    And a request with amount minor_amount 500
    When the context map is applied
    Then state.access_token.token.value is "tok_paypal"
    And customer.id is "cust_stripe_123"
    And amount.minor_amount is 500

  Scenario: Apply context map with camelCase response lookup
    Given a context map entry from "res.token_type" to "state.access_token.token_type"
    And a dependency response with tokenType "Bearer"
    When the context map is applied
    Then state.access_token.token_type is "Bearer"

  Scenario: Apply context map empty map is noop
    Given an empty context map
    And a request with field "original"
    When the context map is applied
    Then field is "original"

  Scenario: Apply context map with id_type.id unwrapping
    Given a context map entry from "res.connector_transaction_id.id" to "connector_transaction_id.id"
    And a dependency response with connectorTransactionId idType id "pi_3ABC"
    And a request with connector_transaction_id id "placeholder"
    When the context map is applied
    Then connector_transaction_id.id is "pi_3ABC"

  Scenario: Explicit context map overrides implicit context value
    Given a request with empty state.access_token.token.value
    And implicit dependency responses set access_token to "implicit_tok"
    When implicit context is applied
    And explicit context map sets state.access_token.token.value from "explicit_tok"
    Then state.access_token.token.value is "explicit_tok"

  Scenario: All supported scenarios match proto schema for all connectors
    Then every connector's scenarios match their proto schema

  Scenario: All override entries match existing scenarios and proto schema
    Then every connector's override entries reference valid scenarios and match proto schema
