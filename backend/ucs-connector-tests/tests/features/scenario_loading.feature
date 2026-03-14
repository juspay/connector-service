Feature: Scenario and Suite Loading
  Loading scenario definitions, suite specs, and connector configurations from disk.

  Scenario: All scenario files can be loaded by name
    Given the scenario root directory exists with at least one suite
    Then every suite contains at least one scenario
    And every scenario has an object grpc_req and non-empty assertion rules

  Scenario: gRPC request and assertions are accessible for all scenarios
    Given the scenario root directory exists with at least one suite
    Then every scenario has an accessible grpc_req that is an object
    And every scenario has accessible non-empty assertions

  Scenario: Suite specs can be loaded for all suites
    Given the scenario root directory exists with at least one suite
    Then every suite spec name matches its folder name
    And every dependency suite name is non-empty
    And every dependency override scenario exists

  Scenario: Dependency scope defaults and overrides are loaded
    Then the authorize suite has dependency scope "Suite"
    And suites "capture, void, refund, get, refund_sync" have dependency scope "Scenario"

  Scenario: Explicit context maps exist for name-mismatch dependencies
    Then the recurring_charge suite has a mandate_reference context map entry
    And the refund_sync suite has a refund_id context map entry

  Scenario: Supported suites can be loaded for known connectors
    Then the stripe connector supports the "authorize" suite

  Scenario: All connectors can be discovered
    Then at least one connector spec exists
    And the "stripe" connector is discoverable
    And the connector list is sorted

  Scenario: Configured connectors default to static run list
    Then the default configured connectors include "stripe", "authorizedotnet", and "paypal"

  Scenario: Configured connectors support env override
    When UCS_ALL_CONNECTORS is set to "stripe, adyen, stripe, ,rapyd"
    Then the configured connectors are "adyen", "rapyd", "stripe"

  Scenario: Recurring charge scenarios exclude unsupported connector_transaction_id field
    Then recurring_charge scenarios "recurring_charge, recurring_charge_low_amount, recurring_charge_with_order_context" do not include connector_transaction_id

  Scenario: Setup recurring extended scenarios have billing address
    Then setup_recurring scenarios "setup_recurring_with_webhook, setup_recurring_with_order_context" include address.billing_address

  Scenario: Three-connector suite coverage includes recurring flows
    Then authorizedotnet supports setup_recurring and recurring_charge suites
    And stripe supports create_customer, setup_recurring, and recurring_charge suites
    And paypal supports create_access_token, setup_recurring, and recurring_charge suites
