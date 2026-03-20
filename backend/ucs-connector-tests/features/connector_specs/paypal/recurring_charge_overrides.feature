@connector:paypal @suite:recurring_charge @override
Feature: PayPal - Recurring Charge Overrides
  Connector-specific overrides for PayPal recurring charge scenarios.

  PayPal override for all recurring_charge scenarios:
    grpc_req patch: payment_method_type -> "CREDIT",
                    connector_customer_id -> null (removed),
                    customer -> null (removed)

  Background:
    Given the dependency "create_access_token" suite default scenario has been executed
    And the dependency "create_customer" suite default scenario has been executed
    And the dependency "setup_recurring" suite default scenario has been executed with context map:
      | target_path                                                                    | source_path                                                         |
      | connector_recurring_payment_id.connector_mandate_id.connector_mandate_id       | res.mandate_reference.connector_mandate_id.connector_mandate_id     |
    And dependency context is propagated to the current request

  @scenario:recurring_charge
  Scenario: Charge using a recurring mandate (PayPal adds payment_method_type, removes customer)
    Given a request is loaded from "recurring_charge" suite scenario "recurring_charge"
    And connector overrides are applied for connector "paypal"
    # PayPal override adds payment_method_type=CREDIT and removes connector_customer_id and customer
    And context placeholders are prepared for suite "recurring_charge"
    And implicit context from dependency requests and responses is applied
    And explicit context map entries are applied
    And auto-generated fields are resolved
    And unresolved context fields are pruned
    When the "recurring_charge" request is sent via gRPC method "types.RecurringPaymentService/Charge"
    Then the response field "connector_transaction_id" should exist
    And the response field "error" should not exist

  @scenario:recurring_charge_low_amount
  Scenario: Charge a low amount using a recurring mandate (PayPal-specific)
    Given a request is loaded from "recurring_charge" suite scenario "recurring_charge_low_amount"
    And connector overrides are applied for connector "paypal"
    And context placeholders are prepared for suite "recurring_charge"
    And implicit context from dependency requests and responses is applied
    And explicit context map entries are applied
    And auto-generated fields are resolved
    And unresolved context fields are pruned
    When the "recurring_charge" request is sent via gRPC method "types.RecurringPaymentService/Charge"
    Then the response field "connector_transaction_id" should exist
    And the response field "error" should not exist

  @scenario:recurring_charge_with_order_context
  Scenario: Charge using a recurring mandate with order context (PayPal-specific)
    Given a request is loaded from "recurring_charge" suite scenario "recurring_charge_with_order_context"
    And connector overrides are applied for connector "paypal"
    And context placeholders are prepared for suite "recurring_charge"
    And implicit context from dependency requests and responses is applied
    And explicit context map entries are applied
    And auto-generated fields are resolved
    And unresolved context fields are pruned
    When the "recurring_charge" request is sent via gRPC method "types.RecurringPaymentService/Charge"
    Then the response field "connector_transaction_id" should exist
    And the response field "error" should not exist
