@connector:stripe @suite:setup_recurring @override
Feature: Stripe - Setup Recurring Payment Overrides
  Connector-specific overrides for Stripe setup recurring scenarios.

  Stripe override for setup_recurring_with_order_context:
    grpc_req patch: off_session -> null (field removed from request)

  Background:
    Given the dependency "create_access_token" suite default scenario has been executed
    And the dependency "create_customer" suite default scenario has been executed
    And dependency context is propagated to the current request

  @scenario:setup_recurring_with_order_context
  Scenario: Setup recurring payment with order context (Stripe removes off_session)
    Given a request is loaded from "setup_recurring" suite scenario "setup_recurring_with_order_context"
    And connector overrides are applied for connector "stripe"
    # Stripe override sets off_session to null, removing it from the request
    And context placeholders are prepared for suite "setup_recurring"
    And implicit context from dependency requests and responses is applied
    And auto-generated fields are resolved
    And unresolved context fields are pruned
    When the "setup_recurring" request is sent via gRPC method "types.PaymentService/SetupRecurring"
    Then the response field "mandate_reference.connector_mandate_id.connector_mandate_id" should exist
    And the response field "error" should not exist
