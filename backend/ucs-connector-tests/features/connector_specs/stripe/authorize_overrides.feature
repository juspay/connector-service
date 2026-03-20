@connector:stripe @suite:authorize @override
Feature: Stripe - Payment Authorization Overrides
  Connector-specific overrides for Stripe payment authorization scenarios.
  These scenarios document how Stripe's behavior differs from the global
  authorize suite defaults.

  Stripe override for no3ds_fail_payment:
    grpc_req patch: card_number -> 4000000000000002 (same as global)
    assert patch: status -> null (removed), error.connector_details.message -> contains "declin"

  Background:
    Given the dependency "create_access_token" suite default scenario has been executed
    And the dependency "create_customer" suite default scenario has been executed
    And dependency context is propagated to the current request

  @scenario:no3ds_fail_payment
  Scenario: No3DS payment failure with Stripe-specific assertions
    Given a request is loaded from "authorize" suite scenario "no3ds_fail_payment"
    And connector overrides are applied for connector "stripe"
    And context placeholders are prepared for suite "authorize"
    And implicit context from dependency requests and responses is applied
    And auto-generated fields are resolved
    And unresolved context fields are pruned
    When the "authorize" request is sent via gRPC method "types.PaymentService/Authorize"
    # Stripe override removes the "status" assertion (null patch)
    # Only the error message assertion remains
    Then the response field "error.connector_details.message" should contain "declin"
