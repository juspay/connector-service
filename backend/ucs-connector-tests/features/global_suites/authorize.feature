@suite:authorize @dependent
Feature: Payment Authorization
  As a payment service consumer
  I want to authorize payments using various card types and capture methods
  So that I can process payments through the connector

  The authorize suite depends on create_access_token and create_customer.
  Both dependencies run once (suite-level scope) and their responses
  provide implicit context (access_token, connector_customer_id) to
  the authorize request.

  Background:
    Given the dependency "create_access_token" suite default scenario has been executed
    And the dependency "create_customer" suite default scenario has been executed
    And dependency context is propagated to the current request

  @scenario:no3ds_auto_capture_credit_card
  Scenario: No3DS auto capture with credit card
    Given a request is loaded from "authorize" suite scenario "no3ds_auto_capture_credit_card"
    And connector overrides are applied for the current connector
    And context placeholders are prepared for suite "authorize"
    And implicit context from dependency requests and responses is applied
    And auto-generated fields are resolved
    And unresolved context fields are pruned
    When the "authorize" request is sent via gRPC method "types.PaymentService/Authorize"
    Then the response field "status" should be one of:
      | CHARGED    |
      | AUTHORIZED |
    And the response field "connector_transaction_id" should exist
    And the response field "error" should not exist

  @scenario:no3ds_auto_capture_debit_card
  Scenario: No3DS auto capture with debit card
    Given a request is loaded from "authorize" suite scenario "no3ds_auto_capture_debit_card"
    And connector overrides are applied for the current connector
    And context placeholders are prepared for suite "authorize"
    And implicit context from dependency requests and responses is applied
    And auto-generated fields are resolved
    And unresolved context fields are pruned
    When the "authorize" request is sent via gRPC method "types.PaymentService/Authorize"
    Then the response field "status" should be one of:
      | CHARGED    |
      | AUTHORIZED |
    And the response field "connector_transaction_id" should exist
    And the response field "error" should not exist

  @default @scenario:no3ds_manual_capture_credit_card
  Scenario: No3DS manual capture with credit card
    Given a request is loaded from "authorize" suite scenario "no3ds_manual_capture_credit_card"
    And connector overrides are applied for the current connector
    And context placeholders are prepared for suite "authorize"
    And implicit context from dependency requests and responses is applied
    And auto-generated fields are resolved
    And unresolved context fields are pruned
    When the "authorize" request is sent via gRPC method "types.PaymentService/Authorize"
    Then the response field "status" should be one of:
      | AUTHORIZED |
    And the response field "connector_transaction_id" should exist
    And the response field "error" should not exist

  @scenario:no3ds_manual_capture_debit_card
  Scenario: No3DS manual capture with debit card
    Given a request is loaded from "authorize" suite scenario "no3ds_manual_capture_debit_card"
    And connector overrides are applied for the current connector
    And context placeholders are prepared for suite "authorize"
    And implicit context from dependency requests and responses is applied
    And auto-generated fields are resolved
    And unresolved context fields are pruned
    When the "authorize" request is sent via gRPC method "types.PaymentService/Authorize"
    Then the response field "status" should be one of:
      | AUTHORIZED |
    And the response field "connector_transaction_id" should exist
    And the response field "error" should not exist

  @scenario:no3ds_fail_payment
  Scenario: No3DS payment failure with declined card
    Given a request is loaded from "authorize" suite scenario "no3ds_fail_payment"
    And connector overrides are applied for the current connector
    And context placeholders are prepared for suite "authorize"
    And implicit context from dependency requests and responses is applied
    And auto-generated fields are resolved
    And unresolved context fields are pruned
    When the "authorize" request is sent via gRPC method "types.PaymentService/Authorize"
    Then the response field "status" should be one of:
      | FAILURE              |
      | AUTHORIZATION_FAILED |
      | ROUTER_DECLINED      |
      | UNRESOLVED           |
    And the response field "error" should exist
    And the response field "error.connector_details.message" should contain "decline"
