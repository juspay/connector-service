@suite:create_customer @independent
Feature: Create Customer
  As a payment service consumer
  I want to create a customer record on the connector
  So that I can associate payments and recurring mandates with a customer

  Background:
    Given the connector is configured in test mode

  @default @scenario:create_customer
  Scenario: Create customer with full address details
    Given a create customer request is loaded from "create_customer" suite scenario "create_customer"
    And connector overrides are applied for the current connector
    And auto-generated fields are resolved
    When the "create_customer" request is sent via gRPC method "types.CustomerService/Create"
    Then the response field "connector_customer_id" should exist
    And the response field "error" should not exist
    And the response field "status_code" should be one of:
      | 200 |
      | 201 |
