@suite:create_customer @independent
Feature: Create Customer
  As a payment service consumer
  I want to create a customer record on the connector
  So that I can associate payments and recurring mandates with a customer

  Background:
    Given the connector is configured in test mode

  @default @scenario:create_customer
  Scenario: Create customer with full address details
    Given a merchant customer ID is auto-generated with prefix "cust_"
    And a customer name is auto-generated
    And a customer email is auto-generated
    And a customer phone number is auto-generated
    And a shipping address is provided:
      | field              | value          |
      | first_name         | auto_generate  |
      | last_name          | auto_generate  |
      | line1              | auto_generate  |
      | line2              | auto_generate  |
      | line3              | auto_generate  |
      | city               | auto_generate  |
      | state              | CA             |
      | zip_code           | auto_generate  |
      | country_alpha2_code| US             |
      | email              | auto_generate  |
      | phone_number       | auto_generate  |
      | phone_country_code | +91            |
    And a billing address is provided with the same structure
    And test mode is enabled
    When I send a create customer request
    Then the response should contain a "connector_customer_id"
    And the response should not contain an "error"
    And the response status code should be one of 200, 201
