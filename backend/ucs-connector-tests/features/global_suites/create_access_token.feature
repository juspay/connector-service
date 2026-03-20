@suite:create_access_token @independent
Feature: Create Access Token
  As a payment service consumer
  I want to create an access token for a connector
  So that I can authenticate subsequent API calls

  Background:
    Given the connector is configured in test mode

  @default @scenario:create_access_token
  Scenario: Create access token successfully
    Given a merchant access token ID is auto-generated
    And the connector is "STRIPE"
    And test mode is enabled
    When I send a create access token request
    Then the response status should be one of "OPERATION_STATUS_SUCCESS"
    And the response should contain an "access_token"
    And the response should not contain an "error"
