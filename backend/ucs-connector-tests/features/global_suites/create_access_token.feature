@suite:create_access_token @independent
Feature: Create Access Token
  As a payment service consumer
  I want to create an access token for a connector
  So that I can authenticate subsequent API calls

  Background:
    Given the connector is configured in test mode

  @default @scenario:create_access_token
  Scenario: Create access token successfully
    Given a create access token request is loaded from "create_access_token" suite scenario "create_access_token"
    And the request field "connector" is set to the connector name
    And auto-generated fields are resolved
    When the "create_access_token" request is sent via gRPC method "types.MerchantAuthenticationService/CreateAccessToken"
    Then the response field "status" should be one of:
      | OPERATION_STATUS_SUCCESS |
    And the response field "access_token" should exist
    And the response field "error" should not exist
