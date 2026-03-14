Feature: JSON Merge Patch
  RFC 7396 JSON merge patch operations for connector override merging.

  Scenario: Merge patch adds, replaces, and removes keys
    Given a JSON object with amount and customer fields
    When a merge patch is applied that changes currency, removes email, and adds connector_feature_data
    Then the amount minor_amount is preserved as 1000
    And the amount currency is changed to "EUR"
    And the customer id is preserved as "cust_123"
    And the customer email field is removed
    And the connector_feature_data value is set

  Scenario: Merge patch replaces non-object values with objects
    Given a JSON object with capture_method set to "AUTOMATIC"
    When a merge patch replaces capture_method with an object containing value "MANUAL"
    Then the capture_method is an object with value "MANUAL"
