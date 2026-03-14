Feature: Report Generation and Sanitization
  Extracting payment method data, ordering suites, generating markdown reports, and masking sensitive data.

  Scenario: Extract payment method and type from card request
    Given a request JSON with a card payment method of type "credit"
    When payment method info is extracted
    Then the payment method is "card"
    And the payment method type is "credit"

  Scenario: Extract payment method from request without payment_method
    Given a request JSON with only an amount field
    When payment method info is extracted
    Then the payment method is absent
    And the payment method type is absent

  Scenario: Suite ordering is consistent
    Then "create_access_token" sorts before "authorize"
    And "authorize" sorts before "capture"
    And "capture" sorts before "refund"
    And "refund" sorts before "get"
    And "get" sorts before "refund_sync"
    And "refund_sync" sorts before "setup_recurring"
    And "setup_recurring" sorts before "recurring_charge"

  Scenario: Generated markdown uses plain status without badges
    Given a report with stripe PASS and paypal FAIL entries for authorize suite
    When markdown is generated from the report
    Then the overview markdown does not contain shield badge URLs
    And the overview contains a Connector Flow Matrix section
    And the stripe pass rate link shows 100.0%
    And the paypal pass rate link shows 0.0%
    And the stripe suite detail has the correct heading and scenario links
    And the stripe scenario detail has request and response sections
    And the paypal scenario detail has dependency request and response sections
    And the paypal suite detail has a Failed Scenarios section

  Scenario: Sanitization masks sensitive gRPC trace and JSON fields
    Given a report entry with sensitive api_key, card_number, bearer tokens in grpc traces
    When the report entry is sanitized
    Then the grpc_request does not contain the original api key or token
    And the grpc_response does not contain the original api key or token
    And the error text does not contain the original token
    And the request body api_key is masked
    And the request body card_number is masked
    And the request body card_cvc is masked
    And the response body access_token is masked

  Scenario: Bearer masking is idempotent and masks multiple tokens
    Given a line with multiple Bearer tokens "abc123" and "def456" and an already masked token
    When bearer tokens are masked twice
    Then the result is the same both times
    And neither "abc123" nor "def456" appear in the output
