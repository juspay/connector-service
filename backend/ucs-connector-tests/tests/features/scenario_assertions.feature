Feature: Scenario Field Assertions
  Evaluating assertion rules against gRPC response JSON payloads.

  Scenario: Core assertion rules all pass on a valid response
    Given a response with status "CHARGED", connectorTransactionId "txn_123", null error, captured_amount 6000, and details message "declined by issuer"
    And a request with amount minor_amount 6000
    When assertions are checked for one_of status, must_exist connector_transaction_id, must_not_exist error, echo captured_amount, and contains "declin" in details.message
    Then all assertions pass
