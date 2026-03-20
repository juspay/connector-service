@connector:authorizedotnet @suite:refund @override
Feature: Authorize.Net - Refund Overrides
  Connector-specific overrides for Authorize.Net refund scenarios.
  Authorize.Net refunds typically fail in test mode because the transaction
  does not meet the criteria for issuing a credit (settlement timing).

  # Authorize.Net supports: create_customer, authorize, capture, void, refund,
  #                          get, refund_sync, setup_recurring, recurring_charge

  @scenario:refund_full_amount
  Scenario: Refund the full payment amount (Authorize.Net-specific)
    # Override: Expects FAILURE/UNRESOLVED status (refund not possible in test mode)
    # Override: Removes connector_refund_id assertion (null)
    # Override: Expects error to be present with settlement criteria message
    Given a refund request with:
      | field                    | value          |
      | merchant_refund_id       | auto_generate  |
      | connector_transaction_id | auto_generate  |
      | payment_amount           | 6000           |
      | refund_amount            | 6000 minor units USD |
    And the state includes connector customer ID and access token
    When I send a refund payment request
    Then the response status should be one of "FAILURE", "UNRESOLVED"
    And the response should contain a "connector_transaction_id"
    And the response should contain an "error"
    And the error connector details message should contain "criteria for issuing a credit"

  @scenario:refund_partial_amount
  Scenario: Refund a partial payment amount (Authorize.Net-specific)
    # Override: Same failure behavior as full refund
    Given a refund request with:
      | field                    | value          |
      | merchant_refund_id       | auto_generate  |
      | connector_transaction_id | auto_generate  |
      | payment_amount           | 6000           |
      | refund_amount            | 3000 minor units USD |
    And the state includes connector customer ID and access token
    When I send a refund payment request
    Then the response status should be one of "FAILURE", "UNRESOLVED"
    And the response should contain a "connector_transaction_id"
    And the response should contain an "error"
    And the error connector details message should contain "criteria for issuing a credit"

  @scenario:refund_with_reason
  Scenario: Refund with a reason (Authorize.Net-specific)
    # Override: Same failure behavior as full refund
    Given a refund request with:
      | field                    | value              |
      | merchant_refund_id       | auto_generate      |
      | connector_transaction_id | auto_generate      |
      | payment_amount           | 6000               |
      | refund_amount            | 6000 minor units USD |
      | reason                   | customer_requested |
    And the state includes connector customer ID and access token
    When I send a refund payment request
    Then the response status should be one of "FAILURE", "UNRESOLVED"
    And the response should contain a "connector_transaction_id"
    And the response should contain an "error"
    And the error connector details message should contain "criteria for issuing a credit"
