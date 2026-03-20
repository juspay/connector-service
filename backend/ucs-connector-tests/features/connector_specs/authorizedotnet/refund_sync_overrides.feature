@connector:authorizedotnet @suite:refund_sync @override
Feature: Authorize.Net - Refund Sync Overrides
  Connector-specific overrides for Authorize.Net refund sync scenarios.
  Authorize.Net uses a fixed refund reference ID and accepts a wider range
  of statuses including failure states.

  @scenario:refund_sync
  Scenario: Synchronize refund status (Authorize.Net-specific)
    # Override: Uses fixed refund_id "authnet_refund_reference" instead of auto-generated
    # Override: Adds merchant_refund_id
    # Override: Accepts FAILURE/UNRESOLVED statuses in addition to normal ones
    # Override: Removes error assertion (null)
    Given a refund sync request with:
      | field                    | value                       |
      | connector_transaction_id | auto_generate               |
      | refund_id                | authnet_refund_reference    |
      | merchant_refund_id       | auto_generate               |
    And the state includes connector customer ID and access token
    When I send a refund sync request
    Then the response status should be one of "PENDING", "REFUND_SUCCESS", "FAILURE", "UNRESOLVED"
    # Note: error assertion is removed (null override) for Authorize.Net

  @scenario:refund_sync_with_reason
  Scenario: Synchronize refund status with reason (Authorize.Net-specific)
    # Override: Same as above with fixed refund reference
    Given a refund sync request with:
      | field                    | value                       |
      | connector_transaction_id | auto_generate               |
      | refund_id                | authnet_refund_reference    |
      | merchant_refund_id       | auto_generate               |
      | refund_reason            | customer_requested          |
    And the state includes connector customer ID and access token
    When I send a refund sync request
    Then the response status should be one of "PENDING", "REFUND_SUCCESS", "FAILURE", "UNRESOLVED"
    # Note: error assertion is removed (null override) for Authorize.Net
