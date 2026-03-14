Feature: Connector Override Loading and Patching
  Loading connector-specific override patches from files and applying assertion patches.

  Scenario: Missing override file returns None
    Given a temporary override root directory with no override files
    When loading a scenario override patch for "stripe" suite "authorize" scenario "no3ds_fail_payment"
    Then the loaded override patch is None

  Scenario: Override patch is loaded from connector file
    Given a temporary override root directory with a stripe override file for authorize/no3ds_fail_payment
    When loading a scenario override patch for "stripe" suite "authorize" scenario "no3ds_fail_payment"
    Then the loaded override patch contains a grpc_req patch with card_number "4000000000000002"
    And the loaded override patch contains assertion rules

  Scenario: Assertion patch adds, replaces, and removes rules
    Given an assertions map with status "AUTHORIZED" and error must_not_exist
    When an assertion patch is applied that changes status to "CHARGED", removes error, and adds connector_transaction_id
    Then the status assertion is one_of "CHARGED"
    And the error assertion is removed
    And the connector_transaction_id assertion is must_exist true
