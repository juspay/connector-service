Feature: Stripe Payment Flows
  As a merchant using the Connector Service
  I want to process payments through Stripe
  So that I can charge customers and manage refunds

  Background:
    Given I am using the Stripe connector
    And I have a valid merchant account
    And I have a test card with number "4111111111111111"

  # ============================================================================
  # Basic Payment Flows
  # ============================================================================
  
  Scenario: Successfully process a payment with automatic capture
    Given I want to process a payment of 1000 cents in "USD"
    And I want to use automatic capture
    When I authorize the payment
    Then the payment should be "charged"
    When I want to attempt a refund of the payment for 2000 cents in "USD"
    Then the refund should be "failed"

  Scenario: Successfully authorize a payment with manual capture
    Given I want to process a payment of 1000 cents in "USD"
    And I want to use manual capture
    When I authorize the payment
    Then I should receive a transaction ID
    And the payment should be "authorized"
    And no error should occur

  Scenario: Successfully capture an authorized payment
    Given I want to process a payment of 1000 cents in "USD"
    And I want to use manual capture
    When I authorize the payment
    Then I should receive a transaction ID
    And the payment should be "authorized"
    When I capture the payment
    Then the payment should be "charged"
    And no error should occur

  Scenario: Successfully void an authorized payment
    Given I want to process a payment of 1000 cents in "USD"
    And I want to use manual capture
    When I authorize the payment
    Then I should receive a transaction ID
    And the payment should be "authorized"
    When I void the payment
    Then the payment should be "voided"
    And no error should occur

  # ============================================================================
  # Payment Sync and Status Check
  # ============================================================================

  Scenario: Successfully sync payment status after capture
    Given I want to process a payment of 1000 cents in "USD"
    And I want to use automatic capture
    When I authorize the payment
    Then I should receive a transaction ID
    And the payment should be "charged"
    When I sync the payment status
    Then the payment should be "charged"
    And no error should occur

  Scenario: Successfully sync voided payment status
    Given I want to process a payment of 1000 cents in "USD"
    And I want to use manual capture
    When I authorize the payment
    Then I should receive a transaction ID
    And the payment should be "authorized"
    When I void the payment
    Then the payment should be "voided"
    When I sync the payment status
    Then the payment should be "voided"
    And no error should occur

  # ============================================================================
  # Refund Flows
  # ============================================================================

  Scenario: Successfully process a full refund
    Given I want to process a payment of 1000 cents in "USD"
    And I want to use automatic capture
    When I authorize the payment
    Then I should receive a transaction ID
    And the payment should be "charged"
    When I process a refund
    Then I should receive a refund ID
    And the refund should be "successful"
    And no error should occur

  Scenario: Successfully sync refund status
    Given I want to process a payment of 1000 cents in "USD"
    And I want to use automatic capture
    When I authorize the payment
    Then I should receive a transaction ID
    And the payment should be "charged"
    When I process a refund
    Then I should receive a refund ID
    And the refund should be "successful"
    When I sync the refund status
    Then the refund should be "successful"
    And no error should occur

  # ============================================================================
  # End-to-End Payment Lifecycle
  # ============================================================================

  Scenario: Complete payment lifecycle - authorize, capture, and refund
    Given I want to process a payment of 1000 cents in "USD"
    And I want to use manual capture
    When I authorize the payment
    Then I should receive a transaction ID
    And the payment should be "authorized"
    When I capture the payment
    Then the payment should be "charged"
    When I sync the payment status
    Then the payment should be "charged"
    When I process a refund
    Then I should receive a refund ID
    And the refund should be "successful"
    When I sync the refund status
    Then the refund should be "successful"
    And no error should occur

  Scenario: Complete payment lifecycle - authorize, void, and verify
    Given I want to process a payment of 1000 cents in "USD"
    And I want to use manual capture
    When I authorize the payment
    Then I should receive a transaction ID
    And the payment should be "authorized"
    When I void the payment
    Then the payment should be "voided"
    When I sync the payment status
    Then the payment should be "voided"
    And no error should occur
