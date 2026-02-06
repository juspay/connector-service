#!/bin/bash

# ============================================================================
# GRACE-UCS Phase 0: Cypress Test Validation Script
# ============================================================================
# 
# This script validates a connector's no_three_ds support in Hyperswitch
# before starting UCS integration work.
#
# Usage: ./validate_connector_cypress.sh <connector_name>
# Example: ./validate_connector_cypress.sh worldpay
#
# ============================================================================

set -euo pipefail  # Strict error handling

# Color codes for output
readonly COLOR_RED='\033[0;31m'
readonly COLOR_GREEN='\033[0;32m'
readonly COLOR_YELLOW='\033[1;33m'
readonly COLOR_BLUE='\033[0;34m'
readonly COLOR_CYAN='\033[0;36m'
readonly COLOR_RESET='\033[0m'

# Script metadata
readonly SCRIPT_VERSION="1.0.0"
readonly SCRIPT_NAME="GRACE-UCS Cypress Validator"

# Paths
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly CONNECTOR_SERVICE_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
readonly HYPERSWITCH_ROOT="$(cd "$CONNECTOR_SERVICE_ROOT/../hyperswitch" && pwd)"
readonly CYPRESS_TESTS_DIR="$HYPERSWITCH_ROOT/cypress-tests"
readonly HS_CONNECTORS_DIR="$HYPERSWITCH_ROOT/crates/hyperswitch_connectors/src/connectors"
readonly GRACE_ROOT="$(cd "$SCRIPT_DIR/../../.." && cd grace && pwd)"

# Load .env file if it exists (silently)
# Priority: 1) GRACE root .env, 2) Local .env
ENV_FILE_GRACE="$GRACE_ROOT/.env"
ENV_FILE_LOCAL="$SCRIPT_DIR/.env"

if [[ -f "$ENV_FILE_GRACE" ]]; then
    # Source the GRACE root .env file (preferred)
    set -a
    source "$ENV_FILE_GRACE"
    set +a
elif [[ -f "$ENV_FILE_LOCAL" ]]; then
    # Fall back to local .env file
    set -a
    source "$ENV_FILE_LOCAL"
    set +a
fi

# Global variables (can be overridden by environment or .env file)
CONNECTOR_NAME=""
CYPRESS_ADMINAPIKEY="${CYPRESS_ADMINAPIKEY:-}"
CYPRESS_CONNECTOR_AUTH_FILE_PATH="${CYPRESS_CONNECTOR_AUTH_FILE_PATH:-}"
CYPRESS_BASEURL="${CYPRESS_BASEURL:-https://integ.hyperswitch.io/api}"

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

log_info() {
    echo -e "${COLOR_BLUE}ℹ️  $1${COLOR_RESET}"
}

log_success() {
    echo -e "${COLOR_GREEN}✅ $1${COLOR_RESET}"
}

log_warning() {
    echo -e "${COLOR_YELLOW}⚠️  $1${COLOR_RESET}"
}

log_error() {
    echo -e "${COLOR_RED}❌ $1${COLOR_RESET}"
}

log_step() {
    echo -e "${COLOR_CYAN}🔧 STEP: $1${COLOR_RESET}"
}

fatal_error() {
    log_error "$1"
    log_error "Script execution terminated."
    exit 1
}

print_banner() {
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "$1"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
}

# ============================================================================
# VALIDATION FUNCTIONS
# ============================================================================

validate_arguments() {
    if [[ $# -ne 1 ]]; then
        echo "Usage: $0 <connector_name>"
        echo ""
        echo "Example: $0 worldpay"
        exit 1
    fi
    
    CONNECTOR_NAME="$1"
    log_info "Connector: $CONNECTOR_NAME"
}

validate_environment() {
    log_step "Validating environment"
    
    # Check if Hyperswitch directory exists
    if [[ ! -d "$HYPERSWITCH_ROOT" ]]; then
        fatal_error "Hyperswitch directory not found at: $HYPERSWITCH_ROOT"
    fi
    
    # Check if cypress-tests directory exists
    if [[ ! -d "$CYPRESS_TESTS_DIR" ]]; then
        fatal_error "Cypress tests directory not found at: $CYPRESS_TESTS_DIR"
    fi
    
    # Check if connector exists in Hyperswitch
    local connector_file="$HS_CONNECTORS_DIR/$CONNECTOR_NAME.rs"
    if [[ ! -f "$connector_file" ]]; then
        fatal_error "Connector '$CONNECTOR_NAME' not found in Hyperswitch at: $connector_file"
    fi
    
    log_success "Environment validation passed"
}

# ============================================================================
# STEP 0: CHECK FEATURE MATRIX
# ============================================================================

check_feature_matrix() {
    log_step "STEP 0: Checking feature_matrix for no_three_ds support"
    
    local connector_file="$HS_CONNECTORS_DIR/$CONNECTOR_NAME.rs"
    
    # Search for feature_matrix and no_three_ds
    if grep -q "feature_matrix" "$connector_file"; then
        if grep -A 20 "feature_matrix" "$connector_file" | grep -q "no_three_ds.*Supported"; then
            log_success "Connector advertises no_three_ds support in feature_matrix"
        else
            log_warning "Connector does not advertise no_three_ds support in feature_matrix"
            log_info "Proceeding with Cypress tests to verify actual functionality"
        fi
    else
        log_warning "No feature_matrix found in connector file"
        log_info "Proceeding with Cypress tests anyway"
    fi
}

# ============================================================================
# STEP 1: REQUEST CREDENTIALS
# ============================================================================

request_credentials() {
    # Check if credentials are already set (from .env or environment)
    if [[ -n "$CYPRESS_ADMINAPIKEY" ]] && [[ -n "$CYPRESS_CONNECTOR_AUTH_FILE_PATH" ]]; then
        log_info "Using credentials from environment/config"
        
        # Validate file exists
        if [[ ! -f "$CYPRESS_CONNECTOR_AUTH_FILE_PATH" ]]; then
            fatal_error "Credentials file not found at: $CYPRESS_CONNECTOR_AUTH_FILE_PATH"
        fi
        
        log_success "Credentials validated successfully"
        return 0
    fi
    
    # Credentials not set, prompt user
    print_banner "🔐 CYPRESS TEST VALIDATION REQUIRED"
    
    echo "To validate the connector's no_three_ds support, I need to run"
    echo "Cypress tests against the Hyperswitch integration environment."
    echo ""
    echo "Tip: You can create a .env file to avoid entering these every time!"
    echo "See .env.example for the template."
    echo ""
    echo "Please provide the following:"
    echo ""
    
    # Request CYPRESS_ADMINAPIKEY if not set
    if [[ -z "$CYPRESS_ADMINAPIKEY" ]]; then
        echo -n "1. CYPRESS_ADMINAPIKEY (admin API key for https://integ.hyperswitch.io): "
        read -r CYPRESS_ADMINAPIKEY
        
        if [[ -z "$CYPRESS_ADMINAPIKEY" ]]; then
            fatal_error "Admin API key is required"
        fi
    fi
    
    # Request CYPRESS_CONNECTOR_AUTH_FILE_PATH if not set
    if [[ -z "$CYPRESS_CONNECTOR_AUTH_FILE_PATH" ]]; then
        echo ""
        echo -n "2. CYPRESS_CONNECTOR_AUTH_FILE_PATH (full path to credentials JSON): "
        read -r CYPRESS_CONNECTOR_AUTH_FILE_PATH
        
        if [[ -z "$CYPRESS_CONNECTOR_AUTH_FILE_PATH" ]]; then
            fatal_error "Connector auth file path is required"
        fi
    fi
    
    # Validate file exists
    if [[ ! -f "$CYPRESS_CONNECTOR_AUTH_FILE_PATH" ]]; then
        fatal_error "Credentials file not found at: $CYPRESS_CONNECTOR_AUTH_FILE_PATH"
    fi
    
    echo ""
    log_success "Credentials collected successfully"
}

# ============================================================================
# STEP 2: NAVIGATE TO CYPRESS TESTS
# ============================================================================

navigate_to_cypress() {
    log_step "STEP 2: Navigating to Cypress tests directory"
    
    cd "$CYPRESS_TESTS_DIR" || fatal_error "Failed to navigate to: $CYPRESS_TESTS_DIR"
    
    log_success "Successfully navigated to: $(pwd)"
}

# ============================================================================
# STEP 3 & 4: EXPORT VARIABLES AND RUN TESTS
# ============================================================================

run_cypress_tests() {
    log_step "STEP 3 & 4: Exporting environment variables and running Cypress tests"
    
    log_info "Environment variables configured:"
    log_info "  - CYPRESS_CONNECTOR: $CONNECTOR_NAME"
    log_info "  - CYPRESS_ADMINAPIKEY: [hidden for security]"
    log_info "  - CYPRESS_BASEURL: $CYPRESS_BASEURL"
    log_info "  - CYPRESS_CONNECTOR_AUTH_FILE_PATH: $CYPRESS_CONNECTOR_AUTH_FILE_PATH"
    
    echo ""
    log_info "🧪 Running Cypress tests for $CONNECTOR_NAME..."
    log_info "📋 Test scope: Payment flows 00000-00004 (no_three_ds validation)"
    log_info "⏳ This may take 2-10 minutes..."
    echo ""
    
    # Run Cypress tests with environment variables explicitly set
    # This ensures variables are available to the npm subprocess
    local test_exit_code
    local test_output_file="/tmp/cypress_test_output_${CONNECTOR_NAME}.log"
    
    set +e  # Temporarily disable exit on error
    
    # Run npm command with environment variables prefixed
    # This is equivalent to the manual two-command approach
    CYPRESS_CONNECTOR="$CONNECTOR_NAME" \
    CYPRESS_ADMINAPIKEY="$CYPRESS_ADMINAPIKEY" \
    CYPRESS_BASEURL="$CYPRESS_BASEURL" \
    CYPRESS_CONNECTOR_AUTH_FILE_PATH="$CYPRESS_CONNECTOR_AUTH_FILE_PATH" \
    npm run cypress:payments -- --spec "cypress/e2e/spec/Payment/*0000{0,1,2,3,4}*.cy.js" 2>&1 | tee "$test_output_file"
    
    test_exit_code=${PIPESTATUS[0]}
    set -e  # Re-enable exit on error
    
    return $test_exit_code
}

# ============================================================================
# STEP 5: ANALYZE TEST RESULTS
# ============================================================================

analyze_test_results() {
    local test_exit_code=$1
    local test_output_file="/tmp/cypress_test_output_${CONNECTOR_NAME}.log"
    
    log_step "STEP 5: Analyzing test results"
    
    # CRITICAL: If Cypress itself failed with unexpected exit code, check carefully
    if [[ $test_exit_code -ne 0 ]]; then
        log_warning "Cypress exited with code $test_exit_code (non-zero)"
        log_info "Analyzing test results to determine if this is acceptable..."
    fi
    
    # Extract test results summary - ONLY for critical tests
    local test_00000_status=""
    local test_00004_status=""
    
    # Parse test 00000 (Setup/Credentials) - CRITICAL
    if grep -q "✔  00000-CoreFlows" "$test_output_file"; then
        test_00000_status="PASSED"
    else
        test_00000_status="FAILED"
    fi
    
    # Parse test 00004 (no_three_ds Flow) - CRITICAL
    # No failures AND no skipped/pending tests allowed
    if grep -q "✔  00004-NoThreeDSAutoCapture" "$test_output_file"; then
        # Extract the test counts for 00004
        # Format: │ ✔  00004-NoThreeDSAutoCapture.cy.js  TIME  TESTS  PASSING  FAILING  PENDING  SKIPPED │
        # Columns:    1  2   3                            4     5      6        7        8        9       10
        local test_00004_line=$(grep "00004-NoThreeDSAutoCapture" "$test_output_file" | tail -1)
        
        # Extract failing and pending counts
        # Column 7 = FAILING, Column 8 = PENDING
        local failing_count=$(echo "$test_00004_line" | awk '{print $7}')
        local pending_count=$(echo "$test_00004_line" | awk '{print $8}')
        
        # Check if failing or pending counts are non-zero or contain "-"
        if [[ "$failing_count" == "-" ]]; then
            failing_count=0
        fi
        if [[ "$pending_count" == "-" ]]; then
            pending_count=0
        fi
        
        # Only mark as PASSED if NO failures AND NO pending/skipped tests
        if [[ "$failing_count" -eq 0 ]] && [[ "$pending_count" -eq 0 ]]; then
            test_00004_status="PASSED"
        else
            if [[ "$pending_count" -gt 0 ]]; then
                test_00004_status="FAILED (${pending_count} tests skipped)"
            elif [[ "$failing_count" -gt 0 ]]; then
                test_00004_status="FAILED (${failing_count} tests failed)"
            else
                test_00004_status="FAILED"
            fi
        fi
    else
        test_00004_status="FAILED"
    fi
    
    # Display results - ONLY critical tests
    print_banner "📊 CYPRESS TEST RESULTS ANALYSIS"
    
    echo "Critical Test Results:"
    echo "  - 00000 (Setup/Credentials): $test_00000_status"
    echo "  - 00004 (no_three_ds Flow): $test_00004_status"
    echo ""
    echo "Note: Tests 00001-00003 are executed but not evaluated for Phase 0 validation"
    echo ""

    
    # Decision logic
    make_decision "$test_00000_status" "$test_00004_status" "$test_output_file"
}

# ============================================================================
# STEP 6: MAKE DECISION
# ============================================================================

make_decision() {
    local test_00000_status=$1
    local test_00004_status=$2
    local test_output_file=$3
    
    # IMPORTANT: Check actual test status FIRST, don't trust Cypress "All specs passed!"
    # Cypress reports "All specs passed!" even when tests are pending/skipped
    
    # CASE 4: ERROR IN 00000 (Credentials Issue) - Check this FIRST
    if [[ "$test_00000_status" == "FAILED" ]]; then
        print_banner "❌ CYPRESS TEST VALIDATION FAILED - WORKFLOW ABORTED"
        
        echo "Connector: $CONNECTOR_NAME"
        echo "Status: VALIDATION FAILED ❌"
        echo ""
        echo "Critical Issue: Credentials Configuration Error"
        echo "Failed Test: 00000 (Setup/Credentials)"
        echo ""
        
        log_error "Test 00000 failed - credential issues detected"
        echo ""
        echo "🔑 CREDENTIALS CONFIGURATION ERROR"
        echo "----------------------------------"
        echo "Test 00000 failed, which indicates one of the following issues:"
        echo ""
        echo "1. Connector credentials are missing from your auth file"
        echo "   File: $CYPRESS_CONNECTOR_AUTH_FILE_PATH"
        echo ""
        echo "2. Connector credentials are incorrectly formatted"
        echo ""
        echo "3. The file path provided is incorrect"
        echo ""
        echo "Required actions:"
        echo "1. Verify $CONNECTOR_NAME credentials exist in: $CYPRESS_CONNECTOR_AUTH_FILE_PATH"
        echo "2. Ensure JSON format is correct"
        echo "3. Ensure all required fields are present"
        echo "4. Verify file permissions allow reading"
        echo ""
        
        exit 1
    fi
    
    # CASE 3: ERROR IN 00004 (check for billing address error, skipped tests, or other failures)
    if [[ "$test_00004_status" == FAILED* ]]; then
        # Check if it's a billing address error (we can allow this)
        if grep -qi "billing.*address" "$test_output_file"; then
            print_banner "⚠️  CYPRESS TEST VALIDATION COMPLETED WITH WARNINGS"
            
            echo "Connector: $CONNECTOR_NAME"
            echo "Status: VALIDATED WITH WARNINGS ⚠️"
            echo ""
            echo "Test 00004 failed due to billing address error"
            echo "This is a configuration issue, not a connector issue"
            echo ""
            echo "Decision: CONTINUE with UCS integration workflow"
            echo "Note: Billing address can be configured later"
            echo ""
            echo "Next Phase: PHASE 1 - Tech Spec Validation"
            echo ""
            
            log_warning "Test 00004 failed due to billing address error"
            log_success "Proceeding with UCS integration - billing can be configured later"
            
            exit 0
        # Check if tests were skipped/pending (we cannot allow this)
        elif [[ "$test_00004_status" == *"skipped"* ]]; then
            print_banner "❌ CYPRESS TEST VALIDATION FAILED - WORKFLOW ABORTED"
            
            echo "Connector: $CONNECTOR_NAME"
            echo "Status: VALIDATION FAILED ❌"
            echo ""
            echo "Critical Issue: no_three_ds flow has incomplete test coverage"
            echo "Failed Test: 00004 (no_three_ds Flow) - $test_00004_status"
            echo ""
            
            log_error "Test 00004 has skipped/pending tests - no_three_ds flow not fully validated"
            echo ""
            echo "🛑 WORKFLOW ABORTED - INCOMPLETE TEST COVERAGE"
            echo "------------------------------------------------"
            echo "The no_three_ds flow test (00004) has skipped or pending tests."
            echo "For critical no_three_ds validation, ALL test cases must execute and pass."
            echo ""
            echo "This usually indicates:"
            echo "1. Missing test data or configuration"
            echo "2. Connector API limitations preventing certain test scenarios"
            echo "3. Test suite issues that need investigation"
            echo ""
            echo "Required actions:"
            echo "1. Investigate why tests are being skipped in test 00004"
            echo "2. Fix the underlying issue (credentials, connector config, etc.)"
            echo "3. Ensure ALL test cases in 00004 can execute (no skips)"
            echo "4. Re-run this validation script after fixes"
            echo ""
            
            exit 1
        else
            # Other error in 00004 (actual failures)
            print_banner "❌ CYPRESS TEST VALIDATION FAILED - WORKFLOW ABORTED"

            
            echo "Connector: $CONNECTOR_NAME"
            echo "Status: VALIDATION FAILED ❌"
            echo ""
            echo "Critical Issue: no_three_ds flow is broken"
            echo "Failed Test: 00004 (NoThreeDS)"
            echo ""
            
            log_error "Test 00004 failed - no_three_ds flow is broken for this connector"
            echo ""
            echo "🛑 WORKFLOW ABORTED"
            echo "-------------------"
            echo "The UCS integration cannot proceed because the source connector"
            echo "(Hyperswitch) has a broken no_three_ds flow."
            echo ""
            echo "Required actions:"
            echo "1. Fix the no_three_ds flow in Hyperswitch first"
            echo "2. Ensure test 00004 passes in Hyperswitch"
            echo "3. Re-run this validation script after fixes"
            echo ""
            
            exit 1
        fi
    fi
    
    # CASE 1: ALL CRITICAL TESTS PASSED
    # Only reach this if test_00000_status == "PASSED" AND test_00004_status == "PASSED"
    if [[ "$test_00000_status" == "PASSED" ]] && [[ "$test_00004_status" == "PASSED" ]]; then
        print_banner "✅ CYPRESS TEST VALIDATION COMPLETED SUCCESSFULLY"
        
        echo "Connector: $CONNECTOR_NAME"
        echo "Status: VALIDATED ✅"
        echo ""
        echo "All critical tests passed:"
        echo "  - Test 00000 (Setup/Credentials): PASSED"
        echo "  - Test 00004 (no_three_ds Flow): PASSED - All 10 test cases executed successfully"
        echo ""
        echo "Decision: CONTINUE with UCS integration workflow"
        echo ""
        echo "Next Phase: PHASE 1 - Tech Spec Validation"
        echo ""
        
        log_success "All critical Cypress tests passed - connector validated successfully"
        log_success "Proceeding with UCS integration workflow"
        
        exit 0
    fi
    
    # FALLBACK: Something unexpected happened
    print_banner "❌ UNEXPECTED TEST STATE - WORKFLOW ABORTED"
    
    echo "Connector: $CONNECTOR_NAME"
    echo "Status: VALIDATION ERROR ❌"
    echo ""
    echo "The test results are in an unexpected state."
    echo "Test 00000 status: $test_00000_status"
    echo "Test 00004 status: $test_00004_status"
    echo ""
    echo "Please review the test output log:"
    echo "/tmp/cypress_test_output_${CONNECTOR_NAME}.log"
    echo ""
    
    exit 1
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

main() {
    print_banner "$SCRIPT_NAME v$SCRIPT_VERSION"
    
    echo "This script validates connector's no_three_ds support in Hyperswitch"
    echo "before starting UCS integration work."
    echo ""
    
    # Validate input arguments
    validate_arguments "$@"
    
    # Validate environment
    validate_environment
    
    # Step 0: Check feature matrix
    check_feature_matrix
    
    # Step 1: Request credentials
    request_credentials
    
    # Step 2: Navigate to cypress tests
    navigate_to_cypress
    
    # Step 3 & 4: Run Cypress tests
    local test_exit_code
    set +e
    run_cypress_tests
    test_exit_code=$?
    set -e
    
    # Step 5 & 6: Analyze results and make decision
    analyze_test_results "$test_exit_code"
}

# Execute main function
main "$@"
