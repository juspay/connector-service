#!/bin/bash

set -euo pipefail

# Configuration
ENCRYPTED_FILE="test-credentials.json.gpg"
CREDS_FILE="test-credentials.json"
PASSPHRASE_FILE=".env.gpg.key"
SET_ENV_VARS=()  # Track environment variables we set (array)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

log_success() {
    echo -e "${GREEN}✅${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

log_error() {
    echo -e "${RED}❌${NC} $1"
}

# Cleanup function
cleanup() {
    log_info "Cleaning up temporary files..."
    rm -f "$CREDS_FILE" 2>/dev/null || true
    
    # Unset all credential environment variables that we set
    if [[ ${#SET_ENV_VARS[@]} -gt 0 ]]; then
        log_info "Cleaning up ${#SET_ENV_VARS[@]} environment variables..."
        # Unset each variable in the array
        for var in "${SET_ENV_VARS[@]}"; do
            unset "$var" 2>/dev/null || true
        done
    fi
    
    log_success "Cleanup complete"
}

# Set cleanup trap
trap cleanup EXIT

# Check dependencies
check_dependencies() {
    if ! command -v gpg &> /dev/null; then
        log_error "GPG is required but not installed. Please install GPG and try again."
        exit 1
    fi
    
    if ! command -v cargo &> /dev/null; then
        log_error "Cargo is required but not installed. Please install Rust and try again."
        exit 1
    fi
    
    if ! command -v jq &> /dev/null; then
        log_warning "jq is not installed. Some credential validation features may not work."
    fi
}

# Check if passphrase is available (env var or file)
check_passphrase() {
    if [[ -n "${GPG_PASSPHRASE:-}" ]]; then
        log_info "Using GPG passphrase from environment variable"
        return 0
    elif [[ -f "$PASSPHRASE_FILE" ]]; then
        log_info "Using GPG passphrase from file: $PASSPHRASE_FILE"
        return 0
    else
        log_error "No GPG passphrase found."
        log_info "Either set GPG_PASSPHRASE environment variable or create file: echo 'your_passphrase' > $PASSPHRASE_FILE"
        log_info "Contact your team lead to get the passphrase."
        exit 1
    fi
}

# Check if encrypted credentials exist
check_encrypted_file() {
    if [[ ! -f "$ENCRYPTED_FILE" ]]; then
        log_error "Encrypted credentials file '$ENCRYPTED_FILE' not found."
        log_info "This file should be committed to the repository."
        log_info "If you're setting up for the first time, create credentials using:"
        log_info "  ./scripts/manage-credentials.sh add <connector> <cred-file>"
        exit 1
    fi
}

# Decrypt credentials
decrypt_credentials() {
    log_info "Decrypting test credentials..."
    
    # Choose decryption method based on available passphrase source
    if [[ -n "${GPG_PASSPHRASE:-}" ]]; then
        # Use environment variable directly
        if ! gpg --quiet --batch --passphrase "$GPG_PASSPHRASE" --decrypt "$ENCRYPTED_FILE" > "$CREDS_FILE" 2>/dev/null; then
            log_error "Failed to decrypt credentials using environment variable. Check your passphrase."
            exit 1
        fi
    elif [[ -f "$PASSPHRASE_FILE" ]]; then
        # Use passphrase file
        if ! gpg --quiet --batch --passphrase-file "$PASSPHRASE_FILE" --decrypt "$ENCRYPTED_FILE" > "$CREDS_FILE" 2>/dev/null; then
            log_error "Failed to decrypt credentials using passphrase file. Check your passphrase."
            exit 1
        fi
    else
        log_error "No passphrase source available for decryption."
        exit 1
    fi
    
    # Validate JSON format
    if ! jq empty "$CREDS_FILE" 2>/dev/null; then
        log_error "Decrypted credentials file has invalid JSON format."
        exit 1
    fi
    
    log_success "Credentials decrypted successfully"
}

# Set environment variables from credential file
set_environment_variables() {
    log_info "Setting up environment variables..."
    
    if [[ ! -f "$CREDS_FILE" ]]; then
        log_error "Credentials file not found after decryption"
        exit 1
    fi
    
    local count=0
    # Iterate through each connector in the JSON file
    while IFS= read -r connector; do
        if [[ -n "$connector" ]]; then
            local connector_upper=$(echo "$connector" | tr '[:lower:]' '[:upper:]')
            
            log_info "Loading credentials for: $connector"
            
            # Set individual environment variables for each key-value pair
            while IFS= read -r line; do
                if [[ -n "$line" && "$line" != "null" ]]; then
                    local var_name="${connector_upper}_${line%%=*}"
                    export "${connector_upper}_${line}"
                    # Track this variable for cleanup
                    SET_ENV_VARS+=("$var_name")
                fi
            done < <(jq -r ".$connector | to_entries[] | \"\(.key | ascii_upcase)=\(.value)\"" "$CREDS_FILE" 2>/dev/null || echo "")
            
            ((count++))
        fi
    done < <(jq -r 'keys[]' "$CREDS_FILE" 2>/dev/null || echo "")
    
    if [[ $count -eq 0 ]]; then
        log_warning "No connectors found in credentials file"
    else
        log_success "Loaded credentials for $count connector(s)"
    fi
}

# Run comprehensive test suite
run_tests() {
    local extra_args="${1:-}"
    
    log_info "Running comprehensive test suite..."
    
    # Run cargo hack test which covers all features
    log_info "Executing: cargo hack test --each-feature $extra_args"
    if cargo hack test --each-feature $extra_args; then
        log_success "All tests passed!"
    else
        log_error "Some tests failed"
        return 1
    fi
}

# Show usage
show_usage() {
    echo "Usage: $0 [extra-args]"
    echo
    echo "Description:"
    echo "  Runs comprehensive test suite with encrypted credentials"
    echo
    echo "Examples:"
    echo "  $0                           # Run all tests"
    echo "  $0 -- --nocapture           # Run tests with extra cargo args"
    echo "  $0 -- adyen                 # Run tests matching 'adyen'"
    echo
    echo "Environment:"
    echo "  This script will:"
    echo "  1. Decrypt test credentials from $ENCRYPTED_FILE"
    echo "  2. Set environment variables for each connector"
    echo "  3. Run cargo hack test --each-feature"
    echo "  4. Clean up credentials after testing"
}

# Main script logic
main() {
    # Parse arguments
    local extra_args="${1:-}"
    
    # Handle help
    if [[ "$extra_args" == "help" ]] || [[ "$extra_args" == "--help" ]] || [[ "$extra_args" == "-h" ]]; then
        show_usage
        exit 0
    fi
    
    # Check dependencies and setup
    check_dependencies
    check_passphrase
    check_encrypted_file
    
    # Show environment info
    log_info "Test Environment Setup"
    log_info "Working Directory: $(pwd)"
    log_info "Rust Version: $(rustc --version 2>/dev/null || echo 'Not found')"
    log_info "Cargo Version: $(cargo --version 2>/dev/null || echo 'Not found')"
    echo
    
    # Decrypt and setup
    decrypt_credentials
    set_environment_variables
    echo
    
    # Run tests
    log_info "Starting test execution..."
    if run_tests "$extra_args"; then
        log_success "All tests completed successfully!"
    else
        log_error "Some tests failed. Check output above for details."
        exit 1
    fi
}

# Run main function
main "$@"