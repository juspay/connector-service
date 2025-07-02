#!/bin/bash

set -euo pipefail

# Configuration
ENCRYPTED_FILE="test-credentials.json.gpg"
CREDS_FILE="test-credentials.json"
PASSPHRASE_FILE=".env.gpg.key"

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

# Check dependencies
check_dependencies() {
    if ! command -v gpg &> /dev/null; then
        log_error "GPG is required but not installed. Please install GPG and try again."
        exit 1
    fi
    
    if ! command -v tar &> /dev/null; then
        log_error "tar is required but not installed."
        exit 1
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
        exit 1
    fi
}

# Decrypt the credential file
decrypt_bundle() {
    if [[ ! -f "$ENCRYPTED_FILE" ]]; then
        log_warning "Encrypted file '$ENCRYPTED_FILE' not found. Creating new credential file."
        echo '{}' > "$CREDS_FILE"
        return 0
    fi
    
    log_info "Decrypting credential file..."
    
    # Choose decryption method based on available passphrase source
    if [[ -n "${GPG_PASSPHRASE:-}" ]]; then
        # Use environment variable directly
        gpg --quiet --batch --passphrase "$GPG_PASSPHRASE" --decrypt "$ENCRYPTED_FILE" > "$CREDS_FILE"
    elif [[ -f "$PASSPHRASE_FILE" ]]; then
        # Use passphrase file
        gpg --quiet --batch --passphrase-file "$PASSPHRASE_FILE" --decrypt "$ENCRYPTED_FILE" > "$CREDS_FILE"
    else
        log_error "No passphrase source available for decryption."
        exit 1
    fi
    
    log_success "Credential file decrypted"
}

# Encrypt the credential file
encrypt_bundle() {
    log_info "Encrypting credential file..."
    
    # Choose encryption method based on available passphrase source
    if [[ -n "${GPG_PASSPHRASE:-}" ]]; then
        # Use environment variable directly
        gpg --symmetric --cipher-algo AES256 --batch --passphrase "$GPG_PASSPHRASE" "$CREDS_FILE"
    elif [[ -f "$PASSPHRASE_FILE" ]]; then
        # Use passphrase file
        gpg --symmetric --cipher-algo AES256 --batch --passphrase-file "$PASSPHRASE_FILE" "$CREDS_FILE"
    else
        log_error "No passphrase source available for encryption."
        exit 1
    fi
    
    # Clean up temporary file
    rm -f "$CREDS_FILE"
    log_success "Credential file encrypted and saved as '$ENCRYPTED_FILE'"
}

# Add new connector credentials
add_credential() {
    local connector="$1"
    local cred_file="$2"
    
    if [[ ! -f "$cred_file" ]]; then
        log_error "Credential file '$cred_file' not found"
        exit 1
    fi
    
    # Validate JSON format of input file
    if ! jq empty "$cred_file" 2>/dev/null; then
        log_error "Invalid JSON format in credential file"
        exit 1
    fi
    
    # Check if connector already exists
    if jq -e ".$connector" "$CREDS_FILE" >/dev/null 2>&1; then
        read -p "Connector '$connector' already exists. Overwrite? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "Operation cancelled"
            return 0
        fi
    fi
    
    # Add connector credentials to the main file
    local temp_file=$(mktemp)
    jq --argjson creds "$(cat "$cred_file")" ". + {\"$connector\": \$creds}" "$CREDS_FILE" > "$temp_file"
    mv "$temp_file" "$CREDS_FILE"
    
    log_success "Added credentials for '$connector'"
}

# Update existing connector credentials
update_credential() {
    local connector="$1"
    local cred_file="$2"
    
    if [[ ! -f "$cred_file" ]]; then
        log_error "Credential file '$cred_file' not found"
        exit 1
    fi
    
    # Check if connector exists
    if ! jq -e ".$connector" "$CREDS_FILE" >/dev/null 2>&1; then
        log_error "Connector '$connector' not found. Use 'add' command to create it."
        exit 1
    fi
    
    # Validate JSON format of input file
    if ! jq empty "$cred_file" 2>/dev/null; then
        log_error "Invalid JSON format in credential file"
        exit 1
    fi
    
    # Update connector credentials in the main file
    local temp_file=$(mktemp)
    jq --argjson creds "$(cat "$cred_file")" ".\"$connector\" = \$creds" "$CREDS_FILE" > "$temp_file"
    mv "$temp_file" "$CREDS_FILE"
    
    log_success "Updated credentials for '$connector'"
}

# Delete connector credentials
delete_credential() {
    local connector="$1"
    local force="${2:-false}"
    
    # Check if connector exists
    if ! jq -e ".$connector" "$CREDS_FILE" >/dev/null 2>&1; then
        log_error "Connector '$connector' not found"
        exit 1
    fi
    
    if [[ "$force" != "true" ]]; then
        read -p "Are you sure you want to delete credentials for '$connector'? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "Operation cancelled"
            return 0
        fi
    fi
    
    # Remove connector from the main file
    local temp_file=$(mktemp)
    jq "del(.\"$connector\")" "$CREDS_FILE" > "$temp_file"
    mv "$temp_file" "$CREDS_FILE"
    
    log_success "Deleted credentials for '$connector'"
}

# List available connectors
list_credentials() {
    if [[ ! -f "$CREDS_FILE" ]] || [[ "$(jq 'keys | length' "$CREDS_FILE" 2>/dev/null)" == "0" ]]; then
        log_info "No credentials found"
        return 0
    fi
    
    log_info "Available connector credentials:"
    jq -r 'keys[]' "$CREDS_FILE" 2>/dev/null | while read -r connector; do
        echo "  • $connector"
    done
}

# Verify file integrity
verify_bundle() {
    if [[ ! -f "$ENCRYPTED_FILE" ]]; then
        log_error "Encrypted file '$ENCRYPTED_FILE' not found"
        exit 1
    fi
    
    log_info "Verifying file integrity..."
    
    # Test decryption
    local temp_file=$(mktemp)
    local decryption_success=false
    
    # Choose decryption method based on available passphrase source
    if [[ -n "${GPG_PASSPHRASE:-}" ]]; then
        # Use environment variable directly
        if gpg --quiet --batch --passphrase "$GPG_PASSPHRASE" --decrypt "$ENCRYPTED_FILE" > "$temp_file" 2>/dev/null; then
            decryption_success=true
        fi
    elif [[ -f "$PASSPHRASE_FILE" ]]; then
        # Use passphrase file
        if gpg --quiet --batch --passphrase-file "$PASSPHRASE_FILE" --decrypt "$ENCRYPTED_FILE" > "$temp_file" 2>/dev/null; then
            decryption_success=true
        fi
    fi
    
    if [[ "$decryption_success" == "true" ]]; then
        log_success "File decryption: OK"
    else
        log_error "File decryption: FAILED"
        rm -f "$temp_file"
        exit 1
    fi
    
    # Test JSON format
    if jq empty "$temp_file" 2>/dev/null; then
        log_success "JSON format: OK"
        
        # List connectors
        local connector_count=$(jq 'keys | length' "$temp_file" 2>/dev/null)
        log_info "Found $connector_count connector(s):"
        jq -r 'keys[]' "$temp_file" 2>/dev/null | sed 's/^/  • /'
    else
        log_error "JSON format: CORRUPTED"
        rm -f "$temp_file"
        exit 1
    fi
    
    rm -f "$temp_file"
    log_success "File verification complete"
}

# Show usage
show_usage() {
    echo "Usage: $0 <command> [arguments]"
    echo
    echo "Commands:"
    echo "  add <connector> <cred-file>    Add new connector credentials"
    echo "  update <connector> <cred-file> Update existing connector credentials"
    echo "  delete <connector> [--force]   Delete connector credentials"
    echo "  list                          List available connectors"
    echo "  verify                        Verify bundle integrity"
    echo "  help                          Show this help message"
    echo
    echo "Examples:"
    echo "  $0 add stripe ./stripe-creds.json"
    echo "  $0 update adyen ./new-adyen-creds.json"
    echo "  $0 delete old_connector --force"
    echo "  $0 list"
    echo "  $0 verify"
}

# Main script logic
main() {
    check_dependencies
    
    local command="${1:-help}"
    
    case "$command" in
        "add")
            if [[ $# -ne 3 ]]; then
                log_error "Usage: $0 add <connector> <cred-file>"
                exit 1
            fi
            check_passphrase
            decrypt_bundle
            add_credential "$2" "$3"
            encrypt_bundle
            ;;
        "update")
            if [[ $# -ne 3 ]]; then
                log_error "Usage: $0 update <connector> <cred-file>"
                exit 1
            fi
            check_passphrase
            decrypt_bundle
            update_credential "$2" "$3"
            encrypt_bundle
            ;;
        "delete")
            if [[ $# -lt 2 ]] || [[ $# -gt 3 ]]; then
                log_error "Usage: $0 delete <connector> [--force]"
                exit 1
            fi
            local force="false"
            if [[ "${3:-}" == "--force" ]]; then
                force="true"
            fi
            check_passphrase
            decrypt_bundle
            delete_credential "$2" "$force"
            encrypt_bundle
            ;;
        "list")
            check_passphrase
            decrypt_bundle
            list_credentials
            rm -rf "$CREDS_DIR" "$ARCHIVE_FILE" 2>/dev/null || true
            ;;
        "verify")
            check_passphrase
            verify_bundle
            ;;
        "help"|"--help"|"-h")
            show_usage
            ;;
        *)
            log_error "Unknown command: $command"
            show_usage
            exit 1
            ;;
    esac
}

# Run main function
main "$@"