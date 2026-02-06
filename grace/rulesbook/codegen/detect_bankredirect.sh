#!/bin/bash

# =============================================================================
# BankRedirect Auto-Detection Script
# =============================================================================
# Detects BankRedirect payment method support from technical_specification.md
# Outputs JSON with supported types for use by the GRACE-UCS workflow
#
# Usage: ./detect_bankredirect.sh <tech_spec_file>
# Output: JSON object with has_bankredirect and supported_types array
# =============================================================================

set -euo pipefail

# Script configuration
readonly SCRIPT_NAME="BankRedirect Detector"
readonly SCRIPT_VERSION="1.0.0"

# =============================================================================
# LOGGING FUNCTIONS
# =============================================================================

log_info() {
    echo "[INFO] $*" >&2
}

log_error() {
    echo "[ERROR] $*" >&2
}

# =============================================================================
# DETECTION FUNCTIONS
# =============================================================================

detect_bankredirect_from_techspec() {
    local tech_spec_file=$1

    # Validate input file exists
    if [[ ! -f "$tech_spec_file" ]]; then
        log_error "Tech spec file not found: $tech_spec_file"
        echo '{"has_bankredirect": false, "supported_types": [], "error": "Tech spec file not found"}'
        return 1
    fi

    # Check if BankRedirect section exists
    if ! grep -q "### 1.4 BankRedirect Payment Methods Configuration" "$tech_spec_file" && \
       ! grep -q "## BankRedirect Payment Methods" "$tech_spec_file"; then
        log_info "No BankRedirect section found in tech spec"
        echo '{"has_bankredirect": false, "supported_types": []}'
        return 0
    fi

    log_info "BankRedirect section found, extracting supported types..."

    # Extract checked BankRedirect types (lines with - [x])
    local supported_types_raw
    supported_types_raw=$(grep -A 20 "#### Supported BankRedirect Types" "$tech_spec_file" | \
                         grep "^- \[x\]" | \
                         sed -E 's/^- \[x\] ([A-Za-z0-9]+).*/\1/' | \
                         tr '[:upper:]' '[:lower:]')

    # Count how many types were found
    local type_count=$(echo "$supported_types_raw" | grep -v '^$' | wc -l | tr -d ' ')

    if [[ "$type_count" -eq 0 ]]; then
        log_info "No BankRedirect types checked in tech spec"
        echo '{"has_bankredirect": false, "supported_types": []}'
        return 0
    fi

    # Convert to JSON array
    local json_types=""
    while IFS= read -r type_name; do
        if [[ -n "$type_name" ]]; then
            # Clean up type name and normalize
            type_name=$(echo "$type_name" | tr -d ' ' | tr '[:upper:]' '[:lower:]')

            # Map to canonical names
            case "$type_name" in
                ideal)
                    json_types="${json_types}\"ideal\","
                    ;;
                giropay)
                    json_types="${json_types}\"giropay\","
                    ;;
                eps)
                    json_types="${json_types}\"eps\","
                    ;;
                sofort)
                    json_types="${json_types}\"sofort\","
                    ;;
                bancontact)
                    json_types="${json_types}\"bancontact\","
                    ;;
                przelewy24)
                    json_types="${json_types}\"przelewy24\","
                    ;;
                blik)
                    json_types="${json_types}\"blik\","
                    ;;
                trustly)
                    json_types="${json_types}\"trustly\","
                    ;;
                openbankinguk)
                    json_types="${json_types}\"openbanking_uk\","
                    ;;
                onlinebankingfpx)
                    json_types="${json_types}\"fpx\","
                    ;;
                onlinebankingczechrepublic)
                    json_types="${json_types}\"online_banking_czech_republic\","
                    ;;
                onlinebankingfinland)
                    json_types="${json_types}\"online_banking_finland\","
                    ;;
                onlinebankingpoland)
                    json_types="${json_types}\"online_banking_poland\","
                    ;;
                onlinebankingslovakia)
                    json_types="${json_types}\"online_banking_slovakia\","
                    ;;
                onlinebankingthailand)
                    json_types="${json_types}\"online_banking_thailand\","
                    ;;
                *)
                    # Unknown type, include as-is
                    json_types="${json_types}\"${type_name}\","
                    ;;
            esac
        fi
    done <<< "$supported_types_raw"

    # Remove trailing comma
    json_types="${json_types%,}"

    # Build final JSON
    if [[ -n "$json_types" ]]; then
        log_info "Detected $type_count BankRedirect types: $json_types"
        echo "{\"has_bankredirect\": true, \"supported_types\": [$json_types]}"
    else
        echo '{"has_bankredirect": false, "supported_types": []}'
    fi

    return 0
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

main() {
    if [[ $# -lt 1 ]]; then
        log_error "Usage: $0 <tech_spec_file>"
        echo '{"has_bankredirect": false, "supported_types": [], "error": "Missing tech spec file argument"}'
        return 1
    fi

    local tech_spec_file=$1

    log_info "Starting BankRedirect detection..."
    log_info "Tech spec file: $tech_spec_file"

    detect_bankredirect_from_techspec "$tech_spec_file"
}

# Run main function
main "$@"
