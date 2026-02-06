#!/bin/bash

# =============================================================================
# BankRedirect User Prompt Script
# =============================================================================
# Two-step prompting for BankRedirect payment method integration:
# Step 1: Ask if user wants BankRedirect at all
# Step 2: If yes, ask which specific types to implement
#
# Usage: ./prompt_bankredirect.sh <detection_json>
# Input: JSON from detect_bankredirect.sh with supported_types array
# Output: JSON with selected_types array and skip flag
# =============================================================================

set -euo pipefail

# Script configuration
readonly SCRIPT_NAME="BankRedirect Prompt"
readonly SCRIPT_VERSION="1.0.0"

# =============================================================================
# DISPLAY FUNCTIONS
# =============================================================================

print_header() {
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "BankRedirect Payment Method Support Detected"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
}

print_footer() {
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "$1"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
}

display_type_with_region() {
    local type=$1
    case "$type" in
        ideal) echo "  • iDEAL (Netherlands)" ;;
        giropay) echo "  • Giropay (Germany)" ;;
        eps) echo "  • EPS (Austria)" ;;
        sofort) echo "  • Sofort (Europe)" ;;
        bancontact) echo "  • Bancontact (Belgium)" ;;
        przelewy24) echo "  • Przelewy24 (Poland)" ;;
        blik) echo "  • BLIK (Poland)" ;;
        trustly) echo "  • Trustly (Europe)" ;;
        openbanking_uk) echo "  • Open Banking UK (United Kingdom)" ;;
        fpx) echo "  • Online Banking FPX (Malaysia)" ;;
        online_banking_czech_republic) echo "  • Online Banking (Czech Republic)" ;;
        online_banking_finland) echo "  • Online Banking (Finland)" ;;
        online_banking_poland) echo "  • Online Banking (Poland)" ;;
        online_banking_slovakia) echo "  • Online Banking (Slovakia)" ;;
        online_banking_thailand) echo "  • Online Banking (Thailand)" ;;
        *) echo "  • $type" ;;
    esac
}

# =============================================================================
# PROMPTING FUNCTIONS
# =============================================================================

prompt_bankredirect_integration() {
    local supported_types_json=$1

    # Parse supported types from JSON
    local supported_types_array=()
    while IFS= read -r type; do
        # Remove quotes and whitespace
        type=$(echo "$type" | tr -d '",' | xargs)
        if [[ -n "$type" && "$type" != "[" && "$type" != "]" ]]; then
            supported_types_array+=("$type")
        fi
    done < <(echo "$supported_types_json" | grep -o '"[^"]*"')

    local type_count=${#supported_types_array[@]}

    if [[ $type_count -eq 0 ]]; then
        echo '{"selected_types": [], "skip": true, "reason": "no_types_detected"}'
        return 0
    fi

    # STEP 1: Display detected types and ask if user wants BankRedirect
    print_header

    echo "Detected BankRedirect types in tech spec:"
    for type in "${supported_types_array[@]}"; do
        display_type_with_region "$type"
    done
    echo ""

    # Ask user if they want to integrate BankRedirect
    local integrate_choice
    while true; do
        read -p "Do you want to integrate BankRedirect payment method? (y/n): " -r integrate_choice
        case "$integrate_choice" in
            y|Y|yes|Yes|YES)
                break
                ;;
            n|N|no|No|NO)
                echo ""
                echo "Skipping BankRedirect integration."
                echo "Continuing to PSync flow..."
                echo ""
                echo '{"selected_types": [], "skip": true, "reason": "user_declined"}'
                return 0
                ;;
            *)
                echo "Please answer 'y' for yes or 'n' for no."
                ;;
        esac
    done

    # STEP 2: User wants BankRedirect, ask which types
    echo ""
    echo "Select BankRedirect types to implement:"
    echo "  1) Implement all detected types (${type_count} types)"
    echo "  2) Select specific types"
    echo ""

    local selection_choice
    while true; do
        read -p "Choice (1 or 2): " -r selection_choice
        case "$selection_choice" in
            1)
                # Implement all types
                local all_types_json=$(printf ',"%s"' "${supported_types_array[@]}")
                all_types_json="[${all_types_json:1}]"  # Remove leading comma and wrap in brackets

                print_footer "Implementing BankRedirect support for ALL detected types"
                for type in "${supported_types_array[@]}"; do
                    echo "  ✓ $(echo $type | tr '_' ' ' | awk '{for(i=1;i<=NF;i++)sub(/./,toupper(substr($i,1,1)),$i)}1')"
                done
                echo ""

                echo "{\"selected_types\": $all_types_json, \"skip\": false}"
                return 0
                ;;
            2)
                # Select specific types
                select_specific_types "${supported_types_array[@]}"
                return 0
                ;;
            *)
                echo "Please enter 1 or 2."
                ;;
        esac
    done
}

select_specific_types() {
    local supported_types=("$@")
    local type_count=${#supported_types[@]}

    echo ""
    echo "Select types to implement (space-separated numbers or 'all'):"
    echo ""

    # Display numbered list
    local i=1
    for type in "${supported_types[@]}"; do
        display_type_with_region "$type" | sed "s/^  •/${i})"
        ((i++))
    done

    echo ""
    read -p "Enter numbers (e.g., '1 3 5' or 'all'): " -r selections

    # Handle 'all' selection
    if [[ "$selections" == "all" || "$selections" == "ALL" ]]; then
        local all_types_json=$(printf ',"%s"' "${supported_types[@]}")
        all_types_json="[${all_types_json:1}]"

        print_footer "Implementing BankRedirect support for ALL types"
        for type in "${supported_types[@]}"; do
            echo "  ✓ $(echo $type | tr '_' ' ' | awk '{for(i=1;i<=NF;i++)sub(/./,toupper(substr($i,1,1)),$i)}1')"
        done
        echo ""

        echo "{\"selected_types\": $all_types_json, \"skip\": false}"
        return 0
    fi

    # Parse space-separated numbers
    local selected_types=()
    for num in $selections; do
        # Validate number is in range
        if [[ "$num" =~ ^[0-9]+$ ]] && [[ $num -ge 1 ]] && [[ $num -le $type_count ]]; then
            local index=$((num - 1))
            selected_types+=("${supported_types[$index]}")
        else
            echo "Warning: Ignoring invalid selection: $num" >&2
        fi
    done

    # Check if any types were selected
    if [[ ${#selected_types[@]} -eq 0 ]]; then
        echo ""
        echo "No valid types selected. Skipping BankRedirect integration."
        echo '{"selected_types": [], "skip": true, "reason": "no_valid_selection"}'
        return 0
    fi

    # Build JSON array
    local selected_json=$(printf ',"%s"' "${selected_types[@]}")
    selected_json="[${selected_json:1}]"

    print_footer "Implementing BankRedirect support for selected types:"
    for type in "${selected_types[@]}"; do
        echo "  ✓ $(echo $type | tr '_' ' ' | awk '{for(i=1;i<=NF;i++)sub(/./,toupper(substr($i,1,1)),$i)}1')"
    done
    echo ""

    echo "{\"selected_types\": $selected_json, \"skip\": false}"
    return 0
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

main() {
    if [[ $# -lt 1 ]]; then
        echo '{"selected_types": [], "skip": true, "error": "Missing detection JSON argument"}' >&2
        return 1
    fi

    local detection_json=$1

    # Extract supported_types array from detection JSON
    local supported_types_json
    supported_types_json=$(echo "$detection_json" | grep -o '"supported_types":\s*\[[^]]*\]' | sed 's/"supported_types"://')

    if [[ -z "$supported_types_json" ]]; then
        echo '{"selected_types": [], "skip": true, "error": "Could not parse supported_types from detection JSON"}'
        return 1
    fi

    prompt_bankredirect_integration "$supported_types_json"
}

# Run main function
main "$@"
