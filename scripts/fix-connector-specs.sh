#!/usr/bin/env bash
# fix-connector-specs.sh — lightweight, per-connector specs.json updater.
#
# Detects which connector .rs files changed in the current PR (or working
# tree), extracts flow names from `create_all_prerequisites!` macros, maps
# them to integration-test suite names, and adds any missing suites to the
# connector's specs.json.
#
# Usage:
#   scripts/fix-connector-specs.sh                   # diff against origin/main
#   scripts/fix-connector-specs.sh --base main       # diff against 'main'
#   scripts/fix-connector-specs.sh --all             # check all connectors
#   scripts/fix-connector-specs.sh --connector nuvei # check one connector
#
# Requires: bash 4+, grep, sed, jq

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONNECTORS_SRC="$REPO_ROOT/crates/integrations/connector-integration/src/connectors"
SPECS_ROOT="$REPO_ROOT/crates/internal/integration-tests/src/connector_specs"

# ---------------------------------------------------------------------------
# Flow → suite mapping (must stay in sync with check_connector_specs.rs)
# ---------------------------------------------------------------------------
flow_to_suite() {
    case "$1" in
        Authorize)                       echo "authorize" ;;
        PSync)                           echo "get" ;;
        Capture)                         echo "capture" ;;
        Void)                            echo "void" ;;
        Refund)                          echo "refund" ;;
        RSync)                           echo "refund_sync" ;;
        SetupMandate)                    echo "setup_recurring" ;;
        RepeatPayment)                   echo "recurring_charge" ;;
        MandateRevoke)                   echo "revoke_mandate" ;;
        CreateConnectorCustomer)         echo "create_customer" ;;
        PaymentMethodToken)              echo "tokenize_payment_method" ;;
        ServerAuthenticationToken)       echo "server_authentication_token" ;;
        ClientAuthenticationToken)       echo "client_authentication_token" ;;
        ServerSessionAuthenticationToken) echo "server_session_authentication_token" ;;
        PreAuthenticate)                 echo "pre_authenticate" ;;
        Authenticate)                    echo "authenticate" ;;
        PostAuthenticate)                echo "post_authenticate" ;;
        CreateOrder)                     echo "create_order" ;;
        IncrementalAuthorization)        echo "incremental_authorization" ;;
        # Flows with no test suite — skip silently
        *)                               echo "" ;;
    esac
}

# ---------------------------------------------------------------------------
# Extract flow names from a connector .rs source file
# ---------------------------------------------------------------------------
extract_flows() {
    local src_file="$1"
    # Match lines like "flow: Authorize," inside create_all_prerequisites!
    # Use `|| true` to avoid pipefail exit when grep finds no matches.
    grep -oE 'flow:\s*[A-Za-z][A-Za-z0-9]*' "$src_file" 2>/dev/null \
        | sed 's/flow:[[:space:]]*//' \
        | sort -u \
        || true
}

# ---------------------------------------------------------------------------
# Update one connector's specs.json with missing suites
# ---------------------------------------------------------------------------
update_specs() {
    local connector="$1"
    local src_file="$CONNECTORS_SRC/${connector}.rs"
    local specs_file="$SPECS_ROOT/${connector}/specs.json"

    if [[ ! -f "$src_file" ]]; then
        echo "[SKIP] $connector — no source file at $src_file"
        return
    fi

    # Extract flows from the macro
    local flows
    flows=$(extract_flows "$src_file")
    if [[ -z "$flows" ]]; then
        echo "[SKIP] $connector — no create_all_prerequisites! macro found"
        return
    fi

    # Ensure specs directory and file exist
    if [[ ! -d "$SPECS_ROOT/$connector" ]]; then
        mkdir -p "$SPECS_ROOT/$connector"
    fi
    if [[ ! -f "$specs_file" ]]; then
        echo "{\"connector\": \"$connector\", \"supported_suites\": []}" > "$specs_file"
    fi

    # Read existing suites
    local existing_suites
    existing_suites=$(jq -r '.supported_suites[]' "$specs_file" 2>/dev/null || true)

    # Collect suites that need to be added
    local added=()
    while IFS= read -r flow; do
        [[ -z "$flow" ]] && continue
        local suite
        suite=$(flow_to_suite "$flow")
        [[ -z "$suite" ]] && continue

        # Check if already present
        if ! echo "$existing_suites" | grep -qxF "$suite"; then
            added+=("$suite")
        fi
    done <<< "$flows"

    if [[ ${#added[@]} -eq 0 ]]; then
        echo "[OK]   $connector — all suites present"
        return
    fi

    # Add missing suites via jq (sort + deduplicate)
    local add_json
    add_json=$(printf '%s\n' "${added[@]}" | jq -R . | jq -s .)
    jq --argjson new_suites "$add_json" \
        '.supported_suites = (.supported_suites + $new_suites | unique | sort)' \
        "$specs_file" > "${specs_file}.tmp" \
        && mv "${specs_file}.tmp" "$specs_file"

    for suite in "${added[@]}"; do
        echo "       ADDED  $connector  suite=$suite"
    done
    echo "[FIXED] $connector — ${#added[@]} suite(s) added"
}

# ---------------------------------------------------------------------------
# Determine which connectors to check
# ---------------------------------------------------------------------------
BASE_BRANCH="origin/main"
MODE=""
TARGET_CONNECTOR=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --base)
            BASE_BRANCH="$2"
            shift 2
            ;;
        --all)
            MODE="all"
            shift
            ;;
        --connector)
            MODE="single"
            TARGET_CONNECTOR="$2"
            shift 2
            ;;
        *)
            echo "Unknown argument: $1" >&2
            exit 1
            ;;
    esac
done

if [[ "$MODE" == "all" ]]; then
    echo "Checking ALL connectors..."
    echo
    for src_file in "$CONNECTORS_SRC"/*.rs; do
        name=$(basename "$src_file" .rs)
        [[ "$name" == "macros" ]] && continue
        update_specs "$name"
    done
elif [[ "$MODE" == "single" ]]; then
    echo "Checking connector: $TARGET_CONNECTOR"
    echo
    update_specs "$TARGET_CONNECTOR"
else
    # Auto-detect changed connectors from git diff
    echo "Detecting changed connectors (diff against $BASE_BRANCH)..."
    echo

    # Files changed under the connectors source directory
    changed_files=$(git diff --name-only "$BASE_BRANCH" -- \
        "crates/integrations/connector-integration/src/connectors/" 2>/dev/null || true)

    if [[ -z "$changed_files" ]]; then
        echo "No connector source files changed. Nothing to do."
        exit 0
    fi

    connectors=()
    local connectors_prefix="crates/integrations/connector-integration/src/connectors"
    while IFS= read -r file; do
        [[ -z "$file" ]] && continue
        # Strip the prefix to get the relative path under connectors/
        local rel="${file#${connectors_prefix}/}"
        # Extract the first path component (connector name)
        local first_component="${rel%%/*}"
        # If no slash, it's a top-level file like "nuvei.rs" — strip .rs
        if [[ "$first_component" == "$rel" ]]; then
            first_component="${first_component%.rs}"
        fi
        # Skip macros
        [[ "$first_component" == "macros" ]] && continue
        connectors+=("$first_component")
    done <<< "$changed_files"

    # Deduplicate
    mapfile -t connectors < <(printf '%s\n' "${connectors[@]}" | sort -u)

    if [[ ${#connectors[@]} -eq 0 ]]; then
        echo "No top-level connector .rs files changed. Nothing to do."
        exit 0
    fi

    echo "Changed connectors: ${connectors[*]}"
    echo

    for connector in "${connectors[@]}"; do
        update_specs "$connector"
    done
fi

echo
echo "Done."
