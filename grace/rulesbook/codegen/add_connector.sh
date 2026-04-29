#!/bin/bash

# =============================================================================
# Hyperswitch Connector Generator v2.0
# =============================================================================
# A robust, maintainable script for generating connector boilerplate code
#
# Usage: ./add_connector_v2.sh <connector_name> <base_url> [options]
#
# Features:
# - Modular design for easy maintenance
# - Comprehensive error handling and validation
# - Self-documenting configuration
# - Future-proof architecture
# =============================================================================

set -euo pipefail  # Strict error handling

# =============================================================================
# CONFIGURATION SECTION
# =============================================================================
# All configurable values are centralized here for easy maintenance

# Script metadata
readonly SCRIPT_VERSION="2.0.0"
readonly SCRIPT_NAME="Hyperswitch Connector Generator"

# Paths configuration
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly ROOT_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"
readonly TEMPLATE_DIR="$SCRIPT_DIR/template-generation"
readonly CRATES_TRAITS="$ROOT_DIR/crates/types-traits"
readonly CRATES_INTEGRATIONS="$ROOT_DIR/crates/integrations"
readonly CRATES_INTERNAL="$ROOT_DIR/crates/internal"
readonly CONFIG_DIR="$ROOT_DIR/config"

# File paths
readonly CONNECTOR_TYPES_FILE="$CRATES_TRAITS/interfaces/src/connector_types.rs"
readonly DOMAIN_TYPES_FILE="$CRATES_TRAITS/domain_types/src/connector_types.rs"
readonly DOMAIN_TYPES_TYPES_FILE="$CRATES_TRAITS/domain_types/src/types.rs"
readonly INTEGRATION_TYPES_FILE="$CRATES_INTEGRATIONS/connector-integration/src/types.rs"
readonly DEFAULT_IMPL_FILE="$CRATES_INTEGRATIONS/connector-integration/src/default_implementations.rs"
readonly CONNECTORS_MODULE_FILE="$CRATES_INTEGRATIONS/connector-integration/src/connectors.rs"
readonly PROTO_FILE="$CRATES_TRAITS/grpc-api-types/proto/payment.proto"
readonly ROUTER_DATA_FILE="$CRATES_TRAITS/domain_types/src/router_data.rs"
readonly CONFIG_FILE="$CONFIG_DIR/development.toml"
readonly SANDBOX_CONFIG_FILE="$CONFIG_DIR/sandbox.toml"
readonly PRODUCTION_CONFIG_FILE="$CONFIG_DIR/production.toml"
readonly FIELD_PROBE_FILE="$CRATES_INTERNAL/field-probe/src/auth.rs"

# Template files
readonly CONNECTOR_TEMPLATE="$TEMPLATE_DIR/connector.rs.template"
readonly TRANSFORMERS_TEMPLATE="$TEMPLATE_DIR/transformers.rs.template"

# =============================================================================
# DYNAMIC FLOW DETECTION
# =============================================================================
# This script automatically detects all available flows from connector_types.rs
# When new flows are added to the ConnectorServiceTrait, they will be automatically
# included in new connector templates without any manual configuration needed.

# Global array to store detected flows
AVAILABLE_FLOWS=()

# =============================================================================
# FLOW DETECTION FUNCTIONS
# =============================================================================

detect_flows_from_connector_service_trait() {
    log_step "Auto-detecting flows from ConnectorServiceTrait"

    local connector_types_file="$CONNECTOR_TYPES_FILE"
    if [[ ! -f "$connector_types_file" ]]; then
        fatal_error "Cannot find connector_types.rs at: $connector_types_file"
    fi

    # Extract all trait names from ConnectorServiceTrait definition
    # This looks for lines like "+ PaymentAuthorizeV2<T>" or "+ PaymentSyncV2"
    local detected_flows
    detected_flows=$(awk '
        /pub trait ConnectorServiceTrait/ { in_trait = 1 }
        in_trait { print }
        in_trait && /^[[:space:]]*\{/ { exit }
    ' "$connector_types_file" | \
                    grep -E "^[[:space:]]*\+[[:space:]]*[A-Z][A-Za-z0-9]*" | \
                    sed -E 's/^[[:space:]]*\+[[:space:]]*([A-Z][A-Za-z0-9]*).*/\1/' | \
                    grep -v "ConnectorCommon" | \
                    sort -u)

    if [[ -z "$detected_flows" ]]; then
        fatal_error "No flows detected from ConnectorServiceTrait"
    fi

    # Convert to array
    while IFS= read -r flow; do
        if [[ -n "$flow" ]]; then
            AVAILABLE_FLOWS+=("$flow")
        fi
    done <<< "$detected_flows"

    log_success "Detected ${#AVAILABLE_FLOWS[@]} flows from ConnectorServiceTrait"
    log_debug "Detected flows: ${AVAILABLE_FLOWS[*]}"
}

# Function to get basic description for any flow
get_flow_description() {
    case "$1" in
        *"Authorize"*) echo "Process payment authorization" ;;
        *"Sync"*) echo "Synchronize status" ;;
        *"Void"*) echo "Void/cancel operations" ;;
        *"Capture"*) echo "Capture authorized payments" ;;
        *"Refund"*) echo "Process refunds" ;;
        *"Mandate"*) echo "Setup recurring payment mandates" ;;
        *"Repeat"*) echo "Process recurring payments" ;;
        *"Order"*) echo "Create payment orders" ;;
        *"Token"*) echo "Handle tokenization" ;;
        *"Dispute"*) echo "Handle payment disputes" ;;
        *"Evidence"*) echo "Submit dispute evidence" ;;
        *"Webhook"*) echo "Handle incoming webhooks" ;;
        *"Validation"*) echo "Basic validation functionality" ;;
        *"Access"*) echo "Handle access tokens" ;;
        *"Session"*) echo "Handle session tokens" ;;
        *"Authenticate"*) echo "Handle authentication" ;;
        *) echo "Payment processing flow" ;;
    esac
}

# =============================================================================
# FLOW METADATA EXTRACTION FUNCTIONS
# =============================================================================
# These functions parse connector_types.rs to extract metadata about each flow
# This metadata is used to generate trait implementations dynamically

# Global indexed arrays to store flow metadata (Bash 3.x compatible)
FLOW_NAMES=()                # All flow trait names
FLOW_GENERICS=()             # "true" or "false" for each flow
FLOW_INTEGRATION_PARAMS=()   # ConnectorIntegrationV2 params for each flow

# Helper function to find index of a flow in FLOW_NAMES array
get_flow_index() {
    local flow_name="$1"
    local i
    for i in "${!FLOW_NAMES[@]}"; do
        if [[ "${FLOW_NAMES[$i]}" == "$flow_name" ]]; then
            echo "$i"
            return 0
        fi
    done
    echo "-1"
}

# Extract metadata for a specific flow trait from connector_types.rs
extract_flow_metadata() {
    local flow_trait="$1"
    local connector_types_file="$CONNECTOR_TYPES_FILE"
    
    log_debug "Extracting metadata for flow: $flow_trait"
    
    # Add flow to the names array
    FLOW_NAMES+=("$flow_trait")
    local flow_idx=$((${#FLOW_NAMES[@]} - 1))
    
    # Check if trait has generics by looking for <T in trait definition
    if grep -A 1 "pub trait $flow_trait" "$connector_types_file" | grep -q "<T"; then
        FLOW_GENERICS[$flow_idx]="true"
        log_debug "  └─ Has generics: true"
    else
        FLOW_GENERICS[$flow_idx]="false"
        log_debug "  └─ Has generics: false"
    fi
    
    # Extract ConnectorIntegrationV2 type parameters
    # First check if this trait even has ConnectorIntegrationV2 to avoid grep hanging
    local trait_def
    trait_def=$(sed -n "/pub trait $flow_trait/,/^}/p" "$connector_types_file")
    
    if ! echo "$trait_def" | grep -q "ConnectorIntegrationV2"; then
        FLOW_INTEGRATION_PARAMS[$flow_idx]=""
        log_debug "  └─ No ConnectorIntegrationV2 found (webhook/validation/redirect trait)"
        return 0
    fi
    
    
    # Extract the ConnectorIntegrationV2 type parameters
    # Join all lines first to handle multi-line definitions, then extract content
    # between ConnectorIntegrationV2< and > (followed by whitespace/brace)
    local integration_types
    integration_types=$(echo "$trait_def" | \
                       tr '\n' ' ' | \
                       sed 's/.*ConnectorIntegrationV2<//;s/>[[:space:]]*{.*//' | \
                       sed 's/^[[:space:]]*//;s/[[:space:]]*$//;s/[[:space:]][[:space:]]*/ /g')
    
    if [[ -n "$integration_types" ]]; then
        FLOW_INTEGRATION_PARAMS[$flow_idx]="$integration_types"
        log_debug "  └─ Integration types: $integration_types"
    else
        FLOW_INTEGRATION_PARAMS[$flow_idx]=""
        log_debug "  └─ No integration types extracted"
    fi
}

# Extract metadata for all detected flows
extract_all_flow_metadata() {
    log_step "Extracting flow metadata from connector_types.rs"
    
    # Clear arrays first
    FLOW_NAMES=()
    FLOW_GENERICS=()
    FLOW_INTEGRATION_PARAMS=()
    
    local flow
    for flow in "${AVAILABLE_FLOWS[@]}"; do
        extract_flow_metadata "$flow"
    done
    
    log_success "Extracted metadata for ${#FLOW_NAMES[@]} flows"
}

# Generate trait implementation code for a specific flow
generate_trait_impl() {
    local flow_trait="$1"
    local flow_idx=$(get_flow_index "$flow_trait")
    
    if [[ $flow_idx -lt 0 ]]; then
        log_debug "Flow $flow_trait not found in metadata"
        return
    fi
    
    local has_generics="${FLOW_GENERICS[$flow_idx]}"
    
    if [[ "$has_generics" == "true" ]]; then
        cat <<EOF
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::${flow_trait}<T> for ${NAME_PASCAL}<T>
{
}

EOF
    else
        cat <<EOF
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::${flow_trait} for ${NAME_PASCAL}<T>
{
}

EOF
    fi
}

# Generate ConnectorIntegrationV2 implementation for a specific flow
generate_connector_integration_impl() {
    local flow_trait="$1"
    local flow_idx=$(get_flow_index "$flow_trait")
    
    if [[ $flow_idx -lt 0 ]]; then
        log_debug "Flow $flow_trait not found in metadata"
        return
    fi
    
    local integration_types="${FLOW_INTEGRATION_PARAMS[$flow_idx]}"
    
    # Trim whitespace and check if empty or malformed
    integration_types=$(echo "$integration_types" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    
    # Skip if no integration types or malformed (e.g., IncomingWebhook, ValidationTrait)
    if [[ -z "$integration_types" ]] || [[ "$integration_types" == "{" ]] || [[  "$integration_types" == "}" ]]; then
        log_debug "Skipping ConnectorIntegrationV2 for $flow_trait (no integration types)"
        return
    fi
    
    # Parse the integration types
    local flow_type data_types
    flow_type=$(echo "$integration_types" | cut -d',' -f1 | sed 's/^[[:space:]]*//' | sed 's/[[:space:]]*$//')
    data_types=$(echo "$integration_types" | cut -d',' -f2- | sed 's/^[[:space:]]*//')
    
    # Additional validation - skip if flow_type is empty or invalid
    if [[ -z "$flow_type" ]] || [[ "$flow_type" == "{" ]] || [[ "$flow_type" == "}"  ]]; then
        log_debug "Skipping ConnectorIntegrationV2 for $flow_trait (invalid flow type)"
        return
    fi
    
    cat <<EOF
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<${flow_type}, ${data_types}>
    for ${NAME_PASCAL}<T>
{
}

EOF
}

# Generate SourceVerification implementation for flows that need it



# =============================================================================

readonly COLOR_RED='\033[0;31m'
readonly COLOR_GREEN='\033[0;32m'
readonly COLOR_YELLOW='\033[1;33m'
readonly COLOR_BLUE='\033[0;34m'
readonly COLOR_PURPLE='\033[0;35m'
readonly COLOR_CYAN='\033[0;36m'
readonly COLOR_RESET='\033[0m'

# =============================================================================
# GLOBAL VARIABLES
# =============================================================================

# User inputs
CONNECTOR_NAME=""
BASE_URL=""
FORCE_MODE=false
YES_MODE=false

# Auto-detected flows (populated by detect_flows_from_connector_service_trait)
SELECTED_FLOWS=()

# Generated values
NAME_SNAKE=""
NAME_PASCAL=""
NAME_UPPER=""
ENUM_ORDINAL=""
BACKUP_DIR=""

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

# Logging functions with consistent formatting
log_info() {
    echo -e "${COLOR_BLUE}ℹ️  INFO: $1${COLOR_RESET}"
}

log_success() {
    echo -e "${COLOR_GREEN}✅ SUCCESS: $1${COLOR_RESET}"
}

log_warning() {
    echo -e "${COLOR_YELLOW}⚠️  WARNING: $1${COLOR_RESET}"
}

log_error() {
    echo -e "${COLOR_RED}❌ ERROR: $1${COLOR_RESET}"
}

log_step() {
    echo -e "${COLOR_PURPLE}🔧 STEP: $1${COLOR_RESET}"
}

log_debug() {
    if [[ "${DEBUG:-false}" == "true" ]]; then
        echo -e "${COLOR_CYAN}🐛 DEBUG: $1${COLOR_RESET}"
    fi
}

# Error handling with context
fatal_error() {
    log_error "$1"
    log_error "Script execution terminated."
    exit 1
}

# Validation helpers
validate_file_exists() {
    local file="$1"
    local description="$2"

    if [[ ! -f "$file" ]]; then
        fatal_error "$description not found at: $file"
    fi
    log_debug "Validated file exists: $file"
}

validate_directory_exists() {
    local dir="$1"
    local description="$2"

    if [[ ! -d "$dir" ]]; then
        fatal_error "$description not found at: $dir"
    fi
    log_debug "Validated directory exists: $dir"
}

# String manipulation utilities
to_snake_case() {
    echo "$1" | sed 's/\([A-Z]\)/_\1/g' | sed 's/^_//' | tr '[:upper:]' '[:lower:]'
}

to_pascal_case() {
    # Convert snake_case to PascalCase
    echo "$1" | awk -F'_' '{for(i=1;i<=NF;i++) $i=toupper(substr($i,1,1)) tolower(substr($i,2))} 1' OFS=''
}

to_upper_case() {
    echo "$1" | tr '[:lower:]' '[:upper:]'
}

# =============================================================================
# HELP AND USAGE FUNCTIONS
# =============================================================================

show_version() {
    echo "$SCRIPT_NAME v$SCRIPT_VERSION"
}

show_help() {
    cat << EOF
$SCRIPT_NAME v$SCRIPT_VERSION

USAGE:
    $0 <connector_name> <base_url> [OPTIONS]

ARGUMENTS:
    connector_name    Name of the connector (snake_case, e.g., 'my_connector')
    base_url         Base URL for the connector API

OPTIONS:
    --list-flows     Show auto-detected flows from codebase
    --force          Ignore git status and force creation
    -y, --yes        Skip confirmation prompts
    --debug          Enable debug logging
    -h, --help       Show this help message
    -v, --version    Show version information

EXAMPLES:
    # Create connector (automatically detects all flows)
    $0 stripe https://api.stripe.com/v1

    # Force creation with auto-confirmation
    $0 example https://api.example.com --force -y

    # List auto-detected flows
    $0 --list-flows

FEATURES:
    • Auto-detects all flows from ConnectorServiceTrait
    • Future-proof: automatically includes new flows when added to codebase
    • Creates empty implementations for all detected flows
    • No manual flow configuration required

WORKFLOW:
    1. Auto-detects flows from connector_types.rs
    2. Validates environment and inputs
    3. Generates connector boilerplate with all flows
    4. Updates integration files
    5. Validates compilation
    6. Provides next steps guidance

For more information, visit: https://github.com/juspay/hyperswitch
EOF
}

show_available_flows() {
    echo "Auto-Detected Flows from ConnectorServiceTrait:"
    echo "==============================================="
    echo

    # Auto-detect flows first
    detect_flows_from_connector_service_trait

    local flow
    for flow in "${AVAILABLE_FLOWS[@]}"; do
        local description=$(get_flow_description "$flow")
        printf "  %-25s %s\n" "$flow" "$description"
    done

    echo
    echo "NOTE: All flows are automatically included when creating a connector."
    echo "No manual selection is required - the script is future-proof!"
}

# =============================================================================
# ARGUMENT PARSING
# =============================================================================

parse_arguments() {
    log_debug "Parsing arguments: $*"

    # Handle special cases first
    if [[ $# -eq 0 ]]; then
        show_help
        exit 0
    fi

    if [[ $# -eq 1 ]]; then
        case "$1" in
            --list-flows)
                show_available_flows
                exit 0
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            -v|--version)
                show_version
                exit 0
                ;;
            *)
                log_error "Missing required arguments."
                show_help
                exit 1
                ;;
        esac
    fi

    # Parse required arguments
    if [[ $# -lt 2 ]]; then
        log_error "Missing required arguments: connector_name and base_url"
        show_help
        exit 1
    fi

    CONNECTOR_NAME="$1"
    BASE_URL="$2"
    shift 2

    # Parse optional arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --force)
                FORCE_MODE=true
                shift
                ;;
            -y|--yes)
                YES_MODE=true
                shift
                ;;
            --debug)
                DEBUG=true
                shift
                ;;
            --list-flows)
                show_available_flows
                exit 0
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            -v|--version)
                show_version
                exit 0
                ;;
            *)
                fatal_error "Unknown option: $1"
                ;;
        esac
    done

    log_debug "Arguments parsed successfully"
}

# =============================================================================
# VALIDATION FUNCTIONS
# =============================================================================

validate_environment() {
    log_step "Validating environment"

    validate_directory_exists "$TEMPLATE_DIR" "Template directory"
    validate_directory_exists "$CRATES_TRAITS" "types-traits crate directory"
    validate_directory_exists "$CRATES_INTEGRATIONS" "integrations crate directory"
    validate_directory_exists "$CRATES_INTERNAL" "internal crate directory"

    # Check required template files
    validate_file_exists "$CONNECTOR_TEMPLATE" "Connector template"
    validate_file_exists "$TRANSFORMERS_TEMPLATE" "Transformers template"

    # Check target files that will be modified
    validate_file_exists "$CONNECTOR_TYPES_FILE" "Connector types file"
    validate_file_exists "$DOMAIN_TYPES_FILE" "Domain types file"
    validate_file_exists "$INTEGRATION_TYPES_FILE" "Integration types file"
    validate_file_exists "$DEFAULT_IMPL_FILE" "Default implementations file"
    validate_file_exists "$CONNECTORS_MODULE_FILE" "Connectors module file"
    validate_file_exists "$PROTO_FILE" "Protocol buffer file"
    validate_file_exists "$FIELD_PROBE_FILE" "Field probe file"

    # Check git status unless forced
    if [[ "$FORCE_MODE" == "false" ]] && command -v git >/dev/null 2>&1; then
        if [[ -n "$(git status --porcelain 2>/dev/null)" ]]; then
            fatal_error "Git working directory is not clean. Use --force to proceed anyway."
        fi
    fi

    log_success "Environment validation passed"
}

validate_inputs() {
    log_step "Validating inputs"

    # Validate connector name
    if [[ ! "$CONNECTOR_NAME" =~ ^[a-z][a-z0-9_]*$ ]]; then
        fatal_error "Connector name must start with a letter and contain only lowercase letters, numbers, and underscores"
    fi

    # Validate base URL
    if [[ ! "$BASE_URL" =~ ^https?://.+ ]]; then
        fatal_error "Base URL must be a valid HTTP/HTTPS URL"
    fi

    # Generate name variants
    NAME_SNAKE="$CONNECTOR_NAME"
    NAME_PASCAL=$(to_pascal_case "$CONNECTOR_NAME")
    NAME_UPPER=$(to_upper_case "$CONNECTOR_NAME")

    # Auto-detect flows from codebase
    detect_flows_from_connector_service_trait

    # Always use all detected flows (no manual selection)
    SELECTED_FLOWS=("${AVAILABLE_FLOWS[@]}")

    log_success "Input validation passed"
    log_info "Configuration: $NAME_SNAKE → $NAME_PASCAL"
    log_info "Base URL: $BASE_URL"
    log_info "Auto-detected ${#SELECTED_FLOWS[@]} flows: ${SELECTED_FLOWS[*]}"
}

check_naming_conflicts() {
    log_step "Checking for naming conflicts"

    # Check if connector files already exist
    local connector_file="$CRATES_INTEGRATIONS/connector-integration/src/connectors/$NAME_SNAKE.rs"
    local connector_dir="$CRATES_INTEGRATIONS/connector-integration/src/connectors/$NAME_SNAKE"

    if [[ -f "$connector_file" ]] || [[ -d "$connector_dir" ]]; then
        if [[ "$FORCE_MODE" == "false" ]]; then
            fatal_error "Connector '$NAME_SNAKE' already exists. Use --force to override."
        else
            log_warning "Connector files exist but will be overwritten due to --force mode"
        fi
    fi

    # Check protobuf enum (skip if --force mode)
    if [[ "$FORCE_MODE" == "false" ]] && grep -q "$NAME_UPPER =" "$PROTO_FILE" 2>/dev/null; then
        fatal_error "Connector '$NAME_UPPER' already exists in protobuf enum"
    elif grep -q "$NAME_UPPER =" "$PROTO_FILE" 2>/dev/null; then
        log_warning "Connector '$NAME_UPPER' already in protobuf enum, will skip protobuf update"
    fi

    # Check domain types (skip if --force mode)
    if [[ "$FORCE_MODE" == "false" ]] && grep -q "$NAME_PASCAL" "$DOMAIN_TYPES_FILE" 2>/dev/null; then
        fatal_error "Connector '$NAME_PASCAL' already exists in domain types"
    elif grep -q "$NAME_PASCAL" "$DOMAIN_TYPES_FILE" 2>/dev/null; then
        log_warning "Connector '$NAME_PASCAL' already in domain types, will skip domain types update"
    fi

    log_success "Conflict check completed"
}

# =============================================================================
# CORE GENERATION FUNCTIONS
# =============================================================================

get_next_enum_ordinal() {
    log_step "Determining next enum ordinal"

    if [[ -f "$PROTO_FILE" ]]; then
        # Extract the highest ordinal from Connector enum
        local max_ordinal
        max_ordinal=$(sed -n '/^enum Connector {/,/^}/p' "$PROTO_FILE" | \
                     grep -o '= [0-9]\+;' | \
                     grep -o '[0-9]\+' | \
                     sort -n | \
                     tail -1)

        if [[ -n "$max_ordinal" ]]; then
            ENUM_ORDINAL=$((max_ordinal + 1))
        else
            ENUM_ORDINAL=100
        fi
    else
        ENUM_ORDINAL=100
    fi

    log_debug "Next enum ordinal: $ENUM_ORDINAL"
}

create_backup() {
    log_step "Creating backup"

    BACKUP_DIR="$ROOT_DIR/.connector_backup_$(date +%s)"
    mkdir -p "$BACKUP_DIR"

    local files_to_backup=(
        "$PROTO_FILE"
        "$DOMAIN_TYPES_FILE"
        "$DOMAIN_TYPES_TYPES_FILE"
        "$CONNECTORS_MODULE_FILE"
        "$INTEGRATION_TYPES_FILE"
        "$DEFAULT_IMPL_FILE"
        "$ROUTER_DATA_FILE"
        "$FIELD_PROBE_FILE"
        "$CONFIG_FILE"
        "$SANDBOX_CONFIG_FILE"
        "$PRODUCTION_CONFIG_FILE"
    )

    local file
    for file in "${files_to_backup[@]}"; do
        if [[ -f "$file" ]]; then
            # Create unique backup names for files with same basename
            if [[ "$file" == "$DOMAIN_TYPES_TYPES_FILE" ]]; then
                cp "$file" "$BACKUP_DIR/domain_types_types.rs"
                log_debug "Backed up: domain_types/types.rs"
            elif [[ "$file" == "$INTEGRATION_TYPES_FILE" ]]; then
                cp "$file" "$BACKUP_DIR/integration_types.rs"
                log_debug "Backed up: connector-integration/types.rs"
            elif [[ "$file" == "$DEFAULT_IMPL_FILE" ]]; then
                cp "$file" "$BACKUP_DIR/default_implementations.rs"
                log_debug "Backed up: connector-integration/default_implementations.rs"
            elif [[ "$file" == "$ROUTER_DATA_FILE" ]]; then
                cp "$file" "$BACKUP_DIR/router_data.rs"
                log_debug "Backed up: domain_types/router_data.rs"
            elif [[ "$file" == "$FIELD_PROBE_FILE" ]]; then
                cp "$file" "$BACKUP_DIR/field_probe_auth.rs"
                log_debug "Backed up: field-probe/auth.rs"
            else
                cp "$file" "$BACKUP_DIR/$(basename "$file")"
                log_debug "Backed up: $(basename "$file")"
            fi
        fi
    done

    log_success "Backup created at: $BACKUP_DIR"
}

substitute_template_variables() {
    local input_file="$1"
    local output_file="$2"

    log_debug "Substituting variables in template: $(basename "$input_file")"

    sed -e "s/{{CONNECTOR_NAME_PASCAL}}/$NAME_PASCAL/g" \
        -e "s/{{CONNECTOR_NAME_SNAKE}}/$NAME_SNAKE/g" \
        -e "s/{{CONNECTOR_NAME_UPPER}}/$NAME_UPPER/g" \
        -e "s|{{BASE_URL}}|$BASE_URL|g" \
        "$input_file" > "$output_file"
}

create_connector_files() {
    log_step "Creating connector files"

    local connectors_dir="$CRATES_INTEGRATIONS/connector-integration/src/connectors"
    local connector_subdir="$connectors_dir/$NAME_SNAKE"

    # Create main connector file from template
    substitute_template_variables "$CONNECTOR_TEMPLATE" "$connectors_dir/$NAME_SNAKE.rs"

    # Create connector subdirectory and transformers file
    mkdir -p "$connector_subdir"
    substitute_template_variables "$TRANSFORMERS_TEMPLATE" "$connector_subdir/transformers.rs"
    
    # Generate and append dynamic implementations
    generate_dynamic_implementations "$connectors_dir/$NAME_SNAKE.rs"

    log_success "Created connector files with dynamic implementations"
}

# Generate dynamic implementation code for all flows and append to connector file
generate_dynamic_implementations() {
    local connector_file="$1"
    
    log_step "Generating dynamic implementations for all flows"
    
    # Create a temporary file for the dynamic implementations
    local temp_file="${connector_file}.dynamic"
    
    # Add header comment
    cat > "$temp_file" <<'EOF'

// =============================================================================
// DYNAMICALLY GENERATED IMPLEMENTATIONS
// =============================================================================
// The following implementations were auto-generated by add_connector.sh
// based on the flows detected in ConnectorServiceTrait.
// 
// To customize a flow implementation:
// 1. Move the empty impl block above (before this comment section)
// 2. Add your custom logic inside the impl block
// 3. The script will not regenerate moved implementations
// =============================================================================

// ===== CONNECTOR SERVICE TRAIT IMPLEMENTATIONS =====
// Main service trait - aggregates all other traits
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ConnectorServiceTrait<T> for {{CONNECTOR_NAME_PASCAL}}<T>
{
}

// ===== FLOW TRAIT IMPLEMENTATIONS =====
EOF

    # Substitute connector name in the header
    sed -i.tmp "s/{{CONNECTOR_NAME_PASCAL}}/$NAME_PASCAL/g" "$temp_file"
    rm -f "${temp_file}.tmp"

    cat >> "$temp_file" <<EOF

// Payout traits and default no-op ConnectorIntegrationV2 impls.
crate::connectors::macros::macro_connector_payout_implementation!(
    connector: ${NAME_PASCAL},
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize]
);

EOF

    # Generate trait implementations for each flow
    local flow
    for flow in "${AVAILABLE_FLOWS[@]}"; do
        case "$flow" in
            ConnectorCommon|VerifyWebhookSourceV2|\
            PayoutCreateV2|PayoutTransferV2|PayoutGetV2|PayoutVoidV2|\
            PayoutStageV2|PayoutCreateLinkV2|PayoutCreateRecipientV2|PayoutEnrollDisburseAccountV2)
                continue
                ;;
        esac

        generate_trait_impl "$flow" >> "$temp_file"
    done

    # Add section for ConnectorIntegrationV2 implementations
    cat >> "$temp_file" <<EOF

// ===== CONNECTOR INTEGRATION V2 IMPLEMENTATIONS =====
EOF
    
    # Generate ConnectorIntegrationV2 implementations
    for flow in "${AVAILABLE_FLOWS[@]}"; do
        case "$flow" in
            ConnectorCommon|IncomingWebhook|ValidationTrait|VerifyRedirectResponse|VerifyWebhookSourceV2|\
            PayoutCreateV2|PayoutTransferV2|PayoutGetV2|PayoutVoidV2|\
            PayoutStageV2|PayoutCreateLinkV2|PayoutCreateRecipientV2|PayoutEnrollDisburseAccountV2)
                continue
                ;;
        esac

        generate_connector_integration_impl "$flow" >> "$temp_file"
    done
    
    # SourceVerification is a simple non-generic trait required by VerifyRedirectResponse
    # Add a single implementation for all connectors
    cat >> "$temp_file" <<EOF



// ===== SOURCE VERIFICATION IMPLEMENTATION =====
// Simple non-generic trait for webhook signature verification
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification for ${NAME_PASCAL}<T>
{
}

EOF
    
    # Append dynamic implementations to the connector file
    cat "$temp_file" >> "$connector_file"
    rm -f "$temp_file"
    
    log_success "Generated dynamic implementations for ${#AVAILABLE_FLOWS[@]} flows"
}


# =============================================================================
# FILE UPDATE FUNCTIONS
# =============================================================================

update_protobuf() {
    log_step "Updating protobuf definitions"

    # Check if already exists
    if grep -q "$NAME_UPPER =" "$PROTO_FILE" 2>/dev/null; then
        log_warning "Skipping protobuf update - $NAME_UPPER already exists"
        return 0
    fi

    python3 - "$NAME_UPPER" "$ENUM_ORDINAL" "$PROTO_FILE" <<'PYEOF'
import sys

name = sys.argv[1]
ordinal = sys.argv[2]
path = sys.argv[3]
content = open(path).read()
start = content.index("enum Connector {")
end = content.index("\n}", start)
entry = f"  {name} = {ordinal};\n"
content = content[:end] + "\n" + entry + content[end + 1:]
open(path, "w").write(content)
PYEOF

    log_success "Updated protobuf with $NAME_UPPER = $ENUM_ORDINAL"
}

update_domain_types() {
    log_step "Updating domain types"

    # Check if already exists in ConnectorEnum
    if grep -q "^[[:space:]]*$NAME_PASCAL," "$DOMAIN_TYPES_FILE" 2>/dev/null; then
        log_warning "Skipping domain types update - $NAME_PASCAL already exists"
        return 0
    fi

    python3 - "$NAME_PASCAL" "$DOMAIN_TYPES_FILE" <<'PYEOF'
import sys

name = sys.argv[1]
path = sys.argv[2]
content = open(path).read()

def find_matching_brace(text: str, open_idx: int) -> int:
    depth = 0
    for idx in range(open_idx, len(text)):
        ch = text[idx]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return idx
    raise SystemExit("matching brace not found")

enum_start = content.index("pub enum ConnectorEnum {")
enum_open = content.index("{", enum_start)
enum_close = find_matching_brace(content, enum_open)
content = content[:enum_close] + f"    {name},\n" + content[enum_close:]

grpc_anchor = "            grpc_api_types::payments::Connector::Unspecified =>"
grpc_entry = f"            grpc_api_types::payments::Connector::{name} => Ok(Self::{name}),\n"
if grpc_anchor not in content:
    raise SystemExit("Connector enum gRPC mapping anchor not found")
content = content.replace(grpc_anchor, grpc_entry + grpc_anchor, 1)

auth_anchor = "            AuthType::Imerchantsolutions(_) => Ok(Self::Imerchantsolutions),"
auth_entry = f"            AuthType::{name}(_) => Ok(Self::{name}),\n"
if auth_anchor not in content:
    raise SystemExit("AuthType to ConnectorEnum mapping anchor not found")
content = content.replace(auth_anchor, auth_entry + auth_anchor, 1)

open(path, "w").write(content)
PYEOF

    log_success "Updated domain types with $NAME_PASCAL"
}

update_domain_types_file() {
    log_step "Updating domain types types.rs file"

    if grep -q "^[[:space:]]*pub $NAME_SNAKE: ConnectorParams," "$DOMAIN_TYPES_TYPES_FILE" 2>/dev/null; then
        log_warning "Skipping types.rs update - $NAME_SNAKE already exists"
        return 0
    fi

    python3 - "$NAME_SNAKE" "$DOMAIN_TYPES_TYPES_FILE" <<'PYEOF'
import sys

name = sys.argv[1]
path = sys.argv[2]
content = open(path).read()
start = content.index("pub struct Connectors {")
end = content.index("\n}", start)
entry = f"    pub {name}: ConnectorParams,\n"
content = content[:end] + "\n" + entry + content[end + 1:]
open(path, "w").write(content)
PYEOF

    log_success "Added $NAME_SNAKE to Connectors struct in types.rs"
}

update_router_data() {
    log_step "Updating router_data.rs (ConnectorSpecificAuth + match arm)"

    # Check if already exists
    if grep -q "ConnectorEnum::$NAME_PASCAL =>" "$ROUTER_DATA_FILE" 2>/dev/null; then
        log_warning "Skipping router_data update - $NAME_PASCAL already exists"
        return 0
    fi

    python3 - "$NAME_PASCAL" "$NAME_SNAKE" "$ROUTER_DATA_FILE" <<'PYEOF'
import sys

name = sys.argv[1]
auth_var = sys.argv[2]
path = sys.argv[3]
content = open(path).read()

def find_matching_brace(text: str, open_idx: int) -> int:
    depth = 0
    for idx in range(open_idx, len(text)):
        ch = text[idx]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return idx
    raise SystemExit("matching brace not found")

enum_start = content.index("pub enum ConnectorSpecificConfig {")
enum_open = content.index("{", enum_start)
enum_close = find_matching_brace(content, enum_open)
enum_entry = (
    f"    {name} {{\n"
    f"        api_key: Secret<String>,\n"
    f"        base_url: Option<String>,\n"
    f"    }},\n"
)
content = content[:enum_close] + enum_entry + content[enum_close:]

macro_anchor = "            Imerchantsolutions { api_key },"
macro_entry = f"            {name} {{ api_key }},\n"
if content.count(macro_anchor) < 2:
    raise SystemExit("base_url_override/connector_key macro anchor not found twice")
content = content.replace(macro_anchor, macro_entry + macro_anchor, 2)

auth_type_anchor = "            AuthType::Imerchantsolutions(imerchantsolutions) => Ok(Self::Imerchantsolutions {"
auth_type_entry = (
    f"            AuthType::{name}({auth_var}) => Ok(Self::{name} {{\n"
    f"                api_key: {auth_var}.api_key.ok_or_else(err)?,\n"
    f"                base_url: {auth_var}.base_url,\n"
    f"            }}),\n"
)
if auth_type_anchor not in content:
    raise SystemExit("ConnectorSpecificConfig gRPC AuthType anchor not found")
content = content.replace(auth_type_anchor, auth_type_entry + auth_type_anchor, 1)

connector_anchor = "            ConnectorEnum::PinelabsOnline => match auth {"
connector_entry = (
    f"            ConnectorEnum::{name} => match auth {{\n"
    f"                ConnectorAuthType::HeaderKey {{ api_key }} => Ok(Self::{name} {{\n"
    f"                    api_key: api_key.clone(),\n"
    f"                    base_url: None,\n"
    f"                }}),\n"
    f"                _ => Err(err().into()),\n"
    f"            }},\n"
)
if connector_anchor not in content:
    raise SystemExit("ConnectorEnum auth conversion anchor not found")
content = content.replace(connector_anchor, connector_entry + connector_anchor, 1)

open(path, "w").write(content)
PYEOF

    log_success "Updated router_data.rs with $NAME_PASCAL auth variant and match arm"
}

update_protobuf_auth() {
    log_step "Updating protobuf auth definitions"

    # Check if config message already exists
    if grep -q "${NAME_PASCAL}Config" "$PROTO_FILE" 2>/dev/null; then
        log_warning "Skipping protobuf auth update - ${NAME_PASCAL}Config already exists"
        return 0
    fi

    python3 - "$NAME_PASCAL" "$NAME_SNAKE" "$NAME_UPPER" "$ENUM_ORDINAL" "$PROTO_FILE" <<'PYEOF'
import re
import sys

name_pascal = sys.argv[1]
name_snake = sys.argv[2]
name_upper = sys.argv[3]
ordinal = sys.argv[4]
path = sys.argv[5]
content = open(path).read()

message = (
    f"message {name_pascal}Config {{\n"
    f"  SecretString api_key = 1;\n"
    f"  optional string base_url = 50;\n"
    f"}}\n\n"
)
comment = "// ConnectorSpecificConfig message"
if comment not in content:
    raise SystemExit("ConnectorSpecificConfig comment anchor not found")
content = content.replace(comment, message + comment, 1)

field_numbers = [int(num) for num in re.findall(r"Config\s+[a-z0-9_]+\s+=\s+(\d+);", content)]
next_field_num = max(field_numbers, default=0) + 1
oneof_close = content.index("\n  }\n}", content.index("message ConnectorSpecificConfig {"))
entry = f"\n    // {name_upper} = {ordinal}\n    {name_pascal}Config {name_snake} = {next_field_num};"
content = content[:oneof_close] + entry + content[oneof_close:]
open(path, "w").write(content)
PYEOF

    log_success "Updated protobuf with ${NAME_PASCAL}Config message and oneof entry"
}

update_router_data_grpc_auth() {
    log_step "Updating router_data.rs gRPC AuthType mapping"

    # Check if already exists
    if grep -q "AuthType::$NAME_PASCAL(" "$ROUTER_DATA_FILE" 2>/dev/null; then
        log_warning "Skipping gRPC auth mapping - $NAME_PASCAL already exists"
        return 0
    fi

    python3 - "$NAME_PASCAL" "$NAME_SNAKE" "$ROUTER_DATA_FILE" <<'PYEOF'
import sys

name = sys.argv[1]
var = sys.argv[2]
path = sys.argv[3]
content = open(path).read()
anchor = "            AuthType::Imerchantsolutions(imerchantsolutions) => Ok(Self::Imerchantsolutions {"
entry = (
    f"            AuthType::{name}({var}) => Ok(Self::{name} {{\n"
    f"                api_key: {var}.api_key.ok_or_else(err)?,\n"
    f"                base_url: {var}.base_url,\n"
    f"            }}),\n"
)
if anchor not in content:
    raise SystemExit("ConnectorSpecificConfig gRPC AuthType anchor not found")
content = content.replace(anchor, entry + anchor, 1)
open(path, "w").write(content)
PYEOF

    log_success "Updated router_data.rs with gRPC AuthType::$NAME_PASCAL mapping"
}

update_connectors_module() {
    log_step "Updating connectors module"

    if grep -q "^pub mod $NAME_SNAKE;" "$CONNECTORS_MODULE_FILE" 2>/dev/null; then
        log_warning "Skipping connectors module update - $NAME_SNAKE already exists"
        return 0
    fi

    # Add module declaration and use statement
    cat >> "$CONNECTORS_MODULE_FILE" << EOF

pub mod $NAME_SNAKE;
pub use self::${NAME_SNAKE}::${NAME_PASCAL};
EOF

    log_success "Updated connectors module"
}

update_integration_types() {
    log_step "Updating integration types"

    if grep -q "ConnectorEnum::$NAME_PASCAL =>" "$INTEGRATION_TYPES_FILE" 2>/dev/null; then
        log_warning "Skipping integration types update - $NAME_PASCAL already exists"
        return 0
    fi

    python3 - "$NAME_PASCAL" "$INTEGRATION_TYPES_FILE" <<'PYEOF'
import sys

name = sys.argv[1]
path = sys.argv[2]
content = open(path).read()
entry = f"            ConnectorEnum::{name} => Box::new(connectors::{name}::<T>::new()),\n"
anchor = "        }\n    }\n}\n\npub struct ResponseRouterData"
if anchor not in content:
    raise SystemExit("convert_connector match closing anchor not found")
content = content.replace(anchor, entry + anchor, 1)
open(path, "w").write(content)
PYEOF

    log_success "Updated integration types with $NAME_PASCAL mapping"
}

update_default_implementations() {
    log_step "Updating default_implementations.rs"

    if grep -q "[[:space:]]$NAME_PASCAL[[:space:],]" "$DEFAULT_IMPL_FILE" 2>/dev/null || grep -q "[[:space:]]$NAME_PASCAL$" "$DEFAULT_IMPL_FILE" 2>/dev/null; then
        log_warning "Skipping default_implementations update - $NAME_PASCAL already exists"
        return 0
    fi

    python3 - "$NAME_PASCAL" "$DEFAULT_IMPL_FILE" <<'PYEOF'
import sys

name = sys.argv[1]
path = sys.argv[2]
content = open(path).read()
marker = "\n);"
idx = content.rfind(marker)
if idx == -1:
    raise SystemExit("default_impl_verify_webhook_source_v2! closing marker not found")
before = content[:idx].rstrip()
suffix = content[idx:]
separator = "," if not before.endswith(",") else ""
content = before + f"{separator}\n    {name}" + suffix
open(path, "w").write(content)
PYEOF

    log_success "Registered $NAME_PASCAL in default_impl_verify_webhook_source_v2!"
}

update_config_file() {
    local config_file="$1"
    local config_name="$2"

    if [[ -f "$config_file" ]]; then
        if grep -q "^$NAME_SNAKE\\.base_url[[:space:]]*=" "$config_file"; then
            log_warning "Skipping $config_name update - $NAME_SNAKE already exists"
            return 0
        fi

        # Check if [connectors] section exists
        if grep -q "^\[connectors\]" "$config_file"; then
            python3 - "$NAME_SNAKE" "$BASE_URL" "$config_file" <<'PYEOF'
import sys

name = sys.argv[1]
base_url = sys.argv[2]
path = sys.argv[3]
lines = open(path).read().splitlines(keepends=True)
for idx, line in enumerate(lines):
    if line.strip() == "[connectors]":
        lines.insert(idx + 1, f'{name}.base_url = "{base_url}"\n')
        break
else:
    raise SystemExit("[connectors] section not found")
open(path, "w").write("".join(lines))
PYEOF
            log_success "Updated $config_name in [connectors] section"
        else
            # Create [connectors] section at the end
            echo "" >> "$config_file"
            echo "[connectors]" >> "$config_file"
            echo "# $NAME_PASCAL connector configuration" >> "$config_file"
            echo "$NAME_SNAKE.base_url = \"$BASE_URL\"" >> "$config_file"
            log_success "Created [connectors] section in $config_name and added configuration"
        fi
    else
        log_warning "$config_name not found, skipping config update"
    fi
}

update_config() {
    log_step "Updating configuration files"

    # Update all environment config files
    update_config_file "$CONFIG_FILE" "development.toml"
    update_config_file "$SANDBOX_CONFIG_FILE" "sandbox.toml"
    update_config_file "$PRODUCTION_CONFIG_FILE" "production.toml"

    log_success "All configuration files updated"
}

update_field_probe() {
    log_step "Updating field-probe auth.rs (ConnectorEnum match arm)"

    # Check if already exists
    if grep -q "ConnectorEnum::$NAME_PASCAL =>" "$FIELD_PROBE_FILE" 2>/dev/null; then
        log_warning "Skipping field-probe update - $NAME_PASCAL already exists"
        return 0
    fi

    python3 - "$NAME_PASCAL" "$FIELD_PROBE_FILE" <<'PYEOF'
import re
import sys

name = sys.argv[1]
path = sys.argv[2]
content = open(path).read()
arm = (
    f"        ConnectorEnum::{name} => ConnectorSpecificConfig::{name} {{\n"
    f"            api_key: k(),\n"
    f"            base_url: None,\n"
    f"        }},\n"
)
content, count = re.subn(r"(\n    \}\n\}\s*)$", "\n" + arm + r"\1", content, count=1)
if count != 1:
    raise SystemExit("dummy_auth match closing anchor not found")
open(path, "w").write(content)
PYEOF

    log_success "Updated field-probe auth.rs with $NAME_PASCAL match arm"
}

# =============================================================================
# VALIDATION AND CLEANUP
# =============================================================================

format_code() {
    log_step "Formatting code"

    if command -v cargo >/dev/null 2>&1; then
        if (cd "$ROOT_DIR" && cargo +nightly fmt --all >/dev/null 2>&1); then
            log_success "Code formatted with nightly rustfmt"
        elif (cd "$ROOT_DIR" && cargo fmt --all >/dev/null 2>&1); then
            log_success "Code formatted with stable rustfmt"
        else
            log_warning "Code formatting failed"
        fi
    else
        log_warning "Cargo not found, skipping code formatting"
    fi
}

validate_compilation() {
    log_step "Validating compilation"

    if command -v cargo >/dev/null 2>&1; then
        log_info "Running cargo check..."

        if (cd "$ROOT_DIR" && cargo check --package connector-integration 2>&1); then
            log_success "Compilation validation passed"
            return 0
        else
            log_error "Compilation validation failed"
            return 1
        fi
    else
        log_warning "Cargo not found, skipping compilation validation"
        return 0
    fi
}

cleanup_backup() {
    if [[ -n "$BACKUP_DIR" ]] && [[ -d "$BACKUP_DIR" ]]; then
        rm -rf "$BACKUP_DIR"
        log_debug "Cleaned up backup directory"
    fi
}

emergency_rollback() {
    log_step "Performing emergency rollback"

    if [[ -n "$BACKUP_DIR" ]] && [[ -d "$BACKUP_DIR" ]]; then
        # Remove created files
        rm -f "$CRATES_INTEGRATIONS/connector-integration/src/connectors/$NAME_SNAKE.rs"
        rm -rf "$CRATES_INTEGRATIONS/connector-integration/src/connectors/$NAME_SNAKE"

        # Restore backed up files
        local backup_file
        for backup_file in "$BACKUP_DIR"/*; do
            if [[ -f "$backup_file" ]]; then
                local filename
                filename=$(basename "$backup_file")
                case "$filename" in
                    "payment.proto")
                        cp "$backup_file" "$PROTO_FILE"
                        ;;
                    "connector_types.rs")
                        cp "$backup_file" "$DOMAIN_TYPES_FILE"
                        ;;
                    "domain_types_types.rs")
                        cp "$backup_file" "$DOMAIN_TYPES_TYPES_FILE"
                        ;;
                    "integration_types.rs")
                        cp "$backup_file" "$INTEGRATION_TYPES_FILE"
                        ;;
                    "default_implementations.rs")
                        cp "$backup_file" "$DEFAULT_IMPL_FILE"
                        ;;
                    "router_data.rs")
                        cp "$backup_file" "$ROUTER_DATA_FILE"
                        ;;
                    "field_probe_auth.rs")
                        cp "$backup_file" "$FIELD_PROBE_FILE"
                        ;;
                    "connectors.rs")
                        cp "$backup_file" "$CONNECTORS_MODULE_FILE"
                        ;;
                    "development.toml")
                        cp "$backup_file" "$CONFIG_FILE"
                        ;;
                    "sandbox.toml")
                        cp "$backup_file" "$SANDBOX_CONFIG_FILE"
                        ;;
                    "production.toml")
                        cp "$backup_file" "$PRODUCTION_CONFIG_FILE"
                        ;;
                esac
            fi
        done

        rm -rf "$BACKUP_DIR"
        log_success "Emergency rollback completed"
    else
        log_warning "No backup found for rollback"
    fi
}

# =============================================================================
# USER INTERACTION
# =============================================================================

show_implementation_plan() {
    if [[ "$YES_MODE" == "true" ]]; then
        return 0
    fi

    echo
    log_step "Implementation Plan"
    echo "====================="
    echo
    echo "📁 Files to create:"
    echo "   ├── crates/integrations/connector-integration/src/connectors/$NAME_SNAKE.rs"
    echo "   └── crates/integrations/connector-integration/src/connectors/$NAME_SNAKE/transformers.rs"
    echo
    echo "📝 Files to modify:"
    echo "   ├── crates/types-traits/grpc-api-types/proto/payment.proto"
    echo "   ├── crates/types-traits/domain_types/src/connector_types.rs"
    echo "   ├── crates/types-traits/domain_types/src/router_data.rs"
    echo "   ├── crates/integrations/connector-integration/src/connectors.rs"
    echo "   ├── crates/integrations/connector-integration/src/types.rs"
    echo "   └── config/development.toml"
    echo
    echo "🎯 Configuration:"
    echo "   ├── Connector: $NAME_PASCAL"
    echo "   ├── Enum ordinal: $ENUM_ORDINAL"
    echo "   ├── Base URL: $BASE_URL"
    echo "   └── Flows: ${SELECTED_FLOWS[*]}"
    echo

    read -p "❓ Proceed with implementation? [y/N]: " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_error "Implementation cancelled by user"
        exit 1
    fi
}

show_next_steps() {
    echo
    log_success "Connector '$NAME_SNAKE' successfully created!"
    echo
    log_step "Next Steps"
    echo "============"
    echo
    echo "1️⃣  Implement Core Logic:"
    echo "   📁 Edit: crates/integrations/connector-integration/src/connectors/$NAME_SNAKE/transformers.rs"
    echo "      • Update request/response structures for your API"
    echo "      • Implement proper field mappings"
    echo "      • Handle authentication requirements"
    echo
    echo "2️⃣  Customize Connector:"
    echo "   📁 Edit: crates/integrations/connector-integration/src/connectors/$NAME_SNAKE.rs"
    echo "      • Update URL patterns and endpoints"
    echo "      • Implement error handling"
    echo "      • Add connector-specific logic"
    echo
    echo "3️⃣  Validation Commands:"
    echo "   📋 Check compilation: cargo check --package connector-integration"
    echo "   📋 Run tests: cargo test --package connector-integration"
    echo "   📋 Build: cargo build --package connector-integration"
    echo
    log_success "Connector '$NAME_PASCAL' is ready for implementation!"
}

# =============================================================================
# MAIN EXECUTION FLOW
# =============================================================================

main() {
    # Print header
    echo "$SCRIPT_NAME v$SCRIPT_VERSION"
    echo "======================================="
    echo

    # Set up error handling
    trap 'emergency_rollback; exit 1' ERR

    # Core execution flow
    parse_arguments "$@"
    validate_environment
    validate_inputs
    check_naming_conflicts
    get_next_enum_ordinal
    
    # Extract flow metadata for dynamic generation
    extract_all_flow_metadata

    # Show implementation plan and get confirmation
    show_implementation_plan

    # Create backup for safety
    create_backup

    # Execute main operations
    create_connector_files
    update_protobuf
    update_protobuf_auth
    update_domain_types
    update_domain_types_file
    update_router_data
    update_router_data_grpc_auth
    update_connectors_module
    update_integration_types
    update_default_implementations
    update_config
    update_field_probe

    # Validate and finalize
    format_code
    if ! validate_compilation; then
        emergency_rollback
        exit 1
    fi

    # Success cleanup and guidance
    cleanup_backup
    show_next_steps
}

# Execute main function with all arguments
main "$@"
