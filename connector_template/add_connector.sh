#!/bin/bash

# Hyperswitch Connector Setup Script
# Usage: ./setup_connector.sh <connector_name> <base_url> [--force] [-y]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print colored output
print_status() {
    echo -e "${BLUE}🔧 $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

# Variables
CONNECTOR_NAME=""
BASE_URL=""
FORCE=false
YES=false
ROOT_DIR=$(pwd)
TEMPLATE_DIR="$ROOT_DIR/connector_template"
BACKUP_DIR=""

# Parse arguments
parse_args() {
    if [ $# -lt 2 ]; then
        echo "Usage: $0 <connector_name> <base_url> [--force] [-y]"
        echo ""
        echo "Examples:"
        echo "  $0 stripe https://api.stripe.com/v1"
        echo "  $0 paypal https://api.paypal.com --force -y"
        exit 1
    fi

    CONNECTOR_NAME="$1"
    BASE_URL="$2"
    shift 2

    while [[ $# -gt 0 ]]; do
        case $1 in
            --force)
                FORCE=true
                shift
                ;;
            -y|--yes)
                YES=true
                shift
                ;;
            *)
                print_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
}

# Validate environment
validate_environment() {
    print_status "Validating environment..."

    # Check if we're in the right directory
    if [ ! -d "$TEMPLATE_DIR" ]; then
        print_error "Template directory not found: $TEMPLATE_DIR"
        print_error "Please run this script from the connector-service root directory"
        exit 1
    fi

    # Check required templates
    if [ ! -f "$TEMPLATE_DIR/connector.rs.template" ]; then
        print_error "connector.rs.template not found"
        exit 1
    fi

    if [ ! -f "$TEMPLATE_DIR/transformers.rs.template" ]; then
        print_error "transformers.rs.template not found"
        exit 1
    fi

    # Check git status
    if [ "$FORCE" = false ]; then
        if command -v git >/dev/null 2>&1; then
            if [ -n "$(git status --porcelain 2>/dev/null)" ]; then
                print_error "Git working directory is not clean. Use --force to proceed anyway"
                exit 1
            fi
        else
            print_warning "Git not available - proceeding without git checks"
        fi
    fi

    print_success "Environment validated"
}

# Validate inputs
validate_inputs() {
    print_status "Validating inputs..."

    # Validate connector name
    if ! echo "$CONNECTOR_NAME" | grep -q '^[a-z][a-z0-9_]*$'; then
        print_error "Connector name must start with a letter and contain only lowercase letters, numbers, and underscores"
        exit 1
    fi

    # Validate base URL
    if ! echo "$BASE_URL" | grep -q '^https\?://.*$'; then
        print_error "Base URL must be a valid HTTP/HTTPS URL"
        exit 1
    fi

    # Generate name variants
    NAME_SNAKE=$(echo "$CONNECTOR_NAME" | tr '[:upper:]' '[:lower:]')
    # Convert to PascalCase: capitalize first letter and letters after underscores
    NAME_PASCAL=$(echo "$NAME_SNAKE" | awk '{gsub(/_/, " "); print}' | awk '{for(i=1;i<=NF;i++) $i=toupper(substr($i,1,1)) tolower(substr($i,2))}1' | tr -d ' ')
    NAME_UPPER=$(echo "$NAME_SNAKE" | tr '[:lower:]' '[:upper:]')

    print_success "Configuration: $NAME_SNAKE → $NAME_PASCAL"
    print_success "Base URL: $BASE_URL"
}

# Check for naming conflicts
check_conflicts() {
    print_status "Checking for naming conflicts..."

    # Check if connector files already exist
    local connector_file="backend/connector-integration/src/connectors/$NAME_SNAKE.rs"
    local connector_dir="backend/connector-integration/src/connectors/$NAME_SNAKE"

    if [ -f "$connector_file" ] || [ -d "$connector_dir" ]; then
        print_error "Connector '$NAME_SNAKE' already exists"
        exit 1
    fi

    # Check protobuf enum
    if grep -q "$NAME_UPPER =" backend/grpc-api-types/proto/payment.proto 2>/dev/null; then
        print_error "Connector '$NAME_UPPER' already exists in protobuf enum"
        exit 1
    fi

    # Check domain types
    if grep -q "$NAME_PASCAL" backend/domain_types/src/connector_types.rs 2>/dev/null; then
        print_error "Connector '$NAME_PASCAL' already exists in domain types"
        exit 1
    fi

    print_success "No naming conflicts found"
}

# Get next enum ordinal
get_next_ordinal() {
    local proto_file="backend/grpc-api-types/proto/payment.proto"
    if [ -f "$proto_file" ]; then
        # Extract only the Connector enum section and find the highest ordinal
        local max_ordinal=$(sed -n '/^enum Connector {/,/^}/p' "$proto_file" | grep -o '= [0-9]\+;' | grep -o '[0-9]\+' | sort -n | tail -1)
        if [ -n "$max_ordinal" ]; then
            ENUM_ORDINAL=$((max_ordinal + 1))
        else
            ENUM_ORDINAL=100
        fi
    else
        ENUM_ORDINAL=100
    fi
}

# Show plan summary
show_plan() {
    if [ "$YES" = true ]; then
        return
    fi

    echo ""
    print_status "Implementation Plan:"
    echo "===================="
    echo ""
    echo "📁 Files to create:"
    echo "   ├── backend/connector-integration/src/connectors/$NAME_SNAKE.rs"
    echo "   └── backend/connector-integration/src/connectors/$NAME_SNAKE/transformers.rs"
    echo ""
    echo "📝 Files to modify:"
    echo "   ├── backend/grpc-api-types/proto/payment.proto"
    echo "   ├── backend/domain_types/src/connector_types.rs"
    echo "   ├── backend/connector-integration/src/connectors.rs"
    echo "   ├── backend/connector-integration/src/types.rs"
    echo "   └── config/development.toml"
    echo ""
    echo "🎯 Configuration:"
    echo "   ├── Connector: $NAME_PASCAL"
    echo "   ├── Enum ordinal: $ENUM_ORDINAL"
    echo "   └── Base URL: $BASE_URL"
    echo ""

    read -p "❓ Proceed with implementation? [y/N]: " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_error "Setup cancelled by user"
        exit 1
    fi
}

# Create backup
create_backup() {
    print_status "Creating backup..."

    BACKUP_DIR="$ROOT_DIR/.connector_backup_$(date +%s)"
    mkdir -p "$BACKUP_DIR"

    local files_to_backup=(
        "backend/grpc-api-types/proto/payment.proto"
        "backend/domain_types/src/connector_types.rs"
        "backend/connector-integration/src/connectors.rs"
        "backend/connector-integration/src/types.rs"
        "config/development.toml"
    )

    for file in "${files_to_backup[@]}"; do
        if [ -f "$file" ]; then
            cp "$file" "$BACKUP_DIR/$(basename "$file")"
        fi
    done

    print_success "Created backup in $BACKUP_DIR"
}

# Substitute template variables
substitute_template() {
    local input_file="$1"
    local output_file="$2"

    sed -e "s/{{CONNECTOR_NAME_PASCAL}}/$NAME_PASCAL/g" \
        -e "s/{{CONNECTOR_NAME_SNAKE}}/$NAME_SNAKE/g" \
        -e "s/{{CONNECTOR_NAME_UPPER}}/$NAME_UPPER/g" \
        -e "s|{{BASE_URL}}|$BASE_URL|g" \
        "$input_file" > "$output_file"
}

# Create connector files
create_connector_files() {
    print_status "Creating connector files..."

    local connectors_dir="backend/connector-integration/src/connectors"
    local connector_subdir="$connectors_dir/$NAME_SNAKE"

    # Create main connector file
    substitute_template "$TEMPLATE_DIR/connector.rs.template" "$connectors_dir/$NAME_SNAKE.rs"

    # Create connector subdirectory and transformers file
    mkdir -p "$connector_subdir"
    substitute_template "$TEMPLATE_DIR/transformers.rs.template" "$connector_subdir/transformers.rs"

    print_success "Created connector files"
}

# Update protobuf enum
update_protobuf() {
    local proto_file="backend/grpc-api-types/proto/payment.proto"
    
    # Find the Connector enum and add new entry before the closing brace
    sed -i.bak "/enum Connector {/,/}/ s/}/  $NAME_UPPER = $ENUM_ORDINAL;\n}/" "$proto_file"
    rm "$proto_file.bak" 2>/dev/null || true
}

# Update domain types
update_domain_types() {
    local domain_file="backend/domain_types/src/connector_types.rs"
    
    # Add to ConnectorEnum
    sed -i.bak "/pub enum ConnectorEnum {/,/}/ s/}/    $NAME_PASCAL,\n}/" "$domain_file"
    
    # Add to gRPC mapping
    sed -i.bak "s/grpc_api_types::payments::Connector::Mifinity => Ok(Self::Mifinity),/grpc_api_types::payments::Connector::Mifinity => Ok(Self::Mifinity),\n            grpc_api_types::payments::Connector::$NAME_PASCAL => Ok(Self::$NAME_PASCAL),/" "$domain_file"
    
    rm "$domain_file.bak" 2>/dev/null || true
}

# Update connectors module
update_connectors_module() {
    local connectors_file="backend/connector-integration/src/connectors.rs"
    
    # Add module declaration and use statement at the end of the file
    cat >> "$connectors_file" << EOF

pub mod $NAME_SNAKE;
pub use self::${NAME_SNAKE}::${NAME_PASCAL};
EOF
}

# Update types mapping
update_types() {
    local types_file="backend/connector-integration/src/types.rs"
    
    # Add the new connector import after the pragma
    sed -i.bak "/\/\/ NEW_CONNECTORS_IMPORT_BELOW/a\\
    $NAME_PASCAL," "$types_file"
    
    # Add the new connector enum mapping after the pragma
    sed -i.bak "/\/\/ NEW_CONNECTORS_ENUM_BELOW/a\\
            ConnectorEnum::$NAME_PASCAL => Box::new($NAME_PASCAL::new())," "$types_file"
    
    rm "$types_file.bak" 2>/dev/null || true
}

# Update config
update_config() {
    local config_file="config/development.toml"
    
    if [ -f "$config_file" ]; then
        # Add a pragma comment if it doesn't exist, then add connector config after it
        if ! grep -q "# NEW_CONNECTORS_BELOW" "$config_file"; then
            sed -i.bak "/^\[connectors\]/a\\
# NEW_CONNECTORS_BELOW\\
" "$config_file"
            rm "$config_file.bak" 2>/dev/null || true
        fi
        
        # Add the new connector config after the pragma with proper newline
        sed -i.bak "/# NEW_CONNECTORS_BELOW/a\\
$NAME_SNAKE.base_url = \"$BASE_URL\"\\
" "$config_file"
        rm "$config_file.bak" 2>/dev/null || true
    fi
}

# Format code
format_code() {
    print_status "Formatting code..."

    if command -v cargo >/dev/null 2>&1; then
        if cargo +nightly fmt --all >/dev/null 2>&1; then
            print_success "Code formatted successfully"
        elif cargo fmt --all >/dev/null 2>&1; then
            print_success "Code formatted successfully (stable)"
        else
            print_warning "Code formatting failed"
        fi
    else
        print_warning "Cargo not found - skipping code formatting"
    fi
}

# Validate compilation
validate_compilation() {
    print_status "Validating compilation..."

    if command -v cargo >/dev/null 2>&1; then
        echo ""
        print_status "Running cargo check..."
        echo ""
        
        # Run cargo check and capture both stdout and stderr
        if cargo check 2>&1; then
            echo ""
            print_success "Compilation validation passed"
        else
            echo ""
            print_error "Compilation validation failed"
            return 1
        fi
    else
        print_warning "Cargo not found - skipping compilation validation"
    fi
}

# Cleanup backup
cleanup_backup() {
    if [ -d "$BACKUP_DIR" ]; then
        rm -rf "$BACKUP_DIR"
        print_success "Cleaned up backup files"
    fi
}

# Emergency rollback
emergency_rollback() {
    if [ -d "$BACKUP_DIR" ]; then
        print_status "Performing emergency rollback..."
        
        # Remove created files
        rm -f "backend/connector-integration/src/connectors/$NAME_SNAKE.rs"
        rm -rf "backend/connector-integration/src/connectors/$NAME_SNAKE"
        
        # Restore backed up files
        for backup_file in "$BACKUP_DIR"/*; do
            if [ -f "$backup_file" ]; then
                local filename=$(basename "$backup_file")
                case "$filename" in
                    "payment.proto")
                        cp "$backup_file" "backend/grpc-api-types/proto/payment.proto"
                        ;;
                    "connector_types.rs")
                        cp "$backup_file" "backend/domain_types/src/connector_types.rs"
                        ;;
                    "connectors.rs")
                        cp "$backup_file" "backend/connector-integration/src/connectors.rs"
                        ;;
                    "types.rs")
                        cp "$backup_file" "backend/connector-integration/src/types.rs"
                        ;;
                    "development.toml")
                        cp "$backup_file" "config/development.toml"
                        ;;
                esac
            fi
        done
        
        rm -rf "$BACKUP_DIR"
        print_success "Emergency rollback completed"
    fi
}

# Show next steps
show_next_steps() {
    echo ""
    print_success "Connector '$NAME_SNAKE' successfully created!"
    echo ""
    print_status "Next Steps:"
    echo "============"
    echo ""
    echo "1️⃣  Implement Core Logic:"
    echo "   📁 Edit: backend/connector-integration/src/connectors/$NAME_SNAKE/transformers.rs"
    echo "      • Update request/response structures for your API"
    echo "      • Implement proper field mappings"
    echo "      • Handle authentication requirements"
    echo ""
    echo "2️⃣  Customize Connector:"
    echo "   📁 Edit: backend/connector-integration/src/connectors/$NAME_SNAKE.rs"
    echo "      • Update URL patterns and endpoints"
    echo "      • Implement error handling"
    echo "      • Add any connector-specific logic"
    echo ""
    echo "3️⃣  Validation Commands:"
    echo "   📋 Check compilation: cargo check --package connector-integration"
    echo "   📋 Run tests: cargo test --package connector-integration"
    echo "   📋 Build: cargo build --package connector-integration"
    echo ""
    print_success "Connector '$NAME_PASCAL' is ready for implementation!"
}

# Main execution
main() {
    echo "🔧 Hyperswitch Connector Setup"
    echo "==============================="
    echo ""

    # Parse arguments and validate
    parse_args "$@"
    validate_environment
    validate_inputs
    check_conflicts
    get_next_ordinal

    # Show plan and get confirmation
    show_plan

    # Create backup for safety
    create_backup

    # Set up error handling
    trap 'emergency_rollback; exit 1' ERR

    # Create connector files and update registration
    create_connector_files
    update_protobuf
    update_domain_types
    update_connectors_module
    update_types
    update_config

    # Format and validate
    format_code
    if ! validate_compilation; then
        emergency_rollback
        exit 1
    fi

    # Clean up and show next steps
    cleanup_backup
    show_next_steps
}

# Run main function with all arguments
main "$@"