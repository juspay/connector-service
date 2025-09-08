# Add Connector Script for Connector-Service

This document explains how to use the `add_connector.sh` script to generate fresh boilerplate code for new payment connectors in the connector-service architecture.

## Overview

The `add_connector.sh` script automates the process of adding new connectors to connector-service by:

1. **Generating Fresh Boilerplate Code** - Creates connector and transformer files from scratch
2. **Following Architecture Patterns** - Uses RouterDataV2, generic types, and macro systems
3. **Maintaining Alphabetical Order** - Automatically places connectors in correct positions
4. **Validating Implementation** - Ensures generated code compiles successfully

## Usage

```bash
./add_connector.sh <connector_name> <base_url>
```

### Arguments

- `connector_name`: Name in snake_case (e.g., `stripe`, `paypal_pro`, `square_sandbox`)
- `base_url`: API base URL (e.g., `https://api.stripe.com`)

### Examples

```bash
# Add Stripe connector
./add_connector.sh stripe https://api.stripe.com

# Add PayPal Pro connector  
./add_connector.sh paypal_pro https://api.paypal.com

# Add Square Sandbox connector
./add_connector.sh square_sandbox https://connect.squareupsandbox.com
```

## Generated Files

The script creates the following files:

### Main Connector File
`backend/connector-integration/src/connectors/{connector_name}.rs`

Contains:
- RouterDataV2-based implementation
- Generic type parameter support (`<T: PaymentMethodDataTypes>`)
- ConnectorIntegrationV2 trait implementations
- Macro-based flow definitions
- Stub implementations for all flows

### Transformer File
`backend/connector-integration/src/connectors/{connector_name}/transformers.rs`

Contains:
- Request/response struct definitions
- Generic type support for payment methods
- RouterDataV2 conversion implementations
- Auth type definitions
- Error response structures

## Modified Files

The script automatically updates these configuration files:

1. `backend/domain_types/src/connector_types.rs` - Adds ConnectorEnum variant
2. `backend/domain_types/src/types.rs` - Adds Connectors struct field
3. `backend/connector-integration/src/types.rs` - Updates use statements and convert_connector
4. `backend/connector-integration/src/connectors.rs` - Adds module exports
5. `config/development.toml` - Adds base URL configuration

## Key Features

### Architecture Compliance
- **RouterDataV2 Integration**: All code uses `RouterDataV2<F, FCD, Req, Res>` pattern
- **Generic Type Support**: Proper `PaymentMethodDataTypes` constraints
- **Macro System**: Uses `macros::create_all_prerequisites!` for setup

### Error Handling
- Input validation (snake_case format, URL validation)
- File backup creation before modifications
- Compilation validation
- Rollback capability on errors

### Alphabetical Ordering
- Automatically determines correct placement
- Maintains consistent ordering across all files

## Generated Code Structure

### Main Connector Implementation

```rust
// Trait implementations with generic type parameters
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ConnectorServiceTrait<T> for ConnectorName<T> {}

// Macro-based flow implementations
macros::create_all_prerequisites!(
    connector_name: ConnectorName,
    generic_type: T,
    api: [
        (flow: Authorize, request_body: ConnectorNamePaymentsRequest<T>, ...),
        // ... other flows
    ],
    // ...
);
```

### Transformer Implementation

```rust
// Generic request structures
#[derive(Debug, Serialize)]
pub struct ConnectorNamePaymentsRequest<T: PaymentMethodDataTypes + ...> {
    // Generic request structure
}

// RouterDataV2 conversion implementations
impl<T: PaymentMethodDataTypes + ...> 
    TryFrom<ConnectorNameRouterData<RouterDataV2<...>, T>>
    for ConnectorNamePaymentsRequest<T> {
    // Conversion implementation
}
```

## Next Steps After Generation

1. **Implement Connector Logic**: Add specific API integration code
2. **Update Endpoints**: Configure actual API endpoints and paths
3. **Handle Responses**: Implement proper status and error mappings
4. **Add Testing**: Create test cases for the connector
5. **Configure Auth**: Add proper authentication mechanisms

## Troubleshooting

### Common Issues

1. **Compilation Errors**: Check that all dependencies are available
2. **Duplicate Connector**: Ensure connector doesn't already exist
3. **Invalid Name Format**: Use snake_case only (lowercase, numbers, underscores)
4. **URL Format**: Ensure base URL starts with http:// or https://

### Backup and Recovery

- Backups are created in `.connector_backups/` directory
- Files are timestamped for easy identification
- Manual restoration may be needed if script fails

### Getting Help

```bash
./add_connector.sh --help
```

## Architecture Notes

This script generates fresh boilerplate specifically for connector-service architecture, not copied from Hyperswitch. The generated code follows connector-service patterns including:

- RouterDataV2 usage throughout
- Generic type parameter support
- Macro-based flow implementations
- Proper error handling patterns
- Resource common data access patterns

The generated connector will be ready for custom implementation while maintaining consistency with the connector-service architecture.