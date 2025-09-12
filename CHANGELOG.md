# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Billdesk Connector**: Added new payment connector for Billdesk payment gateway
  - Supports UPI payment flows (UpiCollect and UpiIntent)
  - Implements UCS v2 macro framework with proper type safety
  - Includes payment authorization and synchronization flows
  - Features Billdesk-specific message format handling and checksum calculation
  - Provides comprehensive error handling and status mapping
  - Registered as connector ID 94 in the system

### Technical Details
- **Files Added**:
  - `backend/connector-integration/src/connectors/billdesk.rs` - Main connector implementation
  - `backend/connector-integration/src/connectors/billdesk/transformers.rs` - Request/response transformers
  - `backend/connector-integration/src/connectors/billdesk/constants.rs` - API endpoints and constants

- **Files Modified**:
  - `backend/connector-integration/src/connectors.rs` - Added billdesk module export
  - `backend/connector-integration/src/types.rs` - Added Billdesk to connector imports
  - `backend/domain_types/src/connector_types.rs` - Added Billdesk to ConnectorEnum
  - `backend/grpc-api-types/proto/payment.proto` - Added BILLDESK = 94 to Connector enum
  - `backend/domain_types/src/types.rs` - Added billdesk field to Connectors struct

### Implementation Features
- **UCS v2 Compliance**: Uses mandatory `create_all_prerequisites!` and `macro_connector_implementation!` macros
- **Type Safety**: Implements Secret<String> for sensitive data and proper domain types
- **Amount Framework**: Uses StringMinorUnit converter for API compatibility
- **UPI Focus**: Specifically implements UPI payment flows as requested
- **Error Handling**: Comprehensive error response structure with network codes

### Migration Notes
- Migrated from euler-api-txns (Haskell) to UCS v2 (Rust)
- Preserves all UPI-specific business logic from original implementation
- Maintains Billdesk API message format and security requirements
- Follows UCS v2 guard rails and type safety patterns

### Known Limitations
- Currently implements UPI Authorize and PSync flows only
- Framework requires comprehensive flow implementations for full integration
- Additional flows (Capture, Refund, etc.) may need stub implementations for complete compilation

### Security
- Sensitive authentication data properly masked using Secret<String>
- Checksum validation implemented for API security
- Proper error handling prevents information leakage