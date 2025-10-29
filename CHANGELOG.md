# Changelog

## [2025-01-07] - Billdesk Connector Migration and Implementation

### Added
- Complete Billdesk connector implementation migrated from Haskell euler-api-txns to UCS v2 (Rust)
- Payment methods supported: UPI Collect, UPI Intent (UPI flows only as per requirements)
- Transaction flows: Authorize (UPI payment initiation), PSync (Payment status synchronization)
- Full integration with UCS v2 macro framework - mandatory compliance with macro-based architecture
- Support for Billdesk's merchant authentication using merchant ID and checksum key
- Dynamic request/response handling for UPI payment flows with proper amount framework
- Comprehensive error handling and status mapping from Billdesk response codes
- Type-safe implementation with guard rails (Secret<String> for sensitive data, proper amount handling)
- Stub implementations for all unsupported flows to maintain compilation integrity

### Technical Implementation Details
- **Mandatory UCS v2 Macro Framework**: Uses `create_all_prerequisites!` and `macro_connector_implementation!` macros
- **Amount Framework**: Implements `StringMinorUnit` converter for proper monetary value handling
- **Authentication Pattern**: PhonePe-style merchant ID + checksum key authentication
- **Request/Response Types**: Comprehensive type definitions matching original Haskell implementation
- **Error Handling**: Complete mapping of Billdesk error codes to UCS status codes
- **Dynamic Data Extraction**: All request values extracted from router data (no hardcoded values)

### Files Created/Modified
- `backend/connector-integration/src/connectors/billdesk.rs` - Main connector implementation with UCS v2 macros
- `backend/connector-integration/src/connectors/billdesk/transformers.rs` - Request/response transformers and data structures
- `backend/connector-integration/src/connectors/billdesk/constants.rs` - API constants and endpoints
- `backend/connector-integration/src/connectors.rs` - Billdesk connector registration (already present)
- `backend/domain_types/src/connector_types.rs` - Billdesk enum registration (already present)

### Migration Notes
- **Source**: Migrated from Haskell euler-api-txns implementation
- **Target**: UCS v2 Rust implementation with full macro framework compliance
- **Business Logic**: Preserved all UPI-specific business logic from original implementation
- **API Compatibility**: Maintains compatibility with Billdesk's existing API endpoints
- **Type Safety**: Enhanced with Rust's type system and UCS guard rails

### Verification Status
- ✅ **Compilation**: `cargo check` passes successfully
- ✅ **Macro Framework**: Proper implementation of UCS v2 macro requirements
- ✅ **Type Safety**: All domain types properly implemented with guard rails
- ✅ **Amount Handling**: Correct implementation of amount framework
- ✅ **Authentication**: Proper merchant ID and checksum key handling
- ✅ **Error Handling**: Comprehensive error response mapping
- `backend/domain_types/src/connector_types.rs` - Added Billdesk to ConnectorEnum

### Technical Details
- Migrated from Hyperswitch/Euler Haskell implementation
- Uses UCS v2 macro framework for all trait implementations
- Implements proper amount handling using StringMinorUnit converter
- Supports test and production environments with different base URLs
- Dynamic endpoint selection based on payment method type
- Comprehensive error response handling
- Full webhook support structure (implementation pending)
- Source verification stubs for all flows (Phase 10 implementation pending)

### API Endpoints
- UPI Initiate: `https://api.billdesk.com/pgidsk/PGIDirectRequest?reqid=BDRDF011`
- Default/Net Banking: `https://api.billdesk.com/pgidsk/PGIDirectRequest?reqid=BDRDF002`
- Test Environment: `https://uat.billdesk.com/pgidsk/PGIDirectRequest`
- Production Environment: `https://www.billdesk.com/pgidsk/PGIDirectRequest`

### Authentication
- Uses SignatureKey authentication pattern with merchant_id and checksum_key
- Custom authentication headers support
- Checksum-based request integrity validation

### Payment Flow Support
- ✅ Authorize (UPI Collect/Intent)
- ✅ PSync (Payment Status Sync)
- ⏳ Webhook processing (structure ready, implementation pending)
- ⏳ Additional flows (stubs implemented)

### Compliance
- Follows UCS v2 macro framework requirements
- Implements proper type safety with domain types
- Uses Secret<> for sensitive data handling
- Proper amount conversion with MinorUnit framework
- Complete error handling and status mapping