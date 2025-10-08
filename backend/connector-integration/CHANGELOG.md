# Changelog

## [2024-12-19] - PhonePe Connector Migration

### Added
- New PhonePe connector implementation migrated from Haskell euler-api-txns to UCS v2 (Rust)
- Payment methods supported: UPI Intent, UPI Collect
- Transaction flows: Authorize, PSync (Payment Status Sync)
- Complete UPI payment integration with PhonePe v3 API
- Proper checksum generation and X-VERIFY header authentication
- Device context detection for UPI Intent flows
- Error handling and status mapping for PhonePe-specific response codes
- Support for both sandbox and production environments

### Files Created/Modified
- `src/connectors/phonepe.rs` - Main connector implementation using UCS v2 macro framework
- `src/connectors/phonepe/transformers.rs` - Request/response transformers with proper type safety
- `src/connectors/phonepe/constants.rs` - API constants and endpoints
- `src/connectors/phonepe/headers.rs` - Header constants for PhonePe integration
- `src/connectors.rs` - PhonePe connector already registered

### Technical Details
- **Migrated from**: Hyperswitch/Euler Haskell implementation
- **Framework**: Uses UCS v2 macro framework for all trait implementations
- **Amount Handling**: Proper amount framework using StringMinorUnit converter
- **Type Safety**: Complete guard rails with Secret<String>, MinorUnit, Email types
- **Authentication**: PhonePe checksum algorithm with SHA256 + key index
- **API Integration**: PhonePe v3 debit and status endpoints
- **Error Mapping**: Comprehensive PhonePe error code to AttemptStatus mapping
- **Payment Methods**: UPI Intent (with device context), UPI Collect (with VPA)
- **Dynamic Data Extraction**: All request values extracted from router data (no hardcoded values)

### Key Features Implemented
- **Authorize Flow**: UPI payment initiation with proper device context detection
- **PSync Flow**: Payment status synchronization with comprehensive response handling
- **Checksum Generation**: PhonePe-specific SHA256 checksum with salt key and key index
- **Header Management**: X-VERIFY and X-MERCHANT-ID headers for authentication
- **Response Handling**: Unified response parsing for success/error scenarios
- **Status Mapping**: PhonePe response codes to proper AttemptStatus enum values
- **Type Safety**: Proper use of domain types (MinorUnit, Secret<String>, Email, etc.)

### API Endpoints
- **Production**: https://mercury-t2.phonepe.com
- **Sandbox**: https://mercury-uat.phonepe.com
- **Debit**: /v3/debit
- **Status**: /v3/transaction/:mid/:tid/status

### Migration Notes
- Preserved all business logic from original Haskell implementation
- Enhanced with proper Rust type safety and error handling
- Uses UCS v2 macro framework for maintainable and consistent code
- Implements only UPI flows as specified (Authorize and PSync)
- All other flows have stub implementations returning NotImplemented errors
- Dynamic value extraction ensures no hardcoded sensitive data