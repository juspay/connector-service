# Changelog

## [2024-01-XX] - EaseBuzz Connector Addition

### Added
- New EaseBuzz connector implementation for UCS v2
- Payment methods supported: UPI, UPI Intent, UPI Collect
- Transaction flows: Authorize, Payment Sync (PSync), Refund Sync (RSync)
- Complete authentication and hash generation support
- Comprehensive error handling and status mapping
- Full type safety with guard rails and proper domain types

### Files Created/Modified
- `backend/connector-integration/src/connectors/easebuzz.rs` - Main connector implementation using UCS v2 macro framework
- `backend/connector-integration/src/connectors/easebuzz/transformers.rs` - Request/response transformers with proper type conversions
- `backend/connector-integration/src/connectors/easebuzz/constants.rs` - API constants and endpoints
- `backend/connector-integration/src/connectors/easebuzz/test.rs` - Unit tests for connector functionality
- `backend/connector-integration/src/connectors.rs` - Added connector registration
- `backend/connector-integration/src/types.rs` - Added connector to type system and factory pattern
- `backend/domain_types/src/connector_types.rs` - Added EaseBuzz to ConnectorEnum

### Technical Details
- Migrated from Hyperswitch/Euler Haskell implementation to UCS v2 Rust
- Uses mandatory UCS v2 macro framework for all trait implementations
- Implements proper amount framework using StringMinorUnit converter
- SHA512 hash generation for request authentication
- Form-encoded request body handling
- Dynamic value extraction from router data (no hardcoded values)
- Complete error response parsing and status mapping
- Support for test and production environments
- UPI-specific payment mode handling (Intent vs Collect)

### API Endpoints
- `/payment/initiateLink` - Payment initiation (Authorize flow)
- `/transaction/sync` - Payment status synchronization (PSync flow)
- `/transaction/refund/sync` - Refund status synchronization (RSync flow)

### Authentication
- API Key + Secret authentication pattern
- SHA512 hash generation for request integrity
- Support for multiple auth types (SignatureKey, BodyKey, HeaderKey)

### Features
- UPI Intent and Collect payment methods
- Real-time payment status synchronization
- Refund status tracking
- Comprehensive error handling
- Type-safe request/response transformations
- Production-ready with full test coverage