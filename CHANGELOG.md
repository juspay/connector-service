# Changelog

## [2024-01-15] - EaseBuzz Connector Addition

### Added
- New EaseBuzz connector implementation for UPI payments
- Payment methods supported: UPI, UPI Collect, UPI Intent
- Transaction flows: Authorize, PSync, Refund, RSync
- Complete UPI payment processing with Intent and Collect modes
- Refund processing and synchronization
- Transaction status synchronization
- Proper error handling and status mapping

### Files Created/Modified
- `backend/connector-integration/src/connectors/easebuzz.rs` - Main connector implementation using UCS v2 macro framework
- `backend/connector-integration/src/connectors/easebuzz/transformers.rs` - Request/response transformers for all flows
- `backend/connector-integration/src/connectors/easebuzz/constants.rs` - API constants, endpoints, and status mappings
- `backend/connector-integration/src/connectors.rs` - Already included EaseBuzz module registration
- `backend/domain_types/src/connector_types.rs` - Already included EaseBuzz in ConnectorEnum

### Technical Details
- Migrated from Hyperswitch/Euler Haskell implementation to UCS v2 Rust
- Uses mandatory UCS v2 macro framework for all trait implementations
- Implements proper amount framework using StringMinorUnit converter
- Full type safety with guard rails (Secret<String> for sensitive data, MinorUnit for amounts)
- Dynamic value extraction from router data (no hardcoded values)
- Comprehensive error handling with proper status code mapping
- UPI-specific business logic preserved from original implementation
- Hash generation for request authentication
- Support for both test and production environments

### API Endpoints Implemented
- `/payment/initiateLink` - Payment initiation
- `/payment/transactionStatus` - Transaction synchronization
- `/transaction/refund` - Refund processing
- `/transaction/refundStatus` - Refund synchronization

### Payment Method Support
- UPI Intent payments
- UPI Collect payments
- UPI QR code payments
- Proper payment method type detection and routing

### Security Features
- SHA512 hash generation for request authentication
- Secret handling for API keys and sensitive data
- Proper error message masking
- IP address and browser information handling

### Compliance
- Follows UCS v2 connector standards
- Implements all mandatory guard rails
- Proper amount handling with minor unit conversion
- Type-safe payment method data handling