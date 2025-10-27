# Changelog

## [2025-01-08] - EaseBuzz Connector Addition

### Added
- New EaseBuzz connector implementation for UPI and payment sync flows
- Payment methods supported: UPI, UPI Collect, UPI Intent
- Transaction flows: Authorize, PSync
- Full webhook support structure (implementation pending)
- Comprehensive error handling and status mapping

### Files Created/Modified
- `src/connectors/easebuzz.rs` - Main connector implementation using UCS v2 macro framework
- `src/connectors/easebuzz/transformers.rs` - Request/response transformers for EaseBuzz API
- `src/connectors/easebuzz/constants.rs` - API constants and endpoints
- `src/connectors.rs` - Added EaseBuzz connector registration
- `src/types.rs` - Added EaseBuzz to connector conversion and imports
- `backend/domain_types/src/connector_types.rs` - Added EaseBuzz to ConnectorEnum
- `backend/domain_types/src/types.rs` - Added EaseBuzzConnectorParams struct

### Technical Details
- Migrated from Hyperswitch/Euler Haskell implementation
- Uses UCS v2 macro framework for all trait implementations
- Implements proper error handling and status mapping
- Full type safety with guard rails (Secret<String>, MinorUnit, Email types)
- Dynamic extraction of all request values from router data (no hardcoded values)
- Authentication using API key and hash-based signature
- Support for test and production environments
- UPI-specific payment flows with VPA handling
- Comprehensive stub implementations for unsupported flows

### API Endpoints
- `/payment/initiateLink` - Payment initiation
- `/payment/txnSync` - Transaction status sync
- Support for both test (`https://testpay.easebuzz.in`) and production (`https://pay.easebuzz.in`) environments

### Payment Method Support
- UPI Intent payments
- UPI Collect payments  
- UPI QR code generation
- Virtual Payment Address (VPA) handling

### Security Features
- API key authentication with Base64 encoding
- Hash-based request signing
- Secret type wrapping for sensitive data
- IP address and user agent tracking
- Webhook signature verification structure

### Known Limitations
- Webhook processing implementation pending
- Refund flows stubbed (not implemented)
- Card payment flows not supported (UPI only as per requirements)
- Mandate flows stubbed (not implemented)