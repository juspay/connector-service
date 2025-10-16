# Changelog

## [2025-01-16] - EaseBuzz Connector Addition

### Added
- New EaseBuzz connector implementation for UCS v2
- Payment methods supported: UPI (Intent/Collect)
- Transaction flows: Authorize, PSync, RSync, Refund
- Full webhook support for payment status updates
- Mandate management capabilities (setup, execute, revoke)
- UPI AutoPay functionality
- Refund processing and synchronization
- Comprehensive error handling and status mapping

### Files Created/Modified
- `src/connectors/easebuzz.rs` - Main connector implementation using UCS v2 macro framework
- `src/connectors/easebuzz/transformers.rs` - Request/response transformers for all EaseBuzz APIs
- `src/connectors/easebuzz/constants.rs` - API constants and endpoints
- `src/connectors.rs` - Added EaseBuzz connector registration
- `src/types.rs` - Added EaseBuzz to connector conversion logic
- `backend/domain_types/src/connector_types.rs` - Added EaseBuzz to ConnectorEnum
- `backend/domain_types/src/types.rs` - Added easebuzz field to Connectors struct
- `backend/grpc-api-types/proto/payment.proto` - Added EASEBUZZ to gRPC Connector enum

### Technical Details
- Migrated from Hyperswitch/Euler Haskell implementation to UCS v2 Rust
- Uses UCS v2 macro framework for all trait implementations (no manual code)
- Implements proper error handling with comprehensive status mapping
- Full type safety with guard rails (Secret<String> for sensitive data, MinorUnit for amounts)
- Supports test and production environments with different base URLs
- Hash generation for API authentication using MD5
- Dynamic request body extraction from router data (no hardcoded values)
- Complete webhook verification and processing capabilities

### API Endpoints Supported
- `/payment/initiateLink` - Payment initiation
- `/transaction/status` - Payment status synchronization
- `/transaction/refund` - Refund processing
- `/transaction/refundStatus` - Refund status synchronization
- UPI AutoPay endpoints for mandate management
- Notification endpoints for mandate status updates

### Payment Methods
- UPI Intent
- UPI Collect
- UPI AutoPay (recurring payments)

### Security Features
- API key authentication with Bearer token
- Request hash generation for integrity verification
- Webhook signature validation
- Sensitive data masking with Secret<> wrapper
- Proper error message sanitization

### Integration Notes
- Connector uses StringMinorUnit amount converter for API compatibility
- All request values are dynamically extracted from router data
- Supports both test and production environments
- Comprehensive error mapping from connector responses to standard errors
- Full compliance with UCS v2 patterns and best practices