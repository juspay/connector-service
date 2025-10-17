# Changelog

## [2024-01-15] - Payu Connector Addition

### Added
- New Payu connector implementation for UCS v2
- Payment methods supported: UPI Collect, UPI Intent
- Transaction flows: Authorize, PaymentSync, RefundSync
- Webhook support with signature verification
- Comprehensive error handling and status mapping
- Test and production environment support

### Files Created/Modified
- `src/connectors/payu.rs` - Main connector implementation with trait implementations
- `src/connectors/payu/transformers.rs` - Request/response transformers and data conversion logic
- `src/connectors/payu/constants.rs` - API constants, endpoints, and status mappings
- `src/connectors.rs` - Added connector registration and exports
- `src/types.rs` - Added connector types and enums for type system integration

### Technical Details
- Migrated from Hyperswitch/Euler Haskell implementation
- Uses UCS v2 macro framework for trait implementations
- Implements proper error handling and status mapping
- Full type safety with guard rails using domain types
- SHA512 hash generation for request authentication
- Form URL encoded request format for Payu API compatibility
- Dynamic extraction of all request data from router data (no hardcoded values)
- Proper amount framework implementation using StringMinorUnit converter

### API Integration
- Base URLs: Production (https://info.payu.in) and Test (https://test.payu.in)
- Authentication: Key-based with SHA512 hash generation
- Request format: Form URL encoded with command-based API structure
- Response handling: Enum-based response parsing for different status types
- Webhook verification: HMAC SHA512 signature validation

### Payment Flow Support
- **Authorize**: UPI payment initiation with VPA validation
- **PaymentSync**: Transaction status verification and updates
- **RefundSync**: Refund status tracking and synchronization
- **Webhooks**: Real-time payment status notifications

### Security Features
- API key and salt-based authentication
- Request hash generation for integrity verification
- Webhook signature validation
- Sensitive data masking using Secret<> wrapper
- IP address and user agent tracking

### Error Handling
- Comprehensive error response parsing
- Status code mapping to attempt statuses
- Error code to description mapping
- Proper error propagation through UCS error framework

### Future Enhancements
- Support for additional payment methods (cards, net banking)
- Capture and void flow implementations
- Mandate setup and recurring payment support
- Enhanced webhook event handling
- Advanced fraud detection integration