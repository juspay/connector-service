# Changelog

## [2024-01-XX] - Billdesk Connector Addition

### Added
- New Billdesk connector implementation for UCS v2
- Payment methods supported: UPI (Unified Payments Interface)
- Transaction flows: Authorize, PSync (Payment Sync)
- Full integration with Billdesk payment gateway API
- Support for UPI Intent/Collect payment flows
- Webhook handling for payment status updates
- Comprehensive error handling and status mapping

### Files Created/Modified
- `src/connectors/billdesk.rs` - Main connector implementation using UCS v2 macro framework
- `src/connectors/billdesk/transformers.rs` - Request/response transformers for Billdesk API
- `src/connectors/billdesk/constants.rs` - API constants, endpoints, and error codes
- `src/connectors/billdesk/api.rs` - API data structures and request/response models
- `src/connectors.rs` - Added Billdesk connector registration
- `src/types.rs` - Added Billdesk to connector conversion logic
- `backend/domain_types/src/connector_types.rs` - Added Billdesk to ConnectorEnum
- `backend/domain_types/src/types.rs` - Added Billdesk configuration parameters

### Technical Details
- Migrated from Hyperswitch/Euler Haskell implementation to UCS v2 Rust
- Uses UCS v2 macro framework for all trait implementations (no manual implementations)
- Implements proper error handling with comprehensive status mapping
- Full type safety with guard rails using domain types
- Amount framework implementation using StringMinorUnit converter
- Dynamic extraction of all request values from router data (no hardcoded values)
- Support for test and production environments
- Authentication using Basic Auth with merchant credentials
- IP address and user agent tracking for security
- UPI-specific payment flow handling with redirect forms

### API Integration
- Base URLs: UAT (https://uat.billdesk.com) and Production (https://www.billdesk.com)
- Request IDs: BDRDF011 (UPI Initiate), BDRDF002 (Authorization), BDRDF003 (Refund)
- Endpoints: PGIDirectRequest with different request IDs for various operations
- Authentication: Basic Auth using merchant_id and checksum_key
- Response handling: Support for both success and error responses
- Status mapping: Billdesk status codes to UCS AttemptStatus enum

### Security Features
- Webhook source verification (stub implementation)
- Request/response integrity validation
- Sensitive data masking using Secret<> wrapper
- IP address and user agent tracking
- Checksum validation for API requests

### Future Enhancements
- Complete webhook verification implementation
- Additional payment method support (Net Banking, Cards, Wallets)
- Refund flow implementation
- Mandate setup and recurring payment support
- Enhanced error handling and retry mechanisms
- Performance monitoring and metrics

### Dependencies
- Added `chrono` for timestamp handling
- Uses existing `base64` encoding through BASE64_ENGINE
- Compatible with existing UCS v2 framework and domain types