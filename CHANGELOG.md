# Changelog

## [2025-01-12] - EaseBuzz Connector Addition

### Added
- New EaseBuzz connector implementation
- Payment methods supported: UPI (Intent and Collect)
- Transaction flows: Authorize (UPI payments), PSync (payment status sync)
- UPI Intent flow for QR code-based payments
- UPI Collect flow for VPA-based payments
- Comprehensive webhook support for payment status updates
- Hash-based authentication using SHA-512 algorithm
- Support for both test and production environments

### Files Created/Modified
- `backend/connector-integration/src/connectors/easebuzz.rs` - Main connector implementation using UCS v2 macro framework
- `backend/connector-integration/src/connectors/easebuzz/transformers.rs` - Request/response transformers with proper type safety
- `backend/connector-integration/src/connectors/easebuzz/constants.rs` - API constants and endpoints
- `backend/connector-integration/src/connectors.rs` - Added EaseBuzz connector registration
- `backend/connector-integration/src/types.rs` - Added EaseBuzz to ConnectorEnum

### Technical Details
- Migrated from Hyperswitch/Euler Haskell implementation
- Uses UCS v2 macro framework (`create_all_prerequisites!` and `macro_connector_implementation!`)
- Implements proper error handling and status mapping
- Full type safety with guard rails:
  - `Secret<String>` for sensitive data (API keys, salts, hashes)
  - `StringMinorUnit` for amount conversion
  - `Email` type for email validation
  - Proper currency and country code handling
- Hash generation using SHA-512 for request authentication
- Support for sub-merchant functionality
- Comprehensive webhook verification and processing
- Form-based redirect handling for UPI payments
- Real-time payment status synchronization

### Security Features
- Secure hash generation for all API requests
- Webhook signature verification
- Sensitive data masking using `Secret<>` wrapper
- Proper authentication header handling

### API Endpoints Supported
- `/initiate_seamless_payment/` - UPI payment initiation
- `/transaction/v1/retrieve` - Payment status synchronization
- Webhook endpoints for real-time status updates

### Payment Flow Support
- **UPI Intent**: QR code generation for mobile app payments
- **UPI Collect**: Direct VPA-based payment collection
- **Payment Sync**: Real-time status checking and updates
- **Webhook Processing**: Automatic status updates via webhooks

### Error Handling
- Comprehensive error response parsing
- Proper status code mapping
- Detailed error messages and codes
- Network error handling and retry logic

### Testing Support
- Full test environment support with separate endpoints
- Test mode configuration handling
- Debug-friendly error messages and logging