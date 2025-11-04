# Changelog

## [2024-01-01] - EaseBuzz Connector Addition

### Added
- New EaseBuzz connector implementation
- Payment methods supported: UPI (UPI Intent, UPI Collect, UPI QR)
- Transaction flows: Authorize, PSync
- Full webhook support for payment status updates
- Comprehensive error handling and status mapping
- Support for test and production environments

### Files Created/Modified
- `src/connectors/easebuzz.rs` - Main connector implementation
- `src/connectors/easebuzz/transformers.rs` - Request/response transformers
- `src/connectors/easebuzz/constants.rs` - API constants and endpoints
- `src/connectors.rs` - Added connector registration
- `src/types.rs` - Added connector to ConnectorEnum and convert_connector function
- `backend/domain_types/src/connector_types.rs` - Added EaseBuzz to ConnectorEnum

### Technical Details
- Migrated from Hyperswitch/Euler Haskell implementation
- Uses UCS v2 macro framework for trait implementations
- Implements proper error handling and status mapping
- Full type safety with guard rails
- UPI-focused implementation with Intent, Collect, and QR code support
- Comprehensive API coverage for payment initiation and synchronization
- Webhook signature verification support
- Test mode support with separate endpoints

### API Endpoints Implemented
- `/payment/initiateLink` - Payment initiation
- `/transaction/v1/retrieve` - Transaction synchronization
- Webhook handling for payment status updates

### Features
- Dynamic amount conversion using StringMinorUnit
- Proper authentication header generation
- UPI payment method validation
- Redirect form generation for UPI flows
- Comprehensive error response handling
- Status mapping between EaseBuzz and internal enums

### Configuration
- Supports both test and production environments
- API key-based authentication
- Configurable timeouts and retry logic
- Webhook signature validation

### Security
- All sensitive data wrapped in Secret<> types
- Proper hash generation for API requests
- Webhook signature verification
- Input validation and sanitization

### Future Enhancements
- Refund flow implementation
- Mandate management support
- EMI plan integration
- Advanced webhook processing
- Additional UPI app support