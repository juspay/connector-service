# Changelog

## [2024-01-XX] - EaseBuzz Connector Addition

### Added
- New EaseBuzz connector implementation for UCS v2
- Payment methods supported: UPI Intent, UPI Collect
- Transaction flows: Authorize, PSync, Refund, RSync
- Webhook support for payment and refund events
- Full integration with UCS v2 macro framework

### Files Created/Modified
- `backend/connector-integration/src/connectors/easebuzz.rs` - Main connector implementation (updated existing)
- `backend/connector-integration/src/connectors/easebuzz/transformers.rs` - Request/response transformers (updated existing)
- `backend/connector-integration/src/connectors/easebuzz/constants.rs` - API constants and endpoints (new)
- `backend/connector-integration/src/connectors.rs` - Added connector registration
- `backend/connector-integration/src/types.rs` - Added connector to type system
- `backend/domain_types/src/connector_types.rs` - Added EaseBuzz to ConnectorEnum
- `backend/grpc-api-types/proto/payment.proto` - Added EaseBuzz to protobuf enum

### Technical Details
- Migrated from Hyperswitch/Euler Haskell implementation
- Uses UCS v2 macro framework for all trait implementations
- Implements proper error handling and status mapping
- Full type safety with guard rails (Secret<String>, MinorUnit, etc.)
- UPI-only payment method support as specified
- Dynamic request body value extraction from router data
- Proper amount framework implementation using StringMinorUnit
- Hash generation for API authentication
- Form data encoding for API requests

### API Endpoints
- Payment Initiate: `/payment/initiateLink`
- Transaction Sync: `/transaction/v1/retrieve`
- Refund: `/transaction/v1/refund`
- Refund Sync: `/transaction/v1/refundStatus`

### Features
- UPI Intent and Collect payment flows
- Real-time payment synchronization
- Refund processing and synchronization
- Webhook event handling
- Test and production environment support
- Comprehensive error handling
- SHA512 hash-based authentication

### Security
- All sensitive data wrapped in Secret<String>
- Proper hash generation for API requests
- Input validation for all parameters
- Type-safe payment amount handling