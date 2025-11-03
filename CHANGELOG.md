# Changelog

## [2024-01-15] - EaseBuzz Connector Addition

### Added
- New EaseBuzz connector implementation
- Payment methods supported: UPI (UPI Intent/Collect)
- Transaction flows: Authorize, PSync, RSync

### Files Created/Modified
- `backend/connector-integration/src/connectors/easebuzz.rs` - Main connector implementation
- `backend/connector-integration/src/connectors/easebuzz/transformers.rs` - Request/response transformers
- `backend/connector-integration/src/connectors/easebuzz/constants.rs` - API constants and endpoints
- `backend/connector-integration/src/connectors/easebuzz/test.rs` - Unit tests
- `backend/connector-integration/src/connectors.rs` - Added connector registration
- `backend/domain_types/src/connector_types.rs` - Added EaseBuzz to ConnectorEnum
- `backend/connector-integration/src/types.rs` - Added EaseBuzz to connector factory

### Technical Details
- Migrated from Hyperswitch/Euler Haskell implementation
- Uses UCS v2 macro framework for trait implementations
- Implements proper error handling and status mapping
- Full type safety with guard rails
- Supports UPI payment flows with hash-based authentication
- Implements proper amount framework using StringMinorUnit converter
- Dynamic extraction of all request values from router data (no hardcoded values)
- Comprehensive webhook support for payment status updates

### API Endpoints Supported
- `/payment/initiateLink` - Payment initiation
- `/pay/initiate` - UPI seamless transaction
- `/transaction/status` - Payment synchronization
- `/transaction/refundStatus` - Refund synchronization

### Authentication
- API Key + Secret based authentication
- SHA512 hash generation for request integrity
- Support for both test and production environments

### Features
- UPI Intent and Collect payment methods
- Real-time payment status synchronization
- Refund status tracking
- Comprehensive error handling
- Type-safe request/response transformations
- Webhook event processing