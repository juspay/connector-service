# Changelog

## [2025-01-08] - Billdesk Connector Addition

### Added
- New Billdesk connector implementation for UCS v2
- Payment methods supported: UPI Collect
- Transaction flows: Authorize, PSync
- Webhook processing support
- Complete type safety with guard rails
- Error handling and status mapping
- UCS v2 macro framework compliance
- Proper amount framework implementation using StringMinorUnit
- Dynamic request body value extraction from router data

### Files Created/Modified
- `backend/connector-integration/src/connectors/billdesk.rs` - Main connector implementation
- `backend/connector-integration/src/connectors/billdesk/transformers.rs` - Request/response transformers
- `backend/connector-integration/src/connectors/billdesk/constants.rs` - API constants and endpoints
- `backend/connector-integration/src/connectors.rs` - Added connector registration
- `backend/connector-integration/src/types.rs` - Added connector to ConnectorEnum and type mapping
- `backend/domain_types/src/connector_types.rs` - Added Billdesk to ConnectorEnum

### Technical Details
- Migrated from Hyperswitch/Euler Haskell implementation
- Uses UCS v2 macro framework for trait implementations
- Implements proper error handling and status mapping
- Full type safety with guard rails (Secret<String>, MinorUnit, Email, etc.)
- Supports UPI payment initiation and status synchronization
- Authentication using Bearer token pattern
- Comprehensive stub implementations for all required flows
- `backend/grpc-api-types/proto/payment.proto` - Added Billdesk to gRPC enum

### Technical Details
- Migrated from Hyperswitch/Euler Haskell implementation
- Uses UCS v2 macro framework for trait implementations
- Implements proper error handling and status mapping
- Full type safety with guard rails (Secret<String>, MinorUnit, etc.)
- Supports test and production environments
- UPI payment flow with redirect handling
- Status synchronization with proper status code mapping
- Webhook verification and processing

### API Endpoints
- UAT: https://uat.billdesk.com/pgidsk/PGIDirectRequest
- Production: https://www.billdesk.com/pgidsk/PGIDirectRequest
- Request IDs: BDRDF011 (UPI Initiate), BDRDF002 (Authorization), BDRDF003 (Status)

### Authentication
- Uses SignatureKey authentication with Bearer token
- Merchant ID extracted from API key
- Checksum validation for transaction integrity

### Features
- UPI Collect payment initiation
- Payment status synchronization
- Webhook processing
- Error handling with proper status mapping
- Test mode support
- Type-safe request/response handling