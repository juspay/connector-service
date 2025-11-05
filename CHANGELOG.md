# Changelog

## [2025-01-08] - Billdesk Connector Enhancement

### Enhanced
- Improved UPI payment flow with VPA extraction from payment method data
- Enhanced status mapping based on Haskell implementation (0300, 0399, 0396, 0398, etc.)
- Better error handling with comprehensive error status codes
- Enhanced authentication support for multiple auth types (SignatureKey, MultiAuthKey, HeaderKey, etc.)
- Improved connector metadata in responses with detailed Billdesk-specific fields
- Enhanced constants with comprehensive Billdesk API mappings
- Better webhook processing with proper status transformation

### Technical Improvements
- Fixed PaymentMethodData access patterns for UPI data extraction
- Enhanced request message formatting with UPI VPA support
- Improved response handling with detailed connector metadata
- Better error reporting and status code mapping
- Enhanced authentication header generation for multiple auth types
- Comprehensive constant definitions for all Billdesk operations

### Files Modified
- `backend/connector-integration/src/connectors/billdesk/transformers.rs` - Enhanced UPI handling and status mapping
- `backend/connector-integration/src/connectors/billdesk.rs` - Improved authentication handling
- `backend/connector-integration/src/connectors/billdesk/constants.rs` - Comprehensive API constants

### API Enhancements
- Support for UPI Collect with VPA extraction
- Enhanced status code mapping (0300/0399=Success, 0396=Pending, 0398=Failure)
- Support for additional request IDs (BDRDF005, BDRDF006, BDRDF007, BDRDF008)
- Comprehensive error status handling (000=Success, 001=Failure, 002=Pending)
- Enhanced currency support (INR, USD, EUR, GBP)
- Support for mandate operations and recurring payments

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