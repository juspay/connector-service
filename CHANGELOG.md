# Changelog

## [2025-01-08] - Billdesk Connector Addition

### Added
- New Billdesk connector implementation for UCS v2
- Payment methods supported: UPI (Unified Payments Interface)
- Transaction flows: Authorize, PSync (Payment Status Sync)
- Support for UPI payment initiation and status checking
- Merchant authentication using Merchant ID and Checksum Key
- Dynamic test/production environment switching

### Files Created/Modified
- `src/connectors/billdesk.rs` - Main connector implementation using UCS v2 macro framework
- `src/connectors/billdesk/transformers.rs` - Request/response transformers for Billdesk API
- `src/connectors/billdesk/constants.rs` - API constants and endpoints
- `src/connectors.rs` - Added Billdesk connector registration
- `src/types.rs` - Added Billdesk to connector enum and conversion logic
- `backend/domain_types/src/connector_types.rs` - Added Billdesk to ConnectorEnum

### Technical Details
- Migrated from Hyperswitch/Euler Haskell implementation
- Uses UCS v2 macro framework for all trait implementations
- Implements proper error handling and status mapping
- Full type safety with guard rails (Secret<String>, MinorUnit, etc.)
- Supports both UAT and production environments
- Message-based authentication following Billdesk API specifications

### API Integration
- Base URLs: 
  - UAT: https://uat.billdesk.com/pgidsk/PGIDirectRequest
  - Production: https://www.billdesk.com/pgidsk/PGIDirectRequest
- Request IDs: BDRDF002 (Authorize), BDRDF003 (Status Check)
- Supports checksum-based request authentication
- Implements Billdesk's message format for UPI transactions

### Features Implemented
- UPI payment initiation with message payload creation
- Payment status synchronization
- Dynamic amount conversion using UCS v2 amount framework
- IP address and user agent handling
- Error response mapping and handling
- Webhook processing framework (basic implementation)

### Known Limitations
- Only UPI payment method is currently supported
- Card payments, net banking, and wallet payments are not implemented
- Full checksum validation needs to be implemented based on Billdesk specifications
- Some advanced features like recurring payments and mandates are stubbed

### Migration Notes
- Preserved all business logic from original Haskell implementation
- Adapted authentication pattern (Merchant ID + Checksum) similar to PhonePe style
- Maintained API compatibility with Billdesk's message-based format
- Used proper UCS v2 type system and guard rails throughout

### Dependencies
- Added hex encoding support for checksum calculation
- Uses hyperswitch-masking for sensitive data handling
- Integrates with common-utils for amount conversion and error handling