# Changelog

## [2025-01-XX] - Billdesk Connector Addition

### Added
- New Billdesk connector implementation
- Payment methods supported: UPI, UPI Collect
- Transaction flows: Authorize, PSync (Payment Status Sync)
- Authentication pattern: Merchant ID + Checksum (similar to PhonePe)
- Support for test and production environments
- Comprehensive error handling and status mapping

### Files Created/Modified
- `src/connectors/billdesk.rs` - Main connector implementation using UCS v2 macro framework
- `src/connectors/billdesk/transformers.rs` - Request/response transformers for Billdesk API
- `src/connectors/billdesk/constants.rs` - API constants, endpoints, and configuration
- `src/connectors.rs` - Added Billdesk connector registration
- `src/types.rs` - Added Billdesk to connector enum and type mappings
- `backend/domain_types/src/connector_types.rs` - Added Billdesk to ConnectorEnum
- `backend/domain_types/src/types.rs` - Added Billdesk connector parameters

### Technical Details
- Migrated from Hyperswitch/Euler Haskell implementation
- Uses UCS v2 macro framework for all trait implementations (no manual implementations)
- Implements proper error handling and status mapping from original Haskell code
- Full type safety with guard rails (Secret<String> for sensitive data, MinorUnit for amounts)
- Dynamic value extraction from router data (no hardcoded values)
- Amount framework using StringMinorUnit converter
- Checksum generation for request authentication
- Support for UPI payment initiation and status synchronization
- Webhook processing capabilities (stub implementation)

### API Integration
- Base URLs: UAT (https://uat.billdesk.com) and Production (https://www.billdesk.com)
- Request IDs: BDRDF011 (UPI Initiate), BDRDF003 (Status Check)
- Message format: Key-value pairs for transaction data
- Status codes: 0300/0399 (Success), 0396 (Pending), 0397/0398 (Failure)
- Supported currencies: INR (primary), USD, EUR, GBP, AED, SAR

### Implementation Notes
- Follows PhonePe-style authentication pattern with Merchant ID + Checksum
- Implements only UPI and sync flows as specified in requirements
- All request body values extracted dynamically from router data
- Proper amount conversion using UCS v2 amount framework
- Comprehensive stub implementations for unsupported flows
- Source verification stubs for all flows (to be implemented in Phase 10)