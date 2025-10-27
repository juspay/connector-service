# Changelog

## [2025-01-08] - Billdesk Connector Addition

### Added
- New Billdesk connector implementation
- Payment methods supported: UPI, UPI Collect
- Transaction flows: Authorize, PSync
- Authentication using merchant ID and checksum key
- Support for test and production environments
- Error handling and status mapping
- Webhook verification framework (stub implementation)

### Files Created/Modified
- `src/connectors/billdesk.rs` - Main connector implementation
- `src/connectors/billdesk/transformers.rs` - Request/response transformers
- `src/connectors/billdesk/constants.rs` - API constants and endpoints
- `src/connectors.rs` - Added connector registration
- `src/types.rs` - Added connector to ConnectorEnum and convert_connector function
- `backend/domain_types/src/connector_types.rs` - Added Billdesk to ConnectorEnum
- `backend/domain_types/src/types.rs` - Added billdesk to Connectors struct

### Technical Details
- Migrated from Hyperswitch/Euler Haskell implementation
- Uses UCS v2 macro framework for trait implementations
- Implements proper error handling and status mapping
- Full type safety with guard rails
- Amount handling using StringMinorUnit converter
- Dynamic extraction of all request data from router data
- No hardcoded values in request/response transformers

### API Endpoints
- UPI Initiate: `/pgidsk/PGIDirectRequest?reqid=BDRDF011`
- Authorization: `/pgidsk/PGIDirectRequest?reqid=BDRDF002`
- Status Check: `/pgidsk/PGIDirectRequest?reqid=BDRDF003`

### Authentication
- Uses Basic authentication with merchant_id:checksum_key format
- Supports both test (uat.billdesk.com) and production (www.billdesk.com) environments

### Known Limitations
- Only UPI and UPI Collect payment methods implemented
- Other flows (Refund, Void, Capture, etc.) are stubbed with NotImplemented responses
- Webhook processing needs implementation based on actual Billdesk webhook format
- Source verification algorithms are stubbed (Phase 10 implementation)