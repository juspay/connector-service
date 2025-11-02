# Changelog

## [2025-01-08] - Billdesk Connector Addition

### Added
- New Billdesk connector implementation for UCS v2
- Payment methods supported: UPI (UpiCollect)
- Transaction flows: Authorize, PSync
- Full integration with UCS v2 macro framework
- Proper error handling and status mapping
- Type safety with guard rails

### Files Created/Modified
- `src/connectors/billdesk.rs` - Main connector implementation using UCS v2 macro framework
- `src/connectors/billdesk/transformers.rs` - Request/response transformers for Billdesk API
- `src/connectors/billdesk/constants.rs` - API constants and endpoints for Billdesk
- `src/connectors.rs` - Added Billdesk connector registration
- `src/types.rs` - Added Billdesk to connector conversion and Connectors struct
- `backend/domain_types/src/connector_types.rs` - Added Billdesk to ConnectorEnum
- `backend/domain_types/src/types.rs` - Added billdesk field to Connectors struct

### Technical Details
- Migrated from Hyperswitch/Euler Haskell implementation
- Uses UCS v2 macro framework for all trait implementations (no manual implementations)
- Implements proper authentication using SignatureKey with merchant_id and checksum_key
- Full type safety with Secret<String> for sensitive data and proper domain types
- Supports test/production environment detection via base URL
- Handles Billdesk-specific response formats and status codes
- Implements webhook processing with proper signature verification stubs
- Complete error handling with proper status code mapping

### API Endpoints Supported
- Authorize (UPI Initiation): `PGIDirectRequest?reqid=BDRDF011`
- PSync (Status Check): `PGIDirectRequest?reqid=BDRDF002`
- UAT Environment: `https://uat.billdesk.com/pgidsk/PGIDirectRequest`
- Production Environment: `https://www.billdesk.com/pgidsk/PGIDirectRequest`

### Payment Methods
- UPI (UpiCollect) - Primary focus as per requirements
- Future extensibility for other payment methods (NB, Card, etc.)

### Status Mapping
- Success: "0300", "0399" -> Charged
- Pending: "0396" -> AuthenticationPending  
- Failure: "0398" -> Failure

### Implementation Notes
- Uses StringMinorUnit amount converter for proper monetary value handling
- Implements all required UCS v2 flows with stub implementations for unsupported flows
- Follows UCS v2 patterns for request/response transformation
- Maintains business logic parity with original Haskell implementation
- Proper webhook source verification (stub for future implementation)