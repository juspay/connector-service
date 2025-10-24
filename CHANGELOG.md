# Changelog

## [2024-01-XX] - Billdesk Connector Addition

### Added
- New Billdesk connector implementation
- Payment methods supported: UPI
- Transaction flows: Authorize, PSync
- Authentication pattern: Merchant ID + Checksum Key (similar to PhonePe)

### Files Created/Modified
- `src/connectors/billdesk.rs` - Main connector implementation
- `src/connectors/billdesk/transformers.rs` - Request/response transformers
- `src/connectors/billdesk/constants.rs` - API constants and endpoints
- `src/connectors.rs` - Added connector registration
- `src/types.rs` - Added connector to ConnectorEnum and convert_connector function
- `backend/domain_types/src/connector_types.rs` - Added Billdesk to ConnectorEnum
- `backend/domain_types/src/types.rs` - Added billdesk configuration to Connectors struct

### Technical Details
- Migrated from Hyperswitch/Euler Haskell implementation
- Uses UCS v2 macro framework for trait implementations
- Implements proper error handling and status mapping
- Full type safety with guard rails
- Supports UPI payment initiation and status synchronization
- Uses StringMinorUnit amount converter for proper amount handling
- Implements webhook verification stub (to be completed in Phase 10)

### API Endpoints
- UAT: https://uat.billdesk.com/pgidsk/PGIDirectRequest
- Production: https://www.billdesk.com/pgidsk/PGIDirectRequest
- Request IDs: BDRDF011 (UPI Initiate), BDRDF002 (Status Check)

### Status Mapping
- Success: "0300", "0399" -> Charged
- Failure: "0396" -> Failure  
- Pending: "0398" -> AuthenticationPending

### Authentication
- Uses SignatureKey authentication with merchant_id and checksum_key
- Custom auth header implementation for Billdesk's requirements