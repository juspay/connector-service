# Changelog

## [2024-01-XX] - easebuzz Connector Addition

### Added
- New easebuzz connector implementation
- Payment methods supported: UPI
- Transaction flows: Authorize, PSync

### Files Created/Modified
- `src/connectors/easebuzz.rs` - Main connector implementation
- `src/connectors/easebuzz/transformers.rs` - Request/response transformers
- `src/connectors/easebuzz/constants.rs` - API constants and endpoints
- `src/connectors.rs` - Added connector registration
- `src/types.rs` - Added connector to ConnectorEnum and convert_connector function
- `backend/domain_types/src/connector_types.rs` - Added Easebuzz to ConnectorEnum
- `backend/domain_types/src/types.rs` - Added easebuzz to Connectors struct
- `backend/grpc-api-types/proto/payment.proto` - Added EASEBUZZ to Connector enum

### Technical Details
- Migrated from Hyperswitch/Euler Haskell implementation
- Uses UCS v2 macro framework for trait implementations
- Implements proper error handling and status mapping
- Full type safety with guard rails
- Supports test and production environments with different base URLs
- UPI payment initiation and synchronization flows implemented