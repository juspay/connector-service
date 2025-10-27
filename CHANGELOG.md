# Changelog

## [2024-01-XX] - EaseBuzz Connector Addition

### Added
- New EaseBuzz connector implementation
- Payment methods supported: UPI (Intent, Collect, Autopay)
- Transaction flows: Authorize, PSync, RSync
- Support for UPI mandate operations
- Support for refund synchronization
- Support for transaction synchronization

### Files Created/Modified
- `src/connectors/easebuzz.rs` - Main connector implementation
- `src/connectors/easebuzz/transformers.rs` - Request/response transformers
- `src/connectors/easebuzz/constants.rs` - API constants and endpoints
- `src/connectors.rs` - Added connector registration
- `src/types.rs` - Added connector to ConnectorEnum and convert_connector function
- `backend/domain_types/src/connector_types.rs` - Added EaseBuzz to ConnectorEnum
- `backend/domain_types/src/types.rs` - Added easebuzz to Connectors struct

### Technical Details
- Migrated from Hyperswitch/Euler Haskell implementation
- Uses UCS v2 macro framework for trait implementations
- Implements proper error handling and status mapping
- Full type safety with guard rails
- Supports test and production environments
- Hash-based authentication for API security
- Dynamic request body extraction from router data
- No hardcoded values - all data extracted dynamically

### API Endpoints
- Payment Initiate: `/payment/initiateLink`
- Transaction Sync: `/transaction/v1/sync`
- Refund Sync: `/transaction/v1/refund/sync`
- UPI Autopay: `/upi/autopay`
- Mandate Operations: `/mandate/*`

### Authentication
- API Key + Salt based authentication
- MD5 hash generation for request validation
- Support for both test and production environments

### Features
- UPI Intent and Collect flows
- UPI Autopay support
- Mandate creation and execution
- Real-time transaction synchronization
- Refund status tracking
- Comprehensive error handling
- Webhook support (stub implementation)