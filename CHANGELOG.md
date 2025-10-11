# Changelog

## [2024-01-XX] - PayTMv2 Connector Addition

### Added
- New PayTMv2 connector implementation
- Payment methods supported: UPI (Intent, Collect, QR)
- Transaction flows: Authorize, PSync

### Files Created/Modified
- `src/connectors/paytmv2.rs` - Main connector implementation
- `src/connectors/paytmv2/transformers.rs` - Request/response transformers
- `src/connectors/paytmv2/constants.rs` - API constants and endpoints
- `src/connectors/paytmv2/api.rs` - API module
- `src/connectors.rs` - Added connector registration
- `src/types.rs` - Added connector to ConnectorEnum and convert_connector function
- `backend/domain_types/src/connector_types.rs` - Added Paytmv2 to ConnectorEnum
- `backend/domain_types/src/types.rs` - Added paytmv2 connector params

### Technical Details
- Migrated from Hyperswitch/Euler Haskell implementation
- Uses UCS v2 macro framework for trait implementations
- Implements proper error handling and status mapping
- Full type safety with guard rails
- Supports UPI payment flows with proper authentication
- Amount handling using StringMinorUnit converter
- Dynamic extraction of all request parameters from router data
- No hardcoded values - all data extracted from router data

### API Endpoints
- `/theia/api/v1/initiateTransaction` - Payment initiation
- `/theia/api/v1/transactionStatus` - Payment status sync
- `/theia/api/v1/validateVpa` - VPA validation
- `/subscription/api/v1/mandate/initiate` - Mandate initiation
- `/subscription/api/v1/mandate/status` - Mandate status

### Features
- UPI Intent, Collect, and QR payment support
- Transaction token generation
- Payment status synchronization
- VPA validation
- Mandate/subscription support
- Proper error handling and response mapping
- Webhook support (stub implementation)
- Source verification (stub implementation)