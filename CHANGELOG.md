# Changelog

## [2024-01-15] - PayTMv2 Connector Addition

### Added
- New PayTMv2 connector implementation
- Payment methods supported: UPI (Intent, Collect, QR)
- Transaction flows: Authorize, PSync, RSync
- Full UCS v2 macro framework compliance
- Proper error handling and status mapping
- Type-safe implementation with guard rails

### Files Created/Modified
- `src/connectors/paytmv2.rs` - Main connector implementation
- `src/connectors/paytmv2/transformers.rs` - Request/response transformers
- `src/connectors/paytmv2/constants.rs` - API constants and endpoints
- `src/connectors.rs` - Added connector registration
- `src/types.rs` - Added connector to ConnectorEnum and type definitions

### Technical Details
- Migrated from Hyperswitch/Euler Haskell implementation
- Uses UCS v2 macro framework for trait implementations
- Implements proper error handling and status mapping
- Full type safety with guard rails
- Amount framework using StringMinorUnit converter
- Authentication using SignatureKey pattern
- UPI-specific payment method handling
- Dynamic extraction of all request values from router data
- No hardcoded values in request transformers

### API Endpoints
- `/theia/api/v1/initiateTransaction` - Payment initiation
- `/merchant-status/api/v1/getTransactionStatus` - Payment status sync
- `/refund/api/v1/refundStatus` - Refund status sync

### Payment Methods
- UPI Intent
- UPI Collect
- UPI QR

### Status Mapping
- SUCCESS -> AttemptStatus::Charged
- PENDING -> AttemptStatus::Pending
- FAILURE -> AttemptStatus::Failure

### Authentication
- Uses SignatureKey authentication pattern
- SHA256 signature generation
- Client ID and Merchant ID extraction from auth type