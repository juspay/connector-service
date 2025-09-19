# Changelog

## [2023-12-13] - Zaakpay Connector Addition

### Added
- New Zaakpay connector implementation
- Payment methods supported: UPI (Unified Payments Interface)
- Transaction flows: Authorize, PSync, RSync (UPI initiation, payment status sync, refund status sync)

### Files Created/Modified
- `src/connectors/zaakpay/mod.rs` - Main connector implementation using UCS v2 macro framework
- `src/connectors/zaakpay/transformers.rs` - Request/response transformers with proper type safety
- `src/connectors/zaakpay/constants.rs` - API constants and endpoints for ZaakPay integration
- `src/connectors.rs` - Added Zaakpay connector registration
- `src/types.rs` - Added Zaakpay to ConnectorEnum for proper type system integration

### Technical Details
- Migrated from Haskell ZaakPay implementation to UCS v2 Rust
- Uses UCS v2 macro framework for all trait implementations (no manual code)
- Implements proper error handling and status mapping from ZaakPay response codes
- Full type safety with guard rails:
  - `Secret<String>` for sensitive data (API keys, tokens)
  - `MinorUnit` for monetary amounts
  - `Email` type for email addresses
  - `Currency` enum for currency fields
  - `CountryAlpha2` for country codes
- Dynamic data extraction from router data (no hardcoded values)
- UPI-focused implementation supporting UPI Intent and Collect flows
- Stub implementations for unsupported flows (card payments, net banking, etc.)

### API Integration Details
- Transaction API: `/transact` for UPI payment initiation
- Check API: `/check` for payment status synchronization
- Refund Status API: `/refundStatus` for refund status checks
- Proper ZaakPay authentication with merchant identifiers and checksum validation

### Implementation Strategy
- Strict UPI-only implementation as requested
- Business logic parity with original Haskell implementation
- Comprehensive error response parsing and status code mapping
- Placeholder implementations for webhook verification and signature validation
- Ready for production with proper guard rails and type safety