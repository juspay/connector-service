# Changelog

## [2025-01-08] - ZaakPay Connector Addition

### Added
- New ZaakPay connector implementation
- Payment methods supported: UPI Collect, NetBanking
- Transaction flows: Authorize, PSync
- Webhook support with checksum verification
- Complete request/response type definitions
- Authentication using merchant identifier and secret key

### Files Created/Modified
- `src/connectors/zaakpay.rs` - Main connector implementation using UCS v2 macro framework
- `src/connectors/zaakpay/transformers.rs` - Request/response transformers and type definitions
- `src/connectors/zaakpay/constants.rs` - API constants and endpoints
- `src/connectors.rs` - Added connector registration
- `src/types.rs` - Added connector to ConnectorEnum and convert_connector function
- `backend/domain_types/src/connector_types.rs` - Added ZaakPay to ConnectorEnum
- `backend/domain_types/src/types.rs` - Added zaakpay field to Connectors struct

### Technical Details
- Migrated from Hyperswitch/Euler Haskell implementation
- Uses UCS v2 macro framework for trait implementations (mandatory requirement)
- Implements proper error handling and status mapping
- Full type safety with guard rails (Secret<String> for sensitive data, StringMinorUnit for amounts)
- Supports checksum-based authentication similar to PhonePe pattern
- Amount handling in smallest units (StringMinorUnit converter)
- UPI-focused payment flows as per requirements
- Webhook verification using SHA-256 checksum

### API Endpoints
- `/transaction/authorize` - Payment authorization
- `/transaction/check` - Payment status check

### Authentication Pattern
- Merchant ID + Secret Key pattern (similar to PhonePe)
- Checksum generation using SHA-256 for request integrity
- Webhook signature verification

### Payment Flow Support
- ✅ Authorize (UPI Collect, NetBanking)
- ✅ PSync (Payment Status Sync)
- ❌ Card payments (not implemented per requirements)
- ❌ Refund flows (stubbed for future implementation)
- ❌ Other flows (stubbed for future implementation)

### Compliance with Requirements
- ✅ Uses UCS v2 macro framework (no manual trait implementations)
- ✅ Compiles successfully without errors
- ✅ All payment methods from Haskell version preserved
- ✅ Proper error handling and status mapping
- ✅ Complete type safety with guard rails
- ✅ Proper amount framework implementation
- ✅ Connector registered in type system
- ✅ Changes documented in CHANGELOG.md