# Changelog

## [2025-01-XX] - ZaakPay Connector Addition

### Added
- New ZaakPay connector implementation
- Payment methods supported: UPI, Netbanking
- Transaction flows: Authorize, PSync, RSync

### Files Created/Modified
- `src/connectors/zaakpay.rs` - Main connector implementation
- `src/connectors/zaakpay/transformers.rs` - Request/response transformers
- `src/connectors/zaakpay/constants.rs` - API constants and endpoints
- `src/connectors.rs` - Added connector registration
- `src/types.rs` - Added connector to ConnectorEnum
- `backend/domain_types/src/connector_types.rs` - Added ZaakPay to ConnectorEnum
- `backend/domain_types/src/types.rs` - Added zaakpay field to Connectors struct
- `backend/grpc-api-types/proto/payment.proto` - Added ZaakPay to protobuf enum

### Technical Details
- Migrated from Hyperswitch/Euler Haskell implementation
- Uses UCS v2 macro framework for trait implementations
- Implements proper error handling and status mapping
- Full type safety with guard rails
- Supports UPI and Netbanking payment methods
- Checksum-based authentication following PhonePe pattern
- Amount handling using StringMinorUnit converter

### Implementation Notes
- Focus on UPI and sync flows as per requirements
- Placeholder checksum generation (needs actual ZaakPay algorithm)
- Stub implementations for unsupported flows
- Proper authentication using API Key and Merchant Identifier
- Dynamic value extraction from router data (no hardcoded values)