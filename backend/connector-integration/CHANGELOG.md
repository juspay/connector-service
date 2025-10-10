# Changelog

## [2024-01-XX] - Mobikwik Connector Addition

### Added
- New Mobikwik connector implementation for UPI payments
- Payment methods supported: UPI (Unified Payments Interface)
- Transaction flows: Authorize, PSync (Payment Sync)
- Full migration from Haskell euler-api-txns implementation

### Files Created/Modified
- `src/connectors/mobikwik.rs` - Main connector implementation using UCS v2 macro framework
- `src/connectors/mobikwik/transformers.rs` - Request/response transformers with all Mobikwik API types
- `src/connectors/mobikwik/constants.rs` - API constants, endpoints, and configuration
- `src/connectors.rs` - Added connector registration and import
- `src/types.rs` - Added connector to ConnectorEnum and match statements
- `backend/domain_types/src/connector_types.rs` - Added Mobikwik to ConnectorEnum
- `backend/domain_types/src/types.rs` - Added mobikwik field to Connectors struct

### Technical Details
- **Migrated from**: Hyperswitch/Euler Haskell implementation
- **Framework**: Uses UCS v2 macro framework (mandatory) - no manual trait implementations
- **API Integration**: Mobikwik Wallet API v2.0
- **Authentication**: Custom signature-based authentication with checksum generation
- **Amount Handling**: StringMinorUnit converter for amounts in minor units as strings
- **Error Handling**: Comprehensive error response parsing and status mapping
- **Type Safety**: Full guard rails with Secret<String> for sensitive data, proper domain types
- **Flows Implemented**:
  - Authorize: UPI payment initiation with phone number and token management
  - PSync: Payment status synchronization with transaction verification
- **Security**: SHA256-based checksum generation for API request authentication
- **Testing**: Support for both test and production environments

### API Endpoints
- Base URLs: 
  - Test: `https://test.mobikwik.com`
  - Production: `https://walletapi.mobikwik.com`
- Main endpoints: `/debitbalance`, `/checkstatus`
- Full API coverage: User management, OTP generation, token management, balance checking, refunds

### Features Preserved from Haskell
- All original request/response types migrated
- Complete business logic parity maintained
- Checksum generation and validation
- Multi-step UPI flow (existing user check → OTP → token → payment)
- Balance checking and debit operations
- Refund processing and status tracking
- Error handling and status code mapping

### Compliance
- ✅ Uses mandatory UCS v2 macro framework
- ✅ No manual trait implementations
- ✅ Proper amount framework implementation
- ✅ Type safety with guard rails
- ✅ Dynamic value extraction from router data
- ✅ Connector registration in type system
- ✅ Comprehensive error handling