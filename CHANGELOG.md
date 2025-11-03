# Changelog

## [2025-01-XX] - Billdesk Connector Addition

### Added
- New Billdesk connector implementation for UCS v2
- Payment methods supported: UPI Collect
- Transaction flows: Authorize, PSync
- Complete connector structure with transformers, constants, and main implementation

### Files Created/Modified
- `src/connectors/billdesk.rs` - Main connector implementation using UCS v2 macro framework
- `src/connectors/billdesk/transformers.rs` - Request/response transformers for Billdesk API
- `src/connectors/billdesk/constants.rs` - API constants and endpoints for Billdesk
- `src/connectors.rs` - Added Billdesk connector registration
- `src/types.rs` - Added Billdesk to connector imports and conversion
- `backend/domain_types/src/connector_types.rs` - Added Billdesk to ConnectorEnum
- `backend/domain_types/src/types.rs` - Added Billdesk to Connectors struct
- `backend/grpc-api-types/proto/payment.proto` - Added BILLDESK to Connector enum

### Technical Details
- Migrated from Hyperswitch/Euler Haskell implementation
- Uses UCS v2 macro framework for trait implementations
- Implements proper error handling and status mapping
- Full type safety with guard rails (Secret<String>, MinorUnit, etc.)
- Authentication pattern: Merchant ID + API Key (similar to PhonePe)
- Amount handling: StringMinorUnit converter for minor units as string
- UPI payment flow implementation with message building
- Webhook processing with signature validation stub

### Implementation Status
- ✅ Basic connector structure and macro setup
- ✅ UPI Collect payment flow (Authorize)
- ✅ Payment status synchronization (PSync)
- ✅ Authentication and request/response handling
- ✅ Error handling and status mapping
- ✅ Type safety and guard rails
- ✅ Connector registration in type system
- 🔄 Compilation fixes in progress (macro system integration)

### Next Steps
- Complete compilation fixes for macro system integration
- Add comprehensive test coverage
- Implement additional UPI flows (Intent)
- Add webhook signature validation
- Implement refund flows (RSync)
- Add mandate management flows