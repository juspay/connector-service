# Changelog

## [2025-01-08] - Billdesk Connector Addition

### Added
- New Billdesk connector implementation for UCS v2
- Payment methods supported: UPI (Intent/Collect)
- Transaction flows: Authorize, PSync (Payment Status Sync)
- Support for test and production environments
- Checksum-based authentication for Billdesk API
- Proper error handling and status mapping

### Files Created/Modified
- `src/connectors/billdesk.rs` - Main connector implementation using UCS v2 macro framework
- `src/connectors/billdesk/transformers.rs` - Request/response transformers for Billdesk API
- `src/connectors/billdesk/constants.rs` - API constants and endpoints
- `src/connectors.rs` - Added Billdesk connector registration
- `src/types.rs` - Added Billdesk to connector imports and match statement
- `backend/domain_types/src/connector_types.rs` - Added Billdesk to ConnectorEnum
- `backend/grpc-api-types/proto/payment.proto` - Added Billdesk to protobuf enum

### Technical Details
- Migrated from Hyperswitch/Euler Haskell implementation
- Uses UCS v2 macro framework for all trait implementations
- Implements proper type safety with guard rails (Secret<String>, MinorUnit, etc.)
- Full amount framework implementation using StringMinorUnit converter
- Dynamic extraction of all request values from router data (no hardcoded values)
- Comprehensive error handling with proper status mapping
- Webhook verification stub (to be implemented in Phase 10)

### Implementation Status
- ✅ Connector structure and macro framework setup
- ✅ Basic request/response transformers
- ✅ Authentication and checksum generation
- ✅ API endpoint configuration
- ✅ Connector registration in type system
- ✅ Protobuf enum integration
- ⚠️ Compilation errors need resolution (multiple trait bound issues, missing fields, etc.)
- ❌ PSync flow implementation incomplete
- ❌ Full UPI integration testing needed
- ❌ Additional flows (Void, Capture, Refund, etc.) are stubs only

### Known Issues
- Multiple compilation errors related to missing trait implementations
- Some payment method types (Upi, NetBanking) not found in enums
- Missing fields in router data structures
- Secret trait methods not in scope
- ConnectorServiceTrait requires many unimplemented flows

### Next Steps
1. Fix compilation errors by adding missing trait implementations
2. Complete PSync flow implementation
3. Add comprehensive UPI payment method support
4. Implement remaining flows as needed
5. Add comprehensive testing
6. Complete webhook verification implementation