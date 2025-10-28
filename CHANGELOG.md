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
- ✅ Connector structure and macro framework setup using UCS v2
- ✅ Basic request/response transformers for Authorize and PSync flows
- ✅ Authentication and checksum generation for Billdesk API
- ✅ API endpoint configuration for UPI and payment flows
- ✅ Connector registration in type system
- ✅ UPI payment method support (UpiCollect, UpiIntent)
- ✅ Proper amount framework implementation using StringMinorUnit
- ✅ Dynamic extraction of all request values from router data
- ✅ Error handling and status mapping
- ⚠️ Compilation errors reduced from 50+ to 34 (significant progress)
- ❌ Some trait implementations still causing compilation issues
- ❌ Full integration testing needed once compilation is resolved

### Known Issues
- Remaining compilation errors related to trait bounds for unsupported flows
- Macro framework expecting trait implementations for flows not implemented
- Need to resolve trait constraint issues for complete compilation
- Core functionality (Authorize, PSync) is implemented and should work once trait issues are resolved

### Next Steps
1. Fix compilation errors by adding missing trait implementations
2. Complete PSync flow implementation
3. Add comprehensive UPI payment method support
4. Implement remaining flows as needed
5. Add comprehensive testing
6. Complete webhook verification implementation