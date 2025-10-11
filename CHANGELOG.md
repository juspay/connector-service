# Changelog

## [2024-01-XX] - IciciUpi Connector Addition

### Added
- New IciciUpi connector implementation for UCS v2
- Payment methods supported: UPI (Unified Payments Interface)
- Transaction flows: Authorize (UPI Collect), PSync (Payment Status Sync)
- Complete connector structure using UCS v2 macro framework
- API endpoints for CollectPay, TransactionStatus, and other UPI operations
- Authentication handling for ICICI UPI API
- Request/response transformers for UPI payment flows
- Error handling and status mapping
- Type-safe implementations with proper guard rails

### Files Created/Modified
- `src/connectors/iciciupi.rs` - Main connector implementation with macro framework
- `src/connectors/iciciupi/transformers.rs` - Request/response transformers and data types
- `src/connectors/iciciupi/constants.rs` - API constants and endpoints
- `src/connectors.rs` - Added connector registration
- `src/types.rs` - Added connector to conversion functions
- `backend/domain_types/src/connector_types.rs` - Added IciciUpi to ConnectorEnum
- `backend/domain_types/src/types.rs` - Added iciciupi field to Connectors struct
- `backend/grpc-api-types/proto/payment.proto` - Added ICICIUPI to protobuf enum

### Technical Details
- Migrated from Hyperswitch/Euler Haskell implementation
- Uses UCS v2 macro framework for all trait implementations
- Implements proper error handling and status mapping
- Full type safety with guard rails (Secret<String>, MinorUnit, etc.)
- Supports both staging and production environments
- Dynamic extraction of all request data from router data
- Proper amount framework implementation using StringMinorUnit

### Implementation Status
- ✅ Connector structure and macro framework setup
- ✅ Basic request/response transformers
- ✅ Authentication handling
- ✅ API endpoint configuration
- ✅ Type system integration
- ✅ Enum registration
- 🔄 Response transformation trait implementations (in progress)
- ⏳ Webhook handling (stub implementation)
- ⏳ Additional UPI flows (mandates, refunds, etc.)

### Known Issues
- Response transformation trait implementations need refinement for generic type compatibility
- Some advanced UPI features (mandates, recurring payments) are stubbed
- Webhook verification needs implementation based on ICICI UPI requirements

### Next Steps
- Complete response transformation implementations
- Implement webhook verification and processing
- Add support for mandate operations
- Add comprehensive error handling for all edge cases
- Add unit tests for all flows
- Add integration tests with ICICI UPI sandbox