# Changelog

## [2024-01-01] - TPSL Connector Addition

### Added
- New TPSL connector implementation for UCS v2
- Payment methods supported: UPI (Intent/Collect)
- Transaction flows: Authorize, PSync
- Full integration with UCS v2 macro framework
- Proper error handling and status mapping
- Complete type safety with guard rails

### Files Created/Modified
- `src/connectors/tpsl.rs` - Main connector implementation using UCS v2 macro framework
- `src/connectors/tpsl/transformers.rs` - Request/response transformers for TPSL API
- `src/connectors/tpsl/constants.rs` - API constants and endpoints for TPSL
- `src/connectors.rs` - Added TPSL connector registration
- `src/types.rs` - Added TPSL to connector conversion logic
- `backend/domain_types/src/connector_types.rs` - Added Tpsl to ConnectorEnum
- `backend/grpc-api-types/proto/payment.proto` - Added TPSL to protobuf Connector enum

### Technical Details
- Migrated from Hyperswitch/Euler Haskell implementation
- Uses UCS v2 macro framework for all trait implementations (no manual code)
- Implements proper error handling and status mapping from TPSL responses
- Full type safety with Secret<String> for sensitive data and MinorUnit for amounts
- Supports UPI payment flows with proper request/response transformation
- Includes stub implementations for all unsupported flows to maintain compilation
- Proper authentication handling using ConnectorAuthType

### API Endpoints
- Production: `https://www.tpsl-india.in/PaymentGateway/services/TransactionDetailsNew`
- Test: `https://www.tekprocess.co.in/PaymentGateway/services/TransactionDetailsNew`

### Payment Methods
- UPI Intent/Collect flows fully implemented
- Transaction token generation and synchronization
- Proper status mapping (SUCCESS, PENDING, FAILURE to UCS AttemptStatus)

### Error Handling
- Comprehensive error response parsing
- Status code mapping
- Proper error message propagation
- Validation error handling

### Notes
- Only UPI and sync flows implemented as per requirements
- Other payment methods (cards, net banking, wallets) have stub implementations
- Webhook verification structure in place (to be implemented)
- Source verification stubs for all flows (to be implemented in Phase 10)