# Changelog

## [2024-01-XX] - TPSL Connector Addition

### Added
- New TPSL connector implementation for UPI payment processing
- Payment methods supported: UPI (Unified Payments Interface)
- Transaction flows: Authorize, PSync (Payment Sync)
- Support for UPI Intent and Collect flows
- Comprehensive error handling and status mapping
- Full integration with UCS v2 macro framework

### Files Created/Modified
- `src/connectors/tpsl.rs` - Main connector implementation using UCS v2 macros
- `src/connectors/tpsl/transformers.rs` - Request/response transformers for TPSL API
- `src/connectors/tpsl/constants.rs` - API constants and endpoint definitions
- `src/connectors.rs` - Added TPSL connector registration
- `src/types.rs` - Added TPSL to connector enum and conversion logic
- `backend/domain_types/src/connector_types.rs` - Added Tpsl to ConnectorEnum
- `backend/grpc-api-types/proto/payment.proto` - Added TPSL to gRPC Connector enum
- `backend/domain_types/src/types.rs` - Added tpsl field to Connectors struct

### Technical Details
- Migrated from Hyperswitch/Euler Haskell implementation to UCS v2 Rust
- Uses UCS v2 macro framework for all trait implementations (no manual code)
- Implements proper authentication with API key support
- Full type safety with guard rails (Secret<String> for sensitive data, MinorUnit for amounts)
- Dynamic request body value extraction from router data (no hardcoded values)
- Comprehensive error response handling with proper status code mapping
- Support for both test and production environments
- UPI-specific business logic preserved from original implementation

### API Endpoints
- Production: `https://www.tpsl-india.in/PaymentGateway/services/TransactionDetailsNew`
- Test: `https://www.tekprocess.co.in/PaymentGateway/services/TransactionDetailsNew`

### Authentication
- API Key based authentication
- Support for currency-specific authentication keys
- Bearer token authentication header

### Payment Flow
1. Authorize: Initiates UPI payment transaction
2. PSync: Synchronizes payment status with TPSL
3. Returns redirect information for UPI app completion

### Features
- UPI VPA (Virtual Payment Address) support
- Mobile number and email validation
- Transaction reference tracking
- Comprehensive status mapping (Success, Pending, Failure, Processing)
- Error code and message handling
- Webhook support structure (implementation ready)

### Compliance
- Follows UCS v2 coding standards and patterns
- Proper error handling and logging
- Type-safe implementations with Rust's type system
- Memory safe and performant Rust implementation