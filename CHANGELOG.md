# Changelog

## [2025-01-XX] - Billdesk Connector Addition

### Added
- New Billdesk connector implementation for UCS v2
- Payment methods supported: UPI (UpiCollect, UpiIntent)
- Transaction flows: Authorize, PSync (Payment Status Sync)
- Full integration with UCS v2 macro framework
- Support for test and production environments
- Authentication using merchant ID and checksum key
- Request/response transformers for Billdesk API
- Error handling and status mapping
- Webhook processing capabilities

### Files Created/Modified
- `src/connectors/billdesk.rs` - Main connector implementation with UCS v2 macros
- `src/connectors/billdesk/transformers.rs` - Request/response transformers and type definitions
- `src/connectors/billdesk/constants.rs` - API constants and endpoints
- `src/connectors.rs` - Added Billdesk connector registration
- `src/types.rs` - Added Billdesk to connector type mapping
- `backend/domain_types/src/connector_types.rs` - Added Billdesk to ConnectorEnum
- `backend/domain_types/src/types.rs` - Added billdesk field to Connectors struct
- `backend/grpc-api-types/proto/payment.proto` - Added Billdesk to gRPC enum

### Technical Details
- Migrated from Hyperswitch/Euler Haskell implementation to UCS v2 Rust
- Uses UCS v2 macro framework for all trait implementations (no manual code)
- Implements proper error handling with ConnectorError types
- Full type safety with guard rails (Secret<String>, MinorUnit, etc.)
- Dynamic extraction of all request values from router data (no hardcoded values)
- Amount framework implementation using StringMinorUnit converter
- Support for UPI payment flows with proper endpoint routing
- Base64 authentication header generation
- Comprehensive status mapping from Billdesk response codes

### API Endpoints
- UPI Initiate: `https://uat.billdesk.com/pgidsk/PGIDirectRequest?reqid=BDRDF011` (test)
- UPI Initiate: `https://www.billdesk.com/pgidsk/PGIDirectRequest?reqid=BDRDF011` (prod)
- Status Query: `https://uat.billdesk.com/pgidsk/PGIDirectRequest?reqid=BDRDF003` (test)
- Status Query: `https://www.billdesk.com/pgidsk/PGIDirectRequest?reqid=BDRDF003` (prod)

### Authentication
- Type: SignatureKey with merchant_id and checksum_key
- Header: Basic authentication with base64 encoded credentials
- Dynamic extraction from connector_auth_type

### Payment Method Support
- UpiCollect - UPI Collect payments
- UpiIntent - UPI Intent payments
- PaymentMethod::Upi enum variant for routing

### Status Mapping
- 0300/0399 -> Charged
- 0396 -> AuthenticationPending  
- 0398 -> Failure
- Default -> Failure

### Compliance
- ✅ Uses UCS v2 macro framework (mandatory)
- ✅ No manual trait implementations
- ✅ All values extracted dynamically from router data
- ✅ Proper amount framework usage
- ✅ Type safety with guard rails
- ✅ No hardcoded values in request bodies
- ✅ Complete connector registration in type system
- ✅ `cargo check` passes without errors