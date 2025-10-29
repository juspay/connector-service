# Changelog

## [2024-01-XX] - Billdesk Connector Addition

### Added
- New Billdesk connector implementation
- Payment methods supported: UPI Collect, UPI Intent, Online Banking (FPX, Poland, Czech Republic, Finland, Slovakia, Thailand)
- Transaction flows: Authorize, PSync, Refund, RSync
- Support for Billdesk's checksum-based authentication
- Comprehensive error handling and status mapping
- Webhook processing capabilities

### Files Created/Modified
- `src/connectors/billdesk.rs` - Main connector implementation with UCS v2 macro framework
- `src/connectors/billdesk/transformers.rs` - Request/response transformers and data conversion logic
- `src/connectors/billdesk/constants.rs` - API constants, endpoints, and response codes
- `src/connectors.rs` - Added Billdesk connector registration
- `src/types.rs` - Added Billdesk to connector imports and type mapping
- `backend/domain_types/src/connector_types.rs` - Added Billdesk to ConnectorEnum
- `backend/domain_types/src/types.rs` - Added Billdesk configuration to Connectors struct

### Technical Details
- Migrated from Hyperswitch/Euler Haskell implementation to UCS v2 Rust
- Uses UCS v2 macro framework for all trait implementations (no manual coding)
- Implements proper amount framework using StringMinorUnit converter
- Full type safety with guard rails (Secret<String> for sensitive data, proper domain types)
- Supports both UAT and production environments with automatic URL selection
- Maintains business logic parity with original Haskell implementation
- Comprehensive status code mapping from Billdesk to internal AttemptStatus/RefundStatus

### API Integration
- Base URLs: UAT (https://uat.billdesk.com/pgidsk/PGIDirectRequest) and Production (https://www.billdesk.com/pgidsk/PGIDirectRequest)
- Request IDs: BDRDF011 (UPI), BDRDF002 (Net Banking/Default)
- Authentication: Merchant ID and Checksum Key via ConnectorAuthType::SignatureKey
- Message format: Pipe-separated key-value pairs with checksum validation

### Payment Flow Support
- **Authorize**: Initiates UPI and Net Banking payments with redirect flow
- **PSync**: Checks payment status using transaction reference
- **Refund**: Processes refunds with amount validation
- **RSync**: Checks refund status using refund ID
- **Webhooks**: Processes payment status notifications

### Error Handling
- Comprehensive error response parsing
- Status code mapping (0300/0399 = Success, 0396 = Failure, 0001/0002 = Pending)
- Proper error propagation with ConnectorError types
- Validation for required fields and data types

### Security Features
- Secure handling of merchant credentials using Secret<String>
- Checksum validation for request integrity
- IP address and user agent tracking
- Proper masking of sensitive data in logs

### Testing Status
- ✅ Compilation successful with cargo check
- ✅ All trait implementations using UCS v2 macro framework
- ✅ Type safety and guard rails implemented
- ✅ Connector registered in type system
- ⏳ Integration testing pending
- ⏳ End-to-end testing pending