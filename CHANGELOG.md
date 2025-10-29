# Changelog

## [2025-01-XX] - Billdesk Connector Migration to UCS v2

### Added
- Complete Billdesk connector implementation using mandatory UCS v2 macro framework
- Payment methods supported: UPI Collect, UPI Intent (UPI-focused as per requirements)
- Transaction flows: Authorize, PSync, Refund, RSync (UPI and sync flows only)
- Support for Billdesk's checksum-based authentication
- Comprehensive error handling and status mapping
- Webhook processing capabilities

### Files Created/Modified
- `backend/connector-integration/src/connectors/billdesk.rs` - Main connector implementation using mandatory UCS v2 macro framework
- `backend/connector-integration/src/connectors/billdesk/transformers.rs` - Request/response transformers and data conversion logic
- `backend/connector-integration/src/connectors/billdesk/constants.rs` - API constants, endpoints, and response codes
- `backend/connector-integration/src/connectors.rs` - Billdesk connector registration (already existed)

### Technical Details
- **MANDATORY**: Uses UCS v2 macro framework - NO manual trait implementations
- Migrated from Hyperswitch/Euler Haskell implementation to UCS v2 Rust
- Uses `create_all_prerequisites!` and `macro_connector_implementation!` macros exclusively
- Implements proper amount framework using StringMinorUnit converter
- Full type safety with guard rails (Secret<String> for sensitive data, proper domain types)
- **CRITICAL**: All request body values extracted dynamically from router data (NO hardcoded values)
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