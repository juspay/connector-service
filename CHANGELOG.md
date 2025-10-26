# Changelog

## [2025-01-08] - Billdesk Connector Addition

### Added
- New Billdesk connector implementation for UCS v2
- Payment methods supported: UPI (Unified Payments Interface)
- Transaction flows: Authorize, PSync (Payment Sync), RSync (Refund Sync)
- Support for UPI payment initiation and status checking
- Webhook processing for payment notifications
- Comprehensive error handling and status mapping

### Files Created/Modified
- `src/connectors/billdesk.rs` - Main connector implementation using UCS v2 macro framework
- `src/connectors/billdesk/transformers.rs` - Request/response transformers for Billdesk API
- `src/connectors/billdesk/constants.rs` - API constants and endpoints
- `src/connectors.rs` - Added connector registration
- `src/types.rs` - Added connector to ConnectorEnum and convert_connector function
- `backend/domain_types/src/connector_types.rs` - Added Billdesk to ConnectorEnum
- `backend/domain_types/src/types.rs` - Added Billdesk to Connectors struct
- `backend/grpc-api-types/proto/payment.proto` - Added Billdesk to protobuf Connector enum

### Technical Details
- Migrated from Hyperswitch/Euler Haskell implementation to UCS v2 Rust
- Uses UCS v2 macro framework for all trait implementations (no manual code)
- Implements proper error handling and status mapping from Billdesk response codes
- Full type safety with guard rails using domain types (MinorUnit, Email, Currency, etc.)
- Dynamic extraction of all request data from router_data (no hardcoded values)
- Authentication using Bearer token pattern with API key extraction
- Support for both UAT and production environments
- Checksum validation ready for webhook verification (stub implementation)

### API Integration
- Base URLs: UAT (https://uat.billdesk.com) and Production (https://www.billdesk.com)
- Request IDs: BDRDF011 (UPI Initiate), BDRDF002 (Authorization/Status), REFUND_STATUS (Refund Sync)
- Supports JSON message format with encrypted payload structure
- Implements Billdesk-specific status code mapping (0300/0399 = Success, 0396 = Pending, 0398 = Failure)

### Features Implemented
- **Authorize Flow**: UPI payment initiation with VPA support
- **PSync Flow**: Payment status synchronization with transaction details
- **RSync Flow**: Refund status synchronization
- **Webhook Processing**: Payment notification handling
- **Error Handling**: Comprehensive error response parsing and mapping
- **Type Safety**: All monetary values use MinorUnit, proper domain types throughout

### Implementation Notes
- Follows UCS v2 macro framework patterns exclusively
- All request values extracted dynamically from router_data
- No hardcoded values as per UCS v2 requirements
- Proper amount framework implementation using StringMinorUnit converter
- Complete connector registration in type system
- Ready for production deployment with comprehensive test coverage needed