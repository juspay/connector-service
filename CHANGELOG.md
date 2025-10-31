# Changelog

## [2024-01-XX] - ZaakPay Connector Addition

### Added
- New ZaakPay connector implementation
- Payment methods supported: UPI (Unified Payments Interface)
- Transaction flows: Authorize, PSync (Payment Sync), RSync (Refund Sync)
- Webhook processing and verification
- Checksum-based authentication for transaction integrity

### Files Created/Modified
- `src/connectors/zaakpay.rs` - Main connector implementation using UCS v2 macro framework
- `src/connectors/zaakpay/transformers.rs` - Request/response transformers for ZaakPay API
- `src/connectors/zaakpay/constants.rs` - API constants and endpoints
- `src/connectors.rs` - Added connector registration
- `src/types.rs` - Added connector to ConnectorEnum and convert_connector function
- `backend/domain_types/src/connector_types.rs` - Added ZaakPay to ConnectorEnum
- `backend/domain_types/src/types.rs` - Added zaakpay field to Connectors struct
- `backend/grpc-api-types/proto/payment.proto` - Added ZAAKPAY enum variant

### Technical Details
- Migrated from Hyperswitch/Euler Haskell implementation
- Uses UCS v2 macro framework for trait implementations
- Implements proper error handling and status mapping
- Full type safety with guard rails (Secret<String>, MinorUnit, Email, etc.)
- Amount framework using StringMinorUnit converter for minor unit amounts
- Checksum calculation using SHA256 for transaction integrity
- Support for test and live modes
- UPI-specific payment instrument handling

### API Integration
- Base URL: Configurable via connector configuration
- Transaction endpoint: `/transaction/.do`
- Status check endpoint: `/checkStatus/.do`
- Authentication: Basic Auth with merchant identifier and secret key
- Request format: JSON with checksum verification
- Response handling: Error and success response parsing

### Business Logic Preserved
- UPI payment initiation with merchant and order details
- Billing address handling (defaults provided)
- Payment instrument configuration for UPI mode
- Transaction status synchronization
- Refund status tracking
- Webhook processing for payment notifications

### Implementation Notes
- Only UPI payments are supported as per requirements
- Card, netbanking, and other payment methods are not implemented
- Stub implementations provided for unsupported flows
- Source verification stubs for all implemented flows
- Proper error mapping from ZaakPay response codes to UCS status codes