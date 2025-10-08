# Changelog

## [2024-01-XX] - GooglePay Connector Addition

### Added
- New GooglePay connector implementation
- Payment methods supported: UPI (Intent and Collect)
- Transaction flows: Authorize, PSync
- Stub implementations for: Void, Capture, Refund, RSync, CreateOrder, CreateSessionToken, SetupMandate, RepeatPayment, Accept, DefendDispute, SubmitEvidence

### Files Created/Modified
- `src/connectors/googlepay.rs` - Main connector implementation
- `src/connectors/googlepay/transformers.rs` - Request/response transformers
- `src/connectors/googlepay/constants.rs` - API constants and endpoints (updated)
- `src/connectors.rs` - Added connector registration
- `src/types.rs` - Added connector to ConnectorEnum imports and convert_connector function
- `backend/domain_types/src/connector_types.rs` - Added GooglePay to ConnectorEnum and ForeignTryFrom implementation

### Technical Details
- Migrated from Euler/Haskell implementation to UCS v2 Rust framework
- Uses UCS v2 macro framework for trait implementations (create_all_prerequisites! and macro_connector_implementation!)
- Implements proper error handling and status mapping
- Full type safety with guard rails (Secret<String> for sensitive data, MinorUnit for amounts, proper domain types)
- Dynamic extraction of all request values from router data (no hardcoded values)
- Supports both UPI Intent and Collect payment flows
- Proper amount conversion using StringMinorUnit converter
- Authentication handling via connector auth types
- Webhook verification stubs implemented
- Source verification stubs for all flows

### API Endpoints
- Production: `https://eulerupi-prod.hyperswitch.io/api/m1/transactions`
- UAT: `https://eulerupi-uat.hyperswitch.io/api/m1/transactions`
- Webhook: `/v2/pay/webhooks/{merchant_id}/{gateway}`

### Key Features
- UPI transaction initiation with dynamic platform detection
- Payment status synchronization
- Proper error response handling
- Redirect form generation for UPI flows
- Mobile number extraction from UPI data
- Transaction reference and UPI request ID generation
- Expiry handling (default 15 minutes)
- Callback URL handling

### Type Safety Implementation
- All monetary amounts use MinorUnit type
- Sensitive data (API keys, auth tokens) wrapped in Secret<String>
- Email addresses use Email type
- Currency uses Currency enum
- Customer IDs use proper domain types
- Transaction IDs extracted from router data dynamically

### Migration Notes
- Preserved all business logic from original Haskell implementation
- Maintained compatibility with Euler API endpoints
- Converted Haskell data types to equivalent Rust structs
- Implemented proper enum handling for OriginatingPlatform
- Added comprehensive error mapping
- Maintained webhook structure compatibility