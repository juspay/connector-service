# Changelog

## [2024-01-XX] - TPSL Connector Addition

### Added
- New TPSL connector implementation for UCS v2
- Payment methods supported: UPI (Intent/Collect)
- Transaction flows: Authorize, PSync
- Full migration from Haskell euler-api-txns implementation

### Files Created/Modified
- `src/connectors/tpsl.rs` - Main connector implementation using UCS v2 macro framework
- `src/connectors/tpsl/transformers.rs` - Request/response transformers for TPSL API
- `src/connectors/tpsl/constants.rs` - Updated with additional API constants and defaults
- `src/connectors.rs` - Added TPSL connector registration
- `src/types.rs` - Added TPSL to connector imports and matching
- `backend/domain_types/src/connector_types.rs` - Added Tpsl to ConnectorEnum
- `backend/domain_types/src/types.rs` - Added TpslConnectorParams struct with test_base_url support

### Technical Details
- **Migrated from**: Hyperswitch/Euler Haskell implementation
- **Framework**: Uses UCS v2 macro framework (create_all_prerequisites! and macro_connector_implementation!)
- **Payment Methods**: UPI Intent and UPI Collect flows
- **API Endpoints**:
  - Production: `https://www.tpsl-india.in`
  - Test: `https://www.tekprocess.co.in`
  - UPI Transaction: `/api/PaynimoEncNew.jsp`
  - UPI Sync: `/api/paynimoV2.req`
- **Authentication**: SignatureKey with merchant_code and security_token
- **Amount Handling**: StringMinorUnit converter for proper amount formatting
- **Error Handling**: Comprehensive error response parsing and status mapping
- **Type Safety**: Full guard rails with Secret<> for sensitive data, proper domain types

### Features Implemented
- ✅ UPI payment initiation (Authorize flow)
- ✅ Payment status synchronization (PSync flow)
- ✅ Proper amount conversion using UCS v2 amount framework
- ✅ Dynamic request body value extraction (no hardcoded values)
- ✅ Type-safe authentication handling
- ✅ Comprehensive error handling
- ✅ Stub implementations for all unsupported flows
- ✅ Source verification stubs for all flows

### API Support
- **Supported**: UPI Intent, UPI Collect
- **Unsupported**: Card payments, Net banking, Wallets, Bank transfers
- **Test Mode**: Full support with separate test base URL

### Configuration
- Requires `merchant_code` and `security_token` in connector authentication
- Supports both production and test environments
- Configurable webhook endpoints for payment notifications

### Migration Notes
- Preserves all business logic from original Haskell implementation
- Maintains API compatibility with TPSL payment gateway
- Uses proper UCS v2 patterns for request/response handling
- Implements all required guard rails and type safety measures