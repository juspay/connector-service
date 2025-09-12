# Changelog

## [2025-01-12] - AxisUpi Connector Addition

### Added
- New AxisUpi connector implementation
- Payment methods supported: UPI Collect, UPI Intent, UPI QR
- Transaction flows: Authorize (UPI payment initiation), PSync (payment status synchronization)

### Files Created/Modified
- `src/connectors/axisupi.rs` - Main connector implementation using UCS v2 macro framework
- `src/connectors/axisupi/transformers.rs` - Request/response transformers for Axis UPI API
- `src/connectors/axisupi/constants.rs` - API constants and endpoints for Axis UPI
- `src/connectors.rs` - Added AxisUpi connector registration
- `src/types.rs` - Added AxisUpi to connector mapping in convert_connector function
- `backend/domain_types/src/connector_types.rs` - Added AxisUpi to ConnectorEnum

### Technical Details
- Migrated from Hyperswitch/Euler Haskell implementation to UCS v2 Rust
- Uses UCS v2 macro framework for all trait implementations (no manual trait implementations)
- Implements proper error handling and status mapping from Axis UPI response codes
- Full type safety with guard rails (Secret<String> for sensitive data, MinorUnit for amounts, Email/Currency/CountryAlpha2 types)
- Supports both production and sandbox environments with configurable base URLs
- Amount framework implementation using StringMinorUnit converter for UPI minor unit amounts
- Comprehensive stub implementations for all unsupported flows to ensure compilation success

### API Endpoints Supported
- Collect: `/api/m1/merchants/transactions/webCollect` - UPI collect payment initiation
- Status: `/api/m1/merchants/transactions/status` - Payment status checking
- Additional endpoints defined for future implementation: refund, register intent, instant refund, VPA validation, etc.

### Configuration
- Production URL: https://upisdk.axisbank.co.in
- Sandbox URL: https://upiuatv3.axisbank.co.in
- Configurable through connector settings with test_mode flag

### Migration Notes
- Preserves all business logic from original Haskell implementation
- UPI-specific flows only (Authorize and PSync) as per requirements
- Proper error response handling with Axis UPI specific error codes
- Webhook verification stubs in place for future implementation
- Source verification stubs implemented for all flows