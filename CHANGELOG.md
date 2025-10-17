# Changelog

## [2025-01-08] - IciciUpi Connector Addition

### Added
- New IciciUpi connector implementation for UPI payments
- Payment methods supported: UPI (Unified Payments Interface)
- Transaction flows: Authorize (UPI Collect), PSync (Payment Status Sync)
- Full UCS v2 macro framework implementation
- Support for sandbox and production environments
- Authentication using SignatureKey pattern
- Comprehensive error handling and status mapping

### Files Created/Modified
- `src/connectors/iciciupi.rs` - Main connector implementation with UCS v2 macros
- `src/connectors/iciciupi/transformers.rs` - Request/response transformers and type definitions
- `src/connectors/iciciupi/constants.rs` - API constants, endpoints, and configuration
- `src/connectors.rs` - Added IciciUpi connector registration
- `src/types.rs` - Added IciciUpi to connector imports and convert_connector function
- `backend/domain_types/src/connector_types.rs` - Added IciciUpi to ConnectorEnum
- `backend/domain_types/src/types.rs` - Added iciciupi connector params
- `backend/grpc-api-types/proto/payment.proto` - Added ICICIUPI enum variant

### Technical Details
- Migrated from Hyperswitch/Euler Haskell implementation to UCS v2 Rust
- Uses UCS v2 macro framework for all trait implementations (no manual code)
- Implements proper amount framework using StringMinorUnit converter
- Full type safety with guard rails (Secret<String> for sensitive data)
- Dynamic value extraction from router data (no hardcoded values)
- Supports test_mode for sandbox/production environment switching
- Stub implementations for all unsupported flows with proper error handling

### API Endpoints
- CollectPay: `/MerchantAPI/UPI/v0/CollectPay2/:merchantId`
- Transaction Status: `/MerchantAPI/UPI/v0/TransactionStatus/:merchantId`
- Base URLs:
  - Sandbox: `https://apibankingonesandbox.icicibank.com/api`
  - Production: `https://apibankingone.icicibank.com/api`

### Authentication
- Uses SignatureKey authentication pattern
- Supports merchant_id, sub_merchant_id, terminal_id, and api_key
- Configurable encryption key support for future enhancements

### Status Mapping
- Success codes: "000", "00" -> Charged
- Pending codes: "001", "01" -> AuthenticationPending
- Other codes -> Failure or AuthenticationPending based on context

### Known Limitations
- Authentication parsing currently uses basic implementation (needs production-ready parsing)
- Webhook verification and processing are stubbed (to be implemented in Phase 10)
- Refund flows are stubbed (to be implemented based on requirements)
- Mandate-related flows are stubbed (to be implemented based on requirements)