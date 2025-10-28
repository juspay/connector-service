# Changelog

## [2025-01-XX] - Billdesk Connector Addition

### Added
- New Billdesk connector implementation for UCS v2
- Payment methods supported: UPI Collect, UPI Intent
- Transaction flows: Authorize, PSync (Payment Status Sync)
- Full integration with UCS v2 macro framework
- Support for Billdesk's merchant authentication using merchant ID and checksum key
- Dynamic request/response handling for UPI payment flows
- Proper error handling and status mapping
- Type-safe implementation with guard rails

### Files Created/Modified
- `src/connectors/billdesk.rs` - Main connector implementation with UCS v2 macros
- `src/connectors/billdesk/transformers.rs` - Request/response transformers and data structures
- `src/connectors/billdesk/constants.rs` - API constants and endpoints
- `src/connectors.rs` - Added Billdesk connector registration
- `src/types.rs` - Added Billdesk to connector conversion logic
- `backend/domain_types/src/connector_types.rs` - Added Billdesk to ConnectorEnum

### Technical Details
- Migrated from Hyperswitch/Euler Haskell implementation
- Uses UCS v2 macro framework for all trait implementations
- Implements proper amount handling using StringMinorUnit converter
- Supports test and production environments with different base URLs
- Dynamic endpoint selection based on payment method type
- Comprehensive error response handling
- Full webhook support structure (implementation pending)
- Source verification stubs for all flows (Phase 10 implementation pending)

### API Endpoints
- UPI Initiate: `https://api.billdesk.com/pgidsk/PGIDirectRequest?reqid=BDRDF011`
- Default/Net Banking: `https://api.billdesk.com/pgidsk/PGIDirectRequest?reqid=BDRDF002`
- Test Environment: `https://uat.billdesk.com/pgidsk/PGIDirectRequest`
- Production Environment: `https://www.billdesk.com/pgidsk/PGIDirectRequest`

### Authentication
- Uses SignatureKey authentication pattern with merchant_id and checksum_key
- Custom authentication headers support
- Checksum-based request integrity validation

### Payment Flow Support
- ✅ Authorize (UPI Collect/Intent)
- ✅ PSync (Payment Status Sync)
- ⏳ Webhook processing (structure ready, implementation pending)
- ⏳ Additional flows (stubs implemented)

### Compliance
- Follows UCS v2 macro framework requirements
- Implements proper type safety with domain types
- Uses Secret<> for sensitive data handling
- Proper amount conversion with MinorUnit framework
- Complete error handling and status mapping