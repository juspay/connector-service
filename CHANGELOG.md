# Changelog

## [2024-01-XX] - ZaakPay Connector Addition

### Added
- New ZaakPay connector implementation
- Payment methods supported: UPI
- Transaction flows: Authorize, PSync, RSync

### Files Created/Modified
- `src/connectors/zaakpay.rs` - Main connector implementation
- `src/connectors/zaakpay/transformers.rs` - Request/response transformers
- `src/connectors/zaakpay/constants.rs` - API constants and endpoints
- `src/connectors.rs` - Added connector registration (already existed)
- `src/types.rs` - Added connector to ConnectorEnum (already existed)

### Technical Details
- Migrated from Hyperswitch/Euler Haskell implementation
- Uses UCS v2 macro framework for trait implementations
- Implements proper error handling and status mapping
- Full type safety with guard rails
- Supports UPI payment method only
- Implements checksum generation and verification
- Supports test and live modes
- Proper amount handling using StringMinorUnit converter

### API Endpoints
- Authorize: `/transaction/.do`
- Status Check: `/status.do`
- Base URL: `https://api.zaakpay.com`

### Response Code Mapping
- 200: Success (Charged)
- 201/202: Pending
- 100: Authentication Failed
- 101/102/103: Failure/Invalid Request

### Transaction Status Mapping
- success: Charged/Success
- pending: Pending
- failure: Failure