# Changelog

## [2024-01-XX] - Paytm Connector Migration to UCS v2

### Added
- Complete Paytm connector implementation migrated from Haskell euler-api-txns to UCS v2 (Rust)
- Payment methods supported: UPI Intent, UPI Collect
- Transaction flows: CreateSessionToken, Authorize, PSync
- Full UCS v2 macro framework compliance - no manual trait implementations
- Proper error handling and status mapping from original Haskell implementation
- Complete type safety with guard rails (Secret<String>, MinorUnit, Email, etc.)

### Files Created/Modified
- `src/connectors/paytm.rs` - Main connector implementation using UCS v2 macros
- `src/connectors/paytm/transformers.rs` - Request/response transformers with comprehensive type mappings
- `src/connectors/paytm/constants.rs` - API constants and endpoints
- `src/connectors.rs` - Already had Paytm connector registered
- `src/types.rs` - Paytm already registered in ConnectorEnum

### Technical Details
- **Mandatory UCS v2 Macro Framework**: Uses `create_all_prerequisites!` and `macro_connector_implementation!` macros exclusively
- **No Manual Implementations**: All trait implementations handled by macros as required
- **UPI-Only Implementation**: Focused on UPI Intent and Collect flows as specified
- **Amount Framework**: Uses StringMajorUnit converter for Paytm's major unit amount format
- **Dynamic Data Extraction**: All request values extracted from router data (no hardcoded values)
- **Signature Generation**: Implements Paytm's exact signature algorithm with AES-CBC encryption
- **Status Mapping**: Comprehensive mapping of Paytm result codes to AttemptStatus
- **Error Handling**: Multi-format error response parsing (session token, callback, standard JSON)

### API Endpoints
- CreateSessionToken: `/theia/api/v1/initiateTransaction`
- Authorize: `/theia/api/v1/processTransaction` 
- PSync: `/v3/order/status`

### Security Features
- AES-128/192/256-CBC encryption with fixed IV from PayTM v2 specification
- SHA-256 signature generation with random salt
- Secret<String> wrapping for all sensitive data
- Proper type safety for all monetary values using MinorUnit

### Compliance
- ✅ Uses mandatory UCS v2 macro framework
- ✅ No manual trait implementations
- ✅ All request values extracted dynamically from router data
- ✅ Proper amount framework implementation
- ✅ Complete type safety with guard rails
- ✅ Registered in ConnectorEnum and connectors.rs
- ✅ Comprehensive error handling
- ✅ UPI and sync flows only as specified