# Changelog

## [2024-01-XX] - TPSL Connector Addition

### Added
- New TPSL connector implementation
- Payment methods supported: UPI (Intent/Collect)
- Transaction flows: Authorize, PSync
- Full UPI payment processing with TPSL API integration
- Support for UPI token generation and transaction processing
- Comprehensive error handling and status mapping
- Proper amount framework implementation using StringMinorUnit

### Files Created/Modified
- `backend/connector-integration/src/connectors/tpsl/mod.rs` - Main connector implementation
- `backend/connector-integration/src/connectors/tpsl/transformers.rs` - Request/response transformers
- `backend/connector-integration/src/connectors/tpsl/constants.rs` - API constants and endpoints
- `backend/connector-integration/src/connectors/tpsl/test.rs` - Test module
- `backend/connector-integration/src/connectors.rs` - Added connector registration
- `backend/connector-integration/src/types.rs` - Added connector to ConnectorEnum and conversion logic
- `backend/domain_types/src/connector_types.rs` - Added Tpsl to ConnectorEnum

### Technical Details
- Migrated from Hyperswitch/Euler Haskell implementation
- Uses UCS v2 macro framework for trait implementations
- Implements proper error handling and status mapping
- Full type safety with guard rails
- UPI-specific business logic preserved from original implementation
- Support for both UPI Intent and Collect flows
- Comprehensive request/response type definitions
- Proper authentication handling with merchant credentials

### API Endpoints
- Production: `https://www.tpsl-india.in/PaymentGateway`
- Test: `https://www.tekprocess.co.in/PaymentGateway`
- UPI Transaction: `/services/UPITransaction`
- UPI Token Generation: `/services/UPITokenGeneration`
- Transaction Details: `/services/TransactionDetailsNew`

### Features
- UPI payment initiation (Intent/Collect)
- Payment status synchronization
- Comprehensive error response handling
- Dynamic merchant and customer data extraction
- Proper amount conversion and currency handling
- Support for webhook callbacks
- Test mode support

### Known Limitations
- Only UPI payment methods supported (as per requirements)
- Card payments, net banking, and wallet payments not implemented
- Refund and RSync flows return NotImplemented errors
- Mandate flows not implemented

### Dependencies
- `serde` for JSON serialization/deserialization
- `chrono` for timestamp handling
- `hyperswitch_masking` for sensitive data handling
- `error_stack` for error handling
- `common_utils` and `domain_types` from UCS framework