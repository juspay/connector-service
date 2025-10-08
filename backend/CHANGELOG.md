# Changelog

## [2024-01-XX] - PayZapp Connector Addition

### Added
- New PayZapp connector implementation
- Payment methods supported: UPI (UPI Intent/Collect)
- Transaction flows: Authorize, PSync
- Full UCS v2 macro framework compliance

### Files Created/Modified
- `src/connectors/payzapp.rs` - Main connector implementation
- `src/connectors/payzapp/transformers.rs` - Request/response transformers
- `src/connectors/payzapp/constants.rs` - API constants and endpoints (updated)
- `src/connectors.rs` - Added connector registration
- `src/types.rs` - Added connector to ConnectorEnum and convert_connector function
- `proto/payment.proto` - Added PayZapp to Connector enum
- `src/connector_types.rs` - Added PayZapp to ForeignTryFrom implementation

### Technical Details
- Migrated from Hyperswitch/Euler Haskell implementation
- Uses UCS v2 macro framework for trait implementations (mandatory)
- Implements proper error handling and status mapping
- Full type safety with guard rails
- Amount framework using StringMinorUnit converter
- UPI-only payment method support as per requirements
- Dynamic extraction of all request values from router data (no hardcoded values)
- Proper authentication handling via ConnectorAuthType
- Comprehensive stub implementations for unsupported flows

### API Endpoints
- Production: https://app.wibmo.com and https://api.wibmo.com
- Test: https://app.pc.enstage-sas.com and https://api.pc.enstage-sas.com
- Auth endpoint: /payment/merchant/init
- Sync endpoint: /v2/in/txn/iap/wpay/enquiry

### Features
- UPI payment initiation
- Payment status synchronization
- Test/Production environment support
- Message hash generation
- Proper error response handling
- Type-safe amount conversion
- Secret handling for sensitive data