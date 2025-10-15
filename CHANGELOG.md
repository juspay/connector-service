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
- `src/connectors.rs` - Added connector registration
- `src/types.rs` - Added connector to ConnectorEnum
- `backend/domain_types/src/connector_types.rs` - Added ZaakPay to ConnectorEnum
- `backend/grpc-api-types/proto/payment.proto` - Added ZAAKPAY to proto enum

### Technical Details
- Migrated from Hyperswitch/Euler Haskell implementation
- Uses UCS v2 macro framework for trait implementations
- Implements proper error handling and status mapping
- Full type safety with guard rails
- UPI-only payment method support as specified
- Amount framework using StringMinorUnit converter
- Dynamic value extraction from router data (no hardcoded values)
- Proper authentication handling via connector auth type

### API Endpoints
- `/transact` - Payment initiation (Authorize flow)
- `/check` - Payment status synchronization (PSync/RSync flows)

### Response Code Mapping
- `100` -> AttemptStatus::Charged
- `101` -> AttemptStatus::Pending  
- `102` -> AttemptStatus::Failure