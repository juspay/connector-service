# Changelog

## [2025-01-12] - IciciUpi Connector Addition

### Added
- New IciciUpi connector implementation
- Payment methods supported: UPI (Unified Payments Interface)
- Transaction flows: Authorize (UPI Collect), PSync (Payment Status Sync)

### Files Created/Modified
- `backend/connector-integration/src/connectors/iciciupi.rs` - Main connector implementation
- `backend/connector-integration/src/connectors/iciciupi/transformers.rs` - Request/response transformers
- `backend/connector-integration/src/connectors/iciciupi/constants.rs` - API constants and endpoints
- `backend/connector-integration/src/connectors.rs` - Added connector registration
- `backend/connector-integration/src/types.rs` - Added connector to ConnectorEnum match
- `backend/grpc-api-types/proto/payment.proto` - Added ICICIUPI to gRPC enum
- `backend/domain_types/src/connector_types.rs` - Added IciciUpi to domain enum

### Technical Details
- Migrated from Hyperswitch/Euler Haskell implementation
- Uses UCS v2 macro framework for trait implementations
- Implements proper error handling and status mapping
- Full type safety with guard rails
- Supports both staging and production environments
- Amount framework using StringMinorUnit for proper monetary value handling
- UPI-specific business logic preserved from original implementation

### API Endpoints
- CollectPay: `/MerchantAPI/UPI/v0/CollectPay2/:merchantId`
- Transaction Status: `/MerchantAPI/UPI/v0/TransactionStatus3/:merchantId`
- Base URLs: 
  - Staging: `https://apibankingonesandbox.icicibank.com/api`
  - Production: `https://apibankingone.icicibank.com/api`

### Features
- UPI payment initiation via CollectPay flow
- Payment status synchronization
- Proper authentication with Bearer token
- Error response handling
- Type-safe request/response transformations
- Support for test and production modes