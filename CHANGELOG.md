# Changelog

## [2024-01-15] - EaseBuzz Connector Addition

### Added
- New EaseBuzz connector implementation for UCS v2
- Payment methods supported: UPI (UPI Intent, UPI Collect)
- Transaction flows: Authorize, PSync, RSync
- Full UPI payment processing capabilities
- Comprehensive error handling and status mapping
- Support for test and production environments

### Files Created/Modified
- `backend/connector-integration/src/connectors/easebuzz.rs` - Main connector implementation using UCS v2 macro framework
- `backend/connector-integration/src/connectors/easebuzz/transformers.rs` - Request/response transformers for data conversion
- `backend/connector-integration/src/connectors/easebuzz/constants.rs` - API constants, endpoints, and configurations
- `backend/connector-integration/src/connectors.rs` - Already contained EaseBuzz registration
- `backend/domain_types/src/connector_types.rs` - Already contained EaseBuzz in ConnectorEnum
- `backend/domain_types/src/types.rs` - Already contained EaseBuzz in Connectors struct

### Technical Details
- **Migrated from**: Hyperswitch/Euler Haskell implementation
- **Framework**: Uses UCS v2 macro framework for all trait implementations
- **Amount Handling**: StringMinorUnit converter for proper monetary value handling
- **Authentication**: Basic Auth with API key support
- **Hash Generation**: SHA512 hash generation for request security
- **Type Safety**: Full guard rails with Secret<String> for sensitive data, MinorUnit for amounts
- **Error Handling**: Comprehensive error response parsing and status mapping
- **Payment Methods**: UPI-only implementation as specified
- **Flows Implemented**: 
  - Authorize: UPI payment initiation
  - PSync: Payment status synchronization
  - RSync: Refund status synchronization

### API Endpoints
- **Test Environment**: https://testpay.easebuzz.in
- **Production Environment**: https://pay.easebuzz.in
- **Payment Initiate**: /payment/initiateLink
- **Transaction Sync**: /transaction/v1/retrieve
- **Refund Sync**: /transaction/v1/refundSync

### Key Features
- Dynamic request body value extraction from router data (no hardcoded values)
- Proper amount conversion using UCS v2 amount framework
- Customer data extraction using getter functions
- Authentication data extraction from connector_auth_type
- URL extraction using get_router_return_url()
- Transaction ID handling using connector_request_reference_id
- IP address and browser info extraction
- Email and phone number handling with proper types

### Compliance
- ✅ Uses UCS v2 macro framework (mandatory)
- ✅ No manual trait implementations
- ✅ All values extracted dynamically from router data
- ✅ Proper type safety with guard rails
- ✅ Amount framework implementation
- ✅ Connector registration in all required files