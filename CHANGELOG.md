# Changelog

## [2024-01-15] - Payu Connector Addition

### Added
- New Payu connector implementation for UCS v2
- Payment methods supported: UPI, UPI Collect, UPI Intent
- Transaction flows: Authorize (UPI payment initiation), PSync (payment status synchronization), RSync (refund status synchronization)
- Support for test and production environments
- Proper error handling and status mapping
- Hash-based authentication using API key and salt
- Webhook support for payment notifications

### Files Created/Modified
- `src/connectors/payu.rs` - Main connector implementation using UCS v2 macro framework
- `src/connectors/payu/transformers.rs` - Request/response transformers for UPI flows
- `src/connectors/payu/constants.rs` - API constants, endpoints, and status mappings
- `src/connectors.rs` - Added connector registration and module exports
- `src/types.rs` - Added Payu to ConnectorEnum with supported payment methods

### Technical Details
- Migrated from Hyperswitch/Euler Haskell implementation
- Uses UCS v2 macro framework for all trait implementations (create_all_prerequisites! and macro_connector_implementation!)
- Implements proper error handling with comprehensive status mapping
- Full type safety with guard rails using domain types
- Amount framework implementation using StringMinorUnit converter
- Hash generation for request authentication using SHA512
- Dynamic extraction of all request data from router data (no hardcoded values)
- Support for UPI VPA validation and transaction processing
- Proper webhook source verification and response handling

### API Integration
- Base URLs: Test (https://test.payu.in) and Production (https://info.payu.in)
- Primary endpoint: /merchant/postservice.php?form=2
- Commands: upi_collect, verify_payment, get_all_refunds_from_txn_ids
- Authentication: API key + salt with SHA512 hash generation
- Request format: Form-encoded with key, command, hash, and var1 parameters

### Payment Flow Support
- **Authorize Flow**: UPI payment initiation with VPA validation
- **PSync Flow**: Payment status verification and synchronization
- **RSync Flow**: Refund status tracking and synchronization
- **Webhook Handling**: Real-time payment status updates

### Security Features
- Hash-based request authentication
- Secret handling for API keys and sensitive data
- IP address and user agent tracking
- Proper error message masking
- Webhook signature validation support

### Compliance
- Supports INR currency for Indian market
- UPI compliance for payment processing
- Proper data handling with PII masking
- Audit trail support with transaction logging