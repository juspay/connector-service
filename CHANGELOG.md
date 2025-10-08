# Changelog

## [2024-01-XX] - AirtelMoney Connector Addition

### Added
- New AirtelMoney connector implementation
- Payment methods supported: UPI (Unified Payments Interface)
- Transaction flows: Authorize, PSync, RSync, Refund

### Files Created/Modified
- `src/connectors/airtelmoney.rs` - Main connector implementation
- `src/connectors/airtelmoney/transformers.rs` - Request/response transformers
- `src/connectors/airtelmoney/constants.rs` - API constants and endpoints
- `src/connectors.rs` - Added connector registration
- `src/types.rs` - Added connector to ConnectorEnum
- `backend/domain_types/src/connector_types.rs` - Added AirtelMoney to ConnectorEnum

### Technical Details
- Migrated from Hyperswitch/Euler Haskell implementation
- Uses UCS v2 macro framework for trait implementations
- Implements proper error handling and status mapping
- Full type safety with guard rails
- Supports OTP generation and verification flows
- Implements direct debit and refund functionality
- Includes customer profile fetching and wallet delinking
- Proper amount framework using StringMinorUnit converter
- Dynamic extraction of all request values from router data
- No hardcoded values - all data extracted dynamically

### API Endpoints
- OTP Generation: `/apbnative/partners/:merchantId/customers/:customerId/authRequest`
- OTP Verification: `/apbnative/partners/:merchantId/customers/:customerId/authToken`
- Customer Profile: `/apbnative/p1/customers/:customerId/profile`
- Direct Debit: `/apbnative/p1/customers/:customerId/account/debit`
- Status Inquiry: `/ecom/v2/inquiry`
- Refund: `/ecom/v2/reversal`
- Payment Initiation: `/ecom/v2/initiatePayment`

### Environment Support
- Production: `https://ecom.airtelbank.com`
- Test: `https://apptest.airtelbank.com`
- Status API: `https://ecom.airtelbank.com` (prod) / `https://apbuat.airtelbank.com:5050` (test)