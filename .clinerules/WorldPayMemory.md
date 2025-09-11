# WorldPay Vantiv Connector - Authorize Flow Implementation Memory

## Overview
WorldPay Vantiv (also known as Worldpay CNP API) is a robust XML-based interface used to process online (card-not-present) transactions. This document captures the complete authorize flow implementation in Hyperswitch.

## Connector Architecture

### Main Connector Structure
- **File**: `hyperswitch/crates/hyperswitch_connectors/src/connectors/worldpayvantiv.rs`
- **Connector Name**: "worldpayvantiv"
- **API Type**: XML-based REST API
- **Currency Unit**: Minor (e.g., cents)
- **Content Type**: "text/xml"

### Key Traits Implemented
```rust
impl api::Payment for Worldpayvantiv {}
impl api::PaymentAuthorize for Worldpayvantiv {}
impl api::PaymentSync for Worldpayvantiv {}
impl api::PaymentCapture for Worldpayvantiv {}
impl api::PaymentVoid for Worldpayvantiv {}
impl api::MandateSetup for Worldpayvantiv {}
```

## Authorize Flow Implementation

### 1. Authentication Structure
```rust
pub struct WorldpayvantivAuthType {
    pub user: Secret<String>,           // API username
    pub password: Secret<String>,       // API password  
    pub merchant_id: Secret<String>,    // Merchant ID
}
```
- Uses Basic Authentication with Base64 encoded credentials
- Authentication header format: `Basic {base64(user:password)}`

### 2. Request Structure (CnpOnlineRequest)

#### Main XML Structure
```xml
<cnpOnlineRequest version="12.23" xmlns="http://www.vantivcnp.com/schema" merchantId="{merchant_id}">
    <authentication>
        <user>{username}</user>
        <password>{password}</password>
    </authentication>
    <authorization>{auth_data}</authorization> <!-- For Auth flow -->
    <sale>{sale_data}</sale>                   <!-- For Sale flow -->
</cnpOnlineRequest>
```

#### Authorization Structure
Key fields in the Authorization struct:
- `id`: Transaction ID with operation prefix (e.g., "auth_{merchant_txn_id}")
- `report_group`: Report grouping for transaction categorization
- `order_id`: Connector request reference ID
- `amount`: Payment amount in minor units
- `order_source`: Determined by payment method (Ecommerce, ApplePay, AndroidPay, etc.)
- `card`: Card data for regular card payments
- `token`: Tokenization data for mandate/recurring payments
- `enhanced_data`: L2/L3 data for corporate cards

### 3. Payment Method Support

#### Supported Card Networks
```rust
vec![
    common_enums::CardNetwork::AmericanExpress,
    common_enums::CardNetwork::DinersClub,
    common_enums::CardNetwork::JCB,
    common_enums::CardNetwork::Mastercard,
    common_enums::CardNetwork::Visa,
    common_enums::CardNetwork::Discover,
]
```

#### Card Data Structure
```rust
pub struct WorldpayvantivCardData {
    pub card_type: WorldpayvativCardType,  // VI, MC, AX, DI, DC, JC
    pub number: cards::CardNumber,
    pub exp_date: Secret<String>,          // MMYY format
    pub card_validation_num: Option<Secret<String>>, // CVV
}
```

#### Wallet Support
- **Apple Pay**: Supports cryptogram-based authentication
- **Google Pay**: Supports cryptogram-based authentication
- Both wallets require payment method token decryption

### 4. Operation Flow Types

#### Transaction Types
```rust
pub enum OperationId {
    Sale,      // Direct capture
    Auth,      // Authorization only
    Capture,   // Capture authorized payment
    Void,      // Void authorization
    VoidPC,    // Void post-capture
    Refund,    // Refund transaction
}
```

#### Flow Decision Logic
```rust
let (authorization, sale) = if item.router_data.request.is_auto_capture()? && item.amount != MinorUnit::zero() {
    // Auto-capture flow - creates Sale transaction
    (None, Some(Sale { ... }))
} else {
    // Manual capture flow - creates Authorization transaction
    (Some(Authorization { ... }), None)
}
```

### 5. Mandate/Recurring Payment Support

#### Processing Types
```rust
pub enum VantivProcessingType {
    InitialCOF,           // Initial Credential on File
    MerchantInitiatedCOF, // Merchant Initiated COF
}
```

#### Mandate Flow Logic
- **Customer Initiated**: Uses `InitialCOF` processing type
- **Merchant Initiated**: Uses `MerchantInitiatedCOF` with network transaction ID
- **Token Based**: Uses connector mandate ID as token

### 6. Response Handling

#### Response Structure
```rust
pub struct CnpOnlineResponse {
    pub version: String,
    pub response_code: String,
    pub message: String,
    pub authorization_response: Option<PaymentResponse>,
    pub sale_response: Option<PaymentResponse>,
    // ... other response types
}
```

#### Payment Response Details
```rust
pub struct PaymentResponse {
    pub id: String,
    pub cnp_txn_id: String,           // Connector transaction ID
    pub order_id: String,             // Reference ID
    pub response: WorldpayvantivResponseCode,
    pub message: String,
    pub auth_code: Option<Secret<String>>,
    pub token_response: Option<TokenResponse>,    // For mandates
    pub network_transaction_id: Option<Secret<String>>,
    pub approved_amount: Option<MinorUnit>,
    pub fraud_result: Option<FraudResult>,        // AVS, CVV results
}
```

### 7. Status Mapping

#### Authorization Status Mapping
```rust
fn get_attempt_status(flow: WorldpayvantivPaymentFlow, response: WorldpayvantivResponseCode) -> AttemptStatus {
    match response {
        WorldpayvantivResponseCode::Approved => match flow {
            WorldpayvantivPaymentFlow::Sale => AttemptStatus::Pending,
            WorldpayvantivPaymentFlow::Auth => AttemptStatus::Authorizing,
        },
        // ... error codes map to failure statuses
    }
}
```

#### Key Response Codes
- `000`: Approved
- `010`: Partially Approved
- `001`: Transaction Received
- `110`: Insufficient Funds
- `350`: Generic Decline
- `301`: Invalid Account Number

### 8. Error Handling

#### Error Response Structure
- Deserializes XML error responses
- Maps connector-specific error codes to standard error format
- Includes network decline codes from enhanced auth response
- Preserves connector transaction ID for failed transactions

### 9. Enhanced Features

#### L2/L3 Data Support
```rust
pub struct EnhancedData {
    pub customer_reference: Option<String>,
    pub sales_tax: Option<MinorUnit>,
    pub tax_exempt: Option<bool>,
    pub discount_amount: Option<MinorUnit>,
    pub shipping_amount: Option<MinorUnit>,
    pub line_item_data: Option<Vec<LineItemData>>,
}
```

#### Fraud Detection Integration
- AVS (Address Verification System) results
- CVV validation results
- Advanced fraud screening results
- Risk scoring integration

### 10. Configuration Requirements

#### Connector Metadata
```rust
pub struct WorldpayvantivMetadataObject {
    pub report_group: String,                    // Required for all transactions
    pub merchant_config_currency: Currency,     // Must match transaction currency
}
```

#### Payment Metadata (Optional)
```rust
pub struct WorldpayvantivPaymentMetadata {
    pub report_group: Option<String>,           // Override default report group
}
```

### 11. Validation Rules

#### Pre-request Validations
- 3DS not supported (throws error if attempted)
- Currency must match merchant config currency
- Transaction ID limited to 28 characters
- Customer ID limited to 50 characters

#### Amount Validations
- Zero amount allowed only for setup mandate flows
- Partial authorization support configurable
- Currency conversion handled automatically

### 12. Testing Structure

#### Test Coverage (from worldpayvantiv.rs test file)
- Authorization flow tests
- Auto-capture flow tests
- Manual capture flow tests
- Void/refund flow tests
- Sync operation tests
- Error scenario tests
- Partial payment tests

#### Key Test Scenarios
- Successful authorization and capture
- Payment synchronization
- Void authorized payments
- Refund captured payments
- Invalid card data handling
- Expiry validation
- Amount validation

## Integration Points

### Hyperswitch Integration
- Implements standard Hyperswitch connector interfaces
- Uses XML serialization/deserialization utilities
- Integrates with router data transformation patterns
- Supports connector-specific response metadata

### External Dependencies
- Base64 encoding for authentication
- XML parsing and generation
- Time handling for date conversions
- Network transaction ID management

## Security Considerations

### Authentication Security
- Credentials stored as Secret types
- Basic auth with secure transmission
- Merchant ID validation

### Data Protection
- PCI-compliant card data handling
- Sensitive data masking in logs
- Secure token management for mandates

## Operational Considerations

### Monitoring and Logging
- Transaction ID correlation
- Response time tracking
- Error rate monitoring
- Fraud result logging

### Troubleshooting
- Detailed error response mapping
- Network transaction ID tracking
- Connector status preservation
- Debug information in failed transactions
