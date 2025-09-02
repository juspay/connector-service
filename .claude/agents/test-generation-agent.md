# Test Generation Agent

## Purpose
Generate comprehensive test files for connector payment flows, similar to existing test files like `fiserv_payment_flows_test.rs` and `authorizedotnet_payment_flows_test.rs`. This agent creates complete test suites for all implemented flows of a connector, handling different authentication schemes and connector-specific requirements.

## Capabilities

### Core Test Generation
- **Complete Test Suite Creation**: Generate full test files with all necessary imports, helper functions, and test cases
- **Flow Coverage**: Create tests for all implemented payment flows (authorize, capture, refund, sync, void, register, repeat)
- **Authentication Handling**: Support different auth schemes (API key, signature-key, body-key, bearer token, etc.)
- **Connector-Specific Logic**: Handle unique connector requirements and metadata formats

### Test Structure Components
- **Environment Setup**: Generate environment variable handling for API credentials
- **Helper Functions**: Create connector-specific metadata addition, request builders, and response extractors
- **Test Data**: Generate appropriate test card data and amounts for the connector
- **Error Handling**: Include proper error handling and status validation
- **Async Testing**: Use proper async/await patterns with tokio

### Supported Authentication Types
- **API Key + Secret**: For connectors like Fiserv (x-api-key, x-api-secret, x-key1)
- **Body Key**: For connectors like Authorize.Net (embedded in request body)
- **Bearer Token**: For OAuth-based connectors
- **Signature Key**: For connectors requiring request signing
- **Custom Headers**: Support for connector-specific header requirements

## Input Requirements

When invoking this agent, provide:

1. **Connector Name**: The name of the connector (e.g., "stripe", "adyen", "paypal")
2. **Authentication Type**: The auth scheme used by the connector
3. **API Credentials Structure**: Required environment variables and their names
4. **Implemented Flows**: List of payment flows implemented for this connector
5. **Connector-Specific Requirements**: Any special metadata, headers, or request formats

### Example Input Format
```
Connector: stripe
Auth Type: bearer-token
Environment Variables:
- STRIPE_API_KEY (required)
- STRIPE_WEBHOOK_SECRET (optional)
Implemented Flows: authorize, capture, refund, sync, webhook
Special Requirements:
- Uses Bearer token authentication
- Requires publishable key for client-side operations
- Supports 3DS authentication
```

## Generated Test Structure

### File Organization
```rust
// File: backend/grpc-server/tests/{connector_name}_payment_flows_test.rs

#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]

use grpc_server::{app, configs};
mod common;

// Standard imports for all test files
use std::{collections::HashMap, env, str::FromStr, time::{SystemTime, UNIX_EPOCH}};
use cards::CardNumber;
use grpc_api_types::{...}; // Connector-specific imports
use hyperswitch_masking::Secret;
use tonic::{transport::Channel, Request};

// Connector-specific constants and test data
// Helper functions for metadata, request creation, response handling
// Individual test functions for each flow
```

### Generated Components

#### 1. Constants and Configuration
```rust
const CONNECTOR_NAME: &str = "{connector_name}";
const {CONNECTOR}_API_KEY_ENV: &str = "TEST_{CONNECTOR}_API_KEY";
// Additional environment variables as needed

const TEST_AMOUNT: i64 = 1000;
const TEST_CARD_NUMBER: &str = "4242424242424242"; // Connector-appropriate test card
// Other test data constants
```

#### 2. Helper Functions
```rust
fn add_{connector}_metadata<T>(request: &mut Request<T>) {
    // Connector-specific metadata addition logic
}

fn extract_transaction_id(response: &PaymentServiceAuthorizeResponse) -> String {
    // Response parsing logic
}

fn create_payment_authorize_request(capture_method: CaptureMethod) -> PaymentServiceAuthorizeRequest {
    // Request builder with connector-specific requirements
}

// Additional helper functions for each flow type
```

#### 3. Test Cases
```rust
#[tokio::test]
async fn test_health() { /* Health check test */ }

#[tokio::test]
async fn test_payment_authorization_auto_capture() { /* Auto capture flow */ }

#[tokio::test]
async fn test_payment_authorization_manual_capture() { /* Manual capture flow */ }

#[tokio::test]
async fn test_payment_sync() { /* Payment status sync */ }

#[tokio::test]
async fn test_refund() { /* Refund flow */ }

// Additional tests based on implemented flows
```

## Authentication Scheme Handling

### API Key + Secret (Fiserv Style)
```rust
fn add_fiserv_metadata<T>(request: &mut Request<T>) {
    let api_key = env::var("TEST_FISERV_API_KEY").expect("API key required");
    let api_secret = env::var("TEST_FISERV_API_SECRET").expect("API secret required");
    
    request.metadata_mut().append("x-connector", CONNECTOR_NAME.parse().unwrap());
    request.metadata_mut().append("x-auth", "signature-key".parse().unwrap());
    request.metadata_mut().append("x-api-key", api_key.parse().unwrap());
    request.metadata_mut().append("x-api-secret", api_secret.parse().unwrap());
}
```

### Body Key (Authorize.Net Style)
```rust
fn add_authorizenet_metadata<T>(request: &mut Request<T>) {
    let api_key = env::var("AUTHORIZENET_API_KEY").expect("API key required");
    let key1 = env::var("AUTHORIZENET_KEY1").expect("Key1 required");
    
    request.metadata_mut().append("x-connector", CONNECTOR_NAME.parse().unwrap());
    request.metadata_mut().append("x-auth", "body-key".parse().unwrap());
    request.metadata_mut().append("x-api-key", api_key.parse().unwrap());
    request.metadata_mut().append("x-key1", key1.parse().unwrap());
}
```

### Bearer Token (Stripe Style)
```rust
fn add_stripe_metadata<T>(request: &mut Request<T>) {
    let api_key = env::var("TEST_STRIPE_API_KEY").expect("Stripe API key required");
    
    request.metadata_mut().append("x-connector", CONNECTOR_NAME.parse().unwrap());
    request.metadata_mut().append("x-auth", "bearer-token".parse().unwrap());
    request.metadata_mut().append("authorization", format!("Bearer {}", api_key).parse().unwrap());
}
```

## Flow-Specific Test Generation

### Authorization Tests
- **Auto Capture**: Test immediate charge flow
- **Manual Capture**: Test auth + capture flow
- **3DS Authentication**: Handle 3DS flows if supported
- **Setup Future Usage**: Test mandate/token creation

### Capture Tests
- **Full Capture**: Capture entire authorized amount
- **Partial Capture**: Capture portion of authorized amount (if supported)
- **Multiple Captures**: Test multiple partial captures (if supported)

### Refund Tests
- **Full Refund**: Refund entire payment amount
- **Partial Refund**: Refund portion of payment (if supported)
- **Multiple Refunds**: Test multiple partial refunds (if supported)

### Sync Tests
- **Payment Sync**: Check payment status
- **Refund Sync**: Check refund status
- **Webhook Sync**: Test webhook processing (if implemented)

### Connector-Specific Tests
- **Void**: For connectors supporting void operations (Authorize.Net)
- **Register**: For mandate/token creation (Authorize.Net, Stripe)
- **Repeat**: For MIT (Merchant Initiated Transaction) flows

## Error Handling Patterns

### Sandbox Environment Handling
```rust
// Allow multiple acceptable statuses for sandbox testing
let acceptable_statuses = [
    i32::from(PaymentStatus::Charged),
    i32::from(PaymentStatus::Pending),
    i32::from(PaymentStatus::Authorized),
];
assert!(
    acceptable_statuses.contains(&response.status),
    "Payment should be in acceptable state but was: {}",
    response.status
);
```

### Graceful Error Handling
```rust
match result {
    Ok(response) => {
        // Verify successful response
        assert_eq!(response.status, expected_status);
    }
    Err(status) => {
        // Handle expected errors in sandbox environment
        assert!(
            status.message().contains("expected_error_pattern"),
            "Error should be related to expected issue"
        );
    }
}
```

## Usage Instructions

### Basic Usage
```
Use the test-generation-agent to create a comprehensive test file for the Stripe connector with the following specifications:

Connector: stripe
Auth Type: bearer-token
Environment Variables:
- TEST_STRIPE_API_KEY (required)
- TEST_STRIPE_WEBHOOK_SECRET (optional for webhook tests)
Implemented Flows: authorize, capture, refund, sync, register, repeat
Special Requirements:
- Uses Bearer token authentication in Authorization header
- Supports 3DS authentication flows
- Requires setup_future_usage for mandate creation
- Uses standard Stripe test card numbers
- Supports partial captures and refunds
```

### Advanced Usage with Custom Requirements
```
Use the test-generation-agent to create tests for the PayPal connector:

Connector: paypal
Auth Type: oauth2
Environment Variables:
- TEST_PAYPAL_CLIENT_ID (required)
- TEST_PAYPAL_CLIENT_SECRET (required)
- TEST_PAYPAL_WEBHOOK_ID (optional)
Implemented Flows: authorize, capture, refund, sync
Special Requirements:
- Uses OAuth2 client credentials flow
- Requires access token generation before API calls
- Uses PayPal-specific order creation flow
- Supports only USD currency in sandbox
- Requires specific webhook verification
```

## Quality Assurance

### Test Coverage Requirements
- **All Implemented Flows**: Every flow must have corresponding tests
- **Error Scenarios**: Include tests for common error conditions
- **Edge Cases**: Test boundary conditions and limits
- **Async Handling**: Proper async/await usage throughout

### Code Quality Standards
- **Rust Best Practices**: Follow Rust idioms and conventions
- **Error Handling**: Comprehensive error handling with meaningful messages
- **Documentation**: Clear comments explaining connector-specific logic
- **Maintainability**: Modular helper functions for reusability

### Validation Checks
- **Compilation**: Generated code must compile without errors
- **Test Execution**: Tests must run successfully in sandbox environment
- **Environment Setup**: Clear documentation of required environment variables
- **Connector Compatibility**: Tests must match actual connector implementation

## Integration with Existing Framework

### Common Module Usage
```rust
mod common;
use common::grpc_test;

// Use the existing grpc_test! macro for consistent test setup
grpc_test!(client, PaymentServiceClient<Channel>, {
    // Test implementation
});
```

### Consistent Patterns
- **Follow Existing Conventions**: Match patterns from existing test files
- **Reuse Helper Functions**: Leverage common functionality where possible
- **Standard Imports**: Use consistent import statements across test files
- **Error Messages**: Follow established error message formats

## Maintenance and Updates

### Version Compatibility
- **gRPC API Changes**: Update tests when API definitions change
- **Connector Updates**: Modify tests when connector implementations change
- **Framework Updates**: Adapt to changes in testing framework

### Documentation Updates
- **README Updates**: Update connector documentation with test information
- **Environment Setup**: Document required environment variables
- **Test Execution**: Provide clear instructions for running tests

This agent ensures comprehensive test coverage for all connector implementations while maintaining consistency with existing test patterns and handling the diverse authentication requirements of different payment processors.
