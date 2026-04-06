# Fraud Connector Implementation Guide

## Overview

This guide provides detailed instructions for implementing fraud detection connectors in Hyperswitch Prism. Use this as a reference when adding support for new fraud detection providers.

## Prerequisites

- Understanding of Rust trait system
- Familiarity with gRPC and Protocol Buffers
- Knowledge of the fraud detection provider's API

## Connector Structure

### Required Files

1. **Connector Implementation**: `crates/integrations/connector-integration/src/connectors/{connector_name}.rs`
2. **Transformers**: `crates/integrations/connector-integration/src/connectors/{connector_name}/transformers.rs` (optional, for complex transformations)
3. **Test Scenarios**: `crates/internal/ucs-connector-tests/scenarios/fraud/{connector_name}/`

### Directory Layout

```
crates/integrations/connector-integration/src/connectors/
├── {connector_name}.rs           # Main connector implementation
└── {connector_name}/
    ├── transformers.rs           # Request/response transformations
    └── types.rs                  # Connector-specific types (optional)
```

## Implementation Steps

### Step 1: Implement `ConnectorCommon`

Every fraud connector must implement the `ConnectorCommon` trait:

```rust
use interfaces::api::ConnectorCommon;

pub struct MyFraudConnector;

impl ConnectorCommon for MyFraudConnector {
    fn id(&self) -> &'static str {
        "my_connector"  // Lowercase, unique identifier
    }

    fn get_currency_unit(&self) -> CurrencyUnit {
        CurrencyUnit::Minor  // or CurrencyUnit::Base
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/json"  // or "application/xml", etc.
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.my_connector.base_url.as_str()
    }

    fn build_error_response(
        &self,
        res: Response,
        _event_builder: Option<&mut Event>,
    ) -> CustomResult<ErrorResponse, ConnectorError> {
        // Parse connector-specific error format
        // Return standardized ErrorResponse
    }
}
```

### Step 2: Implement Each Fraud Flow

For each of the 7 fraud flows, implement `ConnectorIntegrationV2`:

#### 2.1 Sale Flow

```rust
use interfaces::fraud::FraudSaleV2;

impl ConnectorIntegrationV2<
    connector_flow::FraudSale,
    FraudFlowData,
    FraudSaleData,
    FraudSaleResponse,
> for MyFraudConnector {
    fn get_headers(
        &self,
        req: &RouterData<..., FraudSaleData, FraudSaleResponse>,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        // Build HTTP headers
        // Include authentication headers
        // Set content-type
    }

    fn get_url(
        &self,
        req: &RouterData<..., FraudSaleData, FraudSaleResponse>,
        connectors: &Connectors,
    ) -> CustomResult<String, ConnectorError> {
        // Construct endpoint URL
        // May vary by environment (sandbox vs production)
    }

    fn build_request(
        &self,
        req: &RouterData<..., FraudSaleData, FraudSaleResponse>,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, ConnectorError> {
        // Transform FraudSaleData to connector-specific request
        // Serialize to JSON/XML
        // Return Request object
    }

    fn handle_response(
        &self,
        data: &RouterData<..., FraudSaleData, FraudSaleResponse>,
        res: Response,
    ) -> CustomResult<FraudSaleResponse, ConnectorError> {
        // Parse connector response
        // Transform to FraudSaleResponse
        // Handle success and error cases
    }
}

impl FraudSaleV2 for MyFraudConnector {}
```

#### 2.2 Checkout Flow (Pre-Auth)

```rust
use interfaces::fraud::FraudCheckoutV2;

impl ConnectorIntegrationV2<
    connector_flow::FraudCheckout,
    FraudFlowData,
    FraudCheckoutData,
    FraudCheckoutResponse,
> for MyFraudConnector {
    // Implementation similar to Sale
    // Key difference: includes payment_method data
    // Returns decision: Accept/Reject/Review/Challenge
}

impl FraudCheckoutV2 for MyFraudConnector {}
```

#### 2.3 Transaction Flow (Post-Auth)

```rust
use interfaces::fraud::FraudTransactionV2;

impl ConnectorIntegrationV2<
    connector_flow::FraudTransaction,
    FraudFlowData,
    FraudTransactionData,
    FraudTransactionResponse,
> for MyFraudConnector {
    // Implementation includes authorization result
    // May include error codes from payment processor
}

impl FraudTransactionV2 for MyFraudConnector {}
```

#### 2.4 Fulfillment Flow

```rust
use interfaces::fraud::FraudFulfillmentV2;

impl ConnectorIntegrationV2<
    connector_flow::FraudFulfillment,
    FraudFlowData,
    FraudFulfillmentData,
    FraudFulfillmentResponse,
> for MyFraudConnector {
    // Send shipping/fulfillment information
    // Include tracking numbers
    // Update case status
}

impl FraudFulfillmentV2 for MyFraudConnector {}
```

#### 2.5 RecordReturn Flow

```rust
use interfaces::fraud::FraudRecordReturnV2;

impl ConnectorIntegrationV2<
    connector_flow::FraudRecordReturn,
    FraudFlowData,
    FraudRecordReturnData,
    FraudRecordReturnResponse,
> for MyFraudConnector {
    // Record return/refund information
    // Update fraud model
}

impl FraudRecordReturnV2 for MyFraudConnector {}
```

#### 2.6 Get Flow (Sync)

```rust
use interfaces::fraud::FraudGetV2;

impl ConnectorIntegrationV2<
    connector_flow::FraudGet,
    FraudFlowData,
    FraudGetData,
    FraudGetResponse,
> for MyFraudConnector {
    // Query current fraud check status
    // Used for polling when webhooks unavailable
}

impl FraudGetV2 for MyFraudConnector {}
```

#### 2.7 Cancel Flow

```rust
use interfaces::fraud::FraudCancelV2;

impl ConnectorIntegrationV2<
    connector_flow::FraudCancel,
    FraudFlowData,
    FraudCancelData,
    FraudCancelResponse,
> for MyFraudConnector {
    // Cancel pending fraud check
    // Clean up resources
}

impl FraudCancelV2 for MyFraudConnector {}
```

### Step 3: Implement Combined Trait

```rust
use interfaces::fraud::FraudConnectorTrait;

impl FraudConnectorTrait for MyFraudConnector {}
```

### Step 4: Register Connector

Add to `crates/integrations/connector-integration/src/connectors.rs`:

```rust
pub mod my_connector;

// In the connector registry function
pub fn get_fraud_connector(name: &str) -> Option<Box<dyn FraudConnectorTrait>> {
    match name {
        "my_connector" => Some(Box::new(my_connector::MyFraudConnector)),
        _ => None,
    }
}
```

## Data Transformation Patterns

### Request Transformation

```rust
// Transform internal type to connector request
impl From<FraudCheckoutData> for MyConnectorCheckoutRequest {
    fn from(data: FraudCheckoutData) -> Self {
        Self {
            amount: data.amount as f64 / 100.0,  // Convert minor to base
            currency: data.currency.to_string(),
            customer_email: data.customer.map(|c| c.email).flatten(),
            // ... other fields
        }
    }
}
```

### Response Transformation

```rust
// Transform connector response to internal type
impl From<MyConnectorCheckoutResponse> for FraudCheckoutResponse {
    fn from(res: MyConnectorCheckoutResponse) -> Self {
        Self {
            fraud_check_id: res.check_id,
            status: res.decision.into(),
            recommended_action: res.action.into(),
            score: res.risk_score.map(|s| FraudScore {
                score: s,
                risk_level: res.risk_level,
                threshold: None,
            }),
            reasons: res.signals.into_iter().map(|s| FraudReason {
                code: s.code,
                message: s.description,
                description: None,
            }).collect(),
            case_id: res.case_id,
            redirect_url: None,
            connector_metadata: None,
        }
    }
}
```

## Error Handling

### Common Error Patterns

```rust
fn build_error_response(
    &self,
    res: Response,
    _event_builder: Option<&mut Event>,
) -> CustomResult<ErrorResponse, ConnectorError> {
    // Parse connector error format
    let error_body: MyConnectorError = res
        .response
        .parse_struct("MyConnectorError")
        .change_context(ConnectorError::ResponseDeserializationFailed)?;

    Ok(ErrorResponse {
        status_code: res.status_code,
        code: error_body.error_code,
        message: error_body.message,
        reason: error_body.details,
        attempt_status: Some(AttemptStatus::Failure),
        connector_transaction_id: error_body.transaction_id,
        network_advice_code: None,
        network_decline_code: None,
        network_error_message: None,
    })
}
```

## Webhook Handling

If the fraud provider supports webhooks:

```rust
use interfaces::connector_types::IncomingWebhook;

impl IncomingWebhook for MyFraudConnector {
    fn get_event_type(
        &self,
        request: RequestDetails,
        _secrets: Option<ConnectorWebhookSecrets>,
        _config: Option<ConnectorSpecificConfig>,
    ) -> Result<EventType, error_stack::Report<ConnectorError>> {
        // Parse webhook payload
        // Determine event type
        // Return appropriate EventType
    }

    fn process_fraud_webhook(
        &self,
        request: RequestDetails,
        _secrets: Option<ConnectorWebhookSecrets>,
        _config: Option<ConnectorSpecificConfig>,
    ) -> Result<FraudWebhookDetailsResponse, error_stack::Report<ConnectorError>> {
        // Parse fraud-specific webhook
        // Return FraudWebhookDetailsResponse
    }
}
```

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checkout_request_transformation() {
        let data = FraudCheckoutData {
            amount: 10000,
            currency: Currency::USD,
            // ...
        };

        let request: MyConnectorCheckoutRequest = data.into();

        assert_eq!(request.amount, 100.0);
        assert_eq!(request.currency, "USD");
    }
}
```

### Integration Tests

Create test scenarios in `crates/internal/ucs-connector-tests/scenarios/fraud/my_connector/`:

```yaml
# checkout_approved.yaml
name: "Fraud Checkout - Approved"
flow: FraudCheckout
connector: my_connector
request:
  amount:
    minor_amount: 10000
    currency: USD
  # ... other fields
expected:
  status: APPROVED
  recommended_action: ACCEPT
```

## Best Practices

### 1. Idempotency
Ensure requests can be safely retried:
```rust
fn get_headers(&self, ...) -> CustomResult<...> {
    let mut headers = vec![
        ("Idempotency-Key".to_string(), req.idempotency_key.masked()),
    ];
    // ...
}
```

### 2. Timeouts
Respect provider timeout requirements:
```rust
fn build_request(&self, ...) -> CustomResult<Option<Request>> {
    Ok(Some(Request {
        // ...
        timeout: Some(Duration::from_secs(30)),
    }))
}
```

### 3. Logging
Use structured logging for debugging:
```rust
fn handle_response(&self, data, res) -> CustomResult<...> {
    logger::debug!("Fraud provider response: {:?}", res);
    // ...
}
```

### 4. Connector State
Use `ConnectorState` for session management:
```rust
fn handle_response(&self, data, res) -> CustomResult<FraudCheckoutResponse> {
    let mut response: FraudCheckoutResponse = /* ... */;
    
    // Pass through state for next request
    response.connector_state = data.connector_state.clone();
    
    Ok(response)
}
```

## Common Pitfalls

### 1. Currency Units
Always verify if provider uses base or minor currency units:
```rust
// Wrong
amount: data.amount as f64  // If data.amount is in minor units

// Correct
amount: data.amount as f64 / 100.0  // Convert minor to base
```

### 2. Time Zones
Ensure timestamps are in the correct format:
```rust
// ISO 8601 format
created_at: Utc::now().to_rfc3339(),
```

### 3. Empty vs Missing Fields
Distinguish between null and not present:
```rust
// Use Option for truly optional fields
optional_field: Option<String>,

// Use default value for fields that should always exist
required_field: String,
```

## Provider-Specific Notes

### Signifyd
- Uses team-based authentication
- Checkout API returns synchronous decision
- Fulfillment updates are asynchronous

### Riskified
- Requires HMAC signature for authentication
- Supports pre-auth and post-auth flows
- Case management through dashboard

### CyberSource Decision Manager
- Integrated with payment processing
- Uses merchant ID + API key auth
- Supports custom rules

## Resources

- **Existing Connectors**: Reference `crates/integrations/connector-integration/src/connectors/`
- **Test Examples**: Reference `crates/internal/ucs-connector-tests/scenarios/`
- **Hyperswitch FRM Docs**: https://docs.hyperswitch.io/integration-guide/workflows/fraud-and-risk-management
