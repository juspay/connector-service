# Fraud Connector Implementation Guide

## Overview

This guide provides detailed instructions for implementing fraud detection connectors in Hyperswitch Prism. **This follows the exact same pattern as PaymentService** - no new patterns are introduced.

**Important Note**: Signifyd and Riskified have **fundamentally different APIs**. This guide covers both with provider-specific sections where needed.

## Prerequisites

- Understanding of Rust trait system
- Familiarity with gRPC and Protocol Buffers
- Knowledge of the fraud detection provider's API
- Review of the payment connector implementations (e.g., `stripe.rs`, `adyen.rs`)

## Key Architecture Principles

### 1. Abstraction Traits in `interfaces` Crate (REQUIRED)

**PaymentService Pattern**: Payment connectors use abstraction traits defined in `interfaces/src/connector_types.rs`. These are marker traits that extend `ConnectorIntegrationV2`.

**Example from stripe.rs**:
```rust
// From interfaces/src/connector_types.rs
pub trait PaymentAuthorizeV2<T: PaymentMethodDataTypes>:
    ConnectorIntegrationV2<
    connector_flow::Authorize,
    PaymentFlowData,
    PaymentsAuthorizeData<T>,
    PaymentsResponseData,
>
{
}

// Connector implementation
impl<T: PaymentMethodDataTypes + ...> connector_types::PaymentAuthorizeV2<T> for Stripe<T> {}
```

**For fraud, you MUST add these traits to `interfaces/src/connector_types.rs`**:

```rust
// ADD TO: interfaces/src/connector_types.rs

pub trait FraudEvaluatePreAuthorizationV2:
    ConnectorIntegrationV2<
    connector_flow::FraudEvaluatePreAuthorization,
    FraudFlowData,
    FraudEvaluatePreAuthorizationRequest,
    FraudEvaluatePreAuthorizationResponse,
>
{
}

pub trait FraudEvaluatePostAuthorizationV2:
    ConnectorIntegrationV2<
    connector_flow::FraudEvaluatePostAuthorization,
    FraudFlowData,
    FraudEvaluatePostAuthorizationRequest,
    FraudEvaluatePostAuthorizationResponse,
>
{
}

pub trait FraudRecordTransactionDataV2:
    ConnectorIntegrationV2<
    connector_flow::FraudRecordTransactionData,
    FraudFlowData,
    FraudRecordTransactionDataRequest,
    FraudRecordTransactionDataResponse,
>
{
}

pub trait FraudRecordFulfillmentDataV2:
    ConnectorIntegrationV2<
    connector_flow::FraudRecordFulfillmentData,
    FraudFlowData,
    FraudRecordFulfillmentDataRequest,
    FraudRecordFulfillmentDataResponse,
>
{
}

pub trait FraudRecordReturnDataV2:
    ConnectorIntegrationV2<
    connector_flow::FraudRecordReturnData,
    FraudFlowData,
    FraudRecordReturnDataRequest,
    FraudRecordReturnDataResponse,
>
{
}

pub trait FraudGetV2:
    ConnectorIntegrationV2<
    connector_flow::FraudGet,
    FraudFlowData,
    FraudGetRequest,
    FraudGetResponse,
>
{
}
```

Then implement in connectors:

```rust
impl connector_types::FraudEvaluatePreAuthorizationV2 for Signifyd {}
impl connector_types::FraudEvaluatePostAuthorizationV2 for Signifyd {}
impl connector_types::FraudRecordTransactionDataV2 for Signifyd {}
impl connector_types::FraudRecordFulfillmentDataV2 for Signifyd {}
impl connector_types::FraudRecordReturnDataV2 for Signifyd {}
impl connector_types::FraudGetV2 for Signifyd {}
```

### 3. Flow Markers Live in `connector_flow.rs`

Following the existing pattern:
- `Authorize`, `PSync`, `Void`, etc. are in `domain_types/src/connector_flow.rs`
- Fraud flow markers (`FraudEvaluatePreAuthorization`, etc.) are also in `connector_flow.rs`

### 4. Domain Types Live in `fraud/` Subdirectory

Following the payouts pattern:
- `payouts/` contains `payouts_types.rs`, `types.rs`, `router_request_types.rs`
- `fraud/` contains `fraud_types.rs`, `types.rs`, `router_request_types.rs`

## Connector Structure

### Required Files

```
crates/integrations/connector-integration/src/connectors/
├── signifyd.rs
├── signifyd/
│   └── transformers.rs
├── riskified.rs
├── riskified/
│   └── transformers.rs
```

**Note**: Unlike simple connectors, fraud connectors SHOULD have `transformers.rs` subdirectories because:
- Request/response mapping is complex
- Provider-specific data structures differ significantly
- Clean separation of concerns

### Connector Setup Prerequisites (REQUIRED)

Following the payment connector pattern, you MUST use the `create_all_prerequisites` macro to set up the connector state before implementing individual flows.

```rust
// In connectors/signifyd.rs (AFTER imports, BEFORE ConnectorCommon impl)

macros::create_all_prerequisites!(
    connector_name: Signifyd,
    generic_type: T,  // Use () if no generic needed
    [],              // No generic bounds for fraud
    api: [
        (
            flow: FraudEvaluatePreAuthorization,
            request_body: SignifydCheckoutRequest,
            response_body: SignifydCheckoutResponse,
            router_data: RouterDataV2<
                FraudEvaluatePreAuthorization,
                FraudFlowData,
                FraudEvaluatePreAuthorizationRequest,
                FraudEvaluatePreAuthorizationResponse
            >,
        ),
        (
            flow: FraudEvaluatePostAuthorization,
            request_body: SignifydTransactionRequest,
            response_body: SignifydTransactionResponse,
            router_data: RouterDataV2<
                FraudEvaluatePostAuthorization,
                FraudFlowData,
                FraudEvaluatePostAuthorizationRequest,
                FraudEvaluatePostAuthorizationResponse
            >,
        ),
        (
            flow: FraudRecordTransactionData,
            request_body: SignifydSaleRequest,
            response_body: SignifydSaleResponse,
            router_data: RouterDataV2<
                FraudRecordTransactionData,
                FraudFlowData,
                FraudRecordTransactionDataRequest,
                FraudRecordTransactionDataResponse
            >,
        ),
        (
            flow: FraudRecordFulfillmentData,
            request_body: SignifydFulfillmentRequest,
            response_body: SignifydFulfillmentResponse,
            router_data: RouterDataV2<
                FraudRecordFulfillmentData,
                FraudFlowData,
                FraudRecordFulfillmentDataRequest,
                FraudRecordFulfillmentDataResponse
            >,
        ),
        (
            flow: FraudRecordReturnData,
            request_body: SignifydReturnRequest,
            response_body: SignifydReturnResponse,
            router_data: RouterDataV2<
                FraudRecordReturnData,
                FraudFlowData,
                FraudRecordReturnDataRequest,
                FraudRecordReturnDataResponse
            >,
        ),
        (
            flow: FraudGet,
            request_body: NoRequestBody,  // GET request has no body
            response_body: SignifydDecisionResponse,
            router_data: RouterDataV2<
                FraudGet,
                FraudFlowData,
                FraudGetRequest,
                FraudGetResponse
            >,
        ),
    ],
    amount_converters: [],  // No special amount converters needed
    member_functions: {
        // Add any connector-wide helper functions here
        pub fn build_headers<F, FCD, Req, Res>(
            &self,
            req: &RouterDataV2<F, FCD, Req, Res>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, IntegrationError> {
            let mut header = vec![(
                "Content-Type".to_string(),
                Self::common_get_content_type(self).to_string().into(),
            )];
            let mut api_key = self.get_auth_header(&req.connector_config)?;
            header.append(&mut api_key);
            Ok(header)
        }
    }
);
```

**Key Points**:
- The `create_all_prerequisites` macro MUST be called before implementing `ConnectorCommon`
- Define all 6 flows in the `api` array
- Each flow maps to specific request/response types defined in transformers
- The `member_functions` block provides shared helpers for all flows

## Signifyd Implementation

### Authentication

**Method**: Basic Auth with Base64-encoded API Key

```rust
impl ConnectorCommon for Signifyd {
    fn get_auth_header(
        &self,
        auth_type: &ConnectorSpecificConfig,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, IntegrationError> {
        let auth = SignifydAuthType::try_from(auth_type).change_context(...)?;
        
        // Base64 encode the API key
        let encoded = BASE64_ENGINE.encode(auth.api_key.peek());
        
        Ok(vec![(
            "Authorization".to_string(),
            format!("Basic {}", encoded).into_masked(),
        )])
    }
}
```

### Currency Unit

```rust
impl ConnectorCommon for Signifyd {
    fn get_currency_unit(&self) -> CurrencyUnit {
        CurrencyUnit::Minor  // Cents, not dollars
    }
}
```

### API Endpoints

| Flow | Endpoint | Method |
|------|----------|--------|
| EvaluatePreAuthorization | `/v3/orders/events/checkouts` | POST |
| EvaluatePostAuthorization | `/v3/orders/events/transactions` | POST |
| RecordTransactionData | `/v3/orders/events/sales` | POST |
| RecordFulfillmentData | `/v3/orders/events/fulfillments` | POST |
| RecordReturnData | `/v3/orders/events/returns/records` | POST |
| Get | `/v3/decisions/{orderId}` | GET |

**⚠️ CORRECTION**: All endpoints require `/v3/orders/events/` prefix (NOT just `/v3/checkouts`, `/v3/sales`, etc.)

### Sample Implementation

```rust
// crates/integrations/connector-integration/src/connectors/signifyd.rs

mod transformers;
mod test;

use domain_types::{
    connector_flow,
    fraud::fraud_types::*,
    fraud::router_request_types::*,
    connector_types,
};
use interfaces::{
    api::ConnectorCommon,
    connector_integration_v2::ConnectorIntegrationV2,
};

pub struct Signifyd;

// ConnectorCommon implementation
impl ConnectorCommon for Signifyd {
    fn id(&self) -> &'static str {
        "signifyd"
    }

    fn get_currency_unit(&self) -> CurrencyUnit {
        CurrencyUnit::Minor
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.signifyd.base_url.as_str()
    }
}

// Abstraction trait implementations
impl connector_types::FraudEvaluatePreAuthorizationV2 for Signifyd {}
impl connector_types::FraudEvaluatePostAuthorizationV2 for Signifyd {}
impl connector_types::FraudRecordTransactionDataV2 for Signifyd {}
impl connector_types::FraudRecordFulfillmentDataV2 for Signifyd {}
impl connector_types::FraudRecordReturnDataV2 for Signifyd {}
impl connector_types::FraudGetV2 for Signifyd {}

// ConnectorIntegrationV2 implementations using macros
// NOTE: All 6 flows must be implemented with separate macro calls

// Flow 1: EvaluatePreAuthorization
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Signifyd,
    curl_request: Json(SignifydCheckoutRequest),
    curl_response: SignifydCheckoutResponse,
    flow_name: FraudEvaluatePreAuthorization,
    resource_common_data: FraudFlowData,
    flow_request: FraudEvaluatePreAuthorizationRequest,
    flow_response: FraudEvaluatePreAuthorizationResponse,
    http_method: Post,
    other_functions: {
        fn get_url(
            &self,
            req: &RouterDataV2<
                FraudEvaluatePreAuthorization,
                FraudFlowData,
                FraudEvaluatePreAuthorizationRequest,
                FraudEvaluatePreAuthorizationResponse
            >,
        ) -> CustomResult<String, IntegrationError> {
            Ok(format!(
                "{}{}",
                self.base_url(&req.resource_common_data.connectors),
                "v3/orders/events/checkouts"
            ))
        }
    }
);

// Flow 2: EvaluatePostAuthorization
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Signifyd,
    curl_request: Json(SignifydTransactionRequest),
    curl_response: SignifydTransactionResponse,
    flow_name: FraudEvaluatePostAuthorization,
    resource_common_data: FraudFlowData,
    flow_request: FraudEvaluatePostAuthorizationRequest,
    flow_response: FraudEvaluatePostAuthorizationResponse,
    http_method: Post,
    other_functions: {
        fn get_url(
            &self,
            req: &RouterDataV2<...>,
        ) -> CustomResult<String, IntegrationError> {
            Ok(format!(
                "{}{}",
                self.base_url(&req.resource_common_data.connectors),
                "v3/orders/events/transactions"
            ))
        }
    }
);

// Flow 3: RecordTransactionData
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Signifyd,
    curl_request: Json(SignifydSaleRequest),
    curl_response: SignifydSaleResponse,
    flow_name: FraudRecordTransactionData,
    resource_common_data: FraudFlowData,
    flow_request: FraudRecordTransactionDataRequest,
    flow_response: FraudRecordTransactionDataResponse,
    http_method: Post,
    other_functions: {
        fn get_url(
            &self,
            req: &RouterDataV2<...>,
        ) -> CustomResult<String, IntegrationError> {
            Ok(format!(
                "{}{}",
                self.base_url(&req.resource_common_data.connectors),
                "v3/orders/events/sales"
            ))
        }
    }
);

// Flow 4: RecordFulfillmentData
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Signifyd,
    curl_request: Json(SignifydFulfillmentRequest),
    curl_response: SignifydFulfillmentResponse,
    flow_name: FraudRecordFulfillmentData,
    resource_common_data: FraudFlowData,
    flow_request: FraudRecordFulfillmentDataRequest,
    flow_response: FraudRecordFulfillmentDataResponse,
    http_method: Post,
    other_functions: {
        fn get_url(
            &self,
            req: &RouterDataV2<...>,
        ) -> CustomResult<String, IntegrationError> {
            Ok(format!(
                "{}{}",
                self.base_url(&req.resource_common_data.connectors),
                "v3/orders/events/fulfillments"
            ))
        }
    }
);

// Flow 5: RecordReturnData
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Signifyd,
    curl_request: Json(SignifydReturnRequest),
    curl_response: SignifydReturnResponse,
    flow_name: FraudRecordReturnData,
    resource_common_data: FraudFlowData,
    flow_request: FraudRecordReturnDataRequest,
    flow_response: FraudRecordReturnDataResponse,
    http_method: Post,
    other_functions: {
        fn get_url(
            &self,
            req: &RouterDataV2<...>,
        ) -> CustomResult<String, IntegrationError> {
            Ok(format!(
                "{}{}",
                self.base_url(&req.resource_common_data.connectors),
                "v3/orders/events/returns/records"
            ))
        }
    }
);

// Flow 6: Get (Decision retrieval)
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Signifyd,
    curl_request: NoRequestBody,  // GET has no body
    curl_response: SignifydDecisionResponse,
    flow_name: FraudGet,
    resource_common_data: FraudFlowData,
    flow_request: FraudGetRequest,
    flow_response: FraudGetResponse,
    http_method: Get,
    other_functions: {
        fn get_url(
            &self,
            req: &RouterDataV2<...>,
        ) -> CustomResult<String, IntegrationError> {
            let order_id = req.request.order_id
                .as_ref()
                .ok_or(IntegrationError::MissingRequiredField { 
                    field: "order_id".to_string() 
                })?;
            Ok(format!(
                "{}v3/decisions/{}",
                self.base_url(&req.resource_common_data.connectors),
                order_id
            ))
        }
    }
);
```

### Transformers Example

```rust
// crates/integrations/connector-integration/src/connectors/signifyd/transformers.rs

#[derive(Debug, Serialize)]
pub struct SignifydCheckoutRequest {
    pub checkout_id: String,
    pub order_id: String,
    pub purchase: SignifydPurchase,
    pub coverage_requests: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SignifydPurchase {
    pub created_at: String,
    pub order_channel: String,
    pub total_price: i64,
    pub currency: String,
    pub products: Vec<SignifydProduct>,
}

#[derive(Debug, Deserialize)]
pub struct SignifydCheckoutResponse {
    pub signifyd_id: i64,
    pub checkout_id: String,
    pub order_id: String,
    pub decision: Option<SignifydDecision>,
}

#[derive(Debug, Deserialize)]
pub struct SignifydDecision {
    pub checkpoint_action: String,  // ACCEPT, REJECT, HOLD, CHALLENGE
    pub score: i32,
}

// ForeignTryFrom implementations
impl ForeignTryFrom<(FraudEvaluatePreAuthorizationRequest, u64)> for SignifydCheckoutRequest {
    fn foreign_try_from(
        (req, created_at): (FraudEvaluatePreAuthorizationRequest, u64),
    ) -> Result<Self, error_stack::Report<ConnectorError>> {
        Ok(Self {
            checkout_id: req.checkout_id.ok_or(...)?,
            order_id: req.order_id,
            purchase: SignifydPurchase {
                created_at: req.purchase.as_ref().map(|p| p.created_at.clone())
                    .unwrap_or_else(|| current_iso8601()),
                order_channel: req.purchase.as_ref().map(|p| format!("{:?}", p.order_channel))
                    .unwrap_or_else(|| "WEB".to_string()),
                total_price: req.amount,
                currency: req.currency,
                products: req.purchase.map(|p| p.products.into_iter().map(|prod| ...).collect())
                    .ok_or(...)?,
            },
            coverage_requests: req.coverage_requests.map(|c| format!("{:?}", c)),
        })
    }
}
```

## Riskified Implementation

### Authentication

**Method**: HMAC-SHA256 Signature (Hex-encoded)

```rust
impl ConnectorCommon for Riskified {
    fn get_auth_header(
        &self,
        auth_type: &ConnectorSpecificConfig,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, IntegrationError> {
        // Riskified auth requires signature computed over request body
        // This is done in build_request, not here
        Ok(vec![])
    }
}

// Signature generation in transformers or helper function
pub fn generate_riskified_signature(
    secret_token: &Secret<String>,
    payload: &str,
) -> CustomResult<String, ConnectorError> {
    use ring::hmac;
    
    let key = hmac::Key::new(
        hmac::HMAC_SHA256,
        secret_token.expose().as_bytes(),
    );
    let signature_value = hmac::sign(&key, payload.as_bytes());
    let digest = signature_value.as_ref();
    
    // HEX encoding (not Base64!)
    Ok(hex::encode(digest))
}
```

### Required Headers

```rust
fn build_request(
    &self,
    req: &RouterDataV2<...>,
) -> CustomResult<Option<Request>, ConnectorError> {
    let auth = RiskifiedAuthType::try_from(&req.connector_config)?;
    let payload = serde_json::to_string(&connector_request)?;
    let signature = generate_riskified_signature(&auth.secret_token, &payload)?;
    
    let headers = vec![
        ("Content-Type".to_string(), "application/json".to_string().into()),
        ("X-RISKIFIED-SHOP-DOMAIN".to_string(), auth.shop_domain.into_masked()),
        ("X-RISKIFIED-HMAC-SHA256".to_string(), signature.into_masked()),
        ("Accept".to_string(), "application/vnd.riskified.com; version=2".to_string().into()),
    ];
    
    // ...
}
```

### Currency Unit

**⚠️ CRITICAL**: Riskified uses **Major Units** (dollars), not Minor Units!

```rust
impl ConnectorCommon for Riskified {
    fn get_currency_unit(&self) -> CurrencyUnit {
        CurrencyUnit::Major  // Dollars, NOT cents!
    }
}
```

### API Endpoints

| Flow | Endpoint | Method | Notes |
|------|----------|--------|-------|
| EvaluatePreAuthorization | `/decide` | POST | Synchronous response |
| EvaluatePostAuthorization | `/decision` OR `/checkout_denied` | POST | Split by success/failure |
| RecordTransactionData | `/decide` | POST | Async submission |
| RecordFulfillmentData | `/fulfill` | POST | |
| RecordReturnData | `/partial_refund` | POST | |
| Get | **NOT SUPPORTED** | - | Returns error or cached webhook data |

**⚠️ CRITICAL**: Riskified does NOT have a GET endpoint for decision retrieval!

### EvaluatePostAuthorization Complexity

Riskified handles post-auth differently:
- **Success**: POST to `/decision`
- **Failure**: POST to `/checkout_denied`

```rust
impl ConnectorIntegrationV2<
    connector_flow::FraudEvaluatePostAuthorization,
    FraudFlowData,
    FraudEvaluatePostAuthorizationRequest,
    FraudEvaluatePostAuthorizationResponse,
> for Riskified {
    fn build_request(
        &self,
        req: &RouterDataV2<...>,
    ) -> CustomResult<Option<Request>, ConnectorError> {
        if req.request.authorization_success {
            // Success -> /decision
            let connector_req = RiskifiedDecisionRequest::from(&req.request);
            // ...
        } else {
            // Failure -> /checkout_denied
            let connector_req = RiskifiedCheckoutDeniedRequest::from(&req.request);
            // ...
        }
    }
    
    fn get_url(
        &self,
        req: &RouterDataV2<...>,
    ) -> CustomResult<String, IntegrationError> {
        let endpoint = if req.request.authorization_success {
            "api/orders/decision"
        } else {
            "api/orders/checkout_denied"
        };
        
        Ok(format!(
            "{}{}",
            self.base_url(&req.resource_common_data.connectors),
            endpoint
        ))
    }
}
```

### Get Method Not Supported

```rust
impl ConnectorIntegrationV2<
    connector_flow::FraudGet,
    FraudFlowData,
    FraudGetRequest,
    FraudGetResponse,
> for Riskified {
    fn build_request(
        &self,
        _req: &RouterDataV2<...>,
    ) -> CustomResult<Option<Request>, ConnectorError> {
        // Riskified doesn't support polling for decisions
        Err(ConnectorError::NotSupported {
            message: "Riskified does not support Get operation. Decisions are delivered via webhooks.".to_string(),
            connector: "riskified",
        })?
    }
}
```

## Webhook Handling

### Signifyd Webhooks

```rust
impl IncomingWebhook for Signifyd {
    fn get_webhook_source_verification_algorithm(&self) -> ... {
        Ok(Box::new(crypto::HmacSha256))
    }
    
    fn get_webhook_source_verification_signature(
        &self,
        request: &IncomingWebhookRequestDetails<'_>,
    ) -> Result<Vec<u8>, error_stack::Report<ConnectorError>> {
        let header_value = get_header_key_value("x-signifyd-sec-hmac-sha256", request.headers)?;
        Ok(header_value.as_bytes().to_vec())
    }
    
    fn get_webhook_source_verification_message(
        &self,
        request: &IncomingWebhookRequestDetails<'_>,
        ...
    ) -> Result<Vec<u8>, error_stack::Report<ConnectorError>> {
        Ok(request.body.to_vec())
    }
}
```

### Riskified Webhooks

```rust
impl IncomingWebhook for Riskified {
    fn get_webhook_source_verification_algorithm(&self) -> ... {
        Ok(Box::new(crypto::HmacSha256))
    }
    
    fn get_webhook_source_verification_signature(
        &self,
        request: &IncomingWebhookRequestDetails<'_>,
    ) -> Result<Vec<u8>, error_stack::Report<ConnectorError>> {
        let header_value = get_header_key_value("x-riskified-hmac-sha256", request.headers)?;
        // Note: Riskified uses Base64 for webhook signatures (different from API auth!)
        Ok(BASE64_ENGINE.decode(header_value)?)
    }
}
```

## Status Mapping

### Signifyd

| checkpointAction | FraudCheckStatus | FraudAction |
|------------------|------------------|-------------|
| `ACCEPT` | `Legit` | `Accept` |
| `REJECT` | `Fraud` | `Reject` |
| `HOLD` | `ManualReview` | `Reject` |
| `CHALLENGE` | `Pending` | - |
| `CREDIT` | `Pending` | - |

### Riskified

| status | FraudCheckStatus | FraudAction |
|--------|------------------|-------------|
| `approved` | `Legit` | `Accept` |
| `declined` | `Fraud` | `Reject` |
| `canceled` | `Fraud` | `Reject` |
| `pending` | `Pending` | - |
| `processing` | `Pending` | - |
| `review` | `ManualReview` | `Reject` |

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signifyd_status_mapping() {
        assert_eq!(
            map_signifyd_status("ACCEPT"),
            FraudCheckStatus::Legit
        );
        assert_eq!(
            map_signifyd_status("REJECT"),
            FraudCheckStatus::Fraud
        );
        assert_eq!(
            map_signifyd_status("HOLD"),
            FraudCheckStatus::ManualReview
        );
    }
    
    #[test]
    fn test_riskified_status_mapping() {
        assert_eq!(
            map_riskified_status("approved"),
            FraudCheckStatus::Legit
        );
        assert_eq!(
            map_riskified_status("declined"),
            FraudCheckStatus::Fraud
        );
    }
    
    #[test]
    fn test_currency_unit_conversion() {
        // Signifyd: Minor units
        let signifyd = Signifyd;
        assert_eq!(signifyd.get_currency_unit(), CurrencyUnit::Minor);
        
        // Riskified: Major units
        let riskified = Riskified;
        assert_eq!(riskified.get_currency_unit(), CurrencyUnit::Major);
    }
}
```

### Integration Test Scenarios

Create YAML scenarios in `crates/internal/ucs-connector-tests/scenarios/fraud/`:

**signifyd/pre_auth_approved.yaml**:
```yaml
name: "Signifyd Pre-Auth Approved"
flow: FraudEvaluatePreAuthorization
connector: signifyd
request:
  merchant_fraud_id: "fraud_test_001"
  order_id: "order_test_001"
  checkout_id: "checkout_test_001"
  amount:
    minor_amount: 10000  # $100.00 in cents
    currency: USD
  purchase:
    created_at: "2026-04-07T10:00:00Z"
    order_channel: WEB
    products:
      - id: "prod_001"
        sku: "SKU001"
        title: "Test Product"
        quantity: 1
        price: 10000
expected:
  status: LEGIT
  recommended_action: ACCEPT
```

**riskified/checkout_decide.yaml**:
```yaml
name: "Riskified Checkout Decide"
flow: FraudEvaluatePreAuthorization
connector: riskified
request:
  merchant_fraud_id: "fraud_test_001"
  order_id: "order_test_001"
  amount:
    minor_amount: 10000
    currency: USD
  # Riskified fields
  line_items:
    - price: "100.00"  # Major units!
      quantity: 1
      title: "Test Product"
      product_type: physical
      product_id: "prod_001"
  vendor_name: "TestMerchant"
  cart_token: "cart_token_001"
  gateway: "stripe"
expected:
  status: PENDING  # Riskified returns async
```

## Common Pitfalls

### 1. NO Abstraction Traits in interfaces
**Wrong**: Not adding `FraudEvaluatePreAuthorizationV2` etc. to `interfaces/src/connector_types.rs`
**Correct**: Add all 6 fraud abstraction traits extending `ConnectorIntegrationV2` (see Section 1.1)

### 2. Missing Prerequisites Macro
**Wrong**: Skipping `create_all_prerequisites!` macro before implementing flows
**Correct**: MUST call `create_all_prerequisites!` with all 6 flows before implementing `ConnectorCommon`

### 3. Wrong Signifyd Endpoints
**Wrong**: `/v3/checkouts`, `/v3/sales`, `/v3/fulfillments`
**Correct**: `/v3/orders/events/checkouts`, `/v3/orders/events/sales`, `/v3/orders/events/fulfillments`

### 3. Currency Unit Confusion
**Signifyd**: `CurrencyUnit::Minor` (cents)
**Riskified**: `CurrencyUnit::Major` (dollars)

### 4. Riskified Get Method
**Wrong**: Implementing Get for Riskified
**Correct**: Return `NotSupported` error or use webhook cache

### 5. Riskified Post-Auth
**Wrong**: Single endpoint for success/failure
**Correct**: Use `/decision` for success, `/checkout_denied` for failure

### 6. HMAC Encoding
**Signifyd Webhook**: Base64 encoded signature
**Riskified API**: Hex encoded signature  
**Riskified Webhook**: Base64 encoded signature

### 7. Missing Required Fields
**Signifyd**: `checkout_id`, `purchase.created_at`, `purchase.order_channel`
**Riskified**: `cart_token`, `vendor_name`, `line_items[]`

### 8. Device Fingerprint
**Spec mentioned this as required** but it's not used by either provider.
- Signifyd uses `browser_ip`, `client_details`
- Riskified uses session tracking via `cart_token`/beacon

## Appendix: Complete Macro Parameters Reference

### `macro_connector_implementation!` Parameters

| Parameter | Required | Description | Example |
|-----------|----------|-------------|---------|
| `connector_default_implementations` | Yes | List of default trait methods to use | `[get_content_type, get_error_response_v2]` |
| `connector` | Yes | Connector struct name | `Signifyd` |
| `curl_request` | Yes | Request body type with encoding | `Json(SignifydCheckoutRequest)` |
| `curl_response` | Yes | Response body type | `SignifydCheckoutResponse` |
| `flow_name` | Yes | Flow marker struct | `FraudEvaluatePreAuthorization` |
| `resource_common_data` | Yes | Flow data type | `FraudFlowData` |
| `flow_request` | Yes | Request data type | `FraudEvaluatePreAuthorizationRequest` |
| `flow_response` | Yes | Response data type | `FraudEvaluatePreAuthorizationResponse` |
| `http_method` | Yes | HTTP method | `Post`, `Get` |
| `generic_type` | No | Generic type parameter | `T` (for payments) |
| `generic_bounds` | No | Bounds for generic | `[PaymentMethodDataTypes + Send + Sync]` |
| `other_functions` | No | Custom impl functions | `get_url`, `get_headers`, etc. |

### Request Body Type Options for `curl_request`

```rust
// JSON encoding (most common)
curl_request: Json(SignifydCheckoutRequest)

// Form URL encoded
curl_request: FormUrlEncoded(TokenRequest)

// Form data (multipart)
curl_request: FormData(FormDataRequest)

// SOAP XML
curl_request: SoapXml(SoapRequestBody)

// Dynamic content type (runtime selection)
curl_request: Dynamic(DynamicRequest)

// No body (for GET requests)
curl_request: NoRequestBody
```

### Complete Response Handling Pattern

Transformers MUST implement `ForeignTryFrom` for response mapping:

```rust
// In transformers.rs

#[derive(Debug, Deserialize)]
pub struct SignifydCheckoutResponse {
    pub signifyd_id: i64,
    pub checkout_id: String,
    pub decision: Option<SignifydDecision>,
}

#[derive(Debug, Deserialize)]
pub struct SignifydDecision {
    pub checkpoint_action: String,
    pub score: i32,
}

// Router data mapping (REQUIRED for macro to work)
impl ForeignTryFrom<
    ResponseRouterData<
        FraudEvaluatePreAuthorization,
        SignifydCheckoutResponse,
        FraudFlowData,
        FraudEvaluatePreAuthorizationRequest,
        FraudEvaluatePreAuthorizationResponse,
    >
> for RouterDataV2<
    FraudEvaluatePreAuthorization,
    FraudFlowData,
    FraudEvaluatePreAuthorizationRequest,
    FraudEvaluatePreAuthorizationResponse,
>
{
    fn foreign_try_from(
        resp: ResponseRouterData<...>
    ) -> Result<Self, error_stack::Report<ConnectorResponseTransformationError>> {
        let response = resp.response;
        let status = map_signifyd_status(
            response.decision.as_ref().map(|d| d.checkpoint_action.as_str())
        );
        let fraud_action = map_signifyd_action(&status);
        
        Ok(Self {
            response: Ok(FraudEvaluatePreAuthorizationResponse {
                fraud_id: response.signifyd_id.to_string(),
                status,
                recommended_action: fraud_action,
                score: response.decision.map(|d| FraudScore {
                    score: d.score,
                    provider_scale: Some("0-1000".to_string()),
                }),
                reasons: vec![],  // Populate from response if available
                case_id: Some(response.checkout_id),
                redirect_url: None,
                connector_metadata: None,
            }),
            ..resp.router_data
        })
    }
}

// Request mapping (REQUIRED)
impl ForeignTryFrom<(FraudEvaluatePreAuthorizationRequest, u64)> for SignifydCheckoutRequest {
    fn foreign_try_from(
        (req, _created_at): (FraudEvaluatePreAuthorizationRequest, u64)
    ) -> Result<Self, error_stack::Report<ConnectorError>> {
        Ok(Self {
            checkout_id: req.session_id.clone(),  // Or generate unique
            order_id: req.order_id.ok_or(ConnectorError::MissingRequiredField)?,
            purchase: SignifydPurchase {
                created_at: iso8601_now(),
                order_channel: "WEB".to_string(),
                total_price: req.amount,
                currency: req.currency.to_string(),
                products: vec![],  // Map from req if available
            },
            coverage_requests: Some("FRAUD".to_string()),
        })
    }
}
```

### Auth Type Configuration

Add auth types to `crates/types-traits/domain_types/src/types.rs`:

```rust
#[derive(Debug, Deserialize)]
pub struct SignifydAuthType {
    pub api_key: Secret<String>,
}

#[derive(Debug, Deserialize)]
pub struct RiskifiedAuthType {
    pub secret_token: Secret<String>,
    pub shop_domain: String,
}

// Add to Connectors struct
#[derive(Debug, Deserialize)]
pub struct Connectors {
    // ... existing connectors
    pub signifyd: ConnectorConfig<SignifydAuthType>,
    pub riskified: ConnectorConfig<RiskifiedAuthType>,
}
```

## Resources

- **Payouts Pattern Reference**: `crates/types-traits/domain_types/src/payouts/`
- **Flow Markers Reference**: `crates/types-traits/domain_types/src/connector_flow.rs`
- **Payment Connector Examples**: `crates/integrations/connector-integration/src/connectors/stripe.rs`
- **Macro Definitions**: `crates/integrations/connector-integration/src/connectors/macros.rs`
- **Abstraction Traits**: `crates/types-traits/interfaces/src/connector_types.rs`
- **Updated Spec**: `docs/plans/fraud/01-fraud-interface-specification.md`

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-04-06 | Initial guide |
| 2.0.0 | 2026-04-07 | **Fixed Signifyd endpoints**, added Riskified auth details, documented currency units, added transformers pattern, clarified Get limitations |
| **3.0.0** | **2026-04-07** | **MAJOR REVISION**: Added abstraction traits requirement, `create_all_prerequisites` macro documentation, complete macro parameters, response handling patterns, auth type configuration, and appendix with full implementation details |
