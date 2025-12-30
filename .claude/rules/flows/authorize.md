---
paths:
  - backend/connector-integration/src/connectors/**/*.rs
---
# Authorize Flow Pattern

## Structure Template

```
backend/connector-integration/src/connectors/
├── {connector_name}.rs           # Main connector implementation
└── {connector_name}/
    └── transformers.rs           # Data transformation logic
```

## Macro-Based Implementation

```rust
macros::create_all_prerequisites!(
    connector_name: {ConnectorName},
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: {ConnectorName}AuthorizeRequest<T>,
            response_body: {ConnectorName}AuthorizeResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        // ... other flows
    ],
    amount_converters: [amount_converter: {AmountUnit}],
    member_functions: { ... }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: {ConnectorName},
    curl_request: Json({ConnectorName}AuthorizeRequest),
    curl_response: {ConnectorName}AuthorizeResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(&self, req: &...) -> ... { self.build_headers(req) }
        fn get_url(&self, req: &...) -> ... {
            Ok(format!("{}/{endpoint}", self.connector_base_url_payments(req)))
        }
    }
);
```

## Request Transformer

```rust
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<&RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>
    for {ConnectorName}AuthorizeRequest<T>
{
    fn try_from(router_data: &...) -> Result<Self, Self::Error> {
        Ok(Self {
            // CRITICAL: Extract from router_data, NEVER hardcode
            reference_id: router_data.connector_request_reference_id.clone(),
            amount: router_data.request.amount,  // MinorUnit, converter handles it
            currency: router_data.request.currency,
            payment_method: /* extract from router_data.request.payment_method_data */,
        })
    }
}
```

## Response Transformer

```rust
impl TryFrom<{ConnectorName}AuthorizeResponse> for PaymentsResponseData {
    fn try_from(response: ...) -> Result<Self, Self::Error> {
        let status = match response.status.as_str() {
            "success" | "succeeded" | "completed" => enums::AttemptStatus::Charged,
            "authorized" | "requires_capture" => enums::AttemptStatus::Authorized,
            "pending" | "processing" => enums::AttemptStatus::Pending,
            "failed" | "declined" => enums::AttemptStatus::Failure,
            _ => enums::AttemptStatus::Pending,  // Unknown → Pending
        };
        // ...
    }
}
```

## Placeholder Reference

| Placeholder | Replace With |
|-------------|-------------|
| `{ConnectorName}` | PascalCase name (e.g., `Stripe`) |
| `{connector_name}` | snake_case name (e.g., `stripe`) |
| `{AmountUnit}` | `StringMinorUnit`, `FloatMajorUnit`, etc. |
| `{endpoint}` | API endpoint (e.g., `payments`) |
