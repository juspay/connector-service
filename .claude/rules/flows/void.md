---
paths:
  - backend/connector-integration/src/connectors/**/*.rs
---
# Void Flow Pattern

Cancels an authorized but uncaptured payment.

## Macro Implementation

```rust
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: {ConnectorName},
    curl_request: Json({ConnectorName}VoidRequest),
    curl_response: {ConnectorName}VoidResponse,
    flow_name: Void,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsCancelData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    other_functions: {
        fn get_headers(&self, req: &...) -> ... { self.build_headers(req) }
        fn get_url(&self, req: &...) -> ... {
            let payment_id = req.connector_request_reference_id.clone();
            Ok(format!("{}/payments/{}/cancel", self.connector_base_url(req), payment_id))
        }
    }
);
```

## Request Transformer

```rust
#[derive(Debug, Serialize)]
pub struct {ConnectorName}VoidRequest {
    pub reason: Option<String>,     // Cancellation reason
}

impl TryFrom<&RouterDataV2<Void, PaymentFlowData, PaymentsCancelData, PaymentsResponseData>>
    for {ConnectorName}VoidRequest
{
    fn try_from(router_data: &...) -> Result<Self, Self::Error> {
        Ok(Self {
            reason: router_data.request.cancellation_reason.clone(),
        })
    }
}
```

## Status Mapping

```rust
match response.status.as_str() {
    "cancelled" | "voided" => enums::AttemptStatus::Voided,
    "pending" => enums::AttemptStatus::Pending,
    "failed" => enums::AttemptStatus::Failure,
    _ => enums::AttemptStatus::Pending,
}
```
