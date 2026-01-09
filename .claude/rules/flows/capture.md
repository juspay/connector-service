---
paths:
  - backend/connector-integration/src/connectors/**/*.rs
---
# Capture Flow Pattern

Captures previously authorized funds.

## Macro Implementation

```rust
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: {ConnectorName},
    curl_request: Json({ConnectorName}CaptureRequest),
    curl_response: {ConnectorName}CaptureResponse,
    flow_name: Capture,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsCaptureData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    other_functions: {
        fn get_headers(&self, req: &...) -> ... { self.build_headers(req) }
        fn get_url(&self, req: &...) -> ... {
            let payment_id = req.connector_request_reference_id.clone();
            Ok(format!("{}/payments/{}/capture", self.connector_base_url(req), payment_id))
        }
    }
);
```

## Request Transformer

```rust
#[derive(Debug, Serialize)]
pub struct {ConnectorName}CaptureRequest {
    pub amount: MinorUnit,  // Capture amount (may be partial)
}

impl TryFrom<&RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>>
    for {ConnectorName}CaptureRequest
{
    fn try_from(router_data: &...) -> Result<Self, Self::Error> {
        Ok(Self {
            amount: router_data.request.amount_to_capture,
        })
    }
}
```

## Status Mapping

```rust
match response.status.as_str() {
    "captured" | "succeeded" => enums::AttemptStatus::Charged,
    "pending" => enums::AttemptStatus::Pending,
    "failed" => enums::AttemptStatus::Failure,
    _ => enums::AttemptStatus::Pending,
}
```
