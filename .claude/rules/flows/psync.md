---
paths:
  - backend/connector-integration/src/connectors/**/*.rs
---
# PSync Flow Pattern

Payment Sync - retrieves current status of a payment.

## Macro Implementation

```rust
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: {ConnectorName},
    curl_request: Json({ConnectorName}PSyncRequest),  // Often empty for GET
    curl_response: {ConnectorName}PSyncResponse,
    flow_name: PSync,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsSyncData,
    flow_response: PaymentsResponseData,
    http_method: Get,  // Usually GET, some APIs use POST
    other_functions: {
        fn get_headers(&self, req: &...) -> ... { self.build_headers(req) }
        fn get_url(&self, req: &...) -> ... {
            let payment_id = req.connector_request_reference_id.clone();
            Ok(format!("{}/payments/{}", self.connector_base_url(req), payment_id))
        }
    }
);
```

## Request Transformer

```rust
// PSync requests are often empty (ID in URL)
#[derive(Debug, Serialize)]
pub struct {ConnectorName}PSyncRequest {
    // Usually empty - payment ID comes from URL
}

impl TryFrom<&RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>
    for {ConnectorName}PSyncRequest
{
    fn try_from(_router_data: &...) -> Result<Self, Self::Error> {
        Ok(Self {})
    }
}
```

## Status Mapping

```rust
match response.status.as_str() {
    "succeeded" | "completed" | "captured" => enums::AttemptStatus::Charged,
    "authorized" | "requires_capture" => enums::AttemptStatus::Authorized,
    "pending" | "processing" => enums::AttemptStatus::Pending,
    "requires_action" | "requires_authentication" => enums::AttemptStatus::AuthenticationPending,
    "cancelled" | "voided" => enums::AttemptStatus::Voided,
    "failed" | "declined" => enums::AttemptStatus::Failure,
    _ => enums::AttemptStatus::Pending,  // Unknown → Pending
}
```

## RSync Pattern (Refund Sync)

Similar to PSync but for refunds:

```rust
macros::macro_connector_implementation!(
    // ...
    flow_name: RSync,
    resource_common_data: RefundFlowData,
    flow_request: RefundSyncData,
    flow_response: RefundsResponseData,
    http_method: Get,
    other_functions: {
        fn get_url(&self, req: &...) -> ... {
            let refund_id = req.connector_request_reference_id.clone();
            Ok(format!("{}/refunds/{}", self.connector_base_url(req), refund_id))
        }
    }
);
```
