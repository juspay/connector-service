---
paths:
  - backend/connector-integration/src/connectors/**/*.rs
---
# Refund Flow Pattern

Returns funds to the customer.

## Macro Implementation

```rust
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: {ConnectorName},
    curl_request: Json({ConnectorName}RefundRequest),
    curl_response: {ConnectorName}RefundResponse,
    flow_name: Refund,
    resource_common_data: RefundFlowData,  // Note: RefundFlowData not PaymentFlowData
    flow_request: RefundsData,
    flow_response: RefundsResponseData,
    http_method: Post,
    other_functions: {
        fn get_headers(&self, req: &...) -> ... { self.build_headers(req) }
        fn get_url(&self, req: &...) -> ... {
            Ok(format!("{}/refunds", self.connector_base_url(req)))
        }
    }
);
```

## Request Transformer

```rust
#[derive(Debug, Serialize)]
pub struct {ConnectorName}RefundRequest {
    pub payment_id: String,         // Original payment to refund
    pub amount: MinorUnit,          // Refund amount
    pub reason: Option<String>,
}

impl TryFrom<&RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>>
    for {ConnectorName}RefundRequest
{
    fn try_from(router_data: &...) -> Result<Self, Self::Error> {
        Ok(Self {
            payment_id: router_data.request.connector_transaction_id.clone(),
            amount: router_data.request.refund_amount,
            reason: router_data.request.reason.clone(),
        })
    }
}
```

## Status Mapping (CRITICAL)

```rust
// Parent payment status stays Charged!
// Only refund_status changes
Ok(RefundsResponseData {
    status: enums::AttemptStatus::Charged,  // Parent stays Charged
    refund_status: match response.status.as_str() {
        "succeeded" | "completed" => enums::RefundStatus::Success,
        "pending" | "processing" => enums::RefundStatus::Pending,
        "failed" => enums::RefundStatus::Failure,
        _ => enums::RefundStatus::Pending,
    },
    connector_refund_id: response.id.clone(),
})
```
