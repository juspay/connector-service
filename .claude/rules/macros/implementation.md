---
paths:
  - backend/connector-integration/src/connectors/**/*.rs
---
# Macro Implementation Patterns

## Prerequisites Macro

Declare connector structure and supported flows:

```rust
macros::create_all_prerequisites!(
    connector_name: {ConnectorName},
    generic_type: T,
    api: [
        (flow: Authorize, request_body: {ConnectorName}AuthorizeRequest<T>, response_body: ..., router_data: ...),
        (flow: PSync, ...),
        (flow: Capture, ...),
        (flow: Void, ...),
        (flow: Refund, ...),
        (flow: RSync, ...),
    ],
    amount_converters: [amount_converter: {AmountConverter}],
    member_functions: {
        pub fn build_headers<F, FCD, Req, Res>(&self, req: &RouterDataV2<F, FCD, Req, Res>)
            -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError>
        {
            let auth = {ConnectorName}AuthType::try_from(&req.access_token)?;
            Ok(vec![
                ("Authorization".to_string(), format!("Bearer {}", auth.api_key.peek()).into_masked()),
                ("Content-Type".to_string(), "application/json".to_string().into()),
            ])
        }
    }
);
```

## Flow Implementation Macro

```rust
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: {ConnectorName},
    curl_request: Json({ConnectorName}AuthorizeRequest<T>),
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
            Ok(format!("{}/payments", self.connector_base_url(req)))
        }
    }
);
```

## Flow-Specific Patterns

| Flow | HTTP | resource_common_data | flow_request | flow_response |
|------|------|---------------------|--------------|---------------|
| Authorize | Post | PaymentFlowData | PaymentsAuthorizeData<T> | PaymentsResponseData |
| PSync | Get | PaymentFlowData | PaymentsSyncData | PaymentsResponseData |
| Capture | Post | PaymentFlowData | PaymentsCaptureData | PaymentsResponseData |
| Void | Post | PaymentFlowData | PaymentsCancelData | PaymentsResponseData |
| Refund | Post | RefundFlowData | RefundsData | RefundsResponseData |
| RSync | Get | RefundFlowData | RefundSyncData | RefundsResponseData |

## URL Patterns

```rust
// Authorize: POST /payments
Ok(format!("{}/payments", base_url))

// PSync: GET /payments/{id}
let payment_id = req.connector_request_reference_id.clone();
Ok(format!("{}/payments/{}", base_url, payment_id))

// Capture: POST /payments/{id}/capture
Ok(format!("{}/payments/{}/capture", base_url, payment_id))

// Void: POST /payments/{id}/cancel
Ok(format!("{}/payments/{}/cancel", base_url, payment_id))

// Refund: POST /refunds
Ok(format!("{}/refunds", base_url))

// RSync: GET /refunds/{id}
let refund_id = req.connector_request_reference_id.clone();
Ok(format!("{}/refunds/{}", base_url, refund_id))
```
