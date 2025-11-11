# Adyen Connector

## Overview

The Adyen connector provides integration with [Adyen](https://www.adyen.com/), a global payment platform that allows businesses to accept payments through various payment methods. This connector implements the `ConnectorIntegration` and `IncomingWebhook` traits to support a wide range of payment operations.

## Supported Features

| Feature | Support | Notes |
|---------|---------|-------|
| Authorization | ✅ | Authorize a payment without capturing funds |
| Capture | ✅ | Capture previously authorized funds |
| Void | ✅ | Cancel a previously authorized payment |
| Refund | ✅ | Refund previously captured funds |
| Payment Sync | ✅ | Check the status of a payment |
| Refund Sync | ✅ | Check the status of a refund |
| Webhooks | ✅ | Process notifications from Adyen |
| Mandate Setup | ✅ | Set up payment mandates for recurring payments |
| Dispute Handling | ✅ | Accept disputes |

## Authentication Methods

The Adyen connector supports the following authentication methods:

1. **API Key Authentication**: Using Adyen's API key for authentication

```rust
// Authentication header setup
headers::X_API_KEY.to_string(),
auth.api_key.into_masked(),
```

## API Versions

The connector uses Adyen API v68 for most operations:

```rust
const ADYEN_API_VERSION: &str = "v68";
```

## Implementation Details

### Key Components

1. **Adyen Struct**: The main connector implementation that implements various traits for different payment flows.

2. **Transformers Module**: Contains data structures and conversion logic for transforming between domain types and Adyen-specific formats.

3. **Test Module**: Contains tests for the Adyen connector.

### Payment Authorization

The authorization flow converts the generic payment request into Adyen's specific format and sends it to Adyen's payments API:

```rust
fn get_url(
    &self,
    req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
) -> CustomResult<String, errors::ConnectorError> {
    Ok(format!("{}{}/payments", self.connector_base_url(req), ADYEN_API_VERSION))
}
```

The response is then converted back into the generic format for consistent handling across connectors.

### Capture

For capturing authorized payments, the connector sends a request to Adyen's capture API:

```rust
fn get_url(
    &self,
    req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
) -> CustomResult<String, errors::ConnectorError> {
    let id = match &req.request.connector_transaction_id {
        ResponseId::ConnectorTransactionId(id) => id,
        _ => {
            return Err(errors::ConnectorError::MissingConnectorTransactionID.into());
        }
    };
    Ok(format!(
        "{}{}/payments/{}/captures",
        req.resource_common_data.connectors.adyen.base_url, ADYEN_API_VERSION, id
    ))
}
```

### Webhook Processing

The connector implements the `IncomingWebhook` trait to process notifications from Adyen:

```rust
fn process_payment_webhook(
    &self,
    request: RequestDetails,
    _connector_webhook_secret: Option<ConnectorWebhookSecrets>,
    _connector_account_details: Option<ConnectorAuthType>,
) -> Result<WebhookDetailsResponse, error_stack::Report<errors::ConnectorError>> {
    let notif: AdyenNotificationRequestItemWH =
        transformers::get_webhook_object_from_body(request.body).map_err(|err| {
            report!(errors::ConnectorError::WebhookBodyDecodingFailed)
                .attach_printable(format!("error while decoing webhook body {err}"))
        })?;
    Ok(WebhookDetailsResponse {
        resource_id: Some(ResponseId::ConnectorTransactionId(
            notif.psp_reference.clone(),
        )),
        status: transformers::get_adyen_payment_webhook_event(notif.event_code, notif.success)?,
        connector_response_reference_id: Some(notif.psp_reference),
        error_code: notif.reason.clone(),
        error_message: notif.reason,
    })
}
```

## Configuration

The Adyen connector requires the following configuration:

1. **Base URL**: The base URL for Adyen's API
2. **Dispute Base URL** (optional): The base URL for Adyen's dispute API

```rust
#[derive(Clone, serde::Deserialize, Debug)]
pub struct ConnectorParams {
    /// base url
    pub base_url: String,
    pub dispute_base_url: Option<String>,
}
```

## Error Handling

The connector implements custom error handling for Adyen-specific errors:

```rust
fn build_error_response(
    &self,
    res: Response,
    event_builder: Option<&mut events::Event>,
) -> CustomResult<ErrorResponse, errors::ConnectorError> {
    let response: adyen::AdyenErrorResponse = res
        .response
        .parse_struct("ErrorResponse")
        .map_err(|_| errors::ConnectorError::ResponseDeserializationFailed)?;

    with_error_response_body!(event_builder, response);

    Ok(ErrorResponse {
        status_code: res.status_code,
        code: response.error_code,
        message: response.message.to_owned(),
        reason: Some(response.message),
        attempt_status: None,
        connector_transaction_id: response.psp_reference,
    })
}
```

## Testing

The connector includes tests in the `test` module to verify its functionality:

1. **Unit Tests**: Test individual components of the connector
2. **Integration Tests**: Test the connector's interaction with Adyen's API

## Usage Examples

### Authorization Request

```rust
let request = payments::PaymentsAuthorizeRequest {
    amount: 1000,
    currency: payments::Currency::Usd as i32,
    payment_method: payments::PaymentMethod::Card as i32,
    payment_method_data: Some(payments::PaymentMethodData {
        data: Some(payments::payment_method_data::Data::Card(payments::Card {
            card_number: "4111111111111111".to_string(),
            card_exp_month: "03".to_string(),
            card_exp_year: "2030".to_string(),
            card_cvc: "737".to_string(),
            ..Default::default()
        })),
    }),
    connector_request_reference_id: "ref-123".to_string(),
    ..Default::default()
};
```

### Capture Request

```rust
let request = payments::PaymentsCaptureRequest {
    connector_transaction_id: "8837968461238652".to_string(),
    amount_to_capture: 1000,
    currency: payments::Currency::Usd as i32,
    ..Default::default()
};
```

## Webhook Handling

Adyen sends webhooks for various events, which the connector processes to update payment status:

1. **Authorization Result**: Notifies about the result of an authorization
2. **Capture Result**: Notifies about the result of a capture
3. **Refund Result**: Notifies about the result of a refund
4. **Chargeback Result**: Notifies about chargebacks

The connector normalizes these events into a standard format for consistent handling.

## Common Issues and Troubleshooting

1. **Authentication Failures**
   - Ensure the API key is correct and has the necessary permissions
   - Check that the API key is being passed correctly in the headers

2. **Invalid Request Format**
   - Verify that the request data is correctly formatted according to Adyen's requirements
   - Check for missing required fields

3. **Webhook Verification Failures**
   - Ensure the webhook is coming from Adyen (IP verification)
   - Verify the webhook signature if applicable

4. **API Version Compatibility**
   - The connector uses Adyen API v68, ensure compatibility with your Adyen account

## References

1. [Adyen API Documentation](https://docs.adyen.com/api-explorer/)
2. [Adyen Webhook Documentation](https://docs.adyen.com/development-resources/webhooks/)
3. [Adyen Payment Methods](https://docs.adyen.com/payment-methods/)
