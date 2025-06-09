# Razorpay Connector

## Overview

The Razorpay connector provides integration with [Razorpay](https://razorpay.com/), an Indian payment gateway that allows businesses to accept payments through various payment methods. This connector implements the `ConnectorIntegration` and `IncomingWebhook` traits to support a range of payment operations.

## Supported Features

| Feature | Support | Notes |
|---------|---------|-------|
| Authorization | ✅ | Authorize a payment without capturing funds |
| Capture | ✅ | Capture previously authorized funds |
| Refund | ✅ | Refund previously captured funds |
| Payment Sync | ✅ | Check the status of a payment |
| Refund Sync | ✅ | Check the status of a refund |
| Webhooks | ✅ | Process notifications from Razorpay |

## Authentication Methods

The Razorpay connector supports the following authentication method:

1. **Key ID and Secret Authentication**: Using Razorpay's key_id and key_secret for authentication

```rust
// Authentication header setup
let auth_header = base64::encode(format!("{}:{}", auth.key1, auth.api_secret));
headers::AUTHORIZATION.to_string(),
format!("Basic {}", auth_header).into_masked(),
```

## Implementation Details

### Key Components

1. **Razorpay Struct**: The main connector implementation that implements various traits for different payment flows.

2. **Transformers Module**: Contains data structures and conversion logic for transforming between domain types and Razorpay-specific formats.

3. **Test Module**: Contains tests for the Razorpay connector.

### Payment Authorization

The authorization flow converts the generic payment request into Razorpay's specific format and sends it to Razorpay's payments API:

```rust
fn get_url(
    &self,
    _req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
) -> CustomResult<String, errors::ConnectorError> {
    Ok(format!("{}v1/payment_links", self.base_url()))
}
```

The response is then converted back into the generic format for consistent handling across connectors.

### Capture

For capturing authorized payments, the connector sends a request to Razorpay's capture API:

```rust
fn get_url(
    &self,
    req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
) -> CustomResult<String, errors::ConnectorError> {
    let connector_payment_id = req.request.connector_transaction_id.clone();
    Ok(format!(
        "{}v1/payments/{}/capture",
        self.base_url(),
        connector_payment_id
    ))
}
```

### Webhook Processing

The connector implements the `IncomingWebhook` trait to process notifications from Razorpay:

```rust
fn process_payment_webhook(
    &self,
    request: RequestDetails,
    _connector_webhook_secret: Option<ConnectorWebhookSecrets>,
    _connector_account_details: Option<ConnectorAuthType>,
) -> Result<WebhookDetailsResponse, error_stack::Report<errors::ConnectorError>> {
    let webhook_body: razorpay::RazorpayWebhookBody = request
        .body
        .parse_struct("RazorpayWebhookBody")
        .change_context(errors::ConnectorError::WebhookBodyDecodingFailed)?;

    let webhook_object = webhook_body.payload.payment.entity;
    let status = match webhook_object.status.as_str() {
        "captured" => Ok(AttemptStatus::Charged),
        "authorized" => Ok(AttemptStatus::Authorized),
        "failed" => Ok(AttemptStatus::Failure),
        _ => Err(errors::ConnectorError::WebhookBodyDecodingFailed),
    }?;

    Ok(WebhookDetailsResponse {
        resource_id: Some(ResponseId::ConnectorTransactionId(webhook_object.id)),
        status,
        connector_response_reference_id: Some(webhook_object.order_id),
        error_code: None,
        error_message: None,
    })
}
```

## Configuration

The Razorpay connector requires the following configuration:

1. **Base URL**: The base URL for Razorpay's API

```rust
fn base_url(&self) -> String {
    "https://api.razorpay.com/".to_string()
}
```

## Error Handling

The connector implements custom error handling for Razorpay-specific errors:

```rust
fn build_error_response(
    &self,
    res: Response,
) -> CustomResult<ErrorResponse, errors::ConnectorError> {
    let response: razorpay::RazorpayErrorResponse = res
        .response
        .parse_struct("RazorpayErrorResponse")
        .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

    Ok(ErrorResponse {
        status_code: res.status_code,
        code: response.error.code,
        message: response.error.description,
        reason: Some(response.error.description),
        attempt_status: None,
        connector_transaction_id: None,
    })
}
```

## Testing

The connector includes tests in the `test` module to verify its functionality:

1. **Unit Tests**: Test individual components of the connector
2. **Integration Tests**: Test the connector's interaction with Razorpay's API

## Usage Examples

### Authorization Request

```rust
let request = payments::PaymentsAuthorizeRequest {
    amount: 1000,
    currency: payments::Currency::Inr as i32,
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
    connector_transaction_id: "pay_123456789".to_string(),
    amount_to_capture: 1000,
    currency: payments::Currency::Inr as i32,
    ..Default::default()
};
```

## Webhook Handling

Razorpay sends webhooks for various events, which the connector processes to update payment status:

1. **Payment Authorized**: Notifies when a payment is authorized
2. **Payment Captured**: Notifies when a payment is captured
3. **Payment Failed**: Notifies when a payment fails
4. **Refund Created**: Notifies when a refund is created
5. **Refund Processed**: Notifies when a refund is processed

The connector normalizes these events into a standard format for consistent handling.

## Razorpay-Specific Considerations

### Payment Flow

Razorpay's payment flow differs slightly from other processors:

1. **Payment Links**: For authorization, Razorpay creates a payment link that the customer can use to complete the payment.

2. **Order ID and Payment ID**: Razorpay uses both an order ID and a payment ID to track payments. The order ID is created first, and then a payment is associated with that order.

3. **Partial Captures**: Razorpay supports partial captures of authorized amounts.

### Currency Support

Razorpay primarily supports INR (Indian Rupee) for payments, although it does offer some support for international currencies.

### Payment Methods

Razorpay supports various payment methods popular in India:

1. **Cards**: Credit and debit cards
2. **UPI**: Unified Payments Interface
3. **Netbanking**: Direct bank transfers
4. **Wallets**: Various digital wallets
5. **EMI**: Equated Monthly Installments

## Common Issues and Troubleshooting

1. **Authentication Failures**
   - Ensure the key_id and key_secret are correct
   - Verify that the Base64 encoding of the authentication header is correct

2. **Currency Issues**
   - Ensure the currency is supported by Razorpay (primarily INR)
   - Check that the amount is in the correct format (paise for INR)

3. **Webhook Verification**
   - Razorpay webhooks include a signature that should be verified
   - Ensure the webhook secret is correctly configured

4. **Order Creation**
   - Some operations require an order to be created first
   - Ensure the order creation is successful before proceeding with payment operations

## References

1. [Razorpay API Documentation](https://razorpay.com/docs/api/)
2. [Razorpay Payment Links](https://razorpay.com/docs/api/payment-links/)
3. [Razorpay Webhooks](https://razorpay.com/docs/webhooks/)
4. [Razorpay Payment Methods](https://razorpay.com/docs/payments/)
