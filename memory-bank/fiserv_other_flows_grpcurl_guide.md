# Fiserv Connector: `grpcurl` Tests for Various Flows

This guide documents `grpcurl` commands and responses for testing various payment flows with the Fiserv connector, following a successful Authorize transaction.

## Prerequisites

Refer to the [Fiserv Authorize Flow `grpcurl` Integration Test Guide](./fiserv_authorize_grpcurl_guide.md) for initial setup, server configuration, and authentication details. Ensure your gRPC server is running and configured correctly.

**Key Information from Successful Authorize Flow (for reference and use in subsequent flows):**
*   **Card Used**: `4147463011110083` (Visa)
*   **`connector_request_reference_id` (Authorize)**: `GRPCURL_FISERV_AUTH_009`
*   **`connector_meta_data` (Authorize)**: `eyJ0ZXJtaW5hbF9pZCI6IjEwMDAwMDAxIn0=` (Base64 of `{"terminal_id":"10000001"}`)
*   **Authorize Response**:
    ```json
    {
      "resourceId": {
        "connectorTransactionId": "49402f5007cd43b6ad761f315f70898a"
      },
      "connectorResponseReferenceId": "CHG014b7cd1406a858799762f1a651e4247e4",
      "status": "CHARGED"
    }
    ```
*   **`connectorTransactionId` to use for subsequent flows**: `49402f5007cd43b6ad761f315f70898a`

---
## 0. Authorize Payment (Successful Example)

This is the successful authorize call that yielded the `connectorTransactionId` used in subsequent examples.

**Endpoint**: `ucs.payments.PaymentService/PaymentAuthorize`

**`grpcurl` Command:**
```bash
echo '{
  "amount": 1000,
  "minor_amount": 1000,
  "currency": 145,
  "payment_method": 0,
  "payment_method_data": {
    "card": {
      "card_number": "4147463011110083",
      "card_exp_month": "12",
      "card_exp_year": "27",
      "card_cvc": "123",
      "card_holder_name": "joseph Doe",
      "card_network": 0 
    }
  },
  "address": {},
  "email": "test-fiserv-grpcurl@example.com",
  "capture_method": 0,
  "auth_type": 1,
  "return_url": "https://hyperswitch.io/connector-service/fiserv_return_grpcurl",
  "webhook_url": "https://hyperswitch.io/connector-service/fiserv_webhook_grpcurl",
  "browser_info": {
    "accept_header": "application/json",
    "java_enabled": false,
    "language": "en-US",
    "color_depth": 24,
    "screen_height": 1080,
    "screen_width": 1920,
    "time_zone": 300,
    "user_agent": "Mozilla/5.0 (grpcurl test) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36",
    "java_script_enabled": true
  },
  "connector_meta_data": "eyJ0ZXJtaW5hbF9pZCI6IjEwMDAwMDAxIn0=",
  "connector_request_reference_id": "GRPCURL_FISERV_AUTH_009"
}' | grpcurl -plaintext -d @ \
  -H 'x-connector: fiserv' \
  -H 'x-auth: signature-key' \
  -H 'x-api-key: <YOUR_FISERV_API_KEY>' \
  -H 'x-key1: <YOUR_FISERV_MERCHANT_ACCOUNT_ID_OR_KEY1>' \
  -H 'x-api-secret: <YOUR_FISERV_API_SECRET>' \
  localhost:8000 ucs.payments.PaymentService/PaymentAuthorize
```

**Response (Success - Charged):**
```json
{
  "resourceId": {
    "connectorTransactionId": "49402f5007cd43b6ad761f315f70898a"
  },
  "connectorResponseReferenceId": "CHG014b7cd1406a858799762f1a651e4247e4",
  "status": "CHARGED"
}
```

---

## 1. Payment Sync (PSync)

This flow is used to synchronize the status of a previously processed transaction.

**Endpoint**: `ucs.payments.PaymentService/PaymentSync`

**`grpcurl` Command:**

```bash
echo '{
  "resource_id": "49402f5007cd43b6ad761f315f70898a",
  "connector_request_reference_id": "GRPCURL_FISERV_PSYNC_001"
}' | grpcurl -plaintext -d @ \
  -H 'x-connector: fiserv' \
  -H 'x-auth: signature-key' \
  -H 'x-api-key: <YOUR_FISERV_API_KEY>' \
  -H 'x-key1: <YOUR_FISERV_MERCHANT_ACCOUNT_ID_OR_KEY1>' \
  -H 'x-api-secret: <YOUR_FISERV_API_SECRET>' \
  localhost:8000 ucs.payments.PaymentService/PaymentSync
```

**Note**: Replace `<YOUR_FISERV_API_KEY>`, `<YOUR_FISERV_MERCHANT_ACCOUNT_ID_OR_KEY1>`, and `<YOUR_FISERV_API_SECRET>` with your actual credentials. The `resource_id` should be the `connectorTransactionId` obtained from a successful Authorize call.

**Response (Attempt 1 & 2 - Generic Error):**
```json
{
  "resourceId": {
    "noResponseId": false
  },
  "errorCode": "No error code",
  "errorMessage": "No error message"
}
```
**Note (Persistent Issue):** This generic error consistently occurs. It strongly suggests that the response from Fiserv for the PSync/Transaction-Inquiry call has a different structure than what the connector currently expects (`FiservPaymentsResponse` for success, `FiservErrorResponse` for errors). 
To resolve this:
1.  The actual JSON response from Fiserv's transaction inquiry endpoint needs to be captured (e.g., by logging the raw response in `fiserv.rs` before parsing).
2.  New Rust structs matching Fiserv's specific PSync success and error responses need to be defined in `fiserv/transformers.rs`.
3.  The `handle_response_v2` and `build_error_response` (or a new PSync-specific error handler) in `fiserv.rs` must be updated to use these new structs for deserialization.
Without knowing the exact response structure from Fiserv for this endpoint, further `grpcurl` testing for PSync will likely yield the same generic error.

---

## 2. Refund Payment

This flow is used to refund a previously captured transaction.

**Endpoint**: `ucs.payments.PaymentService/Refund`

**Prerequisites for this Refund Test:**
*   A successful Authorize (and Capture, if separate) transaction. We will use the `connectorTransactionId` from the successful Authorize call: `49402f5007cd43b6ad761f315f70898a`.
*   The amount to refund (can be partial or full). For this test, we'll attempt a full refund of 1000 minor units (same as authorized amount).

**`grpcurl` Command:**

```bash
echo '{
  "refund_id": "GRPCURL_FISERV_REFUND_002",
  "connector_transaction_id": "49402f5007cd43b6ad761f315f70898a",
  "refund_amount": 1000,
  "minor_refund_amount": 1000,
  "currency": 145, 
  "payment_amount": 1000, 
  "minor_payment_amount": 1000,
  "reason": "Test refund via grpcurl with refund_connector_metadata",
  "refund_connector_metadata": "eyJ0ZXJtaW5hbF9pZCI6IjEwMDAwMDAxIn0=" 
}' | grpcurl -plaintext -d @ \
  -H 'x-connector: fiserv' \
  -H 'x-auth: signature-key' \
  -H 'x-api-key: <YOUR_FISERV_API_KEY>' \
  -H 'x-key1: <YOUR_FISERV_MERCHANT_ACCOUNT_ID_OR_KEY1>' \
  -H 'x-api-secret: <YOUR_FISERV_API_SECRET>' \
  localhost:8000 ucs.payments.PaymentService/Refund
```
**Note**: 
*   Replace credential placeholders with actual values.
*   `connector_transaction_id` is from the original successful Authorize/Charge.
*   `refund_connector_metadata` (Base64 of `{"terminal_id":"10000001"}`) is crucial for providing the `terminal_id` for the refund operation.

**Response (Success):**
```json
{
  "connectorRefundId": "2acf90d60525498b8f3badffcda36671",
  "refundStatus": "REFUND_SUCCESS"
}
```

---
