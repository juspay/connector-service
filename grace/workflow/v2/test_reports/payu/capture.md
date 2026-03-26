# Test Report: payu / Capture

- **Date**: 2026-03-26 00:32:00
- **Service**: PaymentService/Capture
- **Result**: FAIL
- **Attempts**: 1

## Prerequisite: Authorize (MANUAL capture)

### grpcurl Command (credentials masked)

```bash
grpcurl -plaintext \
  -H "x-connector: payu" \
  -H "x-merchant-id: test_merchant" \
  -H "x-tenant-id: default" \
  -H "x-request-id: capture_payu_prereq_req3" \
  -H "x-connector-request-reference-id: capture_payu_prereq_ref3" \
  -H "x-auth: ***MASKED***" \
  -H "x-api-key: ***MASKED***" \
  -H "x-key1: ***MASKED***" \
  -d @ localhost:8000 types.PaymentService/Authorize <<'JSON'
{
  "merchant_transaction_id": "mti_test_payu_capture_prereq_003",
  "amount": {
    "minor_amount": 1000,
    "currency": "INR"
  },
  "payment_method": {
    "upi_collect": {
      "vpa_id": {"value": "success@payu"}
    }
  },
  "capture_method": "MANUAL",
  "auth_type": "NO_THREE_DS",
  "enrolled_for_3ds": false,
  "return_url": "https://example.com/return",
  "webhook_url": "https://example.com/webhook",
  "address": {
    "billing_address": {
      "first_name": {"value": "John"},
      "email": {"value": "test@example.com"},
      "phone_number": {"value": "4155552671"},
      "phone_country_code": "+1"
    }
  },
  "browser_info": {
    "ip_address": "1.2.3.4"
  },
  "test_mode": true
}
JSON
```

### Prerequisite Authorize Response

```json
{
  "merchantTransactionId": "403993715537066864",
  "connectorTransactionId": "403993715537066864",
  "status": "AUTHENTICATION_PENDING",
  "statusCode": 200
}
```

Prerequisite Authorize returned status `AUTHENTICATION_PENDING` (maps to PENDING for UPI Collect flow — payer approval is needed). The `connectorTransactionId` was `403993715537066864`.

## Capture grpcurl Command (credentials masked)

```bash
grpcurl -plaintext \
  -H "x-connector: payu" \
  -H "x-merchant-id: test_merchant" \
  -H "x-tenant-id: default" \
  -H "x-request-id: capture_payu_req" \
  -H "x-connector-request-reference-id: capture_payu_ref" \
  -H "x-auth: ***MASKED***" \
  -H "x-api-key: ***MASKED***" \
  -H "x-key1: ***MASKED***" \
  -d @ localhost:8000 types.PaymentService/Capture <<'JSON'
{
  "connector_transaction_id": "403993715537066864",
  "amount_to_capture": {
    "minor_amount": 1000,
    "currency": "INR"
  },
  "test_mode": true
}
JSON
```

## Response

```
ERROR:
  Code: Internal
  Message: Failed to execute a processing step: None
```

## Extracted IDs

- connector_transaction_id: N/A (Capture failed)
- connector_refund_id: N/A

## Validation

- statusCode: N/A (gRPC Internal error, no JSON response) — FAIL
- status: N/A — FAIL
- error: gRPC Internal error "Failed to execute a processing step: None" — FAIL

## Failure Analysis

The Capture flow returned a gRPC `Internal` error with message "Failed to execute a processing step: None". This is a **code-level bug** in the Capture flow processing pipeline — the server failed to execute the connector processing step. The error occurs within the server's flow execution, not in grpcurl or request formatting.

Possible root causes:
1. The Capture flow's request body serialization may be failing (form-urlencoded encoding issue)
2. The prerequisite Authorize returned `AUTHENTICATION_PENDING` (UPI pending payer approval), meaning the payment was not yet in an AUTHORIZED state — PayU may require the payment to be fully authorized before capture
3. The connector processing step may have an implementation issue in the Capture flow code path

## Server Logs (if FAIL)

```
Server logs did not contain entries for the Capture request. The server (PID 2761848) writes to /tmp/grpc-server-test.log but the log did not capture recent PayU Capture flow entries — the logs only showed older CancelRecurring entries for cashfree.
```
