# Authorize.Net Connector Integration Test Guide (using grpcurl)

This guide provides instructions on how to perform integration tests for the Authorize.Net connector by sending requests to the running gRPC server using `grpcurl`. These tests interact with the live Authorize.Net sandbox environment.

## 1. Prerequisites

*   The gRPC server (connector service) must be running.
*   Valid Authorize.Net sandbox credentials:
    *   API Login ID (used as `x-api-key` header)
    *   Transaction Key (used as `x-key1` header)
*   `grpcurl` utility installed on your system.
*   Familiarity with the request/response structures defined in your service's `.proto` files (e.g., `payment.proto`).

## 2. General `grpcurl` Command Structure

The basic structure for a `grpcurl` command to test the connector is as follows:

```bash
grpcurl -plaintext \
  -H 'x-connector: authorizedotnet' \
  -H 'x-auth: body-key' \
  -H 'x-api-key: YOUR_API_LOGIN_ID' \
  -H 'x-key1: YOUR_TRANSACTION_KEY' \
  -d '{ ... JSON PAYLOAD ... }' \
  YOUR_GRPC_SERVER_ADDRESS ucs.payments.PaymentService/YourServiceName
```

**Explanation of Headers:**
*   `x-connector: authorizedotnet`: Specifies the target connector.
*   `x-auth: body-key`: Indicates the authentication scheme. For Authorize.Net, where credentials (`api_key`, `key1`) are typically part of the request body to the connector itself, this value tells the gRPC layer how to handle the provided `x-api-key` and `x-key1` headers.
*   `x-api-key`: Your Authorize.Net API Login ID.
*   `x-key1`: Your Authorize.Net Transaction Key.
*   `-d '{...}'`: The JSON payload for the request.
*   `YOUR_GRPC_SERVER_ADDRESS`: e.g., `localhost:8000`.
*   `ucs.payments.PaymentService/YourServiceName`: The specific gRPC service and method to call.

**Note on Credentials in Examples:**
The examples below use placeholder credentials (`YOUR_API_LOGIN_ID`, `YOUR_TRANSACTION_KEY`) and test card numbers. Replace them with your actual sandbox credentials and appropriate test data.

## 3. Testing Payment Flows

### 3.1. Authorize Flow

This flow initiates a payment authorization.

**Service:** `ucs.payments.PaymentService/PaymentAuthorize`

**Sample `grpcurl` command:**
```bash
grpcurl -plaintext \
  -H 'x-connector: authorizedotnet' \
  -H 'x-auth: body-key' \
  -H 'x-api-key: YOUR_API_LOGIN_ID' \
  -H 'x-key1: YOUR_TRANSACTION_KEY' \
  -d '{
    "minor_amount": 1000,
    "currency": "USD",
    "payment_method": "CARD",
    "payment_method_data": {
      "card": {
        "card_number": "4007000000027",
        "card_exp_month": "12",
        "card_exp_year": "2030",
        "card_cvc": "123",
        "card_holder_name": "John Doe"
      }
    },
    "address": {
      "billing": {
        "address": {
          "first_name": "John",
          "last_name": "Doe",
          "line1": "123 Main St",
          "city": "Beverly Hills",
          "state": "CA",
          "zip": "90210",
          "country": "US"
        },
        "phone": {
          "number": "8885550100",
          "country_code": "1"
        }
      }
    },
    "email": "john.doe@example.com",
    "customer_name": "John Doe",
    "auth_type": "NO_THREE_DS",
    "capture_method": "AUTOMATIC",
    "connector_request_reference_id": "anet-auth-test-001",
    "return_url": "http://localhost/return",
    "merchant_order_reference_id": "anet-merch-ord-001"
  }' \
  localhost:8000 ucs.payments.PaymentService/PaymentAuthorize
```

**Expected Response (on success):**
A JSON response with `status: AUTHORIZED` (or `AUTHENTICATION_PENDING` if 3DS were involved and required further steps), and a `resource_id.connector_transaction_id` populated by Authorize.Net.

```json
{
  "resourceId": {
    "connectorTransactionId": "SOME_TRANSACTION_ID_FROM_ANET"
  },
  "status": "AUTHORIZED",
  "connectorResponseReferenceId": "SOME_REF_ID_MAYBE_SAME_AS_TXN_ID"
  // ... other fields as per PaymentsAuthorizeResponse
}
```
**Note:** If you encounter an error like `Code: Internal, Message: Connector processing error: Failed to handle connector response`, it suggests that the authentication headers were likely correct, but an issue occurred within the connector's code when processing the request or (more likely) handling the response from Authorize.Net. This requires debugging the connector service, potentially by checking its logs.

### 3.2. Capture Flow

This flow captures a previously authorized amount.

**Service:** `ucs.payments.PaymentService/PaymentCapture`

**Prerequisite:** A successful Authorize transaction, from which you'll need the `connector_transaction_id`.

**Sample `grpcurl` command:**
```bash
grpcurl -plaintext \
  -H 'x-connector: authorizedotnet' \
  -H 'x-auth: body-key' \
  -H 'x-api-key: YOUR_API_LOGIN_ID' \
  -H 'x-key1: YOUR_TRANSACTION_KEY' \
  -d '{
    "connector_transaction_id": "TRANSACTION_ID_FROM_AUTHORIZE_RESPONSE",
    "amount_to_capture": 1000,
    "currency": "USD"
  }' \
  localhost:8000 ucs.payments.PaymentService/PaymentCapture
```

**Expected Response (on success):**
A JSON response with `status: CHARGED`.
```json
{
  "resourceId": {
    "connectorTransactionId": "TRANSACTION_ID_FROM_AUTHORIZE_RESPONSE" // Usually the same or related
  },
  "status": "CHARGED",
  "connectorResponseReferenceId": "SOME_CAPTURE_REFERENCE_ID"
  // ... other fields as per PaymentsCaptureResponse
}
```

### 3.3. Void Flow

This flow cancels a previously authorized (but not yet captured) transaction.

**Service:** `ucs.payments.PaymentService/VoidPayment`

**Prerequisite:** A successful Authorize transaction. The `PaymentsVoidRequest` proto message uses `connector_request_reference_id`. This should be the `connector_request_reference_id` you sent in the *original* `PaymentsAuthorizeRequest`. The connector internally should map this to the correct Authorize.Net transaction ID (`transId`) for voiding.

**Sample `grpcurl` command:**
```bash
grpcurl -plaintext \
  -H 'x-connector: authorizedotnet' \
  -H 'x-auth: body-key' \
  -H 'x-api-key: YOUR_API_LOGIN_ID' \
  -H 'x-key1: YOUR_TRANSACTION_KEY' \
  -d '{
    "connector_request_reference_id": "anet-auth-test-001"
  }' \
  localhost:8000 ucs.payments.PaymentService/VoidPayment
```

**Expected Response (on success):**
A JSON response with `status: VOIDED`.
```json
{
  "resourceId": {
    "noResponseId": true // Or connectorTransactionId might be present depending on impl.
  },
  "status": "VOIDED",
  "connectorResponseReferenceId": "SOME_VOID_REFERENCE_ID"
  // ... other fields as per PaymentsVoidResponse
}
```

## 4. Troubleshooting Tips

*   **Unique IDs:** Ensure `connector_request_reference_id` and `merchant_order_reference_id` are unique for each new Authorize attempt if your provider or system requires it to avoid duplicate errors.
*   **Authentication Errors:**
    *   `Invalid auth type`: Double-check the `x-auth` header value. `body-key` is what we found to work for Authorize.Net in this setup.
    *   `Missing x-api-key/x-key1/x-api-secret`: Ensure all required authentication headers are present and correctly spelled for the `x-auth` type you're using.
*   **Connector Processing Errors (`Code: Internal`):**
    *   `Failed to handle connector response`: This usually means the request reached the connector and was sent to Authorize.Net, but an error occurred when the connector tried to process Authorize.Net's response. This requires looking at the `connector-service` logs to see the raw request to/response from Authorize.Net to understand what failed (e.g., malformed response, unexpected error code from Authorize.Net, deserialization issues in the connector's transformer code).
    *   Other internal errors: Check service logs for detailed stack traces or error messages.
*   **Card Declines:** Use valid Authorize.Net test card numbers. Real card numbers will not work in the sandbox. Ensure the card details, amount, and currency are acceptable to the Authorize.Net sandbox.
*   **Check Server Logs:** The gRPC server (connector service) logs are invaluable for diagnosing issues, especially for internal errors or unexpected behavior. They often contain the raw request/response to/from the payment gateway.

This guide should help you in performing integration tests for the Authorize.Net connector. Remember to adapt payloads and expected outcomes based on your specific implementation details and test scenarios. 