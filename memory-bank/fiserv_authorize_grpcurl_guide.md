# Fiserv Authorize Flow `grpcurl` Integration Test Guide

This guide outlines the steps to test the Fiserv connector's authorize flow end-to-end using `grpcurl` against the `PaymentService/PaymentAuthorize` gRPC endpoint.

## Prerequisites

1.  **Running gRPC Server**: Ensure the `connector-service` gRPC server is compiled with the latest code and is running. Typically, you can run it using:
    ```bash
    cargo run --package grpc-server
    ```
2.  **Configuration (`config/development.toml`)**:
    *   Verify that the `base_url` for Fiserv under `[connectors.fiserv]` is correctly pointing to the Fiserv test environment.
    *   Ensure that the necessary API keys and secrets for Fiserv are correctly configured, as these will be passed via headers in the `grpcurl` command.
3.  **`grpcurl` Installed**: Make sure `grpcurl` is installed on your system.
4.  **Valid Test Card Details**:
    *   **IMPORTANT**: As of the last testing round, there was a persistent "Unable to assign card to brand: Invalid" (error code 104) from Fiserv. This indicates that the Fiserv test environment requires very specific test card numbers (along with CVC, expiry date, and potentially cardholder name) that are approved for the `terminal_id` being used.
    *   Obtain a known-working test card profile for the Fiserv UAT environment and the specific `terminal_id` you are testing against (e.g., "10000001"). Generic test card numbers may not work.

## `grpcurl` Command Structure

The basic structure of the `grpcurl` command for the Fiserv authorize flow is as follows:

```bash
echo '{
  "amount": <AMOUNT_IN_MAJOR_UNITS_AS_INT64>,
  "minor_amount": <AMOUNT_IN_MINOR_UNITS_AS_INT64>,
  "currency": <CURRENCY_ENUM_INT_VALUE>,
  "payment_method": 0, # Enum for CARD
  "payment_method_data": {
    "card": {
      "card_number": "<VALID_FISERV_TEST_CARD_NUMBER>",
      "card_exp_month": "<EXP_MONTH_MM>",
      "card_exp_year": "<EXP_YEAR_YYYY_OR_YY>",
      "card_cvc": "<CARD_CVC>",
      "card_holder_name": "<CARDHOLDER_NAME (Optional)>",
      "card_network": <CARD_NETWORK_ENUM_INT_VALUE (e.g., 0 for VISA, 1 for MASTERCARD)>
    }
  },
  "address": {
    // Optional: Populate billing/shipping address if needed for the test case
    // "billing": {
    //   "address": {
    //     "line1": "123 Main St",
    //     "city": "Testville",
    //     "zip": "12345",
    //     "country": 0 // US
    //   }
    // }
  },
  "email": "test-user@example.com",
  "capture_method": 0, # Enum for AUTOMATIC
  "auth_type": 1, # Enum for NO_THREE_DS (adjust if testing 3DS)
  "return_url": "https://your.domain/return_url",
  "webhook_url": "https://your.domain/webhook_url",
  "browser_info": { // Optional, but good for mimicking real transactions
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
  "connector_meta_data": "<BASE64_ENCODED_JSON_TERMINAL_ID>",
  "connector_request_reference_id": "GRPCURL_FISERV_AUTH_<UNIQUE_ID>"
}' | grpcurl -plaintext -d @ \
  -H 'x-connector: fiserv' \
  -H 'x-auth: signature-key' \
  -H 'x-api-key: <YOUR_FISERV_API_KEY>' \
  -H 'x-key1: <YOUR_FISERV_MERCHANT_ACCOUNT_ID_OR_KEY1>' \
  -H 'x-api-secret: <YOUR_FISERV_API_SECRET>' \
  localhost:8000 ucs.payments.PaymentService/PaymentAuthorize
```

## Explanation of Components

### Headers (`-H`)

*   `x-connector: fiserv`: Specifies that the request is for the "fiserv" connector.
*   `x-auth: signature-key`: Indicates the authentication method. For Fiserv, this implies the use of API Key, Merchant Account ID (as key1), and API Secret for HMAC signature generation.
*   `x-api-key: <YOUR_FISERV_API_KEY>`: The API key provided by Fiserv.
*   `x-key1: <YOUR_FISERV_MERCHANT_ACCOUNT_ID_OR_KEY1>`: This typically corresponds to the Fiserv Merchant Account ID.
*   `x-api-secret: <YOUR_FISERV_API_SECRET>`: The API secret used for generating the HMAC signature.

### JSON Payload Fields

*   **`amount`**: Payment amount in major units (e.g., 1000 for $10.00). Type: `int64`.
*   **`minor_amount`**: Payment amount in minor units (e.g., 1000 for $10.00). Type: `int64`.
*   **`currency`**: Currency code as an integer enum value (e.g., `145` for `USD`). Refer to `payment.proto` for `Currency` enum definitions.
*   **`payment_method`**: Payment method type enum. `0` for `CARD`.
*   **`payment_method_data.card`**:
    *   `card_number`: The test card number. **Must be a Fiserv-approved test card for the environment.**
    *   `card_exp_month`: Two-digit month (e.g., "12").
    *   `card_exp_year`: Two or four-digit year (e.g., "25" or "2025"). The transformer handles conversion to YYYY.
    *   `card_cvc`: Card Verification Code.
    *   `card_holder_name` (Optional): Name of the cardholder.
    *   `card_network` (Optional but recommended): Integer enum for card network (e.g., `0` for VISA, `1` for MASTERCARD). Refer to `payment.proto` for `CardNetwork` enum.
*   **`address`** (Optional): Billing and/or shipping address details.
*   **`email`**: Customer's email address.
*   **`capture_method`**: `0` for `AUTOMATIC` capture, `1` for `MANUAL`.
*   **`auth_type`**: Authentication type. `1` for `NO_THREE_DS`.
*   **`return_url`**: URL for redirection after payment.
*   **`webhook_url`**: URL for webhook notifications.
*   **`browser_info`** (Optional): Customer's browser details.
*   **`connector_meta_data`**: **Crucial for Fiserv.** This field must contain a base64 encoded JSON string specifying the `terminal_id`.
    *   Example JSON: `{"terminal_id":"10000001"}`
    *   Base64 encoded version of the above: `eyJ0ZXJtaW5hbF9pZCI6IjEwMDAwMDAxIn0=`
    *   To generate this: `echo -n '{"terminal_id":"YOUR_TERMINAL_ID"}' | base64`
*   **`connector_request_reference_id`**: A unique ID for this request.

## Example Command (Illustrative - replace placeholders)

```bash
echo '{
  "amount": 1000,
  "minor_amount": 1000,
  "currency": 145, # USD
  "payment_method": 0,
  "payment_method_data": {
    "card": {
      "card_number": "5239290700000051", # Replace with a known working Fiserv test Mastercard
      "card_exp_month": "12",
      "card_exp_year": "27",
      "card_cvc": "123",
      "card_holder_name": "Joseph Doe",
      "card_network": 1 # MASTERCARD
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
  "connector_meta_data": "eyJ0ZXJtaW5hbF9pZCI6IjEwMDAwMDAxIn0=", # Base64 of {"terminal_id":"10000001"}
  "connector_request_reference_id": "GRPCURL_FISERV_AUTH_XYZ123"
}' | grpcurl -plaintext -d @ \
  -H 'x-connector: fiserv' \
  -H 'x-auth: signature-key' \
  -H 'x-api-key: YOUR_ACTUAL_FISERV_API_KEY' \
  -H 'x-key1: YOUR_ACTUAL_FISERV_MERCHANT_ID' \
  -H 'x-api-secret: YOUR_ACTUAL_FISERV_API_SECRET' \
  localhost:8000 ucs.payments.PaymentService/PaymentAuthorize
```

## Troubleshooting

*   **Connection Refused**: Ensure the gRPC server is running and accessible at `localhost:8000`.
*   **"Unable to assign card to brand: Invalid" (Error 104)**: This is the most common issue encountered. It almost always means the card details (number, expiry, CVC) are not valid or not recognized by the specific Fiserv test environment and `terminal_id`. Double-check with Fiserv documentation or support for valid test card credentials.
*   **HMAC/Signature Errors**: If you get errors related to authentication or signature mismatch:
    *   Verify the `x-api-key`, `x-key1` (Merchant ID), and `x-api-secret` are correct.
    *   Ensure the timestamp and client-request-id generation in the connector code (`fiserv.rs`) matches Fiserv's expectations for signature calculation. The signature is sensitive to the exact request payload.
*   **"Missing required field: connector_meta_data for FiservSessionObject"**: This error indicates that the `connector_meta_data` (containing `terminal_id`) did not reach the Fiserv transformer correctly. Ensure it's correctly base64 encoded in the `grpcurl` request and that the transformations in `domain_types/src/types.rs` are correctly passing it through.
*   **Other Connector Processing Errors**: Check server logs for more detailed error messages from the `connector-service`.

By following these steps and ensuring the prerequisites are met, you should be able to test the Fiserv authorize flow. The key challenge often lies in obtaining the correct set of test credentials and card details for the specific Fiserv test environment.
