/**
 * Node.js tests for the connector-service-ffi napi bindings
 *
 * This file tests the authorize function exposed via napi from the Rust FFI module.
 * Build with: cd backend/ffi && cargo build --features napi --release
 * Run with: node tests/test_node.js
 *
 * Note: The authorize function requires a payload argument.
 * Connector, auth, and masked_metadata are hardcoded in Rust for reference.
 */

const ffi = require('..');

// Test configuration
const TEST_CONFIG = {
    verbose: process.env.VERBOSE === 'true'
};

// Sample payload matching PaymentServiceAuthorizeRequest structure (protobuf format)
const SAMPLE_PAYLOAD = {
    request_ref_id: {
        id: "test_payment_123456"
    },
    amount: 1000,
    minor_amount: 1000,
    currency: "USD",
    payment_method: {
        payment_method: {
            Card: {
                card_number: "4111111111111111",
                card_exp_month: "12",
                card_exp_year: "2050",
                card_cvc: "123",
                card_holder_name: "Test User",
                card_network: 1
            }
        }
    },
    capture_method: "AUTOMATIC",
    email: "customer@example.com",
    customer_name: "Test Customer",
    auth_type: "NO_THREE_DS",
    enrolled_for_3ds: false,
    return_url: "https://example.com/return",
    webhook_url: "https://example.com/webhook",
    description: "Test payment",
    test_mode: true,
    order_details: [],
    address: {
        shipping_address: null,
        billing_address: null
    }
};

// Sample extracted metadata matching MetadataPayload structure
const SAMPLE_EXTRACTED_METADATA = {
    connector: "Stripe",
    connector_auth_type: {
        auth_type: "HeaderKey",
        api_key: "sk_test"

    }
};

let main = async () => {
    const result = ffi.authorizeReq(SAMPLE_PAYLOAD, SAMPLE_EXTRACTED_METADATA);
    let { body, headers, method, url } = JSON.parse(result)
    const response = await fetch(url, {
        method,
        headers,
        body: body || undefined,
    });
    console.log(response)
    const responseText = await response.text();
    const responseHeaders = {};
    response.headers.forEach((value, key) => {
        responseHeaders[key] = value;
    });

    const formattedResponse = {
        status: response.status,
        headers: responseHeaders,
        body: responseText
    };
    const res = ffi.authorizeRes(SAMPLE_PAYLOAD, SAMPLE_EXTRACTED_METADATA, formattedResponse);
    let parsedRespons = JSON.parse(res);
    console.log(parsedRespons)

}
main()