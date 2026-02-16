/**
 * Test suite for connector-service-ffi Node.js bindings
 * 
 * Tests both high-level ConnectorClient API and low-level FFI bindings.
 * Run with: node tests/test_node.js
 */

const { ConnectorClient, authorizeReq, authorizeRes } = require('..');
const fetch = require('node-fetch');

// Sample metadata
const METADATA = {
    connector: "Stripe",
    connector_auth_type: {
        auth_type: "HeaderKey",
        api_key: "sk_test"
    }
};

// Sample payload matching PaymentServiceAuthorizeRequest structure
const PAYLOAD = {
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

/**
 * Test the high-level ConnectorClient API
 */
async function testHighLevelAPI() {
    console.log('='.repeat(60));
    console.log('Test 1: High-Level API (ConnectorClient)');
    console.log('='.repeat(60));
    console.log();

    try {
        // Create client instance
        const client = new ConnectorClient(METADATA);
        console.log('✓ ConnectorClient created successfully');
        console.log(`  Connector: ${client.metadata.connector}`);
        console.log(`  Auth Type: ${client.metadata.connector_auth_type.auth_type}\n`);

        // Execute authorization
        console.log('Authorizing payment...');
        console.log(`  Amount: ${PAYLOAD.amount} ${PAYLOAD.currency}`);
        console.log(`  Card: **** **** **** ${PAYLOAD.payment_method.payment_method.Card.card_number.slice(-4)}`);
        console.log(`  Customer: ${PAYLOAD.customer_name}\n`);

        const result = await client.authorize(PAYLOAD);

        console.log('✓ Authorization completed successfully\n');
        console.log('Response:');
        console.log(JSON.stringify(result, null, 2));

        return result;

    } catch (error) {
        console.error('✗ High-level API test failed:', error.message);
        if (error.cause) {
            console.error('  Caused by:', error.cause.message);
        }
        throw error;
    }
}

/**
 * Test the low-level FFI bindings API
 */
async function testLowLevelAPI() {
    console.log('\n' + '='.repeat(60));
    console.log('Test 2: Low-Level API (authorizeReq/authorizeRes)');
    console.log('='.repeat(60));
    console.log();

    try {
        // Step 1: Build request
        console.log('Building HTTP request with authorizeReq()...');
        const requestJson = authorizeReq(PAYLOAD, METADATA);
        const { body, headers, method, url } = JSON.parse(requestJson);

        console.log('✓ Request built successfully');
        console.log(`  Method: ${method}`);
        console.log(`  URL: ${url}`);
        console.log(`  Headers: ${Object.keys(headers).length} header(s)\n`);

        // Step 2: Execute HTTP request
        console.log('Executing HTTP request...');
        const response = await fetch(url, {
            method,
            headers,
            body: body || undefined,
        });

        console.log('✓ HTTP request completed');
        console.log(`  Status: ${response.status}`);
        console.log(`  Status Text: ${response.statusText}\n`);

        // Step 3: Format response
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

        // Step 4: Parse response
        console.log('Parsing response with authorizeRes()...');
        const resultJson = authorizeRes(PAYLOAD, METADATA, formattedResponse);
        const result = JSON.parse(resultJson);

        console.log('✓ Response parsed successfully\n');
        console.log('Response:');
        console.log(JSON.stringify(result, null, 2));

        return result;

    } catch (error) {
        console.error('✗ Low-level API test failed:', error.message);
        throw error;
    }
}

/**
 * Main test runner
 */
async function main() {
    console.log('\n');
    console.log('╔' + '═'.repeat(58) + '╗');
    console.log('║' + ' '.repeat(10) + 'Connector Service FFI - Test Suite' + ' '.repeat(13) + '║');
    console.log('╚' + '═'.repeat(58) + '╝');
    console.log('\n');

    try {
        // Run high-level API test
        await testHighLevelAPI();

        // Run low-level API test
        await testLowLevelAPI();

        // Success summary
        console.log('\n' + '='.repeat(60));
        console.log('✓ All tests passed successfully!');
        console.log('='.repeat(60));
        console.log('\nBoth APIs are working correctly:');
        console.log('  • High-level: ConnectorClient');
        console.log('  • Low-level: authorizeReq/authorizeRes');
        console.log();

    } catch (error) {
        // Failure summary
        console.log('\n' + '='.repeat(60));
        console.log('✗ Test suite failed');
        console.log('='.repeat(60));
        console.log();
        process.exit(1);
    }
}

// Run tests
main();