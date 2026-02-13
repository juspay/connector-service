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
        api_key: "sk_test_"

    }
};

// Test case structure
class TestCase {
    constructor(name, testFn) {
        this.name = name;
        this.testFn = testFn;
    }

    async run() {
        try {
            console.log(`\n🧪 Running: ${this.name}`);
            await this.testFn();
            return true;
        } catch (error) {
            console.log(`❌ FAILED: ${this.name}`);
            console.log(`   Error: ${error.message}`);
            if (TEST_CONFIG.verbose) {
                console.log(`   Stack: ${error.stack}`);
            }
            return false;
        }
    }
}

// Test suite - requires payload argument
const tests = [
    new TestCase('Basic card authorization with payload and extracted metadata', () => {
        // Call authorize with payload and extracted_metadata
        const result = ffi.authorize(SAMPLE_PAYLOAD, SAMPLE_EXTRACTED_METADATA);
        // Basic validation - result should be a string (JSON or error message)
        if (typeof result !== 'string') {
            throw new Error(`Expected result to be a string, got ${typeof result}`);
        }
        console.log('========================================');
        console.log('RESULT');
        console.log('========================================');
        const parsed = JSON.parse(result);
        console.log(parsed);

    })
];

// Main test runner
async function runTests() {
    console.log('========================================');
    console.log('Connector Service FFI Node.js Test Suite');
    console.log('========================================');
    console.log('Note: Using hardcoded test data (Stripe test card)');
    console.log('');

    let passed = 0;
    let failed = 0;

    for (const test of tests) {
        const success = await test.run();
        if (success) {
            passed++;
        } else {
            failed++;
        }
    }

    if (failed > 0) {
        console.log('❌ Some tests failed!');
        process.exit(1);
    } else {
        console.log('✅ All tests passed!');
        process.exit(0);
    }
}

// Export functions for external use
module.exports = {
    runTests,
    tests
};

// Run tests if executed directly
if (require.main === module) {
    runTests().catch(error => {
        console.error('Fatal error running tests:', error);
        process.exit(1);
    });
}