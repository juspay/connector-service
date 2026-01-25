#!/usr/bin/env node
/**
 * Connector FFI JavaScript Example
 *
 * This example demonstrates how to use the connector-service FFI from JavaScript/Node.js.
 *
 * Run with: node example.js
 */

'use strict';

const {
  ConnectorClient,
  PaymentMethod,
  listConnectors,
  listFlows,
  getConnectorInfo,
  version
} = require('./index');

// Mock HTTP client for demonstration (returns simulated responses)
class MockHttpClient {
  async request(method, url, headers, body) {
    console.log(`    -> ${method} ${url}`);

    // Simulate responses based on URL patterns
    if (url.includes('stripe.com')) {
      if (url.includes('/payment_intents') && method === 'POST' && !url.includes('/capture') && !url.includes('/cancel')) {
        return {
          statusCode: 200,
          headers: {},
          body: JSON.stringify({
            id: 'pi_mock_stripe_12345',
            object: 'payment_intent',
            amount: 2000,
            currency: 'usd',
            status: 'succeeded'
          })
        };
      } else if (url.includes('/capture')) {
        return {
          statusCode: 200,
          headers: {},
          body: JSON.stringify({
            id: 'pi_mock_stripe_12345',
            status: 'succeeded',
            amount: 2000,
            currency: 'usd'
          })
        };
      } else if (url.includes('/refunds')) {
        return {
          statusCode: 200,
          headers: {},
          body: JSON.stringify({
            id: 're_mock_67890',
            amount: 500,
            currency: 'usd',
            status: 'succeeded'
          })
        };
      }
    } else if (url.includes('adyen.com')) {
      if (url.includes('/payments') && method === 'POST') {
        return {
          statusCode: 200,
          headers: {},
          body: JSON.stringify({
            pspReference: '883634778926265D',
            resultCode: 'Authorised',
            amount: { currency: 'EUR', value: 1500 }
          })
        };
      }
    }

    // Default: not found
    return {
      statusCode: 404,
      headers: {},
      body: JSON.stringify({ error: { message: 'Not Found' } })
    };
  }
}

async function main() {
  console.log('='.repeat(70));
  console.log('Connector FFI JavaScript Example');
  console.log('='.repeat(70));
  console.log();

  // Show library info
  console.log(`Library version: ${version()}`);
  console.log(`Supported connectors: ${listConnectors().join(', ')}`);
  console.log(`Supported flows: ${listFlows().join(', ')}`);
  console.log();

  // Show connector details
  console.log('-'.repeat(70));
  console.log('Connector Information');
  console.log('-'.repeat(70));

  for (const connector of ['stripe', 'adyen', 'forte']) {
    const info = getConnectorInfo(connector);
    if (info) {
      console.log(`\n${info.displayName}:`);
      console.log(`  Auth fields: ${info.authFields.join(', ')}`);
      console.log(`  Flows: ${info.supportedFlows.join(', ')}`);
      console.log(`  Currencies: ${info.supportedCurrencies.join(', ')}`);
    }
  }
  console.log();

  // Create mock HTTP client
  const mockHttp = new MockHttpClient();

  // Example 1: Stripe Payment
  console.log('-'.repeat(70));
  console.log('Example 1: Stripe Payment Authorization');
  console.log('-'.repeat(70));

  const stripeClient = new ConnectorClient('stripe', {
    api_key: 'sk_test_YOUR_KEY_HERE'
  }, {
    httpClient: mockHttp
  });

  console.log(`  Client: ${stripeClient.info.displayName}`);
  console.log(`  Base URL: ${stripeClient.info.baseUrl}`);
  console.log();

  const stripeResult = await stripeClient.authorize({
    amount: 2000,
    currency: 'USD',
    paymentMethod: PaymentMethod.card({
      number: '4242424242424242',
      expMonth: 12,
      expYear: 2025,
      cvc: '123',
      holderName: 'Test User'
    }),
    referenceId: 'order_001'
  });

  console.log(`  Success: ${stripeResult.success}`);
  console.log(`  Status: ${stripeResult.status}`);
  console.log(`  Transaction ID: ${stripeResult.transactionId}`);
  console.log(`  Amount: ${stripeResult.amount} ${stripeResult.currency}`);
  console.log();

  // Example 2: Stripe Refund
  if (stripeResult.success && stripeResult.transactionId) {
    console.log('-'.repeat(70));
    console.log('Example 2: Stripe Partial Refund');
    console.log('-'.repeat(70));

    const refundResult = await stripeClient.refund({
      transactionId: stripeResult.transactionId,
      amount: 500,
      currency: 'USD'
    });

    console.log(`  Success: ${refundResult.success}`);
    console.log(`  Status: ${refundResult.status}`);
    console.log(`  Refund ID: ${refundResult.transactionId}`);
    console.log();
  }

  // Example 3: Adyen Payment
  console.log('-'.repeat(70));
  console.log('Example 3: Adyen Payment Authorization');
  console.log('-'.repeat(70));

  const adyenClient = new ConnectorClient('adyen', {
    api_key: 'AQEyhmfuXNWTK0Qc...',
    merchant_id: 'TestMerchant'
  }, {
    httpClient: mockHttp
  });

  console.log(`  Client: ${adyenClient.info.displayName}`);
  console.log();

  const adyenResult = await adyenClient.authorize({
    amount: 1500,
    currency: 'EUR',
    paymentMethod: PaymentMethod.card({
      number: '4111111111111111',
      expMonth: 3,
      expYear: 2030,
      cvc: '737',
      holderName: 'Jane Smith'
    }),
    referenceId: 'order_002'
  });

  console.log(`  Success: ${adyenResult.success}`);
  console.log(`  Status: ${adyenResult.status}`);
  console.log(`  Transaction ID: ${adyenResult.transactionId}`);
  console.log(`  Amount: ${adyenResult.amount} ${adyenResult.currency}`);
  console.log();

  // Example 4: Error Handling
  console.log('-'.repeat(70));
  console.log('Example 4: Error Handling');
  console.log('-'.repeat(70));

  try {
    const badClient = new ConnectorClient('unknown_connector', {});
    console.log('  Should not reach here');
  } catch (e) {
    console.log(`  Caught expected error: ${e.message}`);
  }
  console.log();

  console.log('='.repeat(70));
  console.log('All examples completed!');
  console.log('='.repeat(70));
  console.log();
  console.log('Key Features:');
  console.log('  - Pure JavaScript implementation (no native FFI required)');
  console.log('  - Native FFI support when ffi-napi is installed');
  console.log('  - Full TypeScript type definitions');
  console.log('  - High-level API: authorize(), capture(), refund(), void(), sync()');
  console.log('  - Pluggable HTTP client');
  console.log();
}

main().catch(console.error);
