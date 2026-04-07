/**
 * Test script for hs-paylib server
 * Tests authorization and refund flows for USD (Stripe) and EUR (Adyen)
 */

const http = require('http');

const BASE_URL = 'http://localhost:3000';

// Test card data
const testCards = {
  stripe: {
    number: '4111111111111111',  // Stripe test card
    expMonth: '12',
    expYear: '2027',
    cvc: '123',
    holderName: 'Test User'
  },
  adyen: {
    number: '4111111111111111',  // Adyen test card
    expMonth: '12',
    expYear: '2027',
    cvc: '123',
    holderName: 'Test User'
  }
};

// Helper function to make HTTP requests
function makeRequest(path, data) {
  return new Promise((resolve, reject) => {
    const postData = JSON.stringify(data);
    
    const options = {
      hostname: 'localhost',
      port: 3000,
      path: path,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postData)
      }
    };

    const req = http.request(options, (res) => {
      let responseData = '';
      
      res.on('data', (chunk) => {
        responseData += chunk;
      });
      
      res.on('end', () => {
        try {
          const parsed = JSON.parse(responseData);
          resolve({ statusCode: res.statusCode, data: parsed });
        } catch (e) {
          resolve({ statusCode: res.statusCode, data: responseData });
        }
      });
    });

    req.on('error', (error) => {
      reject(error);
    });

    req.write(postData);
    req.end();
  });
}

// Helper to check health
function checkHealth() {
  return new Promise((resolve, reject) => {
    http.get(`${BASE_URL}/health`, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          resolve(data);
        }
      });
    }).on('error', reject);
  });
}

// Test functions
async function testUSDAuthorization() {
  console.log('\n🧪 Testing USD Authorization (Stripe)...');
  
  const request = {
    merchantTransactionId: `test_usd_${Date.now()}`,
    amount: 10.00,
    currency: 'USD',
    cardNumber: testCards.stripe.number,
    cardExpMonth: testCards.stripe.expMonth,
    cardExpYear: testCards.stripe.expYear,
    cardCvc: testCards.stripe.cvc,
    cardHolderName: testCards.stripe.holderName
  };

  try {
    const response = await makeRequest('/authorize', request);
    console.log('✅ USD Authorization Response:', JSON.stringify(response.data, null, 2));
    return response.data;
  } catch (error) {
    console.error('❌ USD Authorization Error:', error.message);
    throw error;
  }
}

async function testEURAuthorization() {
  console.log('\n🧪 Testing EUR Authorization (Adyen)...');
  
  const request = {
    merchantTransactionId: `test_eur_${Date.now()}`,
    amount: 10.00,
    currency: 'EUR',
    cardNumber: testCards.adyen.number,
    cardExpMonth: testCards.adyen.expMonth,
    cardExpYear: testCards.adyen.expYear,
    cardCvc: testCards.adyen.cvc,
    cardHolderName: testCards.adyen.holderName
  };

  try {
    const response = await makeRequest('/authorize', request);
    console.log('✅ EUR Authorization Response:', JSON.stringify(response.data, null, 2));
    return response.data;
  } catch (error) {
    console.error('❌ EUR Authorization Error:', error.message);
    throw error;
  }
}

async function testUSDRefund(authData) {
  console.log('\n🧪 Testing USD Refund (Stripe)...');
  
  const request = {
    merchantTransactionId: authData.merchantTransactionId,
    connectorTransactionId: authData.connectorTransactionId,
    amount: 10.00,
    currency: 'USD'
  };

  try {
    const response = await makeRequest('/refund', request);
    console.log('✅ USD Refund Response:', JSON.stringify(response.data, null, 2));
    return response.data;
  } catch (error) {
    console.error('❌ USD Refund Error:', error.message);
    throw error;
  }
}

async function testEURRefund(authData) {
  console.log('\n🧪 Testing EUR Refund (Adyen)...');
  
  const request = {
    merchantTransactionId: authData.merchantTransactionId,
    connectorTransactionId: authData.connectorTransactionId,
    amount: 10.00,
    currency: 'EUR'
  };

  try {
    const response = await makeRequest('/refund', request);
    console.log('✅ EUR Refund Response:', JSON.stringify(response.data, null, 2));
    return response.data;
  } catch (error) {
    console.error('❌ EUR Refund Error:', error.message);
    throw error;
  }
}

// Main test runner
async function runTests() {
  console.log('═══════════════════════════════════════════════════');
  console.log('  hs-paylib Server Test Suite');
  console.log('═══════════════════════════════════════════════════');

  // Check if server is running
  try {
    const health = await checkHealth();
    console.log('\n✅ Server is running');
    console.log('   Stripe configured:', health.stripeConfigured);
    console.log('   Adyen configured:', health.adyenConfigured);
  } catch (error) {
    console.error('\n❌ Server is not running. Please start it first:');
    console.error('   npm start');
    process.exit(1);
  }

  let results = {
    usdAuth: null,
    eurAuth: null,
    usdRefund: null,
    eurRefund: null
  };

  // Run tests
  try {
    results.usdAuth = await testUSDAuthorization();
  } catch (e) {
    console.log('USD Authorization failed (expected if credentials not configured)');
  }

  try {
    results.eurAuth = await testEURAuthorization();
  } catch (e) {
    console.log('EUR Authorization failed (expected if credentials not configured)');
  }

  // Only test refunds if authorizations succeeded
  if (results.usdAuth && results.usdAuth.success) {
    try {
      results.usdRefund = await testUSDRefund(results.usdAuth);
    } catch (e) {
      console.log('USD Refund failed');
    }
  }

  if (results.eurAuth && results.eurAuth.success) {
    try {
      results.eurRefund = await testEURRefund(results.eurAuth);
    } catch (e) {
      console.log('EUR Refund failed');
    }
  }

  // Summary
  console.log('\n═══════════════════════════════════════════════════');
  console.log('  Test Summary');
  console.log('═══════════════════════════════════════════════════');
  console.log('USD Authorization:', results.usdAuth?.success ? '✅ PASS' : '❌ FAIL');
  console.log('EUR Authorization:', results.eurAuth?.success ? '✅ PASS' : '❌ FAIL');
  console.log('USD Refund:', results.usdRefund?.success ? '✅ PASS' : '❌ FAIL');
  console.log('EUR Refund:', results.eurRefund?.success ? '✅ PASS' : '❌ FAIL');
  console.log('═══════════════════════════════════════════════════\n');
}

// Run tests if this file is executed directly
if (require.main === module) {
  runTests().catch(console.error);
}

module.exports = { runTests, testUSDAuthorization, testEURAuthorization };
