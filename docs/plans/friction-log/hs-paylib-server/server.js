/**
 * Payment Server with hs-paylib Integration
 * Routes USD payments to Stripe, EUR payments to Adyen
 */

require('dotenv').config();
const express = require('express');
const { PaymentClient, types } = require('hs-paylib');

const app = express();
app.use(express.json());

// Payment client instances (created lazily per currency)
let stripeClient = null;
let adyenClient = null;

/**
 * Initialize Stripe client for USD payments
 */
function getStripeClient() {
  if (!stripeClient) {
    const stripeConfig = {
      connectorConfig: {
        stripe: {
          apiKey: { value: process.env.STRIPE_API_KEY }
        }
      }
    };

    const requestConfig = {
      http: {
        totalTimeoutMs: 30000,
        connectTimeoutMs: 10000,
      }
    };

    stripeClient = new PaymentClient(stripeConfig, requestConfig);
    console.log('Stripe client initialized');
  }
  return stripeClient;
}

/**
 * Initialize Adyen client for EUR payments
 */
function getAdyenClient() {
  if (!adyenClient) {
    const adyenConfig = {
      connectorConfig: {
        adyen: {
          apiKey: { value: process.env.ADYEN_API_KEY },
          merchantAccount: { value: process.env.ADYEN_MERCHANT_ACCOUNT }
        }
      }
    };

    const requestConfig = {
      http: {
        totalTimeoutMs: 30000,
        connectTimeoutMs: 10000,
      }
    };

    adyenClient = new PaymentClient(adyenConfig, requestConfig);
    console.log('Adyen client initialized');
  }
  return adyenClient;
}

/**
 * Get the appropriate client based on currency
 */
function getClientForCurrency(currency) {
  const currencyUpper = currency.toUpperCase();
  
  if (currencyUpper === 'USD') {
    return { client: getStripeClient(), connector: types.Connector.STRIPE };
  } else if (currencyUpper === 'EUR') {
    return { client: getAdyenClient(), connector: types.Connector.ADYEN };
  } else {
    throw new Error(`Unsupported currency: ${currency}. Only USD and EUR are supported.`);
  }
}

/**
 * Map numeric status to human-readable string
 */
function mapStatus(status) {
  const statusMap = {
    0: 'PENDING',
    1: 'PROCESSING',
    2: 'SUCCESS',
    3: 'FAILED',
    4: 'CANCELLED',
    5: 'AUTHORIZED',
    6: 'CAPTURED',
    7: 'REFUNDED',
    8: 'CHARGED',  // Automatic capture success
  };
  return statusMap[status] || `UNKNOWN(${status})`;
}

/**
 * POST /authorize - Authorize a payment
 * Routes based on currency: USD -> Stripe, EUR -> Adyen
 */
app.post('/authorize', async (req, res) => {
  try {
    const {
      merchantTransactionId,
      amount,
      currency,
      cardNumber,
      cardExpMonth,
      cardExpYear,
      cardCvc,
      cardHolderName,
      browserInfo
    } = req.body;

    // Validate required fields
    if (!merchantTransactionId || !amount || !currency || !cardNumber) {
      return res.status(400).json({
        error: 'Missing required fields: merchantTransactionId, amount, currency, cardNumber'
      });
    }

    // Get appropriate client for currency
    const { client } = getClientForCurrency(currency);
    const currencyUpper = currency.toUpperCase();

    // Build authorize request
    const authorizeRequest = {
      merchantTransactionId,
      amount: {
        minorAmount: Math.round(amount * 100), // Convert to minor units (cents)
        currency: types.Currency[currencyUpper],
      },
      captureMethod: types.CaptureMethod.AUTOMATIC,
      paymentMethod: {
        card: {
          cardNumber: { value: cardNumber },
          cardExpMonth: { value: cardExpMonth || '12' },
          cardExpYear: { value: cardExpYear || '2027' },
          cardCvc: { value: cardCvc || '123' },
          cardHolderName: { value: cardHolderName || 'Test User' },
        }
      },
      address: { billingAddress: {} },
      authType: types.AuthenticationType.NO_THREE_DS,
      returnUrl: "https://example.com/return",
      orderDetails: [],
    };

    // Adyen requires browser_info for 3D Secure compliance
    // Field names use snake_case as expected by the FFI layer
    if (currencyUpper === 'EUR') {
      authorizeRequest.browserInfo = browserInfo || {
        user_agent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        accept_header: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        language: 'en-US',
        color_depth: 24,
        screen_height: 1080,
        screen_width: 1920,
        time_zone: -480,
        java_enabled: false,
        java_script_enabled: true
      };
    }

    console.log(`Processing authorization for ${currencyUpper} via ${currencyUpper === 'USD' ? 'Stripe' : 'Adyen'}...`);
    
    const response = await client.authorize(authorizeRequest);
    
    const statusText = mapStatus(response.status);
    console.log('Authorization successful:', {
      status: response.status,
      statusText: statusText,
      transactionId: response.connectorTransactionId,
      merchantTransactionId: response.merchantTransactionId
    });

    res.json({
      success: true,
      status: response.status,
      statusText: statusText,
      connectorTransactionId: response.connectorTransactionId,
      merchantTransactionId: response.merchantTransactionId,
      currency: currencyUpper,
      connector: currencyUpper === 'USD' ? 'stripe' : 'adyen'
    });

  } catch (error) {
    console.error('Authorization error:', error);
    res.status(500).json({
      success: false,
      error: error.message,
      code: error.errorCode || 'UNKNOWN_ERROR',
      details: error.proto ? {
        message: error.proto.errorMessage,
        docUrl: error.proto.docUrl
      } : undefined
    });
  }
});

/**
 * POST /refund - Refund a payment
 * Routes based on original currency
 */
app.post('/refund', async (req, res) => {
  try {
    const {
      merchantTransactionId,
      connectorTransactionId,
      amount,
      currency
    } = req.body;

    // Validate required fields
    if (!merchantTransactionId || !connectorTransactionId || !amount || !currency) {
      return res.status(400).json({
        error: 'Missing required fields: merchantTransactionId, connectorTransactionId, amount, currency'
      });
    }

    // Get appropriate client for currency
    const { client } = getClientForCurrency(currency);
    const currencyUpper = currency.toUpperCase();

    // Build refund request
    // Note: Using refundAmount (not amount) as required by the FFI layer
    const refundRequest = {
      merchantTransactionId: `${merchantTransactionId}_refund_${Date.now()}`,
      refundAmount: {
        minorAmount: Math.round(amount * 100),
        currency: types.Currency[currencyUpper],
      },
      connectorTransactionId: connectorTransactionId,
      reason: 'Customer requested refund'
    };

    console.log(`Processing refund for ${currencyUpper} via ${currencyUpper === 'USD' ? 'Stripe' : 'Adyen'}...`);
    
    const response = await client.refund(refundRequest);
    
    const statusText = mapStatus(response.status);
    console.log('Refund successful:', {
      status: response.status,
      statusText: statusText,
      refundTransactionId: response.connectorRefundTransactionId
    });

    res.json({
      success: true,
      status: response.status,
      statusText: statusText,
      connectorRefundTransactionId: response.connectorRefundTransactionId,
      merchantTransactionId: response.merchantTransactionId,
      currency: currencyUpper,
      connector: currencyUpper === 'USD' ? 'stripe' : 'adyen'
    });

  } catch (error) {
    console.error('Refund error:', error);
    res.status(500).json({
      success: false,
      error: error.message,
      code: error.errorCode || 'UNKNOWN_ERROR',
      details: error.proto ? {
        message: error.proto.errorMessage,
        docUrl: error.proto.docUrl
      } : undefined
    });
  }
});

/**
 * GET /health - Health check endpoint
 */
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    stripeConfigured: !!process.env.STRIPE_API_KEY,
    adyenConfigured: !!(process.env.ADYEN_API_KEY && process.env.ADYEN_MERCHANT_ACCOUNT)
  });
});

/**
 * GET / - API info
 */
app.get('/', (req, res) => {
  res.json({
    name: 'hs-paylib Payment Server',
    description: 'Payment routing: USD -> Stripe, EUR -> Adyen',
    endpoints: {
      'POST /authorize': 'Authorize a payment (USD to Stripe, EUR to Adyen)',
      'POST /refund': 'Refund a payment',
      'GET /health': 'Health check'
    }
  });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`
╔════════════════════════════════════════════════════════╗
║          hs-paylib Payment Server                      ║
╠════════════════════════════════════════════════════════╣
║  Server running on port ${PORT}                        ║
║                                                        ║
║  Routing:                                              ║
║    USD → Stripe                                        ║
║    EUR → Adyen                                         ║
║                                                        ║
║  Endpoints:                                            ║
║    POST /authorize - Process payments                  ║
║    POST /refund    - Process refunds                   ║
║    GET  /health    - Health check                      ║
╚════════════════════════════════════════════════════════╝
  `);
});
