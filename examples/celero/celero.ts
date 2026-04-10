// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py celero
//
// Celero — all integration scenarios and flows in one file.
// Run a scenario:  npx tsx celero.ts checkout_autocapture

import { PaymentClient, types } from 'hyperswitch-prism';
const { ConnectorConfig, ConnectorSpecificConfig, SdkOptions, Environment } = types;

const _defaultConfig: ConnectorConfig = {
    options: {
        environment: Environment.SANDBOX,
    },
};
// Standalone credentials (field names depend on connector auth type):
// _defaultConfig.connectorConfig = {
//     celero: { apiKey: { value: 'YOUR_API_KEY' } }
// };


// ANCHOR: scenario_functions
// One-step Payment (Authorize + Capture)
// Simple payment that authorizes and captures in one call. Use for immediate charges.
async function processCheckoutAutocapture(merchantTransactionId: string, config: ConnectorConfig = _defaultConfig): Promise<any> {
    const paymentClient = new PaymentClient(config);

    // Step 1: Authorize — reserve funds on the payment method
    const authorizeResponse = await paymentClient.authorize({
        "merchantTransactionId": "probe_txn_001",
        "amount": {
            "minorAmount": 1000,
            "currency": "USD"
        },
        "paymentMethod": {
            "cardNumber": "4111111111111111",
            "cardExpMonth": "03",
            "cardExpYear": "2030",
            "cardCvc": "737",
            "cardHolderName": "John Doe"
        },
        "captureMethod": "AUTOMATIC",
        "address": {
        },
        "authType": "NO_THREE_DS",
        "returnUrl": "https://example.com/return"
    });

    if (authorizeResponse.status === 'FAILED') {
        throw new Error(`Payment failed: ${authorizeResponse.error?.message}`);
    }
    if (authorizeResponse.status === 'PENDING') {
        // Awaiting async confirmation — handle via webhook
        return { status: 'pending', transactionId: authorizeResponse.connectorTransactionId };
    }

    return { status: authorizeResponse.status, transactionId: authorizeResponse.connectorTransactionId, error: authorizeResponse.error };
}

// Card Payment (Authorize + Capture)
// Two-step card payment. First authorize, then capture. Use when you need to verify funds before finalizing.
async function processCheckoutCard(merchantTransactionId: string, config: ConnectorConfig = _defaultConfig): Promise<any> {
    const paymentClient = new PaymentClient(config);

    // Step 1: Authorize — reserve funds on the payment method
    const authorizeResponse = await paymentClient.authorize({
        "merchantTransactionId": "probe_txn_001",
        "amount": {
            "minorAmount": 1000,
            "currency": "USD"
        },
        "paymentMethod": {
            "cardNumber": "4111111111111111",
            "cardExpMonth": "03",
            "cardExpYear": "2030",
            "cardCvc": "737",
            "cardHolderName": "John Doe"
        },
        "captureMethod": "MANUAL",
        "address": {
        },
        "authType": "NO_THREE_DS",
        "returnUrl": "https://example.com/return"
    });

    if (authorizeResponse.status === 'FAILED') {
        throw new Error(`Payment failed: ${authorizeResponse.error?.message}`);
    }
    if (authorizeResponse.status === 'PENDING') {
        // Awaiting async confirmation — handle via webhook
        return { status: 'pending', transactionId: authorizeResponse.connectorTransactionId };
    }

    // Step 2: Capture — settle the reserved funds
    const captureResponse = await paymentClient.capture({
        "merchantCaptureId": "probe_capture_001",
        "connectorTransactionId": authorizeResponse.connectorTransactionId,  // from authorize response
        "amountToCapture": {
            "minorAmount": 1000,
            "currency": "USD"
        }
    });

    if (captureResponse.status === 'FAILED') {
        throw new Error(`Capture failed: ${captureResponse.error?.message}`);
    }

    return { status: captureResponse.status, transactionId: authorizeResponse.connectorTransactionId, error: authorizeResponse.error };
}

// Refund
// Return funds to the customer for a completed payment.
async function processRefund(merchantTransactionId: string, config: ConnectorConfig = _defaultConfig): Promise<any> {
    const paymentClient = new PaymentClient(config);

    // Step 1: Authorize — reserve funds on the payment method
    const authorizeResponse = await paymentClient.authorize({
        "merchantTransactionId": "probe_txn_001",
        "amount": {
            "minorAmount": 1000,
            "currency": "USD"
        },
        "paymentMethod": {
            "cardNumber": "4111111111111111",
            "cardExpMonth": "03",
            "cardExpYear": "2030",
            "cardCvc": "737",
            "cardHolderName": "John Doe"
        },
        "captureMethod": "AUTOMATIC",
        "address": {
        },
        "authType": "NO_THREE_DS",
        "returnUrl": "https://example.com/return"
    });

    if (authorizeResponse.status === 'FAILED') {
        throw new Error(`Payment failed: ${authorizeResponse.error?.message}`);
    }
    if (authorizeResponse.status === 'PENDING') {
        // Awaiting async confirmation — handle via webhook
        return { status: 'pending', transactionId: authorizeResponse.connectorTransactionId };
    }

    // Step 2: Refund — return funds to the customer
    const refundResponse = await paymentClient.refund({
        "merchantRefundId": "probe_refund_001",
        "connectorTransactionId": authorizeResponse.connectorTransactionId,  // from authorize response
        "paymentAmount": 1000,
        "refundAmount": {
            "minorAmount": 1000,
            "currency": "USD"
        },
        "reason": "customer_request"
    });

    if (refundResponse.status === 'FAILED') {
        throw new Error(`Refund failed: ${refundResponse.error?.message}`);
    }

    return { status: refundResponse.status, error: refundResponse.error };
}

// Void Payment
// Cancel an authorized but not-yet-captured payment.
async function processVoidPayment(merchantTransactionId: string, config: ConnectorConfig = _defaultConfig): Promise<any> {
    const paymentClient = new PaymentClient(config);

    // Step 1: Authorize — reserve funds on the payment method
    const authorizeResponse = await paymentClient.authorize({
        "merchantTransactionId": "probe_txn_001",
        "amount": {
            "minorAmount": 1000,
            "currency": "USD"
        },
        "paymentMethod": {
            "cardNumber": "4111111111111111",
            "cardExpMonth": "03",
            "cardExpYear": "2030",
            "cardCvc": "737",
            "cardHolderName": "John Doe"
        },
        "captureMethod": "MANUAL",
        "address": {
        },
        "authType": "NO_THREE_DS",
        "returnUrl": "https://example.com/return"
    });

    if (authorizeResponse.status === 'FAILED') {
        throw new Error(`Payment failed: ${authorizeResponse.error?.message}`);
    }
    if (authorizeResponse.status === 'PENDING') {
        // Awaiting async confirmation — handle via webhook
        return { status: 'pending', transactionId: authorizeResponse.connectorTransactionId };
    }

    // Step 2: Void — release reserved funds (cancel authorization)
    const voidResponse = await paymentClient.void({
        "merchantVoidId": "probe_void_001",
        "connectorTransactionId": authorizeResponse.connectorTransactionId,  // from authorize response
    });

    return { status: voidResponse.status, transactionId: authorizeResponse.connectorTransactionId, error: voidResponse.error };
}

// Get Payment Status
// Retrieve current payment status from the connector.
async function processGetPayment(merchantTransactionId: string, config: ConnectorConfig = _defaultConfig): Promise<any> {
    const paymentClient = new PaymentClient(config);

    // Step 1: Authorize — reserve funds on the payment method
    const authorizeResponse = await paymentClient.authorize({
        "merchantTransactionId": "probe_txn_001",
        "amount": {
            "minorAmount": 1000,
            "currency": "USD"
        },
        "paymentMethod": {
            "cardNumber": "4111111111111111",
            "cardExpMonth": "03",
            "cardExpYear": "2030",
            "cardCvc": "737",
            "cardHolderName": "John Doe"
        },
        "captureMethod": "MANUAL",
        "address": {
        },
        "authType": "NO_THREE_DS",
        "returnUrl": "https://example.com/return"
    });

    if (authorizeResponse.status === 'FAILED') {
        throw new Error(`Payment failed: ${authorizeResponse.error?.message}`);
    }
    if (authorizeResponse.status === 'PENDING') {
        // Awaiting async confirmation — handle via webhook
        return { status: 'pending', transactionId: authorizeResponse.connectorTransactionId };
    }

    // Step 2: Get — retrieve current payment status from the connector
    const getResponse = await paymentClient.get({
        "merchantTransactionId": "probe_merchant_txn_001",
        "connectorTransactionId": authorizeResponse.connectorTransactionId,  // from authorize response
        "amount": {
            "minorAmount": 1000,
            "currency": "USD"
        }
    });

    return { status: getResponse.status, transactionId: getResponse.connectorTransactionId, error: getResponse.error };
}

// Flow: PaymentService.authorize (Card)
async function authorize(merchantTransactionId: string, config: ConnectorConfig = _defaultConfig): Promise<any> {
    // Step 1: Authorize — reserve funds on the payment method
    const authorizeResponse = await paymentClient.authorize({
        "merchantTransactionId": "probe_txn_001",
        "amount": {
            "minorAmount": 1000,
            "currency": "USD"
        },
        "paymentMethod": {
            "cardNumber": "4111111111111111",
            "cardExpMonth": "03",
            "cardExpYear": "2030",
            "cardCvc": "737",
            "cardHolderName": "John Doe"
        },
        "captureMethod": "AUTOMATIC",
        "address": {
        },
        "authType": "NO_THREE_DS",
        "returnUrl": "https://example.com/return"
    });

    if (authorizeResponse.status === 'FAILED') {
        throw new Error(`Payment failed: ${authorizeResponse.error?.message}`);
    }
    if (authorizeResponse.status === 'PENDING') {
        // Awaiting async confirmation — handle via webhook
        return { status: 'pending', transactionId: authorizeResponse.connectorTransactionId };
    }

    return { status: authorizeResponse.status, transactionId: authorizeResponse.connectorTransactionId };
}

// Flow: PaymentService.capture
async function capture(merchantTransactionId: string, config: ConnectorConfig = _defaultConfig): Promise<any> {
    // Step 1: Capture — settle the reserved funds
    const captureResponse = await paymentClient.capture({
        "merchantCaptureId": "probe_capture_001",
        "connectorTransactionId": "probe_connector_txn_001",
        "amountToCapture": {
            "minorAmount": 1000,
            "currency": "USD"
        }
    });

    if (captureResponse.status === 'FAILED') {
        throw new Error(`Capture failed: ${captureResponse.error?.message}`);
    }

    return { status: captureResponse.status };
}

// Flow: PaymentService.get
async function get(merchantTransactionId: string, config: ConnectorConfig = _defaultConfig): Promise<any> {
    // Step 1: Get — retrieve current payment status from the connector
    const getResponse = await paymentClient.get({
        "merchantTransactionId": "probe_merchant_txn_001",
        "connectorTransactionId": "probe_connector_txn_001",
        "amount": {
            "minorAmount": 1000,
            "currency": "USD"
        }
    });

    return { status: getResponse.status };
}

// Flow: PaymentService.proxy_authorize
async function proxyAuthorize(merchantTransactionId: string, config: ConnectorConfig = _defaultConfig): Promise<any> {
    // Step 1: proxy_authorize
    const proxyResponse = await paymentClient.proxyAuthorize({
        "merchantTransactionId": "probe_proxy_txn_001",
        "amount": {
            "minorAmount": 1000,
            "currency": "USD"
        },
        "cardProxy": {
            "cardNumber": "4111111111111111",
            "cardExpMonth": "03",
            "cardExpYear": "2030",
            "cardCvc": "123",
            "cardHolderName": "John Doe"
        },
        "address": {
        },
        "captureMethod": "AUTOMATIC",
        "authType": "NO_THREE_DS",
        "returnUrl": "https://example.com/return"
    });

    return { status: proxyResponse.status };
}

// Flow: PaymentService.refund
async function refund(merchantTransactionId: string, config: ConnectorConfig = _defaultConfig): Promise<any> {
    // Step 1: Refund — return funds to the customer
    const refundResponse = await paymentClient.refund({
        "merchantRefundId": "probe_refund_001",
        "connectorTransactionId": "probe_connector_txn_001",
        "paymentAmount": 1000,
        "refundAmount": {
            "minorAmount": 1000,
            "currency": "USD"
        },
        "reason": "customer_request"
    });

    if (refundResponse.status === 'FAILED') {
        throw new Error(`Refund failed: ${refundResponse.error?.message}`);
    }

    return { status: refundResponse.status };
}

// Flow: PaymentService.refund_get
async function refundGet(merchantTransactionId: string, config: ConnectorConfig = _defaultConfig): Promise<any> {
    // Step 1: refund_get
    const refundResponse = await paymentClient.refundGet({
        "merchantRefundId": "probe_refund_001",
        "connectorTransactionId": "probe_connector_txn_001",
        "refundId": "probe_refund_id_001"
    });

    return { status: refundResponse.status };
}

// Flow: PaymentService.void
async function voidPayment(merchantTransactionId: string, config: ConnectorConfig = _defaultConfig): Promise<any> {
    // Step 1: Void — release reserved funds (cancel authorization)
    const voidResponse = await paymentClient.void({
        "merchantVoidId": "probe_void_001",
        "connectorTransactionId": "probe_connector_txn_001"
    });

    return { status: voidResponse.status };
}


// Export all process* functions for the smoke test
export {
    processCheckoutAutocapture, processCheckoutCard, processRefund, processVoidPayment, processGetPayment, authorize, capture, get, proxyAuthorize, refund, refundGet, voidPayment
};

// CLI runner
if (require.main === module) {
    const scenario = process.argv[2] || 'checkout_autocapture';
    const key = 'process' + scenario.replace(/_([a-z])/g, (_, l) => l.toUpperCase()).replace(/^(.)/, c => c.toUpperCase());
    const fn = (globalThis as any)[key] || (exports as any)[key];
    if (!fn) {
        const available = Object.keys(exports).map(k =>
            k.replace(/^process/, '').replace(/([A-Z])/g, '_$1').toLowerCase().replace(/^_/, '')
        );
        console.error(`Unknown scenario: ${scenario}. Available: ${available.join(', ')}`);
        process.exit(1);
    }
    fn('order_001').catch(console.error);
}
