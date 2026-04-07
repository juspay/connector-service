// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py cashfree
//
// Cashfree — all integration scenarios and flows in one file.
// Run a scenario:  npx tsx cashfree.ts checkout_autocapture

import { PaymentClient, types } from 'hyperswitch-prism';
const { ConnectorConfig, ConnectorSpecificConfig, SdkOptions, Environment } = types;

const _defaultConfig: ConnectorConfig = {
    options: {
        environment: Environment.SANDBOX,
    },
};
// Standalone credentials (field names depend on connector auth type):
// _defaultConfig.connectorConfig = {
//     cashfree: { apiKey: { value: 'YOUR_API_KEY' } }
// };


// ANCHOR: scenario_functions
// Flow: PaymentService.authorize (UpiCollect)
async function authorize(merchantTransactionId: string, config: ConnectorConfig = _defaultConfig): Promise<any> {
    // Step 1: Authorize — reserve funds on the payment method
    const authorizeResponse = await paymentClient.authorize({
        "merchantTransactionId": "probe_txn_001",
        "amount": {
            "minorAmount": 1000,
            "currency": "USD"
        },
        "paymentMethod": {
            "vpaId": "test@upi"
        },
        "captureMethod": "AUTOMATIC",
        "address": {
        },
        "authType": "NO_THREE_DS",
        "returnUrl": "https://example.com/return",
        "merchantOrderId": "probe_order_001"
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


// Export all process* functions for the smoke test
export {
    authorize
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
