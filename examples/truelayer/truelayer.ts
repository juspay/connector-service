// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py truelayer
//
// Truelayer — all integration scenarios and flows in one file.
// Run a scenario:  npx tsx truelayer.ts checkout_autocapture

import { PaymentClient, types } from 'hyperswitch-prism';
const { ConnectorConfig, ConnectorSpecificConfig, SdkOptions, Environment } = types;

const _defaultConfig: ConnectorConfig = {
    options: {
        environment: Environment.SANDBOX,
    },
};
// Standalone credentials (field names depend on connector auth type):
// _defaultConfig.connectorConfig = {
//     truelayer: { apiKey: { value: 'YOUR_API_KEY' } }
// };


// ANCHOR: scenario_functions
// Flow: PaymentService.create_server_authentication_token
async function createServerAuthenticationToken(merchantTransactionId: string, config: ConnectorConfig = _defaultConfig): Promise<any> {
    // Step 1: create_server_authentication_token
    const createResponse = await paymentClient.createServerAuthenticationToken({
        // No required fields
    });

    return { status: createResponse.status };
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
        },
        "state": {
            "token": "probe_access_token",
            "expiresInSeconds": 3600,
            "tokenType": "Bearer"
        }
    });

    return { status: getResponse.status };
}

// Flow: PaymentService.handle_event
async function handleEvent(merchantTransactionId: string, config: ConnectorConfig = _defaultConfig): Promise<any> {
    // Step 1: handle_event
    const handleResponse = await paymentClient.handleEvent({
        // No required fields
    });

    return { status: handleResponse.status };
}

// Flow: PaymentService.refund_get
async function refundGet(merchantTransactionId: string, config: ConnectorConfig = _defaultConfig): Promise<any> {
    // Step 1: refund_get
    const refundResponse = await paymentClient.refundGet({
        "merchantRefundId": "probe_refund_001",
        "connectorTransactionId": "probe_connector_txn_001",
        "refundId": "probe_refund_id_001",
        "state": {
            "token": "probe_access_token",
            "expiresInSeconds": 3600,
            "tokenType": "Bearer"
        }
    });

    return { status: refundResponse.status };
}


// Export all process* functions for the smoke test
export {
    createServerAuthenticationToken, get, handleEvent, refundGet
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
