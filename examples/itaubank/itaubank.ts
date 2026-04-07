// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py itaubank
//
// Itaubank — all integration scenarios and flows in one file.
// Run a scenario:  npx tsx itaubank.ts checkout_autocapture

import { PaymentClient, types } from 'hyperswitch-prism';
const { ConnectorConfig, ConnectorSpecificConfig, SdkOptions, Environment } = types;

const _defaultConfig: ConnectorConfig = {
    options: {
        environment: Environment.SANDBOX,
    },
};
// Standalone credentials (field names depend on connector auth type):
// _defaultConfig.connectorConfig = {
//     itaubank: { apiKey: { value: 'YOUR_API_KEY' } }
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


// Export all process* functions for the smoke test
export {
    createServerAuthenticationToken
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
