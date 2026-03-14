// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py globalpay
//
// Flow: MerchantAuthenticationService.CreateAccessToken

const { ConnectorClient } = require('connector-service-node-ffi');

const client = new ConnectorClient({
    connector: 'Globalpay',
    environment: 'sandbox',
    connector_auth_type: {
        header_key: { api_key: 'YOUR_API_KEY' },
    },
});

async function createAccessToken(merchantTransactionId) {
    // Step 1: create_access_token
    const createResponse = await client.createAccessToken({
        // No required fields
    });

    return { status: createResponse.status };
}

createAccessToken("order_001").catch(console.error);
