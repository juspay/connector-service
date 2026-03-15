// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py volt
//
// Flow: PaymentService.Get

const { ConnectorClient } = require('connector-service-node-ffi');

const client = new ConnectorClient({
    connector: 'Volt',
    environment: 'sandbox',
    connector_auth_type: {
        header_key: { api_key: 'YOUR_API_KEY' },
    },
});

async function get(merchantTransactionId) {
    // Step 1: Get — retrieve current payment status from the connector
    const getResponse = await client.get({
        "connectorTransactionId": "probe_connector_txn_001",
        "amount": {  // Amount Information
            "minorAmount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
            "currency": "USD"  // ISO 4217 currency code (e.g., "USD", "EUR")
        },
        "state": {  // State Information
            "accessToken": {  // Access token obtained from connector
                "token": {"value": "probe_access_token"},  // The token string.
                "expiresInSeconds": 3600,  // Expiration timestamp (seconds since epoch)
                "tokenType": "Bearer"  // Token type (e.g., "Bearer", "Basic").
            }
        }
    });

    return { status: getResponse.status };
}

get("order_001").catch(console.error);
