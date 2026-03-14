// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py globalpay
//
// Flow: PaymentService.Void

const { ConnectorClient } = require('connector-service-node-ffi');

const client = new ConnectorClient({
    connector: 'Globalpay',
    environment: 'sandbox',
    connector_auth_type: {
        header_key: { api_key: 'YOUR_API_KEY' },
    },
});

async function voidPayment(merchantTransactionId) {
    // Step 1: Void — release reserved funds (cancel authorization)
    const voidResponse = await client.void({
        "merchant_void_id": "probe_void_001",  // Identification
        "connector_transaction_id": "probe_connector_txn_001",
        "state": {  // State Information
            "access_token": {  // Access token obtained from connector
                "token": {"value": "probe_access_token"},  // The token string.
                "expires_in_seconds": 3600,  // Expiration timestamp (seconds since epoch)
                "token_type": "Bearer"  // Token type (e.g., "Bearer", "Basic").
            }
        }
    });

    return { status: voidResponse.status };
}

voidPayment("order_001").catch(console.error);
