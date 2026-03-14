// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py trustpay
//
// Flow: PaymentService.CreateOrder

const { ConnectorClient } = require('connector-service-node-ffi');

const client = new ConnectorClient({
    connector: 'Trustpay',
    environment: 'sandbox',
    connector_auth_type: {
        header_key: { api_key: 'YOUR_API_KEY' },
    },
});

async function createOrder(merchantTransactionId) {
    // Step 1: create_order
    const createResponse = await client.createOrder({
        "merchant_order_id": "probe_order_001",  // Identification
        "amount": {  // Amount Information
            "minor_amount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
            "currency": "USD"  // ISO 4217 currency code (e.g., "USD", "EUR")
        },
        "state": {  // State Information
            "access_token": {  // Access token obtained from connector
                "token": {"value": "probe_access_token"},  // The token string.
                "expires_in_seconds": 3600,  // Expiration timestamp (seconds since epoch)
                "token_type": "Bearer"  // Token type (e.g., "Bearer", "Basic").
            }
        }
    });

    return { status: createResponse.status };
}

createOrder("order_001").catch(console.error);
