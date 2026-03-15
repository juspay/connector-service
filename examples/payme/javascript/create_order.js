// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py payme
//
// Flow: PaymentService.CreateOrder

const { ConnectorClient } = require('connector-service-node-ffi');

const client = new ConnectorClient({
    connector: 'Payme',
    environment: 'sandbox',
    connector_auth_type: {
        header_key: { api_key: 'YOUR_API_KEY' },
    },
});

async function createOrder(merchantTransactionId) {
    // Step 1: create_order
    const createResponse = await client.createOrder({
        "merchantOrderId": "probe_order_001",  // Identification
        "amount": {  // Amount Information
            "minorAmount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
            "currency": "USD"  // ISO 4217 currency code (e.g., "USD", "EUR")
        }
    });

    return { status: createResponse.status };
}

createOrder("order_001").catch(console.error);
