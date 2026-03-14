// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py payme
//
// Flow: PaymentService.Void

const { ConnectorClient } = require('connector-service-node-ffi');

const client = new ConnectorClient({
    connector: 'Payme',
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
        "amount": {  // Amount Information
            "minor_amount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
            "currency": "USD"  // ISO 4217 currency code (e.g., "USD", "EUR")
        }
    });

    return { status: voidResponse.status };
}

voidPayment("order_001").catch(console.error);
