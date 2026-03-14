// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py novalnet
//
// Flow: PaymentService.Void

const { ConnectorClient } = require('connector-service-node-ffi');

const client = new ConnectorClient({
    connector: 'Novalnet',
    environment: 'sandbox',
    connector_auth_type: {
        header_key: { api_key: 'YOUR_API_KEY' },
    },
});

async function voidPayment(merchantTransactionId) {
    // Step 1: Void — release reserved funds (cancel authorization)
    const voidResponse = await client.void({
        "merchant_void_id": "probe_void_001",  // Identification
        "connector_transaction_id": "probe_connector_txn_001"
    });

    return { status: voidResponse.status };
}

voidPayment("order_001").catch(console.error);
