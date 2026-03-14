// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py worldpayvantiv
//
// Flow: PaymentService.Reverse

const { ConnectorClient } = require('connector-service-node-ffi');

const client = new ConnectorClient({
    connector: 'Worldpayvantiv',
    environment: 'sandbox',
    connector_auth_type: {
        header_key: { api_key: 'YOUR_API_KEY' },
    },
});

async function reverse(merchantTransactionId) {
    // Step 1: reverse
    const reverseResponse = await client.reverse({
        "merchant_reverse_id": "probe_reverse_001",  // Identification
        "connector_transaction_id": "probe_connector_txn_001"
    });

    return { status: reverseResponse.status };
}

reverse("order_001").catch(console.error);
