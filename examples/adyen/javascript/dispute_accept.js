// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py adyen
//
// Flow: DisputeService.Accept

const { ConnectorClient } = require('connector-service-node-ffi');

const client = new ConnectorClient({
    connector: 'Adyen',
    environment: 'sandbox',
    connector_auth_type: {
        header_key: { api_key: 'YOUR_API_KEY' },
    },
});

async function disputeAccept(merchantTransactionId) {
    // Step 1: dispute_accept
    const disputeResponse = await client.disputeAccept({
        "merchant_dispute_id": "probe_dispute_001",  // Identification
        "connector_transaction_id": "probe_txn_001",
        "dispute_id": "probe_dispute_id_001"
    });

    return { status: disputeResponse.status };
}

disputeAccept("order_001").catch(console.error);
