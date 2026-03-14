// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py adyen
//
// Flow: DisputeService.Defend

const { ConnectorClient } = require('connector-service-node-ffi');

const client = new ConnectorClient({
    connector: 'Adyen',
    environment: 'sandbox',
    connector_auth_type: {
        header_key: { api_key: 'YOUR_API_KEY' },
    },
});

async function disputeDefend(merchantTransactionId) {
    // Step 1: dispute_defend
    const disputeResponse = await client.disputeDefend({
        "merchant_dispute_id": "probe_dispute_001",  // Identification
        "connector_transaction_id": "probe_txn_001",
        "dispute_id": "probe_dispute_id_001",
        "reason_code": "probe_reason"  // Defend Details
    });

    return { status: disputeResponse.status };
}

disputeDefend("order_001").catch(console.error);
