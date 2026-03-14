// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py adyen
//
// Flow: DisputeService.SubmitEvidence

const { ConnectorClient } = require('connector-service-node-ffi');

const client = new ConnectorClient({
    connector: 'Adyen',
    environment: 'sandbox',
    connector_auth_type: {
        header_key: { api_key: 'YOUR_API_KEY' },
    },
});

async function disputeSubmitEvidence(merchantTransactionId) {
    // Step 1: dispute_submit_evidence
    const disputeResponse = await client.disputeSubmitEvidence({
        "merchant_dispute_id": "probe_dispute_001",  // Identification
        "connector_transaction_id": "probe_txn_001",
        "dispute_id": "probe_dispute_id_001",
        "evidence_documents": [{"evidence_type": "SERVICE_DOCUMENTATION", "file_content": [112, 114, 111, 98, 101, 32, 101, 118, 105, 100, 101, 110, 99, 101, 32, 99, 111, 110, 116, 101, 110, 116], "file_mime_type": "application/pdf"}]  // Collection of evidence documents
    });

    return { status: disputeResponse.status };
}

disputeSubmitEvidence("order_001").catch(console.error);
