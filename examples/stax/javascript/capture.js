// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py stax
//
// Flow: PaymentService.Capture

const { ConnectorClient } = require('connector-service-node-ffi');

const client = new ConnectorClient({
    connector: 'Stax',
    environment: 'sandbox',
    connector_auth_type: {
        header_key: { api_key: 'YOUR_API_KEY' },
    },
});

async function capture(merchantTransactionId) {
    // Step 1: Capture — settle the reserved funds
    const captureResponse = await client.capture({
        "merchant_capture_id": "probe_capture_001",  // Identification
        "connector_transaction_id": "probe_connector_txn_001",
        "amount_to_capture": {  // Capture Details
            "minor_amount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
            "currency": "USD"  // ISO 4217 currency code (e.g., "USD", "EUR")
        }
    });

    if (captureResponse.status === 'FAILED') {
        throw new Error(`Capture failed: ${captureResponse.error?.message}`);
    }

    return { status: captureResponse.status };
}

capture("order_001").catch(console.error);
