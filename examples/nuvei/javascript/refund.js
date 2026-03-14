// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py nuvei
//
// Flow: PaymentService.Refund

const { ConnectorClient } = require('connector-service-node-ffi');

const client = new ConnectorClient({
    connector: 'Nuvei',
    environment: 'sandbox',
    connector_auth_type: {
        header_key: { api_key: 'YOUR_API_KEY' },
    },
});

async function refund(merchantTransactionId) {
    // Step 1: Refund — return funds to the customer
    const refundResponse = await client.refund({
        "merchant_refund_id": "probe_refund_001",  // Identification
        "connector_transaction_id": "probe_connector_txn_001",
        "payment_amount": 1000,  // Amount Information
        "refund_amount": {
            "minor_amount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
            "currency": "USD"  // ISO 4217 currency code (e.g., "USD", "EUR")
        },
        "reason": "customer_request"  // Reason for the refund
    });

    if (refundResponse.status === 'FAILED') {
        throw new Error(`Refund failed: ${refundResponse.error?.message}`);
    }

    return { status: refundResponse.status };
}

refund("order_001").catch(console.error);
