// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py payme
//
// Flow: PaymentService.Refund

const { ConnectorClient } = require('connector-service-node-ffi');

const client = new ConnectorClient({
    connector: 'Payme',
    environment: 'sandbox',
    connector_auth_type: {
        header_key: { api_key: 'YOUR_API_KEY' },
    },
});

async function refund(merchantTransactionId) {
    // Step 1: Refund — return funds to the customer
    const refundResponse = await client.refund({
        "merchantRefundId": "probe_refund_001",  // Identification
        "connectorTransactionId": "probe_connector_txn_001",
        "paymentAmount": 1000,  // Amount Information
        "refundAmount": {
            "minorAmount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
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
