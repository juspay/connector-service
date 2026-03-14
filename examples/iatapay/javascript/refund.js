// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py iatapay
//
// Flow: PaymentService.Refund

const { ConnectorClient } = require('connector-service-node-ffi');

const client = new ConnectorClient({
    connector: 'Iatapay',
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
        "reason": "customer_request",  // Reason for the refund
        "webhook_url": "https://example.com/webhook",  // URL for webhook notifications
        "state": {  // State data for access token storage and other connector-specific state
            "access_token": {  // Access token obtained from connector
                "token": {"value": "probe_access_token"},  // The token string.
                "expires_in_seconds": 3600,  // Expiration timestamp (seconds since epoch)
                "token_type": "Bearer"  // Token type (e.g., "Bearer", "Basic").
            }
        }
    });

    if (refundResponse.status === 'FAILED') {
        throw new Error(`Refund failed: ${refundResponse.error?.message}`);
    }

    return { status: refundResponse.status };
}

refund("order_001").catch(console.error);
