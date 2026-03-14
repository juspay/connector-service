// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py adyen
//
// Flow: RecurringPaymentService.Charge

const { ConnectorClient } = require('connector-service-node-ffi');

const client = new ConnectorClient({
    connector: 'Adyen',
    environment: 'sandbox',
    connector_auth_type: {
        header_key: { api_key: 'YOUR_API_KEY' },
    },
});

async function recurringCharge(merchantTransactionId) {
    // Step 1: Recurring Charge — charge against the stored mandate
    const recurringResponse = await client.recurringCharge({
        "connector_recurring_payment_id": {  // Reference to existing mandate
            "mandate_id_type": {
                "connector_mandate_id": "probe_mandate_123"
            }
        },
        "amount": {  // Amount Information
            "minor_amount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
            "currency": "USD"  // ISO 4217 currency code (e.g., "USD", "EUR")
        },
        "payment_method": {  // Optional payment Method Information (for network transaction flows)
            "token": {"token": {"value": "probe_pm_token"}}  // Payment tokens
        },
        "return_url": "https://example.com/recurring-return",
        "connector_customer_id": "probe_cust_connector_001",
        "payment_method_type": "PAY_PAL",
        "off_session": True  // Behavioral Flags and Preferences
    });

    if (recurringResponse.status === 'FAILED') {
        throw new Error(`Recurring_Charge failed: ${recurringResponse.error?.message}`);
    }

    return { status: recurringResponse.status };
}

recurringCharge("order_001").catch(console.error);
