// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py paypal
//
// Flow: RecurringPaymentService.Charge

const { ConnectorClient } = require('connector-service-node-ffi');

const client = new ConnectorClient({
    connector: 'Paypal',
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
        "off_session": True,  // Behavioral Flags and Preferences
        "state": {  // State Information
            "access_token": {  // Access token obtained from connector
                "token": {"value": "probe_access_token"},  // The token string.
                "expires_in_seconds": 3600,  // Expiration timestamp (seconds since epoch)
                "token_type": "Bearer"  // Token type (e.g., "Bearer", "Basic").
            }
        }
    });

    if (recurringResponse.status === 'FAILED') {
        throw new Error(`Recurring_Charge failed: ${recurringResponse.error?.message}`);
    }

    return { status: recurringResponse.status };
}

recurringCharge("order_001").catch(console.error);
