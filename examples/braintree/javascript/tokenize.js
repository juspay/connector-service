// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py braintree
//
// Scenario: Tokenize Payment Method
// Store card details in the connector's vault and receive a reusable payment token. Use the returned token for one-click payments and recurring billing without re-collecting card data.

const { ConnectorClient } = require('connector-service-node-ffi');

const client = new ConnectorClient({
    connector: 'Braintree',
    environment: 'sandbox',
    connector_auth_type: {
        header_key: { api_key: 'YOUR_API_KEY' },
    },
});

async function processTokenize(merchantTransactionId) {
    // Tokenize Payment Method
    // Store card details in the connector's vault and receive a reusable payment token. Use the returned token for one-click payments and recurring billing without re-collecting card data.

    // Step 1: Tokenize — store card details and return a reusable token
    const tokenizeResponse = await client.tokenize({
        "amount": {  // Payment Information
            "minor_amount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
            "currency": "USD"  // ISO 4217 currency code (e.g., "USD", "EUR")
        },
        "payment_method": {
            "card": {  // Generic card payment
                "card_number": {"value": "4111111111111111"},  // Card Identification
                "card_exp_month": {"value": "03"},
                "card_exp_year": {"value": "2030"},
                "card_cvc": {"value": "737"},
                "card_holder_name": {"value": "John Doe"}  // Cardholder Information
            }
        },
        "customer": {  // Customer Information
            "name": "John Doe",  // Customer's full name
            "email": {"value": "test@example.com"},  // Customer's email address
            "id": "cust_probe_123",  // Internal customer ID
            "phone_number": "4155552671",  // Customer's phone number
            "phone_country_code": "+1"  // Customer's phone country code
        },
        "address": {  // Address Information
            "billing_address": {
                "first_name": {"value": "John"},  // Personal Information
                "last_name": {"value": "Doe"},
                "line1": {"value": "123 Main St"},  // Address Details
                "city": {"value": "Seattle"},
                "state": {"value": "WA"},
                "zip_code": {"value": "98101"},
                "country_alpha2_code": "US",
                "email": {"value": "test@example.com"},  // Contact Information
                "phone_number": {"value": "4155552671"},
                "phone_country_code": "+1"
            }
        }
    });

    return { token: tokenizeResponse.payment_method_token };
}
