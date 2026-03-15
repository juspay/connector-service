// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py payu
//
// Flow: PaymentService.Authorize (UpiCollect)

const { ConnectorClient } = require('connector-service-node-ffi');

const client = new ConnectorClient({
    connector: 'Payu',
    environment: 'sandbox',
    connector_auth_type: {
        header_key: { api_key: 'YOUR_API_KEY' },
    },
});

async function authorize(merchantTransactionId) {
    // Step 1: Authorize — reserve funds on the payment method
    const authorizeResponse = await client.authorize({
        "merchantTransactionId": "probe_txn_001",  // Identification
        "amount": {  // The amount for the payment
            "minorAmount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
            "currency": "USD"  // ISO 4217 currency code (e.g., "USD", "EUR")
        },
        "paymentMethod": {  // Payment method to be used
            "upiCollect": {  // UPI Collect
                "vpaId": {"value": "test@upi"}  // Virtual Payment Address
            }
        },
        "captureMethod": "AUTOMATIC",  // Method for capturing the payment
        "customer": {  // Customer Information
            "name": "John Doe",  // Customer's full name
            "email": {"value": "test@example.com"},  // Customer's email address
            "id": "cust_probe_123",  // Internal customer ID
            "phoneNumber": "4155552671",  // Customer's phone number
            "phoneCountryCode": "+1"  // Customer's phone country code
        },
        "address": {  // Address Information
            "shippingAddress": {
                "firstName": {"value": "John"},  // Personal Information
                "lastName": {"value": "Doe"},
                "line1": {"value": "123 Main St"},  // Address Details
                "city": {"value": "Seattle"},
                "state": {"value": "WA"},
                "zipCode": {"value": "98101"},
                "countryAlpha2Code": "US",
                "email": {"value": "test@example.com"},  // Contact Information
                "phoneNumber": {"value": "4155552671"},
                "phoneCountryCode": "+1"
            },
            "billingAddress": {
                "firstName": {"value": "John"},  // Personal Information
                "lastName": {"value": "Doe"},
                "line1": {"value": "123 Main St"},  // Address Details
                "city": {"value": "Seattle"},
                "state": {"value": "WA"},
                "zipCode": {"value": "98101"},
                "countryAlpha2Code": "US",
                "email": {"value": "test@example.com"},  // Contact Information
                "phoneNumber": {"value": "4155552671"},
                "phoneCountryCode": "+1"
            }
        },
        "authType": "NO_THREE_DS",  // Authentication Details
        "returnUrl": "https://example.com/return",  // URLs for Redirection and Webhooks
        "webhookUrl": "https://example.com/webhook",
        "completeAuthorizeUrl": "https://example.com/complete",
        "browserInfo": {
            "colorDepth": 24,  // Display Information
            "screenHeight": 900,
            "screenWidth": 1440,
            "javaEnabled": false,  // Browser Settings
            "javaScriptEnabled": true,
            "language": "en-US",
            "timeZoneOffsetMinutes": -480,
            "acceptHeader": "application/json",  // Browser Headers
            "userAgent": "Mozilla/5.0 (probe-bot)",
            "acceptLanguage": "en-US,en;q=0.9",
            "ipAddress": "1.2.3.4"  // Device Information
        }
    });

    if (authorizeResponse.status === 'FAILED') {
        throw new Error(`Payment failed: ${authorizeResponse.error?.message}`);
    }
    if (authorizeResponse.status === 'PENDING') {
        // Awaiting async confirmation — handle via webhook
        return { status: 'pending', transactionId: authorizeResponse.connectorTransactionId };
    }

    return { status: authorizeResponse.status, transactionId: authorizeResponse.connector_transaction_id };
}

authorize("order_001").catch(console.error);
