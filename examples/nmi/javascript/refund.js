// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py nmi
//
// Scenario: Refund a Payment
// Authorize with automatic capture, then refund the captured amount. `connector_transaction_id` from the Authorize response is reused for the Refund call.

const { ConnectorClient } = require('connector-service-node-ffi');

const client = new ConnectorClient({
    connector: 'Nmi',
    environment: 'sandbox',
    connector_auth_type: {
        header_key: { api_key: 'YOUR_API_KEY' },
    },
});

async function processRefund(merchantTransactionId) {
    // Refund a Payment
    // Authorize with automatic capture, then refund the captured amount. `connector_transaction_id` from the Authorize response is reused for the Refund call.

    // Step 1: Authorize — reserve funds on the payment method
    const authorizeResponse = await client.authorize({
        "merchant_transaction_id": "probe_txn_001",  // Identification
        "amount": {  // The amount for the payment
            "minor_amount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
            "currency": "USD"  // ISO 4217 currency code (e.g., "USD", "EUR")
        },
        "payment_method": {  // Payment method to be used
            "card": {  // Generic card payment
                "card_number": {"value": "4111111111111111"},  // Card Identification
                "card_exp_month": {"value": "03"},
                "card_exp_year": {"value": "2030"},
                "card_cvc": {"value": "737"},
                "card_holder_name": {"value": "John Doe"}  // Cardholder Information
            }
        },
        "capture_method": "AUTOMATIC",  // Method for capturing the payment
        "customer": {  // Customer Information
            "name": "John Doe",  // Customer's full name
            "email": {"value": "test@example.com"},  // Customer's email address
            "id": "cust_probe_123",  // Internal customer ID
            "phone_number": "4155552671",  // Customer's phone number
            "phone_country_code": "+1"  // Customer's phone country code
        },
        "address": {  // Address Information
            "shipping_address": {
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
            },
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
        },
        "auth_type": "NO_THREE_DS",  // Authentication Details
        "return_url": "https://example.com/return",  // URLs for Redirection and Webhooks
        "webhook_url": "https://example.com/webhook",
        "complete_authorize_url": "https://example.com/complete",
        "browser_info": {
            "color_depth": 24,  // Display Information
            "screen_height": 900,
            "screen_width": 1440,
            "java_enabled": False,  // Browser Settings
            "java_script_enabled": True,
            "language": "en-US",
            "time_zone_offset_minutes": -480,
            "accept_header": "application/json",  // Browser Headers
            "user_agent": "Mozilla/5.0 (probe-bot)",
            "accept_language": "en-US,en;q=0.9",
            "ip_address": "1.2.3.4"  // Device Information
        }
    });

    if (authorizeResponse.status === 'FAILED') {
        throw new Error(`Payment failed: ${authorizeResponse.error?.message}`);
    }
    if (authorizeResponse.status === 'PENDING') {
        // Awaiting async confirmation — handle via webhook
        return { status: 'pending', transactionId: authorizeResponse.connector_transaction_id };
    }

    // Step 2: Refund — return funds to the customer
    const refundResponse = await client.refund({
        "merchant_refund_id": "probe_refund_001",  // Identification
        "connector_transaction_id": authorize_response.connector_transaction_id,  // from authorize response
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
