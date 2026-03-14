// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py cybersource
//
// Scenario: Recurring / Mandate Payments
// Store a payment mandate with SetupRecurring, then charge it repeatedly with RecurringPaymentService.Charge without requiring customer action.

const { ConnectorClient } = require('connector-service-node-ffi');

const client = new ConnectorClient({
    connector: 'Cybersource',
    environment: 'sandbox',
    connector_auth_type: {
        header_key: { api_key: 'YOUR_API_KEY' },
    },
});

async function processRecurring(merchantTransactionId) {
    // Recurring / Mandate Payments
    // Store a payment mandate with SetupRecurring, then charge it repeatedly with RecurringPaymentService.Charge without requiring customer action.

    // Step 1: Setup Recurring — store the payment mandate
    const setupResponse = await client.setupRecurring({
        "merchant_recurring_payment_id": "probe_mandate_001",  // Identification
        "amount": {  // Mandate Details
            "minor_amount": 0,  // Amount in minor units (e.g., 1000 = $10.00)
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
        "customer": {
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
        },
        "auth_type": "NO_THREE_DS",  // Type of authentication to be used
        "enrolled_for_3ds": False,  // Indicates if the customer is enrolled for 3D Secure
        "metadata": "{}",  // Additional metadata for the connector
        "return_url": "https://example.com/mandate-return",  // URL to redirect after setup
        "setup_future_usage": "OFF_SESSION",  // Indicates future usage intention
        "request_incremental_authorization": False,  // Indicates if incremental authorization is requested
        "customer_acceptance": {  // Details of customer acceptance
            "acceptance_type": "OFFLINE",  // Type of acceptance (e.g., online, offline).
            "accepted_at": 0  // Timestamp when the acceptance was made (Unix timestamp, seconds since epoch).
        },
        "browser_info": {  // Information about the customer's browser
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

    if (setupResponse.status === 'FAILED') {
        throw new Error(`Recurring setup failed: ${setupResponse.error?.message}`);
    }

    // Step 2: Recurring Charge — charge against the stored mandate
    const recurringResponse = await client.recurringCharge({
        "connector_recurring_payment_id": {"connector_mandate_id": {"connector_mandate_id": setup_response.connector_recurring_payment_id}},  // from authorize response
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

    return { status: recurringResponse.status, transactionId: recurringResponse.connector_transaction_id ?? '' };
}
