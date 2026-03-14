// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py finix
//
// Scenario: Create Customer
// Register a customer record in the connector system. Returns a connector_customer_id that can be reused for recurring payments and tokenized card storage.

const { ConnectorClient } = require('connector-service-node-ffi');

const client = new ConnectorClient({
    connector: 'Finix',
    environment: 'sandbox',
    connector_auth_type: {
        header_key: { api_key: 'YOUR_API_KEY' },
    },
});

async function processCreateCustomer(merchantTransactionId) {
    // Create Customer
    // Register a customer record in the connector system. Returns a connector_customer_id that can be reused for recurring payments and tokenized card storage.

    // Step 1: Create Customer — register customer record in the connector
    const createResponse = await client.createCustomer({
        "customer_name": "John Doe",  // Name of the customer
        "email": "test@example.com",  // Email address of the customer
        "phone_number": "4155552671",  // Phone number of the customer
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

    return { customerId: createResponse.connector_customer_id };
}
