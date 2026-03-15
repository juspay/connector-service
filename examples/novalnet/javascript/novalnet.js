// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py novalnet
//
// Novalnet — all integration scenarios and flows in one file.
// Run a scenario:  node novalnet.js checkout_card
'use strict';

const { PaymentClient } = require('hs-playlib');
const { ConnectorConfig, Environment, Connector } = require('hs-playlib').types;

const _defaultConfig = ConnectorConfig.create({
    connector: Connector.NOVALNET,
    environment: Environment.SANDBOX,
});
// Standalone credentials (field names depend on connector auth type):
// _defaultConfig.auth = { novalnet: { apiKey: { value: 'YOUR_API_KEY' } } };


// Card Payment (Authorize + Capture)
// Reserve funds with Authorize, then settle with a separate Capture call. Use for physical goods or delayed fulfillment where capture happens later.
async function processCheckoutCard(merchantTransactionId, config = _defaultConfig) {
    const paymentClient = new PaymentClient(config);

    // Step 1: Authorize — reserve funds on the payment method
    const authorizeResponse = await paymentClient.authorize({
        "merchantTransactionId": "probe_txn_001",  // Identification
        "amount": {  // The amount for the payment
            "minorAmount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
            "currency": "USD"  // ISO 4217 currency code (e.g., "USD", "EUR")
        },
        "paymentMethod": {  // Payment method to be used
            "card": {  // Generic card payment
                "cardNumber": {"value": "4111111111111111"},  // Card Identification
                "cardExpMonth": {"value": "03"},
                "cardExpYear": {"value": "2030"},
                "cardCvc": {"value": "737"},
                "cardHolderName": {"value": "John Doe"}  // Cardholder Information
            }
        },
        "captureMethod": "MANUAL",  // Method for capturing the payment
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

    // Step 2: Capture — settle the reserved funds
    const captureResponse = await paymentClient.capture({
        "merchantCaptureId": "probe_capture_001",  // Identification
        "connectorTransactionId": authorizeResponse.connectorTransactionId,  // from authorize response
        "amountToCapture": {  // Capture Details
            "minorAmount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
            "currency": "USD"  // ISO 4217 currency code (e.g., "USD", "EUR")
        }
    });

    if (captureResponse.status === 'FAILED') {
        throw new Error(`Capture failed: ${captureResponse.error?.message}`);
    }

    return { status: captureResponse.status, transactionId: authorizeResponse.connectorTransactionId };
}

// Card Payment (Automatic Capture)
// Authorize and capture in one call using `capture_method=AUTOMATIC`. Use for digital goods or immediate fulfillment.
async function processCheckoutAutocapture(merchantTransactionId, config = _defaultConfig) {
    const paymentClient = new PaymentClient(config);

    // Step 1: Authorize — reserve funds on the payment method
    const authorizeResponse = await paymentClient.authorize({
        "merchantTransactionId": "probe_txn_001",  // Identification
        "amount": {  // The amount for the payment
            "minorAmount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
            "currency": "USD"  // ISO 4217 currency code (e.g., "USD", "EUR")
        },
        "paymentMethod": {  // Payment method to be used
            "card": {  // Generic card payment
                "cardNumber": {"value": "4111111111111111"},  // Card Identification
                "cardExpMonth": {"value": "03"},
                "cardExpYear": {"value": "2030"},
                "cardCvc": {"value": "737"},
                "cardHolderName": {"value": "John Doe"}  // Cardholder Information
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

    return { status: authorizeResponse.status, transactionId: authorizeResponse.connectorTransactionId };
}

// Wallet Payment (Google Pay / Apple Pay)
// Wallet payments pass an encrypted token from the browser/device SDK. Pass the token blob directly — do not decrypt client-side.
async function processCheckoutWallet(merchantTransactionId, config = _defaultConfig) {
    const paymentClient = new PaymentClient(config);

    // Step 1: Authorize — reserve funds on the payment method
    const authorizeResponse = await paymentClient.authorize({
        "merchantTransactionId": "probe_txn_001",  // Identification
        "amount": {  // The amount for the payment
            "minorAmount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
            "currency": "USD"  // ISO 4217 currency code (e.g., "USD", "EUR")
        },
        "paymentMethod": {  // Payment method to be used
            "googlePay": {  // Google Pay
                "type": "CARD",  // Type of payment method
                "description": "Visa 1111",  // User-facing description of the payment method
                "info": {
                    "cardNetwork": "VISA",  // Card network name
                    "cardDetails": "1111"  // Card details (usually last 4 digits)
                },
                "tokenizationData": {
                    "encryptedData": {  // Encrypted Google Pay payment data
                        "token": "{\"version\":\"ECv2\",\"signature\":\"<sig>\",\"intermediateSigningKey\":{\"signedKey\":\"<signed_key>\",\"signatures\":[\"<sig>\"]},\"signedMessage\":\"<signed_message>\"}",  // Token generated for the wallet
                        "tokenType": "PAYMENT_GATEWAY"  // The type of the token
                    }
                }
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

    return { status: authorizeResponse.status, transactionId: authorizeResponse.connectorTransactionId };
}

// Bank Transfer (SEPA / ACH / BACS)
// Direct bank debit (Sepa). Bank transfers typically use `capture_method=AUTOMATIC`.
async function processCheckoutBank(merchantTransactionId, config = _defaultConfig) {
    const paymentClient = new PaymentClient(config);

    // Step 1: Authorize — reserve funds on the payment method
    const authorizeResponse = await paymentClient.authorize({
        "merchantTransactionId": "probe_txn_001",  // Identification
        "amount": {  // The amount for the payment
            "minorAmount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
            "currency": "EUR"  // ISO 4217 currency code (e.g., "USD", "EUR")
        },
        "paymentMethod": {  // Payment method to be used
            "sepa": {  // Sepa - Single Euro Payments Area direct debit
                "iban": {"value": "DE89370400440532013000"},  // International bank account number (iban) for SEPA
                "bankAccountHolderName": {"value": "John Doe"}  // Owner name for bank debit
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

    return { status: authorizeResponse.status, transactionId: authorizeResponse.connectorTransactionId };
}

// Refund a Payment
// Authorize with automatic capture, then refund the captured amount. `connector_transaction_id` from the Authorize response is reused for the Refund call.
async function processRefund(merchantTransactionId, config = _defaultConfig) {
    const paymentClient = new PaymentClient(config);

    // Step 1: Authorize — reserve funds on the payment method
    const authorizeResponse = await paymentClient.authorize({
        "merchantTransactionId": "probe_txn_001",  // Identification
        "amount": {  // The amount for the payment
            "minorAmount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
            "currency": "USD"  // ISO 4217 currency code (e.g., "USD", "EUR")
        },
        "paymentMethod": {  // Payment method to be used
            "card": {  // Generic card payment
                "cardNumber": {"value": "4111111111111111"},  // Card Identification
                "cardExpMonth": {"value": "03"},
                "cardExpYear": {"value": "2030"},
                "cardCvc": {"value": "737"},
                "cardHolderName": {"value": "John Doe"}  // Cardholder Information
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

    // Step 2: Refund — return funds to the customer
    const refundResponse = await paymentClient.refund({
        "merchantRefundId": "probe_refund_001",  // Identification
        "connectorTransactionId": authorizeResponse.connectorTransactionId,  // from authorize response
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

// Void a Payment
// Authorize funds with a manual capture flag, then cancel the authorization with Void before any capture occurs. Releases the hold on the customer's funds.
async function processVoidPayment(merchantTransactionId, config = _defaultConfig) {
    const paymentClient = new PaymentClient(config);

    // Step 1: Authorize — reserve funds on the payment method
    const authorizeResponse = await paymentClient.authorize({
        "merchantTransactionId": "probe_txn_001",  // Identification
        "amount": {  // The amount for the payment
            "minorAmount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
            "currency": "USD"  // ISO 4217 currency code (e.g., "USD", "EUR")
        },
        "paymentMethod": {  // Payment method to be used
            "card": {  // Generic card payment
                "cardNumber": {"value": "4111111111111111"},  // Card Identification
                "cardExpMonth": {"value": "03"},
                "cardExpYear": {"value": "2030"},
                "cardCvc": {"value": "737"},
                "cardHolderName": {"value": "John Doe"}  // Cardholder Information
            }
        },
        "captureMethod": "MANUAL",  // Method for capturing the payment
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

    // Step 2: Void — release reserved funds (cancel authorization)
    const voidResponse = await paymentClient.void({
        "merchantVoidId": "probe_void_001",  // Identification
        "connectorTransactionId": authorizeResponse.connectorTransactionId,  // from authorize response
    });

    return { status: voidResponse.status, transactionId: authorizeResponse.connectorTransactionId };
}

// Get Payment Status
// Authorize a payment, then poll the connector for its current status using Get. Use this to sync payment state when webhooks are unavailable or delayed.
async function processGetPayment(merchantTransactionId, config = _defaultConfig) {
    const paymentClient = new PaymentClient(config);

    // Step 1: Authorize — reserve funds on the payment method
    const authorizeResponse = await paymentClient.authorize({
        "merchantTransactionId": "probe_txn_001",  // Identification
        "amount": {  // The amount for the payment
            "minorAmount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
            "currency": "USD"  // ISO 4217 currency code (e.g., "USD", "EUR")
        },
        "paymentMethod": {  // Payment method to be used
            "card": {  // Generic card payment
                "cardNumber": {"value": "4111111111111111"},  // Card Identification
                "cardExpMonth": {"value": "03"},
                "cardExpYear": {"value": "2030"},
                "cardCvc": {"value": "737"},
                "cardHolderName": {"value": "John Doe"}  // Cardholder Information
            }
        },
        "captureMethod": "MANUAL",  // Method for capturing the payment
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

    // Step 2: Get — retrieve current payment status from the connector
    const getResponse = await paymentClient.get({
        "connectorTransactionId": authorizeResponse.connectorTransactionId,  // from authorize response
        "amount": {  // Amount Information
            "minorAmount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
            "currency": "USD"  // ISO 4217 currency code (e.g., "USD", "EUR")
        }
    });

    return { status: getResponse.status, transactionId: getResponse.connectorTransactionId };
}

// Flow: PaymentService.Authorize (Card)
async function authorize(merchantTransactionId, config = _defaultConfig) {
    // Step 1: Authorize — reserve funds on the payment method
    const authorizeResponse = await paymentClient.authorize({
        "merchantTransactionId": "probe_txn_001",  // Identification
        "amount": {  // The amount for the payment
            "minorAmount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
            "currency": "USD"  // ISO 4217 currency code (e.g., "USD", "EUR")
        },
        "paymentMethod": {  // Payment method to be used
            "card": {  // Generic card payment
                "cardNumber": {"value": "4111111111111111"},  // Card Identification
                "cardExpMonth": {"value": "03"},
                "cardExpYear": {"value": "2030"},
                "cardCvc": {"value": "737"},
                "cardHolderName": {"value": "John Doe"}  // Cardholder Information
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

    return { status: authorizeResponse.status, transactionId: authorizeResponse.connectorTransactionId };
}

// Flow: PaymentService.Capture
async function capture(merchantTransactionId, config = _defaultConfig) {
    // Step 1: Capture — settle the reserved funds
    const captureResponse = await paymentClient.capture({
        "merchantCaptureId": "probe_capture_001",  // Identification
        "connectorTransactionId": "probe_connector_txn_001",
        "amountToCapture": {  // Capture Details
            "minorAmount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
            "currency": "USD"  // ISO 4217 currency code (e.g., "USD", "EUR")
        }
    });

    if (captureResponse.status === 'FAILED') {
        throw new Error(`Capture failed: ${captureResponse.error?.message}`);
    }

    return { status: captureResponse.status };
}

// Flow: PaymentService.Get
async function get(merchantTransactionId, config = _defaultConfig) {
    // Step 1: Get — retrieve current payment status from the connector
    const getResponse = await paymentClient.get({
        "connectorTransactionId": "probe_connector_txn_001",
        "amount": {  // Amount Information
            "minorAmount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
            "currency": "USD"  // ISO 4217 currency code (e.g., "USD", "EUR")
        }
    });

    return { status: getResponse.status };
}

// Flow: PaymentService.Void
async function voidPayment(merchantTransactionId, config = _defaultConfig) {
    // Step 1: Void — release reserved funds (cancel authorization)
    const voidResponse = await paymentClient.void({
        "merchantVoidId": "probe_void_001",  // Identification
        "connectorTransactionId": "probe_connector_txn_001"
    });

    return { status: voidResponse.status };
}


module.exports = { processCheckoutCard, processCheckoutAutocapture, processCheckoutWallet, processCheckoutBank, processRefund, processVoidPayment, processGetPayment, authorize, capture, get, voidPayment };

if (require.main === module) {
    const scenario = process.argv[2] || 'checkout_card';
    const key = 'process' + scenario.replace(/_([a-z])/g, (_, l) => l.toUpperCase()).replace(/^(.)/, c => c.toUpperCase());
    const fn = module.exports[key];
    if (!fn) {
        const available = Object.keys(module.exports).map(k =>
            k.replace(/^process/, '').replace(/([A-Z])/g, '_$1').toLowerCase().replace(/^_/, '')
        );
        console.error(`Unknown scenario: ${scenario}. Available: ${available.join(', ')}`);
        process.exit(1);
    }
    fn('order_001').catch(console.error);
}
