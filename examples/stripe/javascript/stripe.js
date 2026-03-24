// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py stripe
//
// Stripe — all integration scenarios and flows in one file.
// Run a scenario:  node stripe.js checkout_card
'use strict';

const { PaymentClient, RecurringPaymentClient, CustomerClient, PaymentMethodClient, TokenizedPaymentClient, ProxyPaymentClient } = require('hs-playlib');
const { ConnectorConfig, ConnectorSpecificConfig, SdkOptions, Environment } = require('hs-playlib').types;

const _defaultConfig = ConnectorConfig.create({
    options: SdkOptions.create({ environment: Environment.SANDBOX }),
});
// Standalone credentials (field names depend on connector auth type):
// _defaultConfig.connectorConfig = ConnectorSpecificConfig.create({
//     stripe: { apiKey: { value: 'YOUR_API_KEY' } }
// });


function _buildAuthorizeRequest(captureMethod) {
    return {
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
        "captureMethod": captureMethod,  // Method for capturing the payment
        "address": {  // Address Information
            "billingAddress": {
            }
        },
        "authType": "NO_THREE_DS",  // Authentication Details
        "returnUrl": "https://example.com/return"  // URLs for Redirection and Webhooks
    };
}

function _buildCaptureRequest(connectorTransactionId) {
    return {
        "merchantCaptureId": "probe_capture_001",  // Identification
        "connectorTransactionId": connectorTransactionId,
        "amountToCapture": {  // Capture Details
            "minorAmount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
            "currency": "USD"  // ISO 4217 currency code (e.g., "USD", "EUR")
        }
    };
}

function _buildCreateCustomerRequest() {
    return {
        "merchantCustomerId": "cust_probe_123",  // Identification
        "customerName": "John Doe",  // Name of the customer
        "email": {"value": "test@example.com"},  // Email address of the customer
        "phoneNumber": "4155552671"  // Phone number of the customer
    };
}

function _buildGetRequest(connectorTransactionId) {
    return {
        "merchantTransactionId": "probe_merchant_txn_001",  // Identification
        "connectorTransactionId": connectorTransactionId,
        "amount": {  // Amount Information
            "minorAmount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
            "currency": "USD"  // ISO 4217 currency code (e.g., "USD", "EUR")
        }
    };
}

function _buildRecurringChargeRequest() {
    return {
        "connectorRecurringPaymentId": {  // Reference to existing mandate
            "mandateIdType": {
                "connectorMandateId": "probe-mandate-123"
            }
        },
        "amount": {  // Amount Information
            "minorAmount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
            "currency": "USD"  // ISO 4217 currency code (e.g., "USD", "EUR")
        },
        "paymentMethod": {  // Optional payment Method Information (for network transaction flows)
            "token": {"token": {"value": "probe_pm_token"}}  // Payment tokens
        },
        "returnUrl": "https://example.com/recurring-return",
        "connectorCustomerId": "cust_probe_123",
        "paymentMethodType": "PAY_PAL",
        "offSession": true  // Behavioral Flags and Preferences
    };
}

function _buildRefundRequest(connectorTransactionId) {
    return {
        "merchantRefundId": "probe_refund_001",  // Identification
        "connectorTransactionId": connectorTransactionId,
        "paymentAmount": 1000,  // Amount Information
        "refundAmount": {
            "minorAmount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
            "currency": "USD"  // ISO 4217 currency code (e.g., "USD", "EUR")
        },
        "reason": "customer_request"  // Reason for the refund
    };
}

function _buildSetupRecurringRequest() {
    return {
        "merchantRecurringPaymentId": "probe_mandate_001",  // Identification
        "amount": {  // Mandate Details
            "minorAmount": 0,  // Amount in minor units (e.g., 1000 = $10.00)
            "currency": "USD"  // ISO 4217 currency code (e.g., "USD", "EUR")
        },
        "paymentMethod": {
            "card": {  // Generic card payment
                "cardNumber": {"value": "4111111111111111"},  // Card Identification
                "cardExpMonth": {"value": "03"},
                "cardExpYear": {"value": "2030"},
                "cardCvc": {"value": "737"},
                "cardHolderName": {"value": "John Doe"}  // Cardholder Information
            }
        },
        "address": {  // Address Information
            "billingAddress": {
            }
        },
        "authType": "NO_THREE_DS",  // Type of authentication to be used
        "enrolledFor3Ds": false,  // Indicates if the customer is enrolled for 3D Secure
        "returnUrl": "https://example.com/mandate-return",  // URL to redirect after setup
        "setupFutureUsage": "OFF_SESSION",  // Indicates future usage intention
        "requestIncrementalAuthorization": false,  // Indicates if incremental authorization is requested
        "customerAcceptance": {  // Details of customer acceptance
            "acceptanceType": "OFFLINE",  // Type of acceptance (e.g., online, offline).
            "acceptedAt": 0  // Timestamp when the acceptance was made (Unix timestamp, seconds since epoch).
        }
    };
}

function _buildTokenizeRequest() {
    return {
        "amount": {  // Payment Information
            "minorAmount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
            "currency": "USD"  // ISO 4217 currency code (e.g., "USD", "EUR")
        },
        "paymentMethod": {
            "card": {  // Generic card payment
                "cardNumber": {"value": "4111111111111111"},  // Card Identification
                "cardExpMonth": {"value": "03"},
                "cardExpYear": {"value": "2030"},
                "cardCvc": {"value": "737"},
                "cardHolderName": {"value": "John Doe"}  // Cardholder Information
            }
        },
        "address": {  // Address Information
            "billingAddress": {
            }
        }
    };
}

function _buildVoidRequest(connectorTransactionId) {
    return {
        "merchantVoidId": "probe_void_001",  // Identification
        "connectorTransactionId": connectorTransactionId
    };
}

function _buildTokenizedAuthorizeRequest() {
    return {
        "merchantTransactionId": "probe_tokenized_txn_001",
        "amount": {
            "minorAmount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
            "currency": "USD"  // ISO 4217 currency code (e.g., "USD", "EUR")
        },
        "connectorToken": {
            "value": "pm_1AbcXyzStripeTestToken"
        },
        "captureMethod": "AUTOMATIC",
        "address": {
            "billingAddress": {
            }
        },
        "returnUrl": "https://example.com/return"
    };
}

function _buildTokenizedSetupRecurringRequest() {
    return {
        "merchantRecurringPaymentId": "probe_tokenized_mandate_001",
        "amount": {
            "minorAmount": 0,  // Amount in minor units (e.g., 1000 = $10.00)
            "currency": "USD"  // ISO 4217 currency code (e.g., "USD", "EUR")
        },
        "connectorToken": {
            "value": "pm_1AbcXyzStripeTestToken"
        },
        "address": {
            "billingAddress": {
            }
        },
        "customerAcceptance": {
            "acceptanceType": "ONLINE",  // Type of acceptance (e.g., online, offline).
            "online": {
                "ipAddress": "127.0.0.1",
                "userAgent": "Mozilla/5.0"
            }
        }
    };
}

function _buildProxyAuthorizeRequest() {
    return {
        "merchantTransactionId": "probe_proxy_txn_001",
        "amount": {
            "minorAmount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
            "currency": "USD"  // ISO 4217 currency code (e.g., "USD", "EUR")
        },
        "vaultCard": {
            "cardNumberAlias": {
                "value": "tok_sandbox_abc123"
            },
            "expMonth": "03",
            "expYear": "2030",
            "cvcAlias": {
                "value": "tok_sandbox_cvc456"
            },
            "cardHolderName": "John Doe"
        },
        "captureMethod": "AUTOMATIC",
        "authType": "NO_THREE_DS",
        "address": {
            "billingAddress": {
            }
        },
        "returnUrl": "https://example.com/return"
    };
}

function _buildProxySetupRecurringRequest() {
    return {
        "merchantRecurringPaymentId": "probe_proxy_mandate_001",
        "amount": {
            "minorAmount": 0,  // Amount in minor units (e.g., 1000 = $10.00)
            "currency": "USD"  // ISO 4217 currency code (e.g., "USD", "EUR")
        },
        "vaultCard": {
            "cardNumberAlias": {
                "value": "tok_sandbox_abc123"
            },
            "expMonth": "03",
            "expYear": "2030",
            "cvcAlias": {
                "value": "tok_sandbox_cvc456"
            },
            "cardHolderName": "John Doe"
        },
        "authType": "NO_THREE_DS",
        "address": {
            "billingAddress": {
            }
        }
    };
}

function _buildProxyPreAuthenticateRequest() {
    return {
        "merchantOrderId": "probe_proxy_order_001",
        "amount": {
            "minorAmount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
            "currency": "USD"  // ISO 4217 currency code (e.g., "USD", "EUR")
        },
        "vaultCard": {
            "cardNumberAlias": {
                "value": "tok_sandbox_abc123"
            },
            "expMonth": "03",
            "expYear": "2030",
            "cardHolderName": "John Doe"
        },
        "browserInfo": {
            "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
            "acceptHeader": "application/json",  // Browser Headers
            "language": "en-US",
            "colorDepth": 24,  // Display Information
            "screenHeight": 1080,
            "screenWidth": 1920,
            "timeZoneOffset": -330,
            "javaEnabled": false,  // Browser Settings
            "javaScriptEnabled": true
        },
        "returnUrl": "https://example.com/3ds-return"
    };
}

function _buildProxyAuthenticateRequest() {
    return {
        "merchantOrderId": "probe_proxy_order_001",
        "amount": {
            "minorAmount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
            "currency": "USD"  // ISO 4217 currency code (e.g., "USD", "EUR")
        },
        "vaultCard": {
            "cardNumberAlias": {
                "value": "tok_sandbox_abc123"
            },
            "expMonth": "03",
            "expYear": "2030",
            "cardHolderName": "John Doe"
        },
        "returnUrl": "https://example.com/3ds-return"
    };
}

function _buildProxyPostAuthenticateRequest() {
    return {
        "merchantOrderId": "probe_proxy_order_001",
        "vaultCard": {
            "cardNumberAlias": {
                "value": "tok_sandbox_abc123"
            },
            "expMonth": "03",
            "expYear": "2030",
            "cardHolderName": "John Doe"
        }
    };
}


// ANCHOR: scenario_functions
// Card Payment (Authorize + Capture)
// Reserve funds with Authorize, then settle with a separate Capture call. Use for physical goods or delayed fulfillment where capture happens later.
async function processCheckoutCard(merchantTransactionId, config = _defaultConfig) {
    const paymentClient = new PaymentClient(config);

    // Step 1: Authorize — reserve funds on the payment method
    const authorizeResponse = await paymentClient.authorize(_buildAuthorizeRequest('MANUAL'));

    if (authorizeResponse.status === 'FAILED') {
        throw new Error(`Payment failed: ${authorizeResponse.error?.message}`);
    }
    if (authorizeResponse.status === 'PENDING') {
        // Awaiting async confirmation — handle via webhook
        return { status: 'pending', transactionId: authorizeResponse.connectorTransactionId };
    }

    // Step 2: Capture — settle the reserved funds
    const captureResponse = await paymentClient.capture(_buildCaptureRequest(authorizeResponse.connectorTransactionId));

    if (captureResponse.status === 'FAILED') {
        throw new Error(`Capture failed: ${captureResponse.error?.message}`);
    }

    return { status: captureResponse.status, transactionId: authorizeResponse.connectorTransactionId, error: authorizeResponse.error };
}

// Card Payment (Automatic Capture)
// Authorize and capture in one call using `capture_method=AUTOMATIC`. Use for digital goods or immediate fulfillment.
async function processCheckoutAutocapture(merchantTransactionId, config = _defaultConfig) {
    const paymentClient = new PaymentClient(config);

    // Step 1: Authorize — reserve funds on the payment method
    const authorizeResponse = await paymentClient.authorize(_buildAuthorizeRequest('AUTOMATIC'));

    if (authorizeResponse.status === 'FAILED') {
        throw new Error(`Payment failed: ${authorizeResponse.error?.message}`);
    }
    if (authorizeResponse.status === 'PENDING') {
        // Awaiting async confirmation — handle via webhook
        return { status: 'pending', transactionId: authorizeResponse.connectorTransactionId };
    }

    return { status: authorizeResponse.status, transactionId: authorizeResponse.connectorTransactionId, error: authorizeResponse.error };
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
                        "tokenType": "PAYMENT_GATEWAY",  // The type of the token
                        "token": "{\"id\":\"tok_probe_gpay\",\"object\":\"token\",\"type\":\"card\"}"  // Token generated for the wallet
                    }
                }
            }
        },
        "captureMethod": "AUTOMATIC",  // Method for capturing the payment
        "address": {  // Address Information
            "billingAddress": {
            }
        },
        "authType": "NO_THREE_DS",  // Authentication Details
        "returnUrl": "https://example.com/return"  // URLs for Redirection and Webhooks
    });

    if (authorizeResponse.status === 'FAILED') {
        throw new Error(`Payment failed: ${authorizeResponse.error?.message}`);
    }
    if (authorizeResponse.status === 'PENDING') {
        // Awaiting async confirmation — handle via webhook
        return { status: 'pending', transactionId: authorizeResponse.connectorTransactionId };
    }

    return { status: authorizeResponse.status, transactionId: authorizeResponse.connectorTransactionId, error: authorizeResponse.error };
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
        "address": {  // Address Information
            "billingAddress": {
            }
        },
        "authType": "NO_THREE_DS",  // Authentication Details
        "returnUrl": "https://example.com/return"  // URLs for Redirection and Webhooks
    });

    if (authorizeResponse.status === 'FAILED') {
        throw new Error(`Payment failed: ${authorizeResponse.error?.message}`);
    }
    if (authorizeResponse.status === 'PENDING') {
        // Awaiting async confirmation — handle via webhook
        return { status: 'pending', transactionId: authorizeResponse.connectorTransactionId };
    }

    return { status: authorizeResponse.status, transactionId: authorizeResponse.connectorTransactionId, error: authorizeResponse.error };
}

// Refund a Payment
// Authorize with automatic capture, then refund the captured amount. `connector_transaction_id` from the Authorize response is reused for the Refund call.
async function processRefund(merchantTransactionId, config = _defaultConfig) {
    const paymentClient = new PaymentClient(config);

    // Step 1: Authorize — reserve funds on the payment method
    const authorizeResponse = await paymentClient.authorize(_buildAuthorizeRequest('AUTOMATIC'));

    if (authorizeResponse.status === 'FAILED') {
        throw new Error(`Payment failed: ${authorizeResponse.error?.message}`);
    }
    if (authorizeResponse.status === 'PENDING') {
        // Awaiting async confirmation — handle via webhook
        return { status: 'pending', transactionId: authorizeResponse.connectorTransactionId };
    }

    // Step 2: Refund — return funds to the customer
    const refundResponse = await paymentClient.refund(_buildRefundRequest(authorizeResponse.connectorTransactionId));

    if (refundResponse.status === 'FAILED') {
        throw new Error(`Refund failed: ${refundResponse.error?.message}`);
    }

    return { status: refundResponse.status, error: refundResponse.error };
}

// Recurring / Mandate Payments
// Store a payment mandate with SetupRecurring, then charge it repeatedly with RecurringPaymentService.Charge without requiring customer action.
async function processRecurring(merchantTransactionId, config = _defaultConfig) {
    const paymentClient = new PaymentClient(config);
    const recurringPaymentClient = new RecurringPaymentClient(config);

    // Step 1: Setup Recurring — store the payment mandate
    const setupResponse = await paymentClient.setupRecurring({
        "merchantRecurringPaymentId": "probe_mandate_001",  // Identification
        "amount": {  // Mandate Details
            "minorAmount": 0,  // Amount in minor units (e.g., 1000 = $10.00)
            "currency": "USD"  // ISO 4217 currency code (e.g., "USD", "EUR")
        },
        "paymentMethod": {
            "card": {  // Generic card payment
                "cardNumber": {"value": "4111111111111111"},  // Card Identification
                "cardExpMonth": {"value": "03"},
                "cardExpYear": {"value": "2030"},
                "cardCvc": {"value": "737"},
                "cardHolderName": {"value": "John Doe"}  // Cardholder Information
            }
        },
        "address": {  // Address Information
            "billingAddress": {
            }
        },
        "authType": "NO_THREE_DS",  // Type of authentication to be used
        "enrolledFor3Ds": false,  // Indicates if the customer is enrolled for 3D Secure
        "returnUrl": "https://example.com/mandate-return",  // URL to redirect after setup
        "setupFutureUsage": "OFF_SESSION",  // Indicates future usage intention
        "requestIncrementalAuthorization": false,  // Indicates if incremental authorization is requested
        "customerAcceptance": {  // Details of customer acceptance
            "acceptanceType": "OFFLINE",  // Type of acceptance (e.g., online, offline).
            "acceptedAt": 0  // Timestamp when the acceptance was made (Unix timestamp, seconds since epoch).
        }
    });

    if (setupResponse.status === 'FAILED') {
        throw new Error(`Recurring setup failed: ${setupResponse.error?.message}`);
    }

    // Step 2: Recurring Charge — charge against the stored mandate
    const recurringResponse = await recurringPaymentClient.charge({
        "connectorRecurringPaymentId": { connectorMandateId: { connectorMandateId: setupResponse.mandateReference?.connectorMandateId?.connectorMandateId } },  // from setup response
        "amount": {  // Amount Information
            "minorAmount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
            "currency": "USD"  // ISO 4217 currency code (e.g., "USD", "EUR")
        },
        "returnUrl": "https://example.com/recurring-return",
        "connectorCustomerId": "cust_probe_123",
        "offSession": true  // Behavioral Flags and Preferences
    });

    if (recurringResponse.status === 'FAILED') {
        throw new Error(`Recurring_Charge failed: ${recurringResponse.error?.message}`);
    }

    return { status: recurringResponse.status, transactionId: recurringResponse.connectorTransactionId ?? '', error: recurringResponse.error };
}

// Void a Payment
// Authorize funds with a manual capture flag, then cancel the authorization with Void before any capture occurs. Releases the hold on the customer's funds.
async function processVoidPayment(merchantTransactionId, config = _defaultConfig) {
    const paymentClient = new PaymentClient(config);

    // Step 1: Authorize — reserve funds on the payment method
    const authorizeResponse = await paymentClient.authorize(_buildAuthorizeRequest('MANUAL'));

    if (authorizeResponse.status === 'FAILED') {
        throw new Error(`Payment failed: ${authorizeResponse.error?.message}`);
    }
    if (authorizeResponse.status === 'PENDING') {
        // Awaiting async confirmation — handle via webhook
        return { status: 'pending', transactionId: authorizeResponse.connectorTransactionId };
    }

    // Step 2: Void — release reserved funds (cancel authorization)
    const voidResponse = await paymentClient.void(_buildVoidRequest(authorizeResponse.connectorTransactionId));

    return { status: voidResponse.status, transactionId: authorizeResponse.connectorTransactionId, error: voidResponse.error };
}

// Get Payment Status
// Authorize a payment, then poll the connector for its current status using Get. Use this to sync payment state when webhooks are unavailable or delayed.
async function processGetPayment(merchantTransactionId, config = _defaultConfig) {
    const paymentClient = new PaymentClient(config);

    // Step 1: Authorize — reserve funds on the payment method
    const authorizeResponse = await paymentClient.authorize(_buildAuthorizeRequest('MANUAL'));

    if (authorizeResponse.status === 'FAILED') {
        throw new Error(`Payment failed: ${authorizeResponse.error?.message}`);
    }
    if (authorizeResponse.status === 'PENDING') {
        // Awaiting async confirmation — handle via webhook
        return { status: 'pending', transactionId: authorizeResponse.connectorTransactionId };
    }

    // Step 2: Get — retrieve current payment status from the connector
    const getResponse = await paymentClient.get(_buildGetRequest(authorizeResponse.connectorTransactionId));

    return { status: getResponse.status, transactionId: getResponse.connectorTransactionId, error: getResponse.error };
}

// Create Customer
// Register a customer record in the connector system. Returns a connector_customer_id that can be reused for recurring payments and tokenized card storage.
async function processCreateCustomer(merchantTransactionId, config = _defaultConfig) {
    const customerClient = new CustomerClient(config);

    // Step 1: Create Customer — register customer record in the connector
    const createResponse = await customerClient.create({
        "merchantCustomerId": "cust_probe_123",  // Identification
        "customerName": "John Doe",  // Name of the customer
        "email": {"value": "test@example.com"},  // Email address of the customer
        "phoneNumber": "4155552671"  // Phone number of the customer
    });

    return { customerId: createResponse.connectorCustomerId, error: createResponse.error };
}

// Tokenize Payment Method
// Store card details in the connector's vault and receive a reusable payment token. Use the returned token for one-click payments and recurring billing without re-collecting card data.
async function processTokenize(merchantTransactionId, config = _defaultConfig) {
    const paymentMethodClient = new PaymentMethodClient(config);

    // Step 1: Tokenize — store card details and return a reusable token
    const tokenizeResponse = await paymentMethodClient.tokenize({
        "amount": {  // Payment Information
            "minorAmount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
            "currency": "USD"  // ISO 4217 currency code (e.g., "USD", "EUR")
        },
        "paymentMethod": {
            "card": {  // Generic card payment
                "cardNumber": {"value": "4111111111111111"},  // Card Identification
                "cardExpMonth": {"value": "03"},
                "cardExpYear": {"value": "2030"},
                "cardCvc": {"value": "737"},
                "cardHolderName": {"value": "John Doe"}  // Cardholder Information
            }
        },
        "address": {  // Address Information
            "billingAddress": {
            }
        }
    });

    return { token: tokenizeResponse.paymentMethodToken, error: tokenizeResponse.error };
}

// Tokenized Payment (Authorize + Capture)
// Authorize using a connector-issued payment method token (e.g. Stripe pm_xxx). Card data never touches your server — only the token is sent. Capture settles the reserved funds.
async function processTokenizedCheckout(merchantTransactionId, config = _defaultConfig) {
    const tokenizedPaymentClient = new TokenizedPaymentClient(config);
    const paymentClient = new PaymentClient(config);

    // Step 1: Tokenized Authorize — reserve funds using a connector-issued payment method token
    const authorizeResponse = await tokenizedPaymentClient.tokenizedAuthorize({
        "merchantTransactionId": "probe_tokenized_txn_001",
        "amount": {
            "minorAmount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
            "currency": "USD"  // ISO 4217 currency code (e.g., "USD", "EUR")
        },
        "connectorToken": {
            "value": "pm_1AbcXyzStripeTestToken"
        },
        "captureMethod": "AUTOMATIC",
        "address": {
            "billingAddress": {
            }
        },
        "returnUrl": "https://example.com/return"
    });

    // Step 2: Capture — settle the reserved funds
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

    return {};
}

// Tokenized Recurring Payments
// Store a payment mandate using a connector token with SetupRecurring, then charge it repeatedly with RecurringPaymentService without requiring customer action or re-collecting card data.
async function processTokenizedRecurring(merchantTransactionId, config = _defaultConfig) {
    const tokenizedPaymentClient = new TokenizedPaymentClient(config);
    const recurringPaymentClient = new RecurringPaymentClient(config);

    // Step 1: Tokenized Setup Recurring — store a mandate using a connector token
    const setupResponse = await tokenizedPaymentClient.tokenizedSetupRecurring({
        "merchantRecurringPaymentId": "probe_tokenized_mandate_001",
        "amount": {
            "minorAmount": 0,  // Amount in minor units (e.g., 1000 = $10.00)
            "currency": "USD"  // ISO 4217 currency code (e.g., "USD", "EUR")
        },
        "connectorToken": {
            "value": "pm_1AbcXyzStripeTestToken"
        },
        "address": {
            "billingAddress": {
            }
        },
        "customerAcceptance": {
            "acceptanceType": "ONLINE",  // Type of acceptance (e.g., online, offline).
            "online": {
                "ipAddress": "127.0.0.1",
                "userAgent": "Mozilla/5.0"
            }
        }
    });

    // Step 2: Recurring Charge — charge against the stored mandate
    const recurringResponse = await recurringPaymentClient.charge({
        "connectorRecurringPaymentId": {  // Reference to existing mandate
            "mandateIdType": {
                "connectorMandateId": "probe-mandate-123"
            }
        },
        "amount": {  // Amount Information
            "minorAmount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
            "currency": "USD"  // ISO 4217 currency code (e.g., "USD", "EUR")
        },
        "paymentMethod": {  // Optional payment Method Information (for network transaction flows)
            "token": {"token": {"value": "probe_pm_token"}}  // Payment tokens
        },
        "returnUrl": "https://example.com/recurring-return",
        "connectorCustomerId": "cust_probe_123",
        "paymentMethodType": "PAY_PAL",
        "offSession": true  // Behavioral Flags and Preferences
    });

    if (recurringResponse.status === 'FAILED') {
        throw new Error(`Recurring_Charge failed: ${recurringResponse.error?.message}`);
    }

    return {};
}

// Proxy Payment via Vault (VGS / Basis Theory)
// Authorize using vault alias tokens. Configure an outbound proxy URL in RequestConfig — the proxy substitutes aliases with real card values before the request reaches the connector. Card data never touches your server.
async function processProxyCheckout(merchantTransactionId, config = _defaultConfig) {
    const proxyPaymentClient = new ProxyPaymentClient(config);

    // Step 1: Proxy Authorize — reserve funds using vault alias tokens routed through a proxy
    const authorizeResponse = await proxyPaymentClient.proxyAuthorize({
        "merchantTransactionId": "probe_proxy_txn_001",
        "amount": {
            "minorAmount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
            "currency": "USD"  // ISO 4217 currency code (e.g., "USD", "EUR")
        },
        "vaultCard": {
            "cardNumberAlias": {
                "value": "tok_sandbox_abc123"
            },
            "expMonth": "03",
            "expYear": "2030",
            "cvcAlias": {
                "value": "tok_sandbox_cvc456"
            },
            "cardHolderName": "John Doe"
        },
        "captureMethod": "AUTOMATIC",
        "authType": "NO_THREE_DS",
        "address": {
            "billingAddress": {
            }
        },
        "returnUrl": "https://example.com/return"
    });

    return {};
}

// Proxy Payment with 3DS (VGS + Proxy 3DS)
// Full 3DS flow using vault alias tokens routed through an outbound proxy. The proxy substitutes aliases before forwarding to Netcetera (3DS server). Authorize after successful authentication using the same vault aliases.
async function processProxy3DsCheckout(merchantTransactionId, config = _defaultConfig) {
    const proxyPaymentClient = new ProxyPaymentClient(config);

    // Step 1: Proxy Pre-Authenticate — initiate 3DS using vault aliases (proxy substitutes before Netcetera)
    const preAuthenticateresponse = await proxyPaymentClient.proxyPreAuthenticate({
        "merchantOrderId": "probe_proxy_order_001",
        "amount": {
            "minorAmount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
            "currency": "USD"  // ISO 4217 currency code (e.g., "USD", "EUR")
        },
        "vaultCard": {
            "cardNumberAlias": {
                "value": "tok_sandbox_abc123"
            },
            "expMonth": "03",
            "expYear": "2030",
            "cardHolderName": "John Doe"
        },
        "browserInfo": {
            "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
            "acceptHeader": "application/json",  // Browser Headers
            "language": "en-US",
            "colorDepth": 24,  // Display Information
            "screenHeight": 1080,
            "screenWidth": 1920,
            "timeZoneOffset": -330,
            "javaEnabled": false,  // Browser Settings
            "javaScriptEnabled": true
        },
        "returnUrl": "https://example.com/3ds-return"
    });

    // Step 2: Proxy Authenticate — execute 3DS challenge using vault aliases via proxy
    const authenticateResponse = await proxyPaymentClient.proxyAuthenticate({
        "merchantOrderId": "probe_proxy_order_001",
        "amount": {
            "minorAmount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
            "currency": "USD"  // ISO 4217 currency code (e.g., "USD", "EUR")
        },
        "vaultCard": {
            "cardNumberAlias": {
                "value": "tok_sandbox_abc123"
            },
            "expMonth": "03",
            "expYear": "2030",
            "cardHolderName": "John Doe"
        },
        "returnUrl": "https://example.com/3ds-return"
    });

    // Step 3: Proxy Post-Authenticate — validate 3DS result using vault aliases via proxy
    const postAuthenticateresponse = await proxyPaymentClient.proxyPostAuthenticate({
        "merchantOrderId": "probe_proxy_order_001",
        "vaultCard": {
            "cardNumberAlias": {
                "value": "tok_sandbox_abc123"
            },
            "expMonth": "03",
            "expYear": "2030",
            "cardHolderName": "John Doe"
        }
    });

    // Step 4: Proxy Authorize — reserve funds using vault alias tokens routed through a proxy
    const authorizeResponse = await proxyPaymentClient.proxyAuthorize({
        "merchantTransactionId": "probe_proxy_txn_001",
        "amount": {
            "minorAmount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
            "currency": "USD"  // ISO 4217 currency code (e.g., "USD", "EUR")
        },
        "vaultCard": {
            "cardNumberAlias": {
                "value": "tok_sandbox_abc123"
            },
            "expMonth": "03",
            "expYear": "2030",
            "cvcAlias": {
                "value": "tok_sandbox_cvc456"
            },
            "cardHolderName": "John Doe"
        },
        "captureMethod": "AUTOMATIC",
        "authType": "NO_THREE_DS",
        "address": {
            "billingAddress": {
            }
        },
        "returnUrl": "https://example.com/return"
    });

    return {};
}

// Flow: PaymentService.Authorize (Card)
async function authorize(merchantTransactionId, config = _defaultConfig) {
    const paymentClient = new PaymentClient(config);

    const authorizeResponse = await paymentClient.authorize(_buildAuthorizeRequest('AUTOMATIC'));

    return { status: authorizeResponse.status, transactionId: authorizeResponse.connectorTransactionId };
}

// Flow: PaymentService.Capture
async function capture(merchantTransactionId, config = _defaultConfig) {
    const paymentClient = new PaymentClient(config);

    const captureResponse = await paymentClient.capture(_buildCaptureRequest('probe_connector_txn_001'));

    return { status: captureResponse.status };
}

// Flow: CustomerService.Create
async function createCustomer(merchantTransactionId, config = _defaultConfig) {
    const customerClient = new CustomerClient(config);

    const createResponse = await customerClient.create(_buildCreateCustomerRequest());

    return { status: createResponse.status };
}

// Flow: PaymentService.Get
async function get(merchantTransactionId, config = _defaultConfig) {
    const paymentClient = new PaymentClient(config);

    const getResponse = await paymentClient.get(_buildGetRequest('probe_connector_txn_001'));

    return { status: getResponse.status };
}

// Flow: RecurringPaymentService.Charge
async function recurringCharge(merchantTransactionId, config = _defaultConfig) {
    const recurringPaymentClient = new RecurringPaymentClient(config);

    const recurringResponse = await recurringPaymentClient.charge(_buildRecurringChargeRequest());

    return { status: recurringResponse.status };
}

// Flow: PaymentService.Refund
async function refund(merchantTransactionId, config = _defaultConfig) {
    const paymentClient = new PaymentClient(config);

    const refundResponse = await paymentClient.refund(_buildRefundRequest('probe_connector_txn_001'));

    return { status: refundResponse.status };
}

// Flow: PaymentService.SetupRecurring
async function setupRecurring(merchantTransactionId, config = _defaultConfig) {
    const paymentClient = new PaymentClient(config);

    const setupResponse = await paymentClient.setupRecurring(_buildSetupRecurringRequest());

    return { status: setupResponse.status, mandateId: setupResponse.connectorTransactionId };
}

// Flow: PaymentMethodService.Tokenize
async function tokenize(merchantTransactionId, config = _defaultConfig) {
    const paymentMethodClient = new PaymentMethodClient(config);

    const tokenizeResponse = await paymentMethodClient.tokenize(_buildTokenizeRequest());

    return { status: tokenizeResponse.status };
}

// Flow: PaymentService.Void
async function voidPayment(merchantTransactionId, config = _defaultConfig) {
    const paymentClient = new PaymentClient(config);

    const voidResponse = await paymentClient.void(_buildVoidRequest('probe_connector_txn_001'));

    return { status: voidResponse.status };
}

// Flow: TokenizedPaymentService.Authorize
async function tokenizedAuthorize(merchantTransactionId, config = _defaultConfig) {
    const tokenizedPaymentClient = new TokenizedPaymentClient(config);

    const tokenizedResponse = await tokenizedPaymentClient.tokenizedAuthorize(_buildTokenizedAuthorizeRequest());

    return { status: tokenizedResponse.status };
}

// Flow: TokenizedPaymentService.SetupRecurring
async function tokenizedSetupRecurring(merchantTransactionId, config = _defaultConfig) {
    const tokenizedPaymentClient = new TokenizedPaymentClient(config);

    const tokenizedResponse = await tokenizedPaymentClient.tokenizedSetupRecurring(_buildTokenizedSetupRecurringRequest());

    return { status: tokenizedResponse.status };
}

// Flow: ProxyPaymentService.Authorize
async function proxyAuthorize(merchantTransactionId, config = _defaultConfig) {
    const proxyPaymentClient = new ProxyPaymentClient(config);

    const proxyResponse = await proxyPaymentClient.proxyAuthorize(_buildProxyAuthorizeRequest());

    return { status: proxyResponse.status };
}

// Flow: ProxyPaymentService.SetupRecurring
async function proxySetupRecurring(merchantTransactionId, config = _defaultConfig) {
    const proxyPaymentClient = new ProxyPaymentClient(config);

    const proxyResponse = await proxyPaymentClient.proxySetupRecurring(_buildProxySetupRecurringRequest());

    return { status: proxyResponse.status };
}

// Flow: ProxyPaymentService.PreAuthenticate
async function proxyPreAuthenticate(merchantTransactionId, config = _defaultConfig) {
    const proxyPaymentClient = new ProxyPaymentClient(config);

    const proxyResponse = await proxyPaymentClient.proxyPreAuthenticate(_buildProxyPreAuthenticateRequest());

    return { status: proxyResponse.status };
}

// Flow: ProxyPaymentService.Authenticate
async function proxyAuthenticate(merchantTransactionId, config = _defaultConfig) {
    const proxyPaymentClient = new ProxyPaymentClient(config);

    const proxyResponse = await proxyPaymentClient.proxyAuthenticate(_buildProxyAuthenticateRequest());

    return { status: proxyResponse.status };
}

// Flow: ProxyPaymentService.PostAuthenticate
async function proxyPostAuthenticate(merchantTransactionId, config = _defaultConfig) {
    const proxyPaymentClient = new ProxyPaymentClient(config);

    const proxyResponse = await proxyPaymentClient.proxyPostAuthenticate(_buildProxyPostAuthenticateRequest());

    return { status: proxyResponse.status };
}


module.exports = { processCheckoutCard, processCheckoutAutocapture, processCheckoutWallet, processCheckoutBank, processRefund, processRecurring, processVoidPayment, processGetPayment, processCreateCustomer, processTokenize, processTokenizedCheckout, processTokenizedRecurring, processProxyCheckout, processProxy3DsCheckout, authorize, capture, createCustomer, get, recurringCharge, refund, setupRecurring, tokenize, voidPayment, tokenizedAuthorize, tokenizedSetupRecurring, proxyAuthorize, proxySetupRecurring, proxyPreAuthenticate, proxyAuthenticate, proxyPostAuthenticate, _buildAuthorizeRequest, _buildCaptureRequest, _buildCreateCustomerRequest, _buildGetRequest, _buildProxyAuthenticateRequest, _buildProxyAuthorizeRequest, _buildProxyPostAuthenticateRequest, _buildProxyPreAuthenticateRequest, _buildProxySetupRecurringRequest, _buildRecurringChargeRequest, _buildRefundRequest, _buildSetupRecurringRequest, _buildTokenizeRequest, _buildTokenizedAuthorizeRequest, _buildTokenizedSetupRecurringRequest, _buildVoidRequest };

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
