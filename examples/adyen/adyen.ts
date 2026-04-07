// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py adyen
//
// Adyen — all integration scenarios and flows in one file.
// Run a scenario:  npx tsx adyen.ts checkout_autocapture

import { PaymentClient, types } from 'hyperswitch-prism';
const { ConnectorConfig, ConnectorSpecificConfig, SdkOptions, Environment } = types;

const _defaultConfig: ConnectorConfig = {
    options: {
        environment: Environment.SANDBOX,
    },
};
// Standalone credentials (field names depend on connector auth type):
// _defaultConfig.connectorConfig = {
//     adyen: { apiKey: { value: 'YOUR_API_KEY' } }
// };


// ANCHOR: scenario_functions
// One-step Payment (Authorize + Capture)
// Simple payment that authorizes and captures in one call. Use for immediate charges.
async function processCheckoutAutocapture(merchantTransactionId: string, config: ConnectorConfig = _defaultConfig): Promise<any> {
    const paymentClient = new PaymentClient(config);

    // Step 1: Authorize — reserve funds on the payment method
    const authorizeResponse = await paymentClient.authorize({
        "merchantTransactionId": "probe_txn_001",
        "amount": {
            "minorAmount": 1000,
            "currency": "USD"
        },
        "paymentMethod": {
            "cardNumber": "4111111111111111",
            "cardExpMonth": "03",
            "cardExpYear": "2030",
            "cardCvc": "737",
            "cardHolderName": "John Doe"
        },
        "captureMethod": "AUTOMATIC",
        "address": {
        },
        "authType": "NO_THREE_DS",
        "returnUrl": "https://example.com/return",
        "browserInfo": {
            "colorDepth": 24,
            "screenHeight": 900,
            "screenWidth": 1440,
            "javaEnabled": false,
            "javaScriptEnabled": true,
            "language": "en-US",
            "timeZoneOffsetMinutes": -480,
            "acceptHeader": "application/json",
            "userAgent": "Mozilla/5.0 (probe-bot)",
            "acceptLanguage": "en-US,en;q=0.9",
            "ipAddress": "1.2.3.4"
        }
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

// Card Payment (Authorize + Capture)
// Two-step card payment. First authorize, then capture. Use when you need to verify funds before finalizing.
async function processCheckoutCard(merchantTransactionId: string, config: ConnectorConfig = _defaultConfig): Promise<any> {
    const paymentClient = new PaymentClient(config);

    // Step 1: Authorize — reserve funds on the payment method
    const authorizeResponse = await paymentClient.authorize({
        "merchantTransactionId": "probe_txn_001",
        "amount": {
            "minorAmount": 1000,
            "currency": "USD"
        },
        "paymentMethod": {
            "cardNumber": "4111111111111111",
            "cardExpMonth": "03",
            "cardExpYear": "2030",
            "cardCvc": "737",
            "cardHolderName": "John Doe"
        },
        "captureMethod": "MANUAL",
        "address": {
        },
        "authType": "NO_THREE_DS",
        "returnUrl": "https://example.com/return",
        "browserInfo": {
            "colorDepth": 24,
            "screenHeight": 900,
            "screenWidth": 1440,
            "javaEnabled": false,
            "javaScriptEnabled": true,
            "language": "en-US",
            "timeZoneOffsetMinutes": -480,
            "acceptHeader": "application/json",
            "userAgent": "Mozilla/5.0 (probe-bot)",
            "acceptLanguage": "en-US,en;q=0.9",
            "ipAddress": "1.2.3.4"
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
        "merchantCaptureId": "probe_capture_001",
        "connectorTransactionId": authorizeResponse.connectorTransactionId,  // from authorize response
        "amountToCapture": {
            "minorAmount": 1000,
            "currency": "USD"
        }
    });

    if (captureResponse.status === 'FAILED') {
        throw new Error(`Capture failed: ${captureResponse.error?.message}`);
    }

    return { status: captureResponse.status, transactionId: authorizeResponse.connectorTransactionId, error: authorizeResponse.error };
}

// Refund
// Return funds to the customer for a completed payment.
async function processRefund(merchantTransactionId: string, config: ConnectorConfig = _defaultConfig): Promise<any> {
    const paymentClient = new PaymentClient(config);

    // Step 1: Authorize — reserve funds on the payment method
    const authorizeResponse = await paymentClient.authorize({
        "merchantTransactionId": "probe_txn_001",
        "amount": {
            "minorAmount": 1000,
            "currency": "USD"
        },
        "paymentMethod": {
            "cardNumber": "4111111111111111",
            "cardExpMonth": "03",
            "cardExpYear": "2030",
            "cardCvc": "737",
            "cardHolderName": "John Doe"
        },
        "captureMethod": "AUTOMATIC",
        "address": {
        },
        "authType": "NO_THREE_DS",
        "returnUrl": "https://example.com/return",
        "browserInfo": {
            "colorDepth": 24,
            "screenHeight": 900,
            "screenWidth": 1440,
            "javaEnabled": false,
            "javaScriptEnabled": true,
            "language": "en-US",
            "timeZoneOffsetMinutes": -480,
            "acceptHeader": "application/json",
            "userAgent": "Mozilla/5.0 (probe-bot)",
            "acceptLanguage": "en-US,en;q=0.9",
            "ipAddress": "1.2.3.4"
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
        "merchantRefundId": "probe_refund_001",
        "connectorTransactionId": authorizeResponse.connectorTransactionId,  // from authorize response
        "paymentAmount": 1000,
        "refundAmount": {
            "minorAmount": 1000,
            "currency": "USD"
        },
        "reason": "customer_request"
    });

    if (refundResponse.status === 'FAILED') {
        throw new Error(`Refund failed: ${refundResponse.error?.message}`);
    }

    return { status: refundResponse.status, error: refundResponse.error };
}

// Void Payment
// Cancel an authorized but not-yet-captured payment.
async function processVoidPayment(merchantTransactionId: string, config: ConnectorConfig = _defaultConfig): Promise<any> {
    const paymentClient = new PaymentClient(config);

    // Step 1: Authorize — reserve funds on the payment method
    const authorizeResponse = await paymentClient.authorize({
        "merchantTransactionId": "probe_txn_001",
        "amount": {
            "minorAmount": 1000,
            "currency": "USD"
        },
        "paymentMethod": {
            "cardNumber": "4111111111111111",
            "cardExpMonth": "03",
            "cardExpYear": "2030",
            "cardCvc": "737",
            "cardHolderName": "John Doe"
        },
        "captureMethod": "MANUAL",
        "address": {
        },
        "authType": "NO_THREE_DS",
        "returnUrl": "https://example.com/return",
        "browserInfo": {
            "colorDepth": 24,
            "screenHeight": 900,
            "screenWidth": 1440,
            "javaEnabled": false,
            "javaScriptEnabled": true,
            "language": "en-US",
            "timeZoneOffsetMinutes": -480,
            "acceptHeader": "application/json",
            "userAgent": "Mozilla/5.0 (probe-bot)",
            "acceptLanguage": "en-US,en;q=0.9",
            "ipAddress": "1.2.3.4"
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
        "merchantVoidId": "probe_void_001",
        "connectorTransactionId": authorizeResponse.connectorTransactionId,  // from authorize response
    });

    return { status: voidResponse.status, transactionId: authorizeResponse.connectorTransactionId, error: voidResponse.error };
}

// Flow: PaymentService.authorize (Card)
async function authorize(merchantTransactionId: string, config: ConnectorConfig = _defaultConfig): Promise<any> {
    // Step 1: Authorize — reserve funds on the payment method
    const authorizeResponse = await paymentClient.authorize({
        "merchantTransactionId": "probe_txn_001",
        "amount": {
            "minorAmount": 1000,
            "currency": "USD"
        },
        "paymentMethod": {
            "cardNumber": "4111111111111111",
            "cardExpMonth": "03",
            "cardExpYear": "2030",
            "cardCvc": "737",
            "cardHolderName": "John Doe"
        },
        "captureMethod": "AUTOMATIC",
        "address": {
        },
        "authType": "NO_THREE_DS",
        "returnUrl": "https://example.com/return",
        "browserInfo": {
            "colorDepth": 24,
            "screenHeight": 900,
            "screenWidth": 1440,
            "javaEnabled": false,
            "javaScriptEnabled": true,
            "language": "en-US",
            "timeZoneOffsetMinutes": -480,
            "acceptHeader": "application/json",
            "userAgent": "Mozilla/5.0 (probe-bot)",
            "acceptLanguage": "en-US,en;q=0.9",
            "ipAddress": "1.2.3.4"
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

// Flow: PaymentService.capture
async function capture(merchantTransactionId: string, config: ConnectorConfig = _defaultConfig): Promise<any> {
    // Step 1: Capture — settle the reserved funds
    const captureResponse = await paymentClient.capture({
        "merchantCaptureId": "probe_capture_001",
        "connectorTransactionId": "probe_connector_txn_001",
        "amountToCapture": {
            "minorAmount": 1000,
            "currency": "USD"
        }
    });

    if (captureResponse.status === 'FAILED') {
        throw new Error(`Capture failed: ${captureResponse.error?.message}`);
    }

    return { status: captureResponse.status };
}

// Flow: PaymentService.dispute_accept
async function disputeAccept(merchantTransactionId: string, config: ConnectorConfig = _defaultConfig): Promise<any> {
    // Step 1: dispute_accept
    const disputeResponse = await paymentClient.accept({
        "merchantDisputeId": "probe_dispute_001",
        "connectorTransactionId": "probe_txn_001",
        "disputeId": "probe_dispute_id_001"
    });

    return { status: disputeResponse.status };
}

// Flow: PaymentService.dispute_defend
async function disputeDefend(merchantTransactionId: string, config: ConnectorConfig = _defaultConfig): Promise<any> {
    // Step 1: dispute_defend
    const disputeResponse = await paymentClient.defend({
        "merchantDisputeId": "probe_dispute_001",
        "connectorTransactionId": "probe_txn_001",
        "disputeId": "probe_dispute_id_001",
        "reasonCode": "probe_reason"
    });

    return { status: disputeResponse.status };
}

// Flow: PaymentService.dispute_submit_evidence
async function disputeSubmitEvidence(merchantTransactionId: string, config: ConnectorConfig = _defaultConfig): Promise<any> {
    // Step 1: dispute_submit_evidence
    const disputeResponse = await paymentClient.submitEvidence({
        "merchantDisputeId": "probe_dispute_001",
        "connectorTransactionId": "probe_txn_001",
        "disputeId": "probe_dispute_id_001",
        "evidenceDocuments": [{"evidence_type": "SERVICE_DOCUMENTATION", "file_content": [112, 114, 111, 98, 101, 32, 101, 118, 105, 100, 101, 110, 99, 101, 32, 99, 111, 110, 116, 101, 110, 116], "file_mime_type": "application/pdf"}]
    });

    return { status: disputeResponse.status };
}

// Flow: PaymentService.handle_event
async function handleEvent(merchantTransactionId: string, config: ConnectorConfig = _defaultConfig): Promise<any> {
    // Step 1: handle_event
    const handleResponse = await paymentClient.handleEvent({
        // No required fields
    });

    return { status: handleResponse.status };
}

// Flow: PaymentService.proxy_authorize
async function proxyAuthorize(merchantTransactionId: string, config: ConnectorConfig = _defaultConfig): Promise<any> {
    // Step 1: proxy_authorize
    const proxyResponse = await paymentClient.proxyAuthorize({
        "merchantTransactionId": "probe_proxy_txn_001",
        "amount": {
            "minorAmount": 1000,
            "currency": "USD"
        },
        "cardProxy": {
            "cardNumber": "4111111111111111",
            "cardExpMonth": "03",
            "cardExpYear": "2030",
            "cardCvc": "123",
            "cardHolderName": "John Doe"
        },
        "address": {
        },
        "captureMethod": "AUTOMATIC",
        "authType": "NO_THREE_DS",
        "returnUrl": "https://example.com/return",
        "browserInfo": {
            "colorDepth": 24,
            "screenHeight": 900,
            "screenWidth": 1440,
            "javaEnabled": false,
            "javaScriptEnabled": true,
            "language": "en-US",
            "timeZoneOffsetMinutes": -480,
            "acceptHeader": "application/json",
            "userAgent": "Mozilla/5.0 (probe-bot)",
            "acceptLanguage": "en-US,en;q=0.9",
            "ipAddress": "1.2.3.4"
        }
    });

    return { status: proxyResponse.status };
}

// Flow: PaymentService.proxy_setup_recurring
async function proxySetupRecurring(merchantTransactionId: string, config: ConnectorConfig = _defaultConfig): Promise<any> {
    // Step 1: proxy_setup_recurring
    const proxyResponse = await paymentClient.proxySetupRecurring({
        "merchantRecurringPaymentId": "probe_proxy_mandate_001",
        "amount": {
            "minorAmount": 0,
            "currency": "USD"
        },
        "cardProxy": {
            "cardNumber": "4111111111111111",
            "cardExpMonth": "03",
            "cardExpYear": "2030",
            "cardCvc": "123",
            "cardHolderName": "John Doe"
        },
        "customer": {
            "id": "probe_customer_001"
        },
        "address": {
        },
        "returnUrl": "https://example.com/return",
        "customerAcceptance": {
            "acceptanceType": "OFFLINE",
            "acceptedAt": 0
        },
        "authType": "NO_THREE_DS",
        "setupFutureUsage": "OFF_SESSION",
        "browserInfo": {
            "colorDepth": 24,
            "screenHeight": 900,
            "screenWidth": 1440,
            "javaEnabled": false,
            "javaScriptEnabled": true,
            "language": "en-US",
            "timeZoneOffsetMinutes": -480,
            "acceptHeader": "application/json",
            "userAgent": "Mozilla/5.0 (probe-bot)",
            "acceptLanguage": "en-US,en;q=0.9",
            "ipAddress": "1.2.3.4"
        }
    });

    return { status: proxyResponse.status };
}

// Flow: PaymentService.recurring_charge
async function recurringCharge(merchantTransactionId: string, config: ConnectorConfig = _defaultConfig): Promise<any> {
    // Step 1: Recurring Charge — charge against the stored mandate
    const recurringResponse = await paymentClient.charge({
        "connectorRecurringPaymentId": {
            "connectorMandateId": "probe-mandate-123"
        },
        "amount": {
            "minorAmount": 1000,
            "currency": "USD"
        },
        "paymentMethod": {
            "token": "probe_pm_token"
        },
        "returnUrl": "https://example.com/recurring-return",
        "connectorCustomerId": "cust_probe_123",
        "paymentMethodType": "PAY_PAL",
        "offSession": true
    });

    if (recurringResponse.status === 'FAILED') {
        throw new Error(`Recurring_Charge failed: ${recurringResponse.error?.message}`);
    }

    return { status: recurringResponse.status };
}

// Flow: PaymentService.refund
async function refund(merchantTransactionId: string, config: ConnectorConfig = _defaultConfig): Promise<any> {
    // Step 1: Refund — return funds to the customer
    const refundResponse = await paymentClient.refund({
        "merchantRefundId": "probe_refund_001",
        "connectorTransactionId": "probe_connector_txn_001",
        "paymentAmount": 1000,
        "refundAmount": {
            "minorAmount": 1000,
            "currency": "USD"
        },
        "reason": "customer_request"
    });

    if (refundResponse.status === 'FAILED') {
        throw new Error(`Refund failed: ${refundResponse.error?.message}`);
    }

    return { status: refundResponse.status };
}

// Flow: PaymentService.setup_recurring
async function setupRecurring(merchantTransactionId: string, config: ConnectorConfig = _defaultConfig): Promise<any> {
    // Step 1: Setup Recurring — store the payment mandate
    const setupResponse = await paymentClient.setupRecurring({
        "merchantRecurringPaymentId": "probe_mandate_001",
        "amount": {
            "minorAmount": 0,
            "currency": "USD"
        },
        "paymentMethod": {
            "cardNumber": "4111111111111111",
            "cardExpMonth": "03",
            "cardExpYear": "2030",
            "cardCvc": "737",
            "cardHolderName": "John Doe"
        },
        "customer": {
            "id": "cust_probe_123"
        },
        "address": {
        },
        "authType": "NO_THREE_DS",
        "enrolledFor3Ds": false,
        "returnUrl": "https://example.com/mandate-return",
        "setupFutureUsage": "OFF_SESSION",
        "requestIncrementalAuthorization": false,
        "customerAcceptance": {
            "acceptanceType": "OFFLINE",
            "acceptedAt": 0
        },
        "browserInfo": {
            "colorDepth": 24,
            "screenHeight": 900,
            "screenWidth": 1440,
            "javaEnabled": false,
            "javaScriptEnabled": true,
            "language": "en-US",
            "timeZoneOffsetMinutes": -480,
            "acceptHeader": "application/json",
            "userAgent": "Mozilla/5.0 (probe-bot)",
            "acceptLanguage": "en-US,en;q=0.9",
            "ipAddress": "1.2.3.4"
        }
    });

    if (setupResponse.status === 'FAILED') {
        throw new Error(`Recurring setup failed: ${setupResponse.error?.message}`);
    }

    return { status: setupResponse.status, mandateId: setupResponse.connectorTransactionId };
}

// Flow: PaymentService.void
async function voidPayment(merchantTransactionId: string, config: ConnectorConfig = _defaultConfig): Promise<any> {
    // Step 1: Void — release reserved funds (cancel authorization)
    const voidResponse = await paymentClient.void({
        "merchantVoidId": "probe_void_001",
        "connectorTransactionId": "probe_connector_txn_001"
    });

    return { status: voidResponse.status };
}


// Export all process* functions for the smoke test
export {
    processCheckoutAutocapture, processCheckoutCard, processRefund, processVoidPayment, authorize, capture, disputeAccept, disputeDefend, disputeSubmitEvidence, handleEvent, proxyAuthorize, proxySetupRecurring, recurringCharge, refund, setupRecurring, voidPayment
};

// CLI runner
if (require.main === module) {
    const scenario = process.argv[2] || 'checkout_autocapture';
    const key = 'process' + scenario.replace(/_([a-z])/g, (_, l) => l.toUpperCase()).replace(/^(.)/, c => c.toUpperCase());
    const fn = (globalThis as any)[key] || (exports as any)[key];
    if (!fn) {
        const available = Object.keys(exports).map(k =>
            k.replace(/^process/, '').replace(/([A-Z])/g, '_$1').toLowerCase().replace(/^_/, '')
        );
        console.error(`Unknown scenario: ${scenario}. Available: ${available.join(', ')}`);
        process.exit(1);
    }
    fn('order_001').catch(console.error);
}
