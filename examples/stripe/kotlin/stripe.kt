// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py stripe
//
// Stripe — all scenarios and flows in one file.
// Run a scenario:  ./gradlew run --args="stripe processCheckoutCard"

package examples.stripe

import payments.PaymentClient
import payments.RecurringPaymentClient
import payments.CustomerClient
import payments.PaymentMethodClient
import payments.TokenizedPaymentClient
import payments.ProxyPaymentClient
import payments.PaymentServiceAuthorizeRequest
import payments.PaymentServiceCaptureRequest
import payments.PaymentServiceRefundRequest
import payments.PaymentServiceSetupRecurringRequest
import payments.RecurringPaymentServiceChargeRequest
import payments.PaymentServiceVoidRequest
import payments.PaymentServiceGetRequest
import payments.CustomerServiceCreateRequest
import payments.PaymentMethodServiceTokenizeRequest
import payments.TokenizedPaymentServiceAuthorizeRequest
import payments.TokenizedPaymentServiceSetupRecurringRequest
import payments.ProxyPaymentServiceAuthorizeRequest
import payments.ProxyPaymentMethodAuthenticationServicePreAuthenticateRequest
import payments.ProxyPaymentMethodAuthenticationServiceAuthenticateRequest
import payments.ProxyPaymentMethodAuthenticationServicePostAuthenticateRequest
import payments.ProxyPaymentServiceSetupRecurringRequest
import payments.AcceptanceType
import payments.AuthenticationType
import payments.CaptureMethod
import payments.Currency
import payments.FutureUsage
import payments.PaymentMethodType
import payments.ConnectorConfig
import payments.SdkOptions
import payments.Environment


private fun buildAuthorizeRequest(captureMethodStr: String): PaymentServiceAuthorizeRequest {
    return PaymentServiceAuthorizeRequest.newBuilder().apply {
        merchantTransactionId = "probe_txn_001"  // Identification
        amountBuilder.apply {  // The amount for the payment
            minorAmount = 1000L  // Amount in minor units (e.g., 1000 = $10.00)
            currency = Currency.USD  // ISO 4217 currency code (e.g., "USD", "EUR")
        }
        paymentMethodBuilder.apply {  // Payment method to be used
            cardBuilder.apply {  // Generic card payment
                cardNumberBuilder.value = "4111111111111111"  // Card Identification
                cardExpMonthBuilder.value = "03"
                cardExpYearBuilder.value = "2030"
                cardCvcBuilder.value = "737"
                cardHolderNameBuilder.value = "John Doe"  // Cardholder Information
            }
        }
        captureMethod = CaptureMethod.valueOf(captureMethodStr)  // Method for capturing the payment
        addressBuilder.apply {  // Address Information
            billingAddressBuilder.apply {
            }
        }
        authType = AuthenticationType.NO_THREE_DS  // Authentication Details
        returnUrl = "https://example.com/return"  // URLs for Redirection and Webhooks
    }.build()
}

private fun buildCaptureRequest(connectorTransactionIdStr: String): PaymentServiceCaptureRequest {
    return PaymentServiceCaptureRequest.newBuilder().apply {
        merchantCaptureId = "probe_capture_001"  // Identification
        connectorTransactionId = connectorTransactionIdStr
        amountToCaptureBuilder.apply {  // Capture Details
            minorAmount = 1000L  // Amount in minor units (e.g., 1000 = $10.00)
            currency = Currency.USD  // ISO 4217 currency code (e.g., "USD", "EUR")
        }
    }.build()
}

private fun buildGetRequest(connectorTransactionIdStr: String): PaymentServiceGetRequest {
    return PaymentServiceGetRequest.newBuilder().apply {
        merchantTransactionId = "probe_merchant_txn_001"  // Identification
        connectorTransactionId = connectorTransactionIdStr
        amountBuilder.apply {  // Amount Information
            minorAmount = 1000L  // Amount in minor units (e.g., 1000 = $10.00)
            currency = Currency.USD  // ISO 4217 currency code (e.g., "USD", "EUR")
        }
    }.build()
}

private fun buildRefundRequest(connectorTransactionIdStr: String): PaymentServiceRefundRequest {
    return PaymentServiceRefundRequest.newBuilder().apply {
        merchantRefundId = "probe_refund_001"  // Identification
        connectorTransactionId = connectorTransactionIdStr
        paymentAmount = 1000L  // Amount Information
        refundAmountBuilder.apply {
            minorAmount = 1000L  // Amount in minor units (e.g., 1000 = $10.00)
            currency = Currency.USD  // ISO 4217 currency code (e.g., "USD", "EUR")
        }
        reason = "customer_request"  // Reason for the refund
    }.build()
}

private fun buildVoidRequest(connectorTransactionIdStr: String): PaymentServiceVoidRequest {
    return PaymentServiceVoidRequest.newBuilder().apply {
        merchantVoidId = "probe_void_001"  // Identification
        connectorTransactionId = connectorTransactionIdStr
    }.build()
}

val _defaultConfig: ConnectorConfig = ConnectorConfig.newBuilder()
    .setOptions(SdkOptions.newBuilder().setEnvironment(Environment.SANDBOX).build())
    // .setConnectorConfig(...) — set your connector config here
    .build()


// Scenario: Card Payment (Authorize + Capture)
// Reserve funds with Authorize, then settle with a separate Capture call. Use for physical goods or delayed fulfillment where capture happens later.
fun processCheckoutCard(txnId: String, config: ConnectorConfig = _defaultConfig): Map<String, Any?> {
    val paymentClient = PaymentClient(config)

    // Step 1: Authorize — reserve funds on the payment method
    val authorizeResponse = paymentClient.authorize(buildAuthorizeRequest("MANUAL"))

    when (authorizeResponse.status.name) {
        "FAILED"  -> throw RuntimeException("Payment failed: ${authorizeResponse.error.unifiedDetails.message}")
        "PENDING" -> return mapOf("status" to "PENDING")  // await webhook before proceeding
    }

    // Step 2: Capture — settle the reserved funds
    val captureResponse = paymentClient.capture(buildCaptureRequest(authorizeResponse.connectorTransactionId ?: ""))

    if (captureResponse.status.name == "FAILED")
        throw RuntimeException("Capture failed: ${captureResponse.error.unifiedDetails.message}")

    return mapOf("status" to captureResponse.status.name, "transactionId" to authorizeResponse.connectorTransactionId, "error" to authorizeResponse.error)
}

// Scenario: Card Payment (Automatic Capture)
// Authorize and capture in one call using `capture_method=AUTOMATIC`. Use for digital goods or immediate fulfillment.
fun processCheckoutAutocapture(txnId: String, config: ConnectorConfig = _defaultConfig): Map<String, Any?> {
    val paymentClient = PaymentClient(config)

    // Step 1: Authorize — reserve funds on the payment method
    val authorizeResponse = paymentClient.authorize(buildAuthorizeRequest("AUTOMATIC"))

    when (authorizeResponse.status.name) {
        "FAILED"  -> throw RuntimeException("Payment failed: ${authorizeResponse.error.unifiedDetails.message}")
        "PENDING" -> return mapOf("status" to "PENDING")  // await webhook before proceeding
    }

    return mapOf("status" to authorizeResponse.status.name, "transactionId" to authorizeResponse.connectorTransactionId, "error" to authorizeResponse.error)
}

// Scenario: Wallet Payment (Google Pay / Apple Pay)
// Wallet payments pass an encrypted token from the browser/device SDK. Pass the token blob directly — do not decrypt client-side.
fun processCheckoutWallet(txnId: String, config: ConnectorConfig = _defaultConfig): Map<String, Any?> {
    val paymentClient = PaymentClient(config)

    // Step 1: Authorize — reserve funds on the payment method
    val authorizeResponse = paymentClient.authorize(PaymentServiceAuthorizeRequest.newBuilder().apply {
        merchantTransactionId = "probe_txn_001"  // Identification
        amountBuilder.apply {  // The amount for the payment
            minorAmount = 1000L  // Amount in minor units (e.g., 1000 = $10.00)
            currency = Currency.USD  // ISO 4217 currency code (e.g., "USD", "EUR")
        }
        paymentMethodBuilder.apply {  // Payment method to be used
            googlePayBuilder.apply {  // Google Pay
                type = "CARD"  // Type of payment method
                description = "Visa 1111"  // User-facing description of the payment method
                infoBuilder.apply {
                    cardNetwork = "VISA"  // Card network name
                    cardDetails = "1111"  // Card details (usually last 4 digits)
                }
                tokenizationDataBuilder.apply {
                    encryptedDataBuilder.apply {  // Encrypted Google Pay payment data
                        tokenType = "PAYMENT_GATEWAY"  // The type of the token
                        token = "{\"id\":\"tok_probe_gpay\",\"object\":\"token\",\"type\":\"card\"}"  // Token generated for the wallet
                    }
                }
            }
        }
        captureMethod = CaptureMethod.AUTOMATIC  // Method for capturing the payment
        addressBuilder.apply {  // Address Information
            billingAddressBuilder.apply {
            }
        }
        authType = AuthenticationType.NO_THREE_DS  // Authentication Details
        returnUrl = "https://example.com/return"  // URLs for Redirection and Webhooks
    }.build())

    when (authorizeResponse.status.name) {
        "FAILED"  -> throw RuntimeException("Payment failed: ${authorizeResponse.error.unifiedDetails.message}")
        "PENDING" -> return mapOf("status" to "PENDING")  // await webhook before proceeding
    }

    return mapOf("status" to authorizeResponse.status.name, "transactionId" to authorizeResponse.connectorTransactionId, "error" to authorizeResponse.error)
}

// Scenario: Bank Transfer (SEPA / ACH / BACS)
// Direct bank debit (Sepa). Bank transfers typically use `capture_method=AUTOMATIC`.
fun processCheckoutBank(txnId: String, config: ConnectorConfig = _defaultConfig): Map<String, Any?> {
    val paymentClient = PaymentClient(config)

    // Step 1: Authorize — reserve funds on the payment method
    val authorizeResponse = paymentClient.authorize(PaymentServiceAuthorizeRequest.newBuilder().apply {
        merchantTransactionId = "probe_txn_001"  // Identification
        amountBuilder.apply {  // The amount for the payment
            minorAmount = 1000L  // Amount in minor units (e.g., 1000 = $10.00)
            currency = Currency.EUR  // ISO 4217 currency code (e.g., "USD", "EUR")
        }
        paymentMethodBuilder.apply {  // Payment method to be used
            sepaBuilder.apply {  // Sepa - Single Euro Payments Area direct debit
                ibanBuilder.value = "DE89370400440532013000"  // International bank account number (iban) for SEPA
                bankAccountHolderNameBuilder.value = "John Doe"  // Owner name for bank debit
            }
        }
        captureMethod = CaptureMethod.AUTOMATIC  // Method for capturing the payment
        addressBuilder.apply {  // Address Information
            billingAddressBuilder.apply {
            }
        }
        authType = AuthenticationType.NO_THREE_DS  // Authentication Details
        returnUrl = "https://example.com/return"  // URLs for Redirection and Webhooks
    }.build())

    when (authorizeResponse.status.name) {
        "FAILED"  -> throw RuntimeException("Payment failed: ${authorizeResponse.error.unifiedDetails.message}")
        "PENDING" -> return mapOf("status" to "PENDING")  // await webhook before proceeding
    }

    return mapOf("status" to authorizeResponse.status.name, "transactionId" to authorizeResponse.connectorTransactionId, "error" to authorizeResponse.error)
}

// Scenario: Refund a Payment
// Authorize with automatic capture, then refund the captured amount. `connector_transaction_id` from the Authorize response is reused for the Refund call.
fun processRefund(txnId: String, config: ConnectorConfig = _defaultConfig): Map<String, Any?> {
    val paymentClient = PaymentClient(config)

    // Step 1: Authorize — reserve funds on the payment method
    val authorizeResponse = paymentClient.authorize(buildAuthorizeRequest("AUTOMATIC"))

    when (authorizeResponse.status.name) {
        "FAILED"  -> throw RuntimeException("Payment failed: ${authorizeResponse.error.unifiedDetails.message}")
        "PENDING" -> return mapOf("status" to "PENDING")  // await webhook before proceeding
    }

    // Step 2: Refund — return funds to the customer
    val refundResponse = paymentClient.refund(buildRefundRequest(authorizeResponse.connectorTransactionId ?: ""))

    if (refundResponse.status.name == "FAILED")
        throw RuntimeException("Refund failed: ${refundResponse.error.unifiedDetails.message}")

    return mapOf("status" to refundResponse.status.name, "error" to refundResponse.error)
}

// Scenario: Recurring / Mandate Payments
// Store a payment mandate with SetupRecurring, then charge it repeatedly with RecurringPaymentService.Charge without requiring customer action.
fun processRecurring(txnId: String, config: ConnectorConfig = _defaultConfig): Map<String, Any?> {
    val paymentClient = PaymentClient(config)
    val recurringPaymentClient = RecurringPaymentClient(config)

    // Step 1: Setup Recurring — store the payment mandate
    val setupResponse = paymentClient.setup_recurring(PaymentServiceSetupRecurringRequest.newBuilder().apply {
        merchantRecurringPaymentId = "probe_mandate_001"  // Identification
        amountBuilder.apply {  // Mandate Details
            minorAmount = 0L  // Amount in minor units (e.g., 1000 = $10.00)
            currency = Currency.USD  // ISO 4217 currency code (e.g., "USD", "EUR")
        }
        paymentMethodBuilder.apply {
            cardBuilder.apply {  // Generic card payment
                cardNumberBuilder.value = "4111111111111111"  // Card Identification
                cardExpMonthBuilder.value = "03"
                cardExpYearBuilder.value = "2030"
                cardCvcBuilder.value = "737"
                cardHolderNameBuilder.value = "John Doe"  // Cardholder Information
            }
        }
        addressBuilder.apply {  // Address Information
            billingAddressBuilder.apply {
            }
        }
        authType = AuthenticationType.NO_THREE_DS  // Type of authentication to be used
        enrolledFor3Ds = false  // Indicates if the customer is enrolled for 3D Secure
        returnUrl = "https://example.com/mandate-return"  // URL to redirect after setup
        setupFutureUsage = FutureUsage.OFF_SESSION  // Indicates future usage intention
        requestIncrementalAuthorization = false  // Indicates if incremental authorization is requested
        customerAcceptanceBuilder.apply {  // Details of customer acceptance
            acceptanceType = AcceptanceType.OFFLINE  // Type of acceptance (e.g., online, offline).
            acceptedAt = 0L  // Timestamp when the acceptance was made (Unix timestamp, seconds since epoch).
        }
    }.build())

    if (setupResponse.status.name == "FAILED")
        throw RuntimeException("Setup failed: ${setupResponse.error.unifiedDetails.message}")

    // Step 2: Recurring Charge — charge against the stored mandate
    val recurringResponse = recurringPaymentClient.charge(RecurringPaymentServiceChargeRequest.newBuilder().apply {
        amountBuilder.apply {  // Amount Information
            minorAmount = 1000L  // Amount in minor units (e.g., 1000 = $10.00)
            currency = Currency.USD  // ISO 4217 currency code (e.g., "USD", "EUR")
        }
        returnUrl = "https://example.com/recurring-return"
        connectorCustomerId = "cust_probe_123"
        offSession = true  // Behavioral Flags and Preferences
        connectorRecurringPaymentIdBuilder.apply {
            connectorMandateIdBuilder.apply {
                connectorMandateId = setupResponse.mandateReference.connectorMandateId.connectorMandateId  // from SetupRecurring
            }
        }
    }.build())

    if (recurringResponse.status.name == "FAILED")
        throw RuntimeException("Recurring Charge failed: ${recurringResponse.error.unifiedDetails.message}")

    return mapOf("status" to recurringResponse.status.name, "transactionId" to (recurringResponse.connectorTransactionId ?: ""), "error" to recurringResponse.error)
}

// Scenario: Void a Payment
// Authorize funds with a manual capture flag, then cancel the authorization with Void before any capture occurs. Releases the hold on the customer's funds.
fun processVoidPayment(txnId: String, config: ConnectorConfig = _defaultConfig): Map<String, Any?> {
    val paymentClient = PaymentClient(config)

    // Step 1: Authorize — reserve funds on the payment method
    val authorizeResponse = paymentClient.authorize(buildAuthorizeRequest("MANUAL"))

    when (authorizeResponse.status.name) {
        "FAILED"  -> throw RuntimeException("Payment failed: ${authorizeResponse.error.unifiedDetails.message}")
        "PENDING" -> return mapOf("status" to "PENDING")  // await webhook before proceeding
    }

    // Step 2: Void — release reserved funds (cancel authorization)
    val voidResponse = paymentClient.void(buildVoidRequest(authorizeResponse.connectorTransactionId ?: ""))

    return mapOf("status" to voidResponse.status.name, "transactionId" to authorizeResponse.connectorTransactionId, "error" to voidResponse.error)
}

// Scenario: Get Payment Status
// Authorize a payment, then poll the connector for its current status using Get. Use this to sync payment state when webhooks are unavailable or delayed.
fun processGetPayment(txnId: String, config: ConnectorConfig = _defaultConfig): Map<String, Any?> {
    val paymentClient = PaymentClient(config)

    // Step 1: Authorize — reserve funds on the payment method
    val authorizeResponse = paymentClient.authorize(buildAuthorizeRequest("MANUAL"))

    when (authorizeResponse.status.name) {
        "FAILED"  -> throw RuntimeException("Payment failed: ${authorizeResponse.error.unifiedDetails.message}")
        "PENDING" -> return mapOf("status" to "PENDING")  // await webhook before proceeding
    }

    // Step 2: Get — retrieve current payment status from the connector
    val getResponse = paymentClient.get(buildGetRequest(authorizeResponse.connectorTransactionId ?: ""))

    return mapOf("status" to getResponse.status.name, "transactionId" to getResponse.connectorTransactionId, "error" to getResponse.error)
}

// Scenario: Create Customer
// Register a customer record in the connector system. Returns a connector_customer_id that can be reused for recurring payments and tokenized card storage.
fun processCreateCustomer(txnId: String, config: ConnectorConfig = _defaultConfig): Map<String, Any?> {
    val customerClient = CustomerClient(config)

    // Step 1: Create Customer — register customer record in the connector
    val createResponse = customerClient.create(CustomerServiceCreateRequest.newBuilder().apply {
        merchantCustomerId = "cust_probe_123"  // Identification
        customerName = "John Doe"  // Name of the customer
        emailBuilder.value = "test@example.com"  // Email address of the customer
        phoneNumber = "4155552671"  // Phone number of the customer
    }.build())

    return mapOf("customerId" to createResponse.connectorCustomerId, "error" to createResponse.error)
}

// Scenario: Tokenize Payment Method
// Store card details in the connector's vault and receive a reusable payment token. Use the returned token for one-click payments and recurring billing without re-collecting card data.
fun processTokenize(txnId: String, config: ConnectorConfig = _defaultConfig): Map<String, Any?> {
    val paymentMethodClient = PaymentMethodClient(config)

    // Step 1: Tokenize — store card details and return a reusable token
    val tokenizeResponse = paymentMethodClient.tokenize(PaymentMethodServiceTokenizeRequest.newBuilder().apply {
        amountBuilder.apply {  // Payment Information
            minorAmount = 1000L  // Amount in minor units (e.g., 1000 = $10.00)
            currency = Currency.USD  // ISO 4217 currency code (e.g., "USD", "EUR")
        }
        paymentMethodBuilder.apply {
            cardBuilder.apply {  // Generic card payment
                cardNumberBuilder.value = "4111111111111111"  // Card Identification
                cardExpMonthBuilder.value = "03"
                cardExpYearBuilder.value = "2030"
                cardCvcBuilder.value = "737"
                cardHolderNameBuilder.value = "John Doe"  // Cardholder Information
            }
        }
        addressBuilder.apply {  // Address Information
            billingAddressBuilder.apply {
            }
        }
    }.build())

    return mapOf("token" to tokenizeResponse.paymentMethodToken, "error" to tokenizeResponse.error)
}

// Scenario: Tokenized Payment (Authorize + Capture)
// Authorize using a connector-issued payment method token (e.g. Stripe pm_xxx). Card data never touches your server — only the token is sent. Capture settles the reserved funds.
fun processTokenizedCheckout(txnId: String, config: ConnectorConfig = _defaultConfig): Map<String, Any?> {
    val tokenizedPaymentClient = TokenizedPaymentClient(config)
    val paymentClient = PaymentClient(config)

    // Step 1: Tokenized Authorize — reserve funds using a connector-issued payment method token
    val authorizeResponse = tokenizedPaymentClient.tokenized_authorize(TokenizedPaymentServiceAuthorizeRequest.newBuilder().apply {
        merchantTransactionId = "probe_tokenized_txn_001"
        amountBuilder.apply {
            minorAmount = 1000L  // Amount in minor units (e.g., 1000 = $10.00)
            currency = Currency.USD  // ISO 4217 currency code (e.g., "USD", "EUR")
        }
        connectorTokenBuilder.apply {
            value = "pm_1AbcXyzStripeTestToken"
        }
        captureMethod = CaptureMethod.AUTOMATIC
        addressBuilder.apply {
            billingAddressBuilder.apply {
            }
        }
        returnUrl = "https://example.com/return"
    }.build())

    // Step 2: Capture — settle the reserved funds
    val captureResponse = paymentClient.capture(PaymentServiceCaptureRequest.newBuilder().apply {
        merchantCaptureId = "probe_capture_001"  // Identification
        connectorTransactionId = "probe_connector_txn_001"
        amountToCaptureBuilder.apply {  // Capture Details
            minorAmount = 1000L  // Amount in minor units (e.g., 1000 = $10.00)
            currency = Currency.USD  // ISO 4217 currency code (e.g., "USD", "EUR")
        }
    }.build())

    if (captureResponse.status.name == "FAILED")
        throw RuntimeException("Capture failed: ${captureResponse.error.unifiedDetails.message}")

    return mapOf()
}

// Scenario: Tokenized Recurring Payments
// Store a payment mandate using a connector token with SetupRecurring, then charge it repeatedly with RecurringPaymentService without requiring customer action or re-collecting card data.
fun processTokenizedRecurring(txnId: String, config: ConnectorConfig = _defaultConfig): Map<String, Any?> {
    val tokenizedPaymentClient = TokenizedPaymentClient(config)
    val recurringPaymentClient = RecurringPaymentClient(config)

    // Step 1: Tokenized Setup Recurring — store a mandate using a connector token
    val setupResponse = tokenizedPaymentClient.tokenized_setup_recurring(TokenizedPaymentServiceSetupRecurringRequest.newBuilder().apply {
        merchantRecurringPaymentId = "probe_tokenized_mandate_001"
        amountBuilder.apply {
            minorAmount = 0L  // Amount in minor units (e.g., 1000 = $10.00)
            currency = Currency.USD  // ISO 4217 currency code (e.g., "USD", "EUR")
        }
        connectorTokenBuilder.apply {
            value = "pm_1AbcXyzStripeTestToken"
        }
        addressBuilder.apply {
            billingAddressBuilder.apply {
            }
        }
        customerAcceptanceBuilder.apply {
            acceptanceType = AcceptanceType.ONLINE  // Type of acceptance (e.g., online, offline).
            ipAddress = "127.0.0.1"
            userAgent = "Mozilla/5.0"
        }
    }.build())

    // Step 2: Recurring Charge — charge against the stored mandate
    val recurringResponse = recurringPaymentClient.charge(RecurringPaymentServiceChargeRequest.newBuilder().apply {
        connectorRecurringPaymentIdBuilder.apply {  // Reference to existing mandate
            connectorMandateId = "probe-mandate-123"  // mandate_id sent by the connector
        }
        amountBuilder.apply {  // Amount Information
            minorAmount = 1000L  // Amount in minor units (e.g., 1000 = $10.00)
            currency = Currency.USD  // ISO 4217 currency code (e.g., "USD", "EUR")
        }
        paymentMethodBuilder.apply {  // Optional payment Method Information (for network transaction flows)
            tokenBuilder.apply {  // Payment tokens
                tokenBuilder.value = "probe_pm_token"
            }
        }
        returnUrl = "https://example.com/recurring-return"
        connectorCustomerId = "cust_probe_123"
        paymentMethodType = PaymentMethodType.PAY_PAL
        offSession = true  // Behavioral Flags and Preferences
    }.build())

    if (recurringResponse.status.name == "FAILED")
        throw RuntimeException("Recurring Charge failed: ${recurringResponse.error.unifiedDetails.message}")

    return mapOf()
}

// Scenario: Proxy Payment via Vault (VGS / Basis Theory)
// Authorize using vault alias tokens. Configure an outbound proxy URL in RequestConfig — the proxy substitutes aliases with real card values before the request reaches the connector. Card data never touches your server.
fun processProxyCheckout(txnId: String, config: ConnectorConfig = _defaultConfig): Map<String, Any?> {
    val proxyPaymentClient = ProxyPaymentClient(config)

    // Step 1: Proxy Authorize — reserve funds using vault alias tokens routed through a proxy
    val authorizeResponse = proxyPaymentClient.proxy_authorize(ProxyPaymentServiceAuthorizeRequest.newBuilder().apply {
        merchantTransactionId = "probe_proxy_txn_001"
        amountBuilder.apply {
            minorAmount = 1000L  // Amount in minor units (e.g., 1000 = $10.00)
            currency = Currency.USD  // ISO 4217 currency code (e.g., "USD", "EUR")
        }
        vaultCardBuilder.apply {
            cardNumberAliasBuilder.apply {
                value = "tok_sandbox_abc123"
            }
            expMonth = "03"
            expYear = "2030"
            cvcAliasBuilder.apply {
                value = "tok_sandbox_cvc456"
            }
            cardHolderName = "John Doe"
        }
        captureMethod = CaptureMethod.AUTOMATIC
        authType = AuthenticationType.NO_THREE_DS
        addressBuilder.apply {
            billingAddressBuilder.apply {
            }
        }
        returnUrl = "https://example.com/return"
    }.build())

    return mapOf()
}

// Scenario: Proxy Payment with 3DS (VGS + Proxy 3DS)
// Full 3DS flow using vault alias tokens routed through an outbound proxy. The proxy substitutes aliases before forwarding to Netcetera (3DS server). Authorize after successful authentication using the same vault aliases.
fun processProxy3DsCheckout(txnId: String, config: ConnectorConfig = _defaultConfig): Map<String, Any?> {
    val proxyPaymentClient = ProxyPaymentClient(config)

    // Step 1: Proxy Pre-Authenticate — initiate 3DS using vault aliases (proxy substitutes before Netcetera)
    val preAuthenticateResponse = proxyPaymentClient.proxy_pre_authenticate(ProxyPaymentMethodAuthenticationServicePreAuthenticateRequest.newBuilder().apply {
        merchantOrderId = "probe_proxy_order_001"
        amountBuilder.apply {
            minorAmount = 1000L  // Amount in minor units (e.g., 1000 = $10.00)
            currency = Currency.USD  // ISO 4217 currency code (e.g., "USD", "EUR")
        }
        vaultCardBuilder.apply {
            cardNumberAliasBuilder.apply {
                value = "tok_sandbox_abc123"
            }
            expMonth = "03"
            expYear = "2030"
            cardHolderName = "John Doe"
        }
        browserInfoBuilder.apply {
            userAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
            acceptHeader = "application/json"  // Browser Headers
            language = "en-US"
            colorDepth = 24  // Display Information
            screenHeight = 1080
            screenWidth = 1920
            timeZoneOffset = -330L
            javaEnabled = false  // Browser Settings
            javaScriptEnabled = true
        }
        returnUrl = "https://example.com/3ds-return"
    }.build())

    // Step 2: Proxy Authenticate — execute 3DS challenge using vault aliases via proxy
    val authenticateResponse = proxyPaymentClient.proxy_authenticate(ProxyPaymentMethodAuthenticationServiceAuthenticateRequest.newBuilder().apply {
        merchantOrderId = "probe_proxy_order_001"
        amountBuilder.apply {
            minorAmount = 1000L  // Amount in minor units (e.g., 1000 = $10.00)
            currency = Currency.USD  // ISO 4217 currency code (e.g., "USD", "EUR")
        }
        vaultCardBuilder.apply {
            cardNumberAliasBuilder.apply {
                value = "tok_sandbox_abc123"
            }
            expMonth = "03"
            expYear = "2030"
            cardHolderName = "John Doe"
        }
        returnUrl = "https://example.com/3ds-return"
    }.build())

    // Step 3: Proxy Post-Authenticate — validate 3DS result using vault aliases via proxy
    val postAuthenticateResponse = proxyPaymentClient.proxy_post_authenticate(ProxyPaymentMethodAuthenticationServicePostAuthenticateRequest.newBuilder().apply {
        merchantOrderId = "probe_proxy_order_001"
        vaultCardBuilder.apply {
            cardNumberAliasBuilder.apply {
                value = "tok_sandbox_abc123"
            }
            expMonth = "03"
            expYear = "2030"
            cardHolderName = "John Doe"
        }
    }.build())

    // Step 4: Proxy Authorize — reserve funds using vault alias tokens routed through a proxy
    val authorizeResponse = proxyPaymentClient.proxy_authorize(ProxyPaymentServiceAuthorizeRequest.newBuilder().apply {
        merchantTransactionId = "probe_proxy_txn_001"
        amountBuilder.apply {
            minorAmount = 1000L  // Amount in minor units (e.g., 1000 = $10.00)
            currency = Currency.USD  // ISO 4217 currency code (e.g., "USD", "EUR")
        }
        vaultCardBuilder.apply {
            cardNumberAliasBuilder.apply {
                value = "tok_sandbox_abc123"
            }
            expMonth = "03"
            expYear = "2030"
            cvcAliasBuilder.apply {
                value = "tok_sandbox_cvc456"
            }
            cardHolderName = "John Doe"
        }
        captureMethod = CaptureMethod.AUTOMATIC
        authType = AuthenticationType.NO_THREE_DS
        addressBuilder.apply {
            billingAddressBuilder.apply {
            }
        }
        returnUrl = "https://example.com/return"
    }.build())

    return mapOf()
}

// Flow: PaymentService.Authorize (Card)
fun authorize(txnId: String) {
    val client = PaymentClient(_defaultConfig)
    val request = buildAuthorizeRequest("AUTOMATIC")
    val response = client.authorize(request)
    when (response.status.name) {
        "FAILED"  -> throw RuntimeException("Authorize failed: ${response.error.unifiedDetails.message}")
        "PENDING" -> println("Pending — await webhook before proceeding")
        else      -> println("Authorized: ${response.connectorTransactionId}")
    }
}

// Flow: PaymentService.Capture
fun capture(txnId: String) {
    val client = PaymentClient(_defaultConfig)
    val request = buildCaptureRequest("probe_connector_txn_001")
    val response = client.capture(request)
    if (response.status.name == "FAILED")
        throw RuntimeException("Capture failed: ${response.error.unifiedDetails.message}")
    println("Done: ${response.status.name}")
}

// Flow: CustomerService.Create
fun createCustomer(txnId: String) {
    val client = CustomerClient(_defaultConfig)
    val request = CustomerServiceCreateRequest.newBuilder().apply {
        merchantCustomerId = "cust_probe_123"  // Identification
        customerName = "John Doe"  // Name of the customer
        emailBuilder.value = "test@example.com"  // Email address of the customer
        phoneNumber = "4155552671"  // Phone number of the customer
    }.build()
    val response = client.create(request)
    println("Customer: ${response.connectorCustomerId}")
}

// Flow: PaymentService.Get
fun get(txnId: String) {
    val client = PaymentClient(_defaultConfig)
    val request = buildGetRequest("probe_connector_txn_001")
    val response = client.get(request)
    println("Status: ${response.status.name}")
}

// Flow: RecurringPaymentService.Charge
fun recurringCharge(txnId: String) {
    val client = RecurringPaymentClient(_defaultConfig)
    val request = RecurringPaymentServiceChargeRequest.newBuilder().apply {
        connectorRecurringPaymentIdBuilder.apply {  // Reference to existing mandate
            connectorMandateIdBuilder.apply {  // mandate_id sent by the connector
                connectorMandateId = "probe-mandate-123"
            }
        }
        amountBuilder.apply {  // Amount Information
            minorAmount = 1000L  // Amount in minor units (e.g., 1000 = $10.00)
            currency = Currency.USD  // ISO 4217 currency code (e.g., "USD", "EUR")
        }
        paymentMethodBuilder.apply {  // Optional payment Method Information (for network transaction flows)
            tokenBuilder.apply {  // Payment tokens
                tokenBuilder.value = "probe_pm_token"
            }
        }
        returnUrl = "https://example.com/recurring-return"
        connectorCustomerId = "cust_probe_123"
        paymentMethodType = PaymentMethodType.PAY_PAL
        offSession = true  // Behavioral Flags and Preferences
    }.build()
    val response = client.charge(request)
    if (response.status.name == "FAILED")
        throw RuntimeException("Recurring_Charge failed: ${response.error.unifiedDetails.message}")
    println("Done: ${response.status.name}")
}

// Flow: PaymentService.Refund
fun refund(txnId: String) {
    val client = PaymentClient(_defaultConfig)
    val request = buildRefundRequest("probe_connector_txn_001")
    val response = client.refund(request)
    if (response.status.name == "FAILED")
        throw RuntimeException("Refund failed: ${response.error.unifiedDetails.message}")
    println("Done: ${response.status.name}")
}

// Flow: PaymentService.SetupRecurring
fun setupRecurring(txnId: String) {
    val client = PaymentClient(_defaultConfig)
    val request = PaymentServiceSetupRecurringRequest.newBuilder().apply {
        merchantRecurringPaymentId = "probe_mandate_001"  // Identification
        amountBuilder.apply {  // Mandate Details
            minorAmount = 0L  // Amount in minor units (e.g., 1000 = $10.00)
            currency = Currency.USD  // ISO 4217 currency code (e.g., "USD", "EUR")
        }
        paymentMethodBuilder.apply {
            cardBuilder.apply {  // Generic card payment
                cardNumberBuilder.value = "4111111111111111"  // Card Identification
                cardExpMonthBuilder.value = "03"
                cardExpYearBuilder.value = "2030"
                cardCvcBuilder.value = "737"
                cardHolderNameBuilder.value = "John Doe"  // Cardholder Information
            }
        }
        addressBuilder.apply {  // Address Information
            billingAddressBuilder.apply {
            }
        }
        authType = AuthenticationType.NO_THREE_DS  // Type of authentication to be used
        enrolledFor3Ds = false  // Indicates if the customer is enrolled for 3D Secure
        returnUrl = "https://example.com/mandate-return"  // URL to redirect after setup
        setupFutureUsage = FutureUsage.OFF_SESSION  // Indicates future usage intention
        requestIncrementalAuthorization = false  // Indicates if incremental authorization is requested
        customerAcceptanceBuilder.apply {  // Details of customer acceptance
            acceptanceType = AcceptanceType.OFFLINE  // Type of acceptance (e.g., online, offline).
            acceptedAt = 0L  // Timestamp when the acceptance was made (Unix timestamp, seconds since epoch).
        }
    }.build()
    val response = client.setup_recurring(request)
    when (response.status.name) {
        "FAILED" -> throw RuntimeException("Setup failed: ${response.error.unifiedDetails.message}")
        else     -> println("Mandate stored: ${response.connectorRecurringPaymentId}")
    }
}

// Flow: PaymentMethodService.Tokenize
fun tokenize(txnId: String) {
    val client = PaymentMethodClient(_defaultConfig)
    val request = PaymentMethodServiceTokenizeRequest.newBuilder().apply {
        amountBuilder.apply {  // Payment Information
            minorAmount = 1000L  // Amount in minor units (e.g., 1000 = $10.00)
            currency = Currency.USD  // ISO 4217 currency code (e.g., "USD", "EUR")
        }
        paymentMethodBuilder.apply {
            cardBuilder.apply {  // Generic card payment
                cardNumberBuilder.value = "4111111111111111"  // Card Identification
                cardExpMonthBuilder.value = "03"
                cardExpYearBuilder.value = "2030"
                cardCvcBuilder.value = "737"
                cardHolderNameBuilder.value = "John Doe"  // Cardholder Information
            }
        }
        addressBuilder.apply {  // Address Information
            billingAddressBuilder.apply {
            }
        }
    }.build()
    val response = client.tokenize(request)
    println("Token: ${response.paymentMethodToken}")
}

// Flow: PaymentService.Void
fun void(txnId: String) {
    val client = PaymentClient(_defaultConfig)
    val request = buildVoidRequest("probe_connector_txn_001")
    val response = client.void(request)
    if (response.status.name == "FAILED")
        throw RuntimeException("Void failed: ${response.error.unifiedDetails.message}")
    println("Done: ${response.status.name}")
}

// Flow: TokenizedPaymentService.Authorize
fun tokenizedAuthorize(txnId: String) {
    val client = TokenizedPaymentClient(_defaultConfig)
    val request = TokenizedPaymentServiceAuthorizeRequest.newBuilder().apply {
        merchantTransactionId = "probe_tokenized_txn_001"
        amountBuilder.apply {
            minorAmount = 1000L  // Amount in minor units (e.g., 1000 = $10.00)
            currency = Currency.USD  // ISO 4217 currency code (e.g., "USD", "EUR")
        }
        connectorTokenBuilder.apply {
            value = "pm_1AbcXyzStripeTestToken"
        }
        captureMethod = CaptureMethod.AUTOMATIC
        addressBuilder.apply {
            billingAddressBuilder.apply {
            }
        }
        returnUrl = "https://example.com/return"
    }.build()
    val response = client.tokenized_authorize(request)
    println("Status: ${response.status.name}")
}

// Flow: TokenizedPaymentService.SetupRecurring
fun tokenizedSetupRecurring(txnId: String) {
    val client = TokenizedPaymentClient(_defaultConfig)
    val request = TokenizedPaymentServiceSetupRecurringRequest.newBuilder().apply {
        merchantRecurringPaymentId = "probe_tokenized_mandate_001"
        amountBuilder.apply {
            minorAmount = 0L  // Amount in minor units (e.g., 1000 = $10.00)
            currency = Currency.USD  // ISO 4217 currency code (e.g., "USD", "EUR")
        }
        connectorTokenBuilder.apply {
            value = "pm_1AbcXyzStripeTestToken"
        }
        addressBuilder.apply {
            billingAddressBuilder.apply {
            }
        }
        customerAcceptanceBuilder.apply {
            acceptanceType = AcceptanceType.ONLINE  // Type of acceptance (e.g., online, offline).
            ipAddress = "127.0.0.1"
            userAgent = "Mozilla/5.0"
        }
    }.build()
    val response = client.tokenized_setup_recurring(request)
    println("Status: ${response.status.name}")
}

// Flow: ProxyPaymentService.Authorize
fun proxyAuthorize(txnId: String) {
    val client = ProxyPaymentClient(_defaultConfig)
    val request = ProxyPaymentServiceAuthorizeRequest.newBuilder().apply {
        merchantTransactionId = "probe_proxy_txn_001"
        amountBuilder.apply {
            minorAmount = 1000L  // Amount in minor units (e.g., 1000 = $10.00)
            currency = Currency.USD  // ISO 4217 currency code (e.g., "USD", "EUR")
        }
        vaultCardBuilder.apply {
            cardNumberAliasBuilder.apply {
                value = "tok_sandbox_abc123"
            }
            expMonth = "03"
            expYear = "2030"
            cvcAliasBuilder.apply {
                value = "tok_sandbox_cvc456"
            }
            cardHolderName = "John Doe"
        }
        captureMethod = CaptureMethod.AUTOMATIC
        authType = AuthenticationType.NO_THREE_DS
        addressBuilder.apply {
            billingAddressBuilder.apply {
            }
        }
        returnUrl = "https://example.com/return"
    }.build()
    val response = client.proxy_authorize(request)
    println("Status: ${response.status.name}")
}

// Flow: ProxyPaymentService.SetupRecurring
fun proxySetupRecurring(txnId: String) {
    val client = ProxyPaymentClient(_defaultConfig)
    val request = ProxyPaymentServiceSetupRecurringRequest.newBuilder().apply {
        merchantRecurringPaymentId = "probe_proxy_mandate_001"
        amountBuilder.apply {
            minorAmount = 0L  // Amount in minor units (e.g., 1000 = $10.00)
            currency = Currency.USD  // ISO 4217 currency code (e.g., "USD", "EUR")
        }
        vaultCardBuilder.apply {
            cardNumberAliasBuilder.apply {
                value = "tok_sandbox_abc123"
            }
            expMonth = "03"
            expYear = "2030"
            cvcAliasBuilder.apply {
                value = "tok_sandbox_cvc456"
            }
            cardHolderName = "John Doe"
        }
        authType = AuthenticationType.NO_THREE_DS
        addressBuilder.apply {
            billingAddressBuilder.apply {
            }
        }
    }.build()
    val response = client.proxy_setup_recurring(request)
    println("Status: ${response.status.name}")
}

// Flow: ProxyPaymentService.PreAuthenticate
fun proxyPreAuthenticate(txnId: String) {
    val client = ProxyPaymentClient(_defaultConfig)
    val request = ProxyPaymentMethodAuthenticationServicePreAuthenticateRequest.newBuilder().apply {
        merchantOrderId = "probe_proxy_order_001"
        amountBuilder.apply {
            minorAmount = 1000L  // Amount in minor units (e.g., 1000 = $10.00)
            currency = Currency.USD  // ISO 4217 currency code (e.g., "USD", "EUR")
        }
        vaultCardBuilder.apply {
            cardNumberAliasBuilder.apply {
                value = "tok_sandbox_abc123"
            }
            expMonth = "03"
            expYear = "2030"
            cardHolderName = "John Doe"
        }
        browserInfoBuilder.apply {
            userAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
            acceptHeader = "application/json"  // Browser Headers
            language = "en-US"
            colorDepth = 24  // Display Information
            screenHeight = 1080
            screenWidth = 1920
            timeZoneOffset = -330L
            javaEnabled = false  // Browser Settings
            javaScriptEnabled = true
        }
        returnUrl = "https://example.com/3ds-return"
    }.build()
    val response = client.proxy_pre_authenticate(request)
    println("Status: ${response.status.name}")
}

// Flow: ProxyPaymentService.Authenticate
fun proxyAuthenticate(txnId: String) {
    val client = ProxyPaymentClient(_defaultConfig)
    val request = ProxyPaymentMethodAuthenticationServiceAuthenticateRequest.newBuilder().apply {
        merchantOrderId = "probe_proxy_order_001"
        amountBuilder.apply {
            minorAmount = 1000L  // Amount in minor units (e.g., 1000 = $10.00)
            currency = Currency.USD  // ISO 4217 currency code (e.g., "USD", "EUR")
        }
        vaultCardBuilder.apply {
            cardNumberAliasBuilder.apply {
                value = "tok_sandbox_abc123"
            }
            expMonth = "03"
            expYear = "2030"
            cardHolderName = "John Doe"
        }
        returnUrl = "https://example.com/3ds-return"
    }.build()
    val response = client.proxy_authenticate(request)
    println("Status: ${response.status.name}")
}

// Flow: ProxyPaymentService.PostAuthenticate
fun proxyPostAuthenticate(txnId: String) {
    val client = ProxyPaymentClient(_defaultConfig)
    val request = ProxyPaymentMethodAuthenticationServicePostAuthenticateRequest.newBuilder().apply {
        merchantOrderId = "probe_proxy_order_001"
        vaultCardBuilder.apply {
            cardNumberAliasBuilder.apply {
                value = "tok_sandbox_abc123"
            }
            expMonth = "03"
            expYear = "2030"
            cardHolderName = "John Doe"
        }
    }.build()
    val response = client.proxy_post_authenticate(request)
    println("Status: ${response.status.name}")
}


fun main(args: Array<String>) {
    val txnId = "order_001"
    val flow = args.firstOrNull() ?: "processCheckoutCard"
    when (flow) {
        "processCheckoutCard" -> processCheckoutCard(txnId)
        "processCheckoutAutocapture" -> processCheckoutAutocapture(txnId)
        "processCheckoutWallet" -> processCheckoutWallet(txnId)
        "processCheckoutBank" -> processCheckoutBank(txnId)
        "processRefund" -> processRefund(txnId)
        "processRecurring" -> processRecurring(txnId)
        "processVoidPayment" -> processVoidPayment(txnId)
        "processGetPayment" -> processGetPayment(txnId)
        "processCreateCustomer" -> processCreateCustomer(txnId)
        "processTokenize" -> processTokenize(txnId)
        "processTokenizedCheckout" -> processTokenizedCheckout(txnId)
        "processTokenizedRecurring" -> processTokenizedRecurring(txnId)
        "processProxyCheckout" -> processProxyCheckout(txnId)
        "processProxy3DsCheckout" -> processProxy3DsCheckout(txnId)
        "authorize" -> authorize(txnId)
        "capture" -> capture(txnId)
        "createCustomer" -> createCustomer(txnId)
        "get" -> get(txnId)
        "recurringCharge" -> recurringCharge(txnId)
        "refund" -> refund(txnId)
        "setupRecurring" -> setupRecurring(txnId)
        "tokenize" -> tokenize(txnId)
        "void" -> void(txnId)
        "tokenizedAuthorize" -> tokenizedAuthorize(txnId)
        "tokenizedSetupRecurring" -> tokenizedSetupRecurring(txnId)
        "proxyAuthorize" -> proxyAuthorize(txnId)
        "proxySetupRecurring" -> proxySetupRecurring(txnId)
        "proxyPreAuthenticate" -> proxyPreAuthenticate(txnId)
        "proxyAuthenticate" -> proxyAuthenticate(txnId)
        "proxyPostAuthenticate" -> proxyPostAuthenticate(txnId)
        else -> System.err.println("Unknown flow: $flow. Available: processCheckoutCard, processCheckoutAutocapture, processCheckoutWallet, processCheckoutBank, processRefund, processRecurring, processVoidPayment, processGetPayment, processCreateCustomer, processTokenize, processTokenizedCheckout, processTokenizedRecurring, processProxyCheckout, processProxy3DsCheckout, authorize, capture, createCustomer, get, recurringCharge, refund, setupRecurring, tokenize, void, tokenizedAuthorize, tokenizedSetupRecurring, proxyAuthorize, proxySetupRecurring, proxyPreAuthenticate, proxyAuthenticate, proxyPostAuthenticate")
    }
}
