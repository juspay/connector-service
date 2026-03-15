// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py razorpayv2
//
// Razorpayv2 — all scenarios and flows in one file.
// Run a scenario:  ./gradlew run --args="razorpayv2 processCheckoutCard"

package examples.razorpayv2

import payments.PaymentClient
import payments.PaymentServiceAuthorizeRequest
import payments.PaymentServiceRefundRequest
import payments.PaymentServiceGetRequest
import payments.PaymentServiceCreateOrderRequest
import payments.AuthenticationType
import payments.CaptureMethod
import payments.CountryAlpha2
import payments.Currency
import payments.ConnectorConfig
import payments.Connector
import payments.Environment

val _defaultConfig: ConnectorConfig = ConnectorConfig.newBuilder()
    .setConnector(Connector.RAZORPAY)
    .setEnvironment(Environment.SANDBOX)
    // .setAuth(...) — set your connector auth here
    .build()


// Scenario: Card Payment (Automatic Capture)
// Authorize and capture in one call using `capture_method=AUTOMATIC`. Use for digital goods or immediate fulfillment.
fun processCheckoutAutocapture(txnId: String, config: ConnectorConfig = _defaultConfig): Map<String, Any?> {
    val paymentClient = PaymentClient(config)

    // Step 1: Authorize — reserve funds on the payment method
    val authorizeResponse = paymentClient.authorize(PaymentServiceAuthorizeRequest.newBuilder().apply {
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
        captureMethod = CaptureMethod.AUTOMATIC  // Method for capturing the payment
        customerBuilder.apply {  // Customer Information
            name = "John Doe"  // Customer's full name
            emailBuilder.value = "test@example.com"  // Customer's email address
            id = "cust_probe_123"  // Internal customer ID
            phoneNumber = "4155552671"  // Customer's phone number
            phoneCountryCode = "+1"  // Customer's phone country code
        }
        addressBuilder.apply {  // Address Information
            shippingAddressBuilder.apply {
                firstNameBuilder.value = "John"  // Personal Information
                lastNameBuilder.value = "Doe"
                line1Builder.value = "123 Main St"  // Address Details
                cityBuilder.value = "Seattle"
                stateBuilder.value = "WA"
                zipCodeBuilder.value = "98101"
                countryAlpha2Code = CountryAlpha2.US
                emailBuilder.value = "test@example.com"  // Contact Information
                phoneNumberBuilder.value = "4155552671"
                phoneCountryCode = "+1"
            }
            billingAddressBuilder.apply {
                firstNameBuilder.value = "John"  // Personal Information
                lastNameBuilder.value = "Doe"
                line1Builder.value = "123 Main St"  // Address Details
                cityBuilder.value = "Seattle"
                stateBuilder.value = "WA"
                zipCodeBuilder.value = "98101"
                countryAlpha2Code = CountryAlpha2.US
                emailBuilder.value = "test@example.com"  // Contact Information
                phoneNumberBuilder.value = "4155552671"
                phoneCountryCode = "+1"
            }
        }
        authType = AuthenticationType.NO_THREE_DS  // Authentication Details
        returnUrl = "https://example.com/return"  // URLs for Redirection and Webhooks
        webhookUrl = "https://example.com/webhook"
        completeAuthorizeUrl = "https://example.com/complete"
        merchantOrderId = "probe_order_001"
        browserInfoBuilder.apply {
            colorDepth = 24  // Display Information
            screenHeight = 900
            screenWidth = 1440
            javaEnabled = false  // Browser Settings
            javaScriptEnabled = true
            language = "en-US"
            timeZoneOffsetMinutes = -480
            acceptHeader = "application/json"  // Browser Headers
            userAgent = "Mozilla/5.0 (probe-bot)"
            acceptLanguage = "en-US,en;q=0.9"
            ipAddress = "1.2.3.4"  // Device Information
        }
    }.build())

    when (authorizeResponse.status.name) {
        "FAILED"  -> throw RuntimeException("Payment failed: ${authorizeResponse.error.unifiedDetails.message}")
        "PENDING" -> return mapOf("status" to "PENDING")  // await webhook before proceeding
    }

    return mapOf("status" to authorizeResponse.status.name, "transactionId" to authorizeResponse.connectorTransactionId)
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
                        token = "{\"version\":\"ECv2\",\"signature\":\"<sig>\",\"intermediateSigningKey\":{\"signedKey\":\"<signed_key>\",\"signatures\":[\"<sig>\"]},\"signedMessage\":\"<signed_message>\"}"  // Token generated for the wallet
                        tokenType = "PAYMENT_GATEWAY"  // The type of the token
                    }
                }
            }
        }
        captureMethod = CaptureMethod.AUTOMATIC  // Method for capturing the payment
        customerBuilder.apply {  // Customer Information
            name = "John Doe"  // Customer's full name
            emailBuilder.value = "test@example.com"  // Customer's email address
            id = "cust_probe_123"  // Internal customer ID
            phoneNumber = "4155552671"  // Customer's phone number
            phoneCountryCode = "+1"  // Customer's phone country code
        }
        addressBuilder.apply {  // Address Information
            shippingAddressBuilder.apply {
                firstNameBuilder.value = "John"  // Personal Information
                lastNameBuilder.value = "Doe"
                line1Builder.value = "123 Main St"  // Address Details
                cityBuilder.value = "Seattle"
                stateBuilder.value = "WA"
                zipCodeBuilder.value = "98101"
                countryAlpha2Code = CountryAlpha2.US
                emailBuilder.value = "test@example.com"  // Contact Information
                phoneNumberBuilder.value = "4155552671"
                phoneCountryCode = "+1"
            }
            billingAddressBuilder.apply {
                firstNameBuilder.value = "John"  // Personal Information
                lastNameBuilder.value = "Doe"
                line1Builder.value = "123 Main St"  // Address Details
                cityBuilder.value = "Seattle"
                stateBuilder.value = "WA"
                zipCodeBuilder.value = "98101"
                countryAlpha2Code = CountryAlpha2.US
                emailBuilder.value = "test@example.com"  // Contact Information
                phoneNumberBuilder.value = "4155552671"
                phoneCountryCode = "+1"
            }
        }
        authType = AuthenticationType.NO_THREE_DS  // Authentication Details
        returnUrl = "https://example.com/return"  // URLs for Redirection and Webhooks
        webhookUrl = "https://example.com/webhook"
        completeAuthorizeUrl = "https://example.com/complete"
        merchantOrderId = "probe_order_001"
        browserInfoBuilder.apply {
            colorDepth = 24  // Display Information
            screenHeight = 900
            screenWidth = 1440
            javaEnabled = false  // Browser Settings
            javaScriptEnabled = true
            language = "en-US"
            timeZoneOffsetMinutes = -480
            acceptHeader = "application/json"  // Browser Headers
            userAgent = "Mozilla/5.0 (probe-bot)"
            acceptLanguage = "en-US,en;q=0.9"
            ipAddress = "1.2.3.4"  // Device Information
        }
    }.build())

    when (authorizeResponse.status.name) {
        "FAILED"  -> throw RuntimeException("Payment failed: ${authorizeResponse.error.unifiedDetails.message}")
        "PENDING" -> return mapOf("status" to "PENDING")  // await webhook before proceeding
    }

    return mapOf("status" to authorizeResponse.status.name, "transactionId" to authorizeResponse.connectorTransactionId)
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
        customerBuilder.apply {  // Customer Information
            name = "John Doe"  // Customer's full name
            emailBuilder.value = "test@example.com"  // Customer's email address
            id = "cust_probe_123"  // Internal customer ID
            phoneNumber = "4155552671"  // Customer's phone number
            phoneCountryCode = "+1"  // Customer's phone country code
        }
        addressBuilder.apply {  // Address Information
            shippingAddressBuilder.apply {
                firstNameBuilder.value = "John"  // Personal Information
                lastNameBuilder.value = "Doe"
                line1Builder.value = "123 Main St"  // Address Details
                cityBuilder.value = "Seattle"
                stateBuilder.value = "WA"
                zipCodeBuilder.value = "98101"
                countryAlpha2Code = CountryAlpha2.US
                emailBuilder.value = "test@example.com"  // Contact Information
                phoneNumberBuilder.value = "4155552671"
                phoneCountryCode = "+1"
            }
            billingAddressBuilder.apply {
                firstNameBuilder.value = "John"  // Personal Information
                lastNameBuilder.value = "Doe"
                line1Builder.value = "123 Main St"  // Address Details
                cityBuilder.value = "Seattle"
                stateBuilder.value = "WA"
                zipCodeBuilder.value = "98101"
                countryAlpha2Code = CountryAlpha2.US
                emailBuilder.value = "test@example.com"  // Contact Information
                phoneNumberBuilder.value = "4155552671"
                phoneCountryCode = "+1"
            }
        }
        authType = AuthenticationType.NO_THREE_DS  // Authentication Details
        returnUrl = "https://example.com/return"  // URLs for Redirection and Webhooks
        webhookUrl = "https://example.com/webhook"
        completeAuthorizeUrl = "https://example.com/complete"
        merchantOrderId = "probe_order_001"
        browserInfoBuilder.apply {
            colorDepth = 24  // Display Information
            screenHeight = 900
            screenWidth = 1440
            javaEnabled = false  // Browser Settings
            javaScriptEnabled = true
            language = "en-US"
            timeZoneOffsetMinutes = -480
            acceptHeader = "application/json"  // Browser Headers
            userAgent = "Mozilla/5.0 (probe-bot)"
            acceptLanguage = "en-US,en;q=0.9"
            ipAddress = "1.2.3.4"  // Device Information
        }
    }.build())

    when (authorizeResponse.status.name) {
        "FAILED"  -> throw RuntimeException("Payment failed: ${authorizeResponse.error.unifiedDetails.message}")
        "PENDING" -> return mapOf("status" to "PENDING")  // await webhook before proceeding
    }

    return mapOf("status" to authorizeResponse.status.name, "transactionId" to authorizeResponse.connectorTransactionId)
}

// Scenario: Refund a Payment
// Authorize with automatic capture, then refund the captured amount. `connector_transaction_id` from the Authorize response is reused for the Refund call.
fun processRefund(txnId: String, config: ConnectorConfig = _defaultConfig): Map<String, Any?> {
    val paymentClient = PaymentClient(config)

    // Step 1: Authorize — reserve funds on the payment method
    val authorizeResponse = paymentClient.authorize(PaymentServiceAuthorizeRequest.newBuilder().apply {
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
        captureMethod = CaptureMethod.AUTOMATIC  // Method for capturing the payment
        customerBuilder.apply {  // Customer Information
            name = "John Doe"  // Customer's full name
            emailBuilder.value = "test@example.com"  // Customer's email address
            id = "cust_probe_123"  // Internal customer ID
            phoneNumber = "4155552671"  // Customer's phone number
            phoneCountryCode = "+1"  // Customer's phone country code
        }
        addressBuilder.apply {  // Address Information
            shippingAddressBuilder.apply {
                firstNameBuilder.value = "John"  // Personal Information
                lastNameBuilder.value = "Doe"
                line1Builder.value = "123 Main St"  // Address Details
                cityBuilder.value = "Seattle"
                stateBuilder.value = "WA"
                zipCodeBuilder.value = "98101"
                countryAlpha2Code = CountryAlpha2.US
                emailBuilder.value = "test@example.com"  // Contact Information
                phoneNumberBuilder.value = "4155552671"
                phoneCountryCode = "+1"
            }
            billingAddressBuilder.apply {
                firstNameBuilder.value = "John"  // Personal Information
                lastNameBuilder.value = "Doe"
                line1Builder.value = "123 Main St"  // Address Details
                cityBuilder.value = "Seattle"
                stateBuilder.value = "WA"
                zipCodeBuilder.value = "98101"
                countryAlpha2Code = CountryAlpha2.US
                emailBuilder.value = "test@example.com"  // Contact Information
                phoneNumberBuilder.value = "4155552671"
                phoneCountryCode = "+1"
            }
        }
        authType = AuthenticationType.NO_THREE_DS  // Authentication Details
        returnUrl = "https://example.com/return"  // URLs for Redirection and Webhooks
        webhookUrl = "https://example.com/webhook"
        completeAuthorizeUrl = "https://example.com/complete"
        merchantOrderId = "probe_order_001"
        browserInfoBuilder.apply {
            colorDepth = 24  // Display Information
            screenHeight = 900
            screenWidth = 1440
            javaEnabled = false  // Browser Settings
            javaScriptEnabled = true
            language = "en-US"
            timeZoneOffsetMinutes = -480
            acceptHeader = "application/json"  // Browser Headers
            userAgent = "Mozilla/5.0 (probe-bot)"
            acceptLanguage = "en-US,en;q=0.9"
            ipAddress = "1.2.3.4"  // Device Information
        }
    }.build())

    when (authorizeResponse.status.name) {
        "FAILED"  -> throw RuntimeException("Payment failed: ${authorizeResponse.error.unifiedDetails.message}")
        "PENDING" -> return mapOf("status" to "PENDING")  // await webhook before proceeding
    }

    // Step 2: Refund — return funds to the customer
    val refundResponse = paymentClient.refund(PaymentServiceRefundRequest.newBuilder().apply {
        merchantRefundId = "probe_refund_001"  // Identification
        paymentAmount = 1000L  // Amount Information
        refundAmountBuilder.apply {
            minorAmount = 1000L  // Amount in minor units (e.g., 1000 = $10.00)
            currency = Currency.USD  // ISO 4217 currency code (e.g., "USD", "EUR")
        }
        reason = "customer_request"  // Reason for the refund
        connectorTransactionId = authorizeResponse.connectorTransactionId  // from Authorize
    }.build())

    if (refundResponse.status.name == "FAILED")
        throw RuntimeException("Refund failed: ${refundResponse.error.unifiedDetails.message}")

    return mapOf("status" to refundResponse.status.name)
}

// Scenario: Get Payment Status
// Authorize a payment, then poll the connector for its current status using Get. Use this to sync payment state when webhooks are unavailable or delayed.
fun processGetPayment(txnId: String, config: ConnectorConfig = _defaultConfig): Map<String, Any?> {
    val paymentClient = PaymentClient(config)

    // Step 1: Authorize — reserve funds on the payment method
    val authorizeResponse = paymentClient.authorize(PaymentServiceAuthorizeRequest.newBuilder().apply {
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
        captureMethod = CaptureMethod.MANUAL  // Method for capturing the payment
        customerBuilder.apply {  // Customer Information
            name = "John Doe"  // Customer's full name
            emailBuilder.value = "test@example.com"  // Customer's email address
            id = "cust_probe_123"  // Internal customer ID
            phoneNumber = "4155552671"  // Customer's phone number
            phoneCountryCode = "+1"  // Customer's phone country code
        }
        addressBuilder.apply {  // Address Information
            shippingAddressBuilder.apply {
                firstNameBuilder.value = "John"  // Personal Information
                lastNameBuilder.value = "Doe"
                line1Builder.value = "123 Main St"  // Address Details
                cityBuilder.value = "Seattle"
                stateBuilder.value = "WA"
                zipCodeBuilder.value = "98101"
                countryAlpha2Code = CountryAlpha2.US
                emailBuilder.value = "test@example.com"  // Contact Information
                phoneNumberBuilder.value = "4155552671"
                phoneCountryCode = "+1"
            }
            billingAddressBuilder.apply {
                firstNameBuilder.value = "John"  // Personal Information
                lastNameBuilder.value = "Doe"
                line1Builder.value = "123 Main St"  // Address Details
                cityBuilder.value = "Seattle"
                stateBuilder.value = "WA"
                zipCodeBuilder.value = "98101"
                countryAlpha2Code = CountryAlpha2.US
                emailBuilder.value = "test@example.com"  // Contact Information
                phoneNumberBuilder.value = "4155552671"
                phoneCountryCode = "+1"
            }
        }
        authType = AuthenticationType.NO_THREE_DS  // Authentication Details
        returnUrl = "https://example.com/return"  // URLs for Redirection and Webhooks
        webhookUrl = "https://example.com/webhook"
        completeAuthorizeUrl = "https://example.com/complete"
        merchantOrderId = "probe_order_001"
        browserInfoBuilder.apply {
            colorDepth = 24  // Display Information
            screenHeight = 900
            screenWidth = 1440
            javaEnabled = false  // Browser Settings
            javaScriptEnabled = true
            language = "en-US"
            timeZoneOffsetMinutes = -480
            acceptHeader = "application/json"  // Browser Headers
            userAgent = "Mozilla/5.0 (probe-bot)"
            acceptLanguage = "en-US,en;q=0.9"
            ipAddress = "1.2.3.4"  // Device Information
        }
    }.build())

    when (authorizeResponse.status.name) {
        "FAILED"  -> throw RuntimeException("Payment failed: ${authorizeResponse.error.unifiedDetails.message}")
        "PENDING" -> return mapOf("status" to "PENDING")  // await webhook before proceeding
    }

    // Step 2: Get — retrieve current payment status from the connector
    val getResponse = paymentClient.get(PaymentServiceGetRequest.newBuilder().apply {
        amountBuilder.apply {  // Amount Information
            minorAmount = 1000L  // Amount in minor units (e.g., 1000 = $10.00)
            currency = Currency.USD  // ISO 4217 currency code (e.g., "USD", "EUR")
        }
        connectorTransactionId = authorizeResponse.connectorTransactionId  // from Authorize
    }.build())

    return mapOf("status" to getResponse.status.name, "transactionId" to getResponse.connectorTransactionId)
}

// Flow: PaymentService.Authorize (Card)
fun authorize(txnId: String) {
    val client = PaymentClient(_defaultConfig)
    val request = PaymentServiceAuthorizeRequest.newBuilder().apply {
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
        captureMethod = CaptureMethod.AUTOMATIC  // Method for capturing the payment
        customerBuilder.apply {  // Customer Information
            name = "John Doe"  // Customer's full name
            emailBuilder.value = "test@example.com"  // Customer's email address
            id = "cust_probe_123"  // Internal customer ID
            phoneNumber = "4155552671"  // Customer's phone number
            phoneCountryCode = "+1"  // Customer's phone country code
        }
        addressBuilder.apply {  // Address Information
            shippingAddressBuilder.apply {
                firstNameBuilder.value = "John"  // Personal Information
                lastNameBuilder.value = "Doe"
                line1Builder.value = "123 Main St"  // Address Details
                cityBuilder.value = "Seattle"
                stateBuilder.value = "WA"
                zipCodeBuilder.value = "98101"
                countryAlpha2Code = CountryAlpha2.US
                emailBuilder.value = "test@example.com"  // Contact Information
                phoneNumberBuilder.value = "4155552671"
                phoneCountryCode = "+1"
            }
            billingAddressBuilder.apply {
                firstNameBuilder.value = "John"  // Personal Information
                lastNameBuilder.value = "Doe"
                line1Builder.value = "123 Main St"  // Address Details
                cityBuilder.value = "Seattle"
                stateBuilder.value = "WA"
                zipCodeBuilder.value = "98101"
                countryAlpha2Code = CountryAlpha2.US
                emailBuilder.value = "test@example.com"  // Contact Information
                phoneNumberBuilder.value = "4155552671"
                phoneCountryCode = "+1"
            }
        }
        authType = AuthenticationType.NO_THREE_DS  // Authentication Details
        returnUrl = "https://example.com/return"  // URLs for Redirection and Webhooks
        webhookUrl = "https://example.com/webhook"
        completeAuthorizeUrl = "https://example.com/complete"
        merchantOrderId = "probe_order_001"
        browserInfoBuilder.apply {
            colorDepth = 24  // Display Information
            screenHeight = 900
            screenWidth = 1440
            javaEnabled = false  // Browser Settings
            javaScriptEnabled = true
            language = "en-US"
            timeZoneOffsetMinutes = -480
            acceptHeader = "application/json"  // Browser Headers
            userAgent = "Mozilla/5.0 (probe-bot)"
            acceptLanguage = "en-US,en;q=0.9"
            ipAddress = "1.2.3.4"  // Device Information
        }
    }.build()
    val response = client.authorize(request)
    when (response.status.name) {
        "FAILED"  -> throw RuntimeException("Authorize failed: ${response.error.unifiedDetails.message}")
        "PENDING" -> println("Pending — await webhook before proceeding")
        else      -> println("Authorized: ${response.connectorTransactionId}")
    }
}

// Flow: PaymentService.CreateOrder
fun create_order(txnId: String) {
    val client = PaymentClient(_defaultConfig)
    val request = PaymentServiceCreateOrderRequest.newBuilder().apply {
        merchantOrderId = "probe_order_001"  // Identification
        amountBuilder.apply {  // Amount Information
            minorAmount = 1000L  // Amount in minor units (e.g., 1000 = $10.00)
            currency = Currency.USD  // ISO 4217 currency code (e.g., "USD", "EUR")
        }
    }.build()
    val response = client.create_order(request)
    println("Order: ${response.connectorOrderId}")
}

// Flow: PaymentService.Get
fun get(txnId: String) {
    val client = PaymentClient(_defaultConfig)
    val request = PaymentServiceGetRequest.newBuilder().apply {
        connectorTransactionId = "probe_connector_txn_001"
        amountBuilder.apply {  // Amount Information
            minorAmount = 1000L  // Amount in minor units (e.g., 1000 = $10.00)
            currency = Currency.USD  // ISO 4217 currency code (e.g., "USD", "EUR")
        }
    }.build()
    val response = client.get(request)
    println("Status: ${response.status.name}")
}

// Flow: PaymentService.Refund
fun refund(txnId: String) {
    val client = PaymentClient(_defaultConfig)
    val request = PaymentServiceRefundRequest.newBuilder().apply {
        merchantRefundId = "probe_refund_001"  // Identification
        connectorTransactionId = "probe_connector_txn_001"
        paymentAmount = 1000L  // Amount Information
        refundAmountBuilder.apply {
            minorAmount = 1000L  // Amount in minor units (e.g., 1000 = $10.00)
            currency = Currency.USD  // ISO 4217 currency code (e.g., "USD", "EUR")
        }
        reason = "customer_request"  // Reason for the refund
    }.build()
    val response = client.refund(request)
    if (response.status.name == "FAILED")
        throw RuntimeException("Refund failed: ${response.error.unifiedDetails.message}")
    println("Done: ${response.status.name}")
}


fun main(args: Array<String>) {
    val txnId = "order_001"
    val flow = args.firstOrNull() ?: "processCheckoutAutocapture"
    when (flow) {
        "processCheckoutAutocapture" -> processCheckoutAutocapture(txnId)
        "processCheckoutWallet" -> processCheckoutWallet(txnId)
        "processCheckoutBank" -> processCheckoutBank(txnId)
        "processRefund" -> processRefund(txnId)
        "processGetPayment" -> processGetPayment(txnId)
        "authorize" -> authorize(txnId)
        "create_order" -> create_order(txnId)
        "get" -> get(txnId)
        "refund" -> refund(txnId)
        else -> System.err.println("Unknown flow: $flow. Available: processCheckoutAutocapture, processCheckoutWallet, processCheckoutBank, processRefund, processGetPayment, authorize, create_order, get, refund")
    }
}
