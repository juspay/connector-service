// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py jpmorgan
//
// Jpmorgan — all scenarios and flows in one file.
// Run a scenario:  ./gradlew run --args="jpmorgan processCheckoutCard"

package examples.jpmorgan

import payments.PaymentClient
import payments.MerchantAuthenticationClient
import payments.PaymentServiceAuthorizeRequest
import payments.PaymentServiceCaptureRequest
import payments.PaymentServiceRefundRequest
import payments.PaymentServiceVoidRequest
import payments.PaymentServiceGetRequest
import payments.MerchantAuthenticationServiceCreateAccessTokenRequest
import payments.AuthenticationType
import payments.CaptureMethod
import payments.CountryAlpha2
import payments.Currency
import payments.ConnectorConfig
import payments.Connector
import payments.Environment

val _defaultConfig: ConnectorConfig = ConnectorConfig.newBuilder()
    .setConnector(Connector.JPMORGAN)
    .setEnvironment(Environment.SANDBOX)
    // .setAuth(...) — set your connector auth here
    .build()


// Scenario: Card Payment (Authorize + Capture)
// Reserve funds with Authorize, then settle with a separate Capture call. Use for physical goods or delayed fulfillment where capture happens later.
fun processCheckoutCard(txnId: String, config: ConnectorConfig = _defaultConfig): Map<String, Any?> {
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
        stateBuilder.apply {  // State Information
            accessTokenBuilder.apply {  // Access token obtained from connector
                tokenBuilder.value = "probe_access_token"  // The token string.
                expiresInSeconds = 3600L  // Expiration timestamp (seconds since epoch)
                tokenType = "Bearer"  // Token type (e.g., "Bearer", "Basic").
            }
        }
    }.build())

    when (authorizeResponse.status.name) {
        "FAILED"  -> throw RuntimeException("Payment failed: ${authorizeResponse.error.unifiedDetails.message}")
        "PENDING" -> return mapOf("status" to "PENDING")  // await webhook before proceeding
    }

    // Step 2: Capture — settle the reserved funds
    val captureResponse = paymentClient.capture(PaymentServiceCaptureRequest.newBuilder().apply {
        merchantCaptureId = "probe_capture_001"  // Identification
        amountToCaptureBuilder.apply {  // Capture Details
            minorAmount = 1000L  // Amount in minor units (e.g., 1000 = $10.00)
            currency = Currency.USD  // ISO 4217 currency code (e.g., "USD", "EUR")
        }
        stateBuilder.apply {  // State Information
            accessTokenBuilder.apply {  // Access token obtained from connector
                tokenBuilder.value = "probe_access_token"  // The token string.
                expiresInSeconds = 3600L  // Expiration timestamp (seconds since epoch)
                tokenType = "Bearer"  // Token type (e.g., "Bearer", "Basic").
            }
        }
        connectorTransactionId = authorizeResponse.connectorTransactionId  // from Authorize
    }.build())

    if (captureResponse.status.name == "FAILED")
        throw RuntimeException("Capture failed: ${captureResponse.error.unifiedDetails.message}")

    return mapOf("status" to captureResponse.status.name, "transactionId" to authorizeResponse.connectorTransactionId)
}

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
        stateBuilder.apply {  // State Information
            accessTokenBuilder.apply {  // Access token obtained from connector
                tokenBuilder.value = "probe_access_token"  // The token string.
                expiresInSeconds = 3600L  // Expiration timestamp (seconds since epoch)
                tokenType = "Bearer"  // Token type (e.g., "Bearer", "Basic").
            }
        }
    }.build())

    when (authorizeResponse.status.name) {
        "FAILED"  -> throw RuntimeException("Payment failed: ${authorizeResponse.error.unifiedDetails.message}")
        "PENDING" -> return mapOf("status" to "PENDING")  // await webhook before proceeding
    }

    return mapOf("status" to authorizeResponse.status.name, "transactionId" to authorizeResponse.connectorTransactionId)
}

// Scenario: Bank Transfer (SEPA / ACH / BACS)
// Direct bank debit (Ach). Bank transfers typically use `capture_method=AUTOMATIC`.
fun processCheckoutBank(txnId: String, config: ConnectorConfig = _defaultConfig): Map<String, Any?> {
    val paymentClient = PaymentClient(config)

    // Step 1: Authorize — reserve funds on the payment method
    val authorizeResponse = paymentClient.authorize(PaymentServiceAuthorizeRequest.newBuilder().apply {
        merchantTransactionId = "probe_txn_001"  // Identification
        amountBuilder.apply {  // The amount for the payment
            minorAmount = 1000L  // Amount in minor units (e.g., 1000 = $10.00)
            currency = Currency.USD  // ISO 4217 currency code (e.g., "USD", "EUR")
        }
        paymentMethodBuilder.apply {  // Payment method to be used
            achBuilder.apply {  // Ach - Automated Clearing House
                accountNumberBuilder.value = "000123456789"  // Account number for ach bank debit payment
                routingNumberBuilder.value = "110000000"  // Routing number for ach bank debit payment
                bankAccountHolderNameBuilder.value = "John Doe"  // Bank account holder name
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
        stateBuilder.apply {  // State Information
            accessTokenBuilder.apply {  // Access token obtained from connector
                tokenBuilder.value = "probe_access_token"  // The token string.
                expiresInSeconds = 3600L  // Expiration timestamp (seconds since epoch)
                tokenType = "Bearer"  // Token type (e.g., "Bearer", "Basic").
            }
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
        stateBuilder.apply {  // State Information
            accessTokenBuilder.apply {  // Access token obtained from connector
                tokenBuilder.value = "probe_access_token"  // The token string.
                expiresInSeconds = 3600L  // Expiration timestamp (seconds since epoch)
                tokenType = "Bearer"  // Token type (e.g., "Bearer", "Basic").
            }
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
        stateBuilder.apply {  // State data for access token storage and other connector-specific state
            accessTokenBuilder.apply {  // Access token obtained from connector
                tokenBuilder.value = "probe_access_token"  // The token string.
                expiresInSeconds = 3600L  // Expiration timestamp (seconds since epoch)
                tokenType = "Bearer"  // Token type (e.g., "Bearer", "Basic").
            }
        }
        connectorTransactionId = authorizeResponse.connectorTransactionId  // from Authorize
    }.build())

    if (refundResponse.status.name == "FAILED")
        throw RuntimeException("Refund failed: ${refundResponse.error.unifiedDetails.message}")

    return mapOf("status" to refundResponse.status.name)
}

// Scenario: Void a Payment
// Authorize funds with a manual capture flag, then cancel the authorization with Void before any capture occurs. Releases the hold on the customer's funds.
fun processVoidPayment(txnId: String, config: ConnectorConfig = _defaultConfig): Map<String, Any?> {
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
        stateBuilder.apply {  // State Information
            accessTokenBuilder.apply {  // Access token obtained from connector
                tokenBuilder.value = "probe_access_token"  // The token string.
                expiresInSeconds = 3600L  // Expiration timestamp (seconds since epoch)
                tokenType = "Bearer"  // Token type (e.g., "Bearer", "Basic").
            }
        }
    }.build())

    when (authorizeResponse.status.name) {
        "FAILED"  -> throw RuntimeException("Payment failed: ${authorizeResponse.error.unifiedDetails.message}")
        "PENDING" -> return mapOf("status" to "PENDING")  // await webhook before proceeding
    }

    // Step 2: Void — release reserved funds (cancel authorization)
    val voidResponse = paymentClient.void(PaymentServiceVoidRequest.newBuilder().apply {
        merchantVoidId = "probe_void_001"  // Identification
        stateBuilder.apply {  // State Information
            accessTokenBuilder.apply {  // Access token obtained from connector
                tokenBuilder.value = "probe_access_token"  // The token string.
                expiresInSeconds = 3600L  // Expiration timestamp (seconds since epoch)
                tokenType = "Bearer"  // Token type (e.g., "Bearer", "Basic").
            }
        }
        connectorTransactionId = authorizeResponse.connectorTransactionId  // from Authorize
    }.build())

    return mapOf("status" to voidResponse.status.name, "transactionId" to authorizeResponse.connectorTransactionId)
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
        stateBuilder.apply {  // State Information
            accessTokenBuilder.apply {  // Access token obtained from connector
                tokenBuilder.value = "probe_access_token"  // The token string.
                expiresInSeconds = 3600L  // Expiration timestamp (seconds since epoch)
                tokenType = "Bearer"  // Token type (e.g., "Bearer", "Basic").
            }
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
        stateBuilder.apply {  // State Information
            accessTokenBuilder.apply {  // Access token obtained from connector
                tokenBuilder.value = "probe_access_token"  // The token string.
                expiresInSeconds = 3600L  // Expiration timestamp (seconds since epoch)
                tokenType = "Bearer"  // Token type (e.g., "Bearer", "Basic").
            }
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
        stateBuilder.apply {  // State Information
            accessTokenBuilder.apply {  // Access token obtained from connector
                tokenBuilder.value = "probe_access_token"  // The token string.
                expiresInSeconds = 3600L  // Expiration timestamp (seconds since epoch)
                tokenType = "Bearer"  // Token type (e.g., "Bearer", "Basic").
            }
        }
    }.build()
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
    val request = PaymentServiceCaptureRequest.newBuilder().apply {
        merchantCaptureId = "probe_capture_001"  // Identification
        connectorTransactionId = "probe_connector_txn_001"
        amountToCaptureBuilder.apply {  // Capture Details
            minorAmount = 1000L  // Amount in minor units (e.g., 1000 = $10.00)
            currency = Currency.USD  // ISO 4217 currency code (e.g., "USD", "EUR")
        }
        stateBuilder.apply {  // State Information
            accessTokenBuilder.apply {  // Access token obtained from connector
                tokenBuilder.value = "probe_access_token"  // The token string.
                expiresInSeconds = 3600L  // Expiration timestamp (seconds since epoch)
                tokenType = "Bearer"  // Token type (e.g., "Bearer", "Basic").
            }
        }
    }.build()
    val response = client.capture(request)
    if (response.status.name == "FAILED")
        throw RuntimeException("Capture failed: ${response.error.unifiedDetails.message}")
    println("Done: ${response.status.name}")
}

// Flow: MerchantAuthenticationService.CreateAccessToken
fun create_access_token(txnId: String) {
    val client = MerchantAuthenticationClient(_defaultConfig)
    val request = MerchantAuthenticationServiceCreateAccessTokenRequest.newBuilder().apply {

    }.build()
    val response = client.create_access_token(request)
    println("Access token obtained (statusCode=${response.statusCode})")
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
        stateBuilder.apply {  // State Information
            accessTokenBuilder.apply {  // Access token obtained from connector
                tokenBuilder.value = "probe_access_token"  // The token string.
                expiresInSeconds = 3600L  // Expiration timestamp (seconds since epoch)
                tokenType = "Bearer"  // Token type (e.g., "Bearer", "Basic").
            }
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
        stateBuilder.apply {  // State data for access token storage and other connector-specific state
            accessTokenBuilder.apply {  // Access token obtained from connector
                tokenBuilder.value = "probe_access_token"  // The token string.
                expiresInSeconds = 3600L  // Expiration timestamp (seconds since epoch)
                tokenType = "Bearer"  // Token type (e.g., "Bearer", "Basic").
            }
        }
    }.build()
    val response = client.refund(request)
    if (response.status.name == "FAILED")
        throw RuntimeException("Refund failed: ${response.error.unifiedDetails.message}")
    println("Done: ${response.status.name}")
}

// Flow: PaymentService.Void
fun void(txnId: String) {
    val client = PaymentClient(_defaultConfig)
    val request = PaymentServiceVoidRequest.newBuilder().apply {
        merchantVoidId = "probe_void_001"  // Identification
        connectorTransactionId = "probe_connector_txn_001"
        stateBuilder.apply {  // State Information
            accessTokenBuilder.apply {  // Access token obtained from connector
                tokenBuilder.value = "probe_access_token"  // The token string.
                expiresInSeconds = 3600L  // Expiration timestamp (seconds since epoch)
                tokenType = "Bearer"  // Token type (e.g., "Bearer", "Basic").
            }
        }
    }.build()
    val response = client.void(request)
    if (response.status.name == "FAILED")
        throw RuntimeException("Void failed: ${response.error.unifiedDetails.message}")
    println("Done: ${response.status.name}")
}


fun main(args: Array<String>) {
    val txnId = "order_001"
    val flow = args.firstOrNull() ?: "processCheckoutCard"
    when (flow) {
        "processCheckoutCard" -> processCheckoutCard(txnId)
        "processCheckoutAutocapture" -> processCheckoutAutocapture(txnId)
        "processCheckoutBank" -> processCheckoutBank(txnId)
        "processRefund" -> processRefund(txnId)
        "processVoidPayment" -> processVoidPayment(txnId)
        "processGetPayment" -> processGetPayment(txnId)
        "authorize" -> authorize(txnId)
        "capture" -> capture(txnId)
        "create_access_token" -> create_access_token(txnId)
        "get" -> get(txnId)
        "refund" -> refund(txnId)
        "void" -> void(txnId)
        else -> System.err.println("Unknown flow: $flow. Available: processCheckoutCard, processCheckoutAutocapture, processCheckoutBank, processRefund, processVoidPayment, processGetPayment, authorize, capture, create_access_token, get, refund, void")
    }
}
