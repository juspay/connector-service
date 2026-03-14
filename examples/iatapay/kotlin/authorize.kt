// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py iatapay
//
// Flow: PaymentService.Authorize (Ideal)
//
// SDK: sdk/java (Kotlin/JVM — uses UniFFI protobuf builder pattern)
// Build: ./gradlew compileKotlin  (from sdk/java/)

import payments.PaymentClient
import payments.ConnectorConfig
import payments.Connector
import payments.Environment

fun main() {
    val config = ConnectorConfig.newBuilder()
        .setConnector(Connector.IATAPAY)
        .setEnvironment(Environment.SANDBOX)
        // .setAuth(...) — set your connector auth here
        .build()

    val client = PaymentClient(config)

    val request = PaymentServiceAuthorizeRequest.newBuilder().apply {
        merchantTransactionIdBuilder.value = "probe_txn_001"  // Identification
        amountBuilder.apply {  // The amount for the payment
            minorAmount = 1000L  // Amount in minor units (e.g., 1000 = $10.00)
            currencyBuilder.value = "USD"  // ISO 4217 currency code (e.g., "USD", "EUR")
        }
        paymentMethodBuilder.apply {  // Payment method to be used
            idealBuilder.apply {
            }
        }
        captureMethodBuilder.value = "AUTOMATIC"  // Method for capturing the payment
        customerBuilder.apply {  // Customer Information
            nameBuilder.value = "John Doe"  // Customer's full name
            emailBuilder.value = "test@example.com"  // Customer's email address
            idBuilder.value = "cust_probe_123"  // Internal customer ID
            phoneNumberBuilder.value = "4155552671"  // Customer's phone number
            phoneCountryCodeBuilder.value = "+1"  // Customer's phone country code
        }
        addressBuilder.apply {  // Address Information
            shippingAddressBuilder.apply {
                firstNameBuilder.value = "John"  // Personal Information
                lastNameBuilder.value = "Doe"
                line1Builder.value = "123 Main St"  // Address Details
                cityBuilder.value = "Seattle"
                stateBuilder.value = "WA"
                zipCodeBuilder.value = "98101"
                countryAlpha2CodeBuilder.value = "US"
                emailBuilder.value = "test@example.com"  // Contact Information
                phoneNumberBuilder.value = "4155552671"
                phoneCountryCodeBuilder.value = "+1"
            }
            billingAddressBuilder.apply {
                firstNameBuilder.value = "John"  // Personal Information
                lastNameBuilder.value = "Doe"
                line1Builder.value = "123 Main St"  // Address Details
                cityBuilder.value = "Seattle"
                stateBuilder.value = "WA"
                zipCodeBuilder.value = "98101"
                countryAlpha2CodeBuilder.value = "US"
                emailBuilder.value = "test@example.com"  // Contact Information
                phoneNumberBuilder.value = "4155552671"
                phoneCountryCodeBuilder.value = "+1"
            }
        }
        authTypeBuilder.value = "NO_THREE_DS"  // Authentication Details
        returnUrlBuilder.value = "https://example.com/return"  // URLs for Redirection and Webhooks
        webhookUrlBuilder.value = "https://example.com/webhook"
        completeAuthorizeUrlBuilder.value = "https://example.com/complete"
        browserInfoBuilder.apply {
            colorDepth = 24L  // Display Information
            screenHeight = 900L
            screenWidth = 1440L
            javaEnabled = false  // Browser Settings
            javaScriptEnabled = true
            languageBuilder.value = "en-US"
            timeZoneOffsetMinutes = -480L
            acceptHeaderBuilder.value = "application/json"  // Browser Headers
            userAgentBuilder.value = "Mozilla/5.0 (probe-bot)"
            acceptLanguageBuilder.value = "en-US,en;q=0.9"
            ipAddressBuilder.value = "1.2.3.4"  // Device Information
        }
        stateBuilder.apply {  // State Information
            accessTokenBuilder.apply {  // Access token obtained from connector
                tokenBuilder.value = "probe_access_token"  // The token string.
                expiresInSeconds = 3600L  // Expiration timestamp (seconds since epoch)
                tokenTypeBuilder.value = "Bearer"  // Token type (e.g., "Bearer", "Basic").
            }
        }
    }.build()

    val response = client.authorize(request)
    when (response.status.name) {
        "FAILED"  -> throw RuntimeException("Authorize failed: ${response.error.message}")
        "PENDING" -> println("Pending — await webhook before proceeding")
        else      -> println("Authorized: ${response.connectorTransactionId}")
    }
}
