// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py wellsfargo
//
// Flow: PaymentService.SetupRecurring
//
// SDK: sdk/java (Kotlin/JVM — uses UniFFI protobuf builder pattern)
// Build: ./gradlew compileKotlin  (from sdk/java/)

import payments.PaymentClient
import payments.ConnectorConfig
import payments.Connector
import payments.Environment

fun main() {
    val config = ConnectorConfig.newBuilder()
        .setConnector(Connector.WELLSFARGO)
        .setEnvironment(Environment.SANDBOX)
        // .setAuth(...) — set your connector auth here
        .build()

    val client = PaymentClient(config)

    val request = PaymentServiceSetupRecurringRequest.newBuilder().apply {
        merchantRecurringPaymentIdBuilder.value = "probe_mandate_001"  // Identification
        amountBuilder.apply {  // Mandate Details
            minorAmount = 0L  // Amount in minor units (e.g., 1000 = $10.00)
            currencyBuilder.value = "USD"  // ISO 4217 currency code (e.g., "USD", "EUR")
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
        customerBuilder.apply {
            nameBuilder.value = "John Doe"  // Customer's full name
            emailBuilder.value = "test@example.com"  // Customer's email address
            idBuilder.value = "cust_probe_123"  // Internal customer ID
            phoneNumberBuilder.value = "4155552671"  // Customer's phone number
            phoneCountryCodeBuilder.value = "+1"  // Customer's phone country code
        }
        addressBuilder.apply {  // Address Information
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
        authTypeBuilder.value = "NO_THREE_DS"  // Type of authentication to be used
        enrolledFor3Ds = false  // Indicates if the customer is enrolled for 3D Secure
        returnUrlBuilder.value = "https://example.com/mandate-return"  // URL to redirect after setup
        setupFutureUsageBuilder.value = "OFF_SESSION"  // Indicates future usage intention
        requestIncrementalAuthorization = false  // Indicates if incremental authorization is requested
        customerAcceptanceBuilder.apply {  // Details of customer acceptance
            acceptanceTypeBuilder.value = "OFFLINE"  // Type of acceptance (e.g., online, offline).
            acceptedAt = 0L  // Timestamp when the acceptance was made (Unix timestamp, seconds since epoch).
        }
        browserInfoBuilder.apply {  // Information about the customer's browser
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
    }.build()

    val response = client.setupRecurring(request)
    when (response.status.name) {
        "FAILED" -> throw RuntimeException("Setup failed: ${response.error.message}")
        else     -> println("Mandate stored: ${response.connectorTransactionId}")
    }
}
