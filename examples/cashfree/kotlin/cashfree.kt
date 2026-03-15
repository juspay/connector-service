// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py cashfree
//
// Cashfree — all scenarios and flows in one file.
// Run a scenario:  ./gradlew run --args="cashfree processCheckoutCard"

package examples.cashfree

import payments.PaymentClient
import payments.PaymentServiceAuthorizeRequest
import payments.AuthenticationType
import payments.CaptureMethod
import payments.CountryAlpha2
import payments.Currency
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
            upiCollectBuilder.apply {  // UPI Collect
                vpaIdBuilder.value = "test@upi"  // Virtual Payment Address
            }
        }
        captureMethod = CaptureMethod.valueOf(captureMethodStr)  // Method for capturing the payment
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
        merchantOrderId = "probe_session_id"
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
}

val _defaultConfig: ConnectorConfig = ConnectorConfig.newBuilder()
    .setOptions(SdkOptions.newBuilder().setEnvironment(Environment.SANDBOX).build())
    // .setConnectorConfig(...) — set your connector config here
    .build()


// Flow: PaymentService.Authorize (UpiCollect)
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


fun main(args: Array<String>) {
    val txnId = "order_001"
    val flow = args.firstOrNull() ?: "authorize"
    when (flow) {
        "authorize" -> authorize(txnId)
        else -> System.err.println("Unknown flow: $flow. Available: authorize")
    }
}
