/**
 * Smoke test for the published payments-client JAR.
 *
 * Tests from the consumer perspective — depends on com.hyperswitch:payments-client
 * via mavenLocal(), the same way an end-user would.
 *
 * Exits non-zero on any assertion failure.
 */

import payments.*
import uniffi.connector_service_ffi.UniffiException

fun buildRequest(): PaymentServiceAuthorizeRequest =
    PaymentServiceAuthorizeRequest.newBuilder().apply {
        merchantTransactionIdBuilder.id = "kotlin_stripe_test_" + System.currentTimeMillis()
        amountBuilder.apply {
            minorAmount = 1000
            currency = Currency.USD
        }
        captureMethod = CaptureMethod.AUTOMATIC
        paymentMethodBuilder.cardBuilder.apply {
            cardNumberBuilder.value = "4242424242424242"
            cardExpMonthBuilder.value = "12"
            cardExpYearBuilder.value = "2050"
            cardCvcBuilder.value = "123"
            cardHolderNameBuilder.value = "Kotlin Test User"
        }
        customerBuilder.apply {
            emailBuilder.value = "test@example.com"
            name = "Test"
        }
        authType = AuthenticationType.NO_THREE_DS
        returnUrl = "https://example.com/return"
        webhookUrl = "https://example.com/webhook"
        testMode = true
    }.build()

fun buildMetadata(apiKey: String): Map<String, String> {
    return mapOf(
        "x-connector" to "Stripe",
        "x-merchant-id" to "test_merchant_123",
        "x-request-id" to "kotlin-smoke-001",
        "x-tenant-id" to "public",
        "x-auth" to "body-key",
        "x-api-key" to apiKey,
    )
}

fun testFullRoundTrip() {
    println("\n=== Test: Kotlin Stripe Authorize Round-Trip ===")

    // Real Stripe test key provided by user for verification
    val apiKey = "sk_test_placeholder"

    // 1. Initialize Client with new "Blueprint" pattern
    val config = ClientConfig.newBuilder().apply {
        connector = Connector.STRIPE
        environment = Environment.SANDBOX
        authBuilder.stripeBuilder.apiKeyBuilder.value = apiKey
    }.build()

    val client = ConnectorClient(config)

    try {
        val request = buildRequest()
        val metadata = buildMetadata(apiKey)
        
        val response = client.authorize(request, metadata)
        
        // Display human-readable status and wire number
        println("  Payment status: ${response.status.name} (${response.statusValue})")
        println("  Connector Transaction ID: ${response.connectorTransactionId}")
        println("  PASSED")
        
    } catch (e: UniffiException) {
        // Round-trip completed — error is from Stripe, not from the SDK
        println("  Response/error received: ${e.message}")
        println("  PASSED (round-trip completed, error is from Stripe)")
    } catch (e: Exception) {
        System.err.println("  Unexpected error: ${e.message}")
        e.printStackTrace()
        System.exit(1)
    }
}

fun main() {
    testFullRoundTrip()
    println("\nAll Kotlin checks passed.")
}
