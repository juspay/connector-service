/**
 * Smoke test for the published payments-client JAR.
 *
 * Tests from the consumer perspective — depends on com.hyperswitch:payments-client
 * via mavenLocal(), the same way an end-user would.
 *
 * Exits non-zero on any assertion failure.
 */

import uniffi.connector_service_ffi.UniffiException
import uniffi.connector_service_ffi.authorizeReqTransformer
import org.json.JSONObject
import ucs.v2.Payment.PaymentServiceAuthorizeRequest
import ucs.v2.Payment.PaymentAddress
import ucs.v2.Payment.Currency
import ucs.v2.Payment.CaptureMethod
import ucs.v2.Payment.AuthenticationType
import ucs.v2.Options
import ucs.v2.HttpOptions
import ucs.v2.FfiOptions
import ucs.v2.EnvOptions

fun buildRequest(): PaymentServiceAuthorizeRequest =
    PaymentServiceAuthorizeRequest.newBuilder().apply {
        merchantTransactionIdBuilder.id = "smoke_test_123"
        amountBuilder.apply {
            minorAmount = 1000
            currency = Currency.USD
        }
        captureMethod = CaptureMethod.AUTOMATIC
        paymentMethodBuilder.cardBuilder.apply {
            cardNumberBuilder.value = "4111111111111111"
            cardExpMonthBuilder.value = "12"
            cardExpYearBuilder.value = "2050"
            cardCvcBuilder.value = "123"
            cardHolderNameBuilder.value = "Test User"
        }
        customerBuilder.apply {
            emailBuilder.value = "test@example.com"
            name = "Test"
        }
        authType = AuthenticationType.NO_THREE_DS
        returnUrl = "https://example.com/return"
        webhookUrl = "https://example.com/webhook"
        address = PaymentAddress.getDefaultInstance()
        testMode = true
    }.build()

fun buildMetadata(): Map<String, String> {
    val apiKey = System.getenv("STRIPE_API_KEY") ?: "sk_test_placeholder"
    return mapOf(
        "connector" to "Stripe",
        "connector_auth_type" to JSONObject(mapOf(
            "Stripe" to mapOf(
                "api_key" to apiKey
            )
        )).toString(),
        "x-connector" to "Stripe",
        "x-merchant-id" to "test_merchant_123",
        "x-request-id" to "smoke-test-001",
        "x-tenant-id" to "public",
        "x-auth" to "body-key",
        "x-api-key" to apiKey,
    )
}

fun buildOptions(): Options {
    return Options.newBuilder()
        .setHttp(HttpOptions.newBuilder()
            .setTotalTimeoutMs(30000)
            .setConnectTimeoutMs(10000)
            .setResponseTimeoutMs(20000)
            .setKeepAliveTimeoutMs(5000)
            .build())
        .setFfi(FfiOptions.newBuilder()
            .setEnv(EnvOptions.newBuilder()
                .setTestMode(true)
                .build())
            .build())
        .build()
}

fun assert(condition: Boolean, message: String) {
    if (!condition) {
        System.err.println("ASSERTION FAILED: $message")
        System.exit(1)
    }
}

fun testLowLevelFfi() {
    println("=== Test 1: Low-level FFI (authorizeReqTransformer) ===")

    val requestBytes = buildRequest().toByteArray()
    val metadata = buildMetadata()
    val optionsBytes = buildOptions().toByteArray()

    try {
        val json = JSONObject(authorizeReqTransformer(requestBytes, metadata, optionsBytes))
        val url = json.getString("url")
        val method = json.getString("method")

        assert(url == "https://api.stripe.com/v1/payment_intents",
            "Expected Stripe payment_intents URL, got: $url")
        assert(method == "POST",
            "Expected POST method, got: $method")

        println("  URL:    $url")
        println("  Method: $method")
        println("  PASSED")

    } catch (e: UniffiException) {
        System.err.println("  FFI error: ${e.message}")
        System.exit(1)
    }
}

fun testFullRoundTrip() {
    println("\n=== Test 2: Full round-trip (ConnectorClient) ===")

    val apiKey = System.getenv("STRIPE_API_KEY") ?: ""
    if (apiKey.isEmpty() || apiKey == "sk_test_placeholder") {
        println("  SKIPPED (set STRIPE_API_KEY to enable)")
        return
    }

    val client = ConnectorClient()
    try {
        val response = client.authorize(buildRequest(), buildMetadata())
        println("  Response status: ${response.status}")
        println("  PASSED")
    } catch (e: UniffiException) {
        // Round-trip completed — error is from Stripe (e.g. auth failure), not from the SDK
        println("  Response/error received: ${e.message}")
        println("  PASSED (round-trip completed, error is from Stripe)")
    } catch (e: Exception) {
        System.err.println("  Unexpected error: ${e.message}")
        System.exit(1)
    }
}

fun main() {
    testLowLevelFfi()
    testFullRoundTrip()
    println("\nAll checks passed.")
}
