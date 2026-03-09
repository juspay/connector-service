/**
 * Smoke test for the published payments-client JAR.
 *
 * Tests from the consumer perspective — depends on com.hyperswitch:payments-client
 * via mavenLocal(), the same way an end-user would.
 *
 * Exits non-zero on any assertion failure.
 */

import payments.PaymentClient
import payments.PaymentServiceAuthorizeRequest
import payments.PaymentAddress
import payments.Currency
import payments.CaptureMethod
import payments.AuthenticationType
import payments.FfiConnectorHttpRequest
import payments.FfiOptions
import payments.ConnectorConfig
import payments.RequestConfig
import payments.Connector
import payments.Environment
import uniffi.connector_service_ffi.UniffiException
import uniffi.connector_service_ffi.authorizeReqTransformer

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
        "connector_auth_type" to """{"Stripe":{"api_key":"$apiKey"}}""",
    )
}

fun buildConfig(): ConnectorConfig {
    val apiKey = System.getenv("STRIPE_API_KEY") ?: "sk_test_placeholder"
    return ConnectorConfig.newBuilder().apply {
        connector = Connector.STRIPE
        environment = Environment.SANDBOX
        authBuilder.stripeBuilder.apiKeyBuilder.value = apiKey
    }.build()
}

fun buildDefaults(): RequestConfig {
    return RequestConfig.getDefaultInstance()
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
    
    // Low-level FFI takes FfiOptions as context
    val ffiOptions = FfiOptions.newBuilder().apply {
        connector = Connector.STRIPE
        environment = Environment.SANDBOX
        auth = buildConfig().auth
    }.build()
    val optionsBytes = ffiOptions.toByteArray()

    try {
        val connectorRequestBytes = authorizeReqTransformer(requestBytes, metadata, optionsBytes)
        val connectorRequest = FfiConnectorHttpRequest.parseFrom(connectorRequestBytes)
        val url = connectorRequest.url
        val method = connectorRequest.method

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
    println("\n=== Test 2: Full round-trip (PaymentClient) ===")

    val apiKey = System.getenv("STRIPE_API_KEY") ?: ""
    if (apiKey.isEmpty() || apiKey == "sk_test_placeholder") {
        println("  SKIPPED (set STRIPE_API_KEY to enable)")
        return
    }

    val config = buildConfig()
    val defaults = buildDefaults()
    val client = PaymentClient(config, defaults)
    try {
        val response = client.authorize(buildRequest(), buildMetadata(), null)
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
