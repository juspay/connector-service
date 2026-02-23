/**
 * UniFFI FFI example: authorize_req + full round-trip (Kotlin)
 *
 * Demonstrates two usage patterns:
 *   1. Low-level: call authorizeReqTransformer directly to get the connector HTTP request JSON
 *   2. High-level: use ConnectorClient for a full round-trip (build → HTTP → parse)
 *
 * All types come from proto codegen — Connector, ConnectorAuth, ConnectorConfig
 * follow the same pattern as Currency, CaptureMethod, etc.
 *
 * Prerequisites (run `make setup` first):
 *   - generated/connector_service_ffi.kt  (UniFFI bindings)
 *   - generated/ucs/v2/Payment.java       (protobuf stubs)
 */

import uniffi.connector_service_ffi.UniffiException
import uniffi.connector_service_ffi.authorizeReqTransformer
import org.json.JSONObject
import ucs.v2.Payment.*
import ucs.v2.PaymentMethods.*

fun buildAuthorizeRequestMsg(): PaymentServiceAuthorizeRequest {
    return PaymentServiceAuthorizeRequest.newBuilder().apply {
        // Identification
        requestRefIdBuilder.id = "test_payment_123456"

        // Payment details
        amount = 1000
        minorAmount = 1000
        currency = Currency.USD
        captureMethod = CaptureMethod.AUTOMATIC

        // Card payment method
        paymentMethodBuilder.cardBuilder.apply {
            cardNumberBuilder.value = "4111111111111111"
            cardExpMonthBuilder.value = "12"
            cardExpYearBuilder.value = "2050"
            cardCvcBuilder.value = "123"
            cardHolderNameBuilder.value = "Test User"
        }

        // Customer info
        emailBuilder.value = "customer@example.com"
        customerName = "Test Customer"

        // Auth / 3DS
        authType = AuthenticationType.NO_THREE_DS
        enrolledFor3Ds = false

        // URLs
        returnUrl = "https://example.com/return"
        webhookUrl = "https://example.com/webhook"

        // Address (required)
        address = PaymentAddress.getDefaultInstance()

        // Misc
        description = "Test payment"
        testMode = true
    }.build()
}

fun buildConnectorConfig(): ConnectorConfig {
    val apiKey = System.getenv("STRIPE_API_KEY") ?: "sk_test_placeholder"
    return ConnectorConfig.newBuilder()
        .setConnector(Connector.STRIPE)
        .setAuth(ConnectorAuth.newBuilder()
            .setHeaderKey(HeaderKeyAuth.newBuilder().setApiKey(apiKey).build())
            .build()
        )
        .build()
}

fun demoLowLevelFfi() {
    println("=== Demo 1: Low-level FFI (authorizeReqTransformer) ===\n")

    val requestMsg = buildAuthorizeRequestMsg()
    val requestBytes = requestMsg.toByteArray()

    val config = buildConnectorConfig()
    val configBytes = config.toByteArray()

    println("Request proto bytes: ${requestBytes.size} bytes")
    println("Config proto bytes:  ${configBytes.size} bytes")
    println("Connector: STRIPE\n")

    try {
        val connectorRequestJson = authorizeReqTransformer(requestBytes, configBytes, null)
        val connectorRequest = JSONObject(connectorRequestJson)

        println("Connector HTTP request generated successfully:")
        println("  URL:    ${connectorRequest.getString("url")}")
        println("  Method: ${connectorRequest.getString("method")}")
        println("  Headers: ${connectorRequest.optJSONObject("headers")?.keys()?.asSequence()?.toList() ?: emptyList<String>()}")
        println("\nFull request JSON:")
        println(connectorRequest.toString(2))

    } catch (e: UniffiException.HandlerException) {
        println("Handler returned an error (FFI boundary is working):")
        println("  ${e.message}")
        println("\nThis is expected with placeholder data. To get a full request,")
        println("provide valid STRIPE_API_KEY and complete payment fields.")

    } catch (e: UniffiException) {
        System.err.println("FFI error: ${e.message}")
        System.exit(1)
    }
}

fun demoFullRoundTrip() {
    println("\n=== Demo 2: Full round-trip (ConnectorClient) ===\n")

    val apiKey = System.getenv("STRIPE_API_KEY") ?: ""
    if (apiKey.isEmpty() || apiKey == "sk_test_placeholder") {
        println("Skipping full round-trip: STRIPE_API_KEY not set.")
        println("Run with: STRIPE_API_KEY=sk_test_xxx ./gradlew run")
        return
    }

    val config = ConnectorConfig.newBuilder()
        .setConnector(Connector.STRIPE)
        .setAuth(ConnectorAuth.newBuilder()
            .setHeaderKey(HeaderKeyAuth.newBuilder().setApiKey(apiKey).build())
            .build()
        )
        .build()

    val client = ConnectorClient(config)
    val requestMsg = buildAuthorizeRequestMsg()

    println("Connector: STRIPE")
    println("Sending authorize request...\n")

    try {
        val response = client.authorize(requestMsg)
        println("Authorize response received:")
        println("  Status: ${response.status}")
        println("  Response: $response")

    } catch (e: UniffiException) {
        System.err.println("FFI error: ${e.message}")

    } catch (e: Exception) {
        System.err.println("Error during round-trip: ${e.message}")
    }
}

fun main() {
    demoLowLevelFfi()
    demoFullRoundTrip()
}
