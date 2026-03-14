// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py worldpayxml
//
// Flow: PaymentService.Capture
//
// SDK: sdk/java (Kotlin/JVM — uses UniFFI protobuf builder pattern)
// Build: ./gradlew compileKotlin  (from sdk/java/)

import payments.PaymentClient
import payments.ConnectorConfig
import payments.Connector
import payments.Environment

fun main() {
    val config = ConnectorConfig.newBuilder()
        .setConnector(Connector.WORLDPAYXML)
        .setEnvironment(Environment.SANDBOX)
        // .setAuth(...) — set your connector auth here
        .build()

    val client = PaymentClient(config)

    val request = PaymentServiceCaptureRequest.newBuilder().apply {
        merchantCaptureIdBuilder.value = "probe_capture_001"  // Identification
        connectorTransactionIdBuilder.value = "probe_connector_txn_001"
        amountToCaptureBuilder.apply {  // Capture Details
            minorAmount = 1000L  // Amount in minor units (e.g., 1000 = $10.00)
            currencyBuilder.value = "USD"  // ISO 4217 currency code (e.g., "USD", "EUR")
        }
    }.build()

    val response = client.capture(request)
    if (response.status.name == "FAILED")
        throw RuntimeException("Capture failed: ${response.error.message}")
    println("Done: ${response.status.name}")
}
