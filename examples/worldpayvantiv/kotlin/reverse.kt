// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py worldpayvantiv
//
// Flow: PaymentService.Reverse
//
// SDK: sdk/java (Kotlin/JVM — uses UniFFI protobuf builder pattern)
// Build: ./gradlew compileKotlin  (from sdk/java/)

import payments.PaymentClient
import payments.ConnectorConfig
import payments.Connector
import payments.Environment

fun main() {
    val config = ConnectorConfig.newBuilder()
        .setConnector(Connector.WORLDPAYVANTIV)
        .setEnvironment(Environment.SANDBOX)
        // .setAuth(...) — set your connector auth here
        .build()

    val client = PaymentClient(config)

    val request = PaymentServiceReverseRequest.newBuilder().apply {
        merchantReverseIdBuilder.value = "probe_reverse_001"  // Identification
        connectorTransactionIdBuilder.value = "probe_connector_txn_001"
    }.build()

    val response = client.reverse(request)
    println("Status: ${response.status.name}")
}
