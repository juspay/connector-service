// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py adyen
//
// Flow: DisputeService.Accept
//
// SDK: sdk/java (Kotlin/JVM — uses UniFFI protobuf builder pattern)
// Build: ./gradlew compileKotlin  (from sdk/java/)

import payments.DisputeClient
import payments.ConnectorConfig
import payments.Connector
import payments.Environment

fun main() {
    val config = ConnectorConfig.newBuilder()
        .setConnector(Connector.ADYEN)
        .setEnvironment(Environment.SANDBOX)
        // .setAuth(...) — set your connector auth here
        .build()

    val client = DisputeClient(config)

    val request = DisputeServiceAcceptRequest.newBuilder().apply {
        merchantDisputeIdBuilder.value = "probe_dispute_001"  // Identification
        connectorTransactionIdBuilder.value = "probe_txn_001"
        disputeIdBuilder.value = "probe_dispute_id_001"
    }.build()

    val response = client.disputeAccept(request)
    println("Status: ${response.status.name}")
}
