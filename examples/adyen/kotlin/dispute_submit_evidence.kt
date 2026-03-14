// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py adyen
//
// Flow: DisputeService.SubmitEvidence
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

    val request = DisputeServiceSubmitEvidenceRequest.newBuilder().apply {
        merchantDisputeIdBuilder.value = "probe_dispute_001"  // Identification
        connectorTransactionIdBuilder.value = "probe_txn_001"
        disputeIdBuilder.value = "probe_dispute_id_001"
        // evidenceDocuments: [{"evidence_type": "SERVICE_DOCUMENTATION", "file_content": [112, 114, 111, 98, 101, 32, 101, 118, 105, 100, 101, 110, 99, 101, 32, 99, 111, 110, 116, 101, 110, 116], "file_mime_type": "application/pdf"}]  // Collection of evidence documents
    }.build()

    val response = client.disputeSubmitEvidence(request)
    println("Status: ${response.status.name}")
}
