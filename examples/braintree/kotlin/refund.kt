// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py braintree
//
// Flow: PaymentService.Refund
//
// SDK: sdk/java (Kotlin/JVM — uses UniFFI protobuf builder pattern)
// Build: ./gradlew compileKotlin  (from sdk/java/)

import payments.PaymentClient
import payments.ConnectorConfig
import payments.Connector
import payments.Environment

fun main() {
    val config = ConnectorConfig.newBuilder()
        .setConnector(Connector.BRAINTREE)
        .setEnvironment(Environment.SANDBOX)
        // .setAuth(...) — set your connector auth here
        .build()

    val client = PaymentClient(config)

    val request = PaymentServiceRefundRequest.newBuilder().apply {
        merchantRefundIdBuilder.value = "probe_refund_001"  // Identification
        connectorTransactionIdBuilder.value = "probe_connector_txn_001"
        paymentAmount = 1000L  // Amount Information
        refundAmountBuilder.apply {
            minorAmount = 1000L  // Amount in minor units (e.g., 1000 = $10.00)
            currencyBuilder.value = "USD"  // ISO 4217 currency code (e.g., "USD", "EUR")
        }
        reasonBuilder.value = "customer_request"  // Reason for the refund
    }.build()

    val response = client.refund(request)
    if (response.status.name == "FAILED")
        throw RuntimeException("Refund failed: ${response.error.message}")
    println("Done: ${response.status.name}")
}
