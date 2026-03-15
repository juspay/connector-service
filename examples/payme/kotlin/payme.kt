// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py payme
//
// Payme — all scenarios and flows in one file.
// Run a scenario:  ./gradlew run --args="payme processCheckoutCard"

package examples.payme

import payments.PaymentClient
import payments.PaymentServiceCaptureRequest
import payments.PaymentServiceCreateOrderRequest
import payments.PaymentServiceGetRequest
import payments.PaymentServiceRefundRequest
import payments.PaymentServiceVoidRequest
import payments.Currency
import payments.ConnectorConfig
import payments.Connector
import payments.Environment

val _defaultConfig: ConnectorConfig = ConnectorConfig.newBuilder()
    .setConnector(Connector.PAYME)
    .setEnvironment(Environment.SANDBOX)
    // .setAuth(...) — set your connector auth here
    .build()


// Flow: PaymentService.Capture
fun capture(txnId: String) {
    val client = PaymentClient(_defaultConfig)
    val request = PaymentServiceCaptureRequest.newBuilder().apply {
        merchantCaptureId = "probe_capture_001"  // Identification
        connectorTransactionId = "probe_connector_txn_001"
        amountToCaptureBuilder.apply {  // Capture Details
            minorAmount = 1000L  // Amount in minor units (e.g., 1000 = $10.00)
            currency = Currency.USD  // ISO 4217 currency code (e.g., "USD", "EUR")
        }
    }.build()
    val response = client.capture(request)
    if (response.status.name == "FAILED")
        throw RuntimeException("Capture failed: ${response.error.unifiedDetails.message}")
    println("Done: ${response.status.name}")
}

// Flow: PaymentService.CreateOrder
fun create_order(txnId: String) {
    val client = PaymentClient(_defaultConfig)
    val request = PaymentServiceCreateOrderRequest.newBuilder().apply {
        merchantOrderId = "probe_order_001"  // Identification
        amountBuilder.apply {  // Amount Information
            minorAmount = 1000L  // Amount in minor units (e.g., 1000 = $10.00)
            currency = Currency.USD  // ISO 4217 currency code (e.g., "USD", "EUR")
        }
    }.build()
    val response = client.create_order(request)
    println("Order: ${response.connectorOrderId}")
}

// Flow: PaymentService.Get
fun get(txnId: String) {
    val client = PaymentClient(_defaultConfig)
    val request = PaymentServiceGetRequest.newBuilder().apply {
        connectorTransactionId = "probe_connector_txn_001"
        amountBuilder.apply {  // Amount Information
            minorAmount = 1000L  // Amount in minor units (e.g., 1000 = $10.00)
            currency = Currency.USD  // ISO 4217 currency code (e.g., "USD", "EUR")
        }
    }.build()
    val response = client.get(request)
    println("Status: ${response.status.name}")
}

// Flow: PaymentService.Refund
fun refund(txnId: String) {
    val client = PaymentClient(_defaultConfig)
    val request = PaymentServiceRefundRequest.newBuilder().apply {
        merchantRefundId = "probe_refund_001"  // Identification
        connectorTransactionId = "probe_connector_txn_001"
        paymentAmount = 1000L  // Amount Information
        refundAmountBuilder.apply {
            minorAmount = 1000L  // Amount in minor units (e.g., 1000 = $10.00)
            currency = Currency.USD  // ISO 4217 currency code (e.g., "USD", "EUR")
        }
        reason = "customer_request"  // Reason for the refund
    }.build()
    val response = client.refund(request)
    if (response.status.name == "FAILED")
        throw RuntimeException("Refund failed: ${response.error.unifiedDetails.message}")
    println("Done: ${response.status.name}")
}

// Flow: PaymentService.Void
fun void(txnId: String) {
    val client = PaymentClient(_defaultConfig)
    val request = PaymentServiceVoidRequest.newBuilder().apply {
        merchantVoidId = "probe_void_001"  // Identification
        connectorTransactionId = "probe_connector_txn_001"
        amountBuilder.apply {  // Amount Information
            minorAmount = 1000L  // Amount in minor units (e.g., 1000 = $10.00)
            currency = Currency.USD  // ISO 4217 currency code (e.g., "USD", "EUR")
        }
    }.build()
    val response = client.void(request)
    if (response.status.name == "FAILED")
        throw RuntimeException("Void failed: ${response.error.unifiedDetails.message}")
    println("Done: ${response.status.name}")
}


fun main(args: Array<String>) {
    val txnId = "order_001"
    val flow = args.firstOrNull() ?: "capture"
    when (flow) {
        "capture" -> capture(txnId)
        "create_order" -> create_order(txnId)
        "get" -> get(txnId)
        "refund" -> refund(txnId)
        "void" -> void(txnId)
        else -> System.err.println("Unknown flow: $flow. Available: capture, create_order, get, refund, void")
    }
}
