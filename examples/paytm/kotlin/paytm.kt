// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py paytm
//
// Paytm — all scenarios and flows in one file.
// Run a scenario:  ./gradlew run --args="paytm processCheckoutCard"

package examples.paytm

import payments.MerchantAuthenticationClient
import payments.PaymentClient
import payments.MerchantAuthenticationServiceCreateSessionTokenRequest
import payments.PaymentServiceGetRequest
import payments.Currency
import payments.ConnectorConfig
import payments.Connector
import payments.Environment

val _defaultConfig: ConnectorConfig = ConnectorConfig.newBuilder()
    .setConnector(Connector.PAYTM)
    .setEnvironment(Environment.SANDBOX)
    // .setAuth(...) — set your connector auth here
    .build()


// Flow: MerchantAuthenticationService.CreateSessionToken
fun create_session_token(txnId: String) {
    val client = MerchantAuthenticationClient(_defaultConfig)
    val request = MerchantAuthenticationServiceCreateSessionTokenRequest.newBuilder().apply {
        amountBuilder.apply {  // Amount Information
            minorAmount = 1000L  // Amount in minor units (e.g., 1000 = $10.00)
            currency = Currency.USD  // ISO 4217 currency code (e.g., "USD", "EUR")
        }
    }.build()
    val response = client.create_session_token(request)
    println("Session token obtained (statusCode=${response.statusCode})")
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


fun main(args: Array<String>) {
    val txnId = "order_001"
    val flow = args.firstOrNull() ?: "create_session_token"
    when (flow) {
        "create_session_token" -> create_session_token(txnId)
        "get" -> get(txnId)
        else -> System.err.println("Unknown flow: $flow. Available: create_session_token, get")
    }
}
