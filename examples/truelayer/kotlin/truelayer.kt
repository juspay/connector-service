// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py truelayer
//
// Truelayer — all scenarios and flows in one file.
// Run a scenario:  ./gradlew run --args="truelayer processCheckoutCard"

package examples.truelayer

import payments.MerchantAuthenticationClient
import payments.PaymentClient
import payments.MerchantAuthenticationServiceCreateAccessTokenRequest
import payments.PaymentServiceGetRequest
import payments.Currency
import payments.ConnectorConfig
import payments.Connector
import payments.Environment

val _defaultConfig: ConnectorConfig = ConnectorConfig.newBuilder()
    .setConnector(Connector.TRUELAYER)
    .setEnvironment(Environment.SANDBOX)
    // .setAuth(...) — set your connector auth here
    .build()


// Flow: MerchantAuthenticationService.CreateAccessToken
fun create_access_token(txnId: String) {
    val client = MerchantAuthenticationClient(_defaultConfig)
    val request = MerchantAuthenticationServiceCreateAccessTokenRequest.newBuilder().apply {

    }.build()
    val response = client.create_access_token(request)
    println("Access token obtained (statusCode=${response.statusCode})")
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
        stateBuilder.apply {  // State Information
            accessTokenBuilder.apply {  // Access token obtained from connector
                tokenBuilder.value = "probe_access_token"  // The token string.
                expiresInSeconds = 3600L  // Expiration timestamp (seconds since epoch)
                tokenType = "Bearer"  // Token type (e.g., "Bearer", "Basic").
            }
        }
    }.build()
    val response = client.get(request)
    println("Status: ${response.status.name}")
}


fun main(args: Array<String>) {
    val txnId = "order_001"
    val flow = args.firstOrNull() ?: "create_access_token"
    when (flow) {
        "create_access_token" -> create_access_token(txnId)
        "get" -> get(txnId)
        else -> System.err.println("Unknown flow: $flow. Available: create_access_token, get")
    }
}
