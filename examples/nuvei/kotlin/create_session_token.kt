// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py nuvei
//
// Flow: MerchantAuthenticationService.CreateSessionToken
//
// SDK: sdk/java (Kotlin/JVM — uses UniFFI protobuf builder pattern)
// Build: ./gradlew compileKotlin  (from sdk/java/)

import payments.MerchantAuthenticationClient
import payments.ConnectorConfig
import payments.Connector
import payments.Environment

fun main() {
    val config = ConnectorConfig.newBuilder()
        .setConnector(Connector.NUVEI)
        .setEnvironment(Environment.SANDBOX)
        // .setAuth(...) — set your connector auth here
        .build()

    val client = MerchantAuthenticationClient(config)

    val request = MerchantAuthenticationServiceCreateSessionTokenRequest.newBuilder().apply {
        amountBuilder.apply {  // Amount Information
            minorAmount = 1000L  // Amount in minor units (e.g., 1000 = $10.00)
            currencyBuilder.value = "USD"  // ISO 4217 currency code (e.g., "USD", "EUR")
        }
    }.build()

    val response = client.createSessionToken(request)
    println("Status: ${response.status.name}")
}
