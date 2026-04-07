// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py trustly
//
// Trustly — all scenarios and flows in one file.
// Run a scenario:  ./gradlew run --args="trustly processCheckoutCard"

package examples.trustly

import payments.PaymentClient
import payments.ConnectorConfig
import payments.SdkOptions
import payments.Environment

val _defaultConfig: ConnectorConfig = ConnectorConfig.newBuilder()
    .setOptions(SdkOptions.newBuilder().setEnvironment(Environment.SANDBOX).build())
    // .setConnectorConfig(...) — set your connector config here
    .build()





fun main(args: Array<String>) {
    val txnId = "order_001"
    val flow = args.firstOrNull() ?: "authorize"
    when (flow) {

        else -> System.err.println("Unknown flow: $flow. Available: ")
    }
}
