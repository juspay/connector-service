// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py checkout
//
// Flow: RecurringPaymentService.Charge
//
// SDK: sdk/java (Kotlin/JVM — uses UniFFI protobuf builder pattern)
// Build: ./gradlew compileKotlin  (from sdk/java/)

import payments.RecurringPaymentClient
import payments.ConnectorConfig
import payments.Connector
import payments.Environment

fun main() {
    val config = ConnectorConfig.newBuilder()
        .setConnector(Connector.CHECKOUT)
        .setEnvironment(Environment.SANDBOX)
        // .setAuth(...) — set your connector auth here
        .build()

    val client = RecurringPaymentClient(config)

    val request = RecurringPaymentServiceChargeRequest.newBuilder().apply {
        connectorRecurringPaymentIdBuilder.apply {  // Reference to existing mandate
            mandateIdTypeBuilder.apply {
                connectorMandateIdBuilder.value = "probe_mandate_123"
            }
        }
        amountBuilder.apply {  // Amount Information
            minorAmount = 1000L  // Amount in minor units (e.g., 1000 = $10.00)
            currencyBuilder.value = "USD"  // ISO 4217 currency code (e.g., "USD", "EUR")
        }
        paymentMethodBuilder.apply {  // Optional payment Method Information (for network transaction flows)
            tokenBuilder.value = "probe_pm_token"  // Payment tokens
        }
        returnUrlBuilder.value = "https://example.com/recurring-return"
        connectorCustomerIdBuilder.value = "probe_cust_connector_001"
        paymentMethodTypeBuilder.value = "PAY_PAL"
        offSession = true  // Behavioral Flags and Preferences
    }.build()

    val response = client.recurringCharge(request)
    if (response.status.name == "FAILED")
        throw RuntimeException("Recurring_Charge failed: ${response.error.message}")
    println("Done: ${response.status.name}")
}
