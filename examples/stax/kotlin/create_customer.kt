// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py stax
//
// Flow: CustomerService.Create
//
// SDK: sdk/java (Kotlin/JVM — uses UniFFI protobuf builder pattern)
// Build: ./gradlew compileKotlin  (from sdk/java/)

import payments.CustomerClient
import payments.ConnectorConfig
import payments.Connector
import payments.Environment

fun main() {
    val config = ConnectorConfig.newBuilder()
        .setConnector(Connector.STAX)
        .setEnvironment(Environment.SANDBOX)
        // .setAuth(...) — set your connector auth here
        .build()

    val client = CustomerClient(config)

    val request = CustomerServiceCreateRequest.newBuilder().apply {
        customerNameBuilder.value = "John Doe"  // Name of the customer
        emailBuilder.value = "test@example.com"  // Email address of the customer
        phoneNumberBuilder.value = "4155552671"  // Phone number of the customer
        addressBuilder.apply {  // Address Information
            billingAddressBuilder.apply {
                firstNameBuilder.value = "John"  // Personal Information
                lastNameBuilder.value = "Doe"
                line1Builder.value = "123 Main St"  // Address Details
                cityBuilder.value = "Seattle"
                stateBuilder.value = "WA"
                zipCodeBuilder.value = "98101"
                countryAlpha2CodeBuilder.value = "US"
                emailBuilder.value = "test@example.com"  // Contact Information
                phoneNumberBuilder.value = "4155552671"
                phoneCountryCodeBuilder.value = "+1"
            }
        }
    }.build()

    val response = client.createCustomer(request)
    println("Status: ${response.status.name}")
}
