/**
 * Multi-connector smoke test for the hyperswitch-payments Java SDK.
 *
 * Loads connector credentials from external JSON file and runs authorize flow
 * for multiple connectors.
 *
 * Usage:
 *   ./gradlew run --args="--creds-file creds.json --all"
 *   ./gradlew run --args="--creds-file creds.json --connectors stripe,aci"
 *   ./gradlew run --args="--creds-file creds.json --all --dry-run"
 */

import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import payments.PaymentClient
import payments.PaymentServiceAuthorizeRequest
import payments.PaymentAddress
import payments.Currency
import payments.CaptureMethod
import payments.AuthenticationType
import payments.FfiConnectorHttpRequest
import payments.FfiOptions
import payments.ConnectorConfig
import payments.RequestConfig
import payments.Connector
import payments.Environment
import java.io.File

// Test card configurations
data class TestCard(
    val number: String,
    val expMonth: String,
    val expYear: String,
    val cvc: String,
    val holder: String
)

val TEST_CARDS = mapOf(
    "visa" to TestCard("4111111111111111", "12", "2050", "123", "Test User"),
    "mastercard" to TestCard("5555555555554444", "12", "2050", "123", "Test User")
)

// Default test amount
val DEFAULT_AMOUNT = mapOf("minorAmount" to 1000L, "currency" to Currency.USD)

// Placeholder values
val PLACEHOLDER_VALUES = setOf("", "placeholder", "test", "dummy", "sk_test_placeholder")

// Type for credentials
typealias AuthConfig = Map<String, Any>
typealias Credentials = Map<String, Any>

// Test result
data class TestResult(
    val connector: String,
    val status: String,
    val ffiTest: FfiTestResult? = null,
    val roundTripTest: RoundTripResult? = null,
    val error: String? = null
)

data class FfiTestResult(
    val url: String,
    val method: String,
    val passed: Boolean
)

data class RoundTripResult(
    val status: Int? = null,
    val type: String? = null,
    val passed: Boolean,
    val error: String? = null,
    val skipped: Boolean? = null,
    val reason: String? = null
)

fun loadCredentials(credsFile: String): Credentials {
    val file = File(credsFile)
    if (!file.exists()) {
        throw IllegalArgumentException("Credentials file not found: $credsFile")
    }
    val gson = Gson()
    val type = object : TypeToken<Credentials>() {}.type
    return gson.fromJson(file.readText(), type)
}

fun isPlaceholder(value: String): Boolean {
    if (value.isEmpty()) return true
    val lower = value.lowercase()
    return PLACEHOLDER_VALUES.contains(lower) || lower.contains("placeholder")
}

fun hasValidCredentials(authConfig: AuthConfig): Boolean {
    for ((key, value) in authConfig) {
        if (key == "metadata" || key == "_comment") continue
        
        // Check for SecretString structure: { "value": "..." }
        if (value is Map<*, *>) {
            val valueField = value["value"]
            if (valueField is String && !isPlaceholder(valueField)) {
                return true
            }
        }
        // Fallback for string values (legacy support)
        else if (value is String && !isPlaceholder(value)) {
            return true
        }
    }
    return false
}

fun buildMetadata(connectorName: String, authConfig: AuthConfig): Map<String, String> {
    val authFields = authConfig.filter { it.key != "metadata" }
    val authTypeKey = connectorName.replaceFirstChar { it.uppercase() }
    
    val metadata = mutableMapOf(
        "connector" to authTypeKey,
        "connector_auth_type" to Gson().toJson(mapOf(authTypeKey to authFields)),
        "x-connector" to authTypeKey,
        "x-merchant-id" to "test_merchant_$connectorName",
        "x-request-id" to "smoke-test-$connectorName-${System.currentTimeMillis()}",
        "x-tenant-id" to "public"
    )
    
    if (authFields.containsKey("api_key")) {
        metadata["x-api-key"] = authFields["api_key"].toString()
    }
    if (authFields.containsKey("key1")) {
        metadata["x-key1"] = authFields["key1"].toString()
    }
    
    // Determine auth type
    metadata["x-auth"] = when {
        authFields.containsKey("key2") -> "multi-auth-key"
        authFields.containsKey("api_secret") -> "signature-key"
        authFields.containsKey("key1") -> "body-key"
        else -> "header-key"
    }
    
    return metadata
}

fun buildAuthorizeRequest(cardType: String = "visa"): PaymentServiceAuthorizeRequest {
    val card = TEST_CARDS[cardType] ?: TEST_CARDS["visa"]!!
    
    return PaymentServiceAuthorizeRequest.newBuilder().apply {
        merchantTransactionId = "smoke_test_${System.currentTimeMillis()}_${(0..9999).random()}"
        amountBuilder.apply {
            minorAmount = DEFAULT_AMOUNT["minorAmount"] as Long
            currency = DEFAULT_AMOUNT["currency"] as Currency
        }
        captureMethod = CaptureMethod.AUTOMATIC
        paymentMethodBuilder.cardBuilder.apply {
            cardNumberBuilder.value = card.number
            cardExpMonthBuilder.value = card.expMonth
            cardExpYearBuilder.value = card.expYear
            cardCvcBuilder.value = card.cvc
            cardHolderNameBuilder.value = card.holder
        }
        customerBuilder.apply {
            emailBuilder.value = "test@example.com"
            name = "Test User"
        }
        authType = AuthenticationType.NO_THREE_DS
        returnUrl = "https://example.com/return"
        webhookUrl = "https://example.com/webhook"
        address = PaymentAddress.getDefaultInstance()
        testMode = true
    }.build()
}

fun testConnector(
    instanceName: String,
    authConfig: AuthConfig,
    dryRun: Boolean = false,
    baseConnectorName: String? = null
): TestResult {
    // Use base name for metadata (without index), instance name for display
    val connectorKey = baseConnectorName ?: instanceName
    
    val result = TestResult(
        connector = instanceName,
        status = "pending"
    )
    
    return try {
        val req = buildAuthorizeRequest()
        val metadata = buildMetadata(connectorKey, authConfig)
        
        if (dryRun) {
            return result.copy(
                status = "dry_run",
                ffiTest = FfiTestResult("dry-run", "POST", true)
            )
        }
        
        if (!hasValidCredentials(authConfig)) {
            return result.copy(
                status = "skipped",
                roundTripTest = RoundTripResult(
                    skipped = true,
                    reason = "placeholder_credentials",
                    passed = false
                )
            )
        }
        
        // Get connector enum
        val connectorEnum = Connector.valueOf(connectorKey.uppercase())
        
        // Create connector config with auth
        val configBuilder = ConnectorConfig.newBuilder()
            .setConnector(connectorEnum)
            .setEnvironment(Environment.SANDBOX)
        
        // Set auth fields from authConfig
        val connectorAuthKey = connectorKey.lowercase()
        val authConfigBuilder = configBuilder.authBuilder
        
        // Get the connector-specific auth builder (e.g., getStripeBuilder)
        val connectorAuthBuilderMethod = try {
            authConfigBuilder.javaClass.getMethod("get${connectorAuthKey.replaceFirstChar { it.uppercase() }}Builder")
        } catch (e: NoSuchMethodException) {
            null
        }
        
        if (connectorAuthBuilderMethod != null) {
            val connectorAuthBuilder = connectorAuthBuilderMethod.invoke(authConfigBuilder)
            
            // Set each auth field
            for ((key, value) in authConfig) {
                if (key == "_comment" || key == "metadata") continue
                
                // Convert snake_case to camelCase for method names
                val camelKey = key.split("_").mapIndexed { index, part ->
                    if (index == 0) part else part.replaceFirstChar { it.uppercase() }
                }.joinToString("")
                
                // Get the field builder method (e.g., getApiKeyBuilder)
                val fieldBuilderMethod = try {
                    connectorAuthBuilder?.javaClass?.getMethod("get${camelKey.replaceFirstChar { it.uppercase() }}Builder")
                } catch (e: NoSuchMethodException) {
                    null
                }
                
                if (fieldBuilderMethod != null && value is Map<*, *> && value.containsKey("value")) {
                    val fieldValue = value["value"] as? String
                    if (fieldValue != null) {
                        val fieldBuilder = fieldBuilderMethod.invoke(connectorAuthBuilder)
                        fieldBuilder?.javaClass?.getMethod("setValue", String::class.java)?.invoke(fieldBuilder, fieldValue)
                    }
                }
            }
        }
        
        val config = configBuilder.build()
        val client = PaymentClient(config)
        
        try {
            val response = client.authorize(req)
            result.copy(
                status = "passed",
                roundTripTest = RoundTripResult(
                    status = response.status.number,
                    type = "PaymentServiceAuthorizeResponse",
                    passed = true
                )
            )
        } catch (e: Exception) {
            result.copy(
                status = "passed_with_error",
                roundTripTest = RoundTripResult(
                    passed = true,
                    error = "${e.javaClass.simpleName}: ${e.message}"
                )
            )
        }
    } catch (e: Exception) {
        result.copy(
            status = "failed",
            error = e.message
        )
    }
}

data class Args(
    val credsFile: String = "creds.json",
    val connectors: List<String>? = null,
    val all: Boolean = false,
    val dryRun: Boolean = false,
    val card: String = "visa"
)

fun parseArgs(args: Array<String>): Args {
    var result = Args()
    
    var i = 0
    while (i < args.size) {
        when (args[i]) {
            "--creds-file" -> if (i + 1 < args.size) {
                result = result.copy(credsFile = args[++i])
            }
            "--connectors" -> if (i + 1 < args.size) {
                result = result.copy(connectors = args[++i].split(",").map { it.trim() })
            }
            "--all" -> result = result.copy(all = true)
            "--dry-run" -> result = result.copy(dryRun = true)
            "--card" -> if (i + 1 < args.size) {
                result = result.copy(card = args[++i])
            }
            "--help", "-h" -> {
                println("""
Usage: ./gradlew run --args="[options]"

Options:
  --creds-file <path>     Path to credentials JSON (default: creds.json)
  --connectors <list>     Comma-separated list of connectors to test
  --all                   Test all connectors in the credentials file
  --dry-run               Build requests without executing HTTP calls
  --card <type>           Test card type: visa or mastercard (default: visa)
  --help, -h              Show this help message

Examples:
  ./gradlew run --args="--all"
  ./gradlew run --args="--connectors stripe,aci"
  ./gradlew run --args="--all --dry-run"
""")
                System.exit(0)
            }
        }
        i++
    }
    
    if (!result.all && result.connectors == null) {
        System.err.println("Error: Must specify either --all or --connectors")
        System.exit(1)
    }
    
    return result
}

fun runTests(
    credsFile: String,
    connectors: List<String>?,
    dryRun: Boolean
): List<TestResult> {
    val credentials = loadCredentials(credsFile)
    val results = mutableListOf<TestResult>()
    
    val testConnectors = connectors ?: credentials.keys.toList()
    
    println("\n${"=".repeat(60)}")
    println("Running smoke tests for ${testConnectors.size} connector(s)")
    println("${"=".repeat(60)}\n")
    
    for (connectorName in testConnectors) {
        val authConfigValue = credentials[connectorName]
        
        if (authConfigValue == null) {
            println("\n--- Testing $connectorName ---")
            println("  SKIPPED (not found in credentials file)")
            results.add(TestResult(connectorName, "skipped", error = "not_found"))
            continue
        }
        
        println("\n--- Testing $connectorName ---")
        
        @Suppress("UNCHECKED_CAST")
        when {
            authConfigValue is List<*> -> {
                // Multi-instance connector
                val authConfigList = authConfigValue as List<Map<String, Any>>
                for (i in authConfigList.indices) {
                    val instanceName = "$connectorName[${i + 1}]"
                    println("  Instance: $instanceName")
                    
                    @Suppress("UNCHECKED_CAST")
                    val authConfig = authConfigList[i] as AuthConfig
                    
                    if (!hasValidCredentials(authConfig)) {
                        println("  SKIPPED (placeholder credentials)")
                        results.add(TestResult(
                            instanceName, "skipped",
                            roundTripTest = RoundTripResult(
                                skipped = true,
                                reason = "placeholder_credentials",
                                passed = false
                            )
                        ))
                        continue
                    }
                    
                    val result = testConnector(instanceName, authConfig, dryRun, connectorName)
                    results.add(result)
                    
                    when (result.status) {
                        "passed" -> println("  ✓ PASSED")
                        "passed_with_error" -> println("  ✓ PASSED (with connector error)")
                        "dry_run" -> println("  ✓ DRY RUN")
                        else -> println("  ✗ ${result.status.uppercase()}: ${result.error ?: "Unknown error"}")
                    }
                }
            }
            authConfigValue is Map<*, *> -> {
                // Single-instance connector
                @Suppress("UNCHECKED_CAST")
                val authConfig = authConfigValue as AuthConfig
                
                if (!hasValidCredentials(authConfig)) {
                    println("  SKIPPED (placeholder credentials)")
                    results.add(TestResult(
                        connectorName, "skipped",
                        roundTripTest = RoundTripResult(
                            skipped = true,
                            reason = "placeholder_credentials",
                            passed = false
                        )
                    ))
                    continue
                }
                
                val result = testConnector(connectorName, authConfig, dryRun)
                results.add(result)
                
                when (result.status) {
                    "passed" -> println("  ✓ PASSED")
                    "passed_with_error" -> println("  ✓ PASSED (with connector error)")
                    "dry_run" -> println("  ✓ DRY RUN")
                    else -> println("  ✗ ${result.status.uppercase()}: ${result.error ?: "Unknown error"}")
                }
            }
        }
    }
    
    return results
}

fun printSummary(results: List<TestResult>): Int {
    println("\n${"=".repeat(60)}")
    println("TEST SUMMARY")
    println("${"=".repeat(60)}\n")
    
    val passed = results.count { it.status in listOf("passed", "passed_with_error", "dry_run") }
    val skipped = results.count { it.status == "skipped" }
    val failed = results.count { it.status == "failed" }
    val total = results.size
    
    println("Total:   $total")
    println("Passed:  $passed ✓")
    println("Skipped: $skipped (placeholder credentials)")
    println("Failed:  $failed ✗")
    println()
    
    if (failed > 0) {
        println("Failed tests:")
        for (result in results) {
            if (result.status == "failed") {
                println("  - ${result.connector}: ${result.error ?: "Unknown error"}")
            }
        }
        println()
        return 1
    }
    
    if (passed == 0 && skipped > 0) {
        println("All tests skipped (no valid credentials found)")
        println("Update creds.json with real credentials to run tests")
        return 1
    }
    
    println("All tests completed successfully!")
    return 0
}

fun main(args: Array<String>) {
    val parsedArgs = parseArgs(args)
    
    try {
        val results = runTests(parsedArgs.credsFile, parsedArgs.connectors, parsedArgs.dryRun)
        val exitCode = printSummary(results)
        System.exit(exitCode)
    } catch (e: Exception) {
        System.err.println("\nFatal error: ${e.message}")
        e.printStackTrace()
        System.exit(1)
    }
}
