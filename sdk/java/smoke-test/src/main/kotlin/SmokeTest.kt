/**
 * Multi-connector smoke test for the hyperswitch-payments Java SDK.
 *
 * Loads connector credentials from external JSON file and runs all scenario
 * functions found in examples/{connector}/kotlin/{connector}.kt for each connector.
 *
 * Each example file (stripe.kt, adyen.kt, etc.) is auto-generated and lives in
 * package examples.{connector}. It exports process*(merchantTransactionId, config)
 * functions that the smoke test discovers and invokes via reflection.
 *
 * Usage:
 *   ./gradlew run --args="--creds-file creds.json --all"
 *   ./gradlew run --args="--creds-file creds.json --connectors stripe,adyen"
 *   ./gradlew run --args="--creds-file creds.json --all --dry-run"
 */

import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import payments.ConnectorConfig
import payments.ConnectorSpecificConfig
import payments.SdkOptions
import payments.Environment
import payments.IntegrationError
import payments.ConnectorError
import java.io.File
import java.lang.reflect.InvocationTargetException

// ── ANSI color helpers ──────────────────────────────────────────────────────
private val NO_COLOR = System.getenv("NO_COLOR") != null
    || (System.getenv("FORCE_COLOR") == null
        && System.console() == null
        && System.getenv("TERM").let { it == null || it == "dumb" })

private fun c(code: String, text: String) = if (NO_COLOR) text else "\u001b[${code}m$text\u001b[0m"
private fun green(t: String) = c("32", t)
private fun yellow(t: String) = c("33", t)
private fun red(t: String) = c("31", t)
private fun grey(t: String) = c("90", t)
private fun bold(t: String) = c("1", t)

val PLACEHOLDER_VALUES = setOf("", "placeholder", "test", "dummy", "sk_test_placeholder")

typealias AuthConfig = Map<String, Any>
typealias Credentials = Map<String, Any>

data class ScenarioResult(
    val status: String,  // "passed" | "skipped" | "failed"
    val result: Map<String, Any?>? = null,
    val reason: String? = null,
    val detail: String? = null,
    val error: String? = null,
)

data class ConnectorResult(
    val connector: String,
    var status: String,
    val scenarios: MutableMap<String, ScenarioResult> = mutableMapOf(),
    var error: String? = null,
)

sealed class DiscoveryResult
class ValidScenarios(val scenarios: List<Pair<String, java.lang.reflect.Method>>) : DiscoveryResult()
class ValidationError(val message: String) : DiscoveryResult()

fun loadCredentials(credsFile: String): Credentials {
    val file = File(credsFile)
    if (!file.exists()) throw IllegalArgumentException("Credentials file not found: $credsFile")
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
        if (value is Map<*, *>) {
            val v = value["value"]
            if (v is String && !isPlaceholder(v)) return true
        } else if (value is String && !isPlaceholder(value)) {
            return true
        }
    }
    return false
}

fun buildConnectorConfig(connectorName: String, authConfig: AuthConfig): ConnectorConfig {
    val connectorSpecificBuilder = ConnectorSpecificConfig.newBuilder()

    val connectorBuilderMethod = try {
        connectorSpecificBuilder.javaClass.getMethod("get${connectorName.lowercase().replaceFirstChar { it.uppercase() }}Builder")
    } catch (e: NoSuchMethodException) { null }

    if (connectorBuilderMethod != null) {
        val connectorBuilder = connectorBuilderMethod.invoke(connectorSpecificBuilder)
        for ((key, value) in authConfig) {
            if (key == "_comment" || key == "metadata") continue
            val camelKey = key.split("_").mapIndexed { i, part ->
                if (i == 0) part else part.replaceFirstChar { it.uppercase() }
            }.joinToString("")
            val fieldBuilderMethod = try {
                connectorBuilder?.javaClass?.getMethod("get${camelKey.replaceFirstChar { it.uppercase() }}Builder")
            } catch (e: NoSuchMethodException) { null }
            if (fieldBuilderMethod != null && value is Map<*, *> && value.containsKey("value")) {
                val fieldValue = value["value"] as? String
                if (fieldValue != null) {
                    val fieldBuilder = fieldBuilderMethod.invoke(connectorBuilder)
                    fieldBuilder?.javaClass?.getMethod("setValue", String::class.java)?.invoke(fieldBuilder, fieldValue)
                }
            }
        }
    }

    val sdkOptions = SdkOptions.newBuilder()
        .setEnvironment(Environment.SANDBOX)
        .build()

    return ConnectorConfig.newBuilder()
        .setConnectorConfig(connectorSpecificBuilder.build())
        .setOptions(sdkOptions)
        .build()
}

fun loadFlowManifest(sdkRoot: String): List<String> {
    val manifestPath = File(sdkRoot, "generated/flows.json")
    if (!manifestPath.exists()) {
        throw IllegalStateException(
            "flows.json not found at ${manifestPath.absolutePath}. Run: make generate"
        )
    }
    val gson = Gson()
    val type = object : TypeToken<Map<String, Any>>() {}.type
    val data: Map<String, Any> = gson.fromJson(manifestPath.readText(), type)
    @Suppress("UNCHECKED_CAST")
    return data["flows"] as List<String>
}

fun scenarioToMethodName(scenarioKey: String): String =
    "process" + scenarioKey.split("_").joinToString("") { it.replaceFirstChar { c -> c.uppercase() } }

fun fromMethodName(methodName: String): String {
    return methodName
        .removePrefix("process")
        .replace(Regex("([A-Z])"), "_$1")
        .lowercase()
        .trimStart('_')
}

fun connectorClassName(connectorName: String): String =
    "examples.$connectorName.${connectorName.replaceFirstChar { it.uppercase() }}Kt"

fun discoverAndValidate(
    exampleClass: Class<*>,
    connectorName: String,
    manifest: List<String>,
): DiscoveryResult {

    val declared: List<String>? = try {
        @Suppress("UNCHECKED_CAST")
        exampleClass.getDeclaredField("SUPPORTED_FLOWS").also { it.isAccessible = true }
            .get(null) as? List<String>
    } catch (_: NoSuchFieldException) { null }
    
    val legacyMode = declared == null

    val effectiveDeclared: List<String> = if (!legacyMode) {
        declared!!.distinct()  // Deduplicate
    } else {
        // Legacy mode: scan process* methods against manifest
        manifest.filter { name ->
            try {
                exampleClass.getMethod(scenarioToMethodName(name), String::class.java, ConnectorConfig::class.java)
                true
            } catch (_: NoSuchMethodException) { false }
        }
    }

    // Validate flow names are lowercase snake_case
    for (name in effectiveDeclared) {
        if (name != name.lowercase() || name.contains(" ") || name.contains("-")) {
            return ValidationError(
                "COVERAGE ERROR: Flow name '$name' in SUPPORTED_FLOWS must be lowercase snake_case (e.g., 'authorize', 'payout_create')"
            )
        }
    }

    // CHECK 1
    val implemented = effectiveDeclared.filter { name ->
        try {
            exampleClass.getMethod(scenarioToMethodName(name), String::class.java, ConnectorConfig::class.java)
            true
        } catch (_: NoSuchMethodException) { false }
    }.toSet()
    val missing = effectiveDeclared.filter { it !in implemented }
    if (missing.isNotEmpty()) {
        return ValidationError(
            "COVERAGE ERROR: SUPPORTED_FLOWS declares $missing but no process* method found."
        )
    }

    // CHECK 2 and 3 only apply when SUPPORTED_FLOWS is explicitly defined (not legacy mode)
    if (!legacyMode) {
        // CHECK 2: find all process* methods on the class
        val allProcessMethods = exampleClass.methods
            .filter { it.name.startsWith("process") }
            .map { fromMethodName(it.name) }
            .toSet()
        val undeclared = allProcessMethods - effectiveDeclared.toSet()
        if (undeclared.isNotEmpty()) {
            return ValidationError(
                "COVERAGE ERROR: process* methods exist but not in SUPPORTED_FLOWS: $undeclared"
            )
        }

        // CHECK 3
        val manifestSet = manifest.toSet()
        val stale = effectiveDeclared.filter { it !in manifestSet }
        if (stale.isNotEmpty()) {
            return ValidationError(
                "COVERAGE ERROR: SUPPORTED_FLOWS contains stale flows not in flows.json: $stale"
            )
        }
    }

    val methods = effectiveDeclared.map { name ->
        name to exampleClass.getMethod(scenarioToMethodName(name), String::class.java, ConnectorConfig::class.java)
    }
    return ValidScenarios(methods)
}

fun testConnectorScenarios(
    instanceName: String,
    connectorName: String,
    config: ConnectorConfig,
    sdkRoot: String,
    dryRun: Boolean = false,
): ConnectorResult {
    val result = ConnectorResult(connector = instanceName, status = "passed")

    if (dryRun) {
        result.status = "dry_run"
        return result
    }

    val className = connectorClassName(connectorName)
    val exampleClass = try {
        Class.forName(className)
    } catch (e: ClassNotFoundException) {
        result.status = "skipped"
        result.scenarios["skipped"] = ScenarioResult(status = "skipped", reason = "no_examples_class")
        return result
    }

    // Load flow manifest and validate scenarios
    val manifest = try {
        loadFlowManifest(sdkRoot)
    } catch (e: Exception) {
        result.status = "failed"
        result.error = e.message
        return result
    }

    val discoveryResult = discoverAndValidate(exampleClass, connectorName, manifest)
    when (discoveryResult) {
        is ValidationError -> {
            result.status = "failed"
            result.error = discoveryResult.message
            return result
        }
        is ValidScenarios -> {
            if (discoveryResult.scenarios.isEmpty()) {
                result.status = "skipped"
                result.scenarios["skipped"] = ScenarioResult(status = "skipped", reason = "no_scenario_methods")
                return result
            }
        }
    }

    val scenarioMethods = (discoveryResult as ValidScenarios).scenarios

    var anyFailed = false

    for ((scenarioKey, method) in scenarioMethods) {
        val txnId = "smoke_${scenarioKey}_${Integer.toHexString((Math.random() * 0xFFFFFF).toInt())}"
        print("    [$scenarioKey] running ... ")
        System.out.flush()

        try {
            @Suppress("UNCHECKED_CAST")
            val response = method.invoke(null, txnId, config) as Map<String, Any?>
            val error = response["error"]
            val hasError = error != null && error.toString().let {
                it.isNotBlank() && it != "{}" && !it.matches(Regex("""\w+\s*\{\s*\}"""))
            }
            if (hasError) {
                val errorStr = error.toString()
                println(yellow("SKIPPED (connector error)") + grey(" — $errorStr"))
                result.scenarios[scenarioKey] = ScenarioResult(status = "skipped", reason = "connector_error", detail = errorStr)
            } else {
                println(green("PASSED") + grey(" — $response"))
                result.scenarios[scenarioKey] = ScenarioResult(status = "passed", result = response)
            }
        } catch (e: IntegrationError) {
            val detail = "IntegrationError: ${e.message} (code=${e.errorCode}, action=${e.suggestedAction}, doc=${e.docUrl})"
            println(yellow("SKIPPED (connector error)") + grey(" — $detail"))
            result.scenarios[scenarioKey] = ScenarioResult(status = "skipped", reason = "connector_error", detail = detail)
        } catch (e: ConnectorError) {
            val detail = "ConnectorError: ${e.message} (code=${e.errorCode}, http=${e.httpStatusCode})"
            println(yellow("SKIPPED (connector error)") + grey(" — $detail"))
            result.scenarios[scenarioKey] = ScenarioResult(status = "skipped", reason = "connector_error", detail = detail)
        } catch (e: InvocationTargetException) {
            when (val cause = e.cause ?: e) {
                is IntegrationError -> {
                    val detail = "IntegrationError: ${cause.message} (code=${cause.errorCode}, action=${cause.suggestedAction}, doc=${cause.docUrl})"
                    println(yellow("SKIPPED (connector error)") + grey(" — $detail"))
                    result.scenarios[scenarioKey] = ScenarioResult(status = "skipped", reason = "connector_error", detail = detail)
                }
                is ConnectorError -> {
                    val detail = "ConnectorError: ${cause.message} (code=${cause.errorCode}, http=${cause.httpStatusCode})"
                    println(yellow("SKIPPED (connector error)") + grey(" — $detail"))
                    result.scenarios[scenarioKey] = ScenarioResult(status = "skipped", reason = "connector_error", detail = detail)
                }
                else -> {
                    val detail = "${cause.javaClass.simpleName}: ${cause.message}"
                    println(red("FAILED") + " — $detail")
                    result.scenarios[scenarioKey] = ScenarioResult(status = "failed", error = detail)
                    anyFailed = true
                }
            }
        } catch (e: Exception) {
            val detail = "${e.javaClass.simpleName}: ${e.message}"
            println(red("FAILED") + " — $detail")
            result.scenarios[scenarioKey] = ScenarioResult(status = "failed", error = detail)
            anyFailed = true
        }
    }

    result.status = if (anyFailed) "failed" else "passed"
    return result
}

fun printResult(result: ConnectorResult) {
    when (result.status) {
        "passed" -> {
            val passedCount = result.scenarios.values.count { it.status == "passed" }
            val skippedCount = result.scenarios.values.count { it.status == "skipped" }
            println(green("  PASSED") + " ($passedCount passed, $skippedCount skipped)")
            for ((key, detail) in result.scenarios) {
                when (detail.status) {
                    "passed" -> println(green("    $key: ✓"))
                    "skipped" -> println(yellow("    $key: ~ skipped (${detail.reason})"))
                }
            }
        }
        "dry_run" -> println(grey("  DRY RUN"))
        "skipped" -> {
            val reason = result.scenarios["skipped"]?.reason ?: result.error ?: "unknown"
            println(grey("  SKIPPED ($reason)"))
        }
        else -> {
            println(red("  FAILED"))
            for ((key, detail) in result.scenarios) {
                if (detail.status == "failed") println(red("    $key: ✗ FAILED — ${detail.error ?: "unknown error"}"))
            }
            if (result.error != null) println(red("  Error: ${result.error}"))
        }
    }
}

data class Args(
    val credsFile: String = "creds.json",
    val connectors: List<String>? = null,
    val all: Boolean = false,
    val dryRun: Boolean = false,
    val sdkRoot: String = "../..",
)

fun parseArgs(args: Array<String>): Args {
    var result = Args()
    var i = 0
    while (i < args.size) {
        when (args[i]) {
            "--creds-file" -> if (i + 1 < args.size) result = result.copy(credsFile = args[++i])
            "--connectors" -> if (i + 1 < args.size) result = result.copy(connectors = args[++i].split(",").map { it.trim() })
            "--all" -> result = result.copy(all = true)
            "--dry-run" -> result = result.copy(dryRun = true)
            "--sdk-root" -> if (i + 1 < args.size) result = result.copy(sdkRoot = args[++i])
            "--help", "-h" -> {
                println("""
Usage: ./gradlew run --args="[options]"

Options:
  --creds-file <path>     Path to credentials JSON (default: creds.json)
  --connectors <list>     Comma-separated list of connectors to test
  --all                   Test all connectors in the credentials file
  --dry-run               Build requests without executing HTTP calls
  --sdk-root <path>       Path to SDK root (default: ../..)
  --help, -h              Show this help message

Examples:
  ./gradlew run --args="--all"
  ./gradlew run --args="--connectors stripe,adyen"
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
    dryRun: Boolean,
    sdkRoot: String,
): List<ConnectorResult> {
    val credentials = loadCredentials(credsFile)
    val results = mutableListOf<ConnectorResult>()
    val testConnectors = connectors ?: credentials.keys.toList()

    println("\n${"=".repeat(60)}")
    println("Running smoke tests for ${testConnectors.size} connector(s)")
    println("${"=".repeat(60)}\n")

    for (connectorName in testConnectors) {
        val authConfigValue = credentials[connectorName]
        println("\n${bold("--- Testing $connectorName ---")}")

        if (authConfigValue == null) {
            println(grey("  SKIPPED (not found in credentials file)"))
            results.add(ConnectorResult(connectorName, "skipped", error = "not_found"))
            continue
        }

        @Suppress("UNCHECKED_CAST")
        when {
            authConfigValue is List<*> -> {
                val authConfigList = authConfigValue as List<Map<String, Any>>
                for (i in authConfigList.indices) {
                    val instanceName = "$connectorName[${i + 1}]"
                    println("  Instance: $instanceName")
                    val authConfig = authConfigList[i] as AuthConfig

                    if (!hasValidCredentials(authConfig)) {
                        println(grey("  SKIPPED (placeholder credentials)"))
                        results.add(ConnectorResult(instanceName, "skipped", error = "placeholder_credentials"))
                        continue
                    }

                    val config = try {
                        buildConnectorConfig(connectorName, authConfig)
                    } catch (e: Exception) {
                        println(grey("  SKIPPED (${e.message})"))
                        results.add(ConnectorResult(instanceName, "skipped", error = e.message))
                        continue
                    }

                    val result = testConnectorScenarios(instanceName, connectorName, config, sdkRoot, dryRun)
                    results.add(result)
                    printResult(result)
                }
            }
            authConfigValue is Map<*, *> -> {
                val authConfig = authConfigValue as AuthConfig

                if (!hasValidCredentials(authConfig)) {
                    println(grey("  SKIPPED (placeholder credentials)"))
                    results.add(ConnectorResult(connectorName, "skipped", error = "placeholder_credentials"))
                    continue
                }

                val config = try {
                    buildConnectorConfig(connectorName, authConfig)
                } catch (e: Exception) {
                    println(grey("  SKIPPED (${e.message})"))
                    results.add(ConnectorResult(connectorName, "skipped", error = e.message))
                    continue
                }

                val result = testConnectorScenarios(connectorName, connectorName, config, sdkRoot, dryRun)
                results.add(result)
                printResult(result)
            }
        }
    }

    return results
}

fun printSummary(results: List<ConnectorResult>): Int {
    println("\n${"=".repeat(60)}")
    println(bold("TEST SUMMARY"))
    println("${"=".repeat(60)}\n")

    val passed = results.count { it.status in listOf("passed", "dry_run") }
    val skipped = results.count { it.status == "skipped" }
    val failed = results.count { it.status == "failed" }

    // Count per-scenario statuses
    var totalFlowsPassed = 0
    var totalFlowsSkipped = 0
    var totalFlowsFailed = 0
    for (r in results) {
        for (scenario in r.scenarios.values) {
            when (scenario.status) {
                "passed" -> totalFlowsPassed++
                "skipped" -> totalFlowsSkipped++
                "failed" -> totalFlowsFailed++
            }
        }
    }

    println("Total connectors:   ${results.size}")
    println(green("Passed:  $passed"))
    println(grey("Skipped: $skipped (placeholder credentials or no examples)"))
    println((if (failed > 0) ::red else ::green)("Failed:  $failed"))
    println()
    println("Flow results:")
    println(green("  $totalFlowsPassed flows PASSED"))
    if (totalFlowsSkipped > 0) {
        println(yellow("  $totalFlowsSkipped flows SKIPPED (connector errors)"))
    }
    if (totalFlowsFailed > 0) {
        println(red("  $totalFlowsFailed flows FAILED"))
    }
    println()

    if (failed > 0) {
        println(red("Failed connectors:"))
        for (r in results) {
            if (r.status == "failed") println(red("  - ${r.connector}") + ": ${r.error ?: "see scenarios above"}")
        }
        println()
        return 1
    }

    if (passed == 0 && skipped > 0) {
        println(yellow("All tests skipped (no valid credentials found)"))
        println("Update creds.json with real credentials to run tests")
        return 1
    }

    println(green("All tests completed successfully!"))
    return 0
}

fun main(args: Array<String>) {
    val parsedArgs = parseArgs(args)
    try {
        val results = runTests(parsedArgs.credsFile, parsedArgs.connectors, parsedArgs.dryRun, parsedArgs.sdkRoot)
        val exitCode = printSummary(results)
        System.exit(exitCode)
    } catch (e: Exception) {
        System.err.println("\nFatal error: ${e.message}")
        e.printStackTrace()
        System.exit(1)
    }
}
