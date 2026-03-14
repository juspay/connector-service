package cucumber

import io.cucumber.java.Before
import io.cucumber.java.Scenario
import io.cucumber.java.en.Given
import io.cucumber.java.en.When
import io.cucumber.java.en.Then
import org.json.JSONObject
import payments.*
import java.io.File
import java.nio.charset.StandardCharsets
import java.util.Base64

/**
 * Thin Cucumber step definitions for HTTP client sanity tests.
 *
 * Execute the SDK request and write actual JSON. All assertion/normalization
 * logic is delegated to the shared judge_scenario.js (single source of truth).
 */
class StepDefinitions {
    private var method = ""
    private var url = ""
    private var headers = mutableMapOf<String, String>()
    private var body: String? = null
    private var proxyUrl: String? = null
    private var responseTimeoutMs: Int? = null
    private var scenarioId = ""
    private var sourceId = ""
    private var judged = false

    private val artifactsDir: String
        get() = System.getProperty("artifacts.dir")
            ?: File("").absoluteFile.parentFile.resolve("tests/client_sanity/artifacts").absolutePath

    private val judgeScript: String
        get() = System.getProperty("artifacts.dir")?.let {
            File(it).parentFile.resolve("judge_scenario.js").absolutePath
        } ?: File("").absoluteFile.parentFile.resolve("tests/client_sanity/judge_scenario.js").absolutePath

    @Before
    fun setUp(scenario: Scenario) {
        method = ""; url = ""; headers = mutableMapOf(); body = null
        proxyUrl = null; responseTimeoutMs = null; scenarioId = ""; sourceId = ""
        judged = false
    }

    // ── Given ───────────────────────────────────────────────────

    @Given("the echo server is running on port {int}")
    fun echoServerRunning(port: Int) {}

    @Given("a {string} request to {string}")
    fun setRequest(method: String, url: String) { this.method = method; this.url = url }

    @Given("header {string} is {string}")
    fun setHeader(name: String, value: String) { headers[name] = value }

    @Given("body is {string}")
    fun setBody(body: String) { this.body = body.replace("\\r\\n", "\r\n").replace("\\n", "\n") }

    @Given("a response timeout of {int} ms")
    fun setResponseTimeout(ms: Int) { responseTimeoutMs = ms }

    @Given("the proxy is {string}")
    fun setProxy(url: String) { proxyUrl = url }

    // ── When (thin: execute + write actual JSON) ────────────────

    @When("the request is sent as scenario {string}")
    fun executeRequest(scenarioId: String) {
        this.scenarioId = scenarioId
        this.sourceId = "kotlin_$scenarioId"

        val actualFile = File(artifactsDir, "actual_$sourceId.json")
        val captureFile = File(artifactsDir, "capture_$sourceId.json")
        actualFile.delete(); captureFile.delete()

        val reqHeaders = headers.toMutableMap()
        reqHeaders["x-source"] = sourceId
        reqHeaders["x-scenario-id"] = scenarioId

        val bodyBytes = body?.let { b ->
            if (b.startsWith("base64:")) Base64.getDecoder().decode(b.substring(7))
            else b.toByteArray(StandardCharsets.UTF_8)
        }

        val request = HttpRequest(url = url, method = method, headers = reqHeaders, body = bodyBytes)

        val httpConfig = responseTimeoutMs?.let {
            HttpConfig.newBuilder().setResponseTimeoutMs(it).build()
        }

        val output = JSONObject()
        try {
            val clientConfig = proxyUrl?.takeIf { it.isNotEmpty() }?.let {
                HttpConfig.newBuilder().setProxy(ProxyOptions.newBuilder().setHttpUrl(it).build()).build()
            }
            val client = HttpClient.createClient(clientConfig)
            val response = HttpClient.execute(request, httpConfig, client)

            val ct = (response.headers["content-type"] ?: "").lowercase()
            val bodyStr = if ("application/octet-stream" in ct)
                Base64.getEncoder().encodeToString(response.body)
            else String(response.body, StandardCharsets.UTF_8)

            output.put("response", JSONObject().apply {
                put("statusCode", response.statusCode)
                put("headers", JSONObject(response.headers))
                put("body", bodyStr)
            })
        } catch (e: Exception) {
            val code = if (e is NetworkError) e.code.name else "UNKNOWN_ERROR"
            output.put("error", JSONObject().apply {
                put("code", code)
                put("message", e.message ?: e.toString())
            })
        }

        actualFile.writeText(output.toString(2))
        Thread.sleep(200) // wait for echo server capture
    }

    // ── Then (delegate ALL assertions to the shared judge) ──────

    @Then("the response status should be {int}")
    fun checkStatus(expected: Int) { /* validated by judge */ }

    @Then("the response body should be {string}")
    fun checkBody(expected: String) { /* validated by judge */ }

    @Then("the response header {string} should be {string}")
    fun checkHeader(name: String, value: String) { /* validated by judge */ }

    @Then("the response should have multi-value header {string} with values {string}")
    fun checkMultiHeader(name: String, values: String) { /* validated by judge */ }

    @Then("the SDK should return error {string}")
    fun checkError(code: String) { runJudge() }

    @Then("the server should have received the correct request")
    fun checkCapture() { runJudge() }

    private fun runJudge() {
        if (judged) return
        judged = true
        val proc = ProcessBuilder("node", judgeScript, "kotlin", scenarioId)
            .redirectErrorStream(true).start()
        val stdout = proc.inputStream.bufferedReader().readText()
        val exitCode = proc.waitFor()
        if (exitCode != 0) {
            val msg = try { JSONObject(stdout).getString("message") } catch (_: Exception) {
                "Judge FAILED for $scenarioId"
            }
            throw AssertionError(msg)
        }
    }
}
