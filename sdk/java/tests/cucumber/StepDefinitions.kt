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

class StepDefinitions {
    private var method = ""
    private var url = ""
    private var headers = mutableMapOf<String, String>()
    private var body: String? = null
    private var proxyUrl: String? = null
    private var responseTimeoutMs: Int? = null

    private var scenarioId = ""
    private var sourceId = ""

    private var sdkResponse: SdkResponse? = null
    private var sdkError: SdkError? = null

    private val artifactsDir: String
        get() {
            val baseDir = System.getProperty("artifacts.dir")
                ?: File("").absoluteFile.parentFile.resolve("tests/client_sanity/artifacts").absolutePath
            return baseDir
        }

    data class SdkResponse(
        val statusCode: Int,
        val headers: Map<String, String>,
        val body: String
    )

    data class SdkError(
        val code: String,
        val message: String
    )

    @Before
    fun setUp(scenario: Scenario) {
        method = ""
        url = ""
        headers = mutableMapOf()
        body = null
        proxyUrl = null
        responseTimeoutMs = null
        scenarioId = ""
        sourceId = ""
        sdkResponse = null
        sdkError = null
    }

    @Given("the echo server is running on port {int}")
    fun echoServerRunning(port: Int) {
        // Echo server is started externally; documentation step.
    }

    @Given("a {string} request to {string}")
    fun setRequest(method: String, url: String) {
        this.method = method
        this.url = url
    }

    @Given("header {string} is {string}")
    fun setHeader(name: String, value: String) {
        headers[name] = value
    }

    @Given("body is {string}")
    fun setBody(body: String) {
        this.body = body.replace("\\r\\n", "\r\n").replace("\\n", "\n")
    }

    @Given("a response timeout of {int} ms")
    fun setResponseTimeout(ms: Int) {
        responseTimeoutMs = ms
    }

    @Given("the proxy is {string}")
    fun setProxy(url: String) {
        proxyUrl = url
    }

    @When("the request is sent as scenario {string}")
    fun executeRequest(scenarioId: String) {
        this.scenarioId = scenarioId
        this.sourceId = "kotlin_$scenarioId"

        // Clean old artifacts
        File(artifactsDir, "capture_$sourceId.json").delete()
        File(artifactsDir, "actual_$sourceId.json").delete()

        // Build headers
        val reqHeaders = headers.toMutableMap()
        reqHeaders["x-source"] = sourceId
        reqHeaders["x-scenario-id"] = scenarioId

        // Build body
        val bodyBytes = body?.let { b ->
            if (b.startsWith("base64:")) {
                Base64.getDecoder().decode(b.substring(7))
            } else {
                b.toByteArray(StandardCharsets.UTF_8)
            }
        }

        val request = HttpRequest(
            url = url,
            method = method,
            headers = reqHeaders,
            body = bodyBytes
        )

        // Build HTTP config for timeouts
        val httpConfig = responseTimeoutMs?.let {
            HttpConfig.newBuilder().setResponseTimeoutMs(it).build()
        }

        try {
            // Create client with proxy config
            val clientConfig = proxyUrl?.let { pUrl ->
                if (pUrl.isNotEmpty()) {
                    HttpConfig.newBuilder()
                        .setProxy(ProxyOptions.newBuilder().setHttpUrl(pUrl).build())
                        .build()
                } else null
            }

            val client = HttpClient.createClient(clientConfig)
            val response = HttpClient.execute(request, httpConfig, client)

            val ct = (response.headers["content-type"] ?: "").lowercase()
            val bodyStr = if ("application/octet-stream" in ct) {
                Base64.getEncoder().encodeToString(response.body)
            } else {
                String(response.body, StandardCharsets.UTF_8)
            }

            sdkResponse = SdkResponse(
                statusCode = response.statusCode,
                headers = response.headers,
                body = bodyStr
            )
        } catch (e: Exception) {
            val code = if (e is NetworkError) e.code.name else "UNKNOWN_ERROR"
            sdkError = SdkError(code = code, message = e.message ?: e.toString())
        }

        // Wait for echo server to write capture
        Thread.sleep(200)
    }

    @Then("the response status should be {int}")
    fun checkStatus(expectedStatus: Int) {
        assert(sdkResponse != null) { "Expected response but got error: $sdkError" }
        assert(sdkResponse!!.statusCode == expectedStatus) {
            "Status mismatch: expected $expectedStatus, got ${sdkResponse!!.statusCode}"
        }
    }

    @Then("the response body should be {string}")
    fun checkBody(expectedBody: String) {
        assert(sdkResponse != null) { "Expected response but got error: $sdkError" }
        assert(sdkResponse!!.body == expectedBody) {
            "Body mismatch: expected $expectedBody, got ${sdkResponse!!.body}"
        }
    }

    @Then("the response header {string} should be {string}")
    fun checkHeader(name: String, value: String) {
        assert(sdkResponse != null) { "Expected response but got error: $sdkError" }
        val actual = sdkResponse!!.headers[name.lowercase()] ?: ""
        assert(actual == value) {
            "Header \"$name\" mismatch: expected \"$value\", got \"$actual\""
        }
    }

    @Then("the response should have multi-value header {string} with values {string}")
    fun checkMultiHeader(name: String, valuesStr: String) {
        assert(sdkResponse != null) { "Expected response but got error: $sdkError" }
        val expectedValues = valuesStr.split(",").sorted()
        val actual = sdkResponse!!.headers[name.lowercase()] ?: ""
        val actualValues = actual.split(",").map { it.trim() }.sorted()
        assert(actualValues == expectedValues) {
            "Multi-value header \"$name\" mismatch: expected $expectedValues, got $actualValues"
        }
    }

    @Then("the SDK should return error {string}")
    fun checkError(expectedCode: String) {
        assert(sdkError != null) { "Expected error \"$expectedCode\" but got response: $sdkResponse" }
        assert(sdkError!!.code == expectedCode) {
            "Error code mismatch: expected \"$expectedCode\", got \"${sdkError!!.code}\""
        }
    }

    @Then("the server should have received the correct request")
    fun checkCapture() {
        val captureFile = File(artifactsDir, "capture_$sourceId.json")
        assert(captureFile.exists()) { "Capture file not found for $sourceId" }

        val capture = JSONObject(captureFile.readText())

        // Verify method
        assert(capture.getString("method") == method) {
            "Captured method mismatch: expected $method, got ${capture.getString("method")}"
        }

        // Verify URL (basic check)
        val capturedUrl = capture.getString("url")
        val expectedPath = url.removePrefix("http://localhost:8081")
        assert(capturedUrl.contains(expectedPath.split("?")[0])) {
            "Captured URL mismatch: expected contains $url, got $capturedUrl"
        }

        // Verify headers (ignoring transport noise)
        val ignored = setOf(
            "user-agent", "host", "connection", "accept-encoding", "content-length",
            "x-source", "x-scenario-id", "accept", "keep-alive", "date",
            "transfer-encoding", "accept-language", "sec-fetch-mode",
            "sec-fetch-site", "sec-fetch-dest", "priority"
        )

        val expectedHeaders = headers
            .filter { it.key.lowercase() !in ignored }
            .map { it.key.lowercase() to it.value }
            .toMap()

        val capturedHeaders = mutableMapOf<String, String>()
        val capturedHeadersObj = capture.getJSONObject("headers")
        for (key in capturedHeadersObj.keys()) {
            if (key.lowercase() !in ignored) {
                capturedHeaders[key.lowercase()] = capturedHeadersObj.getString(key)
            }
        }

        assert(capturedHeaders == expectedHeaders) {
            "Captured headers mismatch: expected $expectedHeaders, got $capturedHeaders"
        }

        // Verify body
        val expectedBody = body ?: ""
        val capturedBody = capture.optString("body", "")
        // Simple comparison (multipart normalization omitted for brevity)
        assert(capturedBody == expectedBody) {
            "Captured body mismatch: expected '$expectedBody', got '$capturedBody'"
        }
    }
}
