package payments

import okhttp3.*
import okhttp3.Headers.Companion.toHeaders
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.IOException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit

data class HttpRequest(
    val url: String,
    val method: String,
    val headers: Map<String, String>? = null,
    val body: ByteArray? = null
)

data class HttpResponse(
    val statusCode: Int,
    val headers: Map<String, String>,
    val body: String,
    val latencyMs: Long
)

/**
 * Global HTTP Options matching the unified SDK standard.
 */
data class HttpOptions(
    val total_timeout_ms: Long = 45000L,
    val connect_timeout_ms: Long = 10000L,
    val response_timeout_ms: Long = 30000L,
    val keep_alive_timeout: Long = 60000L,
    val proxy: ProxyConfig? = null,
    val ca_cert: String? = null
)

data class ProxyConfig(
    val http_url: String? = null,
    val https_url: String? = null,
    val bypass_urls: List<String> = emptyList()
)

class ConnectorError(
    message: String,
    val statusCode: Int? = null,
    val errorCode: String? = null
) : Exception(message)

object HttpClient {
    private val clientCache = ConcurrentHashMap<String, OkHttpClient>()
    private const val MAX_CACHE_SIZE = 100

    private fun getClientKey(proxyUrl: String?, options: HttpOptions): String {
        return "proxy=$proxyUrl;connect=${options.connect_timeout_ms};response=${options.response_timeout_ms};ca=${options.ca_cert?.length}"
    }

    private fun createClient(proxyUrl: String?, options: HttpOptions): OkHttpClient {
        val builder = OkHttpClient.Builder()
            .connectTimeout(options.connect_timeout_ms, TimeUnit.MILLISECONDS)
            .readTimeout(options.response_timeout_ms, TimeUnit.MILLISECONDS)
            .writeTimeout(options.response_timeout_ms, TimeUnit.MILLISECONDS)
            .callTimeout(options.total_timeout_ms, TimeUnit.MILLISECONDS)
            .followRedirects(false)
            .followSslRedirects(false)

        if (proxyUrl != null) {
            val url = HttpUrl.parse(proxyUrl)
            if (url != null) {
                builder.proxy(java.net.Proxy(java.net.Proxy.Type.HTTP, java.net.InetSocketAddress(url.host(), url.port())))
            }
        }
        return builder.build()
    }

    fun execute(request: HttpRequest, options: HttpOptions = HttpOptions()): HttpResponse {
        val shouldBypass = options.proxy?.bypass_urls?.contains(request.url) ?: false
        val proxyUrl = if (options.proxy == null || shouldBypass) null 
                       else (options.proxy.https_url ?: options.proxy.http_url)

        val clientKey = getClientKey(proxyUrl, options)
        if (!clientCache.containsKey(clientKey)) {
            if (clientCache.size >= MAX_CACHE_SIZE) clientCache.clear()
            clientCache[clientKey] = createClient(proxyUrl, options)
        }
        
        val client = clientCache[clientKey]!!
        val okHeaders = request.headers?.toHeaders() ?: Headers.Builder().build()
        val mediaType = okHeaders["Content-Type"]?.let { MediaType.parse(it) }
        val requestBody = request.body?.toRequestBody(mediaType)
        
        val okRequest = Request.Builder()
            .url(request.url)
            .method(request.method.uppercase(), requestBody)
            .headers(okHeaders)
            .build()

        val startTime = System.currentTimeMillis()
        try {
            client.newCall(okRequest).execute().use { response ->
                val responseHeaders = mutableMapOf<String, String>()
                for (name in response.headers.names()) {
                    responseHeaders[name.lowercase()] = response.header(name) ?: ""
                }

                return HttpResponse(
                    statusCode = response.code,
                    headers = responseHeaders,
                    body = response.body?.string() ?: "",
                    latencyMs = System.currentTimeMillis() - startTime
                )
            }
        } catch (e: IOException) {
            val msg = e.message ?: ""
            if (msg.contains("timeout", ignoreCase = true)) {
                throw ConnectorError("Timeout calling ${request.url}", 504, "TIMEOUT")
            }
            throw ConnectorError("Network Error: ${e.message}", 500, "NETWORK_FAILURE")
        }
    }
}
