package payments

import okhttp3.*
import okhttp3.Headers.Companion.toHeaders
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.IOException
import java.net.SocketTimeoutException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import ucs.v2.SdkOptions.SdkDefault

data class HttpRequest(
    val url: String,
    val method: String,
    val headers: Map<String, String>? = null,
    val body: ByteArray? = null
)

data class HttpResponse(
    val statusCode: Int,
    val headers: Map<String, String>,
    val body: ByteArray,
    val latencyMs: Long
)

/**
 * Native configuration options for the network transport layer.
 * Decoupled from Protobuf for reuse and portability.
 */
data class HttpOptions(
    val totalTimeoutMs: Long? = null,
    val connectTimeoutMs: Long? = null,
    val responseTimeoutMs: Long? = null,
    val keepAliveTimeoutMs: Long? = null,
    val proxy: ProxyConfig? = null,
    val caCert: ByteArray? = null
)

data class ProxyConfig(
    val httpUrl: String? = null,
    val httpsUrl: String? = null,
    val bypassUrls: List<String> = emptyList()
)

class ConnectorError(
    message: String,
    val statusCode: Int? = null,
    val errorCode: String? = null
) : Exception(message)

object HttpClient {
    private val clientCache = ConcurrentHashMap<String, OkHttpClient>()
    private const val MAX_CACHE_SIZE = 100

    /**
     * Resolve proxy URL, honoring bypass rules.
     */
    fun resolveProxyUrl(url: String, proxy: ProxyConfig?): String? {
        if (proxy == null) return null
        if (proxy.bypassUrls.contains(url)) return null
        return proxy.httpsUrl ?: proxy.httpUrl
    }

    /**
     * Generates a stable key to identify a unique connection pool configuration.
     */
    private fun getClientKey(proxyUrl: String?, options: HttpOptions): String {
        return "proxy=$proxyUrl;connect=${options.connectTimeoutMs};response=${options.responseTimeoutMs};ca=${options.caCert?.size}"
    }

    private fun createClient(proxyUrl: String?, options: HttpOptions): OkHttpClient {
        try {
            val builder = OkHttpClient.Builder()
                .connectTimeout(
                    options.connectTimeoutMs ?: SdkDefault.CONNECT_TIMEOUT_MS_VALUE.toLong(), 
                    TimeUnit.MILLISECONDS
                )
                .readTimeout(
                    options.responseTimeoutMs ?: SdkDefault.RESPONSE_TIMEOUT_MS_VALUE.toLong(), 
                    TimeUnit.MILLISECONDS
                )
                .writeTimeout(
                    options.responseTimeoutMs ?: SdkDefault.RESPONSE_TIMEOUT_MS_VALUE.toLong(), 
                    TimeUnit.MILLISECONDS
                )
                .callTimeout(
                    options.totalTimeoutMs ?: SdkDefault.TOTAL_TIMEOUT_MS_VALUE.toLong(), 
                    TimeUnit.MILLISECONDS
                )
                .followRedirects(false)
                .followSslRedirects(false)

            if (proxyUrl != null) {
                val url = HttpUrl.parse(proxyUrl)
                if (url != null) {
                    builder.proxy(java.net.Proxy(java.net.Proxy.Type.HTTP, java.net.InetSocketAddress(url.host(), url.port())))
                } else {
                    throw Exception("Invalid Proxy URL: $proxyUrl")
                }
            }
            return builder.build()
        } catch (e: Exception) {
            throw ConnectorError("Internal HTTP setup failed: ${e.message}", 500, "CLIENT_INITIALIZATION")
        }
    }

    fun execute(request: HttpRequest, options: HttpOptions = HttpOptions()): HttpResponse {
        val proxyUrl = resolveProxyUrl(request.url, options.proxy)
        val clientKey = getClientKey(proxyUrl, options)
        
        if (!clientCache.containsKey(clientKey)) {
            // Eviction strategy: Remove oldest if cache is full (FIFO attempt)
            if (clientCache.size >= MAX_CACHE_SIZE) {
                val oldestKey = clientCache.keys().nextElement()
                if (oldestKey != null) clientCache.remove(oldestKey)
            }
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
                    body = response.body?.bytes() ?: byteArrayOf(),
                    latencyMs = System.currentTimeMillis() - startTime
                )
            }
        } catch (e: IOException) {
            val msg = e.message?.lowercase() ?: ""
            val latency = System.currentTimeMillis() - startTime
            val totalTimeout = options.totalTimeoutMs ?: SdkDefault.TOTAL_TIMEOUT_MS_VALUE.toLong()

            when {
                msg.contains("timeout") && latency >= totalTimeout -> {
                    throw ConnectorError("Total Request Timeout: ${request.url} exceeded ${totalTimeout}ms", 504, "TOTAL_TIMEOUT")
                }
                msg.contains("connect") -> {
                    throw ConnectorError("Connection Timeout: Failed to connect to ${request.url}", 504, "CONNECT_TIMEOUT")
                }
                msg.contains("read") || msg.contains("write") || e is SocketTimeoutException -> {
                    throw ConnectorError("Response Timeout: Gateway ${request.url} accepted connection but failed to respond", 504, "RESPONSE_TIMEOUT")
                }
                else -> {
                    throw ConnectorError("Network Error: ${e.message}", 500, "NETWORK_FAILURE")
                }
            }
        }
    }
}
