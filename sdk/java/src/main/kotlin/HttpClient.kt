package payments

import okhttp3.*
import okhttp3.Headers.Companion.toHeaders
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.IOException
import java.net.SocketTimeoutException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import ucs.v2.SdkOptions.HttpOptions
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

class ConnectorError(
    message: String,
    val statusCode: Int? = null,
    val errorCode: String? = null
) : Exception(message)

object HttpClient {
    private val clientCache = ConcurrentHashMap<String, OkHttpClient>()
    private const val MAX_CACHE_SIZE = 100

    private fun getClientKey(proxyUrl: String?, options: HttpOptions): String {
        return "proxy=$proxyUrl;connect=${options.connectTimeoutMs};response=${options.responseTimeoutMs};ca=${options.caCert?.size()}"
    }

    private fun createClient(proxyUrl: String?, options: HttpOptions): OkHttpClient {
        try {
            val builder = OkHttpClient.Builder()
                .connectTimeout(
                    (if (options.hasConnectTimeoutMs()) options.connectTimeoutMs else SdkDefault.CONNECT_TIMEOUT_MS_VALUE).toLong(), 
                    TimeUnit.MILLISECONDS
                )
                .readTimeout(
                    (if (options.hasResponseTimeoutMs()) options.responseTimeoutMs else SdkDefault.RESPONSE_TIMEOUT_MS_VALUE).toLong(), 
                    TimeUnit.MILLISECONDS
                )
                .writeTimeout(
                    (if (options.hasResponseTimeoutMs()) options.responseTimeoutMs else SdkDefault.RESPONSE_TIMEOUT_MS_VALUE).toLong(), 
                    TimeUnit.MILLISECONDS
                )
                .callTimeout(
                    (if (options.hasTotalTimeoutMs()) options.totalTimeoutMs else SdkDefault.TOTAL_TIMEOUT_MS_VALUE).toLong(), 
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
            throw ConnectorError("Invalid HTTP Configuration: ${e.message}", 500, "INVALID_CONFIGURATION")
        }
    }

    fun execute(request: HttpRequest, options: HttpOptions = HttpOptions.getDefaultInstance()): HttpResponse {
        val shouldBypass = options.proxy?.bypassUrlsList?.contains(request.url) ?: false
        val proxyUrl = if (!options.hasProxy() || shouldBypass) null 
                       else (if (options.proxy.hasHttpsUrl()) options.proxy.httpsUrl else options.proxy.httpUrl)

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
                    body = response.body?.bytes() ?: byteArrayOf(),
                    latencyMs = System.currentTimeMillis() - startTime
                )
            }
        } catch (e: IOException) {
            val msg = e.message?.lowercase() ?: ""
            val latency = System.currentTimeMillis() - startTime
            val totalTimeout = (if (options.hasTotalTimeoutMs()) options.totalTimeoutMs else SdkDefault.TOTAL_TIMEOUT_MS_VALUE).toLong()

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
