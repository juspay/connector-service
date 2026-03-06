package payments

import okhttp3.*
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.Headers.Companion.toHeaders
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.IOException
import java.net.SocketTimeoutException
import java.util.concurrent.TimeUnit
import ucs.v2.SdkConfig.HttpDefault

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
    /**
     * Creates a high-performance OkHttpClient. (The instance-level connection pool)
     * Infrastructure settings (Proxy) are fixed here.
     */
    fun createClient(config: HttpConfig?): OkHttpClient {
        try {
            val builder = OkHttpClient.Builder()
                .followRedirects(false)
                .followSslRedirects(false)

            val timeouts = if (config != null && config.hasTimeouts()) config.timeouts else null
            
            // Set Instance Defaults
            builder.connectTimeout(
                if (timeouts?.hasConnectTimeoutMs() == true) timeouts.connectTimeoutMs.toLong() else HttpDefault.CONNECT_TIMEOUT_MS_VALUE.toLong(), 
                TimeUnit.MILLISECONDS
            )
            builder.readTimeout(
                if (timeouts?.hasResponseTimeoutMs() == true) timeouts.responseTimeoutMs.toLong() else HttpDefault.RESPONSE_TIMEOUT_MS_VALUE.toLong(), 
                TimeUnit.MILLISECONDS
            )
            builder.callTimeout(
                if (timeouts?.hasTotalTimeoutMs() == true) timeouts.totalTimeoutMs.toLong() else HttpDefault.TOTAL_TIMEOUT_MS_VALUE.toLong(), 
                TimeUnit.MILLISECONDS
            )

            // Configure Proxy (Client Level)
            if (config?.hasProxy() == true) {
                configureProxy(builder, config.proxy)
            }
            
            return builder.build()
        } catch (e: Exception) {
            throw ConnectorError("Internal HTTP setup failed: ${e.message}", 500, "CLIENT_INITIALIZATION")
        }
    }

    private fun configureProxy(builder: OkHttpClient.Builder, p: ProxyOptions) {
        val proxyUrl = p.httpsUrl.takeIf { it.isNotEmpty() } ?: p.httpUrl.takeIf { it.isNotEmpty() }
        if (proxyUrl == null) return

        val url = proxyUrl.toHttpUrlOrNull() ?: return
        
        // Standard Java Proxy
        val proxy = java.net.Proxy(java.net.Proxy.Type.HTTP, java.net.InetSocketAddress(url.host, url.port))
        builder.proxy(proxy)
        
        // Bypass logic (Selector)
        if (p.bypassUrlsCount > 0) {
            val bypassList = p.bypassUrlsList
            builder.proxySelector(object : java.net.ProxySelector() {
                override fun select(uri: java.net.URI): List<java.net.Proxy> {
                    val host = uri.host ?: ""
                    if (bypassList.any { host.endsWith(it) }) {
                        return listOf(java.net.Proxy.NO_PROXY)
                    }
                    return listOf(proxy)
                }
                override fun connectFailed(uri: java.net.URI, sa: java.net.SocketAddress, ioe: IOException) {}
            })
        }
    }

    /**
     * Executes a request using the provided client, allowing per-call timeout overrides.
     */
    fun execute(request: HttpRequest, timeoutConfig: HttpTimeoutConfig?, client: OkHttpClient): HttpResponse {
        val okHeaders = request.headers?.toHeaders() ?: Headers.Builder().build()
        val mediaType = okHeaders["Content-Type"]?.toMediaTypeOrNull()
        val requestBody = request.body?.toRequestBody(mediaType)
        
        // Build the request
        val okRequest = Request.Builder()
            .url(request.url)
            .method(request.method.uppercase(), requestBody)
            .headers(okHeaders)
            .build()

        // Per-call Timeout Overrides
        var callClient = client
        if (timeoutConfig != null) {
            val builder = client.newBuilder()
            if (timeoutConfig.hasConnectTimeoutMs()) {
                builder.connectTimeout(timeoutConfig.connectTimeoutMs.toLong(), TimeUnit.MILLISECONDS)
            }
            if (timeoutConfig.hasResponseTimeoutMs()) {
                builder.readTimeout(timeoutConfig.responseTimeoutMs.toLong(), TimeUnit.MILLISECONDS)
                builder.writeTimeout(timeoutConfig.responseTimeoutMs.toLong(), TimeUnit.MILLISECONDS)
            }
            if (timeoutConfig.hasTotalTimeoutMs()) {
                builder.callTimeout(timeoutConfig.totalTimeoutMs.toLong(), TimeUnit.MILLISECONDS)
            }
            callClient = builder.build()
        }

        val startTime = System.currentTimeMillis()
        try {
            callClient.newCall(okRequest).execute().use { response ->
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
            val totalTimeout = if (timeoutConfig?.hasTotalTimeoutMs() == true) {
                timeoutConfig.totalTimeoutMs.toLong()
            } else {
                HttpDefault.TOTAL_TIMEOUT_MS_VALUE.toLong()
            }

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
