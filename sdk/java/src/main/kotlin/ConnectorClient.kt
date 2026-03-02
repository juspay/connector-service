/**
 * ConnectorClient — high-level wrapper around UniFFI FFI bindings.
 *
 * Handles the full round-trip for any payment flow:
 *   1. Build connector HTTP request via {flow}_req_transformer (FFI)
 *   2. Execute the HTTP request via OkHttp
 *   3. Parse the connector response via {flow}_res_transformer (FFI)
 *
 * Flow methods (authorize, capture, void, refund, …) are defined as Kotlin
 * extension functions in GeneratedFlows.kt — no flow names are hardcoded here.
 * To add a new flow: edit sdk/flows.yaml and run `make codegen`.
 */

import com.google.protobuf.MessageLite
import com.google.protobuf.Parser
import okhttp3.Headers.Companion.toHeaders
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject

class ConnectorClient {

    private val httpClient = OkHttpClient()

    /**
     * Execute a full round-trip for any payment flow.
     *
     * @param flow Flow name matching the FFI transformer prefix (e.g. "authorize").
     * @param requestBytes Serialized protobuf request bytes.
     * @param responseParser Protobuf parser for the expected response type.
     * @param metadata Map with connector routing and auth info.
     * @param optionsBytes Optional FfiOptions serialized to bytes. Pass empty byte array or null for default.
     * @return Parsed protobuf response.
     */
    fun <T : MessageLite> executeFlow(
        flow: String,
        requestBytes: ByteArray,
        responseParser: Parser<T>,
        metadata: Map<String, String>,
        optionsBytes: ByteArray? = null,
    ): T {
        val reqTransformer = FlowRegistry.reqTransformers[flow]
            ?: error("Unknown flow: '$flow'. Add it to sdk/flows.yaml and run `make codegen`.")
        val resTransformer = FlowRegistry.resTransformers[flow]
            ?: error("Unknown flow: '$flow'. Add it to sdk/flows.yaml and run `make codegen`.")

        // Use provided bytes or default to empty byte array
        val opts = optionsBytes ?: ByteArray(0)

        val connectorRequestJson = reqTransformer(requestBytes, metadata, opts)
        val connectorRequest = JSONObject(connectorRequestJson)

        val url = connectorRequest.getString("url")
        val method = connectorRequest.getString("method")

        val headersObj = connectorRequest.optJSONObject("headers") ?: JSONObject()
        val headersMap = mutableMapOf<String, String>()
        for (key in headersObj.keys()) {
            headersMap[key] = headersObj.getString(key)
        }

        val body = connectorRequest.opt("body")?.toString()
        val requestBody = body?.toRequestBody(headersMap["Content-Type"]?.toMediaTypeOrNull())

        val httpRequest = Request.Builder()
            .url(url)
            .method(method, requestBody)
            .headers(headersMap.toHeaders())
            .build()

        val response = httpClient.newCall(httpRequest).execute()

        val responseBody = response.body?.string() ?: ""
        val responseHeaders = mutableMapOf<String, String>()
        for (name in response.headers.names()) {
            responseHeaders[name] = response.header(name) ?: ""
        }

        val resultBytes = resTransformer(
            responseBody.toByteArray(Charsets.UTF_8),
            response.code.toUShort(),
            responseHeaders,
            requestBytes,
            metadata,
            opts,
        )

        return responseParser.parseFrom(resultBytes)
    }
}
