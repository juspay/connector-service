"use strict";

const { ProxyAgent, Agent } = require("undici");

/**
 * Global cache for network dispatchers to ensure optimal connection pooling.
 */
const DISPATCHER_CACHE = new Map();
const TRANSPORT_DIRECT = "TRANSPORT_DIRECT";

/**
 * Standard default configuration for the HTTP client.
 */
const DEFAULT_CONFIG = {
  keepAliveTimeout: 60000,
  keepAliveMaxTimeout: 600000,
  timeoutMs: 30000,
};

/**
 * Generates a stable key to identify a unique connection pool configuration.
 * @param {string|null} proxyUrl - Resolved proxy URL.
 * @param {Object} config - Connection pool settings.
 * @returns {string} Unique cache key.
 */
function getConnectionKey(proxyUrl, config) {
  const connectionIdentity = {
    uri: proxyUrl || TRANSPORT_DIRECT,
    keepAliveTimeout: config.keepAliveTimeout || DEFAULT_CONFIG.keepAliveTimeout,
    keepAliveMaxTimeout: config.keepAliveMaxTimeout || DEFAULT_CONFIG.keepAliveMaxTimeout,
  };
  return JSON.stringify(connectionIdentity);
}

/**
 * Creates a high-performance dispatcher.
 */
function createDispatcher(proxyUrl, config) {
  const options = {
    keepAliveTimeout: config.keepAliveTimeout || DEFAULT_CONFIG.keepAliveTimeout,
    keepAliveMaxTimeout: config.keepAliveMaxTimeout || DEFAULT_CONFIG.keepAliveMaxTimeout,
  };

  if (!proxyUrl) {
    return new Agent(options);
  }

  return new ProxyAgent({
    uri: proxyUrl,
    ...options,
  });
}

/**
 * Standardized network execution engine.
 *
 * @param {Object} request - The network request payload.
 * @param {string} request.url - Destination URL.
 * @param {string} request.method - HTTP Method (GET, POST, etc.).
 * @param {Object} request.headers - HTTP Headers.
 * @param {string|Object} [request.body] - Request body content.
 * 
 * @param {Object} [options] - Execution configuration.
 * @param {number} [options.timeoutMs] - Total request timeout in milliseconds.
 * @param {number} [options.keepAliveTimeout] - How long to keep idle connections alive (ms).
 * @param {number} [options.keepAliveMaxTimeout] - Maximum lifetime of a connection (ms).
 * @param {Object} [options.proxy] - Proxy configuration.
 * @param {string} [options.proxy.http_url] - HTTP Proxy URL.
 * @param {string} [options.proxy.https_url] - HTTPS Proxy URL.
 * @param {string[]} [options.proxy.bypass_urls] - List of URLs to route directly.
 * 
 * @returns {Promise<Object>} Normalized response (statusCode, headers, body).
 */
async function execute(request, options = {}) {
  const { url, method, headers, body } = request;

  // 1. Connection Management
  const proxy = options.proxy;
  const shouldBypassProxy = proxy && proxy.bypass_urls && proxy.bypass_urls.includes(url);
  
  const proxyUrl = (!proxy || shouldBypassProxy) 
    ? null 
    : (proxy.https_url || proxy.http_url);

  const connectionKey = getConnectionKey(proxyUrl, options);
  if (!DISPATCHER_CACHE.has(connectionKey)) {
    DISPATCHER_CACHE.set(connectionKey, createDispatcher(proxyUrl, options));
  }
  const dispatcher = DISPATCHER_CACHE.get(connectionKey);

  // 2. Lifecycle Management
  const controller = new AbortController();
  const timeoutId = setTimeout(
    () => controller.abort(), 
    options.timeoutMs || DEFAULT_CONFIG.timeoutMs
  );

  try {
    const response = await fetch(url, {
      method: String(method).toUpperCase(),
      headers: headers || {},
      body: body || undefined,
      redirect: options.redirect || "manual",
      signal: controller.signal,
      dispatcher,
    });

    const responseHeaders = {};
    response.headers.forEach((v, k) => { responseHeaders[k] = v; });

    return {
      statusCode: response.status,
      headers: responseHeaders,
      body: await response.text(),
    };
  } finally {
    clearTimeout(timeoutId);
  }
}

module.exports = { execute };
