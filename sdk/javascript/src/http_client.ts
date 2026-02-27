import { ProxyAgent, Agent, Dispatcher } from "undici";

/**
 * Normalized HTTP Request structure for the Connector Service.
 */
export interface HttpRequest {
  url: string;
  method: string;
  headers?: Record<string, string>;
  body?: string | Uint8Array;
}

/**
 * Normalized HTTP Response structure.
 */
export interface HttpResponse {
  statusCode: number;
  headers: Record<string, string>;
  body: Uint8Array;
  meta: {
    latencyMs: number;
  };
}

/**
 * Configuration options for the network transport layer.
 */
export interface HttpOptions {
  total_timeout_ms?: number; 
  connect_timeout_ms?: number; 
  response_timeout_ms?: number; 
  keep_alive_timeout?: number;
  proxy?: {
    http_url?: string;
    https_url?: string;
    bypass_urls?: string[];
  };
  ca_cert?: string | Buffer;
}

/**
 * Specialized error class for HTTP failures in the Connector Service.
 */
export class ConnectorError extends Error {
  constructor(
    public message: string,
    public statusCode?: number,
    public errorCode?: string,
    public body?: string,
    public headers?: Record<string, string>
  ) {
    super(message);
    this.name = "ConnectorError";
  }
}

const DISPATCHER_CACHE = new Map<string, Dispatcher>();
const TRANSPORT_DIRECT = "TRANSPORT_DIRECT";
const MAX_CACHE_SIZE = 100; // Prevent OOM by capping unique connection pools

const DEFAULT_CONFIG = {
  total_timeout_ms: 45_000,
  connect_timeout_ms: 10_000,
  response_timeout_ms: 30_000,
  keep_alive_timeout: 60_000,
};

/**
 * Normalize execution options by applying defaults.
 */
function normalizeOptions(options: HttpOptions): HttpOptions {
  return {
    ...options,
    total_timeout_ms: options.total_timeout_ms ?? DEFAULT_CONFIG.total_timeout_ms,
    connect_timeout_ms: options.connect_timeout_ms ?? DEFAULT_CONFIG.connect_timeout_ms,
    response_timeout_ms: options.response_timeout_ms ?? DEFAULT_CONFIG.response_timeout_ms,
    keep_alive_timeout: options.keep_alive_timeout ?? DEFAULT_CONFIG.keep_alive_timeout,
  };
}

/**
 * Resolve proxy URL, honoring bypass rules.
 */
function resolveProxyUrl(url: string, proxy?: HttpOptions["proxy"]): string | null {
  if (!proxy) return null;

  const shouldBypass = Array.isArray(proxy.bypass_urls) && proxy.bypass_urls.includes(url);
  if (shouldBypass) return null;

  return proxy.https_url || proxy.http_url || null;
}

/**
 * Generates a stable key to identify a unique connection pool configuration.
 */
function getConnectionKey(proxyUrl: string | null, config: HttpOptions): string {
  return JSON.stringify({
    uri: proxyUrl || TRANSPORT_DIRECT,
    connect_timeout_ms: config.connect_timeout_ms,
    response_timeout_ms: config.response_timeout_ms,
    caLength: config.ca_cert?.length,
  });
}

/**
 * Creates a high-performance dispatcher with specialized fintech timeouts.
 */
function createDispatcher(proxyUrl: string | null, config: HttpOptions): Dispatcher {
  const responseTimeout = config.response_timeout_ms;
  
  const dispatcherOptions: any = {
    connect: {
      timeout: config.connect_timeout_ms,
      ca: config.ca_cert,
    },
    headersTimeout: responseTimeout,
    bodyTimeout: responseTimeout,
    keepAliveTimeout: config.keep_alive_timeout,
  };

  return proxyUrl 
    ? new ProxyAgent({ uri: proxyUrl, ...dispatcherOptions })
    : new Agent(dispatcherOptions);
}

/**
 * Standardized network execution engine for Unified Connector Service.
 */
export async function execute(
  request: HttpRequest,
  options: HttpOptions = {}
): Promise<HttpResponse> {
  const { url, method, headers, body } = request;
  const config = normalizeOptions(options);

  // 1. Connection Management
  const proxyUrl = resolveProxyUrl(url, config.proxy);
  const connectionKey = getConnectionKey(proxyUrl, config);
  
  let dispatcher = DISPATCHER_CACHE.get(connectionKey);
  if (!dispatcher) {
    // Eviction strategy: Remove oldest dispatcher if cache is full (FIFO)
    if (DISPATCHER_CACHE.size >= MAX_CACHE_SIZE) {
      const oldestKey = DISPATCHER_CACHE.keys().next().value;
      if (oldestKey) DISPATCHER_CACHE.delete(oldestKey);
    }

    dispatcher = createDispatcher(proxyUrl, config);
    DISPATCHER_CACHE.set(connectionKey, dispatcher);
  }

  // 2. Lifecycle Management
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), config.total_timeout_ms);

  const startTime = Date.now();

  try {
    const response = await fetch(url, {
      method: method.toUpperCase(),
      headers: headers || {},
      body: body ?? undefined,
      redirect: "manual",
      signal: controller.signal,
      // @ts-ignore - undici dispatcher is supported in Node.js fetch
      dispatcher,
    });

    const responseHeaders: Record<string, string> = {};
    // Normalize response headers to lowercase for global parity
    response.headers.forEach((v, k) => { responseHeaders[k.toLowerCase()] = v; });

    return {
      statusCode: response.status,
      headers: responseHeaders,
      body: new Uint8Array(await response.arrayBuffer()),
      meta: { latencyMs: Date.now() - startTime }
    };
  } catch (error: any) {
    if (error.name === 'AbortError') {
      throw new ConnectorError(
        `Total Request Timeout: ${method} ${url} exceeded ${config.total_timeout_ms}ms`,
        504,
        'TOTAL_TIMEOUT'
      );
    }

    const cause = error.cause;
    if (cause) {
      if (cause.code === 'UND_ERR_CONNECT_TIMEOUT') {
        throw new ConnectorError(
          `Connection Timeout: Failed to connect to ${url} within ${config.connect_timeout_ms}ms`, 
          504, 
          'CONNECT_TIMEOUT'
        );
      }
      if (cause.code === 'UND_ERR_BODY_TIMEOUT' || cause.code === 'UND_ERR_HEADERS_TIMEOUT') {
        throw new ConnectorError(
          `Response Timeout: Gateway ${url} accepted connection but failed to respond within ${config.response_timeout_ms}ms`, 
          504, 
          'RESPONSE_TIMEOUT'
        );
      }
    }

    throw new ConnectorError(`Network Error: ${error.message}`, 500, error.code || 'NETWORK_FAILURE');
  } finally {
    clearTimeout(timeoutId);
  }
}
