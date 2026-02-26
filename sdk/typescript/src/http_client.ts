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
  body: string;
  meta: {
    latencyMs: number;
  };
}

/**
 * Configuration options for the network transport layer.
 */
export interface HttpOptions {
  totalTimeoutMs?: number; 
  connectTimeoutMs?: number; 
  responseTimeoutMs?: number; 
  
  keepAliveTimeout?: number;
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
  totalTimeoutMs: 45_000,
  connectTimeoutMs: 10_000,
  responseTimeoutMs: 30_000,
  keepAliveTimeout: 60_000,
};

/**
 * Normalize execution options by applying defaults.
 */
function normalizeOptions(options: HttpOptions): HttpOptions {
  return {
    ...options,
    totalTimeoutMs: options.totalTimeoutMs ?? DEFAULT_CONFIG.totalTimeoutMs,
    connectTimeoutMs: options.connectTimeoutMs ?? DEFAULT_CONFIG.connectTimeoutMs,
    responseTimeoutMs: options.responseTimeoutMs ?? DEFAULT_CONFIG.responseTimeoutMs,
    keepAliveTimeout: options.keepAliveTimeout ?? DEFAULT_CONFIG.keepAliveTimeout,
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
    connectTimeoutMs: config.connectTimeoutMs,
    responseTimeoutMs: config.responseTimeoutMs,
    caLength: config.ca_cert?.length,
  });
}

/**
 * Creates a high-performance dispatcher with specialized fintech timeouts.
 */
function createDispatcher(proxyUrl: string | null, config: HttpOptions): Dispatcher {
  const responseTimeout = config.responseTimeoutMs;
  
  const dispatcherOptions: any = {
    connect: {
      timeout: config.connectTimeoutMs,
      ca: config.ca_cert,
    },
    headersTimeout: responseTimeout,
    bodyTimeout: responseTimeout,
    keepAliveTimeout: config.keepAliveTimeout,
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
  const timeoutId = setTimeout(() => controller.abort(), config.totalTimeoutMs);

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

    return {
      statusCode: response.status,
      headers: Object.fromEntries(response.headers.entries()),
      body: await response.text(),
      meta: { latencyMs: Date.now() - startTime }
    };
  } catch (error: any) {
    if (error.name === 'AbortError') {
      throw new ConnectorError(
        `Total Request Timeout: ${method} ${url} exceeded ${config.totalTimeoutMs}ms`,
        504,
        'TOTAL_TIMEOUT'
      );
    }

    const cause = error.cause;
    if (cause) {
      if (cause.code === 'UND_ERR_CONNECT_TIMEOUT') {
        throw new ConnectorError(
          `Connection Timeout: Failed to connect to ${url} within ${config.connectTimeoutMs}ms`, 
          504, 
          'CONNECT_TIMEOUT'
        );
      }
      if (cause.code === 'UND_ERR_BODY_TIMEOUT' || cause.code === 'UND_ERR_HEADERS_TIMEOUT') {
        throw new ConnectorError(
          `Response Timeout: Gateway ${url} accepted connection but failed to respond within ${config.responseTimeoutMs}ms`, 
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
