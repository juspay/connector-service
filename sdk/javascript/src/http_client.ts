import { ProxyAgent, Agent, Dispatcher } from "undici";
// @ts-ignore
import { ucs } from "@generated/proto";

const Defaults = ucs.v2.SdkDefault;

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
 * Specialized error class for HTTP failures in the Connector Service.
 */
export class ConnectorError extends Error {
  constructor(
    public message: string,
    public statusCode?: number,
    public errorCode?: 'CONNECT_TIMEOUT' | 'RESPONSE_TIMEOUT' | 'TOTAL_TIMEOUT' | 'NETWORK_FAILURE' | 'INVALID_CONFIGURATION' | string,
    public body?: string,
    public headers?: Record<string, string>
  ) {
    super(message);
    this.name = "ConnectorError";
  }
}

const DISPATCHER_CACHE = new Map<string, Dispatcher>();
const TRANSPORT_DIRECT = "TRANSPORT_DIRECT";
const MAX_CACHE_SIZE = 100;

/**
 * Resolve proxy URL, honoring bypass rules.
 */
function resolveProxyUrl(url: string, proxy?: ucs.v2.IProxyOptions | null): string | null {
  if (!proxy) return null;
  const shouldBypass = Array.isArray(proxy.bypassUrls) && proxy.bypassUrls.includes(url);
  if (shouldBypass) return null;
  return proxy.httpsUrl || proxy.httpUrl || null;
}

/**
 * Creates a high-performance dispatcher with specialized fintech timeouts.
 */
function createDispatcher(proxyUrl: string | null, config: ucs.v2.IHttpOptions): Dispatcher {
  const dispatcherOptions: any = {
    connect: {
      timeout: config.connectTimeoutMs ?? Defaults.CONNECT_TIMEOUT_MS,
      ca: config.caCert,
    },
    headersTimeout: config.responseTimeoutMs ?? Defaults.RESPONSE_TIMEOUT_MS,
    bodyTimeout: config.responseTimeoutMs ?? Defaults.RESPONSE_TIMEOUT_MS,
    keepAliveTimeout: config.keepAliveTimeoutMs ?? Defaults.KEEP_ALIVE_TIMEOUT_MS,
  };

  try {
    return proxyUrl 
      ? new ProxyAgent({ uri: proxyUrl, ...dispatcherOptions })
      : new Agent(dispatcherOptions);
  } catch (error: any) {
    throw new ConnectorError(
      `Invalid HTTP Configuration: ${error.message}`,
      500,
      'INVALID_CONFIGURATION'
    );
  }
}

/**
 * Standardized network execution engine for Unified Connector Service.
 */
export async function execute(
  request: HttpRequest,
  options: ucs.v2.IHttpOptions = {}
): Promise<HttpResponse> {
  const { url, method, headers, body } = request;

  // 1. Connection Management
  const proxyUrl = resolveProxyUrl(url, options.proxy);
  const connectionKey = JSON.stringify({
    uri: proxyUrl || TRANSPORT_DIRECT,
    connect: options.connectTimeoutMs,
    res: options.responseTimeoutMs,
    ca: options.caCert?.length,
  });
  
  let dispatcher = DISPATCHER_CACHE.get(connectionKey);
  if (!dispatcher) {
    if (DISPATCHER_CACHE.size >= MAX_CACHE_SIZE) {
      const oldestKey = DISPATCHER_CACHE.keys().next().value;
      if (oldestKey) DISPATCHER_CACHE.delete(oldestKey);
    }
    dispatcher = createDispatcher(proxyUrl, options);
    DISPATCHER_CACHE.set(connectionKey, dispatcher);
  }

  // 2. Lifecycle Management
  const totalTimeout = options.totalTimeoutMs ?? Defaults.TOTAL_TIMEOUT_MS;
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), totalTimeout);

  const startTime = Date.now();

  try {
    const response = await fetch(url, {
      method: method.toUpperCase(),
      headers: headers || {},
      body: body ?? undefined,
      redirect: "manual",
      signal: controller.signal,
      // @ts-ignore
      dispatcher,
    });

    const responseHeaders: Record<string, string> = {};
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
        `Total Request Timeout: ${method} ${url} exceeded ${totalTimeout}ms`,
        504,
        'TOTAL_TIMEOUT'
      );
    }

    const cause = error.cause;
    if (cause) {
      if (cause.code === 'UND_ERR_CONNECT_TIMEOUT') {
        throw new ConnectorError(
          `Connection Timeout: Failed to connect to ${url}`, 
          504, 
          'CONNECT_TIMEOUT'
        );
      }
      if (cause.code === 'UND_ERR_BODY_TIMEOUT' || cause.code === 'UND_ERR_HEADERS_TIMEOUT') {
        throw new ConnectorError(
          `Response Timeout: Gateway ${url} accepted connection but failed to respond`, 
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
