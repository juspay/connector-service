import { ProxyAgent, Agent, Dispatcher } from "undici";
// @ts-ignore
import { types } from "./payments/generated/proto";

const Defaults = types.HttpDefault;

/**
 * Normalized HTTP Request structure for the Connector Service.
 */
export interface HttpRequest {
  url: string;
  method: string;
  headers?: Record<string, string>;
  body?: Uint8Array;
}

/**
 * Normalized HTTP Response structure.
 */
export interface HttpResponse {
  statusCode: number;
  headers: Record<string, string>;
  body: Uint8Array;
  latencyMs: number; // Flat field for cross-language parity
}

/**
 * Specialized error class for HTTP failures in the Connector Service.
 */
export class ConnectorError extends Error {
  constructor(
    public message: string,
    public statusCode?: number,
    public errorCode?: 'CONNECT_TIMEOUT' | 'RESPONSE_TIMEOUT' | 'TOTAL_TIMEOUT' | 'NETWORK_FAILURE' | 'INVALID_CONFIGURATION' | 'CLIENT_INITIALIZATION' | 'URL_PARSING_FAILED' | 'RESPONSE_DECODING_FAILED' | 'INVALID_PROXY_CONFIGURATION' | string,
    public body?: string,
    public headers?: Record<string, string>
  ) {
    super(message);
    this.name = "ConnectorError";
  }
}

/**
 * Resolve proxy URL, honoring bypass rules.
 */
export function resolveProxyUrl(url: string, proxy?: types.IProxyOptions | null): string | null {
  if (!proxy) return null;
  const shouldBypass = Array.isArray(proxy.bypassUrls) && proxy.bypassUrls.includes(url);
  if (shouldBypass) return null;
  return proxy.httpsUrl || proxy.httpUrl || null;
}

/**
 * Creates a high-performance dispatcher with specialized fintech timeouts.
 * (The instance-level connection pool)
 */
export function createDispatcher(config: types.IHttpConfig): Dispatcher {
  let ca: string | Uint8Array | undefined;
  if (config.caCert) {
    if (config.caCert.pem) {
      ca = config.caCert.pem;
    } else if (config.caCert.der) {
      ca = config.caCert.der;
    }
  }

  const dispatcherOptions: any = {
    connect: {
      timeout: config.connectTimeoutMs ?? Defaults.CONNECT_TIMEOUT_MS,
      ca,
    },
    headersTimeout: config.responseTimeoutMs ?? Defaults.RESPONSE_TIMEOUT_MS,
    bodyTimeout: config.responseTimeoutMs ?? Defaults.RESPONSE_TIMEOUT_MS,
    keepAliveTimeout: config.keepAliveTimeoutMs ?? Defaults.KEEP_ALIVE_TIMEOUT_MS,
  };

  const proxyUrl = config.proxy?.httpsUrl || config.proxy?.httpUrl;
  try {
    return proxyUrl
      ? new ProxyAgent({ uri: proxyUrl, ...dispatcherOptions })
      : new Agent(dispatcherOptions);
  } catch (error: any) {
    // If we were attempting proxy setup, any constructor failure is a proxy config error.
    const code = proxyUrl ? 'INVALID_PROXY_CONFIGURATION' : 'CLIENT_INITIALIZATION';
    throw new ConnectorError(
      `Internal HTTP setup failed: ${error.message}`,
      500,
      code
    );
  }
}

/**
 * Standardized network execution engine for Unified Connector Service.
 */
export async function execute(
  request: HttpRequest,
  options: types.IHttpConfig = {},
  dispatcher?: Dispatcher // Pass the instance-owned pool here
): Promise<HttpResponse> {
  const { url, method, headers, body } = request;

  try {
    new URL(url);
  } catch {
    throw new ConnectorError(`Invalid URL: ${url}`, undefined, 'URL_PARSING_FAILED');
  }

  const totalTimeout = options.totalTimeoutMs ?? Defaults.TOTAL_TIMEOUT_MS;
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), totalTimeout);

  const startTime = Date.now();

  try {
    const response = await fetch(url, {
      method: method.toUpperCase(),
      headers: headers || {},
      body: body ? Buffer.from(body) : undefined,
      redirect: "manual",
      signal: controller.signal,
      // @ts-ignore
      dispatcher,
    });

    const responseHeaders: Record<string, string> = {};
    response.headers.forEach((v, k) => { responseHeaders[k.toLowerCase()] = v; });

    let responseBody: Uint8Array;
    try {
      responseBody = new Uint8Array(await response.arrayBuffer());
    } catch (e: any) {
      throw new ConnectorError(`Failed to read response body: ${e?.message || e}`, response.status, 'RESPONSE_DECODING_FAILED');
    }

    return {
      statusCode: response.status,
      headers: responseHeaders,
      body: responseBody,
      latencyMs: Date.now() - startTime
    };
  } catch (error: any) {
    if (error instanceof ConnectorError) throw error;
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
