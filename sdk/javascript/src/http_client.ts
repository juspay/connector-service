import { ProxyAgent, Agent, Dispatcher } from "undici";
// @ts-ignore
import { ucs } from "./payments/generated/proto";

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
  latencyMs: number; // Flat field for cross-language parity
}

/**
 * HTTP client configuration options.
 * Uses proto-generated IHttpOptions as the base, with extended caCert type
 * for better developer experience (accepts string, Buffer, or Uint8Array).
 */
export type HttpOptions = Omit<ucs.v2.IHttpOptions, 'caCert'> & {
  caCert?: string | Buffer | Uint8Array;
};

/**
 * Specialized error class for HTTP failures in the Connector Service.
 */
export class ConnectorError extends Error {
  constructor(
    public message: string,
    public statusCode?: number,
    public errorCode?: 'CONNECT_TIMEOUT' | 'RESPONSE_TIMEOUT' | 'TOTAL_TIMEOUT' | 'NETWORK_FAILURE' | 'INVALID_CONFIGURATION' | 'CLIENT_INITIALIZATION' | string,
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
export function resolveProxyUrl(url: string, proxy?: HttpOptions["proxy"]): string | null {
  if (!proxy) return null;
  const shouldBypass = Array.isArray(proxy.bypassUrls) && proxy.bypassUrls.includes(url);
  if (shouldBypass) return null;
  return proxy.httpsUrl || proxy.httpUrl || null;
}

/**
 * Creates a high-performance dispatcher with specialized fintech timeouts.
 * (The instance-level connection pool)
 */
export function createDispatcher(config: HttpOptions): Dispatcher {
  // Convert caCert to Uint8Array if provided as string or Buffer
  let caCert: Uint8Array | undefined;
  if (config.caCert !== undefined) {
    if (typeof config.caCert === 'string') {
      caCert = new TextEncoder().encode(config.caCert);
    } else if (Buffer.isBuffer(config.caCert)) {
      caCert = new Uint8Array(config.caCert);
    } else {
      caCert = config.caCert;
    }
  }

  const dispatcherOptions: any = {
    connect: {
      timeout: config.connectTimeoutMs ?? Defaults.CONNECT_TIMEOUT_MS,
      ca: caCert,
    },
    headersTimeout: config.responseTimeoutMs ?? Defaults.RESPONSE_TIMEOUT_MS,
    bodyTimeout: config.responseTimeoutMs ?? Defaults.RESPONSE_TIMEOUT_MS,
    keepAliveTimeout: config.keepAliveTimeoutMs ?? Defaults.KEEP_ALIVE_TIMEOUT_MS,
  };

  try {
    const proxyUrl = config.proxy?.httpsUrl || config.proxy?.httpUrl;
    return proxyUrl
      ? new ProxyAgent({ uri: proxyUrl, ...dispatcherOptions })
      : new Agent(dispatcherOptions);
  } catch (error: any) {
    throw new ConnectorError(
      `Internal HTTP setup failed: ${error.message}`,
      500,
      'CLIENT_INITIALIZATION'
    );
  }
}

/**
 * Standardized network execution engine for Unified Connector Service.
 */
export async function execute(
  request: HttpRequest,
  options: HttpOptions = {},
  dispatcher?: Dispatcher // Pass the instance-owned pool here
): Promise<HttpResponse> {
  const { url, method, headers, body } = request;

  // Lifecycle Management
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
      latencyMs: Date.now() - startTime
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
