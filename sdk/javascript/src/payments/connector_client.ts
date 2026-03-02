/**
 * ConnectorClient — high-level wrapper using UniFFI bindings via koffi.
 *
 * Handles the full round-trip:
 *   1. Serialize protobuf request to bytes
 *   2. Build connector HTTP request via authorizeReqTransformer (UniFFI FFI)
 *   3. Execute the HTTP request via our standardized HttpClient
 *   4. Parse the connector response via authorizeResTransformer (UniFFI FFI)
 *   5. Deserialize protobuf response from bytes
 */

import { UniffiClient } from "./uniffi_client";
import { execute, HttpOptions, HttpRequest } from "../http_client";
// @ts-ignore - protobuf generated files might not have types yet
import { ucs } from "./generated/proto";

const v2 = ucs.v2;

export class ConnectorClient {
  private _uniffi: UniffiClient;
  private _options: ucs.v2.IOptions;

  /**
   * @param libPath - optional path to the UniFFI shared library
   * @param options - unified SDK configuration from Protobuf (Options message)
   */
  constructor(libPath?: string, options: ucs.v2.IOptions = {}) {
    this._uniffi = new UniffiClient(libPath);
    this._options = options;
  }

  /**
   * Internal helper to map Protobuf HttpOptions to Native HttpClient options.
   */
  private _getNativeHttpOptions(): HttpOptions {
    const proto = this._options.http;
    if (!proto) return {};

    return {
      totalTimeoutMs: proto.totalTimeoutMs ?? undefined,
      connectTimeoutMs: proto.connect_timeout_ms ?? undefined,
      responseTimeoutMs: proto.response_timeout_ms ?? undefined,
      keepAliveTimeoutMs: proto.keep_alive_timeout_ms ?? undefined,
      proxy: proto.proxy ? {
        httpUrl: proto.proxy.httpUrl ?? undefined,
        httpsUrl: proto.proxy.httpsUrl ?? undefined,
        bypassUrls: proto.proxy.bypassUrls ?? undefined,
      } : undefined,
      caCert: proto.caCert ?? undefined,
    };
  }

  /**
   * Execute a full authorize round-trip.
   * @param requestMsg - PaymentServiceAuthorizeRequest message
   * @param metadata - Dict with connector routing and auth info. Must include:
   *                 - "connector": connector name (e.g. "Stripe")
   *                 - "connector_auth_type": JSON string of auth config
   *                 - x-* headers for masked metadata
   * @param ffiOptions - optional IFfiOptions message override
   * @returns decoded PaymentServiceAuthorizeResponse message
   */
  async authorize(
    requestMsg: ucs.v2.IPaymentServiceAuthorizeRequest, 
    metadata: Record<string, string>, 
    ffiOptions?: ucs.v2.IFfiOptions | null
  ): Promise<ucs.v2.PaymentServiceAuthorizeResponse> {
    // 1. Serialize request to bytes
    const requestBytes = Buffer.from(
      v2.PaymentServiceAuthorizeRequest.encode(requestMsg).finish()
    );

    // 2. Resolve FFI options (prefer call-specific, fallback to client-global)
    const ffi = ffiOptions || this._options.ffi;
    const optionsBytes = ffi 
      ? Buffer.from(v2.FfiOptions.encode(ffi).finish()) 
      : Buffer.alloc(0);

    // 3. Build the connector HTTP request via FFI bridge (returns Protobuf bytes)
    const resultBytes = this._uniffi.authorizeReq(requestBytes, metadata, optionsBytes);
    const connectorReq = v2.FfiConnectorHttpRequest.decode(resultBytes);

    const connectorRequest: HttpRequest = {
      url: connectorReq.url,
      method: connectorReq.method,
      headers: connectorReq.headers || {},
      body: connectorReq.body ?? undefined
    };

    // 4. Execute the HTTP request (uses Global HttpOptions mapped to Native)
    const response = await execute(connectorRequest, this._getNativeHttpOptions());

    // 5. Parse the connector response via FFI bridge
    // Serialize native response to FFI-internal Protobuf record (Safe)
    const resProto = v2.FfiConnectorHttpResponse.create({
      statusCode: response.statusCode,
      headers: response.headers,
      body: response.body
    });
    const resBytes = Buffer.from(v2.FfiConnectorHttpResponse.encode(resProto).finish());

    const resultBytesRes = this._uniffi.authorizeRes(
      resBytes,
      requestBytes,
      metadata,
      optionsBytes
    );

    // 6. Decode the protobuf response from bytes
    return v2.PaymentServiceAuthorizeResponse.decode(resultBytesRes);
  }
}
