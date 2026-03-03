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

import { Dispatcher } from "undici";
import { UniffiClient } from "./uniffi_client";
import { execute, createDispatcher, HttpOptions, HttpRequest } from "../http_client";
// @ts-ignore - protobuf generated files might not have types yet
import { ucs } from "./generated/proto";

const v2 = ucs.v2;

export class ConnectorClient {
  private uniffi: UniffiClient;
  private options: ucs.v2.IOptions;
  private dispatcher: Dispatcher;

  /**
   * @param libPath - optional path to the UniFFI shared library
   * @param options - unified SDK configuration from Protobuf (Options message)
   */
  constructor(libPath?: string, options: ucs.v2.IOptions = {}) {
    this.uniffi = new UniffiClient(libPath);
    this.options = options;
    
    // Instance-level cache: create the primary connection pool at startup
    this.dispatcher = createDispatcher(this.getNativeHttpOptions(options.http));
  }

  /**
   * Internal helper to map Protobuf HttpOptions to Native HttpClient options.
   */
  private getNativeHttpOptions(proto?: ucs.v2.IHttpOptions | null): HttpOptions {
    if (!proto) return {};

    return {
      totalTimeoutMs: proto.totalTimeoutMs ?? undefined,
      connectTimeoutMs: proto.connectTimeoutMs ?? undefined,
      responseTimeoutMs: proto.responseTimeoutMs ?? undefined,
      keepAliveTimeoutMs: proto.keepAliveTimeoutMs ?? undefined,
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
   * 
   * @param requestMsg - PaymentServiceAuthorizeRequest protobuf message
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
    // 1. Serialize request
    const requestBytes = Buffer.from(v2.PaymentServiceAuthorizeRequest.encode(requestMsg).finish());

    // 2. Resolve FFI options (prefer call-specific)
    const ffi = ffiOptions || this.options.ffi;
    const optionsBytes = ffi ? Buffer.from(v2.FfiOptions.encode(ffi).finish()) : Buffer.alloc(0);

    // 3. Transform to connector request via FFI (returns Protobuf bytes)
    const resultBytes = this.uniffi.authorizeReq(requestBytes, metadata, optionsBytes);
    const connectorReq = v2.FfiConnectorHttpRequest.decode(resultBytes);

    const connectorRequest: HttpRequest = {
      url: connectorReq.url,
      method: connectorReq.method,
      headers: connectorReq.headers || {},
      body: connectorReq.body ?? undefined
    };

    // 4. Execute HTTP using the instance-owned connection pool
    const response = await execute(
      connectorRequest, 
      this.getNativeHttpOptions(this.options.http), 
      this.dispatcher
    );

    // 5. Transform connector response via FFI
    const resProto = v2.FfiConnectorHttpResponse.create({
      statusCode: response.statusCode,
      headers: response.headers,
      body: response.body
    });
    const resBytes = Buffer.from(v2.FfiConnectorHttpResponse.encode(resProto).finish());

    const resultBytesRes = this.uniffi.authorizeRes(resBytes, requestBytes, metadata, optionsBytes);

    // 6. Decode and return
    return v2.PaymentServiceAuthorizeResponse.decode(resultBytesRes);
  }
}