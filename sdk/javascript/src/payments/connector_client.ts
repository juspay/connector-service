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
import { execute, HttpRequest } from "../http_client";
// @ts-ignore
import { ucs } from "@generated/proto";

const v2 = ucs.v2;

export class ConnectorClient {
  private _uniffi: UniffiClient;
  private _options: ucs.v2.IOptions;

  /**
   * @param libPath - optional path to the UniFFI shared library
   * @param options - unified SDK configuration (http, ffi)
   */
  constructor(libPath?: string, options: ucs.v2.IOptions = {}) {
    this._uniffi = new UniffiClient(libPath);
    this._options = options;
  }

  /**
   * Execute a full authorize round-trip.
   * 
   * @param requestMsg - PaymentServiceAuthorizeRequest protobuf message
   * @param metadata - Dict with connector routing and auth info. Must include:
   *                 - "connector": connector name (e.g. "Stripe")
   *                 - "connector_auth_type": JSON string of auth config
   *                 - x-* headers for masked metadata
   * @param ffiOptions - Optional FfiOptions protobuf message override.
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

    // 3. Build the connector HTTP request via FFI bridge
    const connectorRequest: HttpRequest = this._uniffi.authorizeReq(requestBytes, metadata, optionsBytes);

    // 4. Execute the HTTP request (uses Global HttpOptions)
    const response = await execute(connectorRequest, this._options.http || {});

    // 5. Parse the connector response via FFI bridge
    const resultBytes = this._uniffi.authorizeRes(
      response,
      requestBytes,
      metadata,
      optionsBytes
    );

    // 6. Decode the protobuf response from bytes
    return v2.PaymentServiceAuthorizeResponse.decode(resultBytes);
  }
}
