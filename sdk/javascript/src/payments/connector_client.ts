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

export interface ConnectorClientOptions extends HttpOptions {
  test_mode?: boolean;
}

export class ConnectorClient {
  private _uniffi: UniffiClient;
  private _options: ConnectorClientOptions;

  /**
   * @param libPath - optional path to the UniFFI shared library
   * @param options - global configuration (proxy, timeouts, tls, etc.)
   */
  constructor(libPath?: string, options: ConnectorClientOptions = {}) {
    this._uniffi = new UniffiClient(libPath);
    this._options = options;
  }

  /**
   * Helper to build FfiOptions protobuf bytes
   */
  private _getOptionsBytes(ffiOptions?: any): Buffer {
    const opts = v2.FfiOptions.create({
      env: {
        testMode: this._options.test_mode ?? true
      },
      ...ffiOptions
    });
    return Buffer.from(v2.FfiOptions.encode(opts).finish());
  }

  /**
   * Execute a full authorize round-trip.
   * @param requestMsg - PaymentServiceAuthorizeRequest message
   * @param metadata - connector routing + auth metadata
   * @param ffiOptions - optional FfiOptions object
   * @returns decoded PaymentServiceAuthorizeResponse message
   */
  async authorize(requestMsg: any, metadata: Record<string, string>, ffiOptions: any = null): Promise<any> {
    // 1. Serialize protobuf request to bytes
    const requestBytes = Buffer.from(
      v2.PaymentServiceAuthorizeRequest.encode(requestMsg).finish()
    );

    const optionsBytes = this._getOptionsBytes(ffiOptions);

    // 2. Build the connector HTTP request via FFI bridge
    const connectorRequest: HttpRequest = this._uniffi.authorizeReq(requestBytes, metadata, optionsBytes);

    // 3. Execute the HTTP request
    const response = await execute(connectorRequest, this._options);

    // 4. Parse the connector response via FFI bridge
    const resultBytes = this._uniffi.authorizeRes(
      response,
      requestBytes,
      metadata,
      optionsBytes
    );

    // 5. Decode the protobuf response from bytes
    return v2.PaymentServiceAuthorizeResponse.decode(resultBytes);
  }
}
