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

const PaymentServiceAuthorizeRequest = ucs.v2.PaymentServiceAuthorizeRequest;
const PaymentServiceAuthorizeResponse = ucs.v2.PaymentServiceAuthorizeResponse;

export class ConnectorClient {
  private _uniffi: UniffiClient;
  private _options: HttpOptions;

  /**
   * @param libPath - optional path to the UniFFI shared library
   * @param options - global configuration (proxy, timeouts, tls, etc.)
   */
  constructor(libPath?: string, options: HttpOptions = {}) {
    this._uniffi = new UniffiClient(libPath);
    this._options = options;
  }

  /**
   * Execute a full authorize round-trip.
   * @param requestMsg - PaymentServiceAuthorizeRequest message
   * @param metadata - connector routing + auth metadata
   * @returns decoded PaymentServiceAuthorizeResponse message
   */
  async authorize(requestMsg: any, metadata: Record<string, string>): Promise<any> {
    // 1. Serialize protobuf request to bytes
    const requestBytes = Buffer.from(
      PaymentServiceAuthorizeRequest.encode(requestMsg).finish()
    );

    // 2. Build the connector HTTP request via FFI bridge
    // Now returns a native HttpRequest object, no JSON.parse needed!
    const connectorRequest: HttpRequest = this._uniffi.authorizeReq(requestBytes, metadata);

    // 3. Execute the HTTP request
    const response = await execute(connectorRequest, this._options);

    // 4. Parse the connector response via FFI bridge
    const responseBody = Buffer.from(response.body, "utf-8");
    const resultBytes = this._uniffi.authorizeRes(
      responseBody,
      response.statusCode,
      response.headers,
      requestBytes,
      metadata
    );

    // 5. Decode the protobuf response from bytes
    return PaymentServiceAuthorizeResponse.decode(resultBytes);
  }
}
