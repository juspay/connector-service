/**
 * ConnectorClient — high-level wrapper using UniFFI bindings via koffi.
 *
 * Handles the full round-trip for any payment flow:
 *   1. Serialize protobuf request to bytes
 *   2. Build connector HTTP request via UniffiClient.callReq (generic FFI dispatch)
 *   3. Execute the HTTP request via our standardized HttpClient
 *   4. Parse the connector response via UniffiClient.callRes (generic FFI dispatch)
 *   5. Deserialize protobuf response from bytes
 *
 * Flow methods (authorize, capture, void, refund, …) are in _generated_connector_client_flows.ts.
 * To add a new flow: edit sdk/flows.yaml and run `make codegen`.
 */

import { Dispatcher } from "undici";
import { UniffiClient } from "./uniffi_client";
import { execute, createDispatcher, HttpRequest, ConnectorError } from "../http_client";
// @ts-ignore - protobuf generated files might not have types yet
import { ucs } from "./generated/proto";

const v2 = ucs.v2;

export class ConnectorClient {
  private uniffi: UniffiClient;
  private identity: ucs.v2.ClientIdentity;
  private defaults: ucs.v2.IConfigOptions;
  private dispatcher: Dispatcher;

  /**
   * Initialize the client with mandatory identity and overridable defaults.
   *
   * @param identity - Non-overridable (Connector, Auth).
   * @param defaults - Overridable behavioral settings (Environment, Http).
   * @param libPath - optional path to the UniFFI shared library.
   */
  constructor(
    identity: ucs.v2.IClientIdentity,
    defaults: ucs.v2.IConfigOptions = {},
    libPath?: string
  ) {
    this.uniffi = new UniffiClient(libPath);
    this.identity = ucs.v2.ClientIdentity.create(identity);
    this.defaults = defaults;

    if (identity.connector === undefined) {
      throw new ConnectorError(
        "Connector is required in ClientIdentity",
        400,
        "CLIENT_INITIALIZATION"
      );
    }

    // Instance-level cache: create the primary connection pool at startup
    this.dispatcher = createDispatcher(defaults.http || {});
  }

  /**
   * Merges request-level options with client defaults.
   */
  private _resolveConfig(overrides?: ucs.v2.IConfigOptions | null): {
    ffi: ucs.v2.FfiOptions;
    http: ucs.v2.IHttpConfig;
  } {
    const opt = overrides || {};
    
    const environment = opt.environment ?? this.defaults.environment ?? ucs.v2.Environment.SANDBOX;
    const clientHttp = this.defaults.http || {};
    const overrideHttp = opt.http || {};

    const http: ucs.v2.IHttpConfig = {
      totalTimeoutMs: overrideHttp.totalTimeoutMs ?? clientHttp.totalTimeoutMs,
      connectTimeoutMs: overrideHttp.connectTimeoutMs ?? clientHttp.connectTimeoutMs,
      responseTimeoutMs: overrideHttp.responseTimeoutMs ?? clientHttp.responseTimeoutMs,
      keepAliveTimeoutMs: overrideHttp.keepAliveTimeoutMs ?? clientHttp.keepAliveTimeoutMs,
      proxy: overrideHttp.proxy ?? clientHttp.proxy,
      caCert: overrideHttp.caCert ?? clientHttp.caCert,
    };

    const ffi = ucs.v2.FfiOptions.create({
      environment,
      connector: this.identity.connector,
      auth: this.identity.auth,
    });

    return { ffi, http };
  }

  /**
   * Execute a full round-trip for any registered payment flow.
   *
   * @param flow - Flow name matching the FFI transformer prefix (e.g. "authorize").
   * @param requestMsg - Protobuf request message object.
   * @param metadata - Dict with connector routing and auth info.
   * @param options - Optional ConfigOptions override (Environment, Http).
   */
  async _executeFlow(
    flow: string,
    requestMsg: object,
    metadata: Record<string, string>,
    options?: ucs.v2.IConfigOptions | null,
    reqTypeName?: string,
    resTypeName?: string
  ): Promise<unknown> {
    const reqType = reqTypeName ? (v2 as any)[reqTypeName] : undefined;
    const resType = resTypeName ? (v2 as any)[resTypeName] : undefined;

    if (!reqType || !resType) {
      throw new Error(`Unknown flow: '${flow}' or missing type names.`);
    }

    // 1. Resolve final configuration
    const { ffi, http } = this._resolveConfig(options);
    const optionsBytes = Buffer.from(v2.FfiOptions.encode(ffi).finish());

    // 2. Serialize domain request
    const requestBytes = Buffer.from(reqType.encode(requestMsg).finish());

    // 3. Build connector HTTP request via FFI
    const resultBytes = this.uniffi.callReq(flow, requestBytes, metadata, optionsBytes);
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
      http,
      this.dispatcher
    );

    // 5. Encode HTTP response for FFI
    const resProto = v2.FfiConnectorHttpResponse.create({
      statusCode: response.statusCode,
      headers: response.headers,
      body: response.body
    });
    const resBytes = Buffer.from(v2.FfiConnectorHttpResponse.encode(resProto).finish());

    // 6. Parse connector response via FFI and decode
    const resultBytesRes = this.uniffi.callRes(flow, resBytes, requestBytes, metadata, optionsBytes);
    return resType.decode(resultBytesRes);
  }
}
