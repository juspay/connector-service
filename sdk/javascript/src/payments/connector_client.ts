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
  private config: ucs.v2.IClientConfig;
  private dispatcher: Dispatcher;

  /**
   * @param config - initialization configuration (connector, environment, auth, http)
   * @param libPath - optional path to the UniFFI shared library
   */
  constructor(config: ucs.v2.IClientConfig, libPath?: string) {
    this.uniffi = new UniffiClient(libPath);
    this.config = config;

    if (config.connector === undefined || config.environment === undefined) {
      throw new ConnectorError(
        "Connector and Environment are required in ClientConfig",
        400,
        "CLIENT_INITIALIZATION"
      );
    }

    // Instance-level cache: create the primary connection pool at startup
    this.dispatcher = createDispatcher(config.http || {});
  }

  /**
   * Merges request-level overrides with client defaults to build the 
   * final context for the Rust transformation engine.
   */
  private resolveFfiOptions(requestOptions?: ucs.v2.IRequestOptions | null): ucs.v2.FfiOptions {
    return v2.FfiOptions.create({
      environment: this.config.environment,
      connector: this.config.connector,
      auth: requestOptions?.auth ?? this.config.auth
    });
  }

  /**
   * Merges request-level HTTP overrides with client defaults using 
   * explicit field-level precedence.
   */
  private resolveHttpConfig(requestOptions?: ucs.v2.IRequestOptions | null): ucs.v2.IHttpConfig {
    const defaults = this.config.http || {};
    const overrides = requestOptions?.http || {};

    return {
      totalTimeoutMs: overrides.totalTimeoutMs ?? defaults.totalTimeoutMs,
      connectTimeoutMs: overrides.connectTimeoutMs ?? defaults.connectTimeoutMs,
      responseTimeoutMs: overrides.responseTimeoutMs ?? defaults.responseTimeoutMs,
      keepAliveTimeoutMs: overrides.keepAliveTimeoutMs ?? defaults.keepAliveTimeoutMs,
      proxy: (overrides.proxy ?? defaults.proxy) as ucs.v2.IProxyOptions | null | undefined,
      caCert: (overrides.caCert ?? defaults.caCert) as ucs.v2.ICaCert | null | undefined,
    };
  }

  /**
   * Execute a full round-trip for any registered payment flow.
   *
   * @param flow - Flow name matching the FFI transformer prefix (e.g. "authorize").
   * @param requestMsg - Protobuf request message object.
   * @param metadata - Dict with connector routing and auth info.
   * @param requestOptions - Optional IRequestOptions override (auth, http).
   */
  async _executeFlow(
    flow: string,
    requestMsg: object,
    metadata: Record<string, string>,
    requestOptions?: ucs.v2.IRequestOptions | null,
    reqTypeName?: string,
    resTypeName?: string
  ): Promise<unknown> {
    const reqType = reqTypeName ? (v2 as any)[reqTypeName] : undefined;
    const resType = resTypeName ? (v2 as any)[resTypeName] : undefined;

    if (!reqType || !resType) {
      throw new Error(`Unknown flow: '${flow}' or missing type names.`);
    }

    // 1. Resolve final configuration (Pattern-based merging)
    const ffiOptions = this.resolveFfiOptions(requestOptions);
    const httpConfig = this.resolveHttpConfig(requestOptions);
    const optionsBytes = Buffer.from(v2.FfiOptions.encode(ffiOptions).finish());

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

    // 4. Execute HTTP using the instance-owned connection pool and merged config
    const response = await execute(
      connectorRequest,
      httpConfig,
      this.dispatcher
    );

    // 5. Encode HTTP response as FfiConnectorHttpResponse protobuf bytes
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
