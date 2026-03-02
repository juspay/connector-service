/**
 * ConnectorClient — high-level wrapper using UniFFI bindings via koffi.
 *
 * Handles the full round-trip for any payment flow:
 *   1. Serialize protobuf request to bytes
 *   2. Build connector HTTP request via {flow}_req_transformer (UniFFI FFI)
 *   3. Execute the HTTP request via fetch
 *   4. Parse the connector response via {flow}_res_transformer (UniFFI FFI)
 *   5. Deserialize protobuf response from bytes
 *
 * Flow methods (authorize, capture, void, refund, …) are attached dynamically
 * from _generated_flows.js — no flow names are hardcoded in this file.
 * To add a new flow: edit sdk/flows.yaml and run `make codegen`.
 */

"use strict";

const { UniffiClient } = require("./uniffi_client");
const { ucs } = require("./generated/proto");
const { FLOWS } = require("./_generated_flows");
const FfiOptions = ucs.v2.FfiOptions;

class ConnectorClient {
  /**
   * @param {string} [libPath] - optional path to the UniFFI shared library
   */
  constructor(libPath) {
    this._uniffi = new UniffiClient(libPath);

    // Attach a method for every flow registered in _generated_flows.js.
    // Proto classes are resolved from ucs.v2[className] — no hardcoded class names here.
    for (const [flow, { request: reqCls, response: resCls }] of Object.entries(FLOWS)) {
      this[flow] = async (requestMsg, metadata, ffiOptions) =>
        this._executeFlow(flow, requestMsg, ucs.v2[reqCls], ucs.v2[resCls], metadata, ffiOptions);
    }
  }

  /**
   * Execute a full round-trip for any payment flow.
   * @param {string} flow - flow name matching FFI transformer prefix (e.g. "authorize")
   * @param {Object} requestMsg - protobuf request message
   * @param {Function} requestClass - protobufjs Message class for encoding the request
   * @param {Function} responseClass - protobufjs Message class for decoding the response
   * @param {Object<string,string>} metadata - connector routing + auth metadata
   * @param {Object} [ffiOptions] - optional FfiOptions message with ffi configuration
   * @returns {Promise<Object>} decoded protobuf response message
   */
  async _executeFlow(flow, requestMsg, requestClass, responseClass, metadata, ffiOptions) {
    const requestBytes = Buffer.from(requestClass.encode(requestMsg).finish());

    // Serialize FfiOptions to bytes if provided
    let optionsBytes = Buffer.from([]);
    if (ffiOptions) {
      const ffi = FfiOptions.create(ffiOptions);
      optionsBytes = Buffer.from(FfiOptions.encode(ffi).finish());
    }

    const connectorRequestJson = this._uniffi.callReq(flow, requestBytes, metadata, optionsBytes);
    const { url, method, headers, body } = JSON.parse(connectorRequestJson);

    const response = await fetch(url, {
      method,
      headers,
      body: body || undefined,
    });

    const responseText = await response.text();
    const responseHeaders = {};
    response.headers.forEach((value, key) => {
      responseHeaders[key] = value;
    });

    const responseBody = Buffer.from(responseText, "utf-8");
    const resultBytes = this._uniffi.callRes(
      flow,
      responseBody,
      response.status,
      responseHeaders,
      requestBytes,
      metadata,
      optionsBytes
    );

    return responseClass.decode(resultBytes);
  }
}

module.exports = { ConnectorClient };
