/**
 * ConnectorClient — high-level wrapper using UniFFI bindings via koffi.
 *
 * Handles the full round-trip:
 *   1. Serialize protobuf request to bytes
 *   2. Build connector HTTP request via authorizeReqTransformer (UniFFI FFI)
 *   3. Execute the HTTP request via fetch
 *   4. Parse the connector response via authorizeResTransformer (UniFFI FFI)
 *   5. Deserialize protobuf response from bytes
 *
 * Mirrors the Python client at examples/example-uniffi-py/connector_client.py.
 */

"use strict";

const { UniffiClient } = require("./uniffi_client");
const { ucs } = require("./generated/proto");

const PaymentServiceAuthorizeRequest = ucs.v2.PaymentServiceAuthorizeRequest;
const PaymentServiceAuthorizeResponse = ucs.v2.PaymentServiceAuthorizeResponse;
const FfiOptions = ucs.v2.FfiOptions;

class ConnectorClient {
  /**
   * @param {string} [libPath] - optional path to the UniFFI shared library
   */
  constructor(libPath) {
    this._uniffi = new UniffiClient(libPath);
  }

  /**
   * Execute a full authorize round-trip.
   * @param {Object} requestMsg - PaymentServiceAuthorizeRequest message (plain object or Message instance)
   * @param {Object<string,string>} metadata - connector routing + auth metadata
   * @param {Object} [options] - optional Options message with ffi and http configuration
   * @returns {Promise<Object>} decoded PaymentServiceAuthorizeResponse message
   */
  async authorize(requestMsg, metadata, options = null) {
    // Step 1: Serialize protobuf request to bytes
    const requestBytes = Buffer.from(
      PaymentServiceAuthorizeRequest.encode(requestMsg).finish()
    );

    // Extract FfiOptions from options if provided
    let optionsBytes = null;
    if (options && options.ffi) {
      const ffiOptions = FfiOptions.create(options.ffi);
      optionsBytes = Buffer.from(FfiOptions.encode(ffiOptions).finish());
    }

    // Step 2: Build the connector HTTP request via FFI
    const connectorRequestJson = this._uniffi.authorizeReq(requestBytes, metadata, optionsBytes);
    const { url, method, headers, body } = JSON.parse(connectorRequestJson);

    // Step 3: Execute the HTTP request
    const response = await fetch(url, {
      method,
      headers,
      body: body || undefined,
    });

    // Step 4: Collect response data
    const responseText = await response.text();
    const responseHeaders = {};
    response.headers.forEach((value, key) => {
      responseHeaders[key] = value;
    });

    // Step 5: Parse the connector response via FFI
    const responseBody = Buffer.from(responseText, "utf-8");
    const resultBytes = this._uniffi.authorizeRes(
      responseBody,
      response.status,
      responseHeaders,
      requestBytes,
      metadata,
      optionsBytes
    );

    // Step 6: Decode the protobuf response
    return PaymentServiceAuthorizeResponse.decode(resultBytes);
  }
}

module.exports = { ConnectorClient };
