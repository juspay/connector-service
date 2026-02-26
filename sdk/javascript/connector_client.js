/**
 * ConnectorClient — high-level wrapper using UniFFI bindings via koffi.
 *
 * Handles the full round-trip:
 *   1. Serialize protobuf request to bytes
 *   2. Build connector HTTP request via authorizeReqTransformer (UniFFI FFI)
 *   3. Execute the HTTP request via our standardized HttpClient
 *   4. Parse the connector response via authorizeResTransformer (UniFFI FFI)
 *   5. Deserialize protobuf response from bytes
 *
 * Mirrors the Python client at examples/example-uniffi-py/connector_client.py.
 */

"use strict";

const { UniffiClient } = require("./uniffi_client");
const { execute } = require("./http_client");
const { ucs } = require("./generated/proto");

const PaymentServiceAuthorizeRequest = ucs.v2.PaymentServiceAuthorizeRequest;
const PaymentServiceAuthorizeResponse = ucs.v2.PaymentServiceAuthorizeResponse;

class ConnectorClient {
  /**
   * @param {string} [libPath] - optional path to the UniFFI shared library
   * @param {Object} [options] - global configuration (proxy, timeouts, etc.)
   */
  constructor(libPath, options = {}) {
    this._uniffi = new UniffiClient(libPath);
    this._options = options;
  }

  /**
   * Execute a full authorize round-trip.
   * @param {Object} requestMsg - PaymentServiceAuthorizeRequest message
   * @param {Object<string,string>} metadata - connector routing + auth metadata
   * @returns {Promise<Object>} decoded PaymentServiceAuthorizeResponse message
   */
  async authorize(requestMsg, metadata) {
    // 1. Serialize protobuf request to bytes
    const requestBytes = Buffer.from(
      PaymentServiceAuthorizeRequest.encode(requestMsg).finish()
    );

    // 2. Build the connector HTTP request via FFI bridge
    const connectorRequestJson = this._uniffi.authorizeReq(requestBytes, metadata);
    const connectorRequest = JSON.parse(connectorRequestJson);

    // Ensure body is stringified if it's a JSON object from FFI.
    // This provides parity with Rust's client.json() behavior.
    if (connectorRequest.body && typeof connectorRequest.body === "object") {
      connectorRequest.body = JSON.stringify(connectorRequest.body);
    }

    // 3. Execute the HTTP request via our high-performance transport layer
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

module.exports = { ConnectorClient };
