/**
 * ConnectorClient — high-level wrapper using UniFFI bindings via koffi.
 *
 * Handles the full round-trip:
 *   1. Serialize protobuf request to bytes
 *   2. Build connector HTTP request via authorize_req_transformer (UniFFI FFI)
 *   3. Execute the HTTP request via fetch
 *   4. Parse the connector response via authorize_res_transformer (UniFFI FFI)
 *   5. Deserialize protobuf response from bytes
 *
 * All types (Connector, ConnectorAuth, ConnectorConfig) come from proto
 * codegen — same pattern as PaymentServiceAuthorizeRequest, Currency, etc.
 */

"use strict";

const { UniffiClient } = require("./uniffi_client");
const { ucs } = require("./generated/proto");

const PaymentServiceAuthorizeRequest = ucs.v2.PaymentServiceAuthorizeRequest;
const PaymentServiceAuthorizeResponse = ucs.v2.PaymentServiceAuthorizeResponse;
const ConnectorConfig = ucs.v2.ConnectorConfig;

// Re-export proto types for SDK users — same pattern as Currency, CaptureMethod, etc.
const Connector = ucs.v2.Connector;
const ConnectorAuth = ucs.v2.ConnectorAuth;
const HeaderKeyAuth = ucs.v2.HeaderKeyAuth;
const BodyKeyAuth = ucs.v2.BodyKeyAuth;
const SignatureKeyAuth = ucs.v2.SignatureKeyAuth;
const MultiAuthKeyAuth = ucs.v2.MultiAuthKeyAuth;
const CertificateAuth = ucs.v2.CertificateAuth;
const NoKeyAuth = ucs.v2.NoKeyAuth;
const TemporaryAuth = ucs.v2.TemporaryAuth;

// ── ConnectorClient ──────────────────────────────────────────────────────────

class ConnectorClient {
  /**
   * Create a ConnectorClient configured for a single connector.
   *
   * @param {Object} config - ConnectorConfig proto message:
   *   `{ connector: Connector.STRIPE, auth: { headerKey: { apiKey: "sk_..." } } }`
   * @param {string} [libPath] - Optional path to the UniFFI shared library
   */
  constructor(config, libPath) {
    if (!config || typeof config !== "object") {
      throw new Error("config must be an ConnectorConfig proto message");
    }
    // Encode ConnectorConfig to proto bytes (same pattern as request)
    const verified = ConnectorConfig.verify(config);
    if (verified) throw new Error(`Invalid ConnectorConfig: ${verified}`);
    const msg = ConnectorConfig.create(config);
    this._configBytes = Buffer.from(ConnectorConfig.encode(msg).finish());
    this._uniffi = new UniffiClient(libPath);
  }

  /**
   * Execute a full authorize round-trip.
   * @param {Object} requestMsg - PaymentServiceAuthorizeRequest message
   * @returns {Promise<Object>} decoded PaymentServiceAuthorizeResponse message
   */
  async authorize(requestMsg) {
    // Step 1: Serialize protobuf request to bytes
    const requestBytes = Buffer.from(
      PaymentServiceAuthorizeRequest.encode(requestMsg).finish()
    );

    // Step 2: Build the connector HTTP request via FFI
    const connectorRequestJson = this._uniffi.authorizeReq(
      requestBytes,
      this._configBytes
    );
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
      this._configBytes
    );

    // Step 6: Decode the protobuf response
    return PaymentServiceAuthorizeResponse.decode(resultBytes);
  }
}

module.exports = {
  ConnectorClient,
  Connector,
  ConnectorAuth,
  ConnectorConfig,
  HeaderKeyAuth,
  BodyKeyAuth,
  SignatureKeyAuth,
  MultiAuthKeyAuth,
  CertificateAuth,
  NoKeyAuth,
  TemporaryAuth,
};
