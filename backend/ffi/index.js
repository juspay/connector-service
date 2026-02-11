/**
 * Node.js bindings for connector-service-ffi
 *
 * This module provides Node.js access to the Rust FFI functions.
 * Build with: cd backend/ffi && npx napi build --release
 */

"use strict";

const path = require("path");

function loadNative() {
  const candidates = [
    path.join(__dirname, "connector_service_ffi.node"),
  ];

  let lastErr;
  for (const p of candidates) {
    try {
      // eslint-disable-next-line import/no-dynamic-require, global-require
      return require(p);
    } catch (err) {
      lastErr = err;
    }
  }

  const tried = candidates.map((p) => `- ${p}`).join("\n");
  const msg = `Failed to load native addon. Tried:\n${tried}\n\nLast error: ${lastErr}`;
  const e = new Error(msg);
  e.cause = lastErr;
  throw e;
}

const native = loadNative();

/**
 * Authorize a payment with the provided payload and extracted metadata
 * @param {object} payload - PaymentServiceAuthorizeRequest object
 * @param {object} extractedMetadata - MetadataPayload object with connector and auth info
 * @returns {string} JSON string containing the response
 * @throws Error if payload or extractedMetadata is empty or invalid
 */
function authorize(payload, extractedMetadata) {
  if (!payload || typeof payload !== 'object') {
    throw new Error('Payload must be a non-null object');
  }
  if (!extractedMetadata || typeof extractedMetadata !== 'object') {
    throw new Error('Extracted metadata must be a non-null object');
  }
  const payloadJson = JSON.stringify(payload);
  const extractedMetadataJson = JSON.stringify(extractedMetadata);
  const res = native.authorize(payloadJson, extractedMetadataJson);
  return typeof res === "string" ? res : JSON.stringify(res);
}

module.exports = {
  authorize,
  _native: native,
};
