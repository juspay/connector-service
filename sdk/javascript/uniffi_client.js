/**
 * UniFFI client for Node.js — calls the same shared library as Python/Kotlin.
 *
 * Uses koffi to call the UniFFI C ABI directly, replacing NAPI entirely.
 * Handles RustBuffer serialization/deserialization for the UniFFI protocol.
 */

"use strict";

const koffi = require("koffi");
const path = require("path");

// ── RustBuffer struct layout ────────────────────────────────────────────────
// UniFFI uses RustBuffer { capacity: u64, len: u64, data: *u8 } for all
// compound types (bytes, strings, maps). We allocate via the Rust allocator
// and free via Rust — never from JS.

const RustBuffer = koffi.struct("RustBuffer", {
  capacity: "uint64",
  len: "uint64",
  data: "void *",
});

const RustCallStatus = koffi.struct("RustCallStatus", {
  code: "int8",
  error_buf: RustBuffer,
});

// ── Load the shared library ─────────────────────────────────────────────────

function loadLib(libPath) {
  if (!libPath) {
    const ext = process.platform === "darwin" ? "dylib" : "so";
    libPath = path.join(__dirname, "generated", `libconnector_service_ffi.${ext}`);
  }

  const lib = koffi.load(libPath);

  return {
    authorize_req: lib.func(
      "uniffi_connector_service_ffi_fn_func_authorize_req",
      RustBuffer,
      [RustBuffer, RustBuffer, koffi.out(koffi.pointer(RustCallStatus))]
    ),
    authorize_res: lib.func(
      "uniffi_connector_service_ffi_fn_func_authorize_res",
      RustBuffer,
      [RustBuffer, "uint16", RustBuffer, RustBuffer, RustBuffer, koffi.out(koffi.pointer(RustCallStatus))]
    ),
    alloc: lib.func(
      "ffi_connector_service_ffi_rustbuffer_alloc",
      RustBuffer,
      ["uint64", koffi.out(koffi.pointer(RustCallStatus))]
    ),
    free: lib.func(
      "ffi_connector_service_ffi_rustbuffer_free",
      "void",
      [RustBuffer, koffi.out(koffi.pointer(RustCallStatus))]
    ),
  };
}

// ── RustBuffer helpers ──────────────────────────────────────────────────────

function makeCallStatus() {
  return { code: 0, error_buf: { capacity: 0, len: 0, data: null } };
}

function checkCallStatus(ffi, status) {
  if (status.code === 0) return; // SUCCESS

  if (status.code === 1) {
    // CALL_ERROR — lift the UniffiError from error_buf
    const errMsg = liftError(status.error_buf);
    freeRustBuffer(ffi, status.error_buf);
    throw new Error(errMsg);
  }

  // CALL_UNEXPECTED_ERROR (panic)
  if (status.error_buf.len > 0) {
    const msg = liftString(status.error_buf);
    freeRustBuffer(ffi, status.error_buf);
    throw new Error(`Rust panic: ${msg}`);
  }
  throw new Error("Unknown Rust panic");
}

function liftError(buf) {
  if (!buf.data || buf.len === 0) return "Unknown error";
  const raw = Buffer.from(koffi.decode(buf.data, "uint8", Number(buf.len)));
  let offset = 0;

  // variant: i32 big-endian
  const variant = raw.readInt32BE(offset);
  offset += 4;

  const variantNames = {
    1: "DecodeError",
    2: "MissingMetadata",
    3: "MetadataParseError",
    4: "HandlerError",
    5: "NoConnectorRequest",
  };

  if (variant === 5) return "NoConnectorRequest";

  // All other variants have a string field
  const strLen = raw.readInt32BE(offset);
  offset += 4;
  const msg = raw.subarray(offset, offset + strLen).toString("utf-8");
  return `${variantNames[variant] || "UniffiError"}: ${msg}`;
}

function liftString(buf) {
  if (!buf.data || buf.len === 0) return "";
  const raw = Buffer.from(koffi.decode(buf.data, "uint8", Number(buf.len)));
  return raw.toString("utf-8");
}

function liftBytes(buf) {
  if (!buf.data || buf.len === 0) return Buffer.alloc(0);
  const raw = Buffer.from(koffi.decode(buf.data, "uint8", Number(buf.len)));
  // Bytes are serialized as: i32 length + raw bytes
  const len = raw.readInt32BE(0);
  return raw.subarray(4, 4 + len);
}

function freeRustBuffer(ffi, buf) {
  if (buf.data && buf.len > 0) {
    const status = makeCallStatus();
    ffi.free(buf, status);
  }
}

function allocRustBuffer(ffi, data) {
  const status = makeCallStatus();
  const buf = ffi.alloc(data.length, status);
  checkCallStatus(ffi, status);

  // Copy data into the Rust-allocated buffer
  koffi.encode(buf.data, "uint8", Array.from(data), data.length);
  buf.len = data.length;
  return buf;
}

// ── Serialization (lower) ───────────────────────────────────────────────────

function lowerBytes(ffi, bytes) {
  // UniFFI bytes format: i32 length prefix + raw bytes
  const buf = Buffer.alloc(4 + bytes.length);
  buf.writeInt32BE(bytes.length, 0);
  Buffer.from(bytes).copy(buf, 4);
  return allocRustBuffer(ffi, buf);
}

function lowerMap(ffi, map) {
  // Map<String,String> format: i32 count + [i32 keyLen + keyBytes + i32 valLen + valBytes]*
  const entries = Object.entries(map);
  let totalSize = 4; // count
  const encoded = entries.map(([k, v]) => {
    const keyBuf = Buffer.from(k, "utf-8");
    const valBuf = Buffer.from(v, "utf-8");
    totalSize += 4 + keyBuf.length + 4 + valBuf.length;
    return { keyBuf, valBuf };
  });

  const buf = Buffer.alloc(totalSize);
  let offset = 0;
  buf.writeInt32BE(entries.length, offset);
  offset += 4;

  for (const { keyBuf, valBuf } of encoded) {
    buf.writeInt32BE(keyBuf.length, offset);
    offset += 4;
    keyBuf.copy(buf, offset);
    offset += keyBuf.length;

    buf.writeInt32BE(valBuf.length, offset);
    offset += 4;
    valBuf.copy(buf, offset);
    offset += valBuf.length;
  }

  return allocRustBuffer(ffi, buf);
}

// ── Public API ──────────────────────────────────────────────────────────────

class UniffiClient {
  constructor(libPath) {
    this._ffi = loadLib(libPath);
  }

  /**
   * Build the connector HTTP request.
   * @param {Buffer|Uint8Array} requestBytes - protobuf-encoded PaymentServiceAuthorizeRequest
   * @param {Object<string,string>} metadata - connector routing + auth metadata
   * @returns {string} JSON string: {url, method, headers, body}
   */
  authorizeReq(requestBytes, metadata) {
    const status = makeCallStatus();
    const rbRequest = lowerBytes(this._ffi, requestBytes);
    const rbMetadata = lowerMap(this._ffi, metadata);

    const result = this._ffi.authorize_req(rbRequest, rbMetadata, status);

    try {
      checkCallStatus(this._ffi, status);
      const str = liftString(result);
      return str;
    } finally {
      freeRustBuffer(this._ffi, result);
    }
  }

  /**
   * Parse the connector HTTP response.
   * @param {Buffer|Uint8Array} responseBody - raw response body bytes
   * @param {number} statusCode - HTTP status code
   * @param {Object<string,string>} responseHeaders - HTTP response headers
   * @param {Buffer|Uint8Array} requestBytes - original protobuf request bytes
   * @param {Object<string,string>} metadata - original metadata
   * @returns {Buffer} protobuf-encoded PaymentServiceAuthorizeResponse
   */
  authorizeRes(responseBody, statusCode, responseHeaders, requestBytes, metadata) {
    const status = makeCallStatus();
    const rbResponseBody = lowerBytes(this._ffi, responseBody);
    const rbResponseHeaders = lowerMap(this._ffi, responseHeaders);
    const rbRequestBytes = lowerBytes(this._ffi, requestBytes);
    const rbMetadata = lowerMap(this._ffi, metadata);

    const result = this._ffi.authorize_res(
      rbResponseBody,
      statusCode,
      rbResponseHeaders,
      rbRequestBytes,
      rbMetadata,
      status
    );

    try {
      checkCallStatus(this._ffi, status);
      return liftBytes(result);
    } finally {
      freeRustBuffer(this._ffi, result);
    }
  }
}

module.exports = { UniffiClient };
