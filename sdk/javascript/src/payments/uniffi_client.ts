/**
 * UniFFI client for Node.js — calls the same shared library as Python/Kotlin.
 *
 * Uses koffi to call the UniFFI C ABI directly, replacing NAPI entirely.
 * Handles RustBuffer serialization/deserialization for the UniFFI protocol.
 *
 * Flow dispatch is generic: callReq(flow, ...) and callRes(flow, ...) load
 * the corresponding C symbol dynamically from the flow list in _generated_flows.js.
 * No flow names are hardcoded here — add new flows to flows.yaml and run `make generate`.
 */

import koffi from "koffi";
import path from "path";
// @ts-ignore - generated CommonJS module
import { FLOWS } from "./_generated_flows.js";

// Standard Node.js __dirname
declare const __dirname: string;
const _dirname = __dirname;

const FLOW_NAMES: string[] = Object.keys(FLOWS as Record<string, unknown>);

// ── RustBuffer struct layout ────────────────────────────────────────────────
// UniFFI uses RustBuffer { capacity: u64, len: u64, data: *u8 } for all
// compound types.

export interface RustBuffer {
  capacity: bigint;
  len: bigint;
  data: Buffer | null;
}

export interface RustCallStatus {
  code: number;
  error_buf: RustBuffer;
}

const RustBufferStruct = koffi.struct("RustBuffer", {
  capacity: "uint64",
  len: "uint64",
  data: "void *",
});

const RustCallStatusStruct = koffi.struct("RustCallStatus", {
  code: "int8",
  error_buf: RustBufferStruct,
});

// ── Shared Library Interface ─────────────────────────────────────────────────

interface FfiFunctions {
  alloc: (len: bigint, status: any) => RustBuffer;
  free: (buf: RustBuffer, status: any) => void;
  [key: string]: (...args: any[]) => any;
}

function loadLib(libPath?: string): FfiFunctions {
  if (!libPath) {
    const ext = process.platform === "darwin" ? "dylib" : "so";
    libPath = path.join(_dirname, "generated", `libconnector_service_ffi.${ext}`);
  }

  const lib = koffi.load(libPath);

  const fns: Record<string, any> = {
    alloc: lib.func(
      "ffi_connector_service_ffi_rustbuffer_alloc",
      RustBufferStruct,
      ["uint64", koffi.out(koffi.pointer(RustCallStatusStruct))]
    ),
    free: lib.func(
      "ffi_connector_service_ffi_rustbuffer_free",
      "void",
      [RustBufferStruct, koffi.out(koffi.pointer(RustCallStatusStruct))]
    ),
  };

  // Load req and res transformer symbols for every registered flow.
  for (const flow of FLOW_NAMES) {
    fns[`${flow}_req`] = lib.func(
      `uniffi_connector_service_ffi_fn_func_${flow}_req_transformer`,
      RustBufferStruct,
      [RustBufferStruct, RustBufferStruct, RustBufferStruct, koffi.out(koffi.pointer(RustCallStatusStruct))]
    );
    fns[`${flow}_res`] = lib.func(
      `uniffi_connector_service_ffi_fn_func_${flow}_res_transformer`,
      RustBufferStruct,
      [RustBufferStruct, RustBufferStruct, RustBufferStruct, RustBufferStruct, koffi.out(koffi.pointer(RustCallStatusStruct))]
    );
  }

  return fns as FfiFunctions;
}

// ── Helpers ──────────────────────────────────────────────────────

function makeCallStatus(): RustCallStatus {
  return { code: 0, error_buf: { capacity: 0n, len: 0n, data: null } };
}

function checkCallStatus(ffi: FfiFunctions, status: RustCallStatus): void {
  if (status.code === 0) return;

  if (status.code === 1) {
    const errMsg = liftError(status.error_buf);
    freeRustBuffer(ffi, status.error_buf);
    throw new Error(errMsg);
  }

  if (status.error_buf.len > 0n) {
    const msg = liftString(status.error_buf);
    freeRustBuffer(ffi, status.error_buf);
    throw new Error(`Rust panic: ${msg}`);
  }

  throw new Error("Unknown Rust panic");
}

function liftError(buf: RustBuffer): string {
  if (!buf.data || buf.len === 0n) return "Unknown error";
  const raw = Buffer.from(koffi.decode(buf.data, "uint8", Number(buf.len)));
  let offset = 0;

  // UniFFI Error layout: [i32 variant] + [i32 len] + [bytes]
  const variant = raw.readInt32BE(offset); offset += 4;
  const variantNames: Record<number, string> = {
    1: "DecodeError",
    2: "MissingMetadata",
    3: "MetadataParseError",
    4: "HandlerError",
    5: "NoConnectorRequest",
  };

  if (variant === 5) return "NoConnectorRequest";

  const strLen = raw.readInt32BE(offset); offset += 4;
  const msg = raw.subarray(offset, offset + strLen).toString("utf-8");
  return `${variantNames[variant] || "UniffiError"}: ${msg}`;
}

/**
 * UniFFI Strings are serialized as raw UTF8 bytes when top-level in RustBuffer.
 */
function liftString(buf: RustBuffer): string {
  if (!buf.data || buf.len === 0n) return "";
  const raw = Buffer.from(koffi.decode(buf.data, "uint8", Number(buf.len)));
  return raw.toString("utf-8");
}

/**
 * UniFFI Vec<u8> (Bytes) as return values are serialized as [i32 length] + [raw bytes]
 */
function liftBytes(buf: RustBuffer): Buffer {
  if (!buf.data || buf.len === 0n) return Buffer.alloc(0);
  const raw = Buffer.from(koffi.decode(buf.data, "uint8", Number(buf.len)));

  // UniFFI protocol for return values: first 4 bytes are the length of the actual payload
  const len = raw.readInt32BE(0);
  return raw.subarray(4, 4 + len);
}

function freeRustBuffer(ffi: FfiFunctions, buf: RustBuffer): void {
  if (buf.data && buf.len > 0n) {
    ffi.free(buf, makeCallStatus());
  }
}

function allocRustBuffer(ffi: FfiFunctions, data: Buffer | Uint8Array): RustBuffer {
  const status = makeCallStatus();
  const buf = ffi.alloc(BigInt(data.length), status);
  checkCallStatus(ffi, status);

  koffi.encode(buf.data, "uint8", Array.from(data), data.length);
  buf.len = BigInt(data.length);
  return buf;
}

/**
 * Lowers raw bytes into a UniFFI-compliant buffer for top-level arguments.
 * Protocol: [i32 length prefix] + [raw bytes]
 */
function lowerBytes(ffi: FfiFunctions, data: Buffer | Uint8Array): RustBuffer {
  const buf = Buffer.alloc(4 + data.length);
  buf.writeInt32BE(data.length, 0);
  Buffer.from(data).copy(buf, 4);
  return allocRustBuffer(ffi, buf);
}

/**
 * Lowers a Map into a UniFFI-compliant serialized buffer.
 * Protocol: [i32 count] + [ [i32 key_len]+[key_bytes] + [i32 val_len]+[val_bytes] ] * count
 */
function lowerMap(ffi: FfiFunctions, map: Record<string, string>): RustBuffer {
  const entries = Object.entries(map);
  let totalSize = 4; // count
  const encoded = entries.map(([k, v]) => {
    const kBuf = Buffer.from(k, "utf-8");
    const vBuf = Buffer.from(v, "utf-8");
    totalSize += 4 + kBuf.length + 4 + vBuf.length;
    return { kBuf, vBuf };
  });

  const buf = Buffer.alloc(totalSize);
  let offset = 0;
  buf.writeInt32BE(entries.length, offset); offset += 4;

  for (const { kBuf, vBuf } of encoded) {
    buf.writeInt32BE(kBuf.length, offset); offset += 4;
    kBuf.copy(buf, offset); offset += kBuf.length;
    buf.writeInt32BE(vBuf.length, offset); offset += 4;
    vBuf.copy(buf, offset); offset += vBuf.length;
  }

  return allocRustBuffer(ffi, buf);
}

export class UniffiClient {
  private _ffi: FfiFunctions;

  constructor(libPath?: string) {
    this._ffi = loadLib(libPath);
  }

  /**
   * Build the connector HTTP request for any flow.
   * Returns protobuf-encoded FfiConnectorHttpRequest bytes.
   */
  callReq(
    flow: string,
    requestBytes: Buffer | Uint8Array,
    metadata: Record<string, string>,
    optionsBytes: Buffer | Uint8Array
  ): Buffer {
    const fn = this._ffi[`${flow}_req`];
    if (!fn) throw new Error(`Unknown flow: '${flow}'. Supported: ${FLOW_NAMES.join(", ")}`);

    const rbReq = lowerBytes(this._ffi, requestBytes);
    const rbMeta = lowerMap(this._ffi, metadata);
    const rbOpts = lowerBytes(this._ffi, optionsBytes);
    const status = makeCallStatus();

    const result = fn(rbReq, rbMeta, rbOpts, status);

    try {
      checkCallStatus(this._ffi, status);
      return liftBytes(result);
    } finally {
      freeRustBuffer(this._ffi, result);
    }
  }

  /**
   * Parse the connector HTTP response for any flow.
   * responseBytes: protobuf-encoded FfiConnectorHttpResponse.
   * Returns protobuf-encoded response bytes for the flow's response type.
   */
  callRes(
    flow: string,
    responseBytes: Buffer | Uint8Array,
    requestBytes: Buffer | Uint8Array,
    metadata: Record<string, string>,
    optionsBytes: Buffer | Uint8Array
  ): Buffer {
    const fn = this._ffi[`${flow}_res`];
    if (!fn) throw new Error(`Unknown flow: '${flow}'. Supported: ${FLOW_NAMES.join(", ")}`);

    const rbRes = lowerBytes(this._ffi, responseBytes);
    const rbReq = lowerBytes(this._ffi, requestBytes);
    const rbMeta = lowerMap(this._ffi, metadata);
    const rbOpts = lowerBytes(this._ffi, optionsBytes);
    const status = makeCallStatus();

    const result = fn(rbRes, rbReq, rbMeta, rbOpts, status);

    try {
      checkCallStatus(this._ffi, status);
      return liftBytes(result);
    } finally {
      freeRustBuffer(this._ffi, result);
    }
  }

  // <GENERATED_FLOWS_START> - This section is auto-generated by sdk/codegen/generate.py
  // Do not edit manually. Run `make generate` to update.

  /** Build connector HTTP request for authorize flow. */
  authorizeReq(
    requestBytes: Buffer | Uint8Array,
    metadata: Record<string, string>,
    optionsBytes: Buffer | Uint8Array
  ): Buffer {
    return this.callReq('authorize', requestBytes, metadata, optionsBytes);
  }

  /** Parse connector HTTP response for authorize flow. */
  authorizeRes(
    responseBytes: Buffer | Uint8Array,
    requestBytes: Buffer | Uint8Array,
    metadata: Record<string, string>,
    optionsBytes: Buffer | Uint8Array
  ): Buffer {
    return this.callRes('authorize', responseBytes, requestBytes, metadata, optionsBytes);
  }

  /** Build connector HTTP request for capture flow. */
  captureReq(
    requestBytes: Buffer | Uint8Array,
    metadata: Record<string, string>,
    optionsBytes: Buffer | Uint8Array
  ): Buffer {
    return this.callReq('capture', requestBytes, metadata, optionsBytes);
  }

  /** Parse connector HTTP response for capture flow. */
  captureRes(
    responseBytes: Buffer | Uint8Array,
    requestBytes: Buffer | Uint8Array,
    metadata: Record<string, string>,
    optionsBytes: Buffer | Uint8Array
  ): Buffer {
    return this.callRes('capture', responseBytes, requestBytes, metadata, optionsBytes);
  }

  /** Build connector HTTP request for create_access_token flow. */
  createAccessTokenReq(
    requestBytes: Buffer | Uint8Array,
    metadata: Record<string, string>,
    optionsBytes: Buffer | Uint8Array
  ): Buffer {
    return this.callReq('create_access_token', requestBytes, metadata, optionsBytes);
  }

  /** Parse connector HTTP response for create_access_token flow. */
  createAccessTokenRes(
    responseBytes: Buffer | Uint8Array,
    requestBytes: Buffer | Uint8Array,
    metadata: Record<string, string>,
    optionsBytes: Buffer | Uint8Array
  ): Buffer {
    return this.callRes('create_access_token', responseBytes, requestBytes, metadata, optionsBytes);
  }

  /** Build connector HTTP request for get flow. */
  getReq(
    requestBytes: Buffer | Uint8Array,
    metadata: Record<string, string>,
    optionsBytes: Buffer | Uint8Array
  ): Buffer {
    return this.callReq('get', requestBytes, metadata, optionsBytes);
  }

  /** Parse connector HTTP response for get flow. */
  getRes(
    responseBytes: Buffer | Uint8Array,
    requestBytes: Buffer | Uint8Array,
    metadata: Record<string, string>,
    optionsBytes: Buffer | Uint8Array
  ): Buffer {
    return this.callRes('get', responseBytes, requestBytes, metadata, optionsBytes);
  }

  /** Build connector HTTP request for refund flow. */
  refundReq(
    requestBytes: Buffer | Uint8Array,
    metadata: Record<string, string>,
    optionsBytes: Buffer | Uint8Array
  ): Buffer {
    return this.callReq('refund', requestBytes, metadata, optionsBytes);
  }

  /** Parse connector HTTP response for refund flow. */
  refundRes(
    responseBytes: Buffer | Uint8Array,
    requestBytes: Buffer | Uint8Array,
    metadata: Record<string, string>,
    optionsBytes: Buffer | Uint8Array
  ): Buffer {
    return this.callRes('refund', responseBytes, requestBytes, metadata, optionsBytes);
  }

  /** Build connector HTTP request for void flow. */
  voidReq(
    requestBytes: Buffer | Uint8Array,
    metadata: Record<string, string>,
    optionsBytes: Buffer | Uint8Array
  ): Buffer {
    return this.callReq('void', requestBytes, metadata, optionsBytes);
  }

  /** Parse connector HTTP response for void flow. */
  voidRes(
    responseBytes: Buffer | Uint8Array,
    requestBytes: Buffer | Uint8Array,
    metadata: Record<string, string>,
    optionsBytes: Buffer | Uint8Array
  ): Buffer {
    return this.callRes('void', responseBytes, requestBytes, metadata, optionsBytes);
  }

  // <GENERATED_FLOWS_END>
}
