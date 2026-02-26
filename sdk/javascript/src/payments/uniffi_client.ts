/**
 * UniFFI client for Node.js — calls the same shared library as Python/Kotlin.
 *
 * Uses koffi to call the UniFFI C ABI directly, replacing NAPI entirely.
 * Handles RustBuffer serialization/deserialization for the UniFFI protocol.
 */

import koffi from "koffi";
import path from "path";
import { HttpRequest } from "../http_client";

// Standard Node.js __dirname
declare const __dirname: string;
const _dirname = __dirname;

// ── RustBuffer struct layout ────────────────────────────────────────────────
// UniFFI uses RustBuffer { capacity: u64, len: u64, data: *u8 } for all
// compound types (bytes, strings, maps). 

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
  authorize_req: (req: RustBuffer, meta: RustBuffer, status: any) => RustBuffer;
  capture_req: (req: RustBuffer, meta: RustBuffer, status: any) => RustBuffer;
  void_req: (req: RustBuffer, meta: RustBuffer, status: any) => RustBuffer;
  get_req: (req: RustBuffer, meta: RustBuffer, status: any) => RustBuffer;
  refund_req: (req: RustBuffer, meta: RustBuffer, status: any) => RustBuffer;
  authorize_res: (body: RustBuffer, code: number, headers: RustBuffer, req: RustBuffer, meta: RustBuffer, status: any) => RustBuffer;
  alloc: (len: bigint, status: any) => RustBuffer;
  free: (buf: RustBuffer, status: any) => void;
}

function loadLib(libPath?: string): FfiFunctions {
  if (!libPath) {
    const ext = process.platform === "darwin" ? "dylib" : "so";
    libPath = path.join(_dirname, "generated", `libconnector_service_ffi.${ext}`);
  }

  const lib = koffi.load(libPath);

  return {
    authorize_req: lib.func(
      "uniffi_connector_service_ffi_fn_func_authorize_req_transformer",
      RustBufferStruct,
      [RustBufferStruct, RustBufferStruct, koffi.out(koffi.pointer(RustCallStatusStruct))]
    ),
    capture_req: lib.func(
      "uniffi_connector_service_ffi_fn_func_capture_req_transformer",
      RustBufferStruct,
      [RustBufferStruct, RustBufferStruct, koffi.out(koffi.pointer(RustCallStatusStruct))]
    ),
    void_req: lib.func(
      "uniffi_connector_service_ffi_fn_func_void_req_transformer",
      RustBufferStruct,
      [RustBufferStruct, RustBufferStruct, koffi.out(koffi.pointer(RustCallStatusStruct))]
    ),
    get_req: lib.func(
      "uniffi_connector_service_ffi_fn_func_get_req_transformer",
      RustBufferStruct,
      [RustBufferStruct, RustBufferStruct, koffi.out(koffi.pointer(RustCallStatusStruct))]
    ),
    refund_req: lib.func(
      "uniffi_connector_service_ffi_fn_func_refund_req_transformer",
      RustBufferStruct,
      [RustBufferStruct, RustBufferStruct, koffi.out(koffi.pointer(RustCallStatusStruct))]
    ),
    authorize_res: lib.func(
      "uniffi_connector_service_ffi_fn_func_authorize_res_transformer",
      RustBufferStruct,
      [RustBufferStruct, "uint16", RustBufferStruct, RustBufferStruct, RustBufferStruct, koffi.out(koffi.pointer(RustCallStatusStruct))]
    ),
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

  const variant = raw.readInt32BE(offset);
  offset += 4;

  const variantNames: Record<number, string> = {
    1: "DecodeError",
    2: "MissingMetadata",
    3: "MetadataParseError",
    4: "HandlerError",
    5: "NoConnectorRequest",
  };

  if (variant === 5) return "NoConnectorRequest";

  const strLen = raw.readInt32BE(offset);
  offset += 4;
  const msg = raw.subarray(offset, offset + strLen).toString("utf-8");
  return `${variantNames[variant] || "UniffiError"}: ${msg}`;
}

function liftString(buf: RustBuffer): string {
  if (!buf.data || buf.len === 0n) return "";
  const raw = Buffer.from(koffi.decode(buf.data, "uint8", Number(buf.len)));
  return raw.toString("utf-8");
}

function liftBytes(buf: RustBuffer): Buffer {
  if (!buf.data || buf.len === 0n) return Buffer.alloc(0);
  const raw = Buffer.from(koffi.decode(buf.data, "uint8", Number(buf.len)));
  const len = raw.readInt32BE(0);
  return raw.subarray(4, 4 + len);
}

/**
 * Lifts a Record from a RustBuffer using the UniFFI binary layout.
 */
function liftConnectorHttpRequest(buf: RustBuffer): HttpRequest {
  if (!buf.data || buf.len === 0n) throw new Error("Empty buffer returned from FFI");
  const raw = Buffer.from(koffi.decode(buf.data, "uint8", Number(buf.len)));
  let offset = 0;

  // 1. URL (String)
  const urlLen = raw.readInt32BE(offset); offset += 4;
  const url = raw.subarray(offset, offset + urlLen).toString("utf-8"); offset += urlLen;

  // 2. Method (String)
  const methodLen = raw.readInt32BE(offset); offset += 4;
  const method = raw.subarray(offset, offset + methodLen).toString("utf-8"); offset += methodLen;

  // 3. Headers (HashMap<String, String>)
  const headersCount = raw.readInt32BE(offset); offset += 4;
  const headers: Record<string, string> = {};
  for (let i = 0; i < headersCount; i++) {
    const keyLen = raw.readInt32BE(offset); offset += 4;
    const key = raw.subarray(offset, offset + keyLen).toString("utf-8"); offset += keyLen;
    const valLen = raw.readInt32BE(offset); offset += 4;
    const val = raw.subarray(offset, offset + valLen).toString("utf-8"); offset += valLen;
    headers[key] = val;
  }

  // 4. Body (Option<Vec<u8>>)
  const hasBody = raw.readInt8(offset); offset += 1;
  let body: Uint8Array | undefined;
  if (hasBody === 1) {
    const bodyLen = raw.readInt32BE(offset); offset += 4;
    body = new Uint8Array(raw.subarray(offset, offset + bodyLen));
  }

  return { url, method, headers, body };
}

function freeRustBuffer(ffi: FfiFunctions, buf: RustBuffer): void {
  if (buf.data && buf.len > 0n) {
    const status = makeCallStatus();
    ffi.free(buf, status);
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

// ── Serialization (lower) ───────────────────────────────────────────────────
function lowerBytes(ffi: FfiFunctions, bytes: Buffer | Uint8Array): RustBuffer {
  const buf = Buffer.alloc(4 + bytes.length);
  buf.writeInt32BE(bytes.length, 0);
  Buffer.from(bytes).copy(buf, 4);
  return allocRustBuffer(ffi, buf);
}

function lowerMap(ffi: FfiFunctions, map: Record<string, string>): RustBuffer {
  const entries = Object.entries(map);
  let totalSize = 4;
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

export class UniffiClient {
  private _ffi: FfiFunctions;

  constructor(libPath?: string) {
    this._ffi = loadLib(libPath);
  }

  authorizeReq(requestBytes: Buffer | Uint8Array, metadata: Record<string, string>): HttpRequest {
    const status = makeCallStatus();
    const rbRequest = lowerBytes(this._ffi, requestBytes);
    const rbMetadata = lowerMap(this._ffi, metadata);

    const result = this._ffi.authorize_req(rbRequest, rbMetadata, status);

    try {
      checkCallStatus(this._ffi, status);
      return liftConnectorHttpRequest(result);
    } finally {
      freeRustBuffer(this._ffi, result);
    }
  }

  authorizeRes(
    responseBody: Buffer | Uint8Array,
    statusCode: number,
    responseHeaders: Record<string, string>,
    requestBytes: Buffer | Uint8Array,
    metadata: Record<string, string>
  ): Buffer {
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
