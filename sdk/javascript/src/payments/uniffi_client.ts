/**
 * UniFFI client for Node.js — calls the same shared library as Python/Kotlin.
 *
 * Uses koffi to call the UniFFI C ABI directly, replacing NAPI entirely.
 */

import koffi from "koffi";
import path from "path";
import { HttpRequest, HttpResponse } from "../http_client";

// Standard Node.js __dirname
declare const __dirname: string;
const _dirname = __dirname;

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
  authorize_req: (req: RustBuffer, meta: RustBuffer, opts: RustBuffer, status: any) => RustBuffer;
  authorize_res: (res: RustBuffer, req: RustBuffer, meta: RustBuffer, opts: RustBuffer, status: any) => RustBuffer;
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
      [RustBufferStruct, RustBufferStruct, RustBufferStruct, koffi.out(koffi.pointer(RustCallStatusStruct))]
    ),
    authorize_res: lib.func(
      "uniffi_connector_service_ffi_fn_func_authorize_res_transformer",
      RustBufferStruct,
      [RustBufferStruct, RustBufferStruct, RustBufferStruct, RustBufferStruct, koffi.out(koffi.pointer(RustCallStatusStruct))]
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

function liftString(buf: RustBuffer): string {
  if (!buf.data || buf.len === 0n) return "";
  const raw = Buffer.from(koffi.decode(buf.data, "uint8", Number(buf.len)));
  return raw.toString("utf-8");
}

function liftBytes(buf: RustBuffer): Buffer {
  if (!buf.data || buf.len === 0n) return Buffer.alloc(0);
  const raw = Buffer.from(koffi.decode(buf.data, "uint8", Number(buf.len)));
  // Bytes are serialized as: i32 length + raw bytes
  const len = raw.readInt32BE(0);
  return raw.subarray(4, 4 + len);
}

function liftConnectorHttpRequest(buf: RustBuffer): HttpRequest {
  if (!buf.data || buf.len === 0n) throw new Error("Empty buffer");
  const raw = Buffer.from(koffi.decode(buf.data, "uint8", Number(buf.len)));
  let offset = 0;

  const readStr = () => {
    const len = raw.readInt32BE(offset); offset += 4;
    const s = raw.subarray(offset, offset + len).toString("utf-8"); offset += len;
    return s;
  };

  const url = readStr();
  const method = readStr();

  const headersCount = raw.readInt32BE(offset); offset += 4;
  const headers: Record<string, string> = {};
  for (let i = 0; i < headersCount; i++) {
    headers[readStr()] = readStr();
  }

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
 * Lowers raw data into a UniFFI-compliant RustBuffer.
 * This is used for Top-level Vec<u8> parameters.
 */
function lowerBytes(ffi: FfiFunctions, data: Buffer | Uint8Array): RustBuffer {
  const buf = Buffer.alloc(4 + data.length);
  buf.writeInt32BE(data.length, 0);
  Buffer.from(data).copy(buf, 4);
  return allocRustBuffer(ffi, buf);
}

/**
 * Lowers a Map into a UniFFI-compliant RustBuffer.
 * This is used for Top-level HashMap parameters.
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

/**
 * Lowers an HttpResponse into an FfiConnectorHttpResponse UniFFI record.
 */
function lowerConnectorHttpResponse(ffi: FfiFunctions, res: HttpResponse): RustBuffer {
  // A Record is just the concatenation of its fields.
  // 1. status_code (u16) -> 2 bytes
  // 2. headers (HashMap) -> lowerMap layout
  // 3. body (Vec<u8>)    -> lowerBytes layout
  
  const entries = Object.entries(res.headers);
  let headersSize = 4;
  const encodedHeaders = entries.map(([k, v]) => {
    const kBuf = Buffer.from(k, "utf-8");
    const vBuf = Buffer.from(v, "utf-8");
    headersSize += 4 + kBuf.length + 4 + vBuf.length;
    return { kBuf, vBuf };
  });

  const totalSize = 2 + headersSize + (4 + res.body.length);
  const buf = Buffer.alloc(totalSize);
  let offset = 0;
  
  // 1. status_code
  buf.writeUInt16BE(res.statusCode, offset); offset += 2;

  // 2. headers
  buf.writeInt32BE(entries.length, offset); offset += 4;
  for (const { kBuf, vBuf } of encodedHeaders) {
    buf.writeInt32BE(kBuf.length, offset); offset += 4;
    kBuf.copy(buf, offset); offset += kBuf.length;
    buf.writeInt32BE(vBuf.length, offset); offset += 4;
    vBuf.copy(buf, offset); offset += vBuf.length;
  }

  // 3. body
  buf.writeInt32BE(res.body.length, offset); offset += 4;
  Buffer.from(res.body).copy(buf, offset);

  return allocRustBuffer(ffi, buf);
}

export class UniffiClient {
  private _ffi: FfiFunctions;

  constructor(libPath?: string) {
    this._ffi = loadLib(libPath);
  }

  authorizeReq(
    requestBytes: Buffer | Uint8Array,
    metadata: Record<string, string>,
    optionsBytes: Buffer | Uint8Array
  ): HttpRequest {
    const rbReq = lowerBytes(this._ffi, requestBytes);
    const rbMeta = lowerMap(this._ffi, metadata);
    const rbOpts = lowerBytes(this._ffi, optionsBytes);
    const status = makeCallStatus();

    const result = this._ffi.authorize_req(rbReq, rbMeta, rbOpts, status);

    try {
      checkCallStatus(this._ffi, status);
      return liftConnectorHttpRequest(result);
    } finally {
      freeRustBuffer(this._ffi, result);
    }
  }

  authorizeRes(
    response: HttpResponse,
    requestBytes: Buffer | Uint8Array,
    metadata: Record<string, string>,
    optionsBytes: Buffer | Uint8Array
  ): Buffer {
    const rbRes = lowerConnectorHttpResponse(this._ffi, response);
    const rbReq = lowerBytes(this._ffi, requestBytes);
    const rbMeta = lowerMap(this._ffi, metadata);
    const rbOpts = lowerBytes(this._ffi, optionsBytes);
    const status = makeCallStatus();

    const result = this._ffi.authorize_res(
      rbRes,
      rbReq,
      rbMeta,
      rbOpts,
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
