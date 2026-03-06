// AUTO-GENERATED — do not edit by hand.
// Source: services.proto ∩ bindings/uniffi.rs  |  Regenerate: make generate

import { UniffiClient as _UniffiClientBase } from "./uniffi_client";

export class UniffiClient extends _UniffiClientBase {
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

}
