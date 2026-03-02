// AUTO-GENERATED — do not edit by hand.
// Source: services.proto ∩ bindings/uniffi.rs  |  Regenerate: make generate
//
// Declares dynamically-attached {flow}Req / {flow}Res methods on UniffiClient
// so IDEs offer completions and type checking for the low-level FFI wrapper.

type Bytes = Buffer | Uint8Array;
type Metadata = Record<string, string>;

export declare class UniffiClient {
  constructor(libPath?: string);

  callReq(flow: string, requestBytes: Bytes, metadata: Metadata, optionsBytes?: Bytes | null): string;
  callRes(flow: string, responseBody: Bytes, statusCode: number, responseHeaders: Metadata, requestBytes: Bytes, metadata: Metadata, optionsBytes?: Bytes | null): Buffer;

  /** PaymentService.Authorize — Authorize a payment amount on a payment method. This reserves funds without capturing them, essential for verifying availability before finalizing. */
  authorizeReq(requestBytes: Bytes, metadata: Metadata, optionsBytes?: Bytes | null): string;
  /** PaymentService.Authorize — parse connector HTTP response */
  authorizeRes(responseBody: Bytes, statusCode: number, responseHeaders: Metadata, requestBytes: Bytes, metadata: Metadata, optionsBytes?: Bytes | null): Buffer;

  /** PaymentService.Capture — Finalize an authorized payment transaction. Transfers reserved funds from customer to merchant account, completing the payment lifecycle. */
  captureReq(requestBytes: Bytes, metadata: Metadata, optionsBytes?: Bytes | null): string;
  /** PaymentService.Capture — parse connector HTTP response */
  captureRes(responseBody: Bytes, statusCode: number, responseHeaders: Metadata, requestBytes: Bytes, metadata: Metadata, optionsBytes?: Bytes | null): Buffer;

  /** MerchantAuthenticationService.CreateAccessToken — Generate short-lived connector authentication token. Provides secure credentials for connector API access without storing secrets client-side. */
  createAccessTokenReq(requestBytes: Bytes, metadata: Metadata, optionsBytes?: Bytes | null): string;
  /** MerchantAuthenticationService.CreateAccessToken — parse connector HTTP response */
  createAccessTokenRes(responseBody: Bytes, statusCode: number, responseHeaders: Metadata, requestBytes: Bytes, metadata: Metadata, optionsBytes?: Bytes | null): Buffer;

  /** PaymentService.Get — Retrieve current payment status from the payment processor. Enables synchronization between your system and payment processors for accurate state tracking. */
  getReq(requestBytes: Bytes, metadata: Metadata, optionsBytes?: Bytes | null): string;
  /** PaymentService.Get — parse connector HTTP response */
  getRes(responseBody: Bytes, statusCode: number, responseHeaders: Metadata, requestBytes: Bytes, metadata: Metadata, optionsBytes?: Bytes | null): Buffer;

  /** PaymentService.Refund — Initiate a refund to customer's payment method. Returns funds for returns, cancellations, or service adjustments after original payment. */
  refundReq(requestBytes: Bytes, metadata: Metadata, optionsBytes?: Bytes | null): string;
  /** PaymentService.Refund — parse connector HTTP response */
  refundRes(responseBody: Bytes, statusCode: number, responseHeaders: Metadata, requestBytes: Bytes, metadata: Metadata, optionsBytes?: Bytes | null): Buffer;

  /** PaymentService.Void — Cancel an authorized payment before capture. Releases held funds back to customer, typically used when orders are cancelled or abandoned. */
  voidReq(requestBytes: Bytes, metadata: Metadata, optionsBytes?: Bytes | null): string;
  /** PaymentService.Void — parse connector HTTP response */
  voidRes(responseBody: Bytes, statusCode: number, responseHeaders: Metadata, requestBytes: Bytes, metadata: Metadata, optionsBytes?: Bytes | null): Buffer;

}
