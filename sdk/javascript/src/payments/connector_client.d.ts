// AUTO-GENERATED — do not edit by hand.
// Source: services.proto ∩ bindings/uniffi.rs  |  Regenerate: make generate
//
// Declares dynamically-attached flow methods so IDEs offer completions
// and type checking when using ConnectorClient from TypeScript or JS.
import { ucs } from "./generated/proto";

type Metadata = Record<string, string>;

export declare class ConnectorClient {
  constructor(libPath?: string);

  /** PaymentService.Authorize — Authorize a payment amount on a payment method. This reserves funds without capturing them, essential for verifying availability before finalizing. */
  authorize(
    request: ucs.v2.IPaymentServiceAuthorizeRequest,
    metadata: Metadata,
    ffiOptions?: ucs.v2.IFfiOptions,
  ): Promise<ucs.v2.PaymentServiceAuthorizeResponse>;

  /** PaymentService.Capture — Finalize an authorized payment transaction. Transfers reserved funds from customer to merchant account, completing the payment lifecycle. */
  capture(
    request: ucs.v2.IPaymentServiceCaptureRequest,
    metadata: Metadata,
    ffiOptions?: ucs.v2.IFfiOptions,
  ): Promise<ucs.v2.PaymentServiceCaptureResponse>;

  /** MerchantAuthenticationService.CreateAccessToken — Generate short-lived connector authentication token. Provides secure credentials for connector API access without storing secrets client-side. */
  create_access_token(
    request: ucs.v2.IMerchantAuthenticationServiceCreateAccessTokenRequest,
    metadata: Metadata,
    ffiOptions?: ucs.v2.IFfiOptions,
  ): Promise<ucs.v2.MerchantAuthenticationServiceCreateAccessTokenResponse>;

  /** PaymentService.Get — Retrieve current payment status from the payment processor. Enables synchronization between your system and payment processors for accurate state tracking. */
  get(
    request: ucs.v2.IPaymentServiceGetRequest,
    metadata: Metadata,
    ffiOptions?: ucs.v2.IFfiOptions,
  ): Promise<ucs.v2.PaymentServiceGetResponse>;

  /** PaymentService.Refund — Initiate a refund to customer's payment method. Returns funds for returns, cancellations, or service adjustments after original payment. */
  refund(
    request: ucs.v2.IPaymentServiceRefundRequest,
    metadata: Metadata,
    ffiOptions?: ucs.v2.IFfiOptions,
  ): Promise<ucs.v2.RefundResponse>;

  /** PaymentService.Void — Cancel an authorized payment before capture. Releases held funds back to customer, typically used when orders are cancelled or abandoned. */
  void(
    request: ucs.v2.IPaymentServiceVoidRequest,
    metadata: Metadata,
    ffiOptions?: ucs.v2.IFfiOptions,
  ): Promise<ucs.v2.PaymentServiceVoidResponse>;

}
