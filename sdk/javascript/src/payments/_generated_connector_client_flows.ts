// AUTO-GENERATED — do not edit by hand.
// Source: services.proto ∩ bindings/uniffi.rs  |  Regenerate: make generate

import { ConnectorClient as _ConnectorClientBase } from "./connector_client";
// @ts-ignore - protobuf generated files might not have types yet
import { ucs } from "./generated/proto";

export class ConnectorClient extends _ConnectorClientBase {
  /** PaymentService.Authorize — Authorize a payment amount on a payment method. This reserves funds without capturing them, essential for verifying availability before finalizing. */
  async authorize(
    requestMsg: ucs.v2.IPaymentServiceAuthorizeRequest,
    metadata: Record<string, string>,
    requestOptions?: ucs.v2.IRequestOptions | null
  ): Promise<ucs.v2.PaymentServiceAuthorizeResponse> {
    return this._executeFlow('authorize', requestMsg, metadata, requestOptions, 'PaymentServiceAuthorizeRequest', 'PaymentServiceAuthorizeResponse') as Promise<ucs.v2.PaymentServiceAuthorizeResponse>;
  }

  /** PaymentService.Capture — Finalize an authorized payment transaction. Transfers reserved funds from customer to merchant account, completing the payment lifecycle. */
  async capture(
    requestMsg: ucs.v2.IPaymentServiceCaptureRequest,
    metadata: Record<string, string>,
    requestOptions?: ucs.v2.IRequestOptions | null
  ): Promise<ucs.v2.PaymentServiceCaptureResponse> {
    return this._executeFlow('capture', requestMsg, metadata, requestOptions, 'PaymentServiceCaptureRequest', 'PaymentServiceCaptureResponse') as Promise<ucs.v2.PaymentServiceCaptureResponse>;
  }

  /** MerchantAuthenticationService.CreateAccessToken — Generate short-lived connector authentication token. Provides secure credentials for connector API access without storing secrets client-side. */
  async createAccessToken(
    requestMsg: ucs.v2.IMerchantAuthenticationServiceCreateAccessTokenRequest,
    metadata: Record<string, string>,
    requestOptions?: ucs.v2.IRequestOptions | null
  ): Promise<ucs.v2.MerchantAuthenticationServiceCreateAccessTokenResponse> {
    return this._executeFlow('create_access_token', requestMsg, metadata, requestOptions, 'MerchantAuthenticationServiceCreateAccessTokenRequest', 'MerchantAuthenticationServiceCreateAccessTokenResponse') as Promise<ucs.v2.MerchantAuthenticationServiceCreateAccessTokenResponse>;
  }

  /** PaymentService.Get — Retrieve current payment status from the payment processor. Enables synchronization between your system and payment processors for accurate state tracking. */
  async get(
    requestMsg: ucs.v2.IPaymentServiceGetRequest,
    metadata: Record<string, string>,
    requestOptions?: ucs.v2.IRequestOptions | null
  ): Promise<ucs.v2.PaymentServiceGetResponse> {
    return this._executeFlow('get', requestMsg, metadata, requestOptions, 'PaymentServiceGetRequest', 'PaymentServiceGetResponse') as Promise<ucs.v2.PaymentServiceGetResponse>;
  }

  /** PaymentService.Refund — Initiate a refund to customer's payment method. Returns funds for returns, cancellations, or service adjustments after original payment. */
  async refund(
    requestMsg: ucs.v2.IPaymentServiceRefundRequest,
    metadata: Record<string, string>,
    requestOptions?: ucs.v2.IRequestOptions | null
  ): Promise<ucs.v2.RefundResponse> {
    return this._executeFlow('refund', requestMsg, metadata, requestOptions, 'PaymentServiceRefundRequest', 'RefundResponse') as Promise<ucs.v2.RefundResponse>;
  }

  /** PaymentService.Void — Cancel an authorized payment before capture. Releases held funds back to customer, typically used when orders are cancelled or abandoned. */
  async void(
    requestMsg: ucs.v2.IPaymentServiceVoidRequest,
    metadata: Record<string, string>,
    requestOptions?: ucs.v2.IRequestOptions | null
  ): Promise<ucs.v2.PaymentServiceVoidResponse> {
    return this._executeFlow('void', requestMsg, metadata, requestOptions, 'PaymentServiceVoidRequest', 'PaymentServiceVoidResponse') as Promise<ucs.v2.PaymentServiceVoidResponse>;
  }

}
