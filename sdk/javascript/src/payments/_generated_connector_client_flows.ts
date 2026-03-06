// AUTO-GENERATED — do not edit by hand.
// Source: services.proto ∩ bindings/uniffi.rs  |  Regenerate: make generate

import { ConnectorClient as _ConnectorClientBase } from "./connector_client";
// @ts-ignore - protobuf generated files might not have types yet
import { ucs } from "./generated/proto";

export class PaymentClient extends _ConnectorClientBase {
  /** PaymentService.Authorize — Authorize a payment amount on a payment method. This reserves funds without capturing them, essential for verifying availability before finalizing. */
  async authorize(
    requestMsg: ucs.v2.IPaymentServiceAuthorizeRequest,
    metadata: Record<string, string>,
    ffiOptions?: ucs.v2.IFfiOptions | null
  ): Promise<ucs.v2.PaymentServiceAuthorizeResponse> {
    return this._executeFlow('authorize', requestMsg, metadata, ffiOptions, 'PaymentServiceAuthorizeRequest', 'PaymentServiceAuthorizeResponse') as Promise<ucs.v2.PaymentServiceAuthorizeResponse>;
  }

  /** PaymentService.Capture — Finalize an authorized payment transaction. Transfers reserved funds from customer to merchant account, completing the payment lifecycle. */
  async capture(
    requestMsg: ucs.v2.IPaymentServiceCaptureRequest,
    metadata: Record<string, string>,
    ffiOptions?: ucs.v2.IFfiOptions | null
  ): Promise<ucs.v2.PaymentServiceCaptureResponse> {
    return this._executeFlow('capture', requestMsg, metadata, ffiOptions, 'PaymentServiceCaptureRequest', 'PaymentServiceCaptureResponse') as Promise<ucs.v2.PaymentServiceCaptureResponse>;
  }

  /** PaymentService.CreateOrder — Initialize an order in the payment processor system. Sets up payment context before customer enters card details for improved authorization rates. */
  async createOrder(
    requestMsg: ucs.v2.IPaymentServiceCreateOrderRequest,
    metadata: Record<string, string>,
    ffiOptions?: ucs.v2.IFfiOptions | null
  ): Promise<ucs.v2.PaymentServiceCreateOrderResponse> {
    return this._executeFlow('create_order', requestMsg, metadata, ffiOptions, 'PaymentServiceCreateOrderRequest', 'PaymentServiceCreateOrderResponse') as Promise<ucs.v2.PaymentServiceCreateOrderResponse>;
  }

  /** PaymentService.Get — Retrieve current payment status from the payment processor. Enables synchronization between your system and payment processors for accurate state tracking. */
  async get(
    requestMsg: ucs.v2.IPaymentServiceGetRequest,
    metadata: Record<string, string>,
    ffiOptions?: ucs.v2.IFfiOptions | null
  ): Promise<ucs.v2.PaymentServiceGetResponse> {
    return this._executeFlow('get', requestMsg, metadata, ffiOptions, 'PaymentServiceGetRequest', 'PaymentServiceGetResponse') as Promise<ucs.v2.PaymentServiceGetResponse>;
  }

  /** PaymentService.Refund — Initiate a refund to customer's payment method. Returns funds for returns, cancellations, or service adjustments after original payment. */
  async refund(
    requestMsg: ucs.v2.IPaymentServiceRefundRequest,
    metadata: Record<string, string>,
    ffiOptions?: ucs.v2.IFfiOptions | null
  ): Promise<ucs.v2.RefundResponse> {
    return this._executeFlow('refund', requestMsg, metadata, ffiOptions, 'PaymentServiceRefundRequest', 'RefundResponse') as Promise<ucs.v2.RefundResponse>;
  }

  /** PaymentService.Reverse — Reverse a captured payment before settlement. Recovers funds after capture but before bank settlement, used for corrections or cancellations. */
  async reverse(
    requestMsg: ucs.v2.IPaymentServiceReverseRequest,
    metadata: Record<string, string>,
    ffiOptions?: ucs.v2.IFfiOptions | null
  ): Promise<ucs.v2.PaymentServiceReverseResponse> {
    return this._executeFlow('reverse', requestMsg, metadata, ffiOptions, 'PaymentServiceReverseRequest', 'PaymentServiceReverseResponse') as Promise<ucs.v2.PaymentServiceReverseResponse>;
  }

  /** PaymentService.Void — Cancel an authorized payment before capture. Releases held funds back to customer, typically used when orders are cancelled or abandoned. */
  async void(
    requestMsg: ucs.v2.IPaymentServiceVoidRequest,
    metadata: Record<string, string>,
    ffiOptions?: ucs.v2.IFfiOptions | null
  ): Promise<ucs.v2.PaymentServiceVoidResponse> {
    return this._executeFlow('void', requestMsg, metadata, ffiOptions, 'PaymentServiceVoidRequest', 'PaymentServiceVoidResponse') as Promise<ucs.v2.PaymentServiceVoidResponse>;
  }

}

export class RecurringPaymentClient extends _ConnectorClientBase {
  /** RecurringPaymentService.Charge — Charge using an existing stored recurring payment instruction. Processes repeat payments for subscriptions or recurring billing without collecting payment details. */
  async charge(
    requestMsg: ucs.v2.IRecurringPaymentServiceChargeRequest,
    metadata: Record<string, string>,
    ffiOptions?: ucs.v2.IFfiOptions | null
  ): Promise<ucs.v2.RecurringPaymentServiceChargeResponse> {
    return this._executeFlow('charge', requestMsg, metadata, ffiOptions, 'RecurringPaymentServiceChargeRequest', 'RecurringPaymentServiceChargeResponse') as Promise<ucs.v2.RecurringPaymentServiceChargeResponse>;
  }

}

export class CustomerClient extends _ConnectorClientBase {
  /** CustomerService.Create — Create customer record in the payment processor system. Stores customer details for future payment operations without re-sending personal information. */
  async create(
    requestMsg: ucs.v2.ICustomerServiceCreateRequest,
    metadata: Record<string, string>,
    ffiOptions?: ucs.v2.IFfiOptions | null
  ): Promise<ucs.v2.CustomerServiceCreateResponse> {
    return this._executeFlow('create', requestMsg, metadata, ffiOptions, 'CustomerServiceCreateRequest', 'CustomerServiceCreateResponse') as Promise<ucs.v2.CustomerServiceCreateResponse>;
  }

}

export class MerchantAuthenticationClient extends _ConnectorClientBase {
  /** MerchantAuthenticationService.CreateAccessToken — Generate short-lived connector authentication token. Provides secure credentials for connector API access without storing secrets client-side. */
  async createAccessToken(
    requestMsg: ucs.v2.IMerchantAuthenticationServiceCreateAccessTokenRequest,
    metadata: Record<string, string>,
    ffiOptions?: ucs.v2.IFfiOptions | null
  ): Promise<ucs.v2.MerchantAuthenticationServiceCreateAccessTokenResponse> {
    return this._executeFlow('create_access_token', requestMsg, metadata, ffiOptions, 'MerchantAuthenticationServiceCreateAccessTokenRequest', 'MerchantAuthenticationServiceCreateAccessTokenResponse') as Promise<ucs.v2.MerchantAuthenticationServiceCreateAccessTokenResponse>;
  }

}
