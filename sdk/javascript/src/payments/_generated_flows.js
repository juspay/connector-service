// AUTO-GENERATED — do not edit by hand.
// Source: services.proto ∩ bindings/uniffi.rs  |  Regenerate: make generate
"use strict";

const FLOWS = {
  // authorize: PaymentService.Authorize — Authorize a payment amount on a payment method. This reserves funds without capturing them, essential for verifying availability before finalizing.
  authorize           : { request: "PaymentServiceAuthorizeRequest", response: "PaymentServiceAuthorizeResponse" },

  // capture: PaymentService.Capture — Finalize an authorized payment transaction. Transfers reserved funds from customer to merchant account, completing the payment lifecycle.
  capture             : { request: "PaymentServiceCaptureRequest", response: "PaymentServiceCaptureResponse" },

  // charge: RecurringPaymentService.Charge — Charge using an existing stored recurring payment instruction. Processes repeat payments for subscriptions or recurring billing without collecting payment details.
  charge              : { request: "RecurringPaymentServiceChargeRequest", response: "RecurringPaymentServiceChargeResponse" },

  // create: CustomerService.Create — Create customer record in the payment processor system. Stores customer details for future payment operations without re-sending personal information.
  create              : { request: "CustomerServiceCreateRequest", response: "CustomerServiceCreateResponse" },

  // create_access_token: MerchantAuthenticationService.CreateAccessToken — Generate short-lived connector authentication token. Provides secure credentials for connector API access without storing secrets client-side.
  create_access_token : { request: "MerchantAuthenticationServiceCreateAccessTokenRequest", response: "MerchantAuthenticationServiceCreateAccessTokenResponse" },

  // create_order: PaymentService.CreateOrder — Initialize an order in the payment processor system. Sets up payment context before customer enters card details for improved authorization rates.
  create_order        : { request: "PaymentServiceCreateOrderRequest", response: "PaymentServiceCreateOrderResponse" },

  // get: PaymentService.Get — Retrieve current payment status from the payment processor. Enables synchronization between your system and payment processors for accurate state tracking.
  get                 : { request: "PaymentServiceGetRequest", response: "PaymentServiceGetResponse" },

  // refund: PaymentService.Refund — Initiate a refund to customer's payment method. Returns funds for returns, cancellations, or service adjustments after original payment.
  refund              : { request: "PaymentServiceRefundRequest", response: "RefundResponse" },

  // reverse: PaymentService.Reverse — Reverse a captured payment before settlement. Recovers funds after capture but before bank settlement, used for corrections or cancellations.
  reverse             : { request: "PaymentServiceReverseRequest", response: "PaymentServiceReverseResponse" },

  // void: PaymentService.Void — Cancel an authorized payment before capture. Releases held funds back to customer, typically used when orders are cancelled or abandoned.
  void                : { request: "PaymentServiceVoidRequest", response: "PaymentServiceVoidResponse" },

};

module.exports = { FLOWS };
