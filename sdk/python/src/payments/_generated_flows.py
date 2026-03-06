# AUTO-GENERATED — do not edit by hand.
# Source: services.proto ∩ bindings/uniffi.rs  |  Regenerate: make generate
SERVICE_FLOWS = {
    "PaymentClient": {
        # authorize: PaymentService.Authorize — Authorize a payment amount on a payment method. This reserves funds without capturing them, essential for verifying availability before finalizing.
        "authorize": "PaymentServiceAuthorizeResponse",
        # capture: PaymentService.Capture — Finalize an authorized payment transaction. Transfers reserved funds from customer to merchant account, completing the payment lifecycle.
        "capture": "PaymentServiceCaptureResponse",
        # get: PaymentService.Get — Retrieve current payment status from the payment processor. Enables synchronization between your system and payment processors for accurate state tracking.
        "get": "PaymentServiceGetResponse",
        # refund: PaymentService.Refund — Initiate a refund to customer's payment method. Returns funds for returns, cancellations, or service adjustments after original payment.
        "refund": "RefundResponse",
        # void: PaymentService.Void — Cancel an authorized payment before capture. Releases held funds back to customer, typically used when orders are cancelled or abandoned.
        "void": "PaymentServiceVoidResponse",
    },
    "MerchantAuthenticationClient": {
        # create_access_token: MerchantAuthenticationService.CreateAccessToken — Generate short-lived connector authentication token. Provides secure credentials for connector API access without storing secrets client-side.
        "create_access_token": "MerchantAuthenticationServiceCreateAccessTokenResponse",
    },
}
