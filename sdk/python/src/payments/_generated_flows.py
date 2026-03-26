# AUTO-GENERATED — do not edit by hand.
# Source: services.proto ∩ bindings/uniffi.rs  |  Regenerate: make generate
SERVICE_FLOWS = {
    "DisputeClient": {
        # accept: DisputeService.Accept — Concede dispute and accepts chargeback loss. Acknowledges liability and stops dispute defense process when evidence is insufficient.
        "accept": "DisputeServiceAcceptResponse",
        # defend: DisputeService.Defend — Submit defense with reason code for dispute. Presents formal argument against customer's chargeback claim with supporting documentation.
        "defend": "DisputeServiceDefendResponse",
        # submit_evidence: DisputeService.SubmitEvidence — Upload evidence to dispute customer chargeback. Provides documentation like receipts and delivery proof to contest fraudulent transaction claims.
        "submit_evidence": "DisputeServiceSubmitEvidenceResponse",
    },
    "PaymentMethodAuthenticationClient": {
        # authenticate: PaymentMethodAuthenticationService.Authenticate — Execute 3DS challenge or frictionless verification. Authenticates customer via bank challenge or behind-the-scenes verification for fraud prevention.
        "authenticate": "PaymentMethodAuthenticationServiceAuthenticateResponse",
        # post_authenticate: PaymentMethodAuthenticationService.PostAuthenticate — Validate authentication results with the issuing bank. Processes bank's authentication decision to determine if payment can proceed.
        "post_authenticate": "PaymentMethodAuthenticationServicePostAuthenticateResponse",
        # pre_authenticate: PaymentMethodAuthenticationService.PreAuthenticate — Initiate 3DS flow before payment authorization. Collects device data and prepares authentication context for frictionless or challenge-based verification.
        "pre_authenticate": "PaymentMethodAuthenticationServicePreAuthenticateResponse",
    },
    "DirectPaymentClient": {
        # authorize: DirectPaymentService.Authorize — Authorize a payment amount on a payment method. This reserves funds without capturing them, essential for verifying availability before finalizing.
        "authorize": "PaymentServiceAuthorizeResponse",
        # capture: DirectPaymentService.Capture — Finalize an authorized payment by transferring funds. Captures the authorized amount to complete the transaction and move funds to your merchant account.
        "capture": "PaymentServiceCaptureResponse",
        # create_order: DirectPaymentService.CreateOrder — Create a payment order for later processing. Establishes a transaction context that can be authorized or captured in subsequent API calls.
        "create_order": "PaymentServiceCreateOrderResponse",
        # get: DirectPaymentService.Get — Retrieve current payment status from the payment processor. Enables synchronization between your system and payment processors for accurate state tracking.
        "get": "PaymentServiceGetResponse",
        # refund: DirectPaymentService.Refund — Process a partial or full refund for a captured payment. Returns funds to the customer when goods are returned or services are cancelled.
        "refund": "RefundResponse",
        # reverse: DirectPaymentService.Reverse — Reverse a captured payment in full. Initiates a complete refund when you need to cancel a settled transaction rather than just an authorization.
        "reverse": "PaymentServiceReverseResponse",
        # setup_recurring: DirectPaymentService.SetupRecurring — Configure a payment method for recurring billing. Sets up the mandate and payment details needed for future automated charges.
        "setup_recurring": "PaymentServiceSetupRecurringResponse",
        # void: DirectPaymentService.Void — Cancel an authorized payment that has not been captured. Releases held funds back to the customer's payment method when a transaction cannot be completed.
        "void": "PaymentServiceVoidResponse",
    },
    "RecurringPaymentClient": {
        # charge: RecurringPaymentService.Charge — Charge using an existing stored recurring payment instruction. Processes repeat payments for subscriptions or recurring billing without collecting payment details.
        "charge": "RecurringPaymentServiceChargeResponse",
    },
    "CustomerClient": {
        # create: CustomerService.Create — Create customer record in the payment processor system. Stores customer details for future payment operations without re-sending personal information.
        "create": "CustomerServiceCreateResponse",
    },
    "MerchantAuthenticationClient": {
        # create_access_token: MerchantAuthenticationService.CreateAccessToken — Generate short-lived connector authentication token. Provides secure credentials for connector API access without storing secrets client-side.
        "create_access_token": "MerchantAuthenticationServiceCreateAccessTokenResponse",
        # create_session_token: MerchantAuthenticationService.CreateSessionToken — Create session token for payment processing. Maintains session state across multiple payment operations for improved security and tracking.
        "create_session_token": "MerchantAuthenticationServiceCreateSessionTokenResponse",
    },
    "PayoutClient": {
        # payout_create: PayoutService.Create — Creates a payout.
        "payout_create": "PayoutServiceCreateResponse",
    },
    "ProxiedPaymentClient": {
        # proxied_authenticate: ProxiedPaymentService.Authenticate — Execute 3DS challenge/frictionless step via vault proxy.
        "proxied_authenticate": "PaymentMethodAuthenticationServiceAuthenticateResponse",
        # proxied_authorize: ProxiedPaymentService.Authorize — Authorize using vault-aliased card data. Proxy substitutes before connector.
        "proxied_authorize": "PaymentServiceAuthorizeResponse",
        # proxied_post_authenticate: ProxiedPaymentService.PostAuthenticate — Post-authenticate via vault proxy.
        "proxied_post_authenticate": "PaymentMethodAuthenticationServicePostAuthenticateResponse",
        # proxied_pre_authenticate: ProxiedPaymentService.PreAuthenticate — Start 3DS pre-auth. Proxy substitutes aliases before forwarding to 3DS server.
        "proxied_pre_authenticate": "PaymentMethodAuthenticationServicePreAuthenticateResponse",
        # proxied_setup_recurring: ProxiedPaymentService.SetupRecurring — Setup recurring mandate using vault-aliased card data.
        "proxied_setup_recurring": "PaymentServiceSetupRecurringResponse",
    },
    "PaymentMethodClient": {
        # tokenize: PaymentMethodService.Tokenize — Tokenize payment method for secure storage. Replaces raw card details with secure token for one-click payments and recurring billing.
        "tokenize": "PaymentMethodServiceTokenizeResponse",
    },
    "TokenizedPaymentClient": {
        # tokenized_authorize: TokenizedPaymentService.Authorize — Authorize using a connector-issued payment method token.
        "tokenized_authorize": "PaymentServiceAuthorizeResponse",
        # tokenized_setup_recurring: TokenizedPaymentService.SetupRecurring — Setup a recurring mandate using a connector token.
        "tokenized_setup_recurring": "PaymentServiceSetupRecurringResponse",
    },
}

# Single-step flows: no HTTP round-trip (e.g. webhook processing).
SINGLE_SERVICE_FLOWS = {
    "EventClient": {
        # handle_event: EventService.HandleEvent — Process webhook notifications from connectors. Translates connector events into standardized responses for asynchronous payment state updates.
        "handle_event": "EventServiceHandleResponse",
    },
}
