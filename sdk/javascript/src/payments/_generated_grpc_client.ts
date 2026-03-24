// AUTO-GENERATED — do not edit by hand.
// Source: services.proto  |  Regenerate: make generate  (or: python3 scripts/generators/code/generate.py --lang javascript)

import koffi from "koffi";
import path from "path";
// @ts-ignore - generated CommonJS module
import { types } from "./generated/proto.js";

// Standard Node.js __dirname
declare const __dirname: string;
const _dirname = __dirname;

// ── Config ────────────────────────────────────────────────────────────────────

/**
 * Connection configuration for the gRPC client.
 * Field names must be snake_case — they are serialised to JSON and sent to the
 * Rust FFI layer which deserialises them into GrpcConfigInput.
 * 
 * The connector_config field should contain the connector-specific authentication
 * and configuration in the format expected by the server:
 * {"config": {"ConnectorName": {"api_key": "...", ...}}}
 */
export interface GrpcConfig {
  endpoint: string;
  connector: string;
  connector_config: Record<string, unknown>;
}

// ── koffi FFI bindings ────────────────────────────────────────────────────────

interface GrpcFfi {
  call: (
    method:    string,
    configPtr: Buffer,
    configLen: number,
    reqPtr:    Buffer,
    reqLen:    number,
    outLen:    number[],
  ) => unknown; // opaque koffi pointer
  free: (ptr: unknown, len: number) => void;
}

function loadGrpcFfi(libPath?: string): GrpcFfi {
  if (!libPath) {
    const ext = process.platform === "darwin" ? "dylib" : "so";
    libPath = path.join(_dirname, "generated", `libhyperswitch_grpc_ffi.${ext}`);
  }

  const lib = koffi.load(libPath);

  const call = lib.func("hyperswitch_grpc_call",
    koffi.pointer("uint8"),
    [
      "str",                               // method (null-terminated C string)
      koffi.pointer("uint8"),              // config_ptr
      "uint32",                            // config_len
      koffi.pointer("uint8"),              // req_ptr
      "uint32",                            // req_len
      koffi.out(koffi.pointer("uint32")), // out_len (written by callee)
    ],
  );

  const free = lib.func("hyperswitch_grpc_free", "void", [
    koffi.pointer("uint8"),
    "uint32",
  ]);

  return { call, free };
}

// ── Dispatch helper ───────────────────────────────────────────────────────────

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function callGrpc(ffi: GrpcFfi, config: GrpcConfig, method: string, req: any, ReqType: any, ResType: any): unknown {
  const configBuf = Buffer.from(JSON.stringify(config));
  const reqBuf    = Buffer.from(ReqType.encode(ReqType.fromObject(req)).finish());
  const outLen    = [0];

  const ptr = ffi.call(method, configBuf, configBuf.length, reqBuf, reqBuf.length, outLen);
  const len = outLen[0];
  const rawBytes = Buffer.from(koffi.decode(ptr, "uint8", len) as Uint8Array);
  ffi.free(ptr, len);

  if (rawBytes[0] === 1) {
    throw new Error(`gRPC error (${method}): ${rawBytes.slice(1).toString("utf-8")}`);
  }

  return ResType.decode(rawBytes.slice(1));
}

// ── Sub-clients (one per proto service) ──────────────────────────────────────

// CustomerService
export class GrpcCustomerClient {
  constructor(private ffi: GrpcFfi, private config: GrpcConfig) {}

  /** CustomerService.Create — Create customer record in the payment processor system. Stores customer details for future payment operations without re-sending personal information. */
  async create(req: unknown): Promise<unknown> {
    return callGrpc(this.ffi, this.config, "customer/create",
      req, types.CustomerServiceCreateRequest, types.CustomerServiceCreateResponse);
  }

}

// DisputeService
export class GrpcDisputeClient {
  constructor(private ffi: GrpcFfi, private config: GrpcConfig) {}

  /** DisputeService.SubmitEvidence — Upload evidence to dispute customer chargeback. Provides documentation like receipts and delivery proof to contest fraudulent transaction claims. */
  async submitEvidence(req: unknown): Promise<unknown> {
    return callGrpc(this.ffi, this.config, "dispute/submit_evidence",
      req, types.DisputeServiceSubmitEvidenceRequest, types.DisputeServiceSubmitEvidenceResponse);
  }

  /** DisputeService.Defend — Submit defense with reason code for dispute. Presents formal argument against customer's chargeback claim with supporting documentation. */
  async defend(req: unknown): Promise<unknown> {
    return callGrpc(this.ffi, this.config, "dispute/defend",
      req, types.DisputeServiceDefendRequest, types.DisputeServiceDefendResponse);
  }

  /** DisputeService.Accept — Concede dispute and accepts chargeback loss. Acknowledges liability and stops dispute defense process when evidence is insufficient. */
  async accept(req: unknown): Promise<unknown> {
    return callGrpc(this.ffi, this.config, "dispute/accept",
      req, types.DisputeServiceAcceptRequest, types.DisputeServiceAcceptResponse);
  }

}

// EventService
export class GrpcEventClient {
  constructor(private ffi: GrpcFfi, private config: GrpcConfig) {}

  /** EventService.HandleEvent — Process webhook notifications from connectors. Translates connector events into standardized responses for asynchronous payment state updates. */
  async handleEvent(req: unknown): Promise<unknown> {
    return callGrpc(this.ffi, this.config, "event/handle_event",
      req, types.EventServiceHandleRequest, types.EventServiceHandleResponse);
  }

}

// MerchantAuthenticationService
export class GrpcMerchantAuthenticationClient {
  constructor(private ffi: GrpcFfi, private config: GrpcConfig) {}

  /** MerchantAuthenticationService.CreateAccessToken — Generate short-lived connector authentication token. Provides secure credentials for connector API access without storing secrets client-side. */
  async createAccessToken(req: unknown): Promise<unknown> {
    return callGrpc(this.ffi, this.config, "merchant_authentication/create_access_token",
      req, types.MerchantAuthenticationServiceCreateAccessTokenRequest, types.MerchantAuthenticationServiceCreateAccessTokenResponse);
  }

  /** MerchantAuthenticationService.CreateSessionToken — Create session token for payment processing. Maintains session state across multiple payment operations for improved security and tracking. */
  async createSessionToken(req: unknown): Promise<unknown> {
    return callGrpc(this.ffi, this.config, "merchant_authentication/create_session_token",
      req, types.MerchantAuthenticationServiceCreateSessionTokenRequest, types.MerchantAuthenticationServiceCreateSessionTokenResponse);
  }

  /** MerchantAuthenticationService.CreateSdkSessionToken — Initialize wallet payment sessions for Apple Pay, Google Pay, etc. Sets up secure context for tokenized wallet payments with device verification. */
  async createSdkSessionToken(req: unknown): Promise<unknown> {
    return callGrpc(this.ffi, this.config, "merchant_authentication/create_sdk_session_token",
      req, types.MerchantAuthenticationServiceCreateSdkSessionTokenRequest, types.MerchantAuthenticationServiceCreateSdkSessionTokenResponse);
  }

}

// PaymentMethodAuthenticationService
export class GrpcPaymentMethodAuthenticationClient {
  constructor(private ffi: GrpcFfi, private config: GrpcConfig) {}

  /** PaymentMethodAuthenticationService.PreAuthenticate — Initiate 3DS flow before payment authorization. Collects device data and prepares authentication context for frictionless or challenge-based verification. */
  async preAuthenticate(req: unknown): Promise<unknown> {
    return callGrpc(this.ffi, this.config, "payment_method_authentication/pre_authenticate",
      req, types.PaymentMethodAuthenticationServicePreAuthenticateRequest, types.PaymentMethodAuthenticationServicePreAuthenticateResponse);
  }

  /** PaymentMethodAuthenticationService.Authenticate — Execute 3DS challenge or frictionless verification. Authenticates customer via bank challenge or behind-the-scenes verification for fraud prevention. */
  async authenticate(req: unknown): Promise<unknown> {
    return callGrpc(this.ffi, this.config, "payment_method_authentication/authenticate",
      req, types.PaymentMethodAuthenticationServiceAuthenticateRequest, types.PaymentMethodAuthenticationServiceAuthenticateResponse);
  }

  /** PaymentMethodAuthenticationService.PostAuthenticate — Validate authentication results with the issuing bank. Processes bank's authentication decision to determine if payment can proceed. */
  async postAuthenticate(req: unknown): Promise<unknown> {
    return callGrpc(this.ffi, this.config, "payment_method_authentication/post_authenticate",
      req, types.PaymentMethodAuthenticationServicePostAuthenticateRequest, types.PaymentMethodAuthenticationServicePostAuthenticateResponse);
  }

}

// PaymentMethodService
export class GrpcPaymentMethodClient {
  constructor(private ffi: GrpcFfi, private config: GrpcConfig) {}

  /** PaymentMethodService.Tokenize — Tokenize payment method for secure storage. Replaces raw card details with secure token for one-click payments and recurring billing. */
  async tokenize(req: unknown): Promise<unknown> {
    return callGrpc(this.ffi, this.config, "payment_method/tokenize",
      req, types.PaymentMethodServiceTokenizeRequest, types.PaymentMethodServiceTokenizeResponse);
  }

  /** PaymentMethodService.Eligibility — Check if the payout method is eligible for the transaction */
  async eligibility(req: unknown): Promise<unknown> {
    return callGrpc(this.ffi, this.config, "payment_method/eligibility",
      req, types.PayoutMethodEligibilityRequest, types.PayoutMethodEligibilityResponse);
  }

}

// PaymentService
export class GrpcPaymentClient {
  constructor(private ffi: GrpcFfi, private config: GrpcConfig) {}

  /** PaymentService.Authorize — Authorize a payment amount on a payment method. This reserves funds without capturing them, essential for verifying availability before finalizing. */
  async authorize(req: unknown): Promise<unknown> {
    return callGrpc(this.ffi, this.config, "payment/authorize",
      req, types.PaymentServiceAuthorizeRequest, types.PaymentServiceAuthorizeResponse);
  }

  /** PaymentService.Get — Retrieve current payment status from the payment processor. Enables synchronization between your system and payment processors for accurate state tracking. */
  async get(req: unknown): Promise<unknown> {
    return callGrpc(this.ffi, this.config, "payment/get",
      req, types.PaymentServiceGetRequest, types.PaymentServiceGetResponse);
  }

  /** PaymentService.Void — Cancel an authorized payment before capture. Releases held funds back to customer, typically used when orders are cancelled or abandoned. */
  async void(req: unknown): Promise<unknown> {
    return callGrpc(this.ffi, this.config, "payment/void",
      req, types.PaymentServiceVoidRequest, types.PaymentServiceVoidResponse);
  }

  /** PaymentService.Reverse — Reverse a captured payment before settlement. Recovers funds after capture but before bank settlement, used for corrections or cancellations. */
  async reverse(req: unknown): Promise<unknown> {
    return callGrpc(this.ffi, this.config, "payment/reverse",
      req, types.PaymentServiceReverseRequest, types.PaymentServiceReverseResponse);
  }

  /** PaymentService.Capture — Finalize an authorized payment transaction. Transfers reserved funds from customer to merchant account, completing the payment lifecycle. */
  async capture(req: unknown): Promise<unknown> {
    return callGrpc(this.ffi, this.config, "payment/capture",
      req, types.PaymentServiceCaptureRequest, types.PaymentServiceCaptureResponse);
  }

  /** PaymentService.CreateOrder — Initialize an order in the payment processor system. Sets up payment context before customer enters card details for improved authorization rates. */
  async createOrder(req: unknown): Promise<unknown> {
    return callGrpc(this.ffi, this.config, "payment/create_order",
      req, types.PaymentServiceCreateOrderRequest, types.PaymentServiceCreateOrderResponse);
  }

  /** PaymentService.Refund — Initiate a refund to customer's payment method. Returns funds for returns, cancellations, or service adjustments after original payment. */
  async refund(req: unknown): Promise<unknown> {
    return callGrpc(this.ffi, this.config, "payment/refund",
      req, types.PaymentServiceRefundRequest, types.RefundResponse);
  }

  /** PaymentService.IncrementalAuthorization — Increase authorized amount if still in authorized state. Allows adding charges to existing authorization for hospitality, tips, or incremental services. */
  async incrementalAuthorization(req: unknown): Promise<unknown> {
    return callGrpc(this.ffi, this.config, "payment/incremental_authorization",
      req, types.PaymentServiceIncrementalAuthorizationRequest, types.PaymentServiceIncrementalAuthorizationResponse);
  }

  /** PaymentService.VerifyRedirectResponse — Validate redirect-based payment responses. Confirms authenticity of redirect-based payment completions to prevent fraud and tampering. */
  async verifyRedirectResponse(req: unknown): Promise<unknown> {
    return callGrpc(this.ffi, this.config, "payment/verify_redirect_response",
      req, types.PaymentServiceVerifyRedirectResponseRequest, types.PaymentServiceVerifyRedirectResponseResponse);
  }

  /** PaymentService.SetupRecurring — Setup a recurring payment instruction for future payments/ debits. This could be for SaaS subscriptions, monthly bill payments, insurance payments and similar use cases. */
  async setupRecurring(req: unknown): Promise<unknown> {
    return callGrpc(this.ffi, this.config, "payment/setup_recurring",
      req, types.PaymentServiceSetupRecurringRequest, types.PaymentServiceSetupRecurringResponse);
  }

}

// PayoutService
export class GrpcPayoutClient {
  constructor(private ffi: GrpcFfi, private config: GrpcConfig) {}

  /** PayoutService.Transfer — Creates a payout fund transfer. */
  async transfer(req: unknown): Promise<unknown> {
    return callGrpc(this.ffi, this.config, "payout/transfer",
      req, types.PayoutServiceTransferRequest, types.PayoutServiceTransferResponse);
  }

  /** PayoutService.Stage — Stage the payout. */
  async stage(req: unknown): Promise<unknown> {
    return callGrpc(this.ffi, this.config, "payout/stage",
      req, types.PayoutServiceStageRequest, types.PayoutServiceStageResponse);
  }

  /** PayoutService.CreateLink — Creates a link between the recipient and the payout. */
  async createLink(req: unknown): Promise<unknown> {
    return callGrpc(this.ffi, this.config, "payout/create_link",
      req, types.PayoutServiceCreateLinkRequest, types.PayoutServiceCreateLinkResponse);
  }

  /** PayoutService.CreateRecipient — Create payout recipient. */
  async createRecipient(req: unknown): Promise<unknown> {
    return callGrpc(this.ffi, this.config, "payout/create_recipient",
      req, types.PayoutServiceCreateRecipientRequest, types.PayoutServiceCreateRecipientResponse);
  }

  /** PayoutService.EnrollDisburseAccount — Enroll disburse account. */
  async enrollDisburseAccount(req: unknown): Promise<unknown> {
    return callGrpc(this.ffi, this.config, "payout/enroll_disburse_account",
      req, types.PayoutServiceEnrollDisburseAccountRequest, types.PayoutServiceEnrollDisburseAccountResponse);
  }

}

// RecurringPaymentService
export class GrpcRecurringPaymentClient {
  constructor(private ffi: GrpcFfi, private config: GrpcConfig) {}

  /** RecurringPaymentService.Charge — Charge using an existing stored recurring payment instruction. Processes repeat payments for subscriptions or recurring billing without collecting payment details. */
  async charge(req: unknown): Promise<unknown> {
    return callGrpc(this.ffi, this.config, "recurring_payment/charge",
      req, types.RecurringPaymentServiceChargeRequest, types.RecurringPaymentServiceChargeResponse);
  }

  /** RecurringPaymentService.Revoke — Cancel an existing recurring payment mandate. Stops future automatic charges on customer's stored consent for subscription cancellations. */
  async revoke(req: unknown): Promise<unknown> {
    return callGrpc(this.ffi, this.config, "recurring_payment/revoke",
      req, types.RecurringPaymentServiceRevokeRequest, types.RecurringPaymentServiceRevokeResponse);
  }

}

// ── Top-level GrpcClient ──────────────────────────────────────────────────────

/**
 * Top-level gRPC client for the connector-service.
 *
 * Each sub-client corresponds to one proto service.  Auth headers from
 * `GrpcConfig` are injected automatically on every call via the Rust FFI layer.
 *
 * Example:
 * ```ts
 * const client = new GrpcClient({
 *   endpoint: "http://localhost:8000",
 *   connector: "stripe",
 *   connector_config: {"config": {"Stripe": {"api_key": "sk_test_..."}}},
 * });
 * const res = await client.customer.create({ ... });
 * const res = await client.dispute.submitEvidence({ ... });
 * const res = await client.event.handleEvent({ ... });
 * const res = await client.merchantAuthentication.createAccessToken({ ... });
 * ```
 */
export class GrpcClient {
  public customer: GrpcCustomerClient;
  public dispute: GrpcDisputeClient;
  public event: GrpcEventClient;
  public merchantAuthentication: GrpcMerchantAuthenticationClient;
  public paymentMethodAuthentication: GrpcPaymentMethodAuthenticationClient;
  public paymentMethod: GrpcPaymentMethodClient;
  public payment: GrpcPaymentClient;
  public payout: GrpcPayoutClient;
  public recurringPayment: GrpcRecurringPaymentClient;

  constructor(config: GrpcConfig, libPath?: string) {
    const ffi = loadGrpcFfi(libPath);
    this.customer = new GrpcCustomerClient(ffi, config);
    this.dispute = new GrpcDisputeClient(ffi, config);
    this.event = new GrpcEventClient(ffi, config);
    this.merchantAuthentication = new GrpcMerchantAuthenticationClient(ffi, config);
    this.paymentMethodAuthentication = new GrpcPaymentMethodAuthenticationClient(ffi, config);
    this.paymentMethod = new GrpcPaymentMethodClient(ffi, config);
    this.payment = new GrpcPaymentClient(ffi, config);
    this.payout = new GrpcPayoutClient(ffi, config);
    this.recurringPayment = new GrpcRecurringPaymentClient(ffi, config);
  }
}
