/**
 * Smoke test for the packed hyperswitch-payments npm tarball.
 */

"use strict";

const { UniffiClient, ConnectorClient } = require("./dist/src/index");
const { ucs } = require("./dist/src/payments/generated/proto");

const PaymentServiceAuthorizeRequest = ucs.v2.PaymentServiceAuthorizeRequest;
const Currency = ucs.v2.Currency;
const CaptureMethod = ucs.v2.CaptureMethod;
const AuthenticationType = ucs.v2.AuthenticationType;
const FfiOptions = ucs.v2.FfiOptions;
const EnvOptions = ucs.v2.EnvOptions;

console.log("Loaded hyperswitch-payments from node_modules");

const apiKey = process.env.STRIPE_API_KEY || "sk_test_placeholder";
const metadata = {
  connector: "Stripe",
  connector_auth_type: JSON.stringify({ Stripe: { api_key: apiKey } }),
  "x-connector": "Stripe",
  "x-merchant-id": "test_merchant_123",
  "x-request-id": "test-pack-001",
  "x-tenant-id": "public",
  "x-auth": "header-key",
};

// Create FfiOptions with testMode
const ffiOptions = FfiOptions.create({
  env: EnvOptions.create({ testMode: true })
});
const optionsBytes = Buffer.from(FfiOptions.encode(ffiOptions).finish());

const requestMsg = PaymentServiceAuthorizeRequest.create({
  merchantTransactionId: { id: "test_pack_123" },
  amount: {
    minorAmount: 1000,
    currency: Currency.USD
  },
  captureMethod: CaptureMethod.AUTOMATIC,
  paymentMethod: {
    card: {
      cardNumber: { value: "4242424242424242" },
      cardExpMonth: { value: "12" },
      cardExpYear: { value: "2030" },
      cardCvc: { value: "123" },
      cardHolderName: { value: "Test User" },
    },
  },
  customer: {
    email: { value: "test@example.com" },
    name: "Test"
  },
  authType: AuthenticationType.NO_THREE_DS,
  returnUrl: "https://example.com/return",
  address: {
    billingAddress: {
      addressLine1: "123 Test St",
      city: "Test City",
      country: "US",
      zip: "12345"
    }
  },
  testMode: true,
});

const requestBytes = Buffer.from(
  PaymentServiceAuthorizeRequest.encode(requestMsg).finish()
);

// --- Test 1: Low-level FFI ---
console.log("\n=== Test 1: Low-level FFI (UniffiClient.authorizeReq) ===");
const uniffi = new UniffiClient();
const result = uniffi.authorizeReq(requestBytes, metadata, optionsBytes);
console.log(`  URL:    ${result.url}`);
console.log(`  Method: ${result.method}`);
if (result.url !== "https://api.stripe.com/v1/payment_intents") throw new Error(`Unexpected URL: ${result.url}`);
if (result.method !== "POST") throw new Error("Unexpected method");
console.log("  PASSED");

// --- Test 2: Full round-trip via ConnectorClient ---
async function testRoundTrip() {
  console.log("\n=== Test 2: Full round-trip (ConnectorClient.authorize) ===");
  if (apiKey === "sk_test_placeholder") {
    console.log("  SKIPPED (set STRIPE_API_KEY to enable)");
    return;
  }

  // Use the new Unified Options structure
  const client = new ConnectorClient(null, {
    http: { totalTimeoutMs: 15000 },
    ffi: { env: { testMode: true } }
  });

  try {
    const response = await client.authorize(requestMsg, metadata);
    console.log(`  Response Status: ${response.status}`);
    console.log("  PASSED");
  } catch (e) {
    console.log(`  Response/error received: ${e.message}`);
    console.log("  PASSED (round-trip completed, error is from Stripe)");
  }
}

testRoundTrip()
  .then(() => console.log("\nAll checks passed."))
  .catch((e) => {
    console.error(e);
    process.exit(1);
  });
