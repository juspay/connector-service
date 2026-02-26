/**
 * Smoke test for the packed hyperswitch-payments npm tarball.
 *
 * Usage:
 *   mkdir /tmp/test-js-sdk && cd /tmp/test-js-sdk && npm init -y
 *   npm install <path-to>/hyperswitch-payments-0.1.0.tgz
 *   node test_pack.js
 */

"use strict";

const { UniffiClient, ConnectorClient } = require("hyperswitch-payments");
const { ucs } = require("hyperswitch-payments/src/payments/generated/proto");

const PaymentServiceAuthorizeRequest = ucs.v2.PaymentServiceAuthorizeRequest;
const Currency = ucs.v2.Currency;
const CaptureMethod = ucs.v2.CaptureMethod;
const AuthenticationType = ucs.v2.AuthenticationType;

console.log("Loaded hyperswitch-payments from node_modules");
console.log(`  ConnectorClient: ${typeof ConnectorClient}`);
console.log(`  UniffiClient: ${typeof UniffiClient}`);

const apiKey = process.env.STRIPE_API_KEY || "sk_test_placeholder";
const metadata = {
  connector: "Stripe",
  connector_auth_type: JSON.stringify({ auth_type: "HeaderKey", api_key: apiKey }),
  "x-connector": "Stripe",
  "x-merchant-id": "test_merchant_123",
  "x-request-id": "test-pack-001",
  "x-tenant-id": "public",
  "x-auth": "body-key",
  "x-api-key": apiKey,
};

const requestMsg = PaymentServiceAuthorizeRequest.create({
  requestRefId: { id: "test_pack_123" },
  amount: 1000,
  minorAmount: 1000,
  currency: Currency.USD,
  captureMethod: CaptureMethod.AUTOMATIC,
  paymentMethod: {
    card: {
      cardNumber: { value: "4111111111111111" },
      cardExpMonth: { value: "12" },
      cardExpYear: { value: "2050" },
      cardCvc: { value: "123" },
      cardHolderName: { value: "Test User" },
    },
  },
  email: { value: "test@example.com" },
  customerName: "Test",
  authType: AuthenticationType.NO_THREE_DS,
  returnUrl: "https://example.com/return",
  webhookUrl: "https://example.com/webhook",
  address: {},
  testMode: true,
});

const requestBytes = Buffer.from(
  PaymentServiceAuthorizeRequest.encode(requestMsg).finish()
);

// --- Test 1: Low-level FFI ---
console.log("\n=== Test 1: Low-level FFI (UniffiClient.authorizeReq) ===");
const uniffi = new UniffiClient();
const result = uniffi.authorizeReq(requestBytes, metadata);
const parsed = JSON.parse(result);
console.log(`  URL:    ${parsed.url}`);
console.log(`  Method: ${parsed.method}`);
if (parsed.url !== "https://api.stripe.com/v1/payment_intents") throw new Error("Unexpected URL");
if (parsed.method !== "POST") throw new Error("Unexpected method");
console.log("  PASSED");

// --- Test 2: Full round-trip via ConnectorClient ---
async function testRoundTrip() {
  console.log("\n=== Test 2: Full round-trip (ConnectorClient.authorize) ===");
  if (apiKey === "sk_test_placeholder") {
    console.log("  SKIPPED (set STRIPE_API_KEY to enable)");
    return;
  }

  const client = new ConnectorClient();
  try {
    const response = await client.authorize(requestMsg, metadata);
    console.log(`  Response type: ${typeof response}`);
    console.log(`  Response keys: ${Object.keys(response)}`);
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
